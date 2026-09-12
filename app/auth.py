from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import struct
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import qrcode
from cryptography.fernet import Fernet, InvalidToken


LOGIN_MODES = {"password", "password_or_totp", "totp_only"}
UNLOCK_MINUTES = {2, 5, 10, 15}
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
RECOVERY_CODE_COUNT = 10
PARENT_EXTENSION_THRESHOLD_SECONDS = 90


class AuthError(RuntimeError):
    pass


def fresh_auth_valid(
    *,
    fresh_auth_at: float,
    fresh_auth_boot_id: str | None,
    process_boot_id: str,
    max_age_seconds: int = 90,
    now: float | None = None,
) -> bool:
    """Return whether recent step-up authentication is valid in this process."""
    current = time.time() if now is None else float(now)
    at = float(fresh_auth_at or 0)
    return bool(
        at > 0
        and current - at <= int(max_age_seconds)
        and current >= at
        and fresh_auth_boot_id
        and fresh_auth_boot_id == process_boot_id
    )


def shared_display_privilege_valid(
    *,
    shared_display_mode: bool,
    privileged_until: float,
    privileged_boot_id: str | None,
    process_boot_id: str,
    now: float | None = None,
) -> bool:
    """Return whether a shared-display write window is valid in this process.

    Signed browser sessions may survive an application restart. Parent write
    privilege deliberately does not: a restart invalidates the short unlock
    window so the shared display returns to read-only until a fresh parent OTP
    or recovery code is supplied.
    """
    if not shared_display_mode:
        return True
    current = time.time() if now is None else float(now)
    return bool(
        float(privileged_until or 0) > current
        and privileged_boot_id
        and privileged_boot_id == process_boot_id
    )


def shared_display_extension_allowed(
    *,
    shared_display_mode: bool,
    privileged_until: float,
    privileged_boot_id: str | None,
    process_boot_id: str,
    now: float | None = None,
    threshold_seconds: int = PARENT_EXTENSION_THRESHOLD_SECONDS,
) -> bool:
    """Return whether an active shared-display window is close enough to extend.

    Extension is deliberately unavailable while locked and cannot be stacked
    early.  The caller must still perform a fresh OTP/recovery-code check before
    changing the session deadline.
    """
    current = time.time() if now is None else float(now)
    if not shared_display_mode:
        return False
    if not shared_display_privilege_valid(
        shared_display_mode=True,
        privileged_until=privileged_until,
        privileged_boot_id=privileged_boot_id,
        process_boot_id=process_boot_id,
        now=current,
    ):
        return False
    remaining = float(privileged_until or 0) - current
    return 0 < remaining <= max(1, int(threshold_seconds))


def extend_shared_display_deadline(
    *,
    privileged_until: float,
    unlock_minutes: int,
    now: float | None = None,
) -> float:
    """Add one configured parent window without shortening existing privilege."""
    current = time.time() if now is None else float(now)
    minutes = int(unlock_minutes)
    if minutes <= 0:
        raise ValueError("unlock_minutes must be positive")
    return max(current, float(privileged_until or 0)) + (minutes * 60)


class AuthManager:
    """Local parent authentication and shared-display privilege controller.

    Password verification remains owned by main.py / passlib. This class owns
    TOTP authenticators, recovery codes, session generations and parent-unlock
    policy. TOTP secrets are encrypted at rest using OTP_ENCRYPTION_KEY when
    supplied, otherwise SESSION_SECRET as a compatibility fallback.
    """

    def __init__(
        self,
        db_path: str,
        *,
        encryption_material: str,
        issuer: str = "ZEN Control",
    ) -> None:
        if not encryption_material:
            raise AuthError("OTP encryption material is required")
        self.db_path = db_path
        self.issuer = issuer
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(encryption_material.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))
        self._init_db()

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_accounts (
                    username TEXT PRIMARY KEY,
                    login_mode TEXT NOT NULL DEFAULT 'password',
                    shared_display_mode INTEGER NOT NULL DEFAULT 0,
                    unlock_minutes INTEGER NOT NULL DEFAULT 5,
                    session_generation INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_totp_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    name TEXT NOT NULL,
                    secret_enc TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    last_used_counter INTEGER NOT NULL DEFAULT -1,
                    revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_auth_totp_user
                    ON auth_totp_devices(username, revoked_at, id);

                CREATE TABLE IF NOT EXISTS auth_recovery_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    used_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_recovery_hash
                    ON auth_recovery_codes(username, code_hash);

                CREATE TABLE IF NOT EXISTS auth_totp_enrollments (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    name TEXT NOT NULL,
                    secret_enc TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @classmethod
    def _iso(cls, value: datetime | None = None) -> str:
        return (value or cls._now()).isoformat(timespec="seconds")

    def ensure_account(self, username: str) -> dict[str, Any]:
        username = str(username or "").strip()
        if not username:
            raise AuthError("Username is required")
        now = self._iso()
        with self._db() as db:
            db.execute(
                """INSERT OR IGNORE INTO auth_accounts
                   (username, login_mode, shared_display_mode, unlock_minutes,
                    session_generation, updated_at)
                   VALUES (?, 'password', 0, 5, 0, ?)""",
                (username, now),
            )
            row = db.execute(
                "SELECT * FROM auth_accounts WHERE username=?", (username,)
            ).fetchone()
        return dict(row)

    def account(self, username: str) -> dict[str, Any]:
        row = self.ensure_account(username)
        return {
            **row,
            "shared_display_mode": bool(row["shared_display_mode"]),
            "unlock_minutes": int(row["unlock_minutes"]),
            "session_generation": int(row["session_generation"]),
        }

    def save_account_settings(
        self,
        username: str,
        *,
        login_mode: str,
        shared_display_mode: bool,
        unlock_minutes: int,
    ) -> dict[str, Any]:
        login_mode = str(login_mode or "password").strip().lower()
        if login_mode not in LOGIN_MODES:
            raise AuthError("Invalid login mode")
        try:
            unlock_minutes = int(unlock_minutes)
        except (TypeError, ValueError) as exc:
            raise AuthError("Unlock duration is invalid") from exc
        if unlock_minutes not in UNLOCK_MINUTES:
            raise AuthError("Unlock duration must be 2, 5, 10 or 15 minutes")
        active = self.active_totp_count(username)
        if login_mode != "password" and active < 1:
            raise AuthError("Enroll at least one authenticator before enabling OTP login")
        if shared_display_mode and active < 1:
            raise AuthError("Shared display mode requires at least one active authenticator")
        if login_mode == "totp_only" and self.remaining_recovery_codes(username) < 1:
            raise AuthError("Generate recovery codes before enabling OTP-only login")
        now = self._iso()
        with self._db() as db:
            self.ensure_account(username)
            db.execute(
                """UPDATE auth_accounts
                   SET login_mode=?, shared_display_mode=?, unlock_minutes=?, updated_at=?
                   WHERE username=?""",
                (
                    login_mode,
                    1 if shared_display_mode else 0,
                    unlock_minutes,
                    now,
                    username,
                ),
            )
        return self.account(username)

    def session_generation(self, username: str) -> int:
        return int(self.account(username)["session_generation"])

    def revoke_all_sessions(self, username: str) -> int:
        now = self._iso()
        with self._db() as db:
            self.ensure_account(username)
            db.execute(
                """UPDATE auth_accounts
                   SET session_generation=session_generation+1, updated_at=?
                   WHERE username=?""",
                (now, username),
            )
            row = db.execute(
                "SELECT session_generation FROM auth_accounts WHERE username=?",
                (username,),
            ).fetchone()
        return int(row["session_generation"])

    @staticmethod
    def _normalize_secret(secret: str) -> str:
        return "".join(str(secret or "").upper().split())

    @staticmethod
    def generate_secret() -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_secret(secret: str) -> bytes:
        secret = AuthManager._normalize_secret(secret)
        padding = "=" * ((8 - len(secret) % 8) % 8)
        return base64.b32decode(secret + padding, casefold=True)

    @classmethod
    def hotp(cls, secret: str, counter: int) -> str:
        key = cls._decode_secret(secret)
        msg = struct.pack(">Q", int(counter))
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        value = binary % (10 ** TOTP_DIGITS)
        return f"{value:0{TOTP_DIGITS}d}"

    @classmethod
    def totp(cls, secret: str, at: float | None = None) -> tuple[str, int]:
        now = time.time() if at is None else float(at)
        counter = int(now // TOTP_PERIOD)
        return cls.hotp(secret, counter), counter

    @classmethod
    def verify_secret_code(
        cls,
        secret: str,
        code: str,
        *,
        at: float | None = None,
        last_used_counter: int = -1,
    ) -> int | None:
        code = "".join(str(code or "").split())
        if len(code) != TOTP_DIGITS or not code.isdigit():
            return None
        now = time.time() if at is None else float(at)
        base_counter = int(now // TOTP_PERIOD)
        for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            counter = base_counter + delta
            if counter <= int(last_used_counter):
                continue
            expected = cls.hotp(secret, counter)
            if hmac.compare_digest(expected, code):
                return counter
        return None

    def _encrypt_secret(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode("ascii")).decode("ascii")

    def _decrypt_secret(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("ascii")
        except InvalidToken as exc:
            raise AuthError(
                "Authenticator secret cannot be decrypted. Check OTP_ENCRYPTION_KEY/SESSION_SECRET."
            ) from exc

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()

    def begin_enrollment(self, username: str, name: str) -> dict[str, str]:
        self.ensure_account(username)
        name = str(name or "").strip()[:80]
        if not name:
            raise AuthError("Authenticator name is required")
        token = secrets.token_urlsafe(32)
        secret = self.generate_secret()
        now = self._now()
        expires = now + timedelta(minutes=10)
        with self._db() as db:
            db.execute(
                "DELETE FROM auth_totp_enrollments WHERE username=? OR expires_at < ?",
                (username, self._iso(now)),
            )
            db.execute(
                """INSERT INTO auth_totp_enrollments
                   (token_hash, username, name, secret_enc, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    self._token_hash(token),
                    username,
                    name,
                    self._encrypt_secret(secret),
                    self._iso(now),
                    self._iso(expires),
                ),
            )
        return {"token": token, "name": name, "expires_at": self._iso(expires)}

    def enrollment(self, username: str, token: str) -> dict[str, str] | None:
        with self._db() as db:
            row = db.execute(
                """SELECT * FROM auth_totp_enrollments
                   WHERE token_hash=? AND username=?""",
                (self._token_hash(token), username),
            ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= self._now():
            self.cancel_enrollment(username, token)
            return None
        secret = self._decrypt_secret(row["secret_enc"])
        uri = self.otpauth_uri(username, secret)
        return {
            "token": token,
            "name": row["name"],
            "secret": secret,
            "expires_at": row["expires_at"],
            "otpauth_uri": uri,
            "qr_data_uri": self.qr_data_uri(uri),
        }

    def cancel_enrollment(self, username: str, token: str) -> None:
        with self._db() as db:
            db.execute(
                "DELETE FROM auth_totp_enrollments WHERE token_hash=? AND username=?",
                (self._token_hash(token), username),
            )

    def confirm_enrollment(self, username: str, token: str, code: str) -> dict[str, Any]:
        enrollment = self.enrollment(username, token)
        if not enrollment:
            raise AuthError("Authenticator enrollment expired or no longer exists")
        counter = self.verify_secret_code(enrollment["secret"], code)
        if counter is None:
            raise AuthError("The authenticator code is invalid")
        now = self._iso()
        with self._db() as db:
            cur = db.execute(
                """INSERT INTO auth_totp_devices
                   (username, name, secret_enc, created_at, last_used_at, last_used_counter)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    username,
                    enrollment["name"],
                    self._encrypt_secret(enrollment["secret"]),
                    now,
                    now,
                    counter,
                ),
            )
            db.execute(
                "DELETE FROM auth_totp_enrollments WHERE token_hash=?",
                (self._token_hash(token),),
            )
            device_id = int(cur.lastrowid)
        recovery_codes: list[str] = []
        if self.remaining_recovery_codes(username) == 0:
            recovery_codes = self.regenerate_recovery_codes(username)
        return {
            "device": self.get_totp_device(username, device_id),
            "recovery_codes": recovery_codes,
        }

    def list_totp_devices(self, username: str, *, include_revoked: bool = False) -> list[dict]:
        where = "username=?" if include_revoked else "username=? AND revoked_at IS NULL"
        with self._db() as db:
            rows = db.execute(
                f"""SELECT id, username, name, created_at, last_used_at,
                           last_used_counter, revoked_at
                    FROM auth_totp_devices WHERE {where} ORDER BY id""",
                (username,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_totp_device(self, username: str, device_id: int) -> dict | None:
        with self._db() as db:
            row = db.execute(
                """SELECT id, username, name, created_at, last_used_at,
                          last_used_counter, revoked_at
                   FROM auth_totp_devices WHERE username=? AND id=?""",
                (username, int(device_id)),
            ).fetchone()
        return dict(row) if row else None

    def active_totp_count(self, username: str) -> int:
        with self._db() as db:
            row = db.execute(
                """SELECT COUNT(*) AS c FROM auth_totp_devices
                   WHERE username=? AND revoked_at IS NULL""",
                (username,),
            ).fetchone()
        return int(row["c"] or 0)

    def verify_totp(self, username: str, code: str, *, at: float | None = None) -> dict | None:
        with self._db() as db:
            rows = db.execute(
                """SELECT * FROM auth_totp_devices
                   WHERE username=? AND revoked_at IS NULL ORDER BY id""",
                (username,),
            ).fetchall()
            for row in rows:
                secret = self._decrypt_secret(row["secret_enc"])
                counter = self.verify_secret_code(
                    secret,
                    code,
                    at=at,
                    last_used_counter=int(row["last_used_counter"]),
                )
                if counter is None:
                    continue
                now = self._iso()
                db.execute(
                    """UPDATE auth_totp_devices
                       SET last_used_at=?, last_used_counter=? WHERE id=?""",
                    (now, counter, row["id"]),
                )
                return {
                    "method": "totp",
                    "device_id": int(row["id"]),
                    "device_name": row["name"],
                    "counter": counter,
                }
        return None

    def revoke_totp_device(self, username: str, device_id: int) -> dict:
        account = self.account(username)
        device = self.get_totp_device(username, device_id)
        if not device or device.get("revoked_at"):
            raise AuthError("Authenticator does not exist or is already revoked")
        remaining = self.active_totp_count(username) - 1
        if remaining < 1 and (
            account["login_mode"] != "password" or account["shared_display_mode"]
        ):
            raise AuthError(
                "Cannot revoke the final authenticator while OTP login or shared display mode is enabled"
            )
        now = self._iso()
        with self._db() as db:
            db.execute(
                "UPDATE auth_totp_devices SET revoked_at=? WHERE username=? AND id=?",
                (now, username, int(device_id)),
            )
        return self.get_totp_device(username, device_id) or device

    def otpauth_uri(self, username: str, secret: str) -> str:
        label = quote(f"{self.issuer}:{username}", safe="")
        issuer = quote(self.issuer, safe="")
        return (
            f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
            f"&period={TOTP_PERIOD}&digits={TOTP_DIGITS}"
        )

    @staticmethod
    def qr_data_uri(uri: str) -> str:
        image = qrcode.make(uri)
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        encoded = base64.b64encode(buf.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"

    @staticmethod
    def _normalize_recovery_code(code: str) -> str:
        return "".join(ch for ch in str(code or "").upper() if ch.isalnum())

    def _recovery_hash(self, code: str) -> str:
        # Recovery codes are high-entropy random values. An unkeyed SHA-256 hash
        # deliberately lets them remain usable if OTP_ENCRYPTION_KEY must be
        # repaired, providing a genuine break-glass path for OTP-only accounts.
        normalized = self._normalize_recovery_code(code)
        return hashlib.sha256(normalized.encode("ascii")).hexdigest()

    @staticmethod
    def _new_recovery_code() -> str:
        raw = base64.b32encode(secrets.token_bytes(10)).decode("ascii").rstrip("=")[:16]
        return "-".join(raw[i:i + 4] for i in range(0, 16, 4))

    def regenerate_recovery_codes(self, username: str) -> list[str]:
        self.ensure_account(username)
        codes = [self._new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        now = self._iso()
        with self._db() as db:
            db.execute("DELETE FROM auth_recovery_codes WHERE username=?", (username,))
            db.executemany(
                """INSERT INTO auth_recovery_codes
                   (username, code_hash, created_at, used_at)
                   VALUES (?, ?, ?, NULL)""",
                [(username, self._recovery_hash(code), now) for code in codes],
            )
        return codes

    def verify_recovery_code(self, username: str, code: str) -> bool:
        normalized = self._normalize_recovery_code(code)
        if len(normalized) < 10:
            return False
        digest = self._recovery_hash(code)
        now = self._iso()
        with self._db() as db:
            row = db.execute(
                """SELECT id FROM auth_recovery_codes
                   WHERE username=? AND code_hash=? AND used_at IS NULL""",
                (username, digest),
            ).fetchone()
            if not row:
                return False
            db.execute(
                "UPDATE auth_recovery_codes SET used_at=? WHERE id=?",
                (now, row["id"]),
            )
        return True

    def remaining_recovery_codes(self, username: str) -> int:
        with self._db() as db:
            row = db.execute(
                """SELECT COUNT(*) AS c FROM auth_recovery_codes
                   WHERE username=? AND used_at IS NULL""",
                (username,),
            ).fetchone()
        return int(row["c"] or 0)

    def verify_otp_or_recovery(self, username: str, code: str) -> dict | None:
        compact = "".join(str(code or "").split())
        if len(compact) == TOTP_DIGITS and compact.isdigit():
            return self.verify_totp(username, compact)
        if self.verify_recovery_code(username, code):
            return {"method": "recovery", "device_id": None, "device_name": "Recovery code"}
        return None

    def dashboard_state(self, username: str) -> dict[str, Any]:
        account = self.account(username)
        devices = self.list_totp_devices(username)
        return {
            **account,
            "totp_devices": devices,
            "totp_count": len(devices),
            "recovery_codes_remaining": self.remaining_recovery_codes(username),
        }
