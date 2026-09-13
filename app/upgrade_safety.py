from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 570
SCHEMA_RELEASE = "0.57.0"
SCHEMA_NAME = "operational-resilience-upgrade-safety"


class UpgradeSafetyError(RuntimeError):
    """Policy database cannot be safely inspected, backed up or upgraded."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect_read_only(path: Path) -> sqlite3.Connection:
    # URI mode prevents an inspection from creating a missing database.
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_database(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if not source.exists() or source.stat().st_size == 0:
        return {
            "ok": True,
            "state": "absent",
            "version": 0,
            "quick_check": [],
            "foreign_key_violations": 0,
            "tables": [],
            "table_counts": {},
            "size_bytes": 0,
        }

    try:
        db = _connect_read_only(source)
        try:
            quick = [str(row[0]) for row in db.execute("PRAGMA quick_check").fetchall()]
            foreign = db.execute("PRAGMA foreign_key_check").fetchall()
            version = int(db.execute("PRAGMA user_version").fetchone()[0] or 0)
            tables = [
                str(row[0])
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
            ]
            counts: dict[str, int] = {}
            for table in tables:
                escaped = table.replace('"', '""')
                counts[table] = int(db.execute(f'SELECT COUNT(*) FROM "{escaped}"').fetchone()[0])
        finally:
            db.close()
    except sqlite3.DatabaseError as exc:
        raise UpgradeSafetyError(f"SQLite inspection failed: {exc}") from exc

    ok = quick == ["ok"] and not foreign
    return {
        "ok": ok,
        "state": "ready" if ok else "invalid",
        "version": version,
        "quick_check": quick,
        "foreign_key_violations": len(foreign),
        "tables": tables,
        "table_counts": counts,
        "size_bytes": source.stat().st_size,
    }


def validate_database(path: str | Path) -> dict[str, Any]:
    report = inspect_database(path)
    if report["state"] == "absent":
        raise UpgradeSafetyError("Policy database does not exist")
    if not report["ok"]:
        raise UpgradeSafetyError(
            "Policy database integrity failed before upgrade "
            f"(quick_check={report['quick_check']!r}, foreign_key_violations={report['foreign_key_violations']})"
        )
    return report


def backup_path_for(path: str | Path, target_version: int = SCHEMA_VERSION) -> Path:
    source = Path(path)
    return source.with_name(f"{source.name}.pre-schema-{int(target_version)}.bak")


def create_verified_backup(
    source_path: str | Path,
    destination_path: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    source = Path(source_path)
    destination = Path(destination_path)
    before = validate_database(source)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() and not overwrite:
        existing = validate_database(destination)
        return {
            "ok": True,
            "state": "reused",
            "path": str(destination),
            "sha256": _sha256(destination),
            "size_bytes": destination.stat().st_size,
            "source_version": before["version"],
            "backup_version": existing["version"],
            "quick_check": existing["quick_check"],
            "foreign_key_violations": existing["foreign_key_violations"],
        }

    temporary = destination.with_name(destination.name + ".tmp")
    try:
        temporary.unlink(missing_ok=True)
        src = sqlite3.connect(source, timeout=5.0)
        dst = sqlite3.connect(temporary)
        try:
            src.execute("PRAGMA busy_timeout=5000")
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        after = validate_database(temporary)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    return {
        "ok": True,
        "state": "created",
        "path": str(destination),
        "sha256": _sha256(destination),
        "size_bytes": destination.stat().st_size,
        "source_version": before["version"],
        "backup_version": after["version"],
        "quick_check": after["quick_check"],
        "foreign_key_violations": after["foreign_key_violations"],
    }


def prepare_policy_database_upgrade(
    path: str | Path,
    *,
    target_version: int = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Fail closed and preserve a verified pre-migration SQLite copy.

    This runs before PolicyStore executes any CREATE/ALTER/UPDATE migration work.
    The deterministic sibling backup is intentionally reused after an interrupted
    attempt so a partially upgraded database can never overwrite the original
    pre-upgrade recovery point.
    """

    source = Path(path)
    inspection = inspect_database(source)
    if inspection["state"] == "absent":
        return {
            "ok": True,
            "state": "fresh",
            "from_version": 0,
            "target_version": int(target_version),
            "backup": None,
        }
    if not inspection["ok"]:
        raise UpgradeSafetyError(
            "Refusing schema migration because the existing policy database failed integrity checks"
        )

    current = int(inspection["version"] or 0)
    target = int(target_version)
    if current > target:
        raise UpgradeSafetyError(
            f"Policy database schema {current} is newer than this application supports ({target})"
        )
    if current == target:
        return {
            "ok": True,
            "state": "current",
            "from_version": current,
            "target_version": target,
            "backup": None,
        }

    backup = create_verified_backup(source, backup_path_for(source, target), overwrite=False)
    return {
        "ok": True,
        "state": "upgrade_pending",
        "from_version": current,
        "target_version": target,
        "backup": backup,
    }


def finalize_upgrade_report(preflight: dict[str, Any], path: str | Path) -> dict[str, Any]:
    inspection = validate_database(path)
    current = int(inspection["version"] or 0)
    target = int(preflight.get("target_version") or SCHEMA_VERSION)
    if current != target:
        raise UpgradeSafetyError(
            f"Policy database migration did not reach target schema {target}; found {current}"
        )
    state = "created" if preflight.get("state") == "fresh" else (
        "unchanged" if preflight.get("state") == "current" else "upgraded"
    )
    return {
        **preflight,
        "ok": True,
        "state": state,
        "current_version": current,
        "quick_check": inspection["quick_check"],
        "foreign_key_violations": inspection["foreign_key_violations"],
        "table_count": len(inspection["tables"]),
        "checked_at": _now_iso(),
    }
