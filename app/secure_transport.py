"""Secure transport and remote-access configuration for ZEN Control.

This module deliberately owns only the web transport boundary. It does not
create Cloudflare resources, does not validate or persist tunnel tokens, and
has no RouterOS/reconciliation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any
import os
import re


_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.I)


class SecureTransportConfigError(ValueError):
    """Raised for malformed security-sensitive transport configuration."""


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    raise SecureTransportConfigError(f"Invalid boolean value: {value!r}")


def _public_host(value: Any) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if any(token in host for token in ("://", "/", "\\", ":", "*", "?", "#")):
        raise SecureTransportConfigError("ZEN_PUBLIC_HOST must be a hostname only")
    if len(host) > 253 or not _HOST_RE.fullmatch(host):
        raise SecureTransportConfigError("ZEN_PUBLIC_HOST is not a valid hostname")
    return host


def _allowed_hosts(value: Any) -> tuple[str, ...]:
    result: list[str] = []
    for raw in str(value or "").split(","):
        host = raw.strip().lower().rstrip(".")
        if not host:
            continue
        if host == "*":
            item = host
        elif host.startswith("*."):
            suffix = host[2:]
            if not suffix or not _HOST_RE.fullmatch(suffix):
                raise SecureTransportConfigError(f"Invalid wildcard allowed host: {raw!r}")
            item = host
        elif _HOST_RE.fullmatch(host) or host in {"localhost"} or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            item = host
        else:
            raise SecureTransportConfigError(f"Invalid allowed host: {raw!r}")
        if item not in result:
            result.append(item)
    return tuple(result)


def _host_is_allowed(public_host: str, allowed_hosts: tuple[str, ...]) -> bool:
    if not public_host:
        return False
    for candidate in allowed_hosts:
        if candidate == public_host:
            return True
        if candidate.startswith("*.") and public_host.endswith(candidate[1:]):
            return True
    return False


def _hsts_seconds(value: Any) -> int:
    try:
        seconds = int(str(value if value is not None else "31536000").strip())
    except (TypeError, ValueError) as exc:
        raise SecureTransportConfigError("ZEN_HSTS_MAX_AGE must be an integer") from exc
    if not 0 <= seconds <= 63_072_000:
        raise SecureTransportConfigError("ZEN_HSTS_MAX_AGE must be between 0 and 63072000")
    return seconds


@dataclass(frozen=True)
class SecureTransportConfig:
    remote_access_enabled: bool
    secure_cookies: bool
    public_host: str
    allowed_hosts: tuple[str, ...]
    cloudflare_access_protected: bool
    hsts_max_age: int

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any] | None = None) -> "SecureTransportConfig":
        source = os.environ if values is None else values
        return cls(
            remote_access_enabled=_bool(source.get("ZEN_REMOTE_ACCESS_ENABLED"), False),
            secure_cookies=_bool(source.get("ZEN_SECURE_COOKIES"), False),
            public_host=_public_host(source.get("ZEN_PUBLIC_HOST")),
            allowed_hosts=_allowed_hosts(source.get("ZEN_ALLOWED_HOSTS")),
            cloudflare_access_protected=_bool(source.get("ZEN_CLOUDFLARE_ACCESS_PROTECTED"), False),
            hsts_max_age=_hsts_seconds(source.get("ZEN_HSTS_MAX_AGE")),
        )

    @property
    def enforce_host_allowlist(self) -> bool:
        return bool(self.allowed_hosts and "*" not in self.allowed_hosts)

    def status(self, version: str) -> dict[str, Any]:
        if not self.remote_access_enabled:
            return {
                "schema": "zen_secure_transport_v1",
                "version": str(version),
                "state": "disabled",
                "remote_ready": False,
                "remote_access_enabled": False,
                "public_host": self.public_host or None,
                "secure_cookies": self.secure_cookies,
                "host_allowlist_enforced": self.enforce_host_allowlist,
                "cloudflare_access_protected": self.cloudflare_access_protected,
                "live_external_validation": "not_run",
                "checks": [],
                "evidence_boundary": (
                    "Local configuration only. Tunnel token, Access identity and household data are never exported."
                ),
            }

        checks = [
            {
                "key": "public_host",
                "state": "pass" if bool(self.public_host) else "fail",
                "summary": "Public HTTPS hostname configured" if self.public_host else "ZEN_PUBLIC_HOST is required",
            },
            {
                "key": "secure_cookie",
                "state": "pass" if self.secure_cookies else "fail",
                "summary": "ZEN session cookie is Secure" if self.secure_cookies else "ZEN_SECURE_COOKIES must be enabled",
            },
            {
                "key": "cloudflare_access",
                "state": "pass" if self.cloudflare_access_protected else "fail",
                "summary": (
                    "Operator confirms Cloudflare Access + Protect with Access are configured"
                    if self.cloudflare_access_protected
                    else "Cloudflare Access protection has not been confirmed"
                ),
            },
            {
                "key": "host_allowlist",
                "state": "pass" if (
                    self.enforce_host_allowlist
                    and _host_is_allowed(self.public_host, self.allowed_hosts)
                ) else "fail",
                "summary": (
                    "Explicit Host allowlist covers the public hostname"
                    if self.enforce_host_allowlist and _host_is_allowed(self.public_host, self.allowed_hosts)
                    else "ZEN_ALLOWED_HOSTS must explicitly cover the public hostname and may not be '*'"
                ),
            },
        ]
        remote_ready = all(item["state"] == "pass" for item in checks)
        return {
            "schema": "zen_secure_transport_v1",
            "version": str(version),
            "state": "ready_for_live_validation" if remote_ready else "blocked",
            "remote_ready": remote_ready,
            "remote_access_enabled": True,
            "public_host": self.public_host or None,
            "secure_cookies": self.secure_cookies,
            "host_allowlist_enforced": self.enforce_host_allowlist,
            "cloudflare_access_protected": self.cloudflare_access_protected,
            "hsts_max_age": self.hsts_max_age,
            "live_external_validation": "pending" if remote_ready else "not_run",
            "checks": checks,
            "evidence_boundary": (
                "Configuration readiness is not live Internet proof. Validate the unauthenticated Access challenge "
                "and an authenticated ZEN journey after the tunnel is started."
            ),
        }


def security_headers(config: SecureTransportConfig) -> dict[str, str]:
    """Return bounded response headers that do not alter application authority."""
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    if config.remote_access_enabled and config.secure_cookies and config.hsts_max_age > 0:
        headers["Strict-Transport-Security"] = f"max-age={config.hsts_max_age}"
    return headers
