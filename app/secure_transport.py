"""Secure transport, local HTTPS and optional remote-access configuration.

This module owns only the browser/web transport boundary. It does not create
Cloudflare resources, does not validate or persist tunnel/DNS tokens, and has
no RouterOS, reconciliation or policy-mutation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any
import ipaddress
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


def _hostname(value: Any, *, variable: str, allow_empty: bool = True) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not host and allow_empty:
        return ""
    if any(token in host for token in ("://", "/", "\\", ":", "*", "?", "#")):
        raise SecureTransportConfigError(f"{variable} must be a hostname only")
    if len(host) > 253 or not _HOST_RE.fullmatch(host):
        raise SecureTransportConfigError(f"{variable} is not a valid hostname")
    return host


def _public_host(value: Any) -> str:
    return _hostname(value, variable="ZEN_PUBLIC_HOST")


def _local_host(value: Any) -> str:
    return _hostname(value, variable="ZEN_LOCAL_HOST")


def _bind_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise SecureTransportConfigError("ZEN_LAN_BIND_IP must be a valid IP address") from exc


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
        elif _HOST_RE.fullmatch(host) or host in {"localhost"}:
            item = host
        else:
            try:
                item = str(ipaddress.ip_address(host))
            except ValueError as exc:
                raise SecureTransportConfigError(f"Invalid allowed host: {raw!r}") from exc
        if item not in result:
            result.append(item)
    return tuple(result)


def _host_is_allowed(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    if not host:
        return False
    for candidate in allowed_hosts:
        if candidate == host:
            return True
        if candidate.startswith("*.") and host.endswith(candidate[1:]):
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
    local_host: str
    lan_bind_ip: str
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
            local_host=_local_host(source.get("ZEN_LOCAL_HOST")),
            lan_bind_ip=_bind_ip(source.get("ZEN_LAN_BIND_IP")),
            allowed_hosts=_allowed_hosts(source.get("ZEN_ALLOWED_HOSTS")),
            cloudflare_access_protected=_bool(source.get("ZEN_CLOUDFLARE_ACCESS_PROTECTED"), False),
            hsts_max_age=_hsts_seconds(source.get("ZEN_HSTS_MAX_AGE")),
        )

    @property
    def enforce_host_allowlist(self) -> bool:
        return bool(self.allowed_hosts and "*" not in self.allowed_hosts)

    @property
    def local_configured(self) -> bool:
        return bool(self.local_host and self.lan_bind_ip)

    def _local_status(self) -> dict[str, Any]:
        checks = [
            {
                "key": "local_host",
                "state": "pass" if bool(self.local_host) else "fail",
                "summary": "Local HTTPS hostname configured" if self.local_host else "ZEN_LOCAL_HOST is required",
            },
            {
                "key": "lan_bind_ip",
                "state": "pass" if bool(self.lan_bind_ip) else "fail",
                "summary": "LAN HTTPS bind IP configured" if self.lan_bind_ip else "ZEN_LAN_BIND_IP is required",
            },
            {
                "key": "secure_cookie",
                "state": "pass" if self.secure_cookies else "fail",
                "summary": "ZEN session cookie is Secure" if self.secure_cookies else "Enable ZEN_SECURE_COOKIES after HTTPS validation",
            },
            {
                "key": "host_allowlist",
                "state": "pass" if (
                    self.enforce_host_allowlist and _host_is_allowed(self.local_host, self.allowed_hosts)
                ) else "fail",
                "summary": (
                    "Explicit Host allowlist covers the local HTTPS hostname"
                    if self.enforce_host_allowlist and _host_is_allowed(self.local_host, self.allowed_hosts)
                    else "ZEN_ALLOWED_HOSTS must explicitly cover ZEN_LOCAL_HOST and may not be '*'"
                ),
            },
        ]
        configured = bool(self.local_host and self.lan_bind_ip)
        hardened = configured and all(item["state"] == "pass" for item in checks[2:])
        return {
            "state": "ready_for_live_validation" if hardened else ("configuration_incomplete" if configured else "blocked"),
            "configured": configured,
            "hardened": hardened,
            "host": self.local_host or None,
            "bind_ip": self.lan_bind_ip or None,
            "url": f"https://{self.local_host}/" if self.local_host else None,
            "checks": checks,
            "live_validation": "pending" if hardened else "not_run",
        }

    def _remote_status(self) -> dict[str, Any]:
        if not self.remote_access_enabled:
            return {
                "state": "disabled",
                "enabled": False,
                "ready": False,
                "public_host": self.public_host or None,
                "checks": [],
                "live_validation": "not_run",
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
                    self.enforce_host_allowlist and _host_is_allowed(self.public_host, self.allowed_hosts)
                ) else "fail",
                "summary": (
                    "Explicit Host allowlist covers the public hostname"
                    if self.enforce_host_allowlist and _host_is_allowed(self.public_host, self.allowed_hosts)
                    else "ZEN_ALLOWED_HOSTS must explicitly cover the public hostname and may not be '*'"
                ),
            },
        ]
        ready = all(item["state"] == "pass" for item in checks)
        return {
            "state": "ready_for_live_validation" if ready else "blocked",
            "enabled": True,
            "ready": ready,
            "public_host": self.public_host or None,
            "url": f"https://{self.public_host}/" if self.public_host else None,
            "checks": checks,
            "live_validation": "pending" if ready else "not_run",
        }

    def status(self, version: str) -> dict[str, Any]:
        local = self._local_status()
        remote = self._remote_status()
        remote_ok = (not self.remote_access_enabled) or bool(remote["ready"])
        commissioning_ready = bool(local["hardened"] and remote_ok)
        pwa_secure_origin_ready = bool(local["configured"] or remote["ready"])

        if commissioning_ready:
            state = "ready_for_live_validation"
        elif local["configured"]:
            state = "configuration_incomplete"
        else:
            state = "blocked"

        return {
            "schema": "zen_secure_transport_v2",
            "version": str(version),
            "state": state,
            "commissioning_ready": commissioning_ready,
            "remote_ready": bool(remote["ready"]),
            "remote_access_enabled": self.remote_access_enabled,
            "public_host": self.public_host or None,
            "local_host": self.local_host or None,
            "lan_bind_ip": self.lan_bind_ip or None,
            "secure_cookies": self.secure_cookies,
            "host_allowlist_enforced": self.enforce_host_allowlist,
            "cloudflare_access_protected": self.cloudflare_access_protected,
            "hsts_max_age": self.hsts_max_age,
            "local_https": local,
            "remote_access": remote,
            "pwa": {
                "secure_origin_configured": pwa_secure_origin_ready,
                "state": "ready_for_browser_validation" if pwa_secure_origin_ready else "blocked",
                "browser_validation": "pending" if pwa_secure_origin_ready else "not_run",
                "requirements": [
                    "HTTPS origin",
                    "service worker registration",
                    "standalone installability",
                    "browser notification permission for push",
                ],
            },
            "live_external_validation": "pending" if commissioning_ready else "not_run",
            "checks": local["checks"] + (remote["checks"] if self.remote_access_enabled else []),
            "evidence_boundary": (
                "Configuration readiness is not live HTTPS, certificate, Cloudflare Access or browser/PWA proof. "
                "Use the host acceptance tools and an authenticated browser journey before declaring commissioning complete."
            ),
        }


def security_headers(config: SecureTransportConfig) -> dict[str, str]:
    """Return bounded browser-security headers without changing application authority."""
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    # Browsers ignore HSTS received over plain HTTP. Emitting it whenever the
    # operator has deliberately switched sessions to Secure therefore hardens
    # both the local Caddy HTTPS path and optional public HTTPS path without
    # trusting spoofable forwarded-proto headers from the directly exposed app.
    if config.secure_cookies and config.hsts_max_age > 0 and (config.local_configured or config.remote_access_enabled):
        headers["Strict-Transport-Security"] = f"max-age={config.hsts_max_age}"
    return headers
