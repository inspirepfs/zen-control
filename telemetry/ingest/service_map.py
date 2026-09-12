"""Dynamic DNS-to-service classifier used by telemetry ingest.

ZEN Control publishes the live Policy -> Services catalogue to a shared JSON
file. The ingest process reloads that file when it changes, so newly-added
services begin classifying Pi-hole DNS evidence without an image rebuild.

Fallback is bootstrap/recovery-only: once a valid live catalogue has been
observed, a transient missing/malformed replacement retains the last known-good
live classifier instead of silently switching classification authority back to
built-in defaults. A valid live catalogue with zero DNS signatures is also
valid and deliberately classifies nothing.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

SERVICE_CATALOG_FILE = os.getenv("SERVICE_CATALOG_FILE", "/control-data/service-catalog.json")

_FALLBACK = {
    "YouTube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com"],
    "Netflix": ["netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxso.net"],
    "Prime Video": ["primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net"],
    "BBC iPlayer": ["bbc.co.uk", "bbc.com", "bbci.co.uk", "bbcmedia.co.uk", "bbcmedia.net"],
    "ChatGPT": ["chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    "OpenAI": ["openai.com"],
    "TikTok": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "muscdn.com", "musical.ly"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net"],
    "Roblox": ["roblox.com", "rbxcdn.com"],
    "Steam": ["steampowered.com", "steamcommunity.com", "steamcontent.com", "steamstatic.com"],
    "Xbox": ["xboxlive.com", "xbox.com", "xboxservices.com"],
    "PlayStation": ["playstation.net", "playstation.com", "sonyentertainmentnetwork.com"],
}

_lock = threading.Lock()
_state = {
    "fingerprint": object(),
    "domains": None,
    "source": "fallback",
    "services": 0,
    "error": "",
    "has_live": False,
}


def _normalize_suffix(value):
    value = str(value or "").strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def _compile(entries):
    if not isinstance(entries, list):
        raise ValueError("Service catalogue 'services' must be a list")
    compiled = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Service catalogue entries must be objects")
        name = str(entry.get("name") or entry.get("key") or "").strip()
        if not name:
            continue
        suffixes = entry.get("dns_suffixes") or []
        if not isinstance(suffixes, list):
            raise ValueError("Service catalogue dns_suffixes must be a list")
        for raw in suffixes:
            suffix = _normalize_suffix(raw)
            if suffix:
                compiled.append((suffix, name))
    # Longest suffix wins if a broad and narrow signature overlap.
    compiled.sort(key=lambda item: (-len(item[0]), item[0], item[1]))
    return compiled


def _fallback_compiled():
    return _compile([{"name": name, "dns_suffixes": suffixes} for name, suffixes in _FALLBACK.items()])


def _fingerprint(path: Path):
    try:
        stat = path.stat()
    except OSError:
        return None
    # ZEN publishes with os.replace(), so inode identity makes rapid atomic
    # replacements observable even on filesystems with coarse mtime resolution.
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _load_live(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Service catalogue root must be an object")
    version = payload.get("version", 1)
    if version != 1:
        raise ValueError(f"Unsupported service catalogue version: {version}")
    services = payload.get("services")
    if services is None:
        services = []
    compiled = _compile(services)
    return compiled, len(services)


def _load_if_needed():
    path = Path(SERVICE_CATALOG_FILE)
    fingerprint = _fingerprint(path)

    with _lock:
        if _state["domains"] is not None and _state["fingerprint"] == fingerprint:
            return _state["domains"]

        if fingerprint is not None:
            try:
                compiled, service_count = _load_live(path)
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                error = f"{type(exc).__name__}: {exc}"
            else:
                _state.update({
                    "fingerprint": fingerprint,
                    "domains": compiled,
                    "source": "live",
                    "services": service_count,
                    "error": "",
                    "has_live": True,
                })
                return compiled
        else:
            error = "Service catalogue file is unavailable"

        if _state["has_live"] and _state["domains"] is not None:
            # Never replace established live classification authority with the
            # built-in bootstrap map merely because the next publication cannot
            # currently be trusted. Keep last-known-good data and surface staleness.
            _state.update({
                "fingerprint": fingerprint,
                "source": "stale_live",
                "error": error,
            })
            return _state["domains"]

        compiled = _fallback_compiled()
        _state.update({
            "fingerprint": fingerprint,
            "domains": compiled,
            "source": "fallback",
            "services": len(_FALLBACK),
            "error": error,
            "has_live": False,
        })
        return compiled


def classify_domain(domain):
    domain = str(domain or "").lower().rstrip(".")
    if not domain:
        return ""
    for suffix, service in _load_if_needed():
        if domain == suffix or domain.endswith("." + suffix):
            return service
    return ""


def classifier_status():
    _load_if_needed()
    with _lock:
        return {
            "source": _state["source"],
            "services": _state["services"],
            "signatures": len(_state["domains"] or []),
            "catalog_file": SERVICE_CATALOG_FILE,
            "error": _state["error"],
            "has_live": bool(_state["has_live"]),
        }
