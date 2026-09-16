"""Deterministic service classifier used by telemetry ingest.

ZEN Control publishes the live Policy -> Services catalogue to a shared JSON
file. The ingest process reloads that file when it changes, so newly-added
services begin classifying Pi-hole DNS evidence without an image rebuild.

Fallback is bootstrap/recovery-only: once a valid live catalogue has been
observed, a transient missing/malformed replacement retains the last known-good
live classifier instead of silently switching classification authority back to
built-in defaults. A valid live catalogue with zero DNS signatures is also
valid and deliberately classifies nothing.

``classify_record`` is the evidence-preserving classification entry point. Its
precedence is fixed: manual override, RouterOS detector address-list, DNS
suffix, flow-domain suffix, protocol/port signature, then unknown fallback.
Lower-precedence evidence never replaces a higher-precedence classification.
``classify_domain`` remains the compact DNS-only compatibility API used by the
existing ingest loop.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

SERVICE_CATALOG_FILE = os.getenv("SERVICE_CATALOG_FILE", "/control-data/service-catalog.json")

# The source order is public data as well as documentation, allowing callers
# to show the same deterministic resolution rule as the classifier.
CLASSIFICATION_PRECEDENCE = (
    "manual_override",
    "address_list",
    "dns",
    "flow",
    "port",
    "fallback",
)

_BUILTIN_METADATA = {
    "youtube": {"category": "video", "address_lists": ("Detected_YouTube", "Detected_GoogleVideo")},
    "netflix": {"category": "video", "address_lists": ("Detected_Netflix",)},
    "prime video": {"category": "video", "address_lists": ("Detected_PrimeVideo",)},
    "prime_video": {"category": "video", "address_lists": ("Detected_PrimeVideo",)},
    "bbc iplayer": {"category": "video", "address_lists": ("Detected_BBCiPlayer",)},
    "bbc_iplayer": {"category": "video", "address_lists": ("Detected_BBCiPlayer",)},
    "chatgpt": {"category": "ai", "address_lists": ("Detected_ChatGPT",)},
    "openai": {"category": "ai", "address_lists": ("Detected_OpenAI",)},
    "tiktok": {"category": "social", "address_lists": ("Detected_TikTok",)},
    "discord": {"category": "social", "address_lists": ("Detected_Discord",)},
    "roblox": {"category": "gaming", "address_lists": ("Detected_Roblox",)},
    "steam": {"category": "gaming", "address_lists": ("Detected_Steam",)},
    "xbox": {"category": "gaming", "address_lists": ("Detected_Xbox",)},
    "playstation": {"category": "gaming", "address_lists": ("Detected_PlayStation",)},
}

# Port signatures are intentionally narrow and always low confidence.
_PORT_SIGNATURES = {
    ("UDP", 3074): {"service": "Xbox", "category": "gaming", "key": "xbox"},
}

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
    "service_definitions": [],
}


def _normalize_suffix(value):
    value = str(value or "").strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def _service_definition(entry):
    name = str(entry.get("name") or entry.get("key") or "").strip()
    key = str(entry.get("key") or name).strip().lower()
    builtin = _BUILTIN_METADATA.get(key) or _BUILTIN_METADATA.get(name.lower()) or {}
    address_lists = entry.get("address_lists", entry.get("detector_lists", builtin.get("address_lists", ())))
    if isinstance(address_lists, str):
        address_lists = [address_lists]
    if not isinstance(address_lists, (list, tuple)):
        address_lists = []
    return {
        "key": key,
        "service": name,
        "category": str(entry.get("category") or builtin.get("category") or "other"),
        "address_lists": tuple(str(value).strip() for value in address_lists if str(value).strip()),
    }


def _compile(entries):
    if not isinstance(entries, list):
        raise ValueError("Service catalogue 'services' must be a list")
    compiled = []
    definitions = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Service catalogue entries must be objects")
        definition = _service_definition(entry)
        if not definition["service"]:
            continue
        definitions.append(definition)
        suffixes = entry.get("dns_suffixes") or []
        if not isinstance(suffixes, list):
            raise ValueError("Service catalogue dns_suffixes must be a list")
        for raw in suffixes:
            suffix = _normalize_suffix(raw)
            if suffix:
                compiled.append((suffix, definition))
    # Longest suffix wins if a broad and narrow signature overlap.
    compiled.sort(key=lambda item: (-len(item[0]), item[0], item[1]["service"]))
    return compiled, definitions


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
    compiled, definitions = _compile(services)
    return compiled, len(services), definitions


def _load_if_needed():
    path = Path(SERVICE_CATALOG_FILE)
    fingerprint = _fingerprint(path)

    with _lock:
        if _state["domains"] is not None and _state["fingerprint"] == fingerprint:
            return _state["domains"]

        if fingerprint is not None:
            try:
                compiled, service_count, definitions = _load_live(path)
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
                    "service_definitions": definitions,
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

        compiled, definitions = _fallback_compiled()
        _state.update({
            "fingerprint": fingerprint,
            "domains": compiled,
            "source": "fallback",
            "services": len(_FALLBACK),
            "error": error,
            "has_live": False,
            "service_definitions": definitions,
        })
        return compiled


def classify_domain(domain):
    domain = str(domain or "").lower().rstrip(".")
    if not domain:
        return ""
    for suffix, service in _load_if_needed():
        if domain == suffix or domain.endswith("." + suffix):
            return service["service"]
    return ""


def _precedence(source):
    return CLASSIFICATION_PRECEDENCE.index(source)


def _result(service, *, source, matched_value, confidence):
    """Return the stable, evidence-complete public classification shape."""
    return {
        "category": str(service.get("category") or "other"),
        "service": str(service.get("service") or "Unknown"),
        "confidence": confidence,
        "evidence": {
            "source": source,
            "matched_value": matched_value,
            "precedence": _precedence(source),
        },
    }


def _unknown_result():
    return {
        "category": "unknown",
        "service": "Unknown",
        "confidence": "none",
        "evidence": {
            "source": "fallback",
            "matched_value": None,
            "precedence": "fallback",
        },
    }


def _find_service(value, definitions):
    value = str(value or "").strip().lower()
    for definition in definitions:
        if value in (definition["key"].lower(), definition["service"].lower()):
            return definition
    return None


def _domain_match(domain, compiled):
    domain = _normalize_suffix(domain)
    if not domain:
        return None, None
    for suffix, service in compiled:
        if domain == suffix or domain.endswith("." + suffix):
            return service, suffix
    return None, None


def _signal_domain(signal):
    return signal.get("domain") if isinstance(signal, dict) else signal


def _manual_service(signal, definitions):
    if not signal:
        return None, None
    if isinstance(signal, dict):
        matched = signal.get("service") or signal.get("name") or signal.get("key")
        service = _find_service(matched, definitions)
        if service is None and matched:
            service = {
                "key": str(signal.get("key") or matched).strip().lower(),
                "service": str(matched).strip(),
                "category": str(signal.get("category") or "other"),
            }
        return service, matched
    service = _find_service(signal, definitions)
    if service is None and str(signal).strip():
        service = {
            "key": str(signal).strip().lower(),
            "service": str(signal).strip(),
            "category": "other",
        }
    return service, signal


def classify_record(signals, *, services=None):
    """Classify one record using the documented evidence precedence.

    ``signals`` is a plain mapping so collectors can supply only observed
    evidence. ``services`` optionally supplies a catalogue-shaped list for
    deterministic offline callers; normal ingest uses the current catalogue.
    """
    signals = dict(signals or {})
    if services is None:
        compiled = _load_if_needed()
        with _lock:
            definitions = list(_state["service_definitions"])
    else:
        compiled, definitions = _compile(list(services or []))

    manual = signals.get("manual_override", signals.get("manual"))
    service, matched = _manual_service(manual, definitions)
    if service:
        return _result(service, source="manual_override", matched_value=matched, confidence="high")

    address_lists = signals.get("address_list", signals.get("address_lists", []))
    if isinstance(address_lists, str):
        address_lists = [address_lists]
    for address_list in address_lists or []:
        normalized = str(address_list).strip().lower()
        for definition in definitions:
            if normalized in {item.lower() for item in definition.get("address_lists", ())}:
                return _result(definition, source="address_list", matched_value=address_list, confidence="high")

    service, matched = _domain_match(_signal_domain(signals.get("dns")), compiled)
    if service:
        return _result(service, source="dns", matched_value=matched, confidence="high")

    flow = signals.get("flow") or {}
    service, matched = _domain_match(_signal_domain(flow), compiled)
    if service:
        return _result(service, source="flow", matched_value=matched, confidence="medium")

    port = signals.get("port") or {}
    protocol = str(port.get("protocol", flow.get("protocol", ""))).strip().upper()
    number = port.get("number", port.get("destination_port", port.get("dst_port", flow.get("destination_port", flow.get("dst_port")))))
    try:
        number = int(number)
    except (TypeError, ValueError):
        number = 0
    service = _PORT_SIGNATURES.get((protocol, number))
    if service:
        return _result(service, source="port", matched_value=f"{protocol}/{number}", confidence="low")

    return _unknown_result()


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
