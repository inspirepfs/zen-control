"""Deterministic RouterOS contracts for explicitly provisioned custom services.

Custom service metadata is useful for telemetry without RouterOS authority.  This
module turns an operator-approved custom service into a narrow, app-owned contract
whose ownership can be proven from deterministic names/comments.  It deliberately
never creates logical-group rules or reuses the manually-owned RWxx namespace.
"""

import re


CUSTOM_SERVICE_COMMENT_PREFIX = "MC|SVC|"
CUSTOM_SERVICE_CONTRACT_VERSION = 1


def _service_token(key: str) -> str:
    parts = [part for part in re.split(r"[^a-z0-9]+", str(key or "").lower()) if part]
    if not parts:
        raise ValueError("Custom service key is required for RouterOS provisioning")
    token = "".join(part[:1].upper() + part[1:] for part in parts)
    if len(token) > 48:
        raise ValueError("Custom service key is too long for deterministic RouterOS names")
    return token


def build_custom_service_contract(service: dict) -> dict:
    """Build the exact RouterOS contract for one custom service definition."""
    if not service or service.get("builtin"):
        raise ValueError("Only custom services can use managed custom provisioning")

    key = str(service.get("key") or "").strip().lower()
    name = str(service.get("name") or key).strip()
    tls_patterns = [
        str(value or "").strip().lower()
        for value in (service.get("tls_patterns") or [])
        if str(value or "").strip()
    ]
    if not tls_patterns:
        raise ValueError(
            "Custom RouterOS enforcement requires at least one TLS/SNI pattern; "
            "DNS-only services remain reporting-only"
        )
    if len(tls_patterns) > 40:
        raise ValueError("Custom RouterOS enforcement supports at most 40 TLS/SNI patterns")

    token = _service_token(key)
    source_list = f"MC_Block_{token}"
    detector_list = f"MC_Detected_{token}"
    comment_prefix = f"{CUSTOM_SERVICE_COMMENT_PREFIX}{key}|"

    return {
        "key": key,
        "name": name,
        "classification": "TLS/SNI",
        "category": str(service.get("category") or "other"),
        "dns_suffixes": list(service.get("dns_suffixes") or []),
        "tls_patterns": tls_patterns,
        "coverage_note": (
            "Operator-approved custom TLS/SNI contract. DNS/IPFIX classification remains "
            "evidence-led and may have broader coverage than RouterOS TLS enforcement."
        ),
        "source_list": source_list,
        "detector_lists": [detector_list],
        "rules": [
            {
                "comment": comment_prefix + "BLOCK|01",
                "detector_list": detector_list,
            }
        ],
        "learners": [
            {
                "comment": comment_prefix + f"LEARN|{index:02d}",
                "address_list": detector_list,
                "tls_host": pattern,
            }
            for index, pattern in enumerate(tls_patterns, 1)
        ],
        "managed_custom": True,
        "ownership_prefix": comment_prefix,
        "contract_version": CUSTOM_SERVICE_CONTRACT_VERSION,
    }
