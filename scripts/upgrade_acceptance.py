#!/usr/bin/env python3
"""Offline SQLite upgrade/restore acceptance for ZEN Control.

The supplied database is never modified. Acceptance copies it to a temporary
restore target, opens that copy through the current PolicyStore migration path,
then reopens it to prove migration idempotency and retained row counts.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.policy_store import PolicyStore
from app.upgrade_safety import SCHEMA_RELEASE, SCHEMA_VERSION, inspect_database, validate_database


def probe(path: str | Path, *, expect_schema: int = SCHEMA_VERSION) -> dict:
    source = Path(path)
    before = validate_database(source)
    with tempfile.TemporaryDirectory(prefix="zen-upgrade-acceptance-") as td:
        restored = Path(td) / "restored-policy.db"
        shutil.copy2(source, restored)
        first = PolicyStore(str(restored))
        first_integrity = first.database_integrity_report()
        first_schema = first.schema_status()
        after_first = inspect_database(restored)

        second = PolicyStore(str(restored))
        second_integrity = second.database_integrity_report()
        second_schema = second.schema_status()
        after_second = inspect_database(restored)

    retained = {
        table: {
            "before": int(count),
            "after": int(after_first["table_counts"].get(table, 0)),
            "ok": int(after_first["table_counts"].get(table, 0)) >= int(count),
        }
        for table, count in before["table_counts"].items()
    }
    retained_ok = all(row["ok"] for row in retained.values())
    idempotent = (
        after_first["version"] == after_second["version"]
        and after_first["table_counts"] == after_second["table_counts"]
        and len(second_schema.get("migrations") or []) == len(first_schema.get("migrations") or [])
        and (second_schema.get("upgrade") or {}).get("state") == "unchanged"
    )
    ok = bool(
        first_integrity.get("ok")
        and second_integrity.get("ok")
        and int(first_schema.get("version") or 0) == int(expect_schema)
        and int(second_schema.get("version") or 0) == int(expect_schema)
        and retained_ok
        and idempotent
    )
    return {
        "schema": "zen_upgrade_acceptance_v1",
        "state": "pass" if ok else "fail",
        "authority": "sqlite-upgrade-observation-only-no-routeros-authority",
        "source": {
            "schema_version": before["version"],
            "tables": len(before["tables"]),
            "quick_check": before["quick_check"],
            "foreign_key_violations": before["foreign_key_violations"],
        },
        "upgrade": {
            "expected_schema": int(expect_schema),
            "release": SCHEMA_RELEASE,
            "first_open_schema": first_schema.get("version"),
            "first_open_state": (first_schema.get("upgrade") or {}).get("state"),
            "second_open_schema": second_schema.get("version"),
            "second_open_state": (second_schema.get("upgrade") or {}).get("state"),
            "integrity": bool(first_integrity.get("ok") and second_integrity.get("ok")),
            "retained_counts": retained_ok,
            "idempotent_reopen": idempotent,
        },
        "retained": retained,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove an offline ZEN policy.db can be restored and upgraded safely.")
    parser.add_argument("database", help="SQLite policy database or verified backup. The file is never modified.")
    parser.add_argument("--expect-schema", type=int, default=SCHEMA_VERSION)
    args = parser.parse_args()
    try:
        report = probe(args.database, expect_schema=args.expect_schema)
    except Exception as exc:
        report = {
            "schema": "zen_upgrade_acceptance_v1",
            "state": "fail",
            "authority": "sqlite-upgrade-observation-only-no-routeros-authority",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("state") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
