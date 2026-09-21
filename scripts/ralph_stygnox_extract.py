#!/usr/bin/env python3
"""Deterministically materialize the D7.1 Stygnox extraction seed.

The seed is intentionally a compatibility-preserving physical extraction of the
D6-frozen controller, not the final standalone product.  It copies only the
frozen controller/test surface plus provenance and minimal repository scaffold.
No Git command, model call, network access, or source-repository mutation is
performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import ralph_equivalence
import ralph_ex_ready

SCHEMA = "stygnox_extraction_seed_v1"
MAX_DIFFERENCES = 64
D6_MANIFEST_SHA256 = ralph_ex_ready.FROZEN_MANIFEST_SHA256
D6_SOURCE_TREE_SHA256 = ralph_ex_ready.FROZEN_MANIFEST["baseline"]["source_tree_sha256"]
D5_EQUIVALENCE_SHA256 = ralph_equivalence.FROZEN_CONTRACT_SHA256

README_TEXT = """# Stygnox

Stygnox is being physically extracted from the D6-frozen RALPH-Lite controller.

This repository seed is the **D7.1 extraction baseline**, not a public release.
It deliberately preserves the frozen controller and tests byte-for-byte so the
subsequent extraction stages can change structure behind behavioral-equivalence
checks rather than reimplementing behavior from memory.

## Current status

- D6 source/controller contract: frozen and provenance-bound.
- D5 behavioral-equivalence reference: included as extraction provenance.
- Controller implementation/tests: copied from the frozen source without edits.
- Product/package/API rename: not performed yet.
- Persisted `zen_ralph_*` schemas: retained as compatibility obligations.
- `.ralph` runtime/policy naming and `ZEN_PROFILE`: retained temporarily as
  known compatibility seams, not adopted as Stygnox product identity.

The next stages introduce the standalone protocol/core/runtime boundaries and
then replace the temporary host adapter without silently migrating persisted
state.
"""

GITIGNORE_TEXT = """__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.venv/
venv/
.DS_Store

# Runtime state stays local. The compatibility policy remains tracked during
# extraction until the standalone runtime boundary replaces it.
.ralph/*
!.ralph/policy.md
.stygnox/
"""

SUPPORT_FILES = {
    ".ralph/policy.md": "9d9fa1b732abb7006a7ffb506da7e265c419632ae76e352cf7034500fdb42320",
    "LICENSE": "5132c7f0475b02c8107a2e0f0363e70423c62d2664ab927e76193226e5e05905",
    "tests/__init__.py": "5689d11018f46576627d8e9fc9b4f937787743d90918b34b483d7303006d51b2",
}

KNOWN_COMPATIBILITY_SEAMS = [
    "ZEN_PROFILE remains the frozen host adapter during the extraction seed stage",
    ".ralph remains the frozen runtime/policy directory during the extraction seed stage",
    "zen_ralph_* persisted schemas remain compatibility obligations and are not renamed in D7.1",
    "RALPH-Lite module/CLI names remain compatibility names until later D7 stages",
]


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _frozen_source_map() -> dict[str, str]:
    inventory = ralph_ex_ready.FROZEN_MANIFEST["inventory"]
    result: dict[str, str] = {}
    result.update(inventory["controller_sources"])
    result.update(inventory["controller_tests"])
    return dict(sorted(result.items()))


def _generated_files() -> dict[str, bytes]:
    return {
        ".gitignore": GITIGNORE_TEXT.encode("utf-8"),
        "README.md": README_TEXT.encode("utf-8"),
        "provenance/d5-behavioral-equivalence.json": canonical_bytes(ralph_equivalence.FROZEN_CONTRACT) + b"\n",
        "provenance/d6-ex-ready-manifest.json": canonical_bytes(ralph_ex_ready.FROZEN_MANIFEST) + b"\n",
    }


def seed_manifest(source_root: Path = ROOT) -> dict[str, Any]:
    frozen = _frozen_source_map()
    copied: dict[str, str] = dict(frozen)
    copied.update(SUPPORT_FILES)
    generated = {path: sha256_bytes(data) for path, data in _generated_files().items()}
    return {
        "schema": SCHEMA,
        "source": {
            "d6_manifest_sha256": D6_MANIFEST_SHA256,
            "d6_source_tree_sha256": D6_SOURCE_TREE_SHA256,
            "d5_behavioral_equivalence_sha256": D5_EQUIVALENCE_SHA256,
        },
        "content": {
            "copied_files": dict(sorted(copied.items())),
            "generated_files": dict(sorted(generated.items())),
        },
        "constraints": {
            "known_compatibility_seams": list(KNOWN_COMPATIBILITY_SEAMS),
            "not_yet_performed": [
                "standalone protocol extraction",
                "core/runtime package split",
                "Stygnox CLI/Web rename",
                "ZEN adapter extraction",
                "persisted-schema migration",
                "embedded RALPH removal from ZEN Control",
            ],
        },
    }


def seed_manifest_sha256(source_root: Path = ROOT) -> str:
    return sha256_bytes(canonical_bytes(seed_manifest(source_root)))


def _target_is_inside_source(target: Path, source_root: Path = ROOT) -> bool:
    source = source_root.resolve()
    candidate = target.resolve()
    return candidate == source or source in candidate.parents


def _copy_exact(source_root: Path, target_root: Path, relative: str, expected_sha256: str) -> None:
    source = source_root / relative
    if not source.is_file():
        raise RuntimeError(f"source file missing: {relative}")
    actual = sha256_file(source)
    if actual != expected_sha256:
        raise RuntimeError(f"source drift: {relative}: sha256 {actual} != {expected_sha256}")
    target = target_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def materialize(target_root: Path, source_root: Path = ROOT) -> dict[str, Any]:
    target_root = target_root.resolve()
    if _target_is_inside_source(target_root, source_root):
        raise RuntimeError("refusing to materialize Stygnox seed inside the source repository")
    if target_root.exists() and any(target_root.iterdir()):
        raise RuntimeError(f"output directory is not empty: {target_root}")

    preflight = ralph_ex_ready.validation_result(source_root)
    if not preflight["ok"] or preflight["manifest_sha256"] != D6_MANIFEST_SHA256:
        raise RuntimeError(f"D6 EX-READY preflight failed: {preflight['differences']}")
    eq_differences = ralph_equivalence.compare(ralph_equivalence.wrap(ralph_equivalence.observe_contract()))
    if eq_differences:
        raise RuntimeError(f"D5 behavioral-equivalence preflight failed: {eq_differences}")

    manifest = seed_manifest(source_root)
    target_root.mkdir(parents=True, exist_ok=True)
    for relative, expected in manifest["content"]["copied_files"].items():
        _copy_exact(source_root, target_root, relative, expected)
    for relative, data in _generated_files().items():
        path = target_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    provenance = target_root / "provenance/stygnox-extraction-seed.json"
    provenance.write_bytes(canonical_bytes(manifest) + b"\n")
    return manifest


def differences(target_root: Path, source_root: Path = ROOT) -> list[str]:
    expected = seed_manifest(source_root)
    found: list[str] = []
    expected_files = dict(expected["content"]["copied_files"])
    expected_files.update(expected["content"]["generated_files"])
    expected_files["provenance/stygnox-extraction-seed.json"] = sha256_bytes(canonical_bytes(expected) + b"\n")
    for relative, digest in sorted(expected_files.items()):
        path = target_root / relative
        if not path.is_file():
            found.append(f"$.files.{relative}: missing")
        else:
            actual = sha256_file(path)
            if actual != digest:
                found.append(f"$.files.{relative}: sha256 {actual} != {digest}")
        if len(found) >= MAX_DIFFERENCES:
            return found

    actual_files = {
        path.relative_to(target_root).as_posix()
        for path in target_root.rglob("*")
        if path.is_file()
    }
    unexpected = sorted(actual_files - set(expected_files))
    for relative in unexpected:
        found.append(f"$.files.{relative}: unexpected")
        if len(found) >= MAX_DIFFERENCES:
            return found
    return found


def validation_result(target_root: Path, source_root: Path = ROOT) -> dict[str, Any]:
    issues = differences(target_root, source_root)
    return {
        "schema": SCHEMA,
        "ok": not issues,
        "seed_manifest_sha256": seed_manifest_sha256(source_root),
        "d6_manifest_sha256": D6_MANIFEST_SHA256,
        "d5_behavioral_equivalence_sha256": D5_EQUIVALENCE_SHA256,
        "differences": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--manifest", action="store_true", help="emit the canonical seed manifest")
    action.add_argument("--write", metavar="DIR", help="materialize a new extraction seed directory")
    action.add_argument("--validate", metavar="DIR", help="validate an existing extraction seed directory")
    args = parser.parse_args(argv)

    if args.manifest:
        print(canonical_bytes(seed_manifest()).decode("utf-8"))
        return 0
    if args.write:
        target = Path(args.write)
        manifest = materialize(target)
        result = validation_result(target)
        print(json.dumps({**result, "output": str(target.resolve()), "files": len(manifest["content"]["copied_files"]) + len(manifest["content"]["generated_files"]) + 1}, sort_keys=True, separators=(",", ":")))
        return 0 if result["ok"] else 1
    target = Path(args.validate)
    result = validation_result(target)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
