#!/usr/bin/env python3
"""Apply, qualify, publish, watch and tag a ZEN release patch.

The workflow is intentionally fail-closed around source state and CI:

1. exact dry-run + apply of a -p0 patch;
2. source/host validation;
3. topology-aware affected-service rebuild + app/runtime/topology health proof;
4. Git stage/check/commit/push;
5. wait for the GitHub Actions workflow attached to the pushed commit;
6. create and push an annotated tag only after CI succeeds.

Use --resume when the patch is already applied and the working tree contains
only the release changes you intend to publish.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
from datetime import datetime, timezone
import urllib.request
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
PATCH_BAD_OUTPUT = re.compile(r"\b(?:offset|fuzz|reversed|previously applied|failed)\b", re.IGNORECASE)

SERVICE_PATH_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("mikrotik-control", ("app/", "Dockerfile", "requirements.txt")),
    ("traffic-ingest", ("telemetry/ingest/",)),
    ("goflow2", ("telemetry/goflow2/",)),
    ("zen-local-https", ("deploy/caddy/",)),
)
ONE_SHOT_SERVICES = {"flow-pipe-init"}
POLICY_SERVICE = "mikrotik-control"
POLICY_DB_CONTAINER_PATH = "/data/policy.db"
POLICY_SCHEMA_VERSION = 570


class WorkflowError(RuntimeError):
    """Release workflow failed closed."""


def _print_command(cmd: Sequence[str]) -> None:
    print(f"+ {shlex.join([str(part) for part in cmd])}", flush=True)


def run(
    cmd: Sequence[str],
    *,
    capture: bool = False,
    check: bool = True,
    quiet: bool = False,
    dry_run: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [str(part) for part in cmd]
    _print_command(cmd)
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, "", "")
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE if capture or quiet else None,
        stderr=subprocess.STDOUT if capture or quiet else None,
        check=False,
    )
    if not quiet and capture and proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if check and proc.returncode != 0:
        detail = f"\n{proc.stdout}" if proc.stdout else ""
        raise WorkflowError(f"command failed ({proc.returncode}): {shlex.join(cmd)}{detail}")
    return proc


def resolve_patch(value: str | None) -> Path:
    if not value:
        raise WorkflowError("--patch is required unless --resume is used")
    candidate = Path(value).expanduser()
    options = [candidate]
    if not candidate.is_absolute():
        options = [ROOT / candidate, ROOT.parent / candidate]
    for path in options:
        if path.is_file():
            return path.resolve()
    shown = ", ".join(str(path) for path in options)
    raise WorkflowError(f"patch not found; checked: {shown}")


def patch_output_is_exact(output: str) -> bool:
    return PATCH_BAD_OUTPUT.search(output or "") is None


def current_branch(*, dry_run: bool = False) -> str:
    if dry_run:
        return "main"
    proc = run(["git", "branch", "--show-current"], capture=True, quiet=True)
    branch = proc.stdout.strip()
    if not branch:
        raise WorkflowError("detached HEAD is not supported by the release workflow")
    return branch


def require_tools(names: Iterable[str]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise WorkflowError(f"missing required command(s): {', '.join(missing)}")


def git_status(*, dry_run: bool = False) -> str:
    if dry_run:
        return ""
    return run(["git", "status", "--short"], capture=True, quiet=True).stdout


def git_head(*, dry_run: bool = False) -> str:
    if dry_run:
        return "DRYRUN"
    return run(["git", "rev-parse", "HEAD"], capture=True, quiet=True).stdout.strip()


def remote_branch_head(remote: str, branch: str, *, dry_run: bool = False) -> str | None:
    if dry_run:
        return None
    proc = run(
        ["git", "rev-parse", "--verify", f"refs/remotes/{remote}/{branch}"],
        capture=True,
        quiet=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None


def tag_target(tag: str | None, *, dry_run: bool = False) -> str | None:
    if not tag or dry_run:
        return None
    proc = run(["git", "rev-list", "-n", "1", tag], capture=True, quiet=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None


def _git_text(ref: str, path: str) -> str | None:
    proc = run(["git", "show", f"{ref}:{path}"], capture=True, quiet=True, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def _compose_blocks(text: str) -> tuple[dict[str, str], str]:
    """Split Compose service blocks without evaluating secrets or interpolation."""
    lines = text.splitlines(keepends=True)
    services_index = next((idx for idx, line in enumerate(lines) if line.rstrip() == "services:"), None)
    if services_index is None:
        return {}, text

    blocks: dict[str, list[str]] = {}
    prefix = lines[: services_index + 1]
    suffix: list[str] = []
    current: str | None = None
    service_section = True
    for line in lines[services_index + 1 :]:
        if service_section and line and not line.startswith((" ", "\t", "\r", "\n")):
            service_section = False
            current = None
        if service_section:
            match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*(?:#.*)?$", line.rstrip("\n"))
            if match:
                current = match.group(1)
                blocks[current] = [line]
                continue
            if current is not None:
                blocks[current].append(line)
        else:
            suffix.append(line)
    rendered = {name: "".join(rows) for name, rows in blocks.items()}
    return rendered, "".join(prefix + suffix)


def changed_compose_services(before: str | None, after: str) -> set[str]:
    after_blocks, after_outer = _compose_blocks(after)
    if before is None:
        return set(after_blocks)
    before_blocks, before_outer = _compose_blocks(before)
    changed = {
        name
        for name in set(before_blocks) | set(after_blocks)
        if before_blocks.get(name) != after_blocks.get(name)
    }
    # Top-level resource changes can alter any service even when its inline
    # block is textually stable. Be conservative rather than missing a recreate.
    if before_outer != after_outer:
        changed.update(after_blocks)
    return changed


def service_path_matches(path: str, pattern: str) -> bool:
    path = str(path).lstrip("./")
    if pattern.endswith("/"):
        return path.startswith(pattern)
    return path == pattern


def affected_services(changed_paths: Iterable[str], *, baseline_ref: str | None = None) -> list[str]:
    paths = sorted({str(path).strip() for path in changed_paths if str(path).strip()})
    affected: set[str] = set()
    for service, patterns in SERVICE_PATH_RULES:
        if any(service_path_matches(path, pattern) for path in paths for pattern in patterns):
            affected.add(service)

    if "docker-compose.yml" in paths:
        before = _git_text(baseline_ref, "docker-compose.yml") if baseline_ref else None
        after = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        affected.update(changed_compose_services(before, after))

    # SQL init scripts do not migrate an existing PostgreSQL volume. Recreating
    # telemetry-db would falsely imply the schema change had been applied.
    if any(path.startswith("telemetry/postgres/") for path in paths):
        raise WorkflowError(
            "telemetry/postgres changed; existing PostgreSQL volumes require an explicit migration plan "
            "rather than an automatic container recreate"
        )
    return sorted(affected)


def changed_paths_since(base_ref: str, *, include_worktree: bool) -> list[str]:
    cmd = ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB"]
    cmd.append(base_ref if include_worktree else f"{base_ref}..HEAD")
    proc = run(cmd, capture=True, quiet=True)
    paths = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    if include_worktree:
        untracked = run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            capture=True,
            quiet=True,
        )
        paths.update(line.strip() for line in untracked.stdout.splitlines() if line.strip())
    return sorted(paths)


def parse_compose_ps(text: str) -> dict[str, dict]:
    payload = (text or "").strip()
    if not payload:
        return {}
    rows: list[dict] = []
    try:
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            rows = [parsed]
        elif isinstance(parsed, list):
            rows = [row for row in parsed if isinstance(row, dict)]
    except json.JSONDecodeError:
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise WorkflowError(f"unable to parse docker compose ps JSON: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    result: dict[str, dict] = {}
    for row in rows:
        service = str(row.get("Service") or row.get("service") or "").strip()
        if service:
            result[service] = row
    return result


def compose_ps(*, dry_run: bool = False) -> dict[str, dict]:
    if dry_run:
        return {}
    proc = run(
        ["docker", "compose", "--profile", "*", "ps", "--all", "--format", "json"],
        capture=True,
        quiet=True,
    )
    return parse_compose_ps(proc.stdout)


def configured_compose_services(*, dry_run: bool = False) -> list[str]:
    if dry_run:
        return []
    proc = run(["docker", "compose", "config", "--services"], capture=True, quiet=True)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _row_state(row: dict) -> str:
    return str(row.get("State") or row.get("state") or "").strip().lower()


def _row_health(row: dict) -> str:
    return str(row.get("Health") or row.get("health") or "").strip().lower()


def _row_exit_code(row: dict) -> int | None:
    value = row.get("ExitCode", row.get("exitCode", row.get("exit_code")))
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def topology_requirements(
    before: dict[str, dict],
    targets: Iterable[str],
    *,
    rebuild_all: bool,
    configured_services: Iterable[str],
) -> dict[str, str]:
    required: dict[str, str] = {}
    for service, row in before.items():
        state = _row_state(row)
        if state == "running":
            required[service] = "running"
        elif state == "exited" and _row_exit_code(row) == 0:
            required[service] = "completed"

    desired = set(configured_services) if rebuild_all else set(targets)
    for service in desired:
        required[service] = "completed" if service in ONE_SHOT_SERVICES else "running"
    return required


def topology_failures(after: dict[str, dict], requirements: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for service, expectation in sorted(requirements.items()):
        row = after.get(service)
        if row is None:
            failures.append(f"{service}=missing")
            continue
        state = _row_state(row)
        health = _row_health(row)
        if expectation == "running":
            if state != "running":
                failures.append(f"{service}=state:{state or 'unknown'}")
                continue
            if health and health != "healthy":
                failures.append(f"{service}=health:{health}")
        elif expectation == "completed":
            if state != "exited" or _row_exit_code(row) != 0:
                failures.append(
                    f"{service}=state:{state or 'unknown'}/exit:{_row_exit_code(row)}"
                )
    return failures


def wait_for_topology(
    requirements: dict[str, str],
    timeout: int,
    *,
    dry_run: bool = False,
) -> None:
    if dry_run:
        print(f"Topology health: DRY-RUN · required={','.join(sorted(requirements)) or '-'}", flush=True)
        return
    deadline = time.monotonic() + timeout
    last_failures: list[str] = ["not checked"]
    while time.monotonic() < deadline:
        rows = compose_ps()
        last_failures = topology_failures(rows, requirements)
        if not last_failures:
            running = sum(1 for state in requirements.values() if state == "running")
            completed = sum(1 for state in requirements.values() if state == "completed")
            print(
                f"Topology health: PASS · running={running} completed={completed} "
                f"services={len(requirements)}",
                flush=True,
            )
            return
        time.sleep(2)
    raise WorkflowError(
        f"deployment topology did not recover within {timeout}s: {', '.join(last_failures)}"
    )


def wait_for_runtime_health(
    url: str,
    timeout: int,
    expected_version: str | None,
    *,
    dry_run: bool = False,
) -> None:
    print(f"Runtime health: {url}", flush=True)
    if dry_run:
        print("Runtime health: DRY-RUN", flush=True)
        return
    deadline = time.monotonic() + timeout
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = response.read(16384).decode("utf-8", errors="replace")
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError as exc:
                    last_error = f"non-JSON response: {exc}"
                    time.sleep(2)
                    continue
                if response.status >= 400 or not payload.get("ok"):
                    last_error = f"HTTP {response.status} status={payload.get('status')!r}"
                    time.sleep(2)
                    continue
                if expected_version and str(payload.get("version") or "") != expected_version:
                    last_error = (
                        f"version={payload.get('version')!r}, expected={expected_version!r}"
                    )
                    time.sleep(2)
                    continue
                workers = payload.get("workers") or {}
                alive = sum(1 for row in workers.values() if isinstance(row, dict) and row.get("alive"))
                observers = (payload.get("parallel_observation") or {}).get("configured_workers", "?")
                print(
                    f"Runtime health: PASS · workers={alive}/{len(workers)} observers={observers}",
                    flush=True,
                )
                return
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(8192).decode("utf-8", errors="replace")
                payload = json.loads(body)
                last_error = f"HTTP {exc.code} status={payload.get('status')!r}"
            except Exception:
                last_error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        time.sleep(2)
    raise WorkflowError(f"runtime health did not pass within {timeout}s: {last_error}")


def apply_patch(path: Path, *, dry_run: bool = False) -> None:
    base = ["patch", "--batch", "--forward", "--fuzz=0", "-p0", "-i", str(path)]
    probe = run(["patch", "--dry-run", *base[1:]], capture=True, check=False, dry_run=dry_run)
    if not dry_run:
        if probe.returncode != 0:
            raise WorkflowError("patch dry-run failed; source tree was not modified")
        if not patch_output_is_exact(probe.stdout):
            raise WorkflowError("patch dry-run reported fuzz/offset/reversed/failed evidence; refusing apply")
    applied = run(base, capture=True, check=False, dry_run=dry_run)
    if not dry_run:
        if applied.returncode != 0:
            raise WorkflowError("patch application failed")
        if not patch_output_is_exact(applied.stdout):
            raise WorkflowError("patch application reported non-exact evidence")


def validate_sqlite_backup(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size <= 0:
        raise WorkflowError(f"policy backup missing or empty: {path}")
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0) as db:
            quick = [str(row[0]) for row in db.execute("PRAGMA quick_check").fetchall()]
            foreign = db.execute("PRAGMA foreign_key_check").fetchall()
            version = int(db.execute("PRAGMA user_version").fetchone()[0] or 0)
    except sqlite3.DatabaseError as exc:
        raise WorkflowError(f"policy backup cannot be reopened: {exc}") from exc
    if quick != ["ok"] or foreign:
        raise WorkflowError(
            f"policy backup integrity failed: quick_check={quick!r} foreign_key_violations={len(foreign)}"
        )
    return {
        "ok": True,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "schema_version": version,
        "quick_check": quick,
        "foreign_key_violations": len(foreign),
    }


def _json_line(output: str) -> dict:
    for line in reversed((output or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise WorkflowError("policy backup helper did not return JSON evidence")


def create_live_policy_backup(
    *,
    expected_version: str | None,
    head_sha: str,
    backup_dir: Path,
    dry_run: bool = False,
) -> Path | None:
    """Create an online SQLite backup outside the Docker volume before rebuild."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    release = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(expected_version or "unknown"))
    head = re.sub(r"[^A-Fa-f0-9]+", "", str(head_sha or ""))[:12] or "unknown"
    filename = f"policy-pre-v{release}-{stamp}-{head}.db"
    host_dir = backup_dir.expanduser().resolve()
    host_path = host_dir / filename
    if dry_run:
        print(f"Policy backup: DRY-RUN · {host_path}", flush=True)
        return host_path
    host_dir.mkdir(parents=True, exist_ok=True)

    helper_lines = [
        "import json, os, sqlite3",
        "from pathlib import Path",
        f"src=Path({POLICY_DB_CONTAINER_PATH!r})",
        f"dst=Path('/host-backup/{filename}')",
        "tmp=Path(str(dst)+'.tmp')",
        "if not src.exists() or src.stat().st_size == 0:\n print(json.dumps({'state':'absent'})); raise SystemExit(0)",
        "s=sqlite3.connect(str(src), timeout=5.0); s.execute('PRAGMA busy_timeout=5000')",
        "quick=[str(r[0]) for r in s.execute('PRAGMA quick_check').fetchall()]",
        "foreign=s.execute('PRAGMA foreign_key_check').fetchall()",
        "if quick != ['ok'] or foreign:\n print(json.dumps({'state':'invalid','quick_check':quick,'foreign_key_violations':len(foreign)})); raise SystemExit(4)",
        "tmp.unlink(missing_ok=True)",
        "d=sqlite3.connect(str(tmp)); s.backup(d); d.close(); s.close()",
        "v=sqlite3.connect(str(tmp)); q=[str(r[0]) for r in v.execute('PRAGMA quick_check').fetchall()]; f=v.execute('PRAGMA foreign_key_check').fetchall(); ver=int(v.execute('PRAGMA user_version').fetchone()[0] or 0); v.close()",
        "if q != ['ok'] or f:\n print(json.dumps({'state':'backup-invalid','quick_check':q,'foreign_key_violations':len(f)})); raise SystemExit(5)",
        "os.replace(tmp,dst)",
        "print(json.dumps({'state':'created','path':str(dst),'size_bytes':dst.stat().st_size,'schema_version':ver,'quick_check':q,'foreign_key_violations':len(f)}))",
    ]
    helper = "\n".join(helper_lines)
    proc = run(
        [
            "docker", "compose", "run", "--rm", "--no-deps",
            "-v", f"{host_dir}:/host-backup",
            "--entrypoint", "python3", POLICY_SERVICE, "-c", helper,
        ],
        capture=True,
        check=False,
    )
    if proc.returncode != 0:
        raise WorkflowError(f"pre-upgrade policy backup failed ({proc.returncode})")
    evidence = _json_line(proc.stdout)
    if evidence.get("state") == "absent":
        print("Policy backup: SKIP · no existing policy.db (fresh deployment)", flush=True)
        return None
    if evidence.get("state") != "created":
        raise WorkflowError(f"pre-upgrade policy backup failed closed: {evidence.get('state')}")

    validated = validate_sqlite_backup(host_path)
    print(
        f"Policy backup: PASS · bytes={validated['size_bytes']} schema={validated['schema_version']} file={host_path}",
        flush=True,
    )
    run([
        sys.executable, "scripts/upgrade_acceptance.py", str(host_path),
        "--expect-schema", str(POLICY_SCHEMA_VERSION),
    ])
    print("Policy restore/upgrade smoke: PASS", flush=True)
    return host_path


def validate(*, dry_run: bool = False) -> None:
    app_files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "app").glob("*.py"))
    ingest_files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "telemetry/ingest").glob("*.py"))
    # Environment configuration is a release contract. On real release hosts
    # this also validates the local .env without ever printing secret values;
    # source-only qualification safely falls back to the static contract when
    # .env is absent.
    run([sys.executable, "scripts/env_validate.py"], dry_run=dry_run)
    run([sys.executable, "-m", "py_compile", *app_files, *ingest_files], dry_run=dry_run)
    run([sys.executable, "scripts/ux_validate.py"], dry_run=dry_run)
    run([sys.executable, "scripts/public_release_audit.py"], dry_run=dry_run)
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"], dry_run=dry_run)
    run(["docker", "compose", "--env-file", ".env.example", "config"], quiet=True, dry_run=dry_run)
    run(["docker", "compose", "config"], quiet=True, dry_run=dry_run)
    print("Validation: PASS", flush=True)


def rebuild(services: list[str], *, all_services: bool, no_deps: bool, dry_run: bool = False) -> None:
    if not all_services and not services:
        print("Rebuild: no deployment-impacting services detected", flush=True)
        return
    cmd = ["docker", "compose", "up", "-d", "--build", "--force-recreate"]
    if no_deps:
        cmd.append("--no-deps")
    if not all_services:
        cmd.extend(services)
    run(cmd, dry_run=dry_run)
    ps = ["docker", "compose", "ps"]
    if not all_services:
        ps.extend(services)
    run(ps, dry_run=dry_run)


def wait_for_health(url: str, timeout: int, expected_version: str | None, *, dry_run: bool = False) -> None:
    print(f"Health check: {url}", flush=True)
    if dry_run:
        print("Health check: DRY-RUN", flush=True)
        return
    deadline = time.monotonic() + timeout
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = response.read(8192).decode("utf-8", errors="replace")
                if response.status >= 400:
                    last_error = f"HTTP {response.status}"
                else:
                    if expected_version:
                        try:
                            payload = json.loads(body)
                        except json.JSONDecodeError as exc:
                            raise WorkflowError(f"health response is not JSON while --expect-version is set: {exc}") from exc
                        actual = str(payload.get("version") or "")
                        if actual != expected_version:
                            last_error = f"version={actual!r}, expected={expected_version!r}"
                            time.sleep(2)
                            continue
                    print(f"Health check: PASS · HTTP {response.status}", flush=True)
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        time.sleep(2)
    raise WorkflowError(f"health check did not pass within {timeout}s: {last_error}")


def stage_changes(paths: list[str], *, dry_run: bool = False) -> bool:
    run(["git", "diff", "--check"], dry_run=dry_run)
    print("Working tree before stage:", flush=True)
    if not dry_run:
        status = git_status()
        print(status or "(clean)", end="" if status.endswith("\n") else "\n")
    cmd = ["git", "add", "-A"]
    if paths:
        cmd.extend(["--", *paths])
    run(cmd, dry_run=dry_run)
    run(["git", "diff", "--cached", "--check"], dry_run=dry_run)
    run(["git", "diff", "--cached", "--stat"], dry_run=dry_run)
    if dry_run:
        return True
    proc = run(["git", "diff", "--cached", "--quiet"], check=False, capture=True, quiet=True)
    if proc.returncode not in (0, 1):
        raise WorkflowError("unable to determine staged Git state")
    return proc.returncode == 1


def load_message(args: argparse.Namespace, patch: Path | None) -> str:
    if args.message_file:
        text = Path(args.message_file).expanduser().read_text(encoding="utf-8").strip()
        if not text:
            raise WorkflowError("--message-file is empty")
        return text
    if args.message:
        return args.message.strip()
    if args.tag:
        return f"Release {args.tag}"
    if patch:
        return f"Apply {patch.stem}"
    return "Publish qualified ZEN changes"


def commit(message: str, *, dry_run: bool = False) -> str:
    run(["git", "commit", "-m", message], dry_run=dry_run)
    if dry_run:
        return "DRYRUN"
    return run(["git", "rev-parse", "HEAD"], capture=True, quiet=True).stdout.strip()


def push(remote: str, branch: str, *, dry_run: bool = False) -> None:
    run(["git", "push", remote, branch], dry_run=dry_run)


def wait_for_workflow(
    commit_sha: str,
    workflow: str,
    discovery_timeout: int,
    *,
    dry_run: bool = False,
) -> int:
    if dry_run:
        print(f"Would wait for GitHub workflow {workflow!r} on {commit_sha}", flush=True)
        return 0
    deadline = time.monotonic() + discovery_timeout
    print(f"Waiting for GitHub workflow {workflow!r} for {commit_sha[:12]}...", flush=True)
    while time.monotonic() < deadline:
        proc = run(
            [
                "gh", "run", "list", "--commit", commit_sha, "--workflow", workflow,
                "--limit", "1", "--json", "databaseId,status,conclusion,headSha,name",
            ],
            capture=True,
            check=False,
        )
        if proc.returncode == 0:
            try:
                rows = json.loads(proc.stdout or "[]")
            except json.JSONDecodeError:
                rows = []
            if rows:
                run_id = int(rows[0]["databaseId"])
                print(f"GitHub Actions run: {run_id}", flush=True)
                watched = run(["gh", "run", "watch", str(run_id), "--exit-status"], check=False)
                if watched.returncode != 0:
                    raise WorkflowError(f"GitHub Actions run {run_id} failed; tag was not created")
                return run_id
        time.sleep(3)
    raise WorkflowError(f"no GitHub Actions run for {commit_sha[:12]} appeared within {discovery_timeout}s")


def tag_release(tag: str, message: str, remote: str, *, dry_run: bool = False) -> None:
    if not dry_run:
        local = run(["git", "rev-list", "-n", "1", tag], capture=True, quiet=True, check=False)
        if local.returncode == 0 and local.stdout.strip():
            head = run(["git", "rev-parse", "HEAD"], capture=True, quiet=True).stdout.strip()
            if local.stdout.strip() != head:
                raise WorkflowError(f"tag {tag!r} already exists and does not point at HEAD")
            print(f"Tag {tag} already points at HEAD; leaving local tag unchanged", flush=True)
        else:
            run(["git", "tag", "-a", tag, "-m", message])
    else:
        run(["git", "tag", "-a", tag, "-m", message], dry_run=True)
    run(["git", "push", remote, tag], dry_run=dry_run)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apply -> qualify -> rebuild -> commit -> push -> watch CI -> tag a ZEN release patch."
    )
    parser.add_argument("--patch", help="Patch file. Relative names also resolve from ../ by default.")
    parser.add_argument("--resume", action="store_true", help="Patch is already applied; continue from dirty changes or an already-committed HEAD.")
    parser.add_argument("--message", help="Git commit message. Defaults from --tag or patch filename.")
    parser.add_argument("--message-file", help="Read the Git commit message from a text file.")
    parser.add_argument("--tag", help="Annotated release tag. Created only after successful watched CI by default.")
    parser.add_argument("--tag-message", help="Annotated tag message; defaults to the commit message first line.")
    parser.add_argument("--remote", default="origin", help="Git remote to push (default: origin).")
    parser.add_argument("--branch", help="Branch to push; defaults to the current branch.")
    parser.add_argument("--workflow", default="Quality", help="GitHub Actions workflow name to watch (default: Quality).")
    parser.add_argument("--run-discovery-timeout", type=int, default=120, help="Seconds to wait for the pushed CI run.")
    parser.add_argument("--rebuild-service", action="append", default=[], metavar="SERVICE", help="Additional Compose service to rebuild; repeatable. Auto-detected affected services are included by default.")
    parser.add_argument("--rebuild-all", action="store_true", help="Rebuild/start every Compose service instead of the affected-service plan.")
    parser.add_argument("--no-auto-services", action="store_true", help="Disable affected-service detection and use only --rebuild-service targets.")
    parser.add_argument("--no-deps", action="store_true", help="Pass --no-deps to docker compose up.")
    parser.add_argument("--health-url", default="http://127.0.0.1:8080/health/live", help="Post-rebuild health URL.")
    parser.add_argument("--health-timeout", type=int, default=60, help="Seconds to wait for app/runtime health after rebuild.")
    parser.add_argument("--runtime-health-url", default="http://127.0.0.1:8080/health/runtime", help="Post-rebuild embedded-worker health URL.")
    parser.add_argument("--topology-timeout", type=int, default=90, help="Seconds to wait for the pre-existing Compose topology to recover.")
    parser.add_argument("--expect-version", help="Require this version in the JSON health responses.")
    parser.add_argument("--backup-dir", default="../zen-backups", help="Host directory for verified pre-upgrade policy.db backups (default: ../zen-backups).")
    parser.add_argument("--skip-policy-backup", action="store_true", help="Explicitly bypass the pre-rebuild policy.db backup/restore gate. Not recommended for normal releases.")
    parser.add_argument("--stage", action="append", default=[], metavar="PATH", help="Stage only this path; repeatable. Default: git add -A.")
    parser.add_argument("--skip-validate", action="store_true")
    parser.add_argument("--skip-rebuild", action="store_true")
    parser.add_argument("--skip-health", action="store_true")
    parser.add_argument("--skip-runtime-health", action="store_true")
    parser.add_argument("--skip-topology-health", action="store_true")
    parser.add_argument("--skip-push", action="store_true")
    parser.add_argument("--skip-watch", action="store_true")
    parser.add_argument("--allow-tag-without-ci", action="store_true", help="Permit --tag with --skip-watch. Use only for an intentional exception.")
    parser.add_argument("--yes", action="store_true", help="Run without the interactive confirmation.")
    parser.add_argument("--dry-run", action="store_true", help="Print the workflow plan/commands without modifying source, Git or containers.")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.resume and args.patch:
        raise WorkflowError("use either --patch or --resume, not both")
    if not args.resume and not args.patch:
        raise WorkflowError("--patch is required unless --resume is used")
    if args.message and args.message_file:
        raise WorkflowError("use either --message or --message-file, not both")
    if args.rebuild_all and args.rebuild_service:
        raise WorkflowError("--rebuild-all cannot be combined with --rebuild-service")
    if args.tag and args.skip_push:
        raise WorkflowError("--tag requires pushing the commit first")
    if args.tag and args.skip_watch and not args.allow_tag_without_ci:
        raise WorkflowError("refusing --tag with --skip-watch; add --allow-tag-without-ci for an intentional exception")
    if args.health_timeout < 1 or args.topology_timeout < 1 or args.run_discovery_timeout < 1:
        raise WorkflowError("timeouts must be positive")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_args(args)
        tools = ["git"]
        if not args.resume:
            tools.append("patch")
        if not args.skip_validate or not args.skip_rebuild:
            tools.append("docker")
        if not args.skip_push and not args.skip_watch:
            tools.append("gh")
        require_tools(tools)

        patch = None if args.resume else resolve_patch(args.patch)
        branch = args.branch or current_branch(dry_run=args.dry_run)
        services = list(args.rebuild_service)
        message = load_message(args, patch)
        tag_message = args.tag_message or message.splitlines()[0]

        resume_status = git_status(dry_run=args.dry_run) if args.resume else ""
        resume_clean = bool(args.resume and not resume_status.strip())
        head_before = git_head(dry_run=args.dry_run)
        remote_before = remote_branch_head(args.remote, branch, dry_run=args.dry_run)
        existing_tag_target = tag_target(args.tag, dry_run=args.dry_run)
        if args.tag and existing_tag_target and existing_tag_target != head_before:
            raise WorkflowError(
                f"TAG TARGET MISMATCH: {args.tag} points to {existing_tag_target[:12]} "
                f"but HEAD is {head_before[:12]}"
            )
        already_published = bool(resume_clean and remote_before == head_before and head_before != "DRYRUN")

        if not args.resume and not args.dry_run:
            status = git_status()
            if status.strip():
                raise WorkflowError("working tree must be clean before applying a patch; use --resume only for an intentionally pre-applied release tree")

        print("ZEN release patch workflow", flush=True)
        print(f"root={ROOT}")
        print(f"mode={'resume' if args.resume else 'apply'}")
        if patch:
            print(f"patch={patch}")
        print(f"branch={branch} remote={args.remote}")
        print(f"rebuild={'ALL' if args.rebuild_all else ('auto+' + ','.join(services) if services else 'auto')}")
        print(f"workflow={args.workflow} tag={args.tag or '-'}")
        if args.resume:
            state = "dirty-tree"
            if resume_clean and remote_before != head_before:
                state = "committed-not-published"
            elif already_published:
                state = "committed-published"
            print(f"resume_state={state}")
        if not args.yes and not args.dry_run:
            answer = input("Proceed with this release workflow? [y/N] ").strip().lower()
            if answer not in {"y", "yes"}:
                print("Cancelled.")
                return 2

        if patch:
            apply_patch(patch, dry_run=args.dry_run)

        # Build an affected-service plan from the actual release delta. A dirty
        # tree is compared with the pre-release HEAD; a clean unpublished resume
        # is compared with the remote branch it will replace.
        change_base = head_before
        include_worktree = True
        if args.resume and resume_clean and remote_before and remote_before != head_before:
            change_base = remote_before
            include_worktree = False
        release_paths = (
            []
            if already_published or args.dry_run
            else changed_paths_since(change_base, include_worktree=include_worktree)
        )
        auto_services: list[str] = []
        if not args.no_auto_services and release_paths:
            auto_services = affected_services(release_paths, baseline_ref=change_base)
        if not args.rebuild_all:
            services = sorted(set(auto_services) | set(services))
        print(f"changed_paths={len(release_paths)}")
        print(f"affected_services={'ALL' if args.rebuild_all else (','.join(services) or '-')}")

        # A clean --resume at a commit already present on origin is a publish/tag
        # continuation, not a reason to rerun the entire host qualification and
        # certainly not a reason to manufacture an empty commit.
        if not already_published:
            if not args.skip_validate:
                validate(dry_run=args.dry_run)
            if not args.skip_rebuild:
                topology_before = compose_ps(dry_run=args.dry_run)
                configured = configured_compose_services(dry_run=args.dry_run)
                requirements = topology_requirements(
                    topology_before,
                    services,
                    rebuild_all=args.rebuild_all,
                    configured_services=configured,
                )
                policy_impacted = args.rebuild_all or POLICY_SERVICE in services
                if policy_impacted and not args.skip_policy_backup:
                    create_live_policy_backup(
                        expected_version=args.expect_version,
                        head_sha=head_before,
                        backup_dir=(ROOT / args.backup_dir) if not Path(args.backup_dir).is_absolute() else Path(args.backup_dir),
                        dry_run=args.dry_run,
                    )
                elif policy_impacted:
                    print("Policy backup: SKIPPED BY EXPLICIT OPERATOR OVERRIDE", flush=True)
                rebuild(services, all_services=args.rebuild_all, no_deps=args.no_deps, dry_run=args.dry_run)
                if not args.skip_health:
                    wait_for_health(args.health_url, args.health_timeout, args.expect_version, dry_run=args.dry_run)
                if not args.skip_runtime_health:
                    wait_for_runtime_health(
                        args.runtime_health_url,
                        args.health_timeout,
                        args.expect_version,
                        dry_run=args.dry_run,
                    )
                if not args.skip_topology_health:
                    wait_for_topology(requirements, args.topology_timeout, dry_run=args.dry_run)

        commit_sha = head_before
        if not resume_clean or patch:
            staged = stage_changes(args.stage, dry_run=args.dry_run)
            if staged:
                commit_sha = commit(message, dry_run=args.dry_run)
            elif not args.resume:
                raise WorkflowError("nothing is staged; refusing empty release commit")
            else:
                commit_sha = git_head(dry_run=args.dry_run)
                print(f"Resume: no new changes to commit; continuing from HEAD {commit_sha[:12]}", flush=True)
        else:
            print(f"Resume: clean tree; continuing from existing HEAD {commit_sha[:12]}", flush=True)

        run_id = None
        if not args.skip_push:
            remote_now = remote_branch_head(args.remote, branch, dry_run=args.dry_run)
            if remote_now != commit_sha:
                push(args.remote, branch, dry_run=args.dry_run)
            else:
                print(f"Push: {args.remote}/{branch} already at {commit_sha[:12]}; skipping branch push", flush=True)
            if not args.skip_watch:
                run_id = wait_for_workflow(
                    commit_sha,
                    args.workflow,
                    args.run_discovery_timeout,
                    dry_run=args.dry_run,
                )

        if args.tag:
            if args.skip_watch and not args.allow_tag_without_ci:
                raise WorkflowError("tagging without CI is not allowed")
            tag_release(args.tag, tag_message, args.remote, dry_run=args.dry_run)

        print("\n=== FINAL ===")
        if args.dry_run:
            print("DRY-RUN complete; nothing was modified.")
        else:
            run(["git", "log", "-3", "--oneline", "--decorate"])
            run(["git", "status"])
            if run_id is not None:
                print(f"GitHub Actions: PASS · run={run_id}")
            if args.tag:
                print(f"Tag: {args.tag} pushed to {args.remote}")
        return 0
    except (WorkflowError, OSError, UnicodeError) as exc:
        print(f"RELEASE WORKFLOW: FAIL · {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
