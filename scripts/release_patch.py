#!/usr/bin/env python3
"""Apply, qualify, publish, watch and tag a ZEN release patch.

The workflow is intentionally fail-closed around source state and CI:

1. exact dry-run + apply of a -p0 patch;
2. source/host validation;
3. bounded container rebuild + health check;
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
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
PATCH_BAD_OUTPUT = re.compile(r"\b(?:offset|fuzz|reversed|previously applied|failed)\b", re.IGNORECASE)


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


def validate(*, dry_run: bool = False) -> None:
    app_files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "app").glob("*.py"))
    ingest_files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "telemetry/ingest").glob("*.py"))
    run([sys.executable, "-m", "py_compile", *app_files, *ingest_files], dry_run=dry_run)
    run([sys.executable, "scripts/ux_validate.py"], dry_run=dry_run)
    run([sys.executable, "scripts/public_release_audit.py"], dry_run=dry_run)
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"], dry_run=dry_run)
    run(["docker", "compose", "--env-file", ".env.example", "config"], quiet=True, dry_run=dry_run)
    run(["docker", "compose", "config"], quiet=True, dry_run=dry_run)
    print("Validation: PASS", flush=True)


def rebuild(services: list[str], *, all_services: bool, no_deps: bool, dry_run: bool = False) -> None:
    cmd = ["docker", "compose", "up", "-d", "--build"]
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


def stage_changes(paths: list[str], *, dry_run: bool = False) -> None:
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
    if not dry_run:
        proc = run(["git", "diff", "--cached", "--quiet"], check=False, capture=True, quiet=True)
        if proc.returncode == 0:
            raise WorkflowError("nothing is staged; refusing empty release commit")
        if proc.returncode not in (0, 1):
            raise WorkflowError("unable to determine staged Git state")


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
    parser.add_argument("--resume", action="store_true", help="Patch is already applied; start with the current dirty tree.")
    parser.add_argument("--message", help="Git commit message. Defaults from --tag or patch filename.")
    parser.add_argument("--message-file", help="Read the Git commit message from a text file.")
    parser.add_argument("--tag", help="Annotated release tag. Created only after successful watched CI by default.")
    parser.add_argument("--tag-message", help="Annotated tag message; defaults to the commit message first line.")
    parser.add_argument("--remote", default="origin", help="Git remote to push (default: origin).")
    parser.add_argument("--branch", help="Branch to push; defaults to the current branch.")
    parser.add_argument("--workflow", default="Quality", help="GitHub Actions workflow name to watch (default: Quality).")
    parser.add_argument("--run-discovery-timeout", type=int, default=120, help="Seconds to wait for the pushed CI run.")
    parser.add_argument("--rebuild-service", action="append", default=[], metavar="SERVICE", help="Compose service to rebuild; repeatable. Default: mikrotik-control.")
    parser.add_argument("--rebuild-all", action="store_true", help="Rebuild/start every Compose service instead of selected services.")
    parser.add_argument("--no-deps", action="store_true", help="Pass --no-deps to docker compose up.")
    parser.add_argument("--health-url", default="http://127.0.0.1:8080/health/live", help="Post-rebuild health URL.")
    parser.add_argument("--health-timeout", type=int, default=60, help="Seconds to wait for health after rebuild.")
    parser.add_argument("--expect-version", help="Require this version in the JSON health response.")
    parser.add_argument("--stage", action="append", default=[], metavar="PATH", help="Stage only this path; repeatable. Default: git add -A.")
    parser.add_argument("--skip-validate", action="store_true")
    parser.add_argument("--skip-rebuild", action="store_true")
    parser.add_argument("--skip-health", action="store_true")
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
    if args.health_timeout < 1 or args.run_discovery_timeout < 1:
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
        services = args.rebuild_service or ["mikrotik-control"]
        message = load_message(args, patch)
        tag_message = args.tag_message or message.splitlines()[0]

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
        print(f"rebuild={'ALL' if args.rebuild_all else ','.join(services)}")
        print(f"workflow={args.workflow} tag={args.tag or '-'}")
        if not args.yes and not args.dry_run:
            answer = input("Proceed with this release workflow? [y/N] ").strip().lower()
            if answer not in {"y", "yes"}:
                print("Cancelled.")
                return 2

        if patch:
            apply_patch(patch, dry_run=args.dry_run)
        if not args.skip_validate:
            validate(dry_run=args.dry_run)
        if not args.skip_rebuild:
            rebuild(services, all_services=args.rebuild_all, no_deps=args.no_deps, dry_run=args.dry_run)
            if not args.skip_health:
                wait_for_health(args.health_url, args.health_timeout, args.expect_version, dry_run=args.dry_run)

        stage_changes(args.stage, dry_run=args.dry_run)
        commit_sha = commit(message, dry_run=args.dry_run)

        run_id = None
        if not args.skip_push:
            push(args.remote, branch, dry_run=args.dry_run)
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
