#!/usr/bin/env python3
"""Static UX regression checks for ZEN Control templates.

This is intentionally dependency-free so it can run beside the normal unittest
suite on the host.  It checks repeatable UX hygiene rather than rendering or
network behaviour: current asset versions, responsive standalone chrome,
help navigation/back links, stale branding/terminology and navigation continuity.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
MAIN = ROOT / "app" / "main.py"
PWA_HEAD = TEMPLATES / "_pwa_head.jinja"
PWA_JS = ROOT / "app" / "static" / "pwa.js"
SERVICE_WORKER = ROOT / "app" / "static" / "service-worker.js"
MANIFEST = ROOT / "app" / "static" / "manifest.webmanifest"
HELP_CONTENT = ROOT / "app" / "help_content.py"
HELP_PARTIAL = TEMPLATES / "_context_help.jinja"
HELP_CSS = ROOT / "app" / "static" / "help.css"

AUTH_TEMPLATES = {"login.html", "recovery_codes.html"}
INDEX_TEMPLATE = "index.html"
STANDALONE_OWNER_LINKS = {
    "activity_analytics.html": "Back to Activity",
    "activity_device.html": "Back to Activity",
    "activity_service.html": "Back to Activity",
    "activity_summary.html": "Back to Activity",
    "classification.html": "Back to Activity",
    "device_360.html": "Back to Devices",
    "diagnostics.html": "Back to Operations",
    "import_preview.html": "Back to Operations",
    "performance.html": "Back to Operations",
    "policy_explain.html": "Back to Device 360",
    "policy_history.html": "Back to Activity",
    "policy_quality.html": "Back to Policy tools",
    "policy_summary.html": "Back to Dashboard",
    "simulation.html": "Back to Policy tools",
    "help.html": "Back to ",
}


def release_version() -> str:
    text = MAIN.read_text()
    match = re.search(r'FastAPI\(title="ZEN Control", version="([^"]+)"\)', text)
    if not match:
        raise RuntimeError("Unable to determine release version from app/main.py")
    return match.group(1)


def asset_versions(text: str) -> list[tuple[str, str]]:
    return re.findall(r'href="(/static/[^"?]+\.css)\?v=([^"&]+)"', text)


def validate() -> list[str]:
    version = release_version()
    errors: list[str] = []
    templates = {path.name: path.read_text() for path in sorted(TEMPLATES.glob("*.html"))}

    for name, text in templates.items():
        if 'name="viewport"' not in text:
            errors.append(f"{name}: missing responsive viewport metadata")

        title = re.search(r"<title>(.*?)</title>", text, re.DOTALL)
        if not title:
            errors.append(f"{name}: missing <title>")
        elif "ZEN Control" not in title.group(1):
            errors.append(f"{name}: browser title does not include ZEN Control")

        for asset, found_version in asset_versions(text):
            if found_version != version:
                errors.append(
                    f"{name}: stale asset cache version {found_version} on {asset}; expected {version}"
                )

        if name not in AUTH_TEMPLATES and name != INDEX_TEMPLATE:
            if 'class="standalone-page"' not in text:
                errors.append(f"{name}: missing standalone-page responsive chrome marker")
            if f'/static/layout.css?v={version}' not in text:
                errors.append(f"{name}: standalone page does not load current layout.css")

    for name, label in STANDALONE_OWNER_LINKS.items():
        text = templates.get(name, "")
        if label not in text:
            errors.append(f"{name}: missing owner return action '{label}'")
        if 'back-link' not in text:
            errors.append(f"{name}: owner return action is not using back-link styling")

    joined = "\n".join(templates.values())
    for stale in (
        "MIKROTIK CONTROL ·",
        "No MikroTik Control",
        "Add restricted device",
        ">Restricted devices<",
        "No restricted devices.",
    ):
        if stale in joined:
            errors.append(f"templates: stale user-facing wording remains: {stale!r}")

    index = templates.get(INDEX_TEMPLATE, "")
    if 'value="{{ active_view }}/{{ active_section }}"' not in index:
        errors.append("index.html: parent lock/unlock does not preserve current view/subsection")
    if '#audit/recent' not in index:
        errors.append("index.html: Audit top-level navigation does not preserve its subsection")
    if "btn.setAttribute('aria-current', active ? 'page' : 'false')" not in index:
        errors.append("index.html: active main navigation is missing aria-current updates")
    if "activeTab.scrollIntoView" not in index or "activeSubtab.scrollIntoView" not in index:
        errors.append("index.html: active tablet/mobile navigation is not scrolled into view")

    layout = (ROOT / "app" / "static" / "layout.css").read_text()
    app_css = (ROOT / "app" / "static" / "app.css").read_text()
    for token in (
        ".button-link.back-link::before",
        "scroll-snap-type:x proximity",
        "button:focus-visible",
        "@media(prefers-reduced-motion:reduce)",
    ):
        if token not in layout:
            errors.append(f"layout.css: missing v0.36 UX hardening rule {token!r}")
    if "touch-action:manipulation" not in app_css:
        errors.append("app.css: button-link touch interaction hardening missing")

    help_content = HELP_CONTENT.read_text() if HELP_CONTENT.exists() else ""
    help_partial = HELP_PARTIAL.read_text() if HELP_PARTIAL.exists() else ""
    help_css = HELP_CSS.read_text() if HELP_CSS.exists() else ""
    if 'data-tab="help"' not in index or '>Help</a>' not in index:
        errors.append("index.html: Help is not exposed as a top-level navigation item")
    if 'topic={{ zen_help_for_context(active_view, active_section).key }}' not in index:
        errors.append("index.html: Help navigation is not subsection-aware")
    settings_pos = index.find('data-tab="settings"')
    help_pos = index.find('data-tab="help"')
    if settings_pos < 0 or help_pos < 0 or help_pos < settings_pos:
        errors.append("index.html: Help navigation must appear immediately after Settings")
    if '{% include "_context_help.jinja" %}' in index:
        errors.append("index.html: root context-help strip should not consume page space")
    for name, text in templates.items():
        if name in AUTH_TEMPLATES or name in {INDEX_TEMPLATE, "help.html"}:
            continue
        if '{% include "_context_help.jinja" %}' not in text:
            errors.append(f"{name}: missing contextual help strip")
    for token in (
        'href="/help?topic={{ page_help.key }}&amp;return_to={{ help_return|urlencode }}"',
        'href="/help?topic=glossary&amp;return_to={{ help_return|urlencode }}"',
        "CONTEXT HELP",
        "request.url.path",
    ):
        if token not in help_partial:
            errors.append(f"_context_help.jinja: missing contextual help contract {token!r}")
    for token in (
        '"glossary"',
        '"policy_explain"',
        '"aggregate_groups"',
        '"pwa"',
        "UNKNOWN/UNAVAILABLE",
        "not browser history",
    ):
        if token not in help_content:
            errors.append(f"help_content.py: missing core help/evidence topic {token!r}")
    for token in (".context-help-strip", ".help-shell", ".help-topic-link", "@media(max-width:600px)"):
        if token not in help_css:
            errors.append(f"help.css: missing responsive help UI rule {token!r}")

    pwa_head = PWA_HEAD.read_text() if PWA_HEAD.exists() else ""
    pwa_js = PWA_JS.read_text() if PWA_JS.exists() else ""
    service_worker = SERVICE_WORKER.read_text() if SERVICE_WORKER.exists() else ""
    manifest = MANIFEST.read_text() if MANIFEST.exists() else ""
    for name, text in templates.items():
        if '{% include "_pwa_head.jinja" %}' not in text:
            errors.append(f"{name}: missing shared PWA head include")
    for token in (
        f'/static/manifest.webmanifest?v={version}',
        f'/static/pwa.css?v={version}',
        f'/static/pwa.js?v={version}',
        f'/static/help.css?v={version}',
        'apple-mobile-web-app-capable',
    ):
        if token not in pwa_head:
            errors.append(f"_pwa_head.jinja: missing PWA metadata {token!r}")
    for token in (
        "navigator.serviceWorker.register('/service-worker.js'",
        "window.isSecureContext",
        "HTTPS REQUIRED",
        "beforeinstallprompt",
        "data-pwa-install",
        "controllerchange",
    ):
        if token not in pwa_js:
            errors.append(f"pwa.js: missing install/update behaviour {token!r}")
    for token in (
        "request.mode === 'navigate'",
        "safePresentationAsset",
        "url.pathname.startsWith('/pwa/icon/')",
        "`/static/help.css?v=${RELEASE}`",
        "request.method !== 'GET'",
        "offlineMutations: false",
        "cachedPrivateData: false",
    ):
        if token not in service_worker:
            errors.append(f"service-worker.js: missing safe-cache boundary {token!r}")
    for token in ('"display": "standalone"', '"scope": "/"', '"start_url"', '"icons"'):
        if token not in manifest:
            errors.append(f"manifest.webmanifest: missing installability field {token!r}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate ZEN Control static UX consistency")
    parser.add_argument("--quiet", action="store_true", help="only print failures")
    args = parser.parse_args()

    try:
        version = release_version()
        errors = validate()
    except Exception as exc:  # pragma: no cover - command-line safety
        print(f"UX validation ERROR: {exc}", file=sys.stderr)
        return 2

    if errors:
        print(f"ZEN UX validation: FAIL ({len(errors)} issue(s))")
        for item in errors:
            print(f" - {item}")
        return 1

    if not args.quiet:
        count = len(list(TEMPLATES.glob("*.html")))
        print(f"ZEN UX validation: PASS · release={version} · templates={count}")
        print("checks=viewport,title,asset-version,standalone-chrome,back-links,terminology,navigation,focus,touch,help-navigation,pwa")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
