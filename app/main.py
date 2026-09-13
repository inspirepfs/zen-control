from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from typing import Literal
from urllib.parse import quote_plus
import os
import json
import time
import secrets
import functools
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from passlib.context import CryptContext

from app.router import RouterOSAdapter, RouterError
from app.bypass import DOH_ROUTER_RULES, summarize_bypass_evidence
from app.policy_store import PolicyStore, DEVICE_CATEGORIES
from app.background_work import BackgroundWorker
from app.activity import (
    ActivityStore, ActivityError, build_policy_service_activity, build_service_intelligence,
    resolve_activity_window, compare_activity_totals, format_activity_bytes,
)
from app.parent_summary import build_parent_device_summary, summarize_parent_household
from app.summary_delivery import SummaryDeliveryService
from app.policy_engine import build_device_policy_plan, PolicyPlanError
from app.policy_explain import build_policy_explanation
from app.device360 import build_device_360_snapshot, filter_related_records
from app.policy_simulation import build_policy_simulation, build_profile_impact
from app.classification_intelligence import build_classification_workbench, read_classifier_consumer_status
from app.policy_quality import build_policy_quality_report
from app.policy_history import build_policy_intervals, build_policy_correlation_report
from app.service_catalog import SERVICE_ENFORCEMENT, SUPPORTED_SERVICE_KEYS
from app.service_provisioning import build_custom_service_contract
from app.reconciler import AutoReconciler, ReconciliationError, reconcile_device
from app.quota import service_quota_pairs, telemetry_name_to_key
from app.reward_recovery import (
    recover_pending_reward_redemptions as reconcile_pending_reward_redemptions,
    reward_redemption_reference,
    temporary_state_proves_reward,
)
from app.operations import OperationsMonitor
from app.release_readiness import build_release_readiness, config_roundtrip_smoke, restart_evidence
from app.diagnostics import OperationalDiagnostics, read_telemetry_ingest_status
from app.incidents import IncidentMonitor
from app.auth import AuthManager, AuthError, fresh_auth_valid, shared_display_privilege_valid
from app.auth import shared_display_extension_allowed, extend_shared_display_deadline
from app.ux import build_connected_overview, audit_destination, incident_destination, notification_destination
from app.performance import (
    PERF_ENABLED, build_formal_acceptance, collector as performance_collector,
    instrument, perf_span, timed,
)
from app.pwa import icon_png, status_contract
from app.secure_transport import SecureTransportConfig, security_headers
from app.kid_control_migration import translate_kid_control_snapshot
from app.kid_control_cutover import build_kid_control_cutover_readiness, failed_cutover_cleanup_complete
from app.help_content import get_help_topic, help_for_context, help_catalog, help_api_payload, help_owner
from app.runtime_health import build_runtime_health


SECURE_TRANSPORT = SecureTransportConfig.from_mapping()

app = FastAPI(title="ZEN Control", version="0.55.0")

SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))
OTP_ENCRYPTION_KEY = os.getenv("OTP_ENCRYPTION_KEY") or SESSION_SECRET
PROCESS_BOOT_ID = secrets.token_urlsafe(18)
SERVICE_CATALOG_PATH = os.getenv("SERVICE_CATALOG_PATH", "/data/service-catalog.json")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=SECURE_TRANSPORT.secure_cookies,
    same_site="lax",
)

if SECURE_TRANSPORT.enforce_host_allowlist:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(SECURE_TRANSPORT.allowed_hosts),
    )

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
templates.env.globals["zen_help"] = get_help_topic
templates.env.globals["zen_help_for_context"] = help_for_context
_original_template_response = templates.TemplateResponse

def _performance_template_response(*args, **kwargs):
    with perf_span("template.render"):
        return _original_template_response(*args, **kwargs)

templates.TemplateResponse = _performance_template_response
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.middleware("http")
async def secure_transport_response_headers(request: Request, call_next):
    """Apply browser hardening headers without changing policy/RouterOS authority."""
    response = await call_next(request)
    for name, value in security_headers(SECURE_TRANSPORT).items():
        if name not in response.headers:
            response.headers[name] = value
    return response


def current_secure_transport_status() -> dict:
    """Return sanitized configuration readiness; never tunnel tokens or identity."""
    return SECURE_TRANSPORT.status(app.version)


@app.middleware("http")
async def performance_request_metrics(request: Request, call_next):
    """Bounded request timings retained through v0.30.1 optimization.

    Performance, diagnostic and release-readiness observability endpoints,
    static assets and health probes are excluded so observing the collector
    does not materially pollute the measurements.
    """
    path = request.url.path
    excluded = (
        not PERF_ENABLED
        or path.startswith("/static/")
        or path.startswith("/api/performance")
        or path == "/performance"
        or path.startswith("/local/performance/")
        or path.startswith("/api/operations/diagnostics")
        or path == "/diagnostics"
        or path.startswith("/local/operations/diagnostics")
        or path.startswith("/api/release-readiness")
        or path == "/release-readiness"
        or path.startswith("/local/release-readiness")
        or path == "/service-worker.js"
        or path.startswith("/pwa/icon/")
        or path.startswith("/health")
    )
    if excluded:
        return await call_next(request)

    sample, token = performance_collector.begin_request(request.method, path)
    response = None
    error = ""
    status = 500
    try:
        response = await call_next(request)
        status = int(response.status_code)
        return response
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        route_obj = request.scope.get("route")
        route_path = getattr(route_obj, "path", path)
        route_label = route_path
        if route_path == "/":
            # Bound root-page performance cardinality to the real ZEN IA rather
            # than grouping every main navigation surface into one opaque GET /.
            requested_view = str(request.query_params.get("view") or "dashboard").strip().lower()
            view = requested_view if requested_view in ROOT_VIEWS else "dashboard"
            section = _section_for_view(view, request.query_params.get("section") or "")
            route_label = f"/?view={view}&section={section}"
        finished = performance_collector.finish_request(
            sample, token, route=route_label, status=status, error=error
        )
        if response is not None:
            response.headers["X-ZEN-Request-ID"] = finished.request_id
            response.headers["X-ZEN-Request-Ms"] = f"{finished.duration_ms:.3f}"
            server_parts = [f"zen;dur={finished.duration_ms:.3f}"]
            ranked = sorted(
                finished.components.items(),
                key=lambda item: float(item[1].get("total_ms", 0.0)),
                reverse=True,
            )[:5]
            for name, values in ranked:
                token_name = "".join(
                    character if character.isalnum() else "_" for character in name
                )[:48]
                server_parts.append(
                    f"{token_name};dur={float(values.get('total_ms', 0.0)):.3f}"
                )
            response.headers["Server-Timing"] = ", ".join(server_parts)


@app.middleware("http")
async def private_dynamic_cache_headers(request: Request, call_next):
    """Keep PWA caching away from authenticated/dynamic ZEN responses.

    v0.37 deliberately allows browser/service-worker caching only for static
    presentation assets. Dynamic HTML, APIs, downloads and authentication
    responses remain private/no-store so installing ZEN on a shared tablet does
    not create a persistent offline copy of household policy/activity data.
    """
    response = await call_next(request)
    path = request.url.path
    if not path.startswith("/static/") and not path.startswith("/pwa/icon/") and path != "/service-worker.js":
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
    return response


READ_ONLY_LEGACY_ROUTER_PATHS = frozenset({
    "/ip/kid-control/device",
})
# v0.53 permits exactly one legacy authority mutation: the validated profile's
# `disabled` flag may be toggled during cutover/rollback. Device membership,
# schedules and every destructive Kid Control operation remain forbidden.
BOUNDED_LEGACY_AUTHORITY_WRITE_PATHS = {"/ip/kid-control": frozenset({"disabled"})}
FORBIDDEN_ROUTER_WRITE_PATHS = READ_ONLY_LEGACY_ROUTER_PATHS

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

if ADMIN_PASSWORD_HASH:
    ADMIN_HASH = ADMIN_PASSWORD_HASH
elif ADMIN_PASSWORD:
    ADMIN_HASH = pwd.hash(ADMIN_PASSWORD)
else:
    ADMIN_HASH = pwd.hash("change-me-now")

USERS = {
    ADMIN_USER: {
        "hash": ADMIN_HASH,
        "role": "admin",
    }
}

AUDIT_FALLBACK = []
LOGIN_FAILS = {}
router = instrument(RouterOSAdapter(), "routeros")
policy_store = instrument(
    PolicyStore(os.getenv("POLICY_DB", "/data/policy.db")), "sqlite"
)
auth_manager = instrument(
    AuthManager(
        policy_store.path,
        encryption_material=OTP_ENCRYPTION_KEY,
        issuer=os.getenv("OTP_ISSUER", "ZEN Control"),
    ),
    "auth",
)
activity_store = instrument(ActivityStore(), "telemetry")


def coherent_router_request(func):
    """Reuse one RouterOS transport across one synchronous route.

    Fresh resource reads and post-write validation are preserved. This only
    removes repeated TCP/API login/disconnect churn inside a single user action.
    """
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        with router.coherent_session():
            return func(*args, **kwargs)
    return wrapped


def coherent_router_mutation(func):
    """Own one serialized RouterOS mutation lane for a complete user action.

    Individual adapter mutators also own the same re-entrant lane, so this
    outer boundary prevents a second manual/automatic writer from interleaving
    between the several RouterOS writes and validations that form one action.
    """
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        try:
            with router.mutation_session(owner=f"route:{func.__name__}"):
                with router.coherent_session():
                    return func(*args, **kwargs)
        except RouterError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    return wrapped


def audit(event, username, detail=""):
    """Write audit events durably; retain a tiny in-memory fallback if SQLite fails."""
    store = globals().get("policy_store")
    if store is not None:
        try:
            return store.append_audit(event, username, detail)
        except Exception:
            pass
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "user": username,
        "actor": username,
        "detail": detail,
        "severity": "warning",
    }
    AUDIT_FALLBACK.insert(0, entry)
    del AUDIT_FALLBACK[100:]
    return entry


def recent_audit(limit=30):
    try:
        return policy_store.list_audit(limit)
    except Exception:
        return AUDIT_FALLBACK[:limit]


def publish_service_catalog():
    """Publish current classifier metadata for the telemetry ingest container."""
    try:
        return policy_store.export_service_catalog(SERVICE_CATALOG_PATH)
    except Exception as exc:
        audit("SERVICE_CATALOG_PUBLISH_FAILED", "system", str(exc))
        return {"services": [], "error": str(exc)}


def custom_service_contract_definitions():
    """Return custom definitions plus deterministic preview contracts where valid."""
    result = []
    policy_group_keys = policy_store.policy_group_keys()
    for service in policy_store.list_services():
        if service.get("builtin") or service.get("key") in policy_group_keys:
            continue
        item = dict(service)
        try:
            item["routeros_contract"] = build_custom_service_contract(item)
        except ValueError as exc:
            item["routeros_contract"] = None
            item["provisioning_error"] = str(exc)
        result.append(item)
    return result


def runtime_service_catalog():
    """Built-ins plus custom contracts with explicit local operator approval."""
    return policy_store.routeros_service_catalog()


def current_user(request: Request):
    username = request.session.get("user")
    if not username or username not in USERS:
        return None
    generation = auth_manager.session_generation(username)
    session_generation = request.session.get("auth_generation")
    if session_generation is None or int(session_generation) != generation:
        # Authentication closure: do not grandfather legacy signed sessions that
        # predate server-side generation tracking. Re-authentication is safer
        # than silently adopting an unversioned session into current authority.
        request.session.clear()
        return None
    return {"username": username, "role": USERS[username]["role"]}


def session_auth_state(request: Request, username: str) -> dict:
    state = auth_manager.dashboard_state(username)
    now = time.time()
    privileged_until = float(request.session.get("privileged_until") or 0)
    fresh_auth_at = float(request.session.get("fresh_auth_at") or 0)
    privileged = shared_display_privilege_valid(
        shared_display_mode=bool(state["shared_display_mode"]),
        privileged_until=privileged_until,
        privileged_boot_id=request.session.get("privileged_boot_id"),
        process_boot_id=PROCESS_BOOT_ID,
        now=now,
    )
    remaining = max(0, int(privileged_until - now)) if state["shared_display_mode"] else 0
    return {
        **state,
        "privileged": privileged,
        "locked": bool(state["shared_display_mode"] and not privileged),
        "privileged_until": privileged_until,
        "privileged_seconds_remaining": remaining,
        "fresh_auth": fresh_auth_valid(
            fresh_auth_at=fresh_auth_at,
            fresh_auth_boot_id=request.session.get("fresh_auth_boot_id"),
            process_boot_id=PROCESS_BOOT_ID,
            now=now,
        ),
        "encryption_key_dedicated": bool(os.getenv("OTP_ENCRYPTION_KEY")),
    }


def require_role(*roles):
    def dep(request: Request):
        user = current_user(request)
        if not user:
            raise HTTPException(status_code=401)
        if user["role"] not in roles:
            raise HTTPException(status_code=403)
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            state = session_auth_state(request, user["username"])
            if state["locked"]:
                raise HTTPException(
                    status_code=423,
                    detail="Parent controls are locked. Unlock with a current OTP first.",
                )
        return user
    return dep


def mark_fresh_auth(request: Request, *, privileged: bool = False):
    now = time.time()
    request.session["fresh_auth_at"] = now
    request.session["fresh_auth_boot_id"] = PROCESS_BOOT_ID
    if privileged:
        account = auth_manager.account(request.session.get("user"))
        request.session["privileged_until"] = now + int(account["unlock_minutes"]) * 60
        request.session["privileged_boot_id"] = PROCESS_BOOT_ID


def fresh_auth_ok(request: Request) -> bool:
    return fresh_auth_valid(
        fresh_auth_at=float(request.session.get("fresh_auth_at") or 0),
        fresh_auth_boot_id=request.session.get("fresh_auth_boot_id"),
        process_boot_id=PROCESS_BOOT_ID,
    )


def verify_step_up(request: Request, username: str, *, password: str = "", otp: str = "") -> str:
    if fresh_auth_ok(request):
        return "recent-session"
    remote = request.client.host if request.client else "unknown"
    fail_key = f"stepup:{remote}:{username}"
    fails = LOGIN_FAILS.get(fail_key, {"count": 0, "until": 0})
    if fails["until"] > time.time():
        raise AuthError("Too many failed re-authentication attempts. Try again shortly.")

    try:
        if auth_manager.active_totp_count(username):
            result = auth_manager.verify_otp_or_recovery(username, otp)
            if not result:
                raise AuthError("A fresh authenticator or recovery code is required")
            mark_fresh_auth(request, privileged=True)
            LOGIN_FAILS.pop(fail_key, None)
            return result["method"]

        user = USERS.get(username)
        if not user or not password or not pwd.verify(password, user["hash"]):
            raise AuthError("Current password is required")
        mark_fresh_auth(request, privileged=False)
        LOGIN_FAILS.pop(fail_key, None)
        return "password"
    except AuthError:
        count = fails["count"] + 1
        LOGIN_FAILS[fail_key] = {
            "count": count,
            "until": time.time() + 60 if count >= 5 else 0,
        }
        raise


def csrf_ok(request: Request, token: str):
    stored = request.session.get("csrf", "")
    return bool(token and stored and secrets.compare_digest(token, stored))


ROOT_VIEWS = frozenset({
    "dashboard", "devices", "policies", "schedules",
    "activity", "notifications", "incidents", "audit", "settings",
})
ROOT_VIEW_SECTIONS = {
    "dashboard": ("overview", "controls"),
    "devices": ("managed", "discovery", "bulk"),
    "policies": ("profiles", "assignments", "services", "bandwidth", "tools"),
    "schedules": ("planner", "exceptions", "templates", "router"),
    "activity": ("overview", "devices", "services", "classification", "dns", "summaries", "history"),
    "notifications": ("inbox", "history"),
    "incidents": ("active", "history"),
    "audit": ("recent",),
    "settings": ("parents", "policy", "automation", "security", "operations"),
}


def _view_for_tab(tab: str) -> str:
    view = str(tab or "dashboard").split("/", 1)[0].strip().lower()
    return view if view in ROOT_VIEWS else "dashboard"


def _section_for_view(view: str, section: str = "") -> str:
    allowed = ROOT_VIEW_SECTIONS.get(view) or ("overview",)
    candidate = str(section or "").strip().lower()
    return candidate if candidate in allowed else allowed[0]


def _root_redirect(tab: str, *, status: str, message: str) -> RedirectResponse:
    parts = str(tab or "dashboard").split("/", 1)
    view = _view_for_tab(tab)
    section = _section_for_view(view, parts[1] if len(parts) > 1 else "")
    return RedirectResponse(
        f"/?view={view}&section={section}&{status}={quote_plus(str(message))}#{view}/{section}",
        status_code=303,
    )


def redirect_error(tab: str, message: str):
    return _root_redirect(tab, status="error", message=message)


def redirect_ok(tab: str, message: str):
    return _root_redirect(tab, status="ok", message=message)


def format_rate(value):
    if not value:
        return None
    result = []
    for part in str(value).split("/"):
        try:
            number = int(part)
            if number >= 1_000_000:
                result.append(f"{number / 1_000_000:g}M")
            elif number >= 1_000:
                result.append(f"{number / 1_000:g}k")
            else:
                result.append(str(number))
        except ValueError:
            result.append(part)
    return "/".join(result)


@timed("policy.live_status")
def get_live_status():
    status = router.get_status()
    status["mode"] = status["mode"].upper()
    status["slow_limit"] = format_rate(status.get("slow_limit"))
    temp = router.get_temporary_access()
    status["temp_until"] = (
        f"{temp.get('start_date', '')} {temp.get('start_time', '')}".strip()
        if temp.get("active")
        else None
    )
    status["temporary"] = temp
    return status

@timed("policy.live_devices")
def get_live_devices():
    return [
        {
            "name": device["name"],
            "ip": device["address"],
            "address": device["address"],
            "dynamic": device.get("dynamic", False),
        }
        for device in router.get_restricted_devices()
    ]


@timed("policy.quota_usage")
def get_quota_usage(address: str, at=None) -> dict:
    """Load telemetry only when this device actually has configured quotas.

    Quota telemetry is deliberately fail-open: a PostgreSQL/ingest outage is
    surfaced in policy state but never invents an exhausted quota.
    """
    config = policy_store.get_device_quota_config(address)
    if not config.get("configured"):
        return {"available": True, "configured": False, "service_bytes": {}, "total_bytes": 0}
    if not config.get("engine_enabled"):
        return {
            "available": False,
            "configured": True,
            "error": "Quota engine is disabled in Settings",
            "service_bytes": {},
            "total_bytes": 0,
        }
    try:
        raw = activity_store.daily_usage(
            address,
            policy_store.get_settings().get("policy_timezone", "Europe/London"),
            at=at,
        )
    except ActivityError as exc:
        return {
            "available": False,
            "configured": True,
            "error": f"Telemetry unavailable; quota policy is fail-open: {exc}",
            "service_bytes": {},
            "total_bytes": 0,
        }

    logical = {}
    for name, value in (raw.get("service_bytes") or {}).items():
        key = telemetry_name_to_key(name, policy_store.list_services())
        if key:
            logical[key] = logical.get(key, 0) + int(value or 0)
    return {**raw, "configured": True, "service_bytes": logical}


@timed("policy.effective_policy")
def get_effective_policy(address: str, at=None) -> dict:
    usage = get_quota_usage(address, at=at)
    policy = policy_store.compute_effective_policy(
        address, at=at, quota_usage=usage
    )
    # v0.33 records only policy resolved for "now".  Future/past what-if
    # calculations must never become historical evidence simply because the
    # simulator invoked the resolver.
    record = at is None
    if at is not None:
        try:
            observed = datetime.fromisoformat(str(policy.get("policy_at") or at))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            record = abs((datetime.now(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds()) <= 300
        except ValueError:
            record = False
    if record:
        try:
            policy_store.record_policy_state(address, policy, source="effective-resolver")
        except Exception:
            # History is supporting evidence only.  A recording failure must not
            # make policy resolution or RouterOS reconciliation unavailable.
            pass
    return policy


@timed("policy.live_plan")
def get_live_policy_plan(
    address: str,
    desired_policy: dict | None = None,
    live_enforcement: dict | None = None,
    temporary_access: dict | None = None,
    live_services: dict | None = None,
    live_bandwidth: dict | None = None,
    global_mode: str | None = None,
) -> dict:
    """
    Resolve desired policy against actual RouterOS enforcement.
    """
    if desired_policy is None:
        desired_policy = get_effective_policy(address)

    if live_enforcement is None:
        live_enforcement = router.get_device_enforcement(
            address
        )

    if temporary_access is None:
        getter = getattr(
            router,
            "get_device_temporary_access",
            None,
        )

        if getter:
            temporary_access = getter(address)
        else:
            temporary_access = {"active": False}

    service_catalog = runtime_service_catalog()

    if live_services is None:
        live_services = router.get_device_service_enforcement(
            address, service_catalog=service_catalog
        )

    if live_bandwidth is None:
        live_bandwidth = router.get_device_bandwidth(address)

    if global_mode is None:
        global_mode = router.get_status().get("mode", "normal")

    plan = build_device_policy_plan(
        address,
        desired_policy,
        live_enforcement,
        temporary_access,
        live_services,
        live_bandwidth,
        global_mode,
        service_catalog=service_catalog,
    )
    # Observation workers may publish this read-only evidence for advisory UI
    # surfaces. Mutation paths never consume the published copy: they call this
    # function again while owning the serialized mutation lane and therefore
    # re-read RouterOS immediately before any write.
    plan["live_evidence"] = {
        "enforcement": dict(live_enforcement or {}),
        "temporary_access": dict(temporary_access or {}),
        "services": dict(live_services or {}),
        "bandwidth": dict(live_bandwidth or {}),
    }
    return plan


@timed("policy.explanation")
def get_policy_explanation(address: str, focus_service: str | None = None) -> dict:
    """Explain current policy using local desired state plus fresh RouterOS evidence.

    The explanation path is read-only. RouterOS failures degrade the live portion
    of the explanation rather than fabricating a live state.
    """
    local = policy_store.list_device_policy()
    cfg = dict(local.get(address) or {})
    profile = policy_store.get_profile(cfg.get("profile_id")) if cfg.get("profile_id") else None
    desired = get_effective_policy(address)

    device_name = str(cfg.get("alias") or address)
    known_live = False
    inventory_error = None
    try:
        for item in router.get_restricted_devices():
            if str(item.get("address") or item.get("ip") or "") == address:
                known_live = True
                device_name = str(cfg.get("alias") or item.get("name") or address)
                break
    except RouterError as exc:
        inventory_error = str(exc)

    if address not in local and not known_live:
        if inventory_error:
            raise RouterError(
                f"Cannot prove {address} is a managed device while RouterOS inventory is unavailable: {inventory_error}"
            )
        raise ValueError("Managed device not found")

    temporary = {"active": False}
    temporary_error = None
    try:
        temporary = router.get_device_temporary_access(address)
    except RouterError as exc:
        temporary_error = str(exc)

    live_plan = None
    router_error = None
    if temporary_error:
        # Temporary access is an authority input. Do not manufacture a normal
        # policy plan by pretending a failed temporary-state read means inactive.
        router_error = f"Temporary access state unavailable: {temporary_error}"
    else:
        try:
            live_plan = get_live_policy_plan(
                address, desired_policy=desired, temporary_access=temporary
            )
        except (RouterError, PolicyPlanError, ValueError) as exc:
            router_error = str(exc)

    return build_policy_explanation(
        address=address,
        device_name=device_name,
        device_config=cfg,
        profile=profile,
        desired_policy=desired,
        live_plan=live_plan,
        temporary_access=temporary,
        service_definitions=policy_store.list_services(),
        policy_groups=policy_store.policy_group_catalog(),
        router_error=router_error,
        evidence_warnings=[inventory_error] if inventory_error else [],
        focus_service=focus_service,
    )


PREPARED_VIEW_MAX_AGE = {
    "dashboard:24h": 240,
    "activity:24h": 240,
    "services:24h": 240,
    "classification:24h": 360,
    "history:7d": 360,
}


def _prepared_view(view_key: str, *, max_age_seconds: int | None = None):
    """Return current-revision prepared evidence or None for live fallback."""
    revision = int(policy_store.current_config_revision().get("revision") or 0)
    return policy_store.get_prepared_view(
        view_key,
        required_revision=revision,
        max_age_seconds=max_age_seconds or PREPARED_VIEW_MAX_AGE.get(view_key, 300),
    )


def _wake_background_read_worker() -> None:
    worker = globals().get("background_worker")
    if worker is not None:
        try:
            worker.wake()
        except Exception:
            pass


def _prepared_payload(
    view_key: str,
    *,
    max_age_seconds: int | None = None,
    allow_stale_same_revision: bool = False,
):
    """Read one prepared model with explicit hit/miss/staleness evidence.

    Interactive advisory pages may consume last-known-good evidence after its
    freshness TTL, but never after a configuration revision change.  A stale
    same-revision hit is labelled STALE and wakes the background read worker; it
    is never promoted into RouterOS write authority.
    """
    revision = int(policy_store.current_config_revision().get("revision") or 0)
    max_age = max_age_seconds or PREPARED_VIEW_MAX_AGE.get(view_key, 300)
    prepared = policy_store.get_prepared_view(
        view_key,
        required_revision=revision,
        max_age_seconds=max_age,
        include_stale=True,
    )
    performance_collector.record_evidence("prepared_view.lookup")

    if prepared is None:
        job = policy_store.prepared_view_job_state(view_key) or {}
        job_status = str(job.get("status") or "")
        job_error = str(job.get("error") or "")
        attempts = int(job.get("attempts") or 0)
        max_attempts = max(1, int(job.get("max_attempts") or 1))
        if job_status == "failed":
            state, reason = "failed", "generation_failed"
        elif job_status in {"pending", "running"}:
            state = "preparing"
            reason = "retrying_after_error" if job_error and attempts > 0 else job_status
        elif job_status == "succeeded":
            state, reason = "missing", "published_view_missing"
        else:
            state, reason = "missing", "not_found"
        performance_collector.record_evidence("prepared_view.miss")
        performance_collector.record_evidence(f"prepared_view.miss:{reason}")
        performance_collector.record_evidence(f"prepared_view.miss:{view_key}:{reason}")
        _wake_background_read_worker()
        return None, {
            "view_key": view_key,
            "state": state,
            "reason": reason,
            "source_revision": revision,
            "job_status": job_status or None,
            "attempts": attempts,
            "max_attempts": max_attempts,
        }

    stale_grace_seconds = min(1800, max(300, int(max_age) * 5))
    meta = {
        "view_key": prepared.get("view_key"),
        "captured_at": prepared.get("captured_at"),
        "age_seconds": prepared.get("age_seconds"),
        "source_revision": prepared.get("source_revision"),
        "generation": prepared.get("generation"),
        "payload_bytes": prepared.get("payload_bytes"),
        "state": "fresh" if prepared.get("eligible") else "stale",
        "reason": None,
        "stale_grace_seconds": stale_grace_seconds,
    }

    if prepared.get("eligible"):
        performance_collector.record_evidence("prepared_view.hit")
        performance_collector.record_evidence(f"prepared_view.hit:{view_key}")
        return dict(prepared.get("payload") or {}), meta

    if prepared.get("revision_stale"):
        reason = "revision_mismatch"
    elif str(prepared.get("status") or "") != "ready":
        reason = "status_not_ready"
    elif prepared.get("expired"):
        reason = "expired"
    elif prepared.get("too_old"):
        reason = "too_old"
    else:
        reason = "ineligible"
    meta["reason"] = reason
    _wake_background_read_worker()

    prepared_age = prepared.get("age_seconds")
    within_stale_grace = (
        prepared_age is not None
        and float(prepared_age) <= float(stale_grace_seconds)
    )
    can_serve_stale = (
        allow_stale_same_revision
        and not prepared.get("revision_stale")
        and str(prepared.get("status") or "") == "ready"
        and bool(prepared.get("payload"))
        and within_stale_grace
    )
    if (
        allow_stale_same_revision
        and not prepared.get("revision_stale")
        and str(prepared.get("status") or "") == "ready"
        and bool(prepared.get("payload"))
        and not within_stale_grace
    ):
        reason = "stale_grace_exceeded"
        meta["reason"] = reason
        meta["state"] = "missing"
    if can_serve_stale:
        # A same-revision last-known-good row is a usable advisory hit, not a
        # live-query fallback. Keep the reason separately so freshness can be
        # diagnosed without corrupting hit-rate accounting.
        performance_collector.record_evidence("prepared_view.hit")
        performance_collector.record_evidence("prepared_view.stale_hit")
        performance_collector.record_evidence(f"prepared_view.stale_hit:{view_key}")
        performance_collector.record_evidence(f"prepared_view.stale_reason:{reason}")
        return dict(prepared.get("payload") or {}), meta

    performance_collector.record_evidence("prepared_view.miss")
    performance_collector.record_evidence(f"prepared_view.miss:{reason}")
    performance_collector.record_evidence(f"prepared_view.miss:{view_key}:{reason}")
    return None, meta


def _record_prepared_fallback(view_key: str) -> None:
    performance_collector.record_evidence("prepared_view.fallback")
    performance_collector.record_evidence(f"prepared_view.fallback:{view_key}")


def _publish_router_observation(view_key: str, payload: dict, *, scope: str, ttl_seconds: int = 180):
    """Publish advisory RouterOS evidence for non-blocking read surfaces.

    Mutation paths never consume these rows. They continue to fresh-read and
    verify RouterOS inside the serialized mutation lane.
    """
    try:
        return policy_store.save_prepared_view(
            view_key=view_key,
            kind="router.observation",
            scope=scope,
            payload=payload,
            source_revision=int(policy_store.current_config_revision().get("revision") or 0),
            ttl_seconds=ttl_seconds,
        )
    except Exception:
        return None


def _advisory_router_payload(view_key: str, *, max_age_seconds: int = 180):
    """Read RouterOS observation evidence without forcing a live request.

    Expired evidence may be shown as explicitly STALE, but evidence from a
    different configuration revision is withheld to avoid presenting old service
    semantics as current.
    """
    revision = int(policy_store.current_config_revision().get("revision") or 0)
    row = policy_store.get_prepared_view(
        view_key, required_revision=revision, max_age_seconds=max_age_seconds, include_stale=True
    )
    performance_collector.record_evidence("router_observation.lookup")
    if not row or row.get("revision_stale"):
        performance_collector.record_evidence("router_observation.miss")
        return None, {
            "state": "missing", "view_key": view_key,
            "reason": "revision_mismatch" if row else "not_found",
        }
    stale_grace_seconds = min(1800, max(300, int(max_age_seconds) * 5))
    age_seconds = row.get("age_seconds")
    if (
        not row.get("eligible")
        and (age_seconds is None or float(age_seconds) > float(stale_grace_seconds))
    ):
        performance_collector.record_evidence("router_observation.miss")
        performance_collector.record_evidence("router_observation.miss:stale_grace_exceeded")
        return None, {
            "state": "missing",
            "view_key": view_key,
            "captured_at": row.get("captured_at"),
            "age_seconds": age_seconds,
            "source_revision": row.get("source_revision"),
            "reason": "stale_grace_exceeded",
            "stale_grace_seconds": stale_grace_seconds,
        }
    payload = dict(row.get("payload") or {})
    state = "fresh" if row.get("eligible") else "stale"
    performance_collector.record_evidence(f"router_observation.{state}")
    return payload, {
        "state": state,
        "view_key": view_key,
        "captured_at": row.get("captured_at"),
        "age_seconds": age_seconds,
        "source_revision": row.get("source_revision"),
        "expired": bool(row.get("expired")),
        "too_old": bool(row.get("too_old")),
        "stale_grace_seconds": stale_grace_seconds,
    }


def _build_advisory_policy_summary(
    devices: list[dict],
    device_policy: dict,
    profiles: list[dict],
    policy_plans: dict,
) -> list[dict]:
    """Build Dashboard favourites from already-published reconciler plans.

    Normal Dashboard navigation must not recompute effective policy for every
    managed device. The reconciler's managed-device observation is revision-bound
    and already carries the desired-policy fields needed by the compact favourite
    cards. Missing plan evidence is represented as UNKNOWN rather than triggering
    synchronous policy resolution.
    """
    profile_names = {
        str(item.get("id")): str(item.get("name") or "Unassigned")
        for item in (profiles or [])
        if item.get("id") is not None
    }
    rows = []
    for device in devices or []:
        ip = str(device.get("ip") or device.get("address") or "").strip()
        if not ip:
            continue
        cfg = dict((device_policy or {}).get(ip) or {})
        plan = dict((policy_plans or {}).get(ip) or {})
        profile_id = cfg.get("profile_id")
        rows.append({
            "ip": ip,
            "name": str(cfg.get("alias") or device.get("name") or device.get("host_name") or "Unknown"),
            "profile": profile_names.get(str(profile_id), "Unassigned") if profile_id else "Unassigned",
            "category": cfg.get("category", "other"),
            "favourite": bool(cfg.get("favourite", 0)),
            "desired_mode": str(plan.get("desired_mode") or "unknown"),
            "mode_source": str(plan.get("mode_source") or "advisory evidence unavailable"),
            "bandwidth": str(plan.get("bandwidth_preset") or "unknown"),
            "blocked_services": list(plan.get("blocked_services") or []),
            "conflicts": list(plan.get("conflicts") or []),
            "evidence_state": "ready" if plan.get("desired_mode") else "missing",
        })
    return sorted(rows, key=lambda row: (not row["favourite"], row["name"].lower(), row["ip"]))


def _prepare_dashboard_payload() -> dict:
    local = policy_store.list_device_policy()
    managed_ips = sorted(str(ip) for ip in local if str(ip))
    if not activity_store.health():
        return {
            "schema": "zen_prepared_dashboard_v1",
            "telemetry_available": False,
            "activity_insights": {},
            "security_bypass_attempts": [],
            "security_bypass_evidence": [],
            "security_bypass_summary": summarize_bypass_evidence([]),
        }
    coverage = activity_store.classification_coverage(24)
    evidence = activity_store.bypass_evidence(managed_ips, 24, 120)
    return {
        "schema": "zen_prepared_dashboard_v1",
        "telemetry_available": True,
        "activity_insights": {
            "managed_devices": len(managed_ips),
            "managed_devices_seen": activity_store.managed_activity_count(managed_ips, 24),
            "traffic_classified_percent": coverage.get("traffic_percent"),
            "dns_classified_percent": coverage.get("dns_percent"),
            "traffic_classification_status": coverage.get("traffic_evidence_status", "no_evidence"),
            "dns_classification_status": coverage.get("dns_evidence_status", "no_evidence"),
            "unknown_domains": int(coverage.get("unknown_domains", 0)),
        },
        "activity_coverage": coverage,
        "security_bypass_attempts": activity_store.bypass_attempts(managed_ips, 24, 30),
        "security_bypass_evidence": evidence,
        "security_bypass_summary": summarize_bypass_evidence(evidence),
    }


def _prepare_activity_payload() -> dict:
    local = policy_store.list_device_policy()
    managed_names = {
        str(ip): str((cfg or {}).get("alias") or ip)
        for ip, cfg in local.items() if str(ip)
    }
    if not activity_store.health():
        return {
            "schema": "zen_prepared_activity_v1",
            "telemetry_available": False,
            "overview": {}, "devices": [], "observed_services": [],
            "domains": [], "device_summaries": {}, "dns_service_rows": [],
            "coverage": {}, "unknown_domains": [], "activity_insights": {},
        }
    overview = activity_store.overview(24)
    devices = activity_store.top_devices(24, 12)
    summaries = activity_store.device_activity_summaries(
        [row.get("client_ip") for row in devices], 24, 5, 6
    )
    for row in devices:
        ip = str(row.get("client_ip") or "")
        row["managed"] = ip in managed_names
        row["display_name"] = managed_names.get(ip, ip)
        row["detail"] = summaries.get(ip, {})
    observed = activity_store.top_services(24, 100)
    coverage = activity_store.classification_coverage(24)
    return {
        "schema": "zen_prepared_activity_v1",
        "telemetry_available": True,
        "overview": overview,
        "devices": devices,
        "observed_services": observed,
        "domains": activity_store.dns_top_domains(24, 30),
        "device_summaries": summaries,
        "dns_service_rows": activity_store.dns_top_services(24, 100),
        "coverage": coverage,
        "unknown_domains": activity_store.unknown_domains(24, 30),
        "activity_insights": {
            "observed_services": int(overview.get("observed_services", 0)),
            "attributed_percent": float(overview.get("attributed_percent", 0.0)),
            "dns_block_percent": float(overview.get("dns_block_percent", 0.0)),
            "managed_devices": len(managed_names),
            "managed_devices_seen": activity_store.managed_activity_count(list(managed_names), 24),
            "unique_domains": int(overview.get("unique_domains", 0)),
            "latest_flow": overview.get("latest_flow"),
            "latest_dns": overview.get("latest_dns"),
            "traffic_classified_percent": coverage.get("traffic_percent"),
            "dns_classified_percent": coverage.get("dns_percent"),
            "traffic_classification_status": coverage.get("traffic_evidence_status", "no_evidence"),
            "dns_classification_status": coverage.get("dns_evidence_status", "no_evidence"),
            "unknown_domains": int(coverage.get("unknown_domains", 0)),
        },
    }


def _prepare_services_payload() -> dict:
    if not activity_store.health():
        return {
            "schema": "zen_prepared_services_v1", "telemetry_available": False,
            "traffic": [], "dns": [], "coverage": {}, "unknown_domains": [],
        }
    return {
        "schema": "zen_prepared_services_v1",
        "telemetry_available": True,
        "traffic": activity_store.top_services(24, 100),
        "dns": activity_store.dns_top_services(24, 100),
        "coverage": activity_store.classification_coverage(24),
        "unknown_domains": activity_store.unknown_domains(24, 50),
    }


def _prepare_history_payload() -> dict:
    settings = policy_store.get_settings()
    timezone_name = settings.get("policy_timezone", "Europe/London")
    window = resolve_activity_window("7d", timezone_name)
    names = _activity_managed_names()
    current = activity_store.overview_range(window["start"], window["end"], None)
    previous = activity_store.overview_range(window["previous_start"], window["previous_end"], None)
    top_devices = activity_store.top_devices_range(window["start"], window["end"], 24)
    _decorate_activity_identity(top_devices, names)
    services = activity_store.top_services_range(window["start"], window["end"], 30, None)
    service_defs = policy_store.list_services()
    keys_by_name = {
        str(item.get("name") or "").lower(): str(item.get("key") or "")
        for item in service_defs
    }
    for item in services:
        item["service_key"] = keys_by_name.get(str(item.get("service_name") or "").lower(), "")
    new_domains = activity_store.new_domains_range(window["start"], window["end"], 30, 60, None)
    for item in new_domains:
        item["local_first_seen"] = _activity_local_timestamp(item.get("first_seen"), timezone_name)
    timeline = activity_store.evidence_timeline(window["start"], window["end"], None, 180)
    _decorate_activity_identity(timeline, names)
    for item in timeline:
        item["local_time"] = _activity_local_timestamp(item.get("event_time"), timezone_name)
    return {
        "schema": "zen_prepared_history_v1",
        "window": {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in window.items()},
        "current": current,
        "previous": previous,
        "comparison": compare_activity_totals(current, previous),
        "daily": activity_store.daily_history(window["start"], window["end"], timezone_name, None),
        "top_devices": top_devices,
        "services": services,
        "domains": activity_store.top_domains_range(window["start"], window["end"], 60, None),
        "new_domains": new_domains,
        "timeline": timeline,
        "active_periods": [],
        "timezone_name": timezone_name,
    }


def _build_device360_activity(address: str, timezone_name: str | None = None):
    activity = {}
    activity_error = None
    try:
        timezone_name = timezone_name or policy_store.get_settings().get(
            "policy_timezone", "Europe/London"
        )
        window = resolve_activity_window("today", timezone_name)
        current = activity_store.overview_range(window["start"], window["end"], address)
        previous = activity_store.overview_range(
            window["previous_start"], window["previous_end"], address
        )
        services = activity_store.top_services_range(window["start"], window["end"], 8, address)
        service_keys = {
            str(item.get("name") or "").strip().lower(): str(item.get("key") or "")
            for item in policy_store.list_services()
        }
        for item in services:
            item["service_key"] = service_keys.get(
                str(item.get("service_name") or "").strip().lower(), ""
            )
        activity = {
            "window": {
                key: (value.isoformat() if hasattr(value, "isoformat") else value)
                for key, value in window.items()
            },
            "current": current,
            "previous": previous,
            "services": services,
            "new_domains": activity_store.new_domains_range(
                window["start"], window["end"], 30, 8, address
            ),
            "blocked_domains": activity_store.blocked_domains_range(
                window["start"], window["end"], 8, address
            ),
            "timeline": activity_store.evidence_timeline(
                window["start"], window["end"], address, 16
            ),
        }
    except (ActivityError, ValueError) as exc:
        activity_error = str(exc)
    return activity, activity_error


@timed("device360.compose")
def get_device_360(address: str) -> dict:
    """Compose one read-only device operational view from existing evidence."""
    explanation = get_policy_explanation(address)
    device = explanation.get("device") or {}
    device_name = str(device.get("name") or address)

    try:
        reward_account = policy_store.get_reward_account(address, ledger_limit=6)
    except ValueError as exc:
        reward_account = {
            "ip": address,
            "enabled": False,
            "balance_minutes": 0,
            "ledger": [],
            "error": str(exc),
        }

    prepared, prepared_meta = _prepared_payload(
        f"device360:{address}", max_age_seconds=180
    )
    if prepared:
        activity = dict(prepared.get("activity") or {})
        activity_error = prepared.get("activity_error") or None
    else:
        _record_prepared_fallback(f"device360:{address}")
        activity, activity_error = _build_device360_activity(
            address, explanation.get("timezone") or None
        )

    try:
        incidents = filter_related_records(
            policy_store.list_incidents(include_resolved=True, limit=200),
            address,
            device_name,
            limit=8,
        )
    except Exception:
        incidents = []

    try:
        audit_events = filter_related_records(
            recent_audit(300), address, device_name, limit=10
        )
    except Exception:
        audit_events = []

    snapshot = build_device_360_snapshot(
        explanation=explanation,
        reward_account=reward_account,
        activity=activity,
        activity_error=activity_error,
        incidents=incidents,
        audit_events=audit_events,
    )
    snapshot["prepared_view"] = prepared_meta
    return snapshot


def _background_config_analytics(_payload: dict) -> dict:
    # Read-side only: this handler has no RouterOS adapter and cannot become an
    # alternate enforcement writer.
    return policy_store.build_config_analytics_snapshot()


def _background_prepared_view(payload: dict) -> dict:
    view = str((payload or {}).get("view") or "").strip()
    ttl_seconds = int((payload or {}).get("ttl_seconds") or 300)
    # A prepared model is one coherent analytical read bundle. Reuse one
    # PostgreSQL connection for the bundle instead of reconnecting for every
    # static query; the worker remains read-only and carries no RouterOS adapter.
    with activity_store.coherent_session():
        if view == "dashboard:24h":
            output = _prepare_dashboard_payload()
        elif view == "activity:24h":
            output = _prepare_activity_payload()
        elif view == "services:24h":
            output = _prepare_services_payload()
        elif view == "classification:24h":
            output = _classification_workbench_payload(24)
        elif view == "history:7d":
            output = _prepare_history_payload()
        elif view.startswith("device360:"):
            address = view.split(":", 1)[1]
            activity, activity_error = _build_device360_activity(address)
            output = {
                "schema": "zen_prepared_device360_activity_v1",
                "address": address,
                "activity": activity,
                "activity_error": activity_error,
            }
        else:
            raise ValueError(f"Unknown prepared view: {view}")
    saved = policy_store.save_prepared_view(
        view_key=view,
        kind="analytics.prepared-view",
        scope=str((payload or {}).get("scope") or "analytics:global"),
        payload=output,
        source_revision=int(policy_store.current_config_revision().get("revision") or 0),
        ttl_seconds=ttl_seconds,
    )
    return {
        "schema": "zen_prepared_view_result_v1",
        "view_key": view,
        "generation": int(saved.get("generation") or 0),
        "payload_bytes": int(saved.get("payload_bytes") or 0),
        "authority": "read-only-derived",
    }


def _background_retention(_payload: dict) -> dict:
    return {
        "schema": "zen_background_retention_v1",
        **policy_store.prune_background_history(
            retention_days=14, keep_jobs=250, keep_outbox=250
        ),
        "authority": "local-bookkeeping-only",
    }


def _schedule_background_analytics() -> int:
    """Idempotently publish periodic read-side refresh work.

    Two-minute buckets avoid queue floods while refreshing before the shortest
    prepared-view TTL expires. Configuration revision is part of each
    identity so stale service/policy semantics are never republished after a write.
    Device 360 jobs carry only telemetry/activity preparation; RouterOS evidence is
    still fresh-read synchronously by the request path.
    """
    now = datetime.now(timezone.utc)
    bucket = int(now.timestamp()) // 120
    revision = int(policy_store.current_config_revision().get("revision") or 0)
    specs = [
        ("dashboard:24h", "analytics:dashboard", 180),
        ("activity:24h", "analytics:activity", 180),
        ("services:24h", "analytics:services", 180),
        ("classification:24h", "analytics:classification", 300),
        ("history:7d", "analytics:history", 300),
    ]
    for address in sorted(policy_store.list_device_policy()):
        if address:
            specs.append((f"device360:{address}", f"analytics:device:{address}", 150))
    scheduled = 0
    for view, scope, ttl in specs:
        # Include the running release in derived-job identity so a deployment
        # that fixes a deterministic preparation defect can immediately publish
        # a new attempt even when it lands inside the same two-minute bucket as
        # a terminal job from the previous release. Pending obsolete work is
        # still coalesced by kind/scope.
        key = f"prepared:{view}:v{app.version}:r{revision}:b{bucket}"
        queued = policy_store.enqueue_background_job(
            kind="analytics.prepared-view",
            scope=scope,
            idempotency_key=key,
            payload={"view": view, "scope": scope, "ttl_seconds": ttl},
            max_attempts=3,
            replace_pending=True,
        )
        if queued and queued.get("created"):
            scheduled += 1
    hour_bucket = int(now.timestamp()) // 3600
    maintenance = policy_store.enqueue_background_job(
        kind="maintenance.background-retention",
        scope="maintenance:background",
        idempotency_key=f"background-retention:h{hour_bucket}",
        payload={},
        max_attempts=2,
    )
    return scheduled + (1 if maintenance and maintenance.get("created") else 0)


background_worker = BackgroundWorker(
    policy_store=policy_store,
    handlers={
        "analytics.config-summary": _background_config_analytics,
        "analytics.prepared-view": _background_prepared_view,
        "maintenance.background-retention": _background_retention,
    },
    producer=_schedule_background_analytics,
    audit=audit,
    max_jobs_per_cycle=12,
)


auto_reconciler = AutoReconciler(
    policy_store=policy_store,
    router=router,
    device_loader=get_live_devices,
    plan_loader=get_live_policy_plan,
    audit=audit,
)
operations_monitor = OperationsMonitor(
    policy_store=policy_store,
    router=router,
    reconciler=auto_reconciler,
    audit=audit,
    app_version=app.version,
)
incident_monitor = IncidentMonitor(
    policy_store=policy_store,
    router=router,
    reconciler=auto_reconciler,
    operations=operations_monitor,
    activity_store=activity_store,
    device_loader=get_live_devices,
    policy_loader=get_effective_policy,
    audit=audit,
)

summary_delivery = SummaryDeliveryService(
    policy_store=policy_store,
    summary_builder=lambda period: _build_parent_summary(period),
    audit=audit,
)

operational_diagnostics = OperationalDiagnostics(
    app_version=app.version,
    policy_store=policy_store,
    router=router,
    activity_store=activity_store,
    reconciler=auto_reconciler,
    incident_monitor=incident_monitor,
    summary_delivery=summary_delivery,
    performance_collector=performance_collector,
    service_contract_loader=custom_service_contract_definitions,
    ingest_status_loader=read_telemetry_ingest_status,
    classifier_status_loader=read_classifier_consumer_status,
)


def current_release_readiness() -> dict:
    """Capture the final application release gate without inventing healthy evidence."""
    try:
        operations = operations_monitor.readiness()
    except Exception:
        operations = {"ok": False, "issues": ["runtime readiness probe failed"]}
    try:
        startup = operations_monitor.startup_snapshot()
    except Exception:
        startup = {"status": "pending", "issues": ["startup evidence unavailable"]}
    try:
        diagnostics = operational_diagnostics.capture()
    except Exception:
        diagnostics = {
            "overall": "offline",
            "counts": {"healthy": 0, "warning": 0, "critical": 0, "offline": 1},
        }
    try:
        performance = current_performance_snapshot()
    except Exception:
        performance = {
            "acceptance": {"state": "pending", "targets": []},
            "formal_acceptance": {"state": "pending", "evidence_targets": []},
        }
    try:
        runtime_health = build_runtime_health(
            version=app.version,
            background_worker=background_worker,
            reconciler=auto_reconciler,
            incident_monitor=incident_monitor,
            summary_delivery=summary_delivery,
        )
    except Exception:
        runtime_health = {"schema": "zen_runtime_health_v1", "ok": False, "status": "degraded"}
    try:
        auth = {**auth_manager.dashboard_state(ADMIN_USER), "available": True}
    except Exception:
        auth = {
            "available": False,
            "shared_display_mode": False,
            "totp_count": 0,
            "login_mode": "unknown",
            "recovery_codes_remaining": 0,
        }

    return build_release_readiness(
        version=app.version,
        operations=operations,
        startup=startup,
        diagnostics=diagnostics,
        performance=performance,
        config_smoke=config_roundtrip_smoke(policy_store),
        restart=restart_evidence(policy_store, app.version),
        auth=auth,
        pwa=status_contract(app.version),
        runtime_health=runtime_health,
        secure_transport=current_secure_transport_status(),
    )


@app.on_event("startup")
def start_auto_reconciler():
    # Establish the durable configuration revision baseline before read-side
    # background processing starts. This never writes RouterOS.
    policy_store.ensure_config_revision_baseline(actor="system:startup")
    # Compile the large shared navigation template before the first browser GET.
    # This moves one-time Jinja parsing out of the formal navigation latency set.
    try:
        with perf_span("worker.template_warmup"):
            templates.env.get_template("index.html")
    except Exception as exc:
        audit("TEMPLATE_WARMUP_FAILED", "system:startup", str(exc))
    background_worker.start()

    # Reconcile every reserved reward debit against fresh RouterOS evidence. A
    # crash may happen before *or after* the RouterOS grant, so restart recovery
    # must never blindly refund a potentially-used allowance.
    reconcile_pending_reward_redemptions(
        policy_store=policy_store,
        router=router,
        audit=audit,
        router_error=RouterError,
    )
    # Publish the live service classifier catalogue before telemetry starts
    # relying on it. Failure is visible in audit but never prevents the UI.
    publish_service_catalog()

    # Seed v0.33 policy history from the same effective-policy resolver used by
    # reconciliation. Older retained telemetry intentionally remains unknown.
    for address in sorted(policy_store.list_device_policy()):
        try:
            get_effective_policy(address)
        except Exception as exc:
            audit("POLICY_HISTORY_CHECKPOINT_FAILED", "system:startup", f"{address}: {exc}")

    # Record a durable startup checkpoint and validate current authority.
    # RouterOS being unavailable degrades readiness but never prevents the UI
    # from starting, which keeps recovery controls available during incidents.
    operations_monitor.startup_check()
    auto_reconciler.start()
    incident_monitor.start()
    summary_delivery.start()


@app.on_event("shutdown")
def stop_auto_reconciler():
    summary_delivery.stop()
    background_worker.stop()
    incident_monitor.stop()
    auto_reconciler.stop()
    audit("APPLICATION_STOP", "system:shutdown", "FastAPI shutdown completed")



@app.get("/service-worker.js", include_in_schema=False)
def pwa_service_worker():
    """Serve the service worker at root scope without exposing application data."""
    return FileResponse(
        "app/static/service-worker.js",
        media_type="application/javascript",
        headers={
            "Service-Worker-Allowed": "/",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@app.get("/pwa/icon/{size}.png", include_in_schema=False)
def pwa_icon(size: int):
    if size not in {180, 192, 512}:
        raise HTTPException(status_code=404, detail="Unknown PWA icon size")
    return Response(
        content=icon_png(size),
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.get("/api/pwa/status")
def pwa_status(user=Depends(require_role("admin", "operator", "viewer"))):
    """Document the server-side PWA/security contract for the installed client."""
    return status_contract(app.version)


@app.get("/api/security/transport")
def secure_transport_api(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    """Sanitized secure-transport configuration readiness for commissioning."""
    return current_secure_transport_status()


def _safe_help_return(value: str | None) -> str:
    candidate = str(value or "").strip()
    if not candidate or not candidate.startswith("/") or candidate.startswith("//"):
        return ""
    if "://" in candidate or "\\" in candidate or "\n" in candidate or "\r" in candidate:
        return ""
    return candidate


@app.get("/api/help")
def api_help(
    topic: str = "getting_started",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    """Static read-only help contract; never includes household or credential data."""
    return help_api_payload(topic)


@app.get("/help", response_class=HTMLResponse)
def help_page(
    request: Request,
    topic: str = "getting_started",
    return_to: str = "",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    selected = get_help_topic(topic)
    back_label, owner_href = help_owner(selected["key"])
    back_href = _safe_help_return(return_to) or owner_href
    return templates.TemplateResponse(
        "help.html",
        {
            "request": request,
            "user": user,
            "selected": selected,
            "topics": help_catalog(),
            "back_label": back_label,
            "back_href": back_href,
        },
    )


@app.get("/health/live")
def health_live():
    return {"ok": True, "status": "alive", "version": app.version}


@app.get("/health/runtime")
def health_runtime():
    report = build_runtime_health(
        version=app.version,
        background_worker=background_worker,
        reconciler=auto_reconciler,
        incident_monitor=incident_monitor,
        summary_delivery=summary_delivery,
    )
    if not report.get("ok"):
        return JSONResponse(status_code=503, content=report)
    return report


@app.get("/health/ready")
def health_ready():
    report = operations_monitor.readiness()
    if not report.get("ok"):
        return JSONResponse(status_code=503, content=report)
    return report


@app.get("/health")
def health():
    """Readiness alias retained for monitoring clients that use /health."""
    report = operations_monitor.readiness()
    if not report.get("ok"):
        return JSONResponse(status_code=503, content=report)
    return report


def current_performance_snapshot() -> dict:
    """Compose formal performance evidence without adding measured workload."""
    snapshot = performance_collector.snapshot()
    background = background_worker.performance_snapshot()
    observation = auto_reconciler.performance_snapshot()
    try:
        raw_router = getattr(router, "__wrapped__", router)
        mutation = raw_router.mutation_status()
    except Exception as exc:
        mutation = {
            "schema": "zen_router_mutation_lane_v1",
            "available": False,
            "error": f"{type(exc).__name__}: {exc}"[:240],
        }
    counters = dict(snapshot.get("evidence_counters") or {})
    operational = {
        "schema": "zen_performance_operational_evidence_v1",
        "prepared_views": {
            "lookups": int(counters.get("prepared_view.lookup", 0) or 0),
            "hits": int(counters.get("prepared_view.hit", 0) or 0),
            "misses": int(counters.get("prepared_view.miss", 0) or 0),
            "fallbacks": int(counters.get("prepared_view.fallback", 0) or 0),
        },
        "background_worker": background,
        "parallel_observation": observation,
        "mutation_lane": mutation,
        "reconciliation_queue": policy_store.reconciliation_request_stats(),
    }
    snapshot["operational_evidence"] = operational
    snapshot["formal_acceptance"] = build_formal_acceptance(snapshot, operational)
    return snapshot


@app.get("/api/performance")
def api_performance(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return current_performance_snapshot()


@app.get("/performance", response_class=HTMLResponse)
def performance_page(
    request: Request,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return templates.TemplateResponse(
        "performance.html",
        {
            "request": request,
            "user": user,
            "csrf": request.session.get("csrf", ""),
            "snapshot": current_performance_snapshot(),
        },
    )


@app.get("/api/release-readiness")
def api_release_readiness(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return current_release_readiness()


@app.get("/release-readiness", response_class=HTMLResponse)
def release_readiness_page(
    request: Request,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return templates.TemplateResponse(
        "release_readiness.html",
        {
            "request": request,
            "user": user,
            "report": current_release_readiness(),
        },
    )


@app.get("/local/release-readiness/export")
def release_readiness_export(
    user=Depends(require_role("admin", "operator")),
):
    report = current_release_readiness()
    audit(
        "RELEASE_READINESS_EXPORTED",
        user["username"],
        f"version={report['version']} state={report['state']} pass={report['counts']['pass']} pending={report['counts']['pending']} fail={report['counts']['fail']}",
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": f'attachment; filename="zen-control-release-readiness-{stamp}.json"',
            "Cache-Control": "no-store",
        },
    )


@app.get("/api/operations/diagnostics")
def api_operational_diagnostics(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return operational_diagnostics.capture()


@app.get("/diagnostics", response_class=HTMLResponse)
def diagnostics_page(
    request: Request,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return templates.TemplateResponse(
        "diagnostics.html",
        {
            "request": request,
            "user": user,
            "report": operational_diagnostics.capture(),
        },
    )


@app.get("/local/operations/diagnostics/export")
def diagnostics_export(
    user=Depends(require_role("admin", "operator")),
):
    report = operational_diagnostics.capture()
    audit(
        "OPERATIONS_DIAGNOSTICS_EXPORTED",
        user["username"],
        f"schema={report['schema']} overall={report['overall']} checks={len(report['checks'])}",
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": f'attachment; filename="zen-control-diagnostics-{stamp}.json"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/local/performance/reset")
def performance_reset(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    # Audit before clearing so the reset action does not become part of the new
    # measurement window it creates.
    audit("PERFORMANCE_METRICS_RESET", user["username"], "in-memory v0.30 samples")
    performance_collector.reset()
    return RedirectResponse("/performance", status_code=303)


def login_template_context(request: Request, error: str | None = None):
    state = auth_manager.dashboard_state(ADMIN_USER)
    return {
        "request": request,
        "error": error,
        "admin_user": ADMIN_USER,
        "login_mode": state["login_mode"],
        "totp_count": state["totp_count"],
        "recovery_codes_remaining": state["recovery_codes_remaining"],
    }


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", login_template_context(request))


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(""),
    otp: str = Form(""),
):
    remote = request.client.host if request.client else "unknown"
    key = f"{remote}:{username}"
    fails = LOGIN_FAILS.get(key, {"count": 0, "until": 0})
    if fails["until"] > time.time():
        audit("LOGIN_BLOCKED", username, remote)
        return templates.TemplateResponse(
            "login.html",
            login_template_context(request, "Too many failed attempts. Try again shortly."),
            status_code=429,
        )

    user = USERS.get(username)
    account = auth_manager.account(username) if user else {"login_mode": "password"}
    method = None
    auth_detail = None

    if user and account["login_mode"] in {"password", "password_or_totp"}:
        if password and pwd.verify(password, user["hash"]):
            method = "password"

    auth_system_error = None
    if user and method is None and account["login_mode"] in {"password_or_totp", "totp_only"}:
        if otp:
            try:
                auth_detail = auth_manager.verify_otp_or_recovery(username, otp)
            except AuthError as exc:
                auth_system_error = str(exc)
                audit("LOGIN_AUTH_STORAGE_ERROR", username, auth_system_error)
                auth_detail = None
            if auth_detail:
                method = auth_detail["method"]

    if not user or method is None:
        count = fails["count"] + 1
        LOGIN_FAILS[key] = {
            "count": count,
            "until": time.time() + 60 if count >= 5 else 0,
        }
        audit("LOGIN_FAILED", username, f"{remote} mode={account.get('login_mode', 'unknown')}")
        return templates.TemplateResponse(
            "login.html",
            login_template_context(
                request,
                "Authenticator storage could not be opened; use a recovery code or password fallback."
                if auth_system_error else "Invalid credentials.",
            ),
            status_code=401,
        )

    LOGIN_FAILS.pop(key, None)
    request.session.clear()
    request.session["user"] = username
    request.session["csrf"] = secrets.token_urlsafe(24)
    request.session["auth_generation"] = auth_manager.session_generation(username)
    request.session["fresh_auth_at"] = time.time()
    request.session["fresh_auth_boot_id"] = PROCESS_BOOT_ID
    if account.get("shared_display_mode"):
        request.session["privileged_until"] = (
            time.time() + int(account.get("unlock_minutes", 5)) * 60
        )
        request.session["privileged_boot_id"] = PROCESS_BOOT_ID
    audit(
        "LOGIN_SUCCESS",
        username,
        f"{remote} method={method}"
        + (f" authenticator={auth_detail.get('device_name')}" if auth_detail else ""),
    )
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    user = current_user(request)
    if user:
        audit("LOGOUT", user["username"])
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.post("/auth/unlock")
def auth_unlock(
    request: Request,
    otp: str = Form(...),
    csrf: str = Form(...),
    next_tab: str = Form("dashboard"),
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] not in {"admin", "operator"}:
        raise HTTPException(status_code=403)
    if not csrf_ok(request, csrf):
        return redirect_error(next_tab, "CSRF validation failed")
    remote = request.client.host if request.client else "unknown"
    fail_key = f"unlock:{remote}:{user['username']}"
    fails = LOGIN_FAILS.get(fail_key, {"count": 0, "until": 0})
    if fails["until"] > time.time():
        audit("PARENT_UNLOCK_BLOCKED", user["username"], remote)
        return redirect_error(next_tab, "Too many failed parent codes. Try again shortly.")
    try:
        result = auth_manager.verify_otp_or_recovery(user["username"], otp)
    except AuthError as exc:
        audit("PARENT_UNLOCK_STORAGE_ERROR", user["username"], str(exc))
        return redirect_error(next_tab, "Authenticator storage error. Try a recovery code or check OTP_ENCRYPTION_KEY.")
    if not result:
        count = fails["count"] + 1
        LOGIN_FAILS[fail_key] = {
            "count": count,
            "until": time.time() + 60 if count >= 5 else 0,
        }
        audit("PARENT_UNLOCK_FAILED", user["username"], f"{remote} invalid OTP/recovery code")
        return redirect_error(
            next_tab,
            "Invalid or already-used authenticator code. Authenticator codes are single-use; "
            "if you just used this code, wait for the next 30-second code and try again.",
        )
    LOGIN_FAILS.pop(fail_key, None)
    mark_fresh_auth(request, privileged=True)
    state = auth_manager.account(user["username"])
    audit(
        "PARENT_UNLOCKED",
        user["username"],
        f"method={result['method']} duration={state['unlock_minutes']}m",
    )
    return redirect_ok(next_tab, f"Parent controls unlocked for {state['unlock_minutes']} minutes")


@app.post("/auth/extend")
def auth_extend(
    request: Request,
    otp: str = Form(...),
    csrf: str = Form(...),
    next_tab: str = Form("dashboard"),
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] not in {"admin", "operator"}:
        raise HTTPException(status_code=403)
    if not csrf_ok(request, csrf):
        return redirect_error(next_tab, "CSRF validation failed")

    state = session_auth_state(request, user["username"])
    now = time.time()
    if not state["shared_display_mode"]:
        return redirect_error(next_tab, "More time is only available in shared-display mode")
    if state["locked"]:
        return redirect_error(next_tab, "Parent controls are already locked. Unlock with a current OTP first.")
    if not shared_display_extension_allowed(
        shared_display_mode=True,
        privileged_until=float(request.session.get("privileged_until") or 0),
        privileged_boot_id=request.session.get("privileged_boot_id"),
        process_boot_id=PROCESS_BOOT_ID,
        now=now,
    ):
        return redirect_error(next_tab, "More time becomes available during the final 90 seconds")

    remote = request.client.host if request.client else "unknown"
    fail_key = f"extend:{remote}:{user['username']}"
    fails = LOGIN_FAILS.get(fail_key, {"count": 0, "until": 0})
    if fails["until"] > now:
        audit("PARENT_EXTEND_BLOCKED", user["username"], remote)
        return redirect_error(next_tab, "Too many failed parent codes. Try again shortly.")
    try:
        result = auth_manager.verify_otp_or_recovery(user["username"], otp)
    except AuthError as exc:
        audit("PARENT_EXTEND_STORAGE_ERROR", user["username"], str(exc))
        return redirect_error(next_tab, "Authenticator storage error. Try a recovery code or check OTP_ENCRYPTION_KEY.")
    if not result:
        count = fails["count"] + 1
        LOGIN_FAILS[fail_key] = {
            "count": count,
            "until": time.time() + 60 if count >= 5 else 0,
        }
        audit("PARENT_EXTEND_FAILED", user["username"], f"{remote} invalid OTP/recovery code")
        return redirect_error(
            next_tab,
            "Invalid or already-used authenticator code. Authenticator codes are single-use; "
            "if you just used this code, wait for the next 30-second code and try again.",
        )

    LOGIN_FAILS.pop(fail_key, None)
    account = auth_manager.account(user["username"])
    old_until = float(request.session.get("privileged_until") or 0)
    extended_until = extend_shared_display_deadline(
        privileged_until=old_until,
        unlock_minutes=int(account["unlock_minutes"]),
        now=now,
    )
    request.session["privileged_until"] = extended_until
    request.session["privileged_boot_id"] = PROCESS_BOOT_ID
    request.session["fresh_auth_at"] = now
    request.session["fresh_auth_boot_id"] = PROCESS_BOOT_ID
    audit(
        "PARENT_UNLOCK_EXTENDED",
        user["username"],
        f"method={result['method']} added={account['unlock_minutes']}m",
    )
    return redirect_ok(next_tab, f"Parent controls extended by {account['unlock_minutes']} minutes")


@app.post("/auth/lock")
def auth_lock(
    request: Request,
    csrf: str = Form(...),
    next_tab: str = Form("dashboard"),
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not csrf_ok(request, csrf):
        return redirect_error(next_tab, "CSRF validation failed")
    request.session["privileged_until"] = 0
    request.session["fresh_auth_at"] = 0
    request.session.pop("fresh_auth_boot_id", None)
    request.session.pop("privileged_boot_id", None)
    audit("PARENT_LOCKED", user["username"], "manual relock")
    return redirect_ok(next_tab, "Parent controls locked")


@app.post("/auth/totp/start")
def auth_totp_start(
    request: Request,
    device_name: str = Form(...),
    current_password: str = Form(""),
    otp: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/parents", "CSRF validation failed")
    try:
        verify_step_up(
            request, user["username"], password=current_password, otp=otp
        )
        enrollment = auth_manager.begin_enrollment(user["username"], device_name)
    except AuthError as exc:
        audit("TOTP_ENROLLMENT_FAILED", user["username"], str(exc))
        return redirect_error("settings/parents", str(exc))
    request.session["totp_enrollment_token"] = enrollment["token"]
    audit("TOTP_ENROLLMENT_STARTED", user["username"], f"name={device_name}")
    return redirect_ok("settings/parents", "Authenticator enrollment started. Scan the QR code and confirm it below.")


@app.post("/auth/totp/confirm")
def auth_totp_confirm(
    request: Request,
    token: str = Form(...),
    code: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/parents", "CSRF validation failed")
    try:
        result = auth_manager.confirm_enrollment(user["username"], token, code)
    except AuthError as exc:
        audit("TOTP_ENROLLMENT_FAILED", user["username"], str(exc))
        return redirect_error("settings/parents", str(exc))
    request.session.pop("totp_enrollment_token", None)
    mark_fresh_auth(request, privileged=True)
    device = result["device"]
    audit(
        "TOTP_DEVICE_ENROLLED",
        user["username"],
        f"id={device['id']} name={device['name']}",
    )
    if result.get("recovery_codes"):
        audit("RECOVERY_CODES_GENERATED", user["username"], "initial recovery set")
        return templates.TemplateResponse(
            "recovery_codes.html",
            {
                "request": request,
                "user": user,
                "codes": result["recovery_codes"],
                "reason": "First authenticator enrolled",
            },
        )
    return redirect_ok("settings/parents", f"Authenticator {device['name']} enrolled")


@app.post("/auth/totp/cancel")
def auth_totp_cancel(
    request: Request,
    token: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/parents", "CSRF validation failed")
    auth_manager.cancel_enrollment(user["username"], token)
    request.session.pop("totp_enrollment_token", None)
    audit("TOTP_ENROLLMENT_CANCELLED", user["username"], "")
    return redirect_ok("settings/parents", "Authenticator enrollment cancelled")


@app.post("/auth/totp/{device_id}/revoke")
def auth_totp_revoke(
    device_id: int,
    request: Request,
    current_password: str = Form(""),
    otp: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/parents", "CSRF validation failed")
    try:
        verify_step_up(
            request, user["username"], password=current_password, otp=otp
        )
        device = auth_manager.revoke_totp_device(user["username"], device_id)
    except AuthError as exc:
        return redirect_error("settings/parents", str(exc))
    audit("TOTP_DEVICE_REVOKED", user["username"], f"id={device_id} name={device.get('name')}")
    return redirect_ok("settings/parents", f"Authenticator {device.get('name')} revoked")


@app.post("/auth/recovery/regenerate")
def auth_recovery_regenerate(
    request: Request,
    current_password: str = Form(""),
    otp: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/parents", "CSRF validation failed")
    try:
        verify_step_up(
            request, user["username"], password=current_password, otp=otp
        )
        codes = auth_manager.regenerate_recovery_codes(user["username"])
    except AuthError as exc:
        return redirect_error("settings/parents", str(exc))
    audit("RECOVERY_CODES_GENERATED", user["username"], "replacement recovery set")
    return templates.TemplateResponse(
        "recovery_codes.html",
        {"request": request, "user": user, "codes": codes, "reason": "Recovery codes replaced"},
    )


@app.post("/auth/settings")
def auth_settings_save(
    request: Request,
    login_mode: str = Form(...),
    shared_display_mode: str = Form("0"),
    unlock_minutes: int = Form(5),
    current_password: str = Form(""),
    otp: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/parents", "CSRF validation failed")
    try:
        verify_step_up(
            request, user["username"], password=current_password, otp=otp
        )
        state = auth_manager.save_account_settings(
            user["username"],
            login_mode=login_mode,
            shared_display_mode=str(shared_display_mode).lower() in {"1", "true", "yes", "on"},
            unlock_minutes=unlock_minutes,
        )
    except AuthError as exc:
        audit("AUTH_SETTINGS_FAILED", user["username"], str(exc))
        return redirect_error("settings/parents", str(exc))
    if not state["shared_display_mode"]:
        request.session["privileged_until"] = 0
    audit(
        "AUTH_SETTINGS_UPDATED",
        user["username"],
        f"login_mode={state['login_mode']} shared={state['shared_display_mode']} unlock={state['unlock_minutes']}m",
    )
    return redirect_ok("settings/parents", "Parent authentication settings saved")


@app.post("/auth/sessions/revoke-all")
def auth_sessions_revoke_all(
    request: Request,
    current_password: str = Form(""),
    otp: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/parents", "CSRF validation failed")
    try:
        verify_step_up(
            request, user["username"], password=current_password, otp=otp
        )
    except AuthError as exc:
        return redirect_error("settings/parents", str(exc))
    generation = auth_manager.revoke_all_sessions(user["username"])
    audit("AUTH_SESSIONS_REVOKED", user["username"], f"generation={generation}")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, view: str = "dashboard", section: str = ""):

    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    active_view = str(view or "dashboard").strip().lower()
    if active_view not in ROOT_VIEWS:
        active_view = "dashboard"
    active_section = _section_for_view(active_view, section)

    auth_state = session_auth_state(request, user["username"])
    pending_totp = None
    auth_enrollment_error = None
    if active_view == "settings" and active_section == "parents":
        pending_token = request.session.get("totp_enrollment_token")
        if pending_token:
            try:
                pending_totp = auth_manager.enrollment(user["username"], pending_token)
            except AuthError as exc:
                auth_enrollment_error = str(exc)
            if not pending_totp:
                request.session.pop("totp_enrollment_token", None)

    # Cheap local defaults. v0.30.1 only loads the state needed by the selected
    # top-level view instead of rebuilding every panel after each POST/redirect.
    live_status = {"mode": "UNKNOWN", "temp_until": None, "slow_limit": None}
    devices = []
    web_policy = {"enabled": False}
    schedules = []
    local_profiles = []
    local_device_policy = {}
    policy_templates = []
    services = []
    bandwidth_presets_list = []
    bandwidth_presets = {}
    schedule_plans = []
    schedule_conflicts = []
    policy_clock = {}
    effective_policies = {}
    service_groups = []
    policy_group_catalog = {}
    policy_group_keys = frozenset()
    policy_group_usage = {}
    schedule_templates = []
    date_exceptions = []
    app_settings = {}
    reconciler_status = auto_reconciler.snapshot()
    security_posture = {
        "status": "unknown", "score": 0, "enforcement_ready": False,
        "critical_count": 0, "warning_count": 0, "checks": [],
        "stale": {"total": 0}, "authority": {}, "doh": {},
    }
    security_error = None
    discovery_error = None
    discovered_devices = []
    policy_summary = []
    policy_plans = {}
    operations_startup = operations_monitor.startup_snapshot()
    database_integrity = {"ok": True, "issues": []}
    config_snapshots = []
    audit_total = 0
    managed_inventory = {
        "counts": {}, "restricted_devices": [], "address_lists": [],
        "queues": [], "schedulers": [], "scripts": [], "firewall": [],
    }
    managed_inventory_error = None
    managed_inventory_notice = None
    service_enforcement_catalog = {}
    live_service_keys = frozenset()
    custom_service_defs = []
    custom_service_usage = {}
    service_contract_health = {
        "available": False, "services": [], "healthy": 0, "total": 0,
        "detector_addresses": 0, "degraded": 0, "reporting_only": 0,
    }
    service_contract_health_map = {}
    service_contract_error = None
    telemetry_available = False
    telemetry_source_available = False
    activity_overview = {}
    activity_devices = []
    activity_services = []
    activity_policy_services = []
    activity_domains = []
    activity_device_summaries = {}
    activity_insights = {}
    activity_coverage = {}
    activity_unknown_domains = []
    prepared_view_evidence = {}
    router_observation_evidence = {}
    managed_observation = None
    service_prefill_dns = (
        str(request.query_params.get("prefill_dns") or "").strip().lower().rstrip(".")[:253]
        if active_view == "policies" and active_section == "services" else ""
    )
    security_bypass_attempts = []
    security_bypass_evidence = []
    security_bypass_summary = summarize_bypass_evidence([])
    activity_error = None
    incident_status = incident_monitor.snapshot()
    summary_delivery_status = summary_delivery.snapshot()
    incident_counts = incident_status.get("counts") or policy_store.incident_counts()
    notification_counts = policy_store.notification_counts()
    notifications_inbox = []
    notifications_history = []
    notification_stats = {}
    incidents_active = []
    incidents_history = []
    connected_overview = {
        "state": "unknown",
        "counts": {"healthy": 0, "warning": 0, "critical": 0, "offline": 0},
        "areas": [],
    }
    audit_rows = []

    local_views = {"dashboard", "devices", "policies", "schedules", "activity", "settings"}
    if active_view in local_views:
        local_profiles = policy_store.list_profiles()
        local_device_policy = policy_store.list_device_policy()
        services = policy_store.list_services()
        policy_group_catalog = policy_store.policy_group_catalog()
        policy_group_keys = frozenset(policy_group_catalog)
        app_settings = policy_store.get_settings()
        bandwidth_presets_list = policy_store.list_bandwidth_presets()
        bandwidth_presets = {p["key"]: p for p in bandwidth_presets_list}
        service_enforcement_catalog = runtime_service_catalog()
        live_service_keys = frozenset(service_enforcement_catalog)
        custom_service_defs = custom_service_contract_definitions()
        if active_view == "policies" and active_section == "services":
            custom_service_usage = {
                item["key"]: policy_store.service_usage(item["key"])
                for item in custom_service_defs
            }

    if active_view == "activity":
        # Activity identity is a local desired-state concern. Do not block an
        # analytics page on a RouterOS inventory read merely to obtain names.
        devices = [
            {
                "name": str((cfg or {}).get("alias") or ip),
                "ip": str(ip),
                "address": str(ip),
                "dynamic": False,
            }
            for ip, cfg in sorted(local_device_policy.items())
            if str(ip)
        ]

    if active_view == "policies" and active_section in {"profiles", "tools"}:
        policy_templates = policy_store.list_templates()
        service_groups = policy_store.list_service_groups()
        if active_section == "tools":
            policy_group_usage = {
                key: policy_store.policy_group_usage(key) for key in policy_group_catalog
            }

    if active_view == "settings" and active_section == "policy":
        # Policy defaults only need the cheap local catalogue/profile state.
        pass

    if active_view == "schedules":
        schedule_plans = policy_store.list_schedule_plans()
        schedule_conflicts = (
            policy_store.detect_schedule_conflicts()
            + policy_store.detect_date_exception_conflicts()
        )
        policy_clock = policy_store.get_policy_clock()
        schedule_templates = policy_store.list_schedule_templates()
        date_exceptions = policy_store.list_date_exceptions()

    needs_devices = (
        active_view == "schedules"
        or (active_view == "policies" and active_section == "assignments")
        or (active_view == "settings" and active_section == "security")
    )
    router_read_error = None

    # Normal Dashboard/Devices/Activity navigation is advisory.  It consumes
    # the reconciler's already-fresh observation evidence instead of repeating
    # expensive RouterOS reads in the browser request. Explicit diagnostics,
    # Service Intelligence and mutation paths retain fresh RouterOS reads.
    if active_view in {"dashboard", "activity"}:
        cached_services, service_meta = _advisory_router_payload(
            "router:service-contract-health", max_age_seconds=180
        )
        router_observation_evidence["service_contract_health"] = service_meta
        if cached_services:
            service_contract_health = cached_services
            service_contract_health_map = {
                str(item.get("key") or ""): item
                for item in service_contract_health.get("services", [])
            }
            if service_meta.get("state") == "stale":
                service_contract_error = (
                    "Advisory service-contract evidence is stale; background "
                    "reconciliation is refreshing it."
                )
        else:
            service_contract_error = (
                "Advisory service-contract evidence is not ready; background "
                "reconciliation will refresh it without blocking this page."
            )

    if active_view == "dashboard":
        cached_security, security_meta = _advisory_router_payload(
            "router:security-posture", max_age_seconds=180
        )
        router_observation_evidence["security_posture"] = security_meta
        if cached_security:
            security_posture = cached_security
            if security_meta.get("state") == "stale":
                security_error = (
                    "Advisory RouterOS security evidence is stale; enforcement "
                    "writes still re-prove live posture."
                )

    if active_view in {"dashboard", "devices"}:
        managed_observation, managed_meta = _advisory_router_payload(
            "router:managed-device-observation", max_age_seconds=180
        )
        router_observation_evidence["managed_devices"] = managed_meta
        if managed_observation:
            observed_plans = dict(managed_observation.get("plans") or {})
            observed_errors = dict(managed_observation.get("errors") or {})
            devices = [dict(item) for item in (managed_observation.get("devices") or [])]
            for device in devices:
                address = str(device.get("ip") or device.get("address") or "")
                device["ip"] = address
                device["address"] = address
                plan = dict(observed_plans.get(address) or {})
                if address in observed_errors and not plan:
                    plan = {
                        "address": address, "status": "error",
                        "error": observed_errors[address], "mode_actionable": False,
                    }
                policy_plans[address] = plan
                live_evidence = dict(plan.get("live_evidence") or {})
                if live_evidence:
                    device["live_enforcement"] = dict(live_evidence.get("enforcement") or {})
                    device["temporary_access"] = dict(live_evidence.get("temporary_access") or {})
                    device["live_services"] = dict(live_evidence.get("services") or {})
                    device["live_bandwidth"] = dict(live_evidence.get("bandwidth") or {})
                if active_view == "devices":
                    try:
                        device["reward_account"] = policy_store.get_reward_account(address, ledger_limit=6)
                    except ValueError as exc:
                        device["reward_account"] = {
                            "ip": address, "balance_minutes": 0, "ledger": [],
                            "enabled": False, "error": str(exc),
                        }
            global_modes = [
                str(plan.get("global_mode") or "").upper()
                for plan in observed_plans.values() if plan.get("global_mode")
            ]
            if global_modes:
                live_status["mode"] = global_modes[0]
        else:
            # Missing observation is explicit UNKNOWN evidence.  Local desired
            # identities remain useful, but live controls are withheld until the
            # reconciler publishes a fresh observation.
            devices = [
                {
                    "name": str((cfg or {}).get("alias") or ip),
                    "ip": str(ip), "address": str(ip), "dynamic": False,
                }
                for ip, cfg in sorted(local_device_policy.items()) if str(ip)
            ]
            for device in devices:
                policy_plans[device["ip"]] = {
                    "address": device["ip"], "status": "error",
                    "error": "RouterOS advisory observation is not ready",
                    "mode_actionable": False,
                }
        if active_view == "devices":
            discovered = policy_store.list_discovery_cache()
            restricted_ips = {d["ip"] for d in devices}
            discovered_devices = []
            for item in discovered:
                ip = item.get("address") or item.get("ip")
                if ip:
                    discovered_devices.append({**item, "ip": ip, "managed": ip in restricted_ips})

    if active_view == "settings" and active_section == "operations":
        managed_inventory, managed_inventory_meta = _advisory_router_payload(
            "router:managed-state-inventory", max_age_seconds=300
        )
        router_observation_evidence["managed_inventory"] = managed_inventory_meta
        if managed_inventory:
            if managed_inventory_meta.get("state") == "stale":
                managed_inventory_notice = (
                    "Managed RouterOS inventory is advisory and stale; background "
                    "reconciliation or an explicit live inventory check will refresh it."
                )
        else:
            startup_inventory = dict(
                ((operations_startup.get("inventory") or {}).get("detail") or {})
            )
            if startup_inventory:
                managed_inventory = startup_inventory
                managed_inventory_notice = (
                    "Live advisory inventory is not published yet; showing the startup "
                    "inventory snapshot without blocking this navigation request."
                )
            else:
                managed_inventory = {
                    "counts": {}, "restricted_devices": [], "address_lists": [],
                    "queues": [], "schedulers": [], "scripts": [], "firewall": [],
                }
                managed_inventory_error = (
                    "Managed RouterOS inventory evidence is not ready. Use the explicit "
                    "live inventory endpoint or wait for background reconciliation."
                )

    needs_router = (
        needs_devices
        or active_view == "dashboard"  # cheap web-policy status only
        or (active_view == "policies" and active_section == "services")
        or (active_view == "settings" and active_section == "security")
    )

    # Reuse one RouterOS transport for the synchronous surfaces that explicitly
    # require fresh RouterOS state. Dashboard/Managed Devices consume the
    # reconciler's revision-bound advisory observation above instead of repeating
    # the multi-second inventory/service scan in the browser request. Write and
    # validation routes never consume that prepared evidence and continue to
    # fresh-read RouterOS directly inside the mutation authority boundary.
    if needs_router:
        try:
            with router.coherent_session():                # Dashboard consumes advisory prepared RouterOS evidence above.
                # Fresh service-contract probes stay on the explicit Activity /
                # Service Intelligence paths instead of blocking navigation.

                if needs_devices:
                    devices = get_live_devices()

                if active_view == "dashboard":
                    # The expensive managed-device observation is supplied by the
                    # reconciler read model above. Keep only this small explicit
                    # web-policy status read on the normal Dashboard request.
                    web_policy = router.get_web_policy_status()

                if active_view == "schedules":
                    schedules = router.get_managed_schedules()

                if active_view == "policies" and active_section == "services":
                    try:
                        service_contract_health = router.get_service_contract_health(custom_service_defs)
                        _publish_router_observation(
                            "router:service-contract-health", service_contract_health,
                            scope="router:service-contracts", ttl_seconds=180,
                        )
                    except RouterError as exc:
                        service_contract_error = str(exc)
                        service_contract_health = {
                            "available": False, "services": [], "healthy": 0,
                            "total": len(service_enforcement_catalog), "detector_addresses": 0,
                            "degraded": 0, "reporting_only": len(custom_service_defs),
                        }
                    service_contract_health_map = {
                        str(item.get("key") or ""): item
                        for item in service_contract_health.get("services", [])
                    }

                if active_view == "settings" and active_section == "security":
                    try:
                        security_posture = router.get_security_posture()
                        _publish_router_observation(
                            "router:security-posture", security_posture,
                            scope="router:security", ttl_seconds=180,
                        )
                    except RouterError as exc:
                        security_error = str(exc)
                        security_posture = {
                            "status": "critical", "score": 0, "enforcement_ready": False,
                            "critical_count": 1, "warning_count": 0, "checks": [],
                            "stale": {"total": 0}, "authority": {"global_mode": "unknown"},
                            "doh": {"expected": len(DOH_ROUTER_RULES), "valid": 0, "errors": [str(exc)]},
                        }
        except RouterError as exc:
            router_read_error = str(exc)
            audit("ROUTER_READ_FAILED", user["username"], str(exc))

    # Dashboard favourites reuse the reconciler's revision-bound desired-policy
    # projection. Recomputing effective policy for every device created more than
    # one hundred SQLite transactions per click and dominated warm Dashboard latency.
    # The full policy summary route keeps its canonical local resolver.
    if active_view == "dashboard":
        policy_summary = _build_advisory_policy_summary(
            devices, local_device_policy, local_profiles, policy_plans
        )
    elif active_view == "policies":
        policy_summary = policy_store.build_policy_summary(devices)

    if active_view in {"activity", "dashboard"}:
        try:
            managed_ips = [device.get("ip") for device in devices if device.get("ip")]
            view_key = "activity:24h" if active_view == "activity" else "dashboard:24h"
            prepared, prepared_meta = _prepared_payload(
                view_key, allow_stale_same_revision=True
            )
            prepared_view_evidence[active_view] = prepared_meta
            if prepared:
                telemetry_available = bool(prepared.get("telemetry_available", True))
                telemetry_source_available = telemetry_available
            else:
                telemetry_available = False
                try:
                    telemetry_source_available = bool(activity_store.health())
                except ActivityError:
                    telemetry_source_available = False
                prepared_state = str((prepared_meta or {}).get("state") or "missing")
                if telemetry_source_available and prepared_state == "failed":
                    activity_error = (
                        "Telemetry source is online, but prepared read-model generation failed. "
                        "The background worker will retry without running live analytics in this request."
                    )
                elif telemetry_source_available and prepared_state == "preparing":
                    activity_error = (
                        "Telemetry source is online and the prepared read model is being generated. "
                        "No live analytics fallback was run in this navigation request."
                    )
                elif telemetry_source_available:
                    activity_error = (
                        "Telemetry source is online, but prepared evidence is not published yet; "
                        "the background worker has been asked to refresh it."
                    )
                else:
                    activity_error = (
                        "Telemetry source health is unavailable and prepared evidence is not ready. "
                        "The rest of ZEN Control continues to operate normally."
                    )

            if active_view == "activity" and prepared:
                activity_overview = dict(prepared.get("overview") or {})
                activity_devices = [dict(row) for row in (prepared.get("devices") or [])]
                observed_services = [dict(row) for row in (prepared.get("observed_services") or [])]
                activity_services = observed_services[:12]
                activity_domains = list(prepared.get("domains") or [])
                activity_device_summaries = dict(prepared.get("device_summaries") or {})
                dns_service_rows = [dict(row) for row in (prepared.get("dns_service_rows") or [])]
                activity_coverage = dict(prepared.get("coverage") or {})
                activity_unknown_domains = list(prepared.get("unknown_domains") or [])
                activity_insights = dict(prepared.get("activity_insights") or {})
                if telemetry_available:
                    managed_names = {}
                    for device in devices:
                        ip = str(device.get("ip") or "")
                        if ip:
                            cfg = local_device_policy.get(ip, {})
                            managed_names[ip] = str(cfg.get("alias") or device.get("name") or ip)
                    for row in activity_devices:
                        ip = str(row.get("client_ip") or "")
                        row["managed"] = ip in managed_names
                        row["display_name"] = managed_names.get(ip, row.get("display_name") or ip)
                        row["detail"] = activity_device_summaries.get(ip, row.get("detail") or {})
                    activity_policy_services = build_service_intelligence(
                        services, observed_services, dns_service_rows,
                        service_contract_health, policy_group_catalog, local_profiles
                    )
                    activity_insights.update({
                        "policy_services": len(services),
                        "policy_services_observed": sum(
                            1 for row in activity_policy_services
                            if row.get("policy_tracked") and row.get("observed")
                        ),
                        "managed_devices": len(managed_ips),
                        "tls_contracts_healthy": int(service_contract_health.get("healthy", 0)),
                        "tls_contracts_total": int(service_contract_health.get("total", 0)),
                        "detector_addresses": int(service_contract_health.get("detector_addresses", 0)),
                    })
            elif active_view == "dashboard" and prepared:
                activity_insights = dict(prepared.get("activity_insights") or {})
                activity_coverage = dict(prepared.get("activity_coverage") or {})
                security_bypass_attempts = list(prepared.get("security_bypass_attempts") or [])
                security_bypass_evidence = list(prepared.get("security_bypass_evidence") or [])
                security_bypass_summary = dict(
                    prepared.get("security_bypass_summary") or summarize_bypass_evidence([])
                )
                activity_insights["managed_devices"] = len(managed_ips)
        except ActivityError as exc:
            activity_error = str(exc)

    elif active_view == "settings" and active_section == "security":
        # The explicit security surface may still gather fresh telemetry evidence;
        # it is not part of the fast advisory navigation contract above.
        try:
            managed_ips = [device.get("ip") for device in devices if device.get("ip")]
            telemetry_available = activity_store.health()
            if telemetry_available:
                activity_coverage = activity_store.classification_coverage(24)
                security_bypass_attempts = activity_store.bypass_attempts(managed_ips, 24, 30)
                security_bypass_evidence = activity_store.bypass_evidence(managed_ips, 24, 120)
                security_bypass_summary = summarize_bypass_evidence(security_bypass_evidence)
        except ActivityError as exc:
            activity_error = str(exc)

    if active_view == "notifications":
        notifications_inbox = policy_store.list_notifications(archived=False, limit=120)
        notifications_history = policy_store.list_notifications(archived=True, limit=80)
        notification_stats = policy_store.notification_stats()
        for item in notifications_inbox + notifications_history:
            item["context_link"] = notification_destination(
                item.get("source", ""),
                item.get("event_type", ""),
                item.get("target_url", ""),
            )

    if active_view == "incidents":
        incidents_active = policy_store.list_incidents(include_resolved=False, limit=80)
        incidents_history = [
            item for item in policy_store.list_incidents(include_resolved=True, limit=120)
            if item.get("status") == "resolved"
        ][:30]
        for item in incidents_active:
            item["context_link"] = incident_destination(item.get("source", ""))
        for item in incidents_history:
            item["context_link"] = incident_destination(item.get("source", ""))

    if active_view == "dashboard" or (active_view == "settings" and active_section == "operations"):
        database_integrity = policy_store.database_integrity_report()
        audit_total = policy_store.audit_count()
        if active_view == "settings":
            config_snapshots = policy_store.list_config_snapshots(12)

    if active_view == "audit":
        audit_total = policy_store.audit_count()
        audit_rows = recent_audit(100)
        for row in audit_rows:
            row["context_link"] = audit_destination(row.get("event", ""))

    if active_view == "dashboard":
        # Dashboard keeps the connected-health composition, but it no longer
        # pays for unrelated Discovery, Settings inventory, schedule editors or
        # the full Activity panel DOM/data on every request.
        connected_overview = build_connected_overview(
            live_status=live_status,
            devices=devices,
            policy_plans=policy_plans,
            security_posture=security_posture,
            reconciler_status=reconciler_status,
            service_contract_health=service_contract_health,
            telemetry_available=telemetry_source_available,
            activity_insights=activity_insights,
            database_integrity=database_integrity,
            operations_startup=operations_startup,
            incident_counts=incident_counts,
            audit_total=audit_total,
        )

    if router_read_error and active_view in {"dashboard", "devices"}:
        live_status = {
            "mode": "ERROR", "temp_until": None, "slow_limit": None,
            "error": router_read_error,
        }

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "active_view": active_view,
            "active_section": active_section,
            "user": user,
            "auth_state": auth_state,
            "pending_totp": pending_totp,
            "auth_enrollment_error": auth_enrollment_error,
            "status": live_status,
            "web_policy": web_policy,
            "devices": devices,
            "schedules": schedules,
            "local_profiles": local_profiles,
            "local_device_policy": local_device_policy,
            "policy_templates": policy_templates,
            "services": (
                [(s["key"], s["name"]) for s in services if s["key"] not in policy_group_keys]
                + [(key, item["name"]) for key, item in policy_group_catalog.items()]
            ),
            "concrete_services": [
                (s["key"], s["name"]) for s in services if s["key"] not in policy_group_keys
            ],
            "service_defs": services,
            "service_enforcement_catalog": service_enforcement_catalog,
            "live_service_keys": live_service_keys,
            "custom_service_contracts": {
                item["key"]: item.get("routeros_contract")
                for item in custom_service_defs if item.get("routeros_contract")
            },
            "custom_service_usage": custom_service_usage,
            "policy_group_catalog": policy_group_catalog,
            "policy_group_keys": policy_group_keys,
            "policy_group_usage": policy_group_usage,
            "bandwidth_presets": bandwidth_presets,
            "bandwidth_presets_list": bandwidth_presets_list,
            "device_categories": DEVICE_CATEGORIES,
            "schedule_plans": schedule_plans,
            "schedule_conflicts": schedule_conflicts,
            "effective_policies": effective_policies,
            "policy_plans": policy_plans,
            "service_groups": service_groups,
            "schedule_templates": schedule_templates,
            "date_exceptions": date_exceptions,
            "app_settings": app_settings,
            "config_revision": int(policy_store.current_config_revision().get("revision") or 0),
            "reconciler_status": reconciler_status,
            "security_posture": security_posture,
            "security_error": security_error,
            "security_bypass_attempts": security_bypass_attempts,
            "security_bypass_evidence": security_bypass_evidence,
            "security_bypass_summary": security_bypass_summary,
            "doh_router_rules": DOH_ROUTER_RULES,
            "policy_clock": policy_clock,
            "discovered_devices": discovered_devices,
            "discovery_error": discovery_error,
            "policy_summary": policy_summary,
            "operations_startup": operations_startup,
            "database_integrity": database_integrity,
            "config_snapshots": config_snapshots,
            "audit_total": audit_total,
            "incident_status": incident_status,
            "summary_delivery_status": summary_delivery_status,
            "secure_transport": current_secure_transport_status(),
            "incident_counts": incident_counts,
            "notification_counts": notification_counts,
            "notifications_inbox": notifications_inbox,
            "notifications_history": notifications_history,
            "notification_stats": notification_stats,
            "incidents_active": incidents_active,
            "incidents_history": incidents_history,
            "connected_overview": connected_overview,
            "managed_inventory": managed_inventory,
            "managed_inventory_error": managed_inventory_error,
            "managed_inventory_notice": managed_inventory_notice,
            "service_contract_health": service_contract_health,
            "service_contract_health_map": service_contract_health_map,
            "service_contract_error": service_contract_error,
            "telemetry_available": telemetry_available,
            "telemetry_source_available": telemetry_source_available,
            "activity_overview": activity_overview,
            "activity_devices": activity_devices,
            "activity_services": activity_services,
            "activity_policy_services": activity_policy_services,
            "activity_domains": activity_domains,
            "activity_device_summaries": activity_device_summaries,
            "activity_insights": activity_insights,
            "activity_coverage": activity_coverage,
            "activity_unknown_domains": activity_unknown_domains,
            "prepared_view_evidence": prepared_view_evidence,
            "router_observation_evidence": router_observation_evidence,
            "service_prefill_dns": service_prefill_dns,
            "activity_error": activity_error,
            "flash_error": request.query_params.get("error"),
            "flash_ok": request.query_params.get("ok"),
            "audit": audit_rows,
            "csrf": request.session["csrf"],
        },
    )


@app.get("/api/services/health")
def api_service_health(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        health = router.get_service_contract_health(custom_service_contract_definitions())
        _publish_router_observation(
            "router:service-contract-health", health,
            scope="router:service-contracts", ttl_seconds=180,
        )
        return health
    except RouterError as exc:
        raise HTTPException(status_code=503, detail=str(exc))



@app.get("/api/activity/overview")
def api_activity_overview(
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        if int(hours) == 24:
            prepared, meta = _prepared_payload(
                "activity:24h", allow_stale_same_revision=True
            )
            if prepared and prepared.get("telemetry_available"):
                return {
                    "overview": prepared.get("overview") or {},
                    "devices": list(prepared.get("devices") or [])[:20],
                    "services": list(prepared.get("observed_services") or [])[:20],
                    "domains": list(prepared.get("domains") or [])[:20],
                    "prepared_view": meta,
                }
            return {
                "state": str((meta or {}).get("state") or "preparing"),
                "overview": {}, "devices": [], "services": [], "domains": [],
                "prepared_view": meta,
                "evidence_note": "Prepared activity evidence is not ready; background refresh requested.",
            }
        with activity_store.coherent_session():
            return {
                "overview": activity_store.overview(hours),
                "devices": activity_store.top_devices(hours, 20),
                "services": activity_store.top_services(hours, 20),
                "domains": activity_store.dns_top_domains(hours, 20),
                "prepared_view": None,
            }
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/activity/device/{client_ip}")
def api_activity_device(
    client_ip: str,
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        return {
            "device": activity_store.device_detail(client_ip, hours),
            "series": activity_store.traffic_series(client_ip, hours),
            "services": activity_store.top_services(hours, 20, client_ip),
            "destinations": activity_store.top_destinations(hours, 20, client_ip),
            "domains": activity_store.dns_top_domains(hours, 20, client_ip),
            "dns": activity_store.recent_dns(hours, 50, client_ip),
        }
    except (ActivityError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/activity/services")
def api_activity_services(
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        prepared = meta = None
        if int(hours) == 24:
            prepared, meta = _prepared_payload(
                "services:24h", allow_stale_same_revision=True
            )
        if prepared and prepared.get("telemetry_available"):
            observed = [dict(row) for row in (prepared.get("traffic") or [])]
            dns_rows = [dict(row) for row in (prepared.get("dns") or [])]
            coverage = dict(prepared.get("coverage") or {})
            unknown = list(prepared.get("unknown_domains") or [])
        elif int(hours) == 24:
            observed, dns_rows, coverage, unknown = [], [], {}, []
        else:
            with activity_store.coherent_session():
                observed = activity_store.top_services(hours, 100)
                dns_rows = activity_store.dns_top_services(hours, 100)
                coverage = activity_store.classification_coverage(hours)
                unknown = activity_store.unknown_domains(hours, 50)
        if int(hours) == 24:
            health, _health_meta = _advisory_router_payload(
                "router:service-contract-health", max_age_seconds=180
            )
            health = health or {"available": False, "services": []}
        else:
            try:
                health = router.get_service_contract_health()
            except RouterError:
                health = {"available": False, "services": []}
        return {
            "traffic": observed,
            "policy_services": build_service_intelligence(
                policy_store.list_services(), observed, dns_rows, health,
                policy_store.policy_group_catalog(), policy_store.list_profiles()
            ),
            "dns": dns_rows,
            "coverage": coverage,
            "unknown_domains": unknown,
            "routeros": health,
            "prepared_view": meta,
        }
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/activity/dns")
def api_activity_dns(
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        return {
            "domains": activity_store.dns_top_domains(hours, 50),
            "services": activity_store.dns_top_services(hours, 50),
            "recent": activity_store.recent_dns(hours, 100),
        }
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


def _activity_managed_names():
    local = policy_store.list_device_policy()
    names = {}
    for ip, cfg in local.items():
        if ip:
            names[str(ip)] = str(cfg.get("alias") or ip)
    try:
        for item in router.get_restricted_devices():
            ip = str(item.get("address") or item.get("ip") or "")
            if not ip:
                continue
            cfg = local.get(ip, {})
            names[ip] = str(cfg.get("alias") or item.get("name") or names.get(ip) or ip)
    except RouterError:
        pass
    return names


def _policy_correlation_managed_names():
    """Return managed-device display names for policy-history selectors.

    Prefer local aliases, then the same RouterOS-backed names used by Activity.
    If no name is available, return the IP alone; callers must not render
    ``IP (IP)`` as if it were a distinct device name.
    """
    local = policy_store.list_device_policy()
    activity_names = _activity_managed_names()
    result = {}
    for ip, cfg in local.items():
        ip = str(ip)
        candidate = str(cfg.get("alias") or activity_names.get(ip) or "").strip()
        result[ip] = candidate if candidate and candidate != ip else ""
    return result


def _decorate_activity_identity(rows, names):
    for item in rows or []:
        ip = str(item.get("client_ip") or "")
        item["managed"] = ip in names
        item["display_name"] = names.get(ip, ip)
    return rows


def _activity_local_timestamp(value, timezone_name):
    if not value:
        return ""
    try:
        tz = ZoneInfo(timezone_name)
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            return dt.strftime("%Y-%m-%d %H:%M")
        return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")
    except (ValueError, ZoneInfoNotFoundError):
        return str(value)


@timed("summary.compose")
def _build_parent_summary(period="today"):
    """Build the read-only daily parent summary from retained network evidence."""
    period = str(period or "today").strip().lower()
    if period not in {"today", "yesterday"}:
        raise ValueError("Parent summary period must be today or yesterday")

    settings = policy_store.get_settings()
    timezone_name = settings.get("policy_timezone", "Europe/London")
    window = resolve_activity_window(period, timezone_name)
    names = _activity_managed_names()
    local_devices = policy_store.list_device_policy()
    service_defs = policy_store.list_services()
    keys_by_name = {
        str(item.get("name") or "").strip().lower(): str(item.get("key") or "")
        for item in service_defs
    }
    quota_current = period == "today"
    devices = []

    for ip, name in sorted(names.items(), key=lambda item: (item[1].lower(), item[0])):
        current = activity_store.overview_range(window["start"], window["end"], ip)
        previous = activity_store.overview_range(
            window["previous_start"], window["previous_end"], ip
        )
        services = activity_store.top_services_range(window["start"], window["end"], 6, ip)
        for item in services:
            item["service_key"] = keys_by_name.get(
                str(item.get("service_name") or "").strip().lower(), ""
            )
        new_domains = activity_store.new_domains_range(
            window["start"], window["end"], 30, 12, ip
        )
        blocked_domains = activity_store.blocked_domains_range(
            window["start"], window["end"], 12, ip
        )
        for item in new_domains:
            item["local_first_seen"] = _activity_local_timestamp(
                item.get("first_seen"), timezone_name
            )
        for item in blocked_domains:
            item["local_last_seen"] = _activity_local_timestamp(
                item.get("last_seen"), timezone_name
            )

        quota = {}
        if quota_current:
            try:
                quota = get_effective_policy(ip).get("quota_state") or {}
            except ValueError as exc:
                quota = {
                    "configured": False,
                    "available": False,
                    "telemetry_error": str(exc),
                }

        cfg = local_devices.get(ip, {})
        devices.append(build_parent_device_summary(
            ip=ip,
            name=name,
            profile_name=cfg.get("profile_name") or "Unassigned",
            current=current,
            previous=previous,
            services=services,
            new_domains=new_domains,
            blocked_domains=blocked_domains,
            quota=quota,
            quota_current=quota_current,
        ))

    household = summarize_parent_household(devices)
    for totals in (household["current"], household["previous"]):
        for key in ("total_bytes", "download_bytes", "upload_bytes", "attributed_bytes"):
            totals[key + "_human"] = format_activity_bytes(totals.get(key, 0))

    attention = []
    for device in devices:
        for item in device.get("attention_domains", []):
            row = dict(item)
            row["client_ip"] = device["ip"]
            row["device_name"] = device["name"]
            attention.append(row)
    attention.sort(key=lambda item: (
        -int(item.get("blocked") or 0),
        0 if "new" in item.get("tags", []) else 1,
        -int(item.get("queries") or 0),
        item.get("domain") or "",
    ))

    return {
        "period": period,
        "window": window,
        "timezone_name": timezone_name,
        "devices": devices,
        "household": household,
        "attention_domains": attention[:30],
        "quota_current": quota_current,
        "evidence_note": (
            "Summary facts come from retained IPFIX and Pi-hole DNS evidence. "
            "They are not browser history, foreground-app time or proof of who used a device."
        ),
    }


@app.get("/api/activity/summary")
def api_activity_summary(
    period: str = "today",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        payload = _build_parent_summary(period)
        payload["window"] = {
            key: (value.isoformat() if hasattr(value, "isoformat") else value)
            for key, value in payload["window"].items()
        }
        return payload
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/activity/summary", response_class=HTMLResponse)
def activity_summary_page(
    request: Request,
    period: str = "today",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    error = None
    try:
        payload = _build_parent_summary(period)
    except (ActivityError, ValueError) as exc:
        error = str(exc)
        settings = policy_store.get_settings()
        timezone_name = settings.get("policy_timezone", "Europe/London")
        try:
            window = resolve_activity_window("today", timezone_name)
        except ValueError:
            window = {}
        payload = {
            "period": "today",
            "window": window,
            "timezone_name": timezone_name,
            "devices": [],
            "household": {},
            "attention_domains": [],
            "quota_current": True,
            "evidence_note": (
                "Summary facts come from retained IPFIX and Pi-hole DNS evidence. "
                "They are not browser history, foreground-app time or proof of who used a device."
            ),
        }

    return templates.TemplateResponse(
        "activity_summary.html",
        {
            "request": request,
            "user": user,
            "error": error,
            **payload,
        },
        status_code=503 if error else 200,
    )


@app.get("/api/activity/analytics")
def api_activity_analytics(
    period: str = "7d",
    client_ip: str = "",
    start: str = "",
    end: str = "",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        selected = str(client_ip or "").strip() or None
        if (str(period or "7d").lower() == "7d" and not selected and not start and not end):
            prepared, meta = _prepared_payload("history:7d")
            if prepared:
                return {
                    "window": prepared.get("window") or {},
                    "current": prepared.get("current") or {},
                    "previous": prepared.get("previous") or {},
                    "comparison": prepared.get("comparison") or {},
                    "daily": prepared.get("daily") or [],
                    "services": prepared.get("services") or [],
                    "domains": prepared.get("domains") or [],
                    "new_domains": prepared.get("new_domains") or [],
                    "timeline": prepared.get("timeline") or [],
                    "active_periods": [],
                    "prepared_view": meta,
                }
            _record_prepared_fallback("history:7d")
        settings = policy_store.get_settings()
        timezone_name = settings.get("policy_timezone", "Europe/London")
        window = resolve_activity_window(period, timezone_name, start, end)
        if selected:
            import ipaddress as _ipaddress
            _ipaddress.ip_address(selected)
        current = activity_store.overview_range(window["start"], window["end"], selected)
        previous = activity_store.overview_range(window["previous_start"], window["previous_end"], selected)
        return {
            "window": {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in window.items()},
            "current": current,
            "previous": previous,
            "comparison": compare_activity_totals(current, previous),
            "daily": activity_store.daily_history(window["start"], window["end"], timezone_name, selected),
            "services": activity_store.top_services_range(window["start"], window["end"], 30, selected),
            "domains": activity_store.top_domains_range(window["start"], window["end"], 50, selected),
            "new_domains": activity_store.new_domains_range(window["start"], window["end"], 30, 50, selected),
            "timeline": activity_store.evidence_timeline(window["start"], window["end"], selected, 160),
            "active_periods": activity_store.active_periods(selected, window["start"], window["end"], 30, 50) if selected else [],
            "prepared_view": None,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/activity/analytics", response_class=HTMLResponse)
def activity_analytics_page(
    request: Request,
    period: str = "7d",
    client_ip: str = "",
    start: str = "",
    end: str = "",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    settings = policy_store.get_settings()
    timezone_name = settings.get("policy_timezone", "Europe/London")
    names = _activity_managed_names()
    error = None
    selected = str(client_ip or "").strip()
    prepared_meta = None
    try:
        prepared = None
        if (str(period or "7d").lower() == "7d" and not selected and not start and not end):
            prepared, prepared_meta = _prepared_payload("history:7d")
        if prepared:
            window = dict(prepared.get("window") or {})
            current = dict(prepared.get("current") or {})
            previous = dict(prepared.get("previous") or {})
            comparison = dict(prepared.get("comparison") or {})
            daily = list(prepared.get("daily") or [])
            top_devices = [dict(row) for row in (prepared.get("top_devices") or [])]
            services = [dict(row) for row in (prepared.get("services") or [])]
            domains = list(prepared.get("domains") or [])
            new_domains = [dict(row) for row in (prepared.get("new_domains") or [])]
            timeline = [dict(row) for row in (prepared.get("timeline") or [])]
            active_periods = []
            timezone_name = str(prepared.get("timezone_name") or timezone_name)
            selected_name = "All devices"
        else:
            if str(period or "7d").lower() == "7d" and not selected and not start and not end:
                _record_prepared_fallback("history:7d")
            if selected:
                import ipaddress as _ipaddress
                _ipaddress.ip_address(selected)
            window = resolve_activity_window(period, timezone_name, start, end)
            current = activity_store.overview_range(window["start"], window["end"], selected or None)
            previous = activity_store.overview_range(window["previous_start"], window["previous_end"], selected or None)
            comparison = compare_activity_totals(current, previous)
            daily = activity_store.daily_history(window["start"], window["end"], timezone_name, selected or None)
            top_devices = activity_store.top_devices_range(window["start"], window["end"], 24)
            _decorate_activity_identity(top_devices, names)
            services = activity_store.top_services_range(window["start"], window["end"], 30, selected or None)
            service_defs = policy_store.list_services()
            keys_by_name = {str(item.get("name") or "").lower(): str(item.get("key") or "") for item in service_defs}
            for item in services:
                item["service_key"] = keys_by_name.get(str(item.get("service_name") or "").lower(), "")
            domains = activity_store.top_domains_range(window["start"], window["end"], 60, selected or None)
            new_domains = activity_store.new_domains_range(window["start"], window["end"], 30, 60, selected or None)
            timeline = activity_store.evidence_timeline(window["start"], window["end"], selected or None, 180)
            _decorate_activity_identity(timeline, names)
            for item in timeline:
                item["local_time"] = _activity_local_timestamp(item.get("event_time"), timezone_name)
            active_periods = activity_store.active_periods(selected, window["start"], window["end"], 30, 60) if selected else []
            for item in active_periods:
                item["local_start"] = _activity_local_timestamp(item.get("start"), timezone_name)
                item["local_end"] = _activity_local_timestamp(item.get("end"), timezone_name)
            for item in new_domains:
                item["local_first_seen"] = _activity_local_timestamp(item.get("first_seen"), timezone_name)
            selected_name = names.get(selected, selected) if selected else "All devices"
    except (ActivityError, ValueError) as exc:
        error = str(exc)
        try:
            window = resolve_activity_window("7d", timezone_name)
        except ValueError:
            window = {}
        current = previous = {}
        comparison = {}
        daily = top_devices = services = domains = new_domains = timeline = active_periods = []
        selected_name = names.get(selected, selected) if selected else "All devices"
        prepared_meta = None

    return templates.TemplateResponse(
        "activity_analytics.html",
        {
            "request": request,
            "user": user,
            "period": period,
            "custom_start": start,
            "custom_end": end,
            "selected_ip": selected,
            "selected_name": selected_name,
            "managed_names": names,
            "window": window,
            "current": current,
            "previous": previous,
            "comparison": comparison,
            "daily": daily,
            "top_devices": top_devices,
            "services": services,
            "domains": domains,
            "new_domains": new_domains,
            "timeline": timeline,
            "active_periods": active_periods,
            "timezone_name": timezone_name,
            "prepared_view": prepared_meta,
            "error": error,
        },
        status_code=503 if error else 200,
    )


def _policy_correlation_payload(client_ip: str, period="7d", start="", end=""):
    local = policy_store.list_device_policy()
    names = _policy_correlation_managed_names()
    selected = str(client_ip or "").strip()
    if not selected and names:
        selected = sorted(names, key=lambda item: (names[item] or item).lower())[0]
    if not selected:
        raise ValueError("No managed devices are available for policy correlation")
    import ipaddress as _ipaddress
    _ipaddress.ip_address(selected)
    if selected not in names:
        raise ValueError("Policy correlation is available only for locally managed devices")
    settings = policy_store.get_settings()
    timezone_name = settings.get("policy_timezone", "Europe/London")
    window = resolve_activity_window(period, timezone_name, start, end)
    identity = policy_store.get_managed_device_identity(selected)
    if not identity:
        # Locally managed rows are assigned a management identity during store
        # initialization/update. Refuse to fall back to IP continuity if that
        # evidence is unexpectedly absent.
        raise ValueError("Current device management identity is unavailable")
    history = policy_store.list_policy_state_history(
        selected,
        window["start"].isoformat(),
        window["end"].isoformat(),
        800,
        identity_id=identity["identity_id"],
    )
    intervals = build_policy_intervals(
        history,
        window["start"],
        window["end"],
        identity_start=identity["managed_since"],
    )
    usage = activity_store.policy_interval_usage(selected, intervals)
    report = build_policy_correlation_report(
        device_ip=selected,
        device_name=names.get(selected) or selected,
        history=history,
        usage=usage,
        start=window["start"],
        end=window["end"],
        timezone_name=timezone_name,
        identity=identity,
        collection_status=read_telemetry_ingest_status(),
    )
    report["window"] = {
        key: (value.isoformat() if hasattr(value, "isoformat") else value)
        for key, value in window.items()
    }
    return report, names, selected, timezone_name


@app.get("/api/activity/policy-history")
def api_activity_policy_history(
    client_ip: str = "", period: str = "7d", start: str = "", end: str = "",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        report, _, _, _ = _policy_correlation_payload(client_ip, period, start, end)
        return report
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/activity/policy-history", response_class=HTMLResponse)
def activity_policy_history_page(
    request: Request, client_ip: str = "", period: str = "7d", start: str = "", end: str = "",
    user=Depends(require_role("admin", "operator", "viewer")),
):
    error = None
    report = None
    local = policy_store.list_device_policy()
    names = _policy_correlation_managed_names()
    selected = str(client_ip or "").strip()
    timezone_name = policy_store.get_settings().get("policy_timezone", "Europe/London")
    try:
        report, names, selected, timezone_name = _policy_correlation_payload(
            client_ip, period, start, end
        )
    except (ValueError, ActivityError) as exc:
        error = str(exc)
        if not selected and names:
            selected = sorted(names, key=lambda item: (names[item] or item).lower())[0]
    return templates.TemplateResponse(
        "policy_history.html",
        {
            "request": request, "user": user, "report": report, "error": error,
            "managed_names": names, "selected_ip": selected,
            "selected_name": names.get(selected) or selected or "Managed device",
            "period": period, "custom_start": start, "custom_end": end,
            "timezone_name": timezone_name,
            "total_bytes_human": format_activity_bytes((report or {}).get("total_bytes", 0)),
        },
        status_code=503 if error and "Telemetry database unavailable" in error else 200,
    )


def _classification_workbench_payload(hours: int = 24) -> dict:
    hours = int(hours)
    if hours not in {24, 24 * 7, 24 * 30}:
        raise ValueError("Classification window must be 24, 168 or 720 hours")
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    previous_start = start - timedelta(hours=hours)
    settings = policy_store.get_settings()
    timezone_name = settings.get("policy_timezone", "Europe/London")
    trend_days = max(7, min(30, (hours + 23) // 24))
    trend_start = end - timedelta(days=trend_days)
    component_errors = []

    def _safe(label, fn, default):
        try:
            return fn()
        except ActivityError as exc:
            component_errors.append({"component": label, "error": str(exc)})
            return default

    current = activity_store.classification_coverage_range(start, end)
    previous = activity_store.classification_coverage_range(previous_start, start)
    daily = _safe(
        "daily_history",
        lambda: activity_store.classification_history(trend_start, end, timezone_name),
        [],
    )
    dns_available = bool(current.get("dns_available", True))
    candidates = _safe(
        "candidate_dns",
        lambda: activity_store.unknown_domains(hours, 80),
        [],
    ) if dns_available else []
    service_changes = _safe(
        "service_movement",
        lambda: activity_store.service_attribution_changes(hours, 16),
        [],
    )
    service_defs = policy_store.list_services()
    payload = build_classification_workbench(
        current, previous, daily, candidates, service_defs,
        service_changes,
        hours=hours,
    )
    coverage_errors = list(current.get("evidence_errors") or [])
    coverage_errors.extend(previous.get("evidence_errors") or [])
    classifier_consumer = read_classifier_consumer_status()
    if classifier_consumer.get("degraded"):
        availability = str(classifier_consumer.get("availability") or "unavailable")
        source = str(classifier_consumer.get("source") or "unknown")
        if availability == "stale":
            consumer_error = "Classifier consumer heartbeat is stale"
        elif availability != "available":
            consumer_error = str(classifier_consumer.get("error") or "Classifier consumer heartbeat is unavailable")
        elif source == "stale_live":
            consumer_error = str(classifier_consumer.get("error") or "Classifier consumer is retaining the last-known-good live catalogue")
        elif source == "fallback":
            consumer_error = "Classifier consumer is using the bootstrap fallback catalogue"
        else:
            consumer_error = f"Classifier consumer state is {source}"
        component_errors.append({"component": "classifier_consumer", "error": consumer_error})
    payload["degraded_evidence"] = bool(coverage_errors or component_errors)
    payload["evidence_errors"] = coverage_errors + component_errors
    payload["classifier_consumer"] = classifier_consumer
    payload["timezone_name"] = timezone_name
    payload["trend_days"] = trend_days
    for item in payload.get("candidates", []):
        item["prefill_url"] = (
            "/?view=policies&section=services&prefill_dns="
            + quote_plus(str(item.get("prefill_dns") or ""))
            + "#policies/services"
        )
        for match in item.get("signature_matches", []):
            match["service_url"] = (
                "/?view=policies&section=services&focus=service:"
                + quote_plus(str(match.get("key") or ""))
                + "#policies/services"
            )
        for hint in item.get("name_hints", []):
            hint["service_url"] = (
                "/?view=policies&section=services&focus=service:"
                + quote_plus(str(hint.get("key") or ""))
                + "#policies/services"
            )
    return payload


def _classification_preparing_payload(hours: int, prepared_meta: dict | None = None) -> dict:
    return {
        "schema": "zen_classification_intelligence_v1",
        "state": "preparing",
        "hours": int(hours) if int(hours) in {24, 168, 720} else 24,
        "current": {}, "previous": {},
        "deltas": {"traffic_pp": None, "dns_pp": None},
        "trend": "unknown", "daily": [], "candidates": [],
        "candidate_counts": {"signature_match": 0, "name_hint": 0, "unmatched": 0},
        "candidate_accounting": {
            "unknown_queries": 0, "listed_queries": 0,
            "listed_share_percent": None, "valid": True,
        },
        "evidence": {
            "status": "unavailable", "traffic_observed": False,
            "dns_observed": False, "traffic_accounting_valid": False,
            "dns_accounting_valid": False, "accounting_valid": False,
        },
        "catalogue": {}, "service_changes": [], "trend_days": 7,
        "classifier_consumer": {
            "availability": "unavailable", "source": "unknown",
            "services": 0, "signatures": 0, "has_live": False,
            "degraded": True, "error": "Prepared classification evidence is not ready",
            "observed_at": None, "age_seconds": None,
        },
        "timezone_name": policy_store.get_settings().get("policy_timezone", "Europe/London"),
        "evidence_note": (
            "Prepared classification evidence is not ready. Background refresh has "
            "been requested; missing evidence is not converted into zero activity."
        ),
        "prepared_view": prepared_meta,
    }


@app.get("/api/activity/classification")
def api_activity_classification(
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        if int(hours) == 24:
            prepared, meta = _prepared_payload(
                "classification:24h", allow_stale_same_revision=True
            )
            if prepared:
                return {**prepared, "prepared_view": meta}
            return _classification_preparing_payload(hours, meta)
        with activity_store.coherent_session():
            return {**_classification_workbench_payload(hours), "prepared_view": None}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/activity/classification", response_class=HTMLResponse)
def activity_classification_page(
    request: Request,
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    error = None
    try:
        prepared = meta = None
        if int(hours) == 24:
            prepared, meta = _prepared_payload(
                "classification:24h", allow_stale_same_revision=True
            )
            payload = dict(prepared) if prepared else _classification_preparing_payload(hours, meta)
        else:
            with activity_store.coherent_session():
                payload = _classification_workbench_payload(hours)
        payload["prepared_view"] = meta
    except (ValueError, ActivityError) as exc:
        error = str(exc)
        payload = _classification_preparing_payload(hours, None)
        payload["evidence_note"] = (
            "Classification evidence is unavailable. ZEN does not convert missing telemetry into zero activity."
        )
    return templates.TemplateResponse(
        "classification.html",
        {"request": request, "user": user, "error": error, **payload},
        status_code=503 if error else 200,
    )


@app.get("/activity/service/{service_key}", response_class=HTMLResponse)
@coherent_router_request
def activity_service_page(
    request: Request,
    service_key: str,
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    definitions = {item["key"]: item for item in policy_store.list_services()}
    definition = definitions.get(service_key)
    if not definition:
        raise HTTPException(status_code=404, detail="Service not found")
    if service_key in policy_store.policy_group_keys():
        raise HTTPException(status_code=400, detail="Open a concrete service rather than an aggregate policy group")

    router_health = {}
    try:
        health = router.get_service_contract_health()
        router_health = next((item for item in health.get("services", []) if item.get("key") == service_key), {})
    except RouterError:
        router_health = {}

    error = None
    detail = {}
    try:
        detail = activity_store.service_detail(definition["name"], hours)
        name_map = {}
        try:
            live = router.get_restricted_devices()
        except RouterError:
            live = []
        local = policy_store.list_device_policy()
        for item in live:
            ip = str(item.get("address") or item.get("ip") or "")
            if ip:
                cfg = local.get(ip, {})
                name_map[ip] = str(cfg.get("alias") or item.get("name") or ip)
        for item in detail.get("top_devices", []):
            ip = str(item.get("client_ip") or "")
            item["display_name"] = name_map.get(ip, ip)
            item["managed"] = ip in name_map
    except (ActivityError, ValueError) as exc:
        error = str(exc)

    return templates.TemplateResponse(
        "activity_service.html",
        {
            "request": request,
            "user": user,
            "service": definition,
            "router_health": router_health,
            "detail": detail,
            "hours": hours,
            "error": error,
        },
        status_code=503 if error else 200,
    )


@app.get("/activity/device/{client_ip}", response_class=HTMLResponse)
def activity_device_page(
    request: Request,
    client_ip: str,
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    device_label = client_ip
    managed = False
    try:
        local_policy = policy_store.list_device_policy().get(client_ip, {})
        router_name = ""
        try:
            for item in router.get_restricted_devices():
                if str(item.get("address") or "") == client_ip:
                    managed = True
                    router_name = str(item.get("name") or "")
                    break
        except RouterError:
            managed = client_ip in policy_store.list_device_policy()
        device_label = str(local_policy.get("alias") or router_name or client_ip)

        detail = activity_store.device_detail(client_ip, hours)
        series = activity_store.traffic_series(client_ip, hours)
        services = activity_store.top_services(hours, 12, client_ip)
        policy_services = build_policy_service_activity(
            policy_store.list_services(), services, policy_store.policy_group_catalog(), policy_store.list_profiles()
        )
        destinations = activity_store.top_destinations(hours, 20, client_ip)
        domains = activity_store.dns_top_domains(hours, 30, client_ip)
        dns = activity_store.recent_dns(hours, 100, client_ip)
    except (ActivityError, ValueError) as exc:
        return templates.TemplateResponse(
            "activity_device.html",
            {
                "request": request,
                "user": user,
                "client_ip": client_ip,
                "device_label": device_label,
                "managed": managed,
                "hours": hours,
                "error": str(exc),
                "detail": {},
                "series": [],
                "services": [],
                "policy_services": [],
                "destinations": [],
                "domains": [],
                "dns": [],
            },
            status_code=503,
        )

    return templates.TemplateResponse(
        "activity_device.html",
        {
            "request": request,
            "user": user,
            "client_ip": client_ip,
            "device_label": device_label,
            "managed": managed,
            "hours": hours,
            "error": None,
            "detail": detail,
            "series": series,
            "services": services,
            "policy_services": policy_services,
            "destinations": destinations,
            "domains": domains,
            "dns": dns,
        },
    )


@app.post("/mode/{mode}")
@coherent_router_mutation
def set_mode(
    mode: Literal["normal", "slow", "blocked"],
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        before = get_live_status()["mode"]
        router.cancel_temporary_access()
        result = router.set_mode(mode)
        after = result["mode"].upper()
        audit("MODE_CHANGE", user["username"], f"{before} -> {after}")
    except RouterError as exc:
        audit("MODE_CHANGE_FAILED", user["username"], f"{mode}: {exc}")
        raise HTTPException(status_code=502, detail=str(exc))
    return RedirectResponse("/?view=dashboard&section=overview#dashboard/overview", status_code=303)


@app.post("/temporary")
@coherent_router_mutation
def temporary(
    request: Request,
    minutes: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    if minutes not in {15, 30, 60}:
        raise HTTPException(status_code=400, detail="Unsupported duration")

    try:
        before = get_live_status()["mode"]
        if before not in {"NORMAL", "SLOW", "BLOCKED"}:
            raise RouterError(f"Cannot start temporary access from state {before}")

        result = router.set_temporary_normal(minutes, before.lower())
        audit(
            "TEMP_NORMAL",
            user["username"],
            f"{minutes}m from {before}; restore handled by RouterOS",
        )
    except RouterError as exc:
        audit("TEMP_NORMAL_FAILED", user["username"], str(exc))
        raise HTTPException(status_code=502, detail=str(exc))

    return RedirectResponse("/?view=dashboard&section=controls#dashboard/controls", status_code=303)


@app.post("/schedules/add")
@coherent_router_mutation
def add_schedule(
    request: Request,
    label: str = Form(...),
    mode: Literal["normal", "slow", "blocked"] = Form(...),
    clock_time: str = Form(...),
    days: list[str] = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        result = router.add_managed_schedule(label, mode, clock_time, days)
        audit(
            "SCHEDULE_ADDED",
            user["username"],
            f"{result['label']} {result['mode'].upper()} "
            f"{result['time']} {','.join(result['days'])}",
        )
    except RouterError as exc:
        audit("SCHEDULE_ADD_FAILED", user["username"], str(exc))
        raise HTTPException(status_code=502, detail=str(exc))
    return RedirectResponse("/?view=schedules&section=router#schedules/router", status_code=303)


@app.post("/schedules/remove")
@coherent_router_mutation
def remove_schedule(
    request: Request,
    schedule_id: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        router.remove_managed_schedule(schedule_id)
        audit("SCHEDULE_REMOVED", user["username"], schedule_id)
    except RouterError as exc:
        audit("SCHEDULE_REMOVE_FAILED", user["username"], str(exc))
        raise HTTPException(status_code=502, detail=str(exc))
    return RedirectResponse("/?view=schedules&section=router#schedules/router", status_code=303)



@app.post("/local/profiles/add")
def local_profile_add(
    request: Request,
    name: str = Form(...),
    desired_mode: Literal["normal", "slow", "blocked"] = Form(...),
    bandwidth_preset: str = Form(...),
    notes: str = Form(""),
    blocked_services: list[str] = Form([]),
    daily_quota_mb: str = Form("0"),
    daily_quota_action: Literal["slow", "blocked"] = Form("blocked"),
    service_quota_key: list[str] = Form([]),
    service_quota_mb: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        service_quotas = service_quota_pairs(
            service_quota_key, service_quota_mb,
            supported_service_keys=policy_store.routeros_supported_service_keys() | policy_store.policy_group_keys(),
        )
        profile = policy_store.create_profile(
            name, desired_mode, bandwidth_preset, notes, blocked_services,
            daily_quota_mb, daily_quota_action, service_quotas,
        )
        audit("LOCAL_PROFILE_ADDED", user["username"], profile["name"])
        auto_reconciler.wake()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=profiles#policies/profiles", status_code=303)


@app.post("/local/profiles/update")
def local_profile_update(
    request: Request,
    profile_id: int = Form(...),
    name: str = Form(...),
    desired_mode: Literal["normal", "slow", "blocked"] = Form(...),
    bandwidth_preset: str = Form(...),
    notes: str = Form(""),
    blocked_services: list[str] = Form([]),
    daily_quota_mb: str = Form("0"),
    daily_quota_action: Literal["slow", "blocked"] = Form("blocked"),
    service_quota_key: list[str] = Form([]),
    service_quota_mb: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        service_quotas = service_quota_pairs(
            service_quota_key, service_quota_mb,
            supported_service_keys=policy_store.routeros_supported_service_keys() | policy_store.policy_group_keys(),
        )
        profile = policy_store.update_profile(
            profile_id, name, desired_mode, bandwidth_preset, notes, blocked_services,
            daily_quota_mb, daily_quota_action, service_quotas,
        )
        audit("LOCAL_PROFILE_UPDATED", user["username"], profile["name"])
        auto_reconciler.wake()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=profiles#policies/profiles", status_code=303)


@app.post("/local/profiles/delete")
def local_profile_delete(
    request: Request,
    profile_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.delete_profile(profile_id)
        audit("LOCAL_PROFILE_DELETED", user["username"], str(profile_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=profiles#policies/profiles", status_code=303)


@app.post("/local/devices/update")
def local_device_update(
    request: Request,
    ip: str = Form(...),
    alias: str = Form(""),
    notes: str = Form(""),
    profile_id: str = Form(""),
    mode_override: Literal["inherit", "normal", "slow", "blocked"] = Form("inherit"),
    category: str = Form("other"),
    favourite: bool = Form(False),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.update_device(ip, alias, notes, profile_id, mode_override, category, favourite)
        audit("LOCAL_DEVICE_POLICY_UPDATED", user["username"], ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=assignments#policies/assignments", status_code=303)


@app.post("/local/templates/save")
def local_template_save(
    request: Request,
    name: str = Form(...),
    profile_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.save_template_from_profile(name, profile_id)
        audit("LOCAL_TEMPLATE_SAVED", user["username"], name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=profiles#policies/profiles", status_code=303)


@app.post("/local/templates/apply")
def local_template_apply(
    request: Request,
    template_id: int = Form(...),
    profile_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.apply_template(template_id, profile_id)
        audit(
            "LOCAL_TEMPLATE_APPLIED",
            user["username"],
            f"template={template_id} profile={profile_id}",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=profiles#policies/profiles", status_code=303)


@app.post("/local/templates/delete")
def local_template_delete(
    request: Request,
    template_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.delete_template(template_id)
        audit("LOCAL_TEMPLATE_DELETED", user["username"], str(template_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=profiles#policies/profiles", status_code=303)



@app.post("/local/devices/bulk")
def local_devices_bulk(
    request: Request,
    ips: list[str] = Form([]),
    profile_id: str = Form(""),
    mode_override: Literal["inherit", "normal", "slow", "blocked"] = Form("inherit"),
    category: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.bulk_update_devices(ips, profile_id, mode_override, category or None)
        audit("LOCAL_DEVICE_BULK_UPDATED", user["username"], ",".join(ips))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=devices&section=bulk#devices/bulk", status_code=303)


@app.post("/local/bandwidth/add")
def local_bandwidth_add(
    request: Request,
    key: str = Form(...),
    name: str = Form(...),
    upload: str = Form(...),
    download: str = Form(...),
    description: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.save_bandwidth_preset(key, name, upload, download, description)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=bandwidth#policies/bandwidth", status_code=303)


@app.post("/local/bandwidth/delete")
def local_bandwidth_delete(
    request: Request,
    key: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.delete_bandwidth_preset(key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=bandwidth#policies/bandwidth", status_code=303)


@app.post("/local/services/add")
def local_service_add(
    request: Request,
    key: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    category: str = Form("other"),
    dns_suffixes: str = Form(""),
    tls_patterns: str = Form(""),
    classifier_enabled: str = Form("1"),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.save_service(
            key, name, description, category, dns_suffixes, tls_patterns,
            str(classifier_enabled).lower() not in {"0", "false", "off", "no"},
        )
        publish_service_catalog()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=services#policies/services", status_code=303)


@app.post("/local/services/provision")
@coherent_router_mutation
def local_service_provision(
    request: Request,
    key: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    service = policy_store.get_service(key)
    if not service or service.get("builtin") or key in policy_store.policy_group_keys():
        return redirect_error("policies/services", "Custom service not found")
    try:
        contract = build_custom_service_contract(service)
        router.assert_policy_enforcement_ready()
        preview = router.inspect_custom_service_contract(contract)
        if preview.get("status") not in {"absent", "healthy"}:
            raise RouterError(preview.get("error") or "Custom RouterOS contract conflicts")
        result = router.provision_custom_service_contract(contract)
        try:
            policy_store.set_service_enforcement_approved(key, True)
        except Exception as storage_exc:
            try:
                router.remove_custom_service_contract(contract)
            except Exception as rollback_exc:
                audit(
                    "CUSTOM_SERVICE_PROVISION_ROLLBACK_FAILED",
                    user["username"],
                    f"{key}: storage={storage_exc}; rollback={rollback_exc}",
                )
            raise ValueError(
                f"RouterOS contract validated but local approval could not be recorded: {storage_exc}"
            ) from storage_exc
        publish_service_catalog()
        auto_reconciler.wake()
        audit(
            "CUSTOM_SERVICE_PROVISIONED",
            user["username"],
            (
                f"{key}: source={contract['source_list']} "
                f"learners={len(contract['learners'])} blocks={len(contract['rules'])} "
                f"created={result.get('created', 0)} idempotent={result.get('idempotent', False)}"
            ),
        )
    except (ValueError, RouterError) as exc:
        audit("CUSTOM_SERVICE_PROVISION_FAILED", user["username"], f"{key}: {exc}")
        return redirect_error("policies/services", str(exc))
    return redirect_ok("policies/services", f"{service['name']} RouterOS contract is healthy")


@app.post("/local/services/unprovision")
@coherent_router_mutation
def local_service_unprovision(
    request: Request,
    key: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    service = policy_store.get_service(key)
    if not service or service.get("builtin") or key in policy_store.policy_group_keys():
        return redirect_error("policies/services", "Custom service not found")
    try:
        contract = build_custom_service_contract(service)
        result = router.remove_custom_service_contract(contract)
        policy_store.set_service_enforcement_approved(key, False)
        publish_service_catalog()
        auto_reconciler.wake()
        audit(
            "CUSTOM_SERVICE_UNPROVISIONED",
            user["username"],
            (
                f"{key}: rules={result.get('removed_rules', 0)} "
                f"list_entries={result.get('removed_entries', 0)} "
                f"idempotent={result.get('idempotent', False)}"
            ),
        )
    except (ValueError, RouterError) as exc:
        audit("CUSTOM_SERVICE_UNPROVISION_FAILED", user["username"], f"{key}: {exc}")
        return redirect_error("policies/services", str(exc))
    return redirect_ok("policies/services", f"{service['name']} RouterOS contract removed; telemetry history retained")


@app.post("/local/services/delete")
def local_service_delete(
    request: Request,
    key: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        service = policy_store.get_service(key)
        if service and not service.get("builtin") and key not in policy_store.policy_group_keys():
            try:
                contract = build_custom_service_contract(service)
            except ValueError:
                contract = None
            if contract:
                preview = router.inspect_custom_service_contract(contract)
                if preview.get("status") != "absent":
                    raise ValueError(
                        "RouterOS still contains or conflicts with this custom MC contract; remove it before deleting the service"
                    )
        policy_store.delete_service(key)
        publish_service_catalog()
        audit("CUSTOM_SERVICE_DELETED", user["username"], f"{key}: metadata removed; retained telemetry is unchanged")
    except (ValueError, RouterError) as exc:
        return redirect_error("policies/services", str(exc))
    return redirect_ok("policies/services", "Custom service definition deleted; historical telemetry retained")


@app.post("/local/schedule-plans/add")
def local_schedule_plan_add(
    request: Request,
    label: str = Form(...),
    target_type: str = Form(...),
    target_value: str = Form(""),
    action_type: str = Form(...),
    mode_action_value: str = Form(""),
    service_action_value: str = Form(""),
    clock_time: str = Form(...),
    days: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/planner", "CSRF validation failed")
    action_value = (
        mode_action_value if action_type == "mode" else service_action_value
    )
    try:
        policy_store.create_schedule_plan(
            label, target_type, target_value, action_type, action_value, clock_time, days
        )
        audit(
            "POLICY_SCHEDULE_CREATED",
            user["username"],
            f"{label}: {target_type}={target_value or 'all'} {action_type}={action_value} {clock_time}",
        )
    except ValueError as exc:
        return redirect_error("schedules/planner", str(exc))
    return redirect_ok("schedules/planner", "Policy schedule created")


@app.post("/local/schedule-plans/toggle")
def local_schedule_plan_toggle(
    request: Request,
    plan_id: int = Form(...),
    enabled: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/planner", "CSRF validation failed")
    try:
        desired = str(enabled).lower() in {"1", "true", "yes", "on"}
        policy_store.set_schedule_plan_enabled(plan_id, desired)
        audit(
            "POLICY_SCHEDULE_TOGGLED",
            user["username"],
            f"id={plan_id} enabled={desired}",
        )
    except ValueError as exc:
        return redirect_error("schedules/planner", str(exc))
    return redirect_ok("schedules/planner", "Policy schedule updated")


@app.post("/local/schedule-plans/delete")
def local_schedule_plan_delete(
    request: Request,
    plan_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/planner", "CSRF validation failed")
    try:
        policy_store.delete_schedule_plan(plan_id)
        audit("POLICY_SCHEDULE_DELETED", user["username"], f"id={plan_id}")
    except ValueError as exc:
        return redirect_error("schedules/planner", str(exc))
    return redirect_ok("schedules/planner", "Policy schedule deleted")



@app.post("/local/policy-groups/add")
def local_policy_group_add(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    members: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("policies/tools", "CSRF validation failed")
    try:
        group = policy_store.create_policy_group(name, description, members)
        audit(
            "AGGREGATE_POLICY_GROUP_CREATED",
            user["username"],
            f"key={group['key']} name={group['name']} members={','.join(group['members'])}",
        )
    except ValueError as exc:
        return redirect_error("policies/tools", str(exc))
    return redirect_ok("policies/tools", f"Aggregate policy group {group['name']} created")


@app.post("/local/policy-groups/update")
def local_policy_group_update(
    request: Request,
    key: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    members: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("policies/tools", "CSRF validation failed")
    try:
        before = next(
            (item for item in policy_store.list_policy_groups() if item["key"] == str(key).strip().lower()),
            None,
        )
        if not before:
            raise ValueError("Aggregate policy group not found")
        usage = policy_store.policy_group_usage(key)
        group = policy_store.update_policy_group(key, name, description, members)
        audit(
            "AGGREGATE_POLICY_GROUP_UPDATED",
            user["username"],
            (
                f"key={group['key']} name={before['name']}->{group['name']} "
                f"members={','.join(before['members'])}->{','.join(group['members'])} "
                f"references={usage['total']}"
            ),
        )
        if before["members"] != group["members"]:
            auto_reconciler.wake()
    except ValueError as exc:
        return redirect_error("policies/tools", str(exc))
    return redirect_ok("policies/tools", f"Aggregate policy group {group['name']} updated")


@app.post("/local/policy-groups/delete")
def local_policy_group_delete(
    request: Request,
    key: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("policies/tools", "CSRF validation failed")
    try:
        current = next(
            (item for item in policy_store.list_policy_groups() if item["key"] == str(key).strip().lower()),
            None,
        )
        if not current:
            raise ValueError("Aggregate policy group not found")
        policy_store.delete_policy_group(key)
        audit(
            "AGGREGATE_POLICY_GROUP_DELETED",
            user["username"],
            f"key={current['key']} name={current['name']} members={','.join(current['members'])}",
        )
        auto_reconciler.wake()
    except ValueError as exc:
        return redirect_error("policies/tools", str(exc))
    return redirect_ok("policies/tools", f"Aggregate policy group {current['name']} deleted")


@app.post("/local/service-groups/add")
def local_service_group_add(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    services: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.save_service_group(name, description, services)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=tools#policies/tools", status_code=303)


@app.post("/local/service-groups/apply")
def local_service_group_apply(
    request: Request,
    group_id: int = Form(...),
    profile_id: int = Form(...),
    action: Literal["block", "allow"] = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("policies/tools", "CSRF validation failed")
    try:
        profile = policy_store.apply_service_group(group_id, profile_id, action)
        audit(
            "SERVICE_COLLECTION_APPLIED",
            user["username"],
            f"group={group_id} profile={profile_id} action={action}",
        )
        auto_reconciler.wake()
    except ValueError as exc:
        return redirect_error("policies/tools", str(exc))
    return redirect_ok(
        "policies/tools",
        f"Service collection {action.upper()} applied to {profile['name']}",
    )


@app.post("/local/service-groups/delete")
def local_service_group_delete(
    request: Request,
    group_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        policy_store.delete_service_group(group_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedirectResponse("/?view=policies&section=tools#policies/tools", status_code=303)


@app.post("/local/schedule-templates/add")
def local_schedule_template_add(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    entry1_time: str = Form(...),
    entry1_mode: str = Form(...),
    entry1_days: list[str] = Form([]),
    entry2_time: str = Form(""),
    entry2_mode: str = Form(""),
    entry2_days: list[str] = Form([]),
    entry3_time: str = Form(""),
    entry3_mode: str = Form(""),
    entry3_days: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/templates", "CSRF validation failed")
    entries = [{"time": entry1_time, "mode": entry1_mode, "days": entry1_days}]
    for t, m, d in [
        (entry2_time, entry2_mode, entry2_days),
        (entry3_time, entry3_mode, entry3_days),
    ]:
        if t and m and d:
            entries.append({"time": t, "mode": m, "days": d})
    try:
        template_id = policy_store.save_schedule_template(name, description, entries)
        audit(
            "POLICY_SCHEDULE_TEMPLATE_CREATED",
            user["username"],
            f"id={template_id} name={name}",
        )
    except ValueError as exc:
        return redirect_error("schedules/templates", str(exc))
    return redirect_ok("schedules/templates", "Schedule template created")


@app.post("/local/schedule-templates/delete")
def local_schedule_template_delete(
    request: Request,
    template_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/templates", "CSRF validation failed")
    try:
        policy_store.delete_schedule_template(template_id)
        audit(
            "POLICY_SCHEDULE_TEMPLATE_DELETED",
            user["username"],
            f"id={template_id}",
        )
    except ValueError as exc:
        return redirect_error("schedules/templates", str(exc))
    return redirect_ok("schedules/templates", "Schedule template deleted")


@app.post("/local/date-exceptions/add")
def local_date_exception_add(
    request: Request,
    label: str = Form(...),
    start_date: str = Form(...),
    end_date: str = Form(...),
    target_type: str = Form(...),
    target_value: str = Form(""),
    mode: str = Form(...),
    template_id: str = Form(""),
    notes: str = Form(""),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/exceptions", "CSRF validation failed")
    try:
        exception_id = policy_store.save_date_exception(
            label, start_date, end_date, target_type, target_value, mode,
            int(template_id) if template_id else None, notes
        )
        audit(
            "POLICY_DATE_EXCEPTION_CREATED",
            user["username"],
            f"id={exception_id} {label}: {start_date}->{end_date} {target_type}={target_value or 'all'} {mode}",
        )
    except ValueError as exc:
        return redirect_error("schedules/exceptions", str(exc))
    return redirect_ok("schedules/exceptions", "Date exception created")


@app.post("/local/date-exceptions/delete")
def local_date_exception_delete(
    request: Request,
    exception_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/exceptions", "CSRF validation failed")
    try:
        policy_store.delete_date_exception(exception_id)
        audit(
            "POLICY_DATE_EXCEPTION_DELETED",
            user["username"],
            f"id={exception_id}",
        )
    except ValueError as exc:
        return redirect_error("schedules/exceptions", str(exc))
    return redirect_ok("schedules/exceptions", "Date exception deleted")


def _policy_quality_snapshot():
    """Build the local-only policy quality contract without RouterOS access."""
    return build_policy_quality_report(
        profiles=policy_store.list_profiles(),
        devices=policy_store.list_device_policy(),
        schedules=policy_store.list_schedule_plans(),
        schedule_templates=policy_store.list_schedule_templates(),
        date_exceptions=policy_store.list_date_exceptions(),
        service_groups=policy_store.list_service_groups(),
        services=policy_store.list_services(),
        settings=policy_store.get_settings(),
        policy_groups=policy_store.policy_group_catalog(),
    )


@app.get("/policy/quality", response_class=HTMLResponse)
def policy_quality_page(
    request: Request,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    report = _policy_quality_snapshot()
    return templates.TemplateResponse(
        "policy_quality.html",
        {
            "request": request,
            "user": user,
            "report": report,
        },
    )


@app.get("/api/policy/quality")
def policy_quality_api(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return _policy_quality_snapshot()


@app.get("/policy/simulate", response_class=HTMLResponse)
def policy_simulate_page(
    request: Request,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    clock = policy_store.get_policy_clock()
    return templates.TemplateResponse(
        "simulation.html",
        {
            "request": request,
            "user": user,
            "csrf": request.session.get("csrf", ""),
            "result": None,
            "impact": None,
            "devices": list(policy_store.list_device_policy().values()),
            "profiles": policy_store.list_profiles(),
            "clock": clock,
        },
    )


@app.post("/policy/simulate", response_class=HTMLResponse)
@coherent_router_request
def policy_simulate_run(
    request: Request,
    ip: str = Form(...),
    date: str = Form(...),
    clock_time: str = Form(...),
    scenario_profile_id: str = Form("keep"),
    scenario_mode_override: str = Form("keep"),
    compare_live: bool = Form(False),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator", "viewer")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        at = f"{date}T{clock_time}:00"
        quota_usage = get_quota_usage(ip, at=at)
        baseline = policy_store.compute_effective_policy(ip, at=at, quota_usage=quota_usage)
        scenario = policy_store.simulate_effective_policy(
            ip,
            at=at,
            quota_usage=quota_usage,
            profile_id=None if scenario_profile_id == "unassigned" else scenario_profile_id,
            mode_override=scenario_mode_override,
            keep_profile=scenario_profile_id == "keep",
            keep_mode=scenario_mode_override == "keep",
        )
        cfg = policy_store.list_device_policy().get(ip, {})
        device_name = cfg.get("alias") or ip
        live_plan = None
        live_error = None
        if compare_live:
            try:
                live_plan = get_live_policy_plan(ip, desired_policy=scenario)
            except (RouterError, PolicyPlanError, ValueError) as exc:
                live_error = str(exc)
        result = build_policy_simulation(
            address=ip,
            device_name=device_name,
            baseline=baseline,
            scenario=scenario,
            scenario_label="What-if device scenario",
            simulation_at=scenario.get("policy_at") or at,
            live_plan=live_plan,
            live_error=live_error,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return templates.TemplateResponse(
        "simulation.html",
        {
            "request": request,
            "user": user,
            "csrf": csrf,
            "result": result,
            "impact": None,
            "devices": list(policy_store.list_device_policy().values()),
            "profiles": policy_store.list_profiles(),
            "clock": policy_store.get_policy_clock(),
            "selected": {
                "ip": ip, "date": date, "time": clock_time,
                "profile": scenario_profile_id, "mode": scenario_mode_override,
                "compare_live": compare_live,
            },
        },
    )


@app.post("/local/simulate", response_class=HTMLResponse)
@coherent_router_request
def local_simulate(
    request: Request,
    ip: str = Form(...),
    date: str = Form(...),
    clock_time: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator", "viewer")),
):
    """Compatibility path for the original future-time simulator."""
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        at = f"{date}T{clock_time}:00"
        quota_usage = get_quota_usage(ip, at=at)
        baseline = policy_store.compute_effective_policy(ip, at=at, quota_usage=quota_usage)
        cfg = policy_store.list_device_policy().get(ip, {})
        result = build_policy_simulation(
            address=ip,
            device_name=cfg.get("alias") or ip,
            baseline=baseline,
            scenario=baseline,
            scenario_label="Saved policy at selected time",
            simulation_at=baseline.get("policy_at") or at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return templates.TemplateResponse(
        "simulation.html",
        {
            "request": request, "user": user, "result": result, "impact": None,
            "csrf": csrf, "devices": list(policy_store.list_device_policy().values()),
            "profiles": policy_store.list_profiles(), "clock": policy_store.get_policy_clock(),
        },
    )


@app.post("/local/devices/preview", response_class=HTMLResponse)
def local_device_policy_preview(
    request: Request,
    ip: str = Form(...),
    profile_id: str = Form(""),
    mode_override: str = Form("inherit"),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    clock = policy_store.get_policy_clock()
    try:
        usage = get_quota_usage(ip, at=clock["iso"])
        baseline = policy_store.compute_effective_policy(ip, at=clock["iso"], quota_usage=usage)
        scenario = policy_store.simulate_effective_policy(
            ip, at=clock["iso"], profile_id=profile_id, mode_override=mode_override,
            keep_profile=False, keep_mode=False, quota_usage=usage,
        )
        cfg = policy_store.list_device_policy().get(ip, {})
        result = build_policy_simulation(
            address=ip, device_name=cfg.get("alias") or ip,
            baseline=baseline, scenario=scenario,
            scenario_label="Unsaved device assignment",
            simulation_at=scenario.get("policy_at") or clock["iso"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return templates.TemplateResponse(
        "simulation.html",
        {"request": request, "user": user, "csrf": csrf, "result": result,
         "impact": None, "devices": list(policy_store.list_device_policy().values()),
         "profiles": policy_store.list_profiles(), "clock": clock},
    )


@app.post("/local/profiles/preview", response_class=HTMLResponse)
def local_profile_preview(
    request: Request,
    profile_id: int = Form(...),
    name: str = Form(...),
    desired_mode: Literal["normal", "slow", "blocked"] = Form(...),
    bandwidth_preset: str = Form(...),
    notes: str = Form(""),
    blocked_services: list[str] = Form([]),
    daily_quota_mb: str = Form("0"),
    daily_quota_action: Literal["slow", "blocked"] = Form("blocked"),
    service_quota_key: list[str] = Form([]),
    service_quota_mb: list[str] = Form([]),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        service_quotas = service_quota_pairs(
            service_quota_key, service_quota_mb,
            supported_service_keys=policy_store.routeros_supported_service_keys() | policy_store.policy_group_keys(),
        )
        candidate = policy_store.build_profile_candidate(
            profile_id, name, desired_mode, bandwidth_preset, notes,
            blocked_services, daily_quota_mb, daily_quota_action, service_quotas,
        )
        clock = policy_store.get_policy_clock()
        rows = []
        for ip, cfg in policy_store.list_device_policy().items():
            if int(cfg.get("profile_id") or 0) != int(profile_id):
                continue
            usage = get_quota_usage(ip, at=clock["iso"])
            baseline = policy_store.compute_effective_policy(ip, at=clock["iso"], quota_usage=usage)
            scenario = policy_store.simulate_effective_policy(
                ip, at=clock["iso"], profile_candidate=candidate, quota_usage=usage,
            )
            sim = build_policy_simulation(
                address=ip, device_name=cfg.get("alias") or ip,
                baseline=baseline, scenario=scenario,
                scenario_label=f"Unsaved profile: {candidate['name']}",
                simulation_at=scenario.get("policy_at") or clock["iso"],
                scope="profile",
            )
            rows.append(sim)
        impact = build_profile_impact(
            profile_id=profile_id, profile_name=candidate["name"],
            simulation_at=clock["iso"], rows=rows,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return templates.TemplateResponse(
        "simulation.html",
        {"request": request, "user": user, "csrf": csrf, "result": None,
         "impact": impact, "devices": list(policy_store.list_device_policy().values()),
         "profiles": policy_store.list_profiles(), "clock": clock},
    )


@app.get("/local/config/export")
def local_config_export(
    user=Depends(require_role("admin")),
):
    return JSONResponse(
        content=policy_store.export_config(),
        headers={"Content-Disposition": 'attachment; filename="zen-control-config.json"'},
    )


@app.post("/local/config/import")
async def local_config_import(
    request: Request,
    config_json: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/operations", "CSRF validation failed")
    try:
        payload = json.loads(config_json)
        checkpoint = policy_store.create_config_snapshot(
            user["username"], "Automatic pre-import safety snapshot", force=True
        )
        policy_store.import_config(payload)
        publish_service_catalog()
        audit(
            "CONFIG_IMPORTED",
            user["username"],
            f"pre_import_snapshot={checkpoint['id']} digest={policy_store.config_digest()[:12]}",
        )
        auto_reconciler.wake()
    except (ValueError, json.JSONDecodeError) as exc:
        audit("CONFIG_IMPORT_FAILED", user["username"], str(exc))
        return redirect_error("settings/operations", str(exc))
    return redirect_ok(
        "settings/operations",
        f"Configuration imported; rollback checkpoint #{checkpoint['id']} retained",
    )


@app.post("/local/operations/snapshot")
def local_operations_snapshot(
    request: Request,
    reason: str = Form("Manual operator checkpoint"),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/operations", "CSRF validation failed")
    try:
        snapshot = policy_store.create_config_snapshot(
            user["username"], reason, force=True
        )
        audit(
            "CONFIG_SNAPSHOT_CREATED",
            user["username"],
            f"snapshot={snapshot['id']} digest={snapshot['sha256'][:12]} reason={snapshot['reason']}",
        )
    except (ValueError, OSError) as exc:
        audit("CONFIG_SNAPSHOT_FAILED", user["username"], str(exc))
        return redirect_error("settings/operations", str(exc))
    return redirect_ok("settings/operations", f"Configuration snapshot #{snapshot['id']} created")


@app.post("/local/operations/restore")
def local_operations_restore(
    request: Request,
    snapshot_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/operations", "CSRF validation failed")
    try:
        result = policy_store.restore_config_snapshot(snapshot_id, user["username"])
        publish_service_catalog()
        audit(
            "CONFIG_SNAPSHOT_RESTORED",
            user["username"],
            (
                f"restored={result['restored']} safety_snapshot={result['safety_snapshot']} "
                f"digest={result['sha256'][:12]}"
            ),
        )
        auto_reconciler.clear_hold()
        auto_reconciler.wake()
    except ValueError as exc:
        audit("CONFIG_SNAPSHOT_RESTORE_FAILED", user["username"], f"snapshot={snapshot_id}: {exc}")
        return redirect_error("settings/operations", str(exc))
    return redirect_ok(
        "settings",
        f"Restored snapshot #{result['restored']}; pre-restore safety snapshot #{result['safety_snapshot']} retained",
    )


@app.get("/api/operations/status")
def api_operations_status(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return operations_monitor.status()


@app.get("/api/operations/inventory")
def api_operations_inventory(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        inventory = router.get_managed_state_inventory()
        _publish_router_observation(
            "router:managed-state-inventory", inventory,
            scope="router:managed-state", ttl_seconds=300,
        )
        return {"ok": True, "inventory": inventory}
    except RouterError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/api/audit")
def api_audit(
    limit: int = 100,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return {
        "ok": True,
        "count": policy_store.audit_count(),
        "events": policy_store.list_audit(limit),
    }


@app.get("/api/operations/snapshots/{snapshot_id}")
def api_operations_snapshot(
    snapshot_id: int,
    user=Depends(require_role("admin")),
):
    try:
        snapshot = policy_store.get_config_snapshot(snapshot_id, include_payload=True)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ok": True, "snapshot": snapshot}


@app.get("/local/operations/snapshots/{snapshot_id}/export")
def local_operations_snapshot_export(
    snapshot_id: int,
    user=Depends(require_role("admin")),
):
    try:
        snapshot = policy_store.get_config_snapshot(snapshot_id, include_payload=True)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    filename = f"zen-control-snapshot-{snapshot_id}.json"
    return JSONResponse(
        content=snapshot["payload"],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/summary-delivery")
def api_summary_delivery_status(
    user=Depends(require_role("admin")),
):
    return summary_delivery.snapshot()


@app.post("/local/summary-delivery/settings")
def local_summary_delivery_settings(
    request: Request,
    summary_delivery_enabled: str = Form("0"),
    summary_delivery_time: str = Form("07:00"),
    summary_delivery_period: str = Form("yesterday"),
    summary_delivery_email_enabled: str = Form("0"),
    summary_delivery_email_to: str = Form(""),
    summary_delivery_webhook_enabled: str = Form("0"),
    summary_delivery_webhook_url: str = Form(""),
    summary_delivery_retry_limit: str = Form("3"),
    summary_delivery_retention_days: str = Form("90"),
    config_revision: int | None = Form(None),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    try:
        saved = policy_store.save_summary_delivery_settings(
            summary_delivery_enabled,
            summary_delivery_time,
            summary_delivery_period,
            summary_delivery_email_enabled,
            summary_delivery_email_to,
            summary_delivery_webhook_enabled,
            summary_delivery_webhook_url,
            summary_delivery_retry_limit,
            summary_delivery_retention_days,
            expected_revision=config_revision,
            actor=user["username"],
        )
        audit(
            "SUMMARY_DELIVERY_SETTINGS_UPDATED",
            user["username"],
            (
                f"enabled={saved['summary_delivery_enabled']} "
                f"time={saved['summary_delivery_time']} "
                f"period={saved['summary_delivery_period']} "
                f"email={saved['summary_delivery_email_enabled']} "
                f"webhook={saved['summary_delivery_webhook_enabled']} "
                f"retry={saved['summary_delivery_retry_limit']} "
                f"retention={saved['summary_delivery_retention_days']}d"
            ),
        )
        summary_delivery.reconcile_configuration()
        summary_delivery.wake()
    except ValueError as exc:
        return redirect_error("settings/automation", str(exc))
    return redirect_ok("settings/automation", "Parent summary delivery settings saved")


@app.post("/local/summary-delivery/test")
def local_summary_delivery_test(
    request: Request,
    channel: str = Form(...),
    period: str = Form("today"),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    try:
        row = summary_delivery.enqueue_test(channel, actor=user["username"], period=period)
    except (ValueError, ActivityError) as exc:
        return redirect_error("settings/automation", str(exc))
    return redirect_ok(
        "settings",
        f"Test {row['channel']} summary queued as delivery #{row['id']}",
    )


@app.post("/local/summary-delivery/retry")
def local_summary_delivery_retry(
    request: Request,
    delivery_id: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    try:
        row = summary_delivery.retry(delivery_id, actor=user["username"])
    except ValueError as exc:
        return redirect_error("settings/automation", str(exc))
    return redirect_ok("settings/automation", f"Delivery #{row['id']} queued for retry")


@app.post("/local/summary-delivery/run")
def local_summary_delivery_run(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    result = summary_delivery.run_cycle()
    audit(
        "SUMMARY_DELIVERY_MANUAL_CYCLE",
        user["username"],
        str(result.get("summary") or result.get("result")),
    )
    if result.get("result") == "error":
        return redirect_error("settings/automation", result.get("summary") or "Summary delivery cycle failed")
    return redirect_ok("settings/automation", f"Summary delivery cycle: {result.get('summary')}")


@app.post("/local/settings")
def local_settings_save(
    request: Request,
    default_profile_id: str = Form(""),
    default_category: str = Form("other"),
    default_bandwidth_preset: str = Form("normal"),
    default_temp_minutes: str = Form("30"),
    policy_timezone: str = Form("Europe/London"),
    config_revision: int | None = Form(None),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/policy", "CSRF validation failed")
    try:
        current_settings = policy_store.get_settings()
        policy_store.save_settings(
            default_profile_id,
            default_category,
            default_bandwidth_preset,
            default_temp_minutes,
            policy_timezone,
            current_settings.get("auto_reconcile_mode", "off"),
            current_settings.get("auto_reconcile_interval_seconds", "30"),
            current_settings.get("auto_reconcile_failure_threshold", "3"),
            current_settings.get("auto_reconcile_cooldown_seconds", "300"),
            expected_revision=config_revision,
            actor=user["username"],
        )
    except ValueError as exc:
        return redirect_error("settings/policy", str(exc))
    return redirect_ok("settings/policy", "Global defaults saved")


@app.post("/local/rewards/settings")
def local_reward_settings(
    request: Request,
    reward_bank_enabled: str = Form("0"),
    reward_bank_max_minutes: str = Form("240"),
    reward_default_grant_minutes: str = Form("30"),
    reward_max_redeem_minutes: str = Form("60"),
    config_revision: int | None = Form(None),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/policy", "CSRF validation failed")
    try:
        saved = policy_store.save_reward_settings(
            reward_bank_enabled,
            reward_bank_max_minutes,
            reward_default_grant_minutes,
            reward_max_redeem_minutes,
            expected_revision=config_revision,
            actor=user["username"],
        )
        audit(
            "REWARD_SETTINGS",
            user["username"],
            (
                f"enabled={saved['reward_bank_enabled']} "
                f"cap={saved['reward_bank_max_minutes']}m "
                f"default_grant={saved['reward_default_grant_minutes']}m "
                f"max_redeem={saved['reward_max_redeem_minutes']}m"
            ),
        )
    except ValueError as exc:
        return redirect_error("settings/policy", str(exc))
    return redirect_ok("settings/policy", "Reward-time settings saved")


@app.post("/local/quotas/settings")
def local_quota_settings(
    request: Request,
    quota_engine_enabled: str = Form("0"),
    quota_warning_percent: str = Form("80"),
    config_revision: int | None = Form(None),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/policy", "CSRF validation failed")
    try:
        saved = policy_store.save_quota_settings(
            quota_engine_enabled,
            quota_warning_percent,
            expected_revision=config_revision,
            actor=user["username"],
        )
        audit(
            "QUOTA_SETTINGS",
            user["username"],
            f"enabled={saved['quota_engine_enabled']} warning={saved['quota_warning_percent']}%",
        )
        auto_reconciler.wake()
    except ValueError as exc:
        return redirect_error("settings/policy", str(exc))
    state = "enabled" if saved["quota_engine_enabled"] == "1" else "disabled"
    return redirect_ok("settings/policy", f"Daily quota engine {state}")


@app.post("/local/reconciler/settings")
def local_reconciler_settings(
    request: Request,
    auto_reconcile_mode: Literal["off", "observe", "enforce"] = Form("off"),
    auto_reconcile_interval_seconds: str = Form("30"),
    auto_reconcile_failure_threshold: str = Form("3"),
    auto_reconcile_cooldown_seconds: str = Form("300"),
    config_revision: int | None = Form(None),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    try:
        current = policy_store.get_settings()
        saved = policy_store.save_settings(
            current.get("default_profile_id", ""),
            current.get("default_category", "other"),
            current.get("default_bandwidth_preset", "normal"),
            current.get("default_temp_minutes", "30"),
            current.get("policy_timezone", "Europe/London"),
            auto_reconcile_mode,
            auto_reconcile_interval_seconds,
            auto_reconcile_failure_threshold,
            auto_reconcile_cooldown_seconds,
            expected_revision=config_revision,
            actor=user["username"],
        )
        auto_reconciler.clear_hold()
        auto_reconciler.wake()
        audit(
            "AUTO_RECONCILE_SETTINGS",
            user["username"],
            (
                f"mode={saved['auto_reconcile_mode']} "
                f"interval={saved['auto_reconcile_interval_seconds']}s "
                f"failures={saved['auto_reconcile_failure_threshold']} "
                f"cooldown={saved['auto_reconcile_cooldown_seconds']}s"
            ),
        )
    except ValueError as exc:
        return redirect_error("settings/automation", str(exc))
    return redirect_ok("settings/automation", f"Automatic reconciliation set to {auto_reconcile_mode.upper()}")


@app.get("/api/notifications")
def api_notifications(
    archived: bool = False,
    limit: int = 100,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return {
        "schema": "zen_notifications_v1",
        "counts": policy_store.notification_counts(),
        "stats": policy_store.notification_stats(),
        "notifications": policy_store.list_notifications(archived=archived, limit=limit),
    }


@app.post("/local/notifications/read-all")
def local_notifications_read_all(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("notifications/inbox", "CSRF validation failed")
    changed = policy_store.mark_all_notifications_read(user["username"])
    audit("NOTIFICATIONS_READ_ALL", user["username"], f"count={changed}")
    return redirect_ok("notifications/inbox", f"Marked {changed} notification{'s' if changed != 1 else ''} read")


@app.post("/local/notifications/{notification_id}/read")
def local_notification_read(
    notification_id: int,
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("notifications/inbox", "CSRF validation failed")
    try:
        row = policy_store.mark_notification_read(notification_id, user["username"])
    except ValueError as exc:
        return redirect_error("notifications/inbox", str(exc))
    audit("NOTIFICATION_READ", user["username"], f"id={notification_id} source={row.get('source')}")
    return redirect_ok("notifications/inbox", f"Notification #{notification_id} marked read")


@app.post("/local/notifications/{notification_id}/ack")
def local_notification_ack(
    notification_id: int,
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("notifications/inbox", "CSRF validation failed")
    try:
        row = policy_store.acknowledge_notification(notification_id, user["username"])
    except ValueError as exc:
        return redirect_error("notifications/inbox", str(exc))
    audit("NOTIFICATION_ACKNOWLEDGED", user["username"], f"id={notification_id} source={row.get('source')}")
    return redirect_ok("notifications/inbox", f"Notification #{notification_id} acknowledged")


@app.post("/local/notifications/{notification_id}/dismiss")
def local_notification_dismiss(
    notification_id: int,
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("notifications/inbox", "CSRF validation failed")
    try:
        row = policy_store.dismiss_notification(notification_id, user["username"])
    except ValueError as exc:
        return redirect_error("notifications/inbox", str(exc))
    audit("NOTIFICATION_DISMISSED", user["username"], f"id={notification_id} source={row.get('source')}")
    return redirect_ok("notifications/inbox", f"Notification #{notification_id} dismissed")


@app.get("/api/incidents")
def api_incidents(
    include_resolved: bool = False,
    limit: int = 100,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return {
        "counts": policy_store.incident_counts(),
        "monitor": incident_monitor.snapshot(),
        "incidents": policy_store.list_incidents(
            include_resolved=include_resolved,
            limit=limit,
        ),
    }


@app.post("/local/incidents/scan")
def local_incident_scan(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("incidents/active", "CSRF validation failed")
    result = incident_monitor.run_cycle(
        trigger="manual",
    )
    audit(
        "INCIDENT_SCAN_MANUAL",
        user["username"],
        result.get("summary") or result.get("result", "unknown"),
    )
    return redirect_ok("incidents/active", result.get("summary") or "Incident scan completed")


@app.post("/local/incidents/{incident_id}/ack")
def local_incident_ack(
    incident_id: int,
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("incidents/active", "CSRF validation failed")
    try:
        incident = policy_store.acknowledge_incident(incident_id, user["username"])
    except ValueError as exc:
        return redirect_error("incidents/active", str(exc))
    audit(
        "INCIDENT_ACKNOWLEDGED",
        user["username"],
        f"id={incident_id} fingerprint={incident.get('fingerprint')}",
    )
    return redirect_ok("incidents/active", f"Incident #{incident_id} acknowledged")


@app.post("/local/incidents/{incident_id}/resolve")
def local_incident_resolve(
    incident_id: int,
    request: Request,
    resolution: str = Form("Resolved by operator"),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("incidents/active", "CSRF validation failed")
    try:
        incident = policy_store.resolve_incident(
            incident_id,
            user["username"],
            resolution,
        )
    except ValueError as exc:
        return redirect_error("incidents/active", str(exc))
    audit(
        "INCIDENT_RESOLVED",
        user["username"],
        f"id={incident_id} fingerprint={incident.get('fingerprint')} resolution={incident.get('resolution')}",
    )
    return redirect_ok("incidents/active", f"Incident #{incident_id} resolved")


@app.post("/local/incidents/settings")
def local_incident_settings(
    request: Request,
    incident_monitor_enabled: str = Form("0"),
    incident_scan_interval_seconds: str = Form("60"),
    incident_bypass_min_status: str = Form("elevated"),
    incident_retention_days: str = Form("30"),
    config_revision: int | None = Form(None),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    try:
        saved = policy_store.save_incident_settings(
            incident_monitor_enabled,
            incident_scan_interval_seconds,
            incident_bypass_min_status,
            incident_retention_days,
            expected_revision=config_revision,
            actor=user["username"],
        )
    except ValueError as exc:
        return redirect_error("settings/automation", str(exc))
    incident_monitor.wake()
    audit(
        "INCIDENT_SETTINGS",
        user["username"],
        (
            f"enabled={saved['incident_monitor_enabled']} "
            f"interval={saved['incident_scan_interval_seconds']}s "
            f"bypass={saved['incident_bypass_min_status']} "
            f"retention={saved['incident_retention_days']}d"
        ),
    )
    return redirect_ok("settings/automation", "Incident monitoring settings saved")


@app.get("/api/security/posture")
def api_security_posture(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        return {"ok": True, "posture": router.get_security_posture()}
    except RouterError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/api/security/bypass")
def api_security_bypass(
    hours: int = 24,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        managed = router.get_restricted_devices()
        ips = [item.get("address") for item in managed if item.get("address")]
        evidence = activity_store.bypass_evidence(ips, hours, 200)
        return {
            "ok": True,
            "hours": max(1, min(int(hours), 24 * 7)),
            "summary": summarize_bypass_evidence(evidence),
            "evidence": evidence,
            "doh_hardening": router.get_security_posture().get("doh", {}),
            "limitations": (
                "Evidence-led only: arbitrary HTTPS/443, ECH, custom VPN ports and "
                "application-specific tunnels cannot be reliably identified from IPFIX/SNI alone."
            ),
        }
    except ActivityError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except RouterError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/local/security/cleanup-stale")
@coherent_router_mutation
def local_security_cleanup_stale(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/security", "CSRF validation failed")
    try:
        before = router.get_security_posture()
        result = router.cleanup_stale_managed_resources()
        after = router.get_security_posture()
        audit(
            "SECURITY_STALE_CLEANUP",
            user["username"],
            (
                f"removed={result.get('total', 0)} "
                f"lists={result.get('address_lists', 0)} queues={result.get('queues', 0)} "
                f"schedulers={result.get('schedulers', 0)} scripts={result.get('scripts', 0)} "
                f"score={before.get('score')}->{after.get('score')}"
            ),
        )
        auto_reconciler.wake()
    except RouterError as exc:
        audit("SECURITY_STALE_CLEANUP_FAILED", user["username"], str(exc))
        return redirect_error("settings/security", str(exc))
    return redirect_ok(
        "settings",
        f"Removed {result.get('total', 0)} stale app-owned RouterOS resource(s)",
    )


@app.get("/api/config/revision")
def api_config_revision(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return {
        "current": policy_store.current_config_revision(),
        "recent": policy_store.list_config_revisions(20),
    }


@app.get("/api/background/status")
def api_background_status(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    snapshot = background_worker.snapshot()
    snapshot["prepared_views"] = policy_store.list_prepared_views(50)
    return snapshot


@app.get("/api/background/prepared-views")
def api_background_prepared_views(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return {
        "revision": policy_store.current_config_revision(),
        "views": policy_store.list_prepared_views(100),
    }


@app.get("/api/reconciler/requests")
def api_reconciliation_requests(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return {
        "schema": "zen_reconciliation_requests_v1",
        "summary": policy_store.reconciliation_request_stats(),
        "requests": policy_store.list_reconciliation_requests(50),
    }


@app.get("/api/reconciler/status")
def api_reconciler_status(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    return auto_reconciler.snapshot()


@app.post("/local/reconciler/run-now")
@coherent_router_request
def local_reconciler_run_now(
    request: Request,
    run_mode: Literal["observe", "enforce"] = Form("observe"),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    try:
        result = auto_reconciler.run_cycle(
            trigger="ui-run-now",
            actor=user["username"],
            mode_override=run_mode,
            ignore_hold=False,
        )
        audit(
            "RECONCILER_RUN_NOW",
            user["username"],
            f"mode={run_mode} result={result['result']} {result['summary']}",
        )
    except ReconciliationError as exc:
        return redirect_error("settings/automation", str(exc))
    return redirect_ok("settings/automation", result["summary"])


@app.post("/local/reconciler/clear-hold")
def local_reconciler_clear_hold(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/automation", "CSRF validation failed")
    auto_reconciler.clear_hold()
    audit("AUTO_RECONCILE_HOLD_CLEARED", user["username"], "manual reset")
    return redirect_ok("settings/automation", "Automatic reconciliation cooldown hold cleared")


@app.post("/local/profiles/clone")
def local_profile_clone(
    request: Request,
    profile_id: int = Form(...),
    new_name: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("policies/profiles", "CSRF validation failed")
    try:
        policy_store.clone_profile(profile_id, new_name)
    except ValueError as exc:
        return redirect_error("policies/profiles", str(exc))
    return redirect_ok("policies/profiles", "Profile cloned")


@app.post("/local/schedule-templates/clone")
def local_schedule_template_clone(
    request: Request,
    template_id: int = Form(...),
    new_name: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("schedules/templates", "CSRF validation failed")
    try:
        policy_store.clone_schedule_template(template_id, new_name)
    except ValueError as exc:
        return redirect_error("schedules/templates", str(exc))
    return redirect_ok("schedules/templates", "Schedule template cloned")


@app.post("/local/devices/copy-policy")
def local_device_copy_policy(
    request: Request,
    source_ip: str = Form(...),
    target_ip: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("devices/bulk", "CSRF validation failed")
    if source_ip == target_ip:
        return redirect_error("devices/bulk", "Source and target devices must be different")
    try:
        policy_store.copy_device_policy(source_ip, target_ip)
    except ValueError as exc:
        return redirect_error("devices/bulk", str(exc))
    return redirect_ok("devices/bulk", "Device policy copied")


def _kid_control_cutover_context():
    snapshot = router.get_legacy_kid_control_snapshot()
    preview = translate_kid_control_snapshot(snapshot)
    staged = policy_store.get_legacy_migration_stage("mikrotik_kid_control")
    cutover = policy_store.get_legacy_migration_cutover("mikrotik_kid_control")
    readiness = build_kid_control_cutover_readiness(
        staged=staged,
        fresh_preview=preview,
        fresh_snapshot=snapshot,
        settings=policy_store.get_settings(),
        existing_profiles=policy_store.list_profiles(),
        existing_device_policy=policy_store.list_device_policy(),
        current_cutover=cutover,
    )
    return snapshot, preview, staged, cutover, readiness


def _kid_control_authority_otp(request: Request, username: str, otp: str) -> str:
    """Require an explicit fresh OTP/recovery code for authority transfer."""
    if auth_manager.active_totp_count(username) < 1:
        raise AuthError("Kid Control authority transfer requires an enrolled authenticator")
    remote = request.client.host if request.client else "unknown"
    fail_key = f"kid-cutover:{remote}:{username}"
    fails = LOGIN_FAILS.get(fail_key, {"count": 0, "until": 0})
    if fails["until"] > time.time():
        raise AuthError("Too many failed authority-transfer codes. Try again shortly.")
    try:
        result = auth_manager.verify_otp_or_recovery(username, otp)
        if not result:
            raise AuthError("A fresh authenticator or recovery code is required")
        LOGIN_FAILS.pop(fail_key, None)
        mark_fresh_auth(request, privileged=True)
        return str(result.get("method") or "otp")
    except AuthError:
        count = int(fails.get("count") or 0) + 1
        LOGIN_FAILS[fail_key] = {
            "count": count,
            "until": time.time() + 60 if count >= 5 else 0,
        }
        raise


@app.get("/migration/kid-control", response_class=HTMLResponse)
@coherent_router_request
def kid_control_migration_page(
    request: Request,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    preview = None
    staged = policy_store.get_legacy_migration_stage("mikrotik_kid_control")
    cutover = policy_store.get_legacy_migration_cutover("mikrotik_kid_control")
    readiness = None
    read_error = ""
    try:
        _, preview, staged, cutover, readiness = _kid_control_cutover_context()
    except (RouterError, ValueError) as exc:
        read_error = str(exc)
    return templates.TemplateResponse(
        "kid_control_migration.html",
        {
            "request": request,
            "user": user,
            "csrf": request.session.get("csrf", ""),
            "preview": preview,
            "staged": staged,
            "cutover": cutover,
            "readiness": readiness,
            "read_error": read_error,
            "flash_error": request.query_params.get("error"),
            "flash_ok": request.query_params.get("ok"),
        },
    )


@app.get("/api/migration/kid-control")
@coherent_router_request
def kid_control_migration_api(
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        _, preview, staged, cutover, readiness = _kid_control_cutover_context()
    except (RouterError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {
        "schema": "zen_kid_control_migration_status_v2",
        "preview": preview,
        "staged": staged,
        "cutover": cutover,
        "readiness": readiness,
    }


@app.post("/local/migration/kid-control/stage")
@coherent_router_request
def kid_control_migration_stage(
    request: Request,
    preview_fingerprint: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus("CSRF validation failed"),
            status_code=303,
        )
    current_cutover = policy_store.get_legacy_migration_cutover("mikrotik_kid_control")
    if current_cutover and current_cutover.get("state") in {"prepared", "authoritative", "failed"}:
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus("Cannot replace the staged proposal while an authority transfer is prepared, active or awaiting recovery"),
            status_code=303,
        )
    try:
        preview = translate_kid_control_snapshot(router.get_legacy_kid_control_snapshot())
        if preview["source_fingerprint"] != str(preview_fingerprint or "").strip().lower():
            raise ValueError("Legacy Kid Control changed since preview; refresh and review the new translation before staging")
        staged = policy_store.stage_legacy_migration(
            "mikrotik_kid_control", preview, actor=user["username"]
        )
        audit(
            "KID_CONTROL_MIGRATION_STAGED",
            user["username"],
            (
                f"fingerprint={staged['source_fingerprint'][:12]} "
                f"profiles={preview['summary']['legacy_profiles']} "
                f"devices={preview['summary']['configured_devices']} router_writes=0"
            ),
        )
    except (RouterError, ValueError) as exc:
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus(str(exc)), status_code=303
        )
    return RedirectResponse(
        "/migration/kid-control?ok=" + quote_plus("Legacy Kid Control replacement staged locally; enforcement remains unchanged"),
        status_code=303,
    )


def _kid_control_verify_legacy_profiles_active(legacy_profiles):
    """Prove the exact retained legacy profiles are present and enabled."""
    snapshot = router.get_legacy_kid_control_snapshot()
    rows_by_name = {}
    for row in snapshot.get("profiles", []) or []:
        rows_by_name.setdefault(str(row.get("name") or ""), []).append(row)
    for expected in legacy_profiles or []:
        name = str(expected.get("name") or "")
        expected_id = str(expected.get("id") or "")
        rows = rows_by_name.get(name, [])
        if len(rows) != 1:
            raise RouterError(f"Expected exactly one retained legacy Kid Control profile named '{name}'")
        row = rows[0]
        if expected_id and str(row.get("id") or "") != expected_id:
            raise RouterError(f"Legacy Kid Control profile '{name}' identity changed during recovery")
        if bool(row.get("disabled")):
            raise RouterError(f"Legacy Kid Control profile '{name}' is still disabled after recovery")
    return True


def _kid_control_restore_failed_transfer(*, artifacts, router_devices, live_before, legacy_profiles):
    """Best-effort fail-safe restoration; caller must hold authority-transfer guard."""
    errors = []
    for profile in reversed(legacy_profiles or []):
        try:
            router.set_legacy_kid_control_profile_disabled(
                profile.get("name", ""), False, expected_id=profile.get("id", "")
            )
        except Exception as exc:
            errors.append(f"legacy:{profile.get('name')}: {exc}")

    # A migration-created Restricted_Devices row did not exist before cutover,
    # so removing that row is the complete restoration for that device.  Do not
    # try to restore a mode through an authority row that may already have been
    # removed by an earlier successful cleanup attempt.
    created_addresses = {
        str(item.get("address") or "")
        for item in (router_devices or [])
        if item.get("created")
    }
    for previous in reversed(live_before or []):
        if str(previous.get("ip") or "") in created_addresses:
            continue
        try:
            router.set_device_mode(
                previous["ip"], previous.get("mode") or "normal",
                description="migration:rollback",
            )
        except Exception as exc:
            errors.append(f"mode:{previous.get('ip')}: {exc}")

    # Remove migration-owned membership for every materialised device.  The
    # adapter removes only rows carrying the migration ownership marker, so this
    # also recovers a crash that happened between an add and evidence update.
    addresses = {
        str(item.get("ip") or "") for item in (artifacts or {}).get("devices", []) or []
    } | {
        str(item.get("address") or "") for item in (router_devices or [])
    }
    for address in sorted(x for x in addresses if x):
        try:
            router.rollback_kid_control_migration_device(address)
        except Exception as exc:
            errors.append(f"membership:{address}: {exc}")
    if artifacts:
        try:
            policy_store.rollback_kid_control_materialization(artifacts)
        except Exception as exc:
            errors.append(f"local-policy: {exc}")
    try:
        _kid_control_verify_legacy_profiles_active(legacy_profiles)
    except Exception as exc:
        errors.append(f"legacy-proof: {exc}")
    return errors


@app.post("/local/migration/kid-control/cutover")
@coherent_router_request
def kid_control_migration_cutover(
    request: Request,
    otp: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus("CSRF validation failed"), status_code=303
        )
    fingerprint = ""
    artifacts = None
    router_devices = []
    legacy_profiles = []
    live_before = []
    auth_method = ""
    try:
        auth_method = _kid_control_authority_otp(request, user["username"], otp)
        with auto_reconciler.authority_transfer_guard():
            try:
                snapshot, preview, staged, current_cutover, readiness = _kid_control_cutover_context()
                if not readiness.get("ready"):
                    detail = "; ".join(item.get("detail", "") for item in readiness.get("blocking", [])[:4])
                    raise ValueError("Kid Control authority transfer is not ready: " + (detail or "readiness gate failed"))
                fingerprint = preview["source_fingerprint"]
                router.assert_policy_enforcement_ready()

                profile_rows = {str(item.get("name") or ""): item for item in snapshot.get("profiles", []) or []}
                for profile in preview.get("profiles", []) or []:
                    name = str(profile.get("legacy_name") or "")
                    raw = profile_rows.get(name) or {}
                    legacy_profiles.append({"name": name, "id": str(raw.get("id") or "")})
                    if not raw.get("id"):
                        raise ValueError(f"Legacy Kid Control profile '{name}' has no stable RouterOS identity")

                artifacts = policy_store.materialize_kid_control_replacement(staged)

                # Persist recovery evidence before the first RouterOS migration
                # write.  Legacy authority is still active at this point.
                policy_store.record_legacy_migration_cutover(
                    "mikrotik_kid_control", "prepared", fingerprint,
                    actor=user["username"], evidence={
                        "local_artifacts": artifacts,
                        "router_devices": [],
                        "live_before": [],
                        "legacy_profiles": legacy_profiles,
                        "reconciliations": [],
                        "auth_method": auth_method,
                    },
                )

                for device in readiness.get("devices", []) or []:
                    ip = device["ip"]
                    prepared = router.prepare_kid_control_migration_device(
                        ip, device["mac"], device.get("name") or device["mac"]
                    )
                    router_devices.append(prepared)
                    before_mode = "normal" if prepared.get("created") else router.get_device_enforcement(ip).get("mode", "normal")
                    live_before.append({"ip": ip, "mode": before_mode})
                    policy_store.record_legacy_migration_cutover(
                        "mikrotik_kid_control", "prepared", fingerprint,
                        actor=user["username"], evidence={
                            "local_artifacts": artifacts,
                            "router_devices": router_devices,
                            "live_before": live_before,
                            "legacy_profiles": legacy_profiles,
                            "reconciliations": [],
                            "auth_method": auth_method,
                        },
                    )

                reconciliations = []
                for device in readiness.get("devices", []) or []:
                    result = reconcile_device(
                        device["ip"], plan_loader=get_live_policy_plan, router=router,
                        description="migration:kid-control",
                    )
                    if result.get("status") == "temporary":
                        raise ValueError(f"Temporary access is active for {device['ip']}; cutover cannot prove stable authority")
                    verified = get_live_policy_plan(device["ip"])
                    if verified.get("policy_actionable"):
                        raise RouterError(f"ZEN enforcement did not converge for {device['ip']}")
                    reconciliations.append({
                        "ip": device["ip"], "status": result.get("status"),
                        "desired_mode": verified.get("desired_mode"),
                        "live_mode": verified.get("live_mode"),
                    })

                prepared_evidence = {
                    "local_artifacts": artifacts,
                    "router_devices": router_devices,
                    "live_before": live_before,
                    "legacy_profiles": legacy_profiles,
                    "reconciliations": reconciliations,
                    "auth_method": auth_method,
                }
                policy_store.record_legacy_migration_cutover(
                    "mikrotik_kid_control", "prepared", fingerprint,
                    actor=user["username"], evidence=prepared_evidence,
                )

                disabled = []
                for profile in legacy_profiles:
                    disabled.append(router.set_legacy_kid_control_profile_disabled(
                        profile["name"], True, expected_id=profile["id"]
                    ))

                verification_snapshot = router.get_legacy_kid_control_snapshot()
                target_names = {item["name"] for item in legacy_profiles}
                still_active = [
                    str(row.get("name") or "")
                    for row in verification_snapshot.get("profiles", []) or []
                    if str(row.get("name") or "") in target_names and not bool(row.get("disabled"))
                ]
                if still_active:
                    raise RouterError("Legacy Kid Control remained active after cutover: " + ", ".join(still_active))

                final_evidence = {**prepared_evidence, "legacy_disabled": disabled}
                policy_store.record_legacy_migration_cutover(
                    "mikrotik_kid_control", "authoritative", fingerprint,
                    actor=user["username"], evidence=final_evidence,
                )
                audit(
                    "KID_CONTROL_AUTHORITY_TRANSFERRED", user["username"],
                    f"fingerprint={fingerprint[:12]} devices={len(router_devices)} profiles={len(legacy_profiles)} authority=zen",
                )
            except (RouterError, ReconciliationError, ValueError) as exc:
                cleanup_errors = _kid_control_restore_failed_transfer(
                    artifacts=artifacts, router_devices=router_devices,
                    live_before=live_before, legacy_profiles=legacy_profiles,
                )
                if fingerprint:
                    policy_store.record_legacy_migration_cutover(
                        "mikrotik_kid_control", "failed", fingerprint,
                        actor=user["username"], evidence={
                            "error": str(exc),
                            "cleanup_errors": cleanup_errors,
                            "cleanup_complete": not cleanup_errors,
                            "recovery_required": True,
                            "local_artifacts": artifacts or {},
                            "router_devices": router_devices,
                            "live_before": live_before,
                            "legacy_profiles": legacy_profiles,
                            "auth_method": auth_method,
                        },
                    )
                raise
    except (AuthError, RouterError, ReconciliationError, ValueError) as exc:
        audit("KID_CONTROL_AUTHORITY_TRANSFER_FAILED", user["username"], str(exc))
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus(str(exc)), status_code=303
        )

    return RedirectResponse(
        "/migration/kid-control?ok=" + quote_plus("ZEN is now authoritative for the migrated Kid Control policy; legacy configuration is retained but disabled"),
        status_code=303,
    )


@app.post("/local/migration/kid-control/rollback")
@coherent_router_request
def kid_control_migration_rollback(
    request: Request,
    otp: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus("CSRF validation failed"), status_code=303
        )
    try:
        auth_method = _kid_control_authority_otp(request, user["username"], otp)
        cutover = policy_store.get_legacy_migration_cutover("mikrotik_kid_control")
        if not cutover or cutover.get("state") not in {"prepared", "authoritative", "failed"}:
            raise ValueError("No prepared, authoritative or failed Kid Control transfer is available to roll back")
        evidence = cutover.get("evidence") or {}
        with auto_reconciler.authority_transfer_guard():
            router.assert_policy_enforcement_ready()
            cleanup_already_completed = failed_cutover_cleanup_complete(cutover)
            if cleanup_already_completed:
                # The cutover failure path already restored authority and
                # persisted that cleanup result.  Finalise recovery by proving
                # the retained legacy profile is active; do not replay mode or
                # membership writes against authority that has already gone.
                _kid_control_verify_legacy_profiles_active(
                    evidence.get("legacy_profiles", []) or []
                )
                cleanup_errors = []
            else:
                cleanup_errors = _kid_control_restore_failed_transfer(
                    artifacts=evidence.get("local_artifacts") or {},
                    router_devices=evidence.get("router_devices") or [],
                    live_before=evidence.get("live_before") or [],
                    legacy_profiles=evidence.get("legacy_profiles") or [],
                )
            if cleanup_errors:
                raise RouterError(
                    "Kid Control rollback remains incomplete: " + "; ".join(cleanup_errors[:4])
                )
            rolled = policy_store.record_legacy_migration_cutover(
                "mikrotik_kid_control", "rolled_back", cutover["source_fingerprint"],
                actor=user["username"],
                evidence={
                    "from_event": cutover.get("id"),
                    "legacy_restored": True,
                    "cleanup_already_completed": cleanup_already_completed,
                    "auth_method": auth_method,
                },
            )
            audit(
                "KID_CONTROL_AUTHORITY_ROLLED_BACK",
                user["username"],
                f"from_event={cutover.get('id')} rollback_event={rolled.get('id')} authority=legacy",
            )
    except (AuthError, RouterError, ReconciliationError, ValueError) as exc:
        audit("KID_CONTROL_AUTHORITY_ROLLBACK_FAILED", user["username"], str(exc))
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus(str(exc)), status_code=303
        )
    return RedirectResponse(
        "/migration/kid-control?ok=" + quote_plus("Legacy MikroTik Kid Control authority restored; migration-created ZEN authority was rolled back"),
        status_code=303,
    )


@app.post("/local/migration/kid-control/discard")
def kid_control_migration_discard(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus("CSRF validation failed"),
            status_code=303,
        )
    current_cutover = policy_store.get_legacy_migration_cutover("mikrotik_kid_control")
    if current_cutover and current_cutover.get("state") in {"prepared", "authoritative", "failed"}:
        return RedirectResponse(
            "/migration/kid-control?error=" + quote_plus("Complete authority rollback/recovery before discarding the staged migration"),
            status_code=303,
        )
    removed = policy_store.clear_legacy_migration_stage("mikrotik_kid_control")
    audit(
        "KID_CONTROL_MIGRATION_STAGE_DISCARDED",
        user["username"],
        f"removed={removed} router_writes=0",
    )
    return RedirectResponse(
        "/migration/kid-control?ok=" + quote_plus("Staged migration discarded; legacy Kid Control was not modified"),
        status_code=303,
    )


@app.post("/local/config/preview")
def local_config_preview(
    request: Request,
    config_json: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("settings/operations", "CSRF validation failed")
    try:
        payload = json.loads(config_json)
        diff = policy_store.preview_import(payload)
    except (ValueError, json.JSONDecodeError) as exc:
        return redirect_error("settings/operations", str(exc))
    return templates.TemplateResponse(
        "import_preview.html",
        {
            "request": request,
            "user": user,
            "csrf": csrf,
            "diff": diff,
            "config_json": config_json,
        },
    )


@app.get("/devices/{address}", response_class=HTMLResponse)
@coherent_router_request
def device_360_page(
    request: Request,
    address: str,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        snapshot = get_device_360(address)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RouterError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return templates.TemplateResponse(
        "device_360.html",
        {"request": request, "user": user, "snapshot": snapshot},
    )


@app.get("/api/devices/{address}/360")
@coherent_router_request
def device_360_api(
    address: str,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        return get_device_360(address)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RouterError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/policy/explain/{address}", response_class=HTMLResponse)
@coherent_router_request
def policy_explain_page(
    request: Request,
    address: str,
    service: str | None = None,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        explanation = get_policy_explanation(address, focus_service=service)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RouterError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return templates.TemplateResponse(
        "policy_explain.html",
        {"request": request, "user": user, "explanation": explanation},
    )


@app.get("/api/policy/explain/{address}")
@coherent_router_request
def policy_explain_api(
    address: str,
    service: str | None = None,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        return get_policy_explanation(address, focus_service=service)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RouterError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/local/policy-summary")
@coherent_router_request
def local_policy_summary(
    request: Request,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        devices = get_live_devices()
    except Exception:
        devices = []
    summary = policy_store.build_policy_summary(devices)
    return templates.TemplateResponse(
        "policy_summary.html",
        {"request": request, "user": user, "summary": summary},
    )


@app.post("/devices/policy/apply")
def apply_device_policy(
    request: Request,
    ip: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    """Durably queue reconciliation and return without waiting on RouterOS."""
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        queued = auto_reconciler.request_reconciliation(
            target=ip,
            actor=user["username"],
            reason="Manual device policy apply requested",
        )
        audit(
            "POLICY_RECONCILE_QUEUED", user["username"],
            f"id={queued['id']} target={ip} revision={queued['requested_revision']}",
        )
    except (ValueError, ReconciliationError) as exc:
        audit("POLICY_RECONCILE_QUEUE_FAILED", user["username"], f"{ip}: {exc}")
        raise HTTPException(status_code=409, detail=str(exc))
    return redirect_ok(
        "devices/managed",
        f"Policy apply queued for {ip}; desired revision {queued['requested_revision']} will reconcile in the background",
    )


@app.post("/devices/policy/apply-all")
def apply_all_device_policies(
    request: Request,
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    """Queue all-device convergence without holding the HTTP request on RouterOS."""
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        queued = auto_reconciler.request_reconciliation(
            target="*",
            actor=user["username"],
            reason="Manual all-device policy apply requested",
        )
        audit(
            "POLICY_RECONCILE_ALL_QUEUED", user["username"],
            f"id={queued['id']} revision={queued['requested_revision']}",
        )
    except (ValueError, ReconciliationError) as exc:
        audit("POLICY_RECONCILE_ALL_QUEUE_FAILED", user["username"], str(exc))
        raise HTTPException(status_code=409, detail=str(exc))
    return redirect_ok(
        "devices/managed",
        f"All-device policy reconciliation queued at desired revision {queued['requested_revision']}",
    )


@app.get("/api/devices/{ip}/rewards")
def get_device_reward_status(
    ip: str,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        return {"ok": True, "reward": policy_store.get_reward_account(ip, ledger_limit=20)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/devices/rewards/adjust")
def adjust_device_rewards(
    request: Request,
    ip: str = Form(...),
    delta_minutes: int = Form(...),
    reason: str = Form("Manual reward adjustment"),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    if not csrf_ok(request, csrf):
        return redirect_error("devices/managed", "CSRF validation failed")
    try:
        result = policy_store.adjust_reward_minutes(
            ip,
            delta_minutes,
            reason=reason,
            actor=user["username"],
            kind="grant" if delta_minutes > 0 else "deduct",
        )
        audit(
            "REWARD_ADJUSTED",
            user["username"],
            (
                f"{ip}: {result['delta_minutes']:+d}m; "
                f"balance={result['balance_minutes']}m; reason={result['reason']}"
            ),
        )
    except ValueError as exc:
        return redirect_error("devices/managed", str(exc))
    return redirect_ok(
        "devices/managed",
        f"Reward balance for {ip}: {result['balance_minutes']} minutes",
    )


@app.post("/devices/rewards/redeem")
@coherent_router_mutation
def redeem_device_rewards(
    request: Request,
    ip: str = Form(...),
    minutes: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    """Spend reward-bank minutes on the proven RouterOS temporary NORMAL path.

    The debit is reserved atomically before the router write. Router failures
    receive a compensating refund. Successful access is still expired by the
    RouterOS scheduler, independently of this application.
    """
    if not csrf_ok(request, csrf):
        return redirect_error("devices/managed", "CSRF validation failed")

    reservation = None
    router_grant_confirmed = False
    try:
        global_mode = str(router.get_status().get("mode") or "unknown").lower()
        if global_mode != "normal":
            raise RouterError(
                f"Global mode is {global_mode.upper()}; reward access cannot "
                "bypass the MASTER/global restriction"
            )

        existing = router.get_device_temporary_access(ip)
        if existing.get("active"):
            raise RouterError(
                "Reward time cannot be redeemed while temporary access is already active; "
                "end the current override first so reward minutes cannot accidentally shorten it"
            )
        plan = get_live_policy_plan(ip)
        restore_mode = plan.get("desired_mode")
        if restore_mode == "normal":
            raise ValueError(
                "Reward time can only be redeemed when the effective device mode is SLOW or BLOCKED"
            )

        reservation = policy_store.reserve_reward_redemption(
            ip,
            minutes,
            actor=user["username"],
            reason="Reward bank redemption for temporary NORMAL access",
        )

        result = router.set_device_temporary_normal(
            ip,
            minutes,
            description=f"reward:{user['username']}",
            restore_mode=restore_mode,
            reference=reward_redemption_reference(reservation["id"]),
        )
        router_grant_confirmed = temporary_state_proves_reward(result, reservation["id"])
        if not router_grant_confirmed:
            raise RouterError(
                "RouterOS temporary access became active without the durable reward redemption reference"
            )
        completed = policy_store.complete_reward_redemption(
            reservation["id"],
            restore_at=result.get("restore_at_iso") or result.get("restore_time") or "",
            note="RouterOS temporary access confirmed",
        )
        account = policy_store.get_reward_account(ip, ledger_limit=0)
        audit(
            "REWARD_REDEEMED",
            user["username"],
            (
                f"{ip}: spent={minutes}m balance={account['balance_minutes']}m; "
                f"redemption={completed['id']}; restore={result.get('restore_mode')}; "
                f"restore_at={result.get('restore_at_iso') or result.get('restore_time')}"
            ),
        )
        auto_reconciler.wake()
    except (ValueError, RouterError) as exc:
        if reservation is not None and not router_grant_confirmed:
            # If the grant call failed, make one fresh evidence check before
            # refunding. An API outage is uncertainty, not proof that access was
            # never granted, so retain the debit in RESERVED state in that case.
            state = None
            state_error = None
            try:
                state = router.get_device_temporary_access(ip)
            except RouterError as verify_exc:
                state_error = str(verify_exc)

            if state is not None and temporary_state_proves_reward(state, reservation["id"]):
                try:
                    policy_store.complete_reward_redemption(
                        reservation["id"],
                        restore_at=state.get("restore_at") or state.get("restore_time") or "",
                        note=f"RouterOS reward grant recovered after response failure: {exc}",
                    )
                    router_grant_confirmed = True
                    audit(
                        "REWARD_REDEMPTION_RECOVERED_APPLIED",
                        user["username"],
                        f"{ip}: redemption={reservation['id']} confirmed after response failure",
                    )
                except ValueError:
                    pass
            elif state is not None and not state.get("active"):
                try:
                    refunded = policy_store.refund_reward_redemption(
                        reservation["id"],
                        note=f"RouterOS reward access failed before a grant was proven: {exc}",
                    )
                    audit(
                        "REWARD_REDEMPTION_REFUNDED",
                        user["username"],
                        f"{ip}: redemption={refunded['id']} refunded after proven non-grant: {exc}",
                    )
                except ValueError as refund_exc:
                    audit(
                        "REWARD_REFUND_FAILED",
                        user["username"],
                        f"{ip}: redemption={reservation['id']} refund failed: {refund_exc}",
                    )
            else:
                audit(
                    "REWARD_REDEMPTION_RECOVERY_DEFERRED",
                    user["username"],
                    (
                        f"{ip}: redemption={reservation['id']} retained as reserved after uncertain "
                        f"RouterOS result; verify_error={state_error or 'active unbound temporary access'}"
                    ),
                )
        elif reservation is not None and router_grant_confirmed:
            # RouterOS has already proven the allowance. Never return the minutes
            # just because the local completion write failed; startup recovery
            # will complete the durable debit from the bound RouterOS reference.
            audit(
                "REWARD_REDEMPTION_RECOVERY_DEFERRED",
                user["username"],
                f"{ip}: redemption={reservation['id']} RouterOS grant confirmed; local completion pending: {exc}",
            )
        return redirect_error("devices/managed", str(exc))

    return redirect_ok(
        "devices/managed",
        f"Redeemed {minutes} reward minutes for {ip}",
    )


@app.post("/devices/rewards/recover")
@coherent_router_request
def recover_device_reward_redemptions(
    request: Request,
    ip: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    """Recheck deliberately-held reward reservations against fresh RouterOS evidence."""
    if not csrf_ok(request, csrf):
        return redirect_error("devices/managed", "CSRF validation failed")

    outcomes = reconcile_pending_reward_redemptions(
        policy_store=policy_store,
        router=router,
        audit=audit,
        router_error=RouterError,
        actor=user["username"],
        ip=ip,
    )
    if not outcomes:
        return redirect_ok("devices/managed", f"No pending reward recovery for {ip}")

    applied = sum(1 for item in outcomes if item.get("recovery") == "applied")
    refunded = sum(1 for item in outcomes if item.get("recovery") == "refunded")
    deferred = sum(1 for item in outcomes if item.get("recovery") == "deferred")
    message = (
        f"Reward recovery for {ip}: applied={applied}, refunded={refunded}, deferred={deferred}"
    )
    if deferred:
        return redirect_error("devices/managed", message)
    return redirect_ok("devices/managed", message)


@app.get("/api/devices/{ip}/quota")
def get_device_quota_status(
    ip: str,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    try:
        policy = get_effective_policy(ip)
        return {
            "ok": True,
            "ip": ip,
            "quota": policy.get("quota_state") or {},
            "desired_mode": policy.get("mode"),
            "blocked_services": policy.get("blocked_services") or [],
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/devices/{ip}/temporary")
def get_device_temporary_status(
    ip: str,
    user=Depends(require_role("admin", "operator", "viewer")),
):
    """Machine-readable per-device temporary NORMAL status."""
    try:
        return {"ok": True, "temporary": router.get_device_temporary_access(ip)}
    except RouterError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/devices/temporary/start")
@coherent_router_mutation
def start_device_temporary_access(
    request: Request,
    ip: str = Form(...),
    minutes: int = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    """Grant a bounded per-device NORMAL override with RouterOS expiry."""
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    if minutes not in {15, 30, 60}:
        raise HTTPException(status_code=400, detail="Temporary access supports 15, 30 or 60 minutes")

    try:
        global_mode = str(router.get_status().get("mode") or "unknown").lower()
        if global_mode != "normal":
            raise RouterError(
                f"Global mode is {global_mode.upper()}; per-device temporary access "
                "cannot bypass the MASTER/global restriction"
            )

        before = router.get_device_enforcement(ip)
        existing = router.get_device_temporary_access(ip)
        plan = get_live_policy_plan(ip)
        restore_mode = (
            existing.get("restore_mode")
            if existing.get("active")
            else plan.get("desired_mode")
        )
        result = router.set_device_temporary_normal(
            ip,
            minutes,
            description=f"temporary:{user['username']}",
            restore_mode=restore_mode,
        )
        event = "DEVICE_TEMP_EXTENDED" if existing.get("active") else "DEVICE_TEMP_STARTED"
        audit(
            event,
            user["username"],
            (
                f"{ip}: {minutes}m NORMAL; before={before.get('mode')}; "
                f"restore={result.get('restore_mode')}; "
                f"restore_at={result.get('restore_at_iso') or result.get('restore_time')}"
            ),
        )
        auto_reconciler.wake()
    except RouterError as exc:
        audit(
            "DEVICE_TEMP_START_FAILED",
            user["username"],
            f"{ip}: {exc}",
        )
        raise HTTPException(status_code=502, detail=str(exc))

    return RedirectResponse("/?view=devices&section=managed#devices/managed", status_code=303)


@app.post("/devices/temporary/cancel")
@coherent_router_mutation
def cancel_device_temporary_access(
    request: Request,
    ip: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    """Cancel temporary NORMAL and immediately restore the captured mode."""
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

    try:
        before = router.get_device_temporary_access(ip)
        result = router.cancel_device_temporary_access(ip, restore=True)
        audit(
            "DEVICE_TEMP_CANCELLED",
            user["username"],
            (
                f"{ip}: active={before.get('active', False)}; "
                f"restored={result.get('restore_mode') or 'none'}"
            ),
        )
        # A schedule may have changed while the temporary override was active.
        # Wake the reconciler so the captured fail-safe state is quickly converged to the
        # current effective policy when necessary.
        auto_reconciler.wake()
    except RouterError as exc:
        audit(
            "DEVICE_TEMP_CANCEL_FAILED",
            user["username"],
            f"{ip}: {exc}",
        )
        raise HTTPException(status_code=502, detail=str(exc))

    return RedirectResponse("/?view=devices&section=managed#devices/managed", status_code=303)


@app.post("/devices/enforcement")
@coherent_router_mutation
def set_device_enforcement(
    request: Request,
    ip: str = Form(...),
    action: Literal["normal", "slow", "blocked"] = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin", "operator")),
):
    """
    Apply immediate live RouterOS enforcement.

    This endpoint intentionally does not mutate Policy Studio desired state.
    """
    if not csrf_ok(request, csrf):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed",
        )

    try:
        before = router.get_device_enforcement(ip)

        # Explicit manual mode control supersedes any outstanding temporary
        # override; otherwise its RouterOS scheduler could later restore an old
        # state over the operator's new choice.
        temporary = router.get_device_temporary_access(ip)
        if temporary.get("active"):
            router.cancel_device_temporary_access(ip, restore=False)

        after = router.set_device_mode(
            ip,
            action,
            description="UI enforcement",
        )

        audit(
            "DEVICE_ENFORCEMENT_CHANGE",
            user["username"],
            f"{ip}: {before['mode'].upper()} -> "
            f"{after['mode'].upper()}",
        )

    except RouterError as exc:
        audit(
            "DEVICE_ENFORCEMENT_CHANGE_FAILED",
            user["username"],
            f"{ip} {action}: {exc}",
        )
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )

    return RedirectResponse("/?view=devices&section=managed#devices/managed", status_code=303)


@app.post("/devices/add")
@coherent_router_mutation
def add_device(
    request: Request,
    ip: str = Form(...),
    description: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        result = router.add_restricted_device(ip, description)
        audit(
            "DEVICE_RESTRICTED",
            user["username"],
            f"{result['description']} {result['address']} {result['mac_address']}",
        )
    except RouterError as exc:
        audit("DEVICE_RESTRICT_FAILED", user["username"], f"{ip}: {exc}")
        raise HTTPException(status_code=502, detail=str(exc))
    return RedirectResponse("/?view=devices&section=managed#devices/managed", status_code=303)


@app.post("/devices/remove")
@coherent_router_mutation
def remove_device(
    request: Request,
    ip: str = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    try:
        # Remove any app-owned RouterOS temporary scheduler/script first so a
        # future one-shot restore cannot recreate mode state for an unmanaged IP.
        router.cancel_device_temporary_access(ip, restore=False)
        result = router.remove_restricted_device(ip)
        # Reward banks are keyed by the managed IP. Purge the account when the
        # device leaves management so a future device reusing the address does
        # not inherit someone else's allowance.
        retirement = policy_store.retire_device_state(ip)
        audit(
            "DEVICE_UNRESTRICTED",
            user["username"],
            f"{result['address']} (DHCP reservation retained; "
            f"local policy retired={retirement['device_policy']} "
            f"schedules={retirement['schedule_plans']} "
            f"exceptions={retirement['date_exceptions']})",
        )
    except RouterError as exc:
        audit("DEVICE_UNRESTRICT_FAILED", user["username"], f"{ip}: {exc}")
        raise HTTPException(status_code=502, detail=str(exc))
    return RedirectResponse("/?view=devices&section=managed#devices/managed", status_code=303)


@app.post("/web-policy")
@coherent_router_mutation
def set_web_policy(
    request: Request,
    action: Literal["enable", "disable"] = Form(...),
    csrf: str = Form(...),
    user=Depends(require_role("admin")),
):
    if not csrf_ok(request, csrf):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    enabled = action == "enable"
    try:
        before = router.get_web_policy_status()["enabled"]
        router.set_web_policy(enabled)
        audit(
            "WEB_POLICY_CHANGE",
            user["username"],
            f"{'ENABLED' if before else 'DISABLED'} -> "
            f"{'ENABLED' if enabled else 'DISABLED'}",
        )
    except RouterError as exc:
        audit("WEB_POLICY_CHANGE_FAILED", user["username"], str(exc))
        raise HTTPException(status_code=502, detail=str(exc))
    return RedirectResponse("/?view=dashboard&section=controls#dashboard/controls", status_code=303)
