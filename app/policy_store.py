import json
import os
import sqlite3
import re
import ipaddress
import hashlib
import uuid
from datetime import date, datetime, time as dt_time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from contextlib import contextmanager
from pathlib import Path

from app.bandwidth import BandwidthRateError, normalize_rate
from app.performance import perf_span
from app.policy_time import local_midnight, normalize_policy_datetime, resolve_local_wall_time, utc_instant
from app.quota import (
    bytes_for_mb,
    format_bytes as format_quota_bytes,
    normalize_quota_action,
    normalize_quota_mb,
    normalize_service_quotas,
    percent_used,
)
from app.service_catalog import builtin_service_metadata, SERVICE_ENFORCEMENT
from app.service_provisioning import build_custom_service_contract
from app.summary_delivery import (
    normalize_delivery_time, normalize_email_recipients, normalize_webhook_url,
)
from app.policy_groups import (
    POLICY_GROUPS,
    expand_policy_keys,
    group_members,
    policy_group_states,
    normalized_group_catalog,
)


DEFAULT_SERVICES = [
    ("youtube", "YouTube"),
    ("netflix", "Netflix"),
    ("prime_video", "Prime Video"),
    ("bbc_iplayer", "BBC iPlayer"),
    ("chatgpt", "ChatGPT"),
    ("openai", "OpenAI"),
    ("gaming", "Gaming"),
    ("social_media", "Social media"),
    ("tiktok", "TikTok"),
    ("discord", "Discord"),
    ("roblox", "Roblox"),
    ("steam", "Steam"),
    ("xbox", "Xbox"),
    ("playstation", "PlayStation"),
]

DEFAULT_BANDWIDTH_PRESETS = {
    "normal": ("Normal", "Unlimited", "Unlimited", "No additional bandwidth restriction."),
    "slow": ("Slow", "128k", "256k", "Very limited browsing; streaming should struggle."),
    "very_slow": ("Very slow", "64k", "128k", "Barely usable connectivity."),
    "homework": ("Homework", "512k", "2M", "Useful web access without comfortable HD streaming."),
    "basic": ("Basic", "1M", "5M", "General browsing and messaging with constrained video."),
}

DEVICE_CATEGORIES = [
    ("phone", "Phone"),
    ("tablet", "Tablet"),
    ("laptop", "Laptop"),
    ("tv", "TV"),
    ("console", "Console"),
    ("iot", "IoT"),
    ("other", "Other"),
]


class ConfigRevisionConflict(ValueError):
    """A caller attempted to write against a stale configuration revision."""


class PolicyStore:
    """Container-local desired-policy configuration.

    This class deliberately contains no RouterOS client and performs no router
    writes. Router enforcement is a later integration phase.
    """

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _db(self):
        with perf_span("sqlite.connect"):
            conn = sqlite3.connect(self.path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        try:
            with perf_span("sqlite.transaction"):
                yield conn
                conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._db() as db:
            # SQLite is shared by request handlers and background workers. WAL
            # plus a bounded busy timeout improves durability and reduces avoidable
            # writer contention without changing authority.
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    desired_mode TEXT NOT NULL DEFAULT 'normal',
                    bandwidth_preset TEXT NOT NULL DEFAULT 'normal',
                    notes TEXT NOT NULL DEFAULT '',
                    blocked_services TEXT NOT NULL DEFAULT '[]',
                    daily_quota_mb INTEGER NOT NULL DEFAULT 0,
                    daily_quota_action TEXT NOT NULL DEFAULT 'blocked',
                    service_quotas TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS device_policy (
                    ip TEXT PRIMARY KEY,
                    alias TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT 'other',
                    favourite INTEGER NOT NULL DEFAULT 0,
                    profile_id INTEGER NULL,
                    mode_override TEXT NOT NULL DEFAULT 'inherit',
                    FOREIGN KEY(profile_id) REFERENCES profiles(id)
                );

                CREATE TABLE IF NOT EXISTS managed_device_identity (
                    ip TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL UNIQUE,
                    managed_since TEXT NOT NULL,
                    current_name TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS policy_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    desired_mode TEXT NOT NULL,
                    bandwidth_preset TEXT NOT NULL,
                    notes TEXT NOT NULL DEFAULT '',
                    blocked_services TEXT NOT NULL DEFAULT '[]',
                    daily_quota_mb INTEGER NOT NULL DEFAULT 0,
                    daily_quota_action TEXT NOT NULL DEFAULT 'blocked',
                    service_quotas TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS bandwidth_presets (
                    key TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    upload TEXT NOT NULL,
                    download TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    builtin INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS services (
                    key TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    builtin INTEGER NOT NULL DEFAULT 0,
                    category TEXT NOT NULL DEFAULT 'other',
                    dns_suffixes TEXT NOT NULL DEFAULT '[]',
                    tls_patterns TEXT NOT NULL DEFAULT '[]',
                    classifier_enabled INTEGER NOT NULL DEFAULT 1,
                    enforcement_approved INTEGER NOT NULL DEFAULT 0,
                    enforcement_approved_at TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS schedule_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_value TEXT NOT NULL,
                    clock_time TEXT NOT NULL,
                    days TEXT NOT NULL DEFAULT '[]',
                    enabled INTEGER NOT NULL DEFAULT 1
                );


                CREATE TABLE IF NOT EXISTS service_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    services TEXT NOT NULL DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS aggregate_policy_groups (
                    key TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    members TEXT NOT NULL DEFAULT '[]',
                    builtin INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS schedule_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    entries TEXT NOT NULL DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS date_exceptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    start_date TEXT NOT NULL,
                    end_date TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    template_id INTEGER NULL,
                    notes TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'info'
                );

                CREATE INDEX IF NOT EXISTS idx_audit_log_id
                    ON audit_log(id DESC);

                CREATE TABLE IF NOT EXISTS policy_state_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    captured_at TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    state_hash TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'effective-resolver',
                    desired_mode TEXT NOT NULL,
                    mode_source TEXT NOT NULL DEFAULT '',
                    bandwidth_preset TEXT NOT NULL DEFAULT 'normal',
                    blocked_services TEXT NOT NULL DEFAULT '[]',
                    policy_groups TEXT NOT NULL DEFAULT '[]',
                    schedule_active INTEGER NOT NULL DEFAULT 0,
                    schedule_reason TEXT NOT NULL DEFAULT '',
                    active_date_exception TEXT NOT NULL DEFAULT '{}',
                    quota_state TEXT NOT NULL DEFAULT '{}',
                    policy_at TEXT NOT NULL DEFAULT '',
                    identity_id TEXT NOT NULL DEFAULT '',
                    device_name TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_policy_state_history_ip_time
                    ON policy_state_history(ip, captured_at, id);

                CREATE TABLE IF NOT EXISTS summary_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL DEFAULT 'scheduled',
                    report_date TEXT NOT NULL,
                    period TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    destination TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    next_attempt_at TEXT NOT NULL DEFAULT '',
                    last_attempt_at TEXT NOT NULL DEFAULT '',
                    sent_at TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_summary_deliveries_status_next
                    ON summary_deliveries(status, next_attempt_at, id);
                CREATE INDEX IF NOT EXISTS idx_summary_deliveries_report
                    ON summary_deliveries(report_date DESC, channel, id DESC);

                CREATE TABLE IF NOT EXISTS config_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_config_snapshots_id
                    ON config_snapshots(id DESC);

                CREATE TABLE IF NOT EXISTS legacy_migration_staging (
                    source TEXT PRIMARY KEY,
                    source_fingerprint TEXT NOT NULL,
                    staged_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS legacy_migration_cutover_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    source_fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    evidence TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_legacy_migration_cutover_source
                    ON legacy_migration_cutover_events(source, id DESC);

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'warning',
                    status TEXT NOT NULL DEFAULT 'open',
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    opened_at TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    acknowledged_at TEXT,
                    acknowledged_by TEXT NOT NULL DEFAULT '',
                    resolved_at TEXT,
                    resolved_by TEXT NOT NULL DEFAULT '',
                    resolution TEXT NOT NULL DEFAULT '',
                    suppress_until_clear INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_status_updated
                    ON incidents(status, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_incidents_source_status
                    ON incidents(source, status);

                CREATE TABLE IF NOT EXISTS reward_accounts (
                    ip TEXT PRIMARY KEY,
                    balance_minutes INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reward_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    delta_minutes INTEGER NOT NULL,
                    balance_after INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT '',
                    reference TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reward_ledger_ip_id
                    ON reward_ledger(ip, id DESC);

                CREATE TABLE IF NOT EXISTS reward_redemptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    minutes INTEGER NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    restore_at TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_reward_redemptions_ip_id
                    ON reward_redemptions(ip, id DESC);

                CREATE TABLE IF NOT EXISTS discovery_cache (
                    ip TEXT PRIMARY KEY,
                    mac TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL DEFAULT '',
                    host_name TEXT NOT NULL DEFAULT '',
                    comment TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    last_seen TEXT NOT NULL DEFAULT '',
                    seen_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS config_revision_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    revision INTEGER NOT NULL DEFAULT 0,
                    digest TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS config_revisions (
                    revision INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    scope TEXT NOT NULL DEFAULT 'config',
                    digest TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS outbox_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    aggregate_type TEXT NOT NULL DEFAULT '',
                    aggregate_key TEXT NOT NULL DEFAULT '',
                    revision INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    dispatched_at TEXT NOT NULL DEFAULT '',
                    background_job_id INTEGER NULL
                );

                CREATE INDEX IF NOT EXISTS idx_outbox_status_id
                    ON outbox_events(status, id);

                CREATE TABLE IF NOT EXISTS background_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'global',
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    available_at TEXT NOT NULL,
                    lease_owner TEXT NOT NULL DEFAULT '',
                    lease_token TEXT NOT NULL DEFAULT '',
                    lease_expires_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT NOT NULL DEFAULT '',
                    finished_at TEXT NOT NULL DEFAULT '',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_background_jobs_claim
                    ON background_jobs(status, available_at, id);

                CREATE TABLE IF NOT EXISTS reconciliation_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    requested_revision INTEGER NOT NULL DEFAULT 0,
                    applied_revision INTEGER NOT NULL DEFAULT 0,
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    started_at TEXT NOT NULL DEFAULT '',
                    finished_at TEXT NOT NULL DEFAULT '',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_reconciliation_requests_status_id
                    ON reconciliation_requests(status, id);

                CREATE INDEX IF NOT EXISTS idx_reconciliation_requests_target_id
                    ON reconciliation_requests(target, id DESC);

                CREATE TABLE IF NOT EXISTS background_scope_locks (
                    scope TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    token TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS background_worker_metrics (
                    worker_name TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL DEFAULT '',
                    heartbeat_at TEXT NOT NULL DEFAULT '',
                    cycles INTEGER NOT NULL DEFAULT 0,
                    jobs_claimed INTEGER NOT NULL DEFAULT 0,
                    jobs_succeeded INTEGER NOT NULL DEFAULT 0,
                    jobs_failed INTEGER NOT NULL DEFAULT 0,
                    jobs_deferred INTEGER NOT NULL DEFAULT 0,
                    last_duration_ms REAL NOT NULL DEFAULT 0,
                    last_result TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS prepared_views (
                    view_key TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'global',
                    source_revision INTEGER NOT NULL DEFAULT 0,
                    captured_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    payload_bytes INTEGER NOT NULL DEFAULT 0,
                    generation INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'ready',
                    error TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_prepared_views_kind_scope
                    ON prepared_views(kind, scope);
                """
            )
            db.execute(
                """INSERT OR IGNORE INTO config_revision_state
                   (singleton, revision, digest, updated_at, actor, reason)
                   VALUES (1, 0, '', '', '', '')"""
            )

            for key, (name, upload, download, description) in DEFAULT_BANDWIDTH_PRESETS.items():
                db.execute(
                    """INSERT OR IGNORE INTO bandwidth_presets
                       (key, name, upload, download, description, builtin)
                       VALUES (?, ?, ?, ?, ?, 1)""",
                    (key, name, upload, download, description),
                )
            for key, name in DEFAULT_SERVICES:
                db.execute(
                    """INSERT OR IGNORE INTO services (key, name, description, builtin)
                       VALUES (?, ?, '', 1)""",
                    (key, name),
                )

            now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for key, group in POLICY_GROUPS.items():
                db.execute(
                    """INSERT OR IGNORE INTO aggregate_policy_groups
                       (key, name, description, members, builtin, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 1, ?, ?)""",
                    (
                        key, group["name"], group.get("description", ""),
                        json.dumps(sorted(group.get("members") or [])), now_iso, now_iso,
                    ),
                )

            service_cols = {row["name"] for row in db.execute("PRAGMA table_info(services)")}
            if "category" not in service_cols:
                db.execute("ALTER TABLE services ADD COLUMN category TEXT NOT NULL DEFAULT 'other'")
            if "dns_suffixes" not in service_cols:
                db.execute("ALTER TABLE services ADD COLUMN dns_suffixes TEXT NOT NULL DEFAULT '[]'")
            if "tls_patterns" not in service_cols:
                db.execute("ALTER TABLE services ADD COLUMN tls_patterns TEXT NOT NULL DEFAULT '[]'")
            if "classifier_enabled" not in service_cols:
                db.execute("ALTER TABLE services ADD COLUMN classifier_enabled INTEGER NOT NULL DEFAULT 1")
            if "enforcement_approved" not in service_cols:
                db.execute("ALTER TABLE services ADD COLUMN enforcement_approved INTEGER NOT NULL DEFAULT 0")
            if "enforcement_approved_at" not in service_cols:
                db.execute("ALTER TABLE services ADD COLUMN enforcement_approved_at TEXT NOT NULL DEFAULT ''")

            # Built-in service signatures are product contracts. Refresh only the
            # classification metadata so old databases gain the current TLS/DNS
            # coverage without touching names, descriptions or policy state.
            for service_key in SERVICE_ENFORCEMENT:
                metadata = builtin_service_metadata(service_key) or {}
                db.execute(
                    """UPDATE services SET category=?, dns_suffixes=?, tls_patterns=?, classifier_enabled=1
                       WHERE key=? AND builtin=1""",
                    (
                        metadata.get("category", "other"),
                        json.dumps(metadata.get("dns_suffixes") or []),
                        json.dumps(metadata.get("tls_patterns") or []),
                        service_key,
                    ),
                )

            cols = {row["name"] for row in db.execute("PRAGMA table_info(device_policy)")}
            if "category" not in cols:
                db.execute("ALTER TABLE device_policy ADD COLUMN category TEXT NOT NULL DEFAULT 'other'")
            if "favourite" not in cols:
                db.execute("ALTER TABLE device_policy ADD COLUMN favourite INTEGER NOT NULL DEFAULT 0")

            history_cols = {row["name"] for row in db.execute("PRAGMA table_info(policy_state_history)")}
            if "identity_id" not in history_cols:
                db.execute("ALTER TABLE policy_state_history ADD COLUMN identity_id TEXT NOT NULL DEFAULT ''")
            if "device_name" not in history_cols:
                db.execute("ALTER TABLE policy_state_history ADD COLUMN device_name TEXT NOT NULL DEFAULT ''")

            # v0.49 starts explicit physical-management epochs. Existing history
            # is deliberately *not* back-bound to a new identity because an IP
            # may have been reused before this evidence existed. The current
            # device gets a fresh epoch at upgrade time; older rows remain
            # legacy IP-scoped evidence with identity_id=''.
            identity_now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for row in db.execute("SELECT ip, alias FROM device_policy ORDER BY ip").fetchall():
                if db.execute(
                    "SELECT 1 FROM managed_device_identity WHERE ip=?", (row["ip"],)
                ).fetchone():
                    continue
                db.execute(
                    """INSERT INTO managed_device_identity
                       (ip, identity_id, managed_since, current_name)
                       VALUES (?, ?, ?, ?)""",
                    (
                        row["ip"],
                        f"mdi_{uuid.uuid4().hex}",
                        identity_now,
                        str(row["alias"] or "")[:50],
                    ),
                )

            # Canonicalize legacy checkpoint instants to UTC before any range
            # query compares TEXT values. ISO-8601 lexical ordering is only safe
            # when every row uses the same offset.
            for row in db.execute(
                "SELECT id, captured_at FROM policy_state_history ORDER BY id"
            ).fetchall():
                try:
                    raw = datetime.fromisoformat(str(row["captured_at"]))
                    if raw.tzinfo is None:
                        raw = raw.replace(tzinfo=timezone.utc)
                    canonical = raw.astimezone(timezone.utc).isoformat(timespec="seconds")
                except (TypeError, ValueError):
                    continue
                if canonical != row["captured_at"]:
                    db.execute(
                        "UPDATE policy_state_history SET captured_at=? WHERE id=?",
                        (canonical, row["id"]),
                    )

            profile_cols = {row["name"] for row in db.execute("PRAGMA table_info(profiles)")}
            if "daily_quota_mb" not in profile_cols:
                db.execute("ALTER TABLE profiles ADD COLUMN daily_quota_mb INTEGER NOT NULL DEFAULT 0")
            if "daily_quota_action" not in profile_cols:
                db.execute("ALTER TABLE profiles ADD COLUMN daily_quota_action TEXT NOT NULL DEFAULT 'blocked'")
            if "service_quotas" not in profile_cols:
                db.execute("ALTER TABLE profiles ADD COLUMN service_quotas TEXT NOT NULL DEFAULT '{}'")

            template_cols = {row["name"] for row in db.execute("PRAGMA table_info(policy_templates)")}
            if "daily_quota_mb" not in template_cols:
                db.execute("ALTER TABLE policy_templates ADD COLUMN daily_quota_mb INTEGER NOT NULL DEFAULT 0")
            if "daily_quota_action" not in template_cols:
                db.execute("ALTER TABLE policy_templates ADD COLUMN daily_quota_action TEXT NOT NULL DEFAULT 'blocked'")
            if "service_quotas" not in template_cols:
                db.execute("ALTER TABLE policy_templates ADD COLUMN service_quotas TEXT NOT NULL DEFAULT '{}'")

            defaults = {
                "default_profile_id": "",
                "default_category": "other",
                "default_bandwidth_preset": "normal",
                "default_temp_minutes": "30",
                "policy_timezone": os.getenv("POLICY_TIMEZONE", "Europe/London"),
                "auto_reconcile_mode": "off",
                "auto_reconcile_interval_seconds": "30",
                "auto_reconcile_failure_threshold": "3",
                "auto_reconcile_cooldown_seconds": "300",
                "reward_bank_enabled": "1",
                "reward_bank_max_minutes": "240",
                "reward_default_grant_minutes": "30",
                "reward_max_redeem_minutes": "60",
                "quota_engine_enabled": "0",
                "quota_warning_percent": "80",
                "snapshot_retention_count": "30",
                "audit_retention_events": "5000",
                "incident_monitor_enabled": "1",
                "incident_scan_interval_seconds": "60",
                "incident_bypass_min_status": "elevated",
                "incident_retention_days": "30",
                "summary_delivery_enabled": "0",
                "summary_delivery_time": "07:00",
                "summary_delivery_period": "yesterday",
                "summary_delivery_email_enabled": "0",
                "summary_delivery_email_to": "",
                "summary_delivery_webhook_enabled": "0",
                "summary_delivery_webhook_url": "",
                "summary_delivery_retry_limit": "3",
                "summary_delivery_retention_days": "90",
                "policy_history_retention_days": "365",
            }
            for key, value in defaults.items():
                db.execute(
                    "INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)",
                    (key, value),
                )

            incident_cols = {row["name"] for row in db.execute("PRAGMA table_info(incidents)")}
            if "suppress_until_clear" not in incident_cols:
                db.execute("ALTER TABLE incidents ADD COLUMN suppress_until_clear INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def _operations_now_iso():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _bounded_json(payload):
        return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"))

    def _assert_config_revision_db(self, db, expected_revision):
        row = db.execute(
            "SELECT revision FROM config_revision_state WHERE singleton=1"
        ).fetchone()
        current = int(row["revision"] if row else 0)
        if expected_revision is not None and int(expected_revision) != current:
            raise ConfigRevisionConflict(
                f"Configuration changed from revision {int(expected_revision)} to {current}; reload before saving"
            )
        return current

    def _advance_config_revision_db(
        self,
        db,
        *,
        actor="system:policy-store",
        reason="Configuration updated",
        scope="config",
        digest="",
    ):
        current = self._assert_config_revision_db(db, None)
        revision = current + 1
        now = self._operations_now_iso()
        actor = str(actor or "system:policy-store")[:100]
        reason = str(reason or "Configuration updated")[:240]
        scope = str(scope or "config")[:100]
        digest = str(digest or "")[:128]
        db.execute(
            """UPDATE config_revision_state
               SET revision=?, digest=?, updated_at=?, actor=?, reason=?
               WHERE singleton=1""",
            (revision, digest, now, actor, reason),
        )
        db.execute(
            """INSERT INTO config_revisions
               (revision, created_at, actor, reason, scope, digest)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (revision, now, actor, reason, scope, digest),
        )
        payload = {
            "revision": revision,
            "scope": scope,
            "reason": reason,
            "actor": actor,
        }
        db.execute(
            """INSERT INTO outbox_events
               (created_at, topic, aggregate_type, aggregate_key, revision, payload_json, status)
               VALUES (?, 'config.changed', 'configuration', 'global', ?, ?, 'pending')""",
            (now, revision, self._bounded_json(payload)),
        )
        return revision

    @contextmanager
    def config_write(
        self,
        *,
        actor="system:policy-store",
        reason="Configuration updated",
        scope="config",
        expected_revision=None,
    ):
        """Open one configuration transaction with optimistic concurrency.

        The application write, revision journal entry and outbox event commit in
        the same SQLite transaction. Existing call sites may omit
        ``expected_revision``; callers that present a revision gain stale-write
        rejection without introducing a second authority path.
        """
        with self._db() as db:
            self._assert_config_revision_db(db, expected_revision)
            yield db
            self._advance_config_revision_db(
                db,
                actor=actor,
                reason=reason,
                scope=scope,
            )

    def current_config_revision(self):
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM config_revision_state WHERE singleton=1"
            ).fetchone()
        return dict(row) if row else {
            "singleton": 1,
            "revision": 0,
            "digest": "",
            "updated_at": "",
            "actor": "",
            "reason": "",
        }

    def list_config_revisions(self, limit=50):
        limit = max(1, min(500, int(limit)))
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM config_revisions ORDER BY revision DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def ensure_config_revision_baseline(self, actor="system:startup"):
        current = self.current_config_revision()
        if int(current.get("revision") or 0) > 0:
            return current
        digest = self.config_digest()
        with self._db() as db:
            revision = self._assert_config_revision_db(db, None)
            if revision == 0:
                self._advance_config_revision_db(
                    db,
                    actor=actor,
                    reason="v0.54 revision journal baseline",
                    scope="bootstrap",
                    digest=digest,
                )
            else:
                db.execute(
                    "UPDATE config_revision_state SET digest=? WHERE singleton=1 AND digest=''",
                    (digest,),
                )
        return self.current_config_revision()

    def list_outbox_events(self, *, status=None, limit=100):
        limit = max(1, min(500, int(limit)))
        with self._db() as db:
            if status:
                rows = db.execute(
                    "SELECT * FROM outbox_events WHERE status=? ORDER BY id DESC LIMIT ?",
                    (str(status), limit),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM outbox_events ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["payload"] = json.loads(item.pop("payload_json"))
            except (json.JSONDecodeError, TypeError):
                item["payload"] = {}
            result.append(item)
        return result

    def enqueue_background_job(
        self,
        *,
        kind,
        scope,
        idempotency_key,
        payload=None,
        max_attempts=3,
        available_at=None,
        replace_pending=False,
    ):
        kind = str(kind or "").strip()[:100]
        scope = str(scope or "global").strip()[:160]
        idempotency_key = str(idempotency_key or "").strip()[:240]
        if not kind or not idempotency_key:
            raise ValueError("Background job kind and idempotency key are required")
        max_attempts = max(1, min(10, int(max_attempts)))
        now = self._operations_now_iso()
        available_at = str(available_at or now)
        with self._db() as db:
            if replace_pending:
                # Prepared analytics are derived state. Keep only the newest
                # pending job for a kind/scope so a slow refresh cycle cannot
                # build an ever-growing queue of obsolete time buckets. Running
                # work is never cancelled underneath its lease owner.
                db.execute(
                    """DELETE FROM background_jobs
                       WHERE kind=? AND scope=? AND status='pending'
                         AND idempotency_key<>?""",
                    (kind, scope, idempotency_key),
                )
            cur = db.execute(
                """INSERT OR IGNORE INTO background_jobs
                   (kind, scope, idempotency_key, payload_json, status, attempts,
                    max_attempts, available_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)""",
                (
                    kind,
                    scope,
                    idempotency_key,
                    self._bounded_json(payload),
                    max_attempts,
                    available_at,
                    now,
                    now,
                ),
            )
            row = db.execute(
                "SELECT * FROM background_jobs WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
        item = self._background_job_dict(row)
        if item is not None:
            item["created"] = bool(cur.rowcount)
        return item

    @staticmethod
    def _background_job_dict(row):
        if not row:
            return None
        item = dict(row)
        for source, target in (("payload_json", "payload"), ("result_json", "result")):
            try:
                item[target] = json.loads(item.pop(source))
            except (json.JSONDecodeError, TypeError):
                item[target] = {}
        return item

    def dispatch_outbox_to_background_jobs(self, limit=50):
        limit = max(1, min(500, int(limit)))
        now = self._operations_now_iso()
        dispatched = 0
        with self._db() as db:
            rows = db.execute(
                """SELECT * FROM outbox_events
                   WHERE status='pending' ORDER BY id LIMIT ?""",
                (limit,),
            ).fetchall()
            for row in rows:
                topic = str(row["topic"] or "")
                if topic != "config.changed":
                    db.execute(
                        "UPDATE outbox_events SET status='ignored', dispatched_at=? WHERE id=?",
                        (now, row["id"]),
                    )
                    continue
                revision = int(row["revision"] or 0)
                try:
                    payload = json.loads(row["payload_json"] or "{}")
                except json.JSONDecodeError:
                    payload = {}
                key = f"config-analytics:r{revision}"
                db.execute(
                    """INSERT OR IGNORE INTO background_jobs
                       (kind, scope, idempotency_key, payload_json, status, attempts,
                        max_attempts, available_at, created_at, updated_at)
                       VALUES ('analytics.config-summary', 'analytics:config', ?, ?, 'pending', 0, 3, ?, ?, ?)""",
                    (key, self._bounded_json(payload), now, now, now),
                )
                job = db.execute(
                    "SELECT id FROM background_jobs WHERE idempotency_key=?",
                    (key,),
                ).fetchone()
                db.execute(
                    """UPDATE outbox_events
                       SET status='dispatched', dispatched_at=?, background_job_id=?
                       WHERE id=?""",
                    (now, int(job["id"]), int(row["id"])),
                )
                dispatched += 1
        return dispatched

    def recover_expired_background_work(self):
        now = self._operations_now_iso()
        with self._db() as db:
            db.execute(
                "DELETE FROM background_scope_locks WHERE lease_expires_at<>'' AND lease_expires_at<=?",
                (now,),
            )
            cur = db.execute(
                """UPDATE background_jobs
                   SET status='pending', lease_owner='', lease_token='', lease_expires_at='',
                       available_at=?, updated_at=?, error='Recovered expired worker lease'
                   WHERE status='running' AND lease_expires_at<>'' AND lease_expires_at<=?
                     AND attempts < max_attempts""",
                (now, now, now),
            )
            db.execute(
                """UPDATE background_jobs
                   SET status='failed', finished_at=?, updated_at=?,
                       error=CASE WHEN error='' THEN 'Lease expired after maximum attempts' ELSE error END
                   WHERE status='running' AND lease_expires_at<>'' AND lease_expires_at<=?
                     AND attempts >= max_attempts""",
                (now, now, now),
            )
        return int(cur.rowcount or 0)

    def claim_background_job(self, *, worker_name, lease_seconds=30, kinds=()):
        worker_name = str(worker_name or "worker")[:80]
        lease_seconds = max(5, min(300, int(lease_seconds)))
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat(timespec="seconds")
        expires = (now_dt + timedelta(seconds=lease_seconds)).isoformat(timespec="seconds")
        token = uuid.uuid4().hex
        kinds = tuple(str(item) for item in kinds if str(item))
        kind_sql = ""
        params = [now]
        if kinds:
            kind_sql = " AND kind IN (" + ",".join("?" for _ in kinds) + ")"
            params.extend(kinds)
        with self._db() as db:
            row = db.execute(
                f"""UPDATE background_jobs
                    SET status='running', attempts=attempts+1, lease_owner=?, lease_token=?,
                        lease_expires_at=?, started_at=CASE WHEN started_at='' THEN ? ELSE started_at END,
                        updated_at=?
                    WHERE id=(
                        SELECT id FROM background_jobs
                        WHERE status='pending' AND available_at<=? AND attempts < max_attempts
                        {kind_sql}
                        ORDER BY id LIMIT 1
                    ) AND status='pending'
                    RETURNING *""",
                (worker_name, token, expires, now, now, *params),
            ).fetchone()
        return self._background_job_dict(row)

    @staticmethod
    def _reconciliation_request_dict(row):
        if not row:
            return None
        item = dict(row)
        try:
            item["result"] = json.loads(item.pop("result_json"))
        except (json.JSONDecodeError, TypeError):
            item["result"] = {}
        return item

    def enqueue_reconciliation_request(
        self, *, target="*", actor="system:reconciler", reason="Manual reconciliation requested", requested_revision=None
    ):
        """Durably request reconciliation without granting RouterOS authority.

        The row is intent/evidence only. AutoReconciler remains the sole consumer
        that may enter the serialized RouterOS mutation lane. Repeated pending
        requests for the same target are superseded so rapid UI actions converge
        on the latest desired state instead of replaying stale work.
        """
        target = str(target or "*").strip() or "*"
        if target != "*":
            ipaddress.ip_address(target)
        actor = str(actor or "system:reconciler")[:100]
        reason = str(reason or "Manual reconciliation requested")[:240]
        if requested_revision is None:
            requested_revision = int(self.current_config_revision().get("revision") or 0)
        requested_revision = max(0, int(requested_revision))
        now = self._operations_now_iso()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """UPDATE reconciliation_requests
                   SET status='superseded', finished_at=?, error='Superseded by newer request'
                   WHERE target=? AND status='pending'""",
                (now, target),
            )
            cur = db.execute(
                """INSERT INTO reconciliation_requests
                   (target, requested_revision, actor, reason, status, created_at)
                   VALUES (?, ?, ?, ?, 'pending', ?)""",
                (target, requested_revision, actor, reason, now),
            )
            row = db.execute(
                "SELECT * FROM reconciliation_requests WHERE id=?", (int(cur.lastrowid),)
            ).fetchone()
        return self._reconciliation_request_dict(row)

    def recover_reconciliation_requests(self):
        """Replay an interrupted request after restart using fresh reads.

        Router mutations are idempotently re-derived from current RouterOS and
        desired state; no pre-restart observation is promoted to authority.
        """
        now = self._operations_now_iso()
        with self._db() as db:
            cur = db.execute(
                """UPDATE reconciliation_requests
                   SET status='pending', started_at='', error='Recovered interrupted reconciliation'
                   WHERE status='running'"""
            )
        return int(cur.rowcount or 0)

    def claim_reconciliation_request(self):
        now = self._operations_now_iso()
        with self._db() as db:
            row = db.execute(
                """UPDATE reconciliation_requests
                   SET status='running', started_at=?, error=''
                   WHERE id=(
                       SELECT id FROM reconciliation_requests
                       WHERE status='pending' ORDER BY id LIMIT 1
                   ) AND status='pending'
                   RETURNING *""",
                (now,),
            ).fetchone()
        return self._reconciliation_request_dict(row)

    def finish_reconciliation_request(
        self, request_id, *, status, applied_revision=0, result=None, error=""
    ):
        status = str(status or "failed").strip().lower()
        if status not in {"succeeded", "partial", "temporary", "failed", "superseded"}:
            raise ValueError("Invalid reconciliation request status")
        now = self._operations_now_iso()
        with self._db() as db:
            cur = db.execute(
                """UPDATE reconciliation_requests
                   SET status=?, applied_revision=?, result_json=?, error=?, finished_at=?
                   WHERE id=? AND status='running'""",
                (
                    status, max(0, int(applied_revision or 0)), self._bounded_json(result),
                    str(error or "")[:500], now, int(request_id),
                ),
            )
            if cur.rowcount != 1:
                raise ValueError("Reconciliation request is no longer running")
            row = db.execute(
                "SELECT * FROM reconciliation_requests WHERE id=?", (int(request_id),)
            ).fetchone()
        return self._reconciliation_request_dict(row)

    def list_reconciliation_requests(self, limit=50):
        limit = max(1, min(500, int(limit)))
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM reconciliation_requests ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._reconciliation_request_dict(row) for row in rows]

    def reconciliation_request_stats(self):
        with self._db() as db:
            counts = {
                row["status"]: int(row["count"])
                for row in db.execute(
                    "SELECT status, COUNT(*) AS count FROM reconciliation_requests GROUP BY status"
                ).fetchall()
            }
            latest = db.execute(
                "SELECT * FROM reconciliation_requests ORDER BY id DESC LIMIT 1"
            ).fetchone()
            recent = db.execute(
                """SELECT created_at, started_at, finished_at, status
                   FROM reconciliation_requests
                   WHERE status IN ('succeeded','partial','temporary')
                     AND started_at<>'' AND finished_at<>''
                   ORDER BY id DESC LIMIT 100"""
            ).fetchall()

        def elapsed_ms(start, end):
            try:
                a = datetime.fromisoformat(str(start or ""))
                b = datetime.fromisoformat(str(end or ""))
                if a.tzinfo is None:
                    a = a.replace(tzinfo=timezone.utc)
                if b.tzinfo is None:
                    b = b.replace(tzinfo=timezone.utc)
                return max(0.0, (b - a).total_seconds() * 1000.0)
            except (TypeError, ValueError):
                return None

        def latency_stats(values):
            values = sorted(float(value) for value in values if value is not None)
            if not values:
                return {"count": 0, "min_ms": 0.0, "avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
            def percentile(p):
                if len(values) == 1:
                    return values[0]
                rank = (len(values) - 1) * p
                lower = int(rank)
                upper = min(lower + 1, len(values) - 1)
                fraction = rank - lower
                return values[lower] + (values[upper] - values[lower]) * fraction
            return {
                "count": len(values),
                "min_ms": round(values[0], 3),
                "avg_ms": round(sum(values) / len(values), 3),
                "p50_ms": round(percentile(0.50), 3),
                "p95_ms": round(percentile(0.95), 3),
                "max_ms": round(values[-1], 3),
            }

        queue_wait = [elapsed_ms(row["created_at"], row["started_at"]) for row in recent]
        processing = [elapsed_ms(row["started_at"], row["finished_at"]) for row in recent]
        convergence = [elapsed_ms(row["created_at"], row["finished_at"]) for row in recent]
        return {
            "schema": "zen_reconciliation_queue_v1",
            "counts": counts,
            "pending": int(counts.get("pending", 0)),
            "running": int(counts.get("running", 0)),
            "failed": int(counts.get("failed", 0)),
            "latest": self._reconciliation_request_dict(latest),
            "latency": {
                "queue_wait": latency_stats(queue_wait),
                "processing": latency_stats(processing),
                "convergence": latency_stats(convergence),
            },
        }

    def acquire_background_scope_lock(self, *, scope, owner, token, lease_seconds=30):
        scope = str(scope or "global")[:160]
        owner = str(owner or "worker")[:80]
        token = str(token or "")[:80]
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat(timespec="seconds")
        expires = (now_dt + timedelta(seconds=max(5, int(lease_seconds)))).isoformat(timespec="seconds")
        with self._db() as db:
            db.execute(
                "DELETE FROM background_scope_locks WHERE scope=? AND lease_expires_at<=?",
                (scope, now),
            )
            try:
                db.execute(
                    """INSERT INTO background_scope_locks
                       (scope, owner, token, lease_expires_at, updated_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (scope, owner, token, expires, now),
                )
                return True
            except sqlite3.IntegrityError:
                row = db.execute(
                    "SELECT owner, token FROM background_scope_locks WHERE scope=?",
                    (scope,),
                ).fetchone()
                return bool(row and row["owner"] == owner and row["token"] == token)

    def release_background_scope_lock(self, *, scope, owner, token):
        with self._db() as db:
            cur = db.execute(
                "DELETE FROM background_scope_locks WHERE scope=? AND owner=? AND token=?",
                (str(scope), str(owner), str(token)),
            )
        return cur.rowcount == 1

    def _update_background_job_with_lease(self, job_id, worker_name, lease_token, sql, values):
        with self._db() as db:
            cur = db.execute(
                sql,
                (*values, int(job_id), str(worker_name), str(lease_token)),
            )
            if cur.rowcount != 1:
                raise ValueError("Background job lease no longer belongs to this worker")

    def complete_background_job(self, job_id, *, worker_name, lease_token, result=None):
        now = self._operations_now_iso()
        self._update_background_job_with_lease(
            job_id,
            worker_name,
            lease_token,
            """UPDATE background_jobs
               SET status='succeeded', result_json=?, error='', finished_at=?, updated_at=?,
                   lease_owner='', lease_token='', lease_expires_at=''
               WHERE id=? AND status='running' AND lease_owner=? AND lease_token=?""",
            (self._bounded_json(result), now, now),
        )

    def fail_background_job(self, job_id, *, worker_name, lease_token, error):
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat(timespec="seconds")
        retry_at = (now_dt + timedelta(seconds=5)).isoformat(timespec="seconds")
        with self._db() as db:
            row = db.execute(
                """SELECT attempts, max_attempts FROM background_jobs
                   WHERE id=? AND status='running' AND lease_owner=? AND lease_token=?""",
                (int(job_id), str(worker_name), str(lease_token)),
            ).fetchone()
            if not row:
                raise ValueError("Background job lease no longer belongs to this worker")
            terminal = int(row["attempts"]) >= int(row["max_attempts"])
            db.execute(
                """UPDATE background_jobs
                   SET status=?, error=?, available_at=?, finished_at=?, updated_at=?,
                       lease_owner='', lease_token='', lease_expires_at=''
                   WHERE id=?""",
                (
                    "failed" if terminal else "pending",
                    str(error or "Background job failed")[:500],
                    retry_at,
                    now if terminal else "",
                    now,
                    int(job_id),
                ),
            )

    def defer_background_job(self, job_id, *, worker_name, lease_token, delay_seconds=1, reason="deferred"):
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat(timespec="seconds")
        available = (now_dt + timedelta(seconds=max(1, int(delay_seconds)))).isoformat(timespec="seconds")
        self._update_background_job_with_lease(
            job_id,
            worker_name,
            lease_token,
            """UPDATE background_jobs
               SET status='pending', attempts=CASE WHEN attempts>0 THEN attempts-1 ELSE 0 END, available_at=?, error=?, updated_at=?,
                   lease_owner='', lease_token='', lease_expires_at=''
               WHERE id=? AND status='running' AND lease_owner=? AND lease_token=?""",
            (available, str(reason or "deferred")[:240], now),
        )

    def list_background_jobs(self, limit=100):
        limit = max(1, min(500, int(limit)))
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM background_jobs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._background_job_dict(row) for row in rows]

    def record_background_worker_metrics(self, *, worker_name, cycle):
        now = self._operations_now_iso()
        with self._db() as db:
            existing = db.execute(
                "SELECT started_at FROM background_worker_metrics WHERE worker_name=?",
                (str(worker_name),),
            ).fetchone()
            started_at = str(existing["started_at"] or now) if existing else now
            db.execute(
                """INSERT INTO background_worker_metrics
                   (worker_name, started_at, heartbeat_at, cycles, jobs_claimed,
                    jobs_succeeded, jobs_failed, jobs_deferred, last_duration_ms,
                    last_result, last_error)
                   VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(worker_name) DO UPDATE SET
                     heartbeat_at=excluded.heartbeat_at,
                     cycles=background_worker_metrics.cycles+1,
                     jobs_claimed=background_worker_metrics.jobs_claimed+excluded.jobs_claimed,
                     jobs_succeeded=background_worker_metrics.jobs_succeeded+excluded.jobs_succeeded,
                     jobs_failed=background_worker_metrics.jobs_failed+excluded.jobs_failed,
                     jobs_deferred=background_worker_metrics.jobs_deferred+excluded.jobs_deferred,
                     last_duration_ms=excluded.last_duration_ms,
                     last_result=excluded.last_result,
                     last_error=excluded.last_error""",
                (
                    str(worker_name)[:80],
                    started_at,
                    now,
                    int(cycle.get("claimed") or 0),
                    int(cycle.get("succeeded") or 0),
                    int(cycle.get("failed") or 0),
                    int(cycle.get("deferred") or 0),
                    float(cycle.get("duration_ms") or 0.0),
                    str(cycle.get("result") or "")[:40],
                    str(cycle.get("last_error") or "")[:240],
                ),
            )

    def save_prepared_view(
        self,
        *,
        view_key,
        kind,
        scope='global',
        payload=None,
        source_revision=None,
        ttl_seconds=300,
        status='ready',
        error='',
    ):
        """Publish one bounded read-side prepared view.

        Prepared views are derived evidence only. They never carry write callbacks
        or RouterOS authority and are rejected by consumers when their configuration
        revision is stale. The row is replaced in place, so periodic refresh cannot
        create unbounded retained household data.
        """
        view_key = str(view_key or '').strip()[:240]
        kind = str(kind or '').strip()[:100]
        scope = str(scope or 'global').strip()[:160]
        if not view_key or not kind:
            raise ValueError('Prepared view key and kind are required')
        payload_json = self._bounded_json(payload)
        payload_bytes = len(payload_json.encode('utf-8'))
        if payload_bytes > 2_000_000:
            raise ValueError('Prepared view payload exceeds 2 MB safety limit')
        if source_revision is None:
            source_revision = int(self.current_config_revision().get('revision') or 0)
        ttl_seconds = max(15, min(86400, int(ttl_seconds)))
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat(timespec='seconds')
        expires = (now_dt + timedelta(seconds=ttl_seconds)).isoformat(timespec='seconds')
        with self._db() as db:
            db.execute(
                """INSERT INTO prepared_views
                   (view_key, kind, scope, source_revision, captured_at, expires_at,
                    payload_json, payload_bytes, generation, status, error, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                   ON CONFLICT(view_key) DO UPDATE SET
                     kind=excluded.kind, scope=excluded.scope,
                     source_revision=excluded.source_revision,
                     captured_at=excluded.captured_at, expires_at=excluded.expires_at,
                     payload_json=excluded.payload_json, payload_bytes=excluded.payload_bytes,
                     generation=prepared_views.generation+1,
                     status=excluded.status, error=excluded.error, updated_at=excluded.updated_at""",
                (
                    view_key, kind, scope, int(source_revision), now, expires,
                    payload_json, payload_bytes, str(status or 'ready')[:40],
                    str(error or '')[:500], now,
                ),
            )
        return self.get_prepared_view(view_key, include_stale=True)

    def get_prepared_view(
        self,
        view_key,
        *,
        required_revision=None,
        max_age_seconds=None,
        include_stale=False,
    ):
        """Return a prepared view only when its evidence is still eligible.

        Staleness is explicit. A configuration revision mismatch never silently
        serves old policy/service semantics, and expired evidence is withheld unless
        a diagnostics caller explicitly requests ``include_stale``.
        """
        with self._db() as db:
            row = db.execute(
                'SELECT * FROM prepared_views WHERE view_key=?',
                (str(view_key),),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            item['payload'] = json.loads(item.pop('payload_json'))
        except (json.JSONDecodeError, TypeError):
            item['payload'] = {}
            item['status'] = 'invalid'
        now = datetime.now(timezone.utc)
        try:
            captured = datetime.fromisoformat(str(item.get('captured_at') or ''))
            if captured.tzinfo is None:
                captured = captured.replace(tzinfo=timezone.utc)
            age_seconds = max(0.0, (now - captured.astimezone(timezone.utc)).total_seconds())
        except (TypeError, ValueError):
            age_seconds = None
        item['age_seconds'] = round(age_seconds, 3) if age_seconds is not None else None
        revision_stale = (
            required_revision is not None
            and int(item.get('source_revision') or 0) != int(required_revision)
        )
        expired = str(item.get('expires_at') or '') <= now.isoformat(timespec='seconds')
        too_old = (
            max_age_seconds is not None
            and age_seconds is not None
            and age_seconds > max(1, int(max_age_seconds))
        )
        item['eligible'] = bool(
            str(item.get('status') or '') == 'ready'
            and not revision_stale
            and not expired
            and not too_old
        )
        item['revision_stale'] = revision_stale
        item['expired'] = expired
        item['too_old'] = too_old
        if not item['eligible'] and not include_stale:
            return None
        return item

    def list_prepared_views(self, limit=100):
        limit = max(1, min(500, int(limit)))
        with self._db() as db:
            rows = db.execute(
                """SELECT view_key, kind, scope, source_revision, captured_at,
                          expires_at, payload_bytes, generation, status, error, updated_at
                   FROM prepared_views ORDER BY updated_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def prune_background_history(self, *, retention_days=14, keep_jobs=200, keep_outbox=200):
        """Bound durable worker bookkeeping without touching active work.

        Only terminal jobs and already-dispatched/ignored outbox rows are eligible,
        and the newest bounded floor is always retained even if older than the age
        threshold. Prepared views are single-row upserts and therefore need no
        destructive data-retention pass.
        """
        retention_days = max(1, min(365, int(retention_days)))
        keep_jobs = max(20, min(5000, int(keep_jobs)))
        keep_outbox = max(20, min(5000, int(keep_outbox)))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(timespec='seconds')
        with self._db() as db:
            cur_jobs = db.execute(
                """DELETE FROM background_jobs
                   WHERE status IN ('succeeded','failed') AND updated_at<?
                     AND id NOT IN (SELECT id FROM background_jobs WHERE status IN ('succeeded','failed') ORDER BY id DESC LIMIT ?)""",
                (cutoff, keep_jobs),
            )
            cur_outbox = db.execute(
                """DELETE FROM outbox_events
                   WHERE status IN ('dispatched','ignored') AND created_at<?
                     AND id NOT IN (SELECT id FROM outbox_events WHERE status IN ('dispatched','ignored') ORDER BY id DESC LIMIT ?)""",
                (cutoff, keep_outbox),
            )
        return {
            'jobs_deleted': int(cur_jobs.rowcount or 0),
            'outbox_deleted': int(cur_outbox.rowcount or 0),
            'retention_days': retention_days,
            'keep_jobs': keep_jobs,
            'keep_outbox': keep_outbox,
        }

    def background_work_stats(self):
        with self._db() as db:
            jobs = {
                row["status"]: int(row["count"])
                for row in db.execute(
                    "SELECT status, COUNT(*) AS count FROM background_jobs GROUP BY status"
                ).fetchall()
            }
            outbox = {
                row["status"]: int(row["count"])
                for row in db.execute(
                    "SELECT status, COUNT(*) AS count FROM outbox_events GROUP BY status"
                ).fetchall()
            }
            locks = int(db.execute("SELECT COUNT(*) FROM background_scope_locks").fetchone()[0])
            metrics = [dict(row) for row in db.execute(
                "SELECT * FROM background_worker_metrics ORDER BY worker_name"
            ).fetchall()]
            prepared = db.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(payload_bytes),0) AS bytes FROM prepared_views"
            ).fetchone()
        return {
            "available": True,
            "revision": self.current_config_revision(),
            "jobs": jobs,
            "outbox": outbox,
            "scope_locks": locks,
            "workers": metrics,
            "prepared_views": {
                "count": int(prepared["count"] or 0),
                "payload_bytes": int(prepared["bytes"] or 0),
            },
        }

    def build_config_analytics_snapshot(self):
        """Read-only local analytics used by the first v0.54 background job."""
        with self._db() as db:
            counts = {}
            for table in (
                "profiles", "device_policy", "services", "schedule_plans",
                "aggregate_policy_groups", "incidents",
            ):
                counts[table] = int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            modes = {
                row["mode_override"]: int(row["count"])
                for row in db.execute(
                    "SELECT mode_override, COUNT(*) AS count FROM device_policy GROUP BY mode_override"
                ).fetchall()
            }
        return {
            "schema": "zen_config_analytics_v1",
            "captured_at": self._operations_now_iso(),
            "revision": int(self.current_config_revision().get("revision") or 0),
            "counts": counts,
            "device_mode_overrides": modes,
            "authority": "read-only-local",
        }

    @staticmethod
    def _policy_history_instant_iso(value):
        """Normalize a policy-history boundary to one comparable UTC TEXT form."""
        if isinstance(value, datetime):
            observed = value
        else:
            observed = datetime.fromisoformat(str(value))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        return observed.astimezone(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _policy_history_state(policy):
        policy = dict(policy or {})
        quota = dict(policy.get("quota_state") or {})
        daily = dict(quota.get("daily") or {})
        # Keep only durable decision evidence.  Large usage detail is unnecessary
        # for policy identity and remains in PostgreSQL telemetry.
        quota_summary = {
            "configured": bool(quota.get("configured")),
            "enabled": bool(quota.get("enabled")),
            "available": bool(quota.get("available", True)),
            "active": bool(quota.get("active")),
            "mode_active": bool(quota.get("mode_active")),
            "service_active": bool(quota.get("service_active")),
            "active_service_blocks": sorted(quota.get("active_service_blocks") or []),
            "daily_exhausted": bool(daily.get("exhausted")),
            "daily_action": str(daily.get("action") or ""),
        }
        return {
            "desired_mode": str(policy.get("mode") or "normal"),
            "mode_source": str(policy.get("mode_source") or "default"),
            "bandwidth_preset": str(policy.get("bandwidth_preset") or "normal"),
            "blocked_services": sorted(str(item) for item in (policy.get("blocked_services") or [])),
            "policy_groups": sorted(str(item) for item in (policy.get("blocked_policy_groups") or [])),
            "schedule_active": bool(policy.get("schedule_active")),
            "schedule_reason": str(policy.get("schedule_reason") or ""),
            "active_date_exception": dict(policy.get("active_date_exception") or {}),
            "quota_state": quota_summary,
            "policy_at": str(policy.get("policy_at") or ""),
        }

    def record_policy_state(self, ip, policy, source="effective-resolver", captured_at=None):
        """Record durable desired-policy evidence for the current management epoch.

        A new checkpoint is written when either the desired-policy state changes
        or the retained display name changes. Name-only checkpoints keep the same
        state hash, so correlation can preserve historical naming without
        pretending the policy itself changed.
        """
        ip = str(ip or "").strip()
        ipaddress.ip_address(ip)
        state = self._policy_history_state(policy)
        state_identity = {key: value for key, value in state.items() if key != "policy_at"}
        canonical = self._canonical_json(state_identity)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        captured_at = self._policy_history_instant_iso(
            captured_at or self._operations_now_iso()
        )
        source = str(source or "effective-resolver")[:80]

        with self._db() as db:
            managed = db.execute(
                "SELECT * FROM managed_device_identity WHERE ip=?", (ip,)
            ).fetchone()
            identity_id = str(managed["identity_id"]) if managed else ""
            device_name = (
                str(managed["current_name"] or "").strip()
                if managed else ip
            ) or ip

            previous = db.execute(
                """SELECT state_hash, device_name
                   FROM policy_state_history
                   WHERE ip=? AND identity_id=?
                   ORDER BY captured_at DESC, id DESC LIMIT 1""",
                (ip, identity_id),
            ).fetchone()
            if (
                previous
                and previous["state_hash"] == digest
                and str(previous["device_name"] or ip) == device_name
            ):
                return {
                    "created": False,
                    "state_hash": digest,
                    "identity_id": identity_id,
                }

            cur = db.execute(
                """INSERT INTO policy_state_history
                   (captured_at, ip, state_hash, source, desired_mode, mode_source,
                    bandwidth_preset, blocked_services, policy_groups,
                    schedule_active, schedule_reason, active_date_exception,
                    quota_state, policy_at, identity_id, device_name)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    captured_at, ip, digest, source, state["desired_mode"],
                    state["mode_source"], state["bandwidth_preset"],
                    json.dumps(state["blocked_services"]),
                    json.dumps(state["policy_groups"]),
                    1 if state["schedule_active"] else 0,
                    state["schedule_reason"],
                    json.dumps(state["active_date_exception"]),
                    json.dumps(state["quota_state"]), state["policy_at"],
                    identity_id, device_name,
                ),
            )
            setting = db.execute(
                "SELECT value FROM app_settings WHERE key='policy_history_retention_days'"
            ).fetchone()
            try:
                retention = max(
                    30,
                    min(int(setting["value"] if setting else "365"), 3650),
                )
            except (TypeError, ValueError):
                retention = 365
            cutoff = (
                datetime.now(timezone.utc) - timedelta(days=retention)
            ).isoformat(timespec="seconds")
            db.execute(
                "DELETE FROM policy_state_history WHERE captured_at < ?", (cutoff,)
            )
        return {
            "created": True,
            "id": cur.lastrowid,
            "state_hash": digest,
            "identity_id": identity_id,
        }

    def list_policy_state_history(
        self, ip, start=None, end=None, limit=500, identity_id=None
    ):
        ip = str(ip or "").strip()
        ipaddress.ip_address(ip)
        limit = max(1, min(int(limit), 2000))
        clauses = ["ip=?"]
        params = [ip]

        if identity_id is not None:
            clauses.append("identity_id=?")
            params.append(str(identity_id))

        start_value = self._policy_history_instant_iso(start) if start else None
        end_value = self._policy_history_instant_iso(end) if end else None
        if start_value:
            clauses.append("captured_at > ?")
            params.append(start_value)
        if end_value:
            clauses.append("captured_at < ?")
            params.append(end_value)

        where = " AND ".join(clauses)
        with self._db() as db:
            rows = db.execute(
                f"""SELECT * FROM policy_state_history WHERE {where}
                    ORDER BY captured_at ASC, id ASC LIMIT ?""",
                (*params, limit),
            ).fetchall()
            if start_value:
                previous_clauses = ["ip=?", "captured_at <= ?"]
                previous_params = [ip, start_value]
                if identity_id is not None:
                    previous_clauses.append("identity_id=?")
                    previous_params.append(str(identity_id))
                previous = db.execute(
                    f"""SELECT * FROM policy_state_history
                        WHERE {' AND '.join(previous_clauses)}
                        ORDER BY captured_at DESC, id DESC LIMIT 1""",
                    tuple(previous_params),
                ).fetchone()
            else:
                previous = None

        result = []
        if previous:
            result.append(dict(previous))
        seen = {int(item["id"]) for item in result}
        for row in rows:
            if int(row["id"]) not in seen:
                result.append(dict(row))
        result.sort(
            key=lambda item: (
                self._policy_history_instant_iso(item["captured_at"]),
                item["id"],
            )
        )
        for item in result:
            item["blocked_services"] = json.loads(
                item.get("blocked_services") or "[]"
            )
            item["policy_groups"] = json.loads(
                item.get("policy_groups") or "[]"
            )
            item["schedule_active"] = bool(item.get("schedule_active"))
            item["active_date_exception"] = json.loads(
                item.get("active_date_exception") or "{}"
            )
            item["quota_state"] = json.loads(item.get("quota_state") or "{}")
        return result

    def policy_history_stats(self):
        with self._db() as db:
            row = db.execute(
                """SELECT COUNT(*) AS checkpoints,
                          COUNT(DISTINCT ip) AS addresses,
                          COUNT(DISTINCT NULLIF(identity_id,'')) AS identities,
                          MIN(captured_at) AS first_checkpoint,
                          MAX(captured_at) AS last_checkpoint
                   FROM policy_state_history"""
            ).fetchone()
        if not row:
            return {
                "checkpoints": 0,
                "devices": 0,
                "addresses": 0,
                "identities": 0,
                "first_checkpoint": None,
                "last_checkpoint": None,
            }
        result = dict(row)
        # Retain the historical public key while making its IP-address meaning
        # explicit for newer callers.
        result["devices"] = result.get("addresses", 0)
        return result

    def append_audit(self, event, actor, detail="", severity="info"):
        event = str(event or "UNKNOWN").strip()[:80] or "UNKNOWN"
        actor = str(actor or "system").strip()[:100] or "system"
        detail = str(detail or "")[:2000]
        severity = str(severity or "info").strip().lower()
        if severity not in {"info", "warning", "error", "critical"}:
            severity = "info"
        created_at = self._operations_now_iso()
        with self._db() as db:
            cur = db.execute(
                """INSERT INTO audit_log
                   (created_at, event, actor, detail, severity)
                   VALUES (?, ?, ?, ?, ?)""",
                (created_at, event, actor, detail, severity),
            )
            setting = db.execute(
                "SELECT value FROM app_settings WHERE key='audit_retention_events'"
            ).fetchone()
            try:
                retention = int(setting["value"] if setting else "5000")
            except (TypeError, ValueError):
                retention = 5000
            retention = max(500, min(retention, 50000))
            db.execute(
                """DELETE FROM audit_log
                   WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)""",
                (retention,),
            )
            audit_id = cur.lastrowid
        return {
            "id": audit_id,
            "ts": created_at,
            "event": event,
            "user": actor,
            "actor": actor,
            "detail": detail,
            "severity": severity,
        }

    def list_audit(self, limit=100):
        try:
            limit = max(1, min(int(limit), 1000))
        except (TypeError, ValueError):
            limit = 100
        with self._db() as db:
            rows = db.execute(
                """SELECT id, created_at, event, actor, detail, severity
                   FROM audit_log ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "ts": row["created_at"],
                "event": row["event"],
                "user": row["actor"],
                "actor": row["actor"],
                "detail": row["detail"],
                "severity": row["severity"],
            }
            for row in rows
        ]

    def audit_count(self):
        with self._db() as db:
            row = db.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()
        return int(row["c"] if row else 0)

    @staticmethod
    def _canonical_json(payload):
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _semantic_config_payload(payload):
        """Normalize exported config so database-local IDs do not define identity.

        Restore/import legitimately recreates AUTOINCREMENT IDs. The semantic
        digest therefore hashes semantic policy identity (names, device IPs and settings) rather
        than transient SQLite row numbers.
        """
        data = json.loads(json.dumps(payload))
        profiles = data.get("profiles", []) or []
        profile_names = {str(item.get("id")): item.get("name") for item in profiles}
        templates = data.get("schedule_templates", []) or []
        template_names = {str(item.get("id")): item.get("name") for item in templates}

        for item in profiles:
            item.pop("id", None)
        profiles.sort(key=lambda item: str(item.get("name", "")).lower())

        for item in data.get("device_policy", []) or []:
            pid = item.pop("profile_id", None)
            if not item.get("profile_name") and pid not in (None, ""):
                item["profile_name"] = profile_names.get(str(pid))
        (data.get("device_policy", []) or []).sort(key=lambda item: str(item.get("ip", "")))

        for section, key in (
            ("policy_templates", "name"),
            ("service_groups", "name"),
            ("aggregate_policy_groups", "name"),
            ("schedule_templates", "name"),
        ):
            for item in data.get(section, []) or []:
                item.pop("id", None)
                if section == "aggregate_policy_groups":
                    # Storage/audit metadata and derived presentation fields are
                    # not configuration identity. Restore legitimately recreates
                    # these values at a different wall-clock time.
                    item.pop("created_at", None)
                    item.pop("updated_at", None)
                    item.pop("member_names", None)
            (data.get(section, []) or []).sort(key=lambda item: str(item.get(key, "")).lower())

        for item in data.get("services", []) or []:
            # Approval state is semantic; the timestamp recording when that state
            # was written is operational metadata and may change during restore.
            item.pop("enforcement_approved_at", None)

        for item in data.get("schedule_plans", []) or []:
            item.pop("id", None)
            if item.get("target_type") == "profile":
                item["target_value"] = profile_names.get(
                    str(item.get("target_value")), item.get("target_value")
                )
        (data.get("schedule_plans", []) or []).sort(
            key=lambda item: (str(item.get("clock_time", "")), str(item.get("label", "")).lower())
        )

        for item in data.get("date_exceptions", []) or []:
            item.pop("id", None)
            if item.get("target_type") == "profile":
                item["target_value"] = profile_names.get(
                    str(item.get("target_value")), item.get("target_value")
                )
            tid = item.pop("template_id", None)
            if not item.get("template_name") and tid not in (None, ""):
                item["template_name"] = template_names.get(str(tid))
        (data.get("date_exceptions", []) or []).sort(
            key=lambda item: (str(item.get("start_date", "")), str(item.get("label", "")).lower())
        )

        for section, key in (("bandwidth_presets", "key"), ("services", "key")):
            (data.get(section, []) or []).sort(key=lambda item: str(item.get(key, "")))

        settings = data.get("app_settings") or {}
        default_profile_id = settings.get("default_profile_id")
        if default_profile_id not in (None, ""):
            settings["default_profile_id"] = profile_names.get(
                str(default_profile_id), str(default_profile_id)
            )
        return data

    def config_digest(self, payload=None):
        if payload is None:
            payload = self.export_config()
        semantic = self._semantic_config_payload(payload)
        canonical = self._canonical_json(semantic).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _incident_now_iso():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _incident_severity(value):
        value = str(value or "warning").strip().lower()
        if value not in {"info", "warning", "critical"}:
            value = "warning"
        return value

    @staticmethod
    def _incident_row(row):
        return dict(row) if row is not None else None

    def upsert_incident(
        self,
        *,
        fingerprint,
        source,
        severity,
        title,
        detail="",
        subject="",
        actor="system:incident-monitor",
    ):
        fingerprint = str(fingerprint or "").strip()[:240]
        source = str(source or "unknown").strip()[:120] or "unknown"
        subject = str(subject or "").strip()[:160]
        severity = self._incident_severity(severity)
        title = str(title or "Incident").strip()[:200] or "Incident"
        detail = str(detail or "").strip()[:3000]
        if not fingerprint:
            raise ValueError("Incident fingerprint is required")
        now = self._incident_now_iso()

        with self._db() as db:
            row = db.execute(
                "SELECT * FROM incidents WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                cur = db.execute(
                    """INSERT INTO incidents
                       (fingerprint, source, subject, severity, status, title, detail,
                        opened_at, first_seen_at, last_seen_at, updated_at, occurrences)
                       VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, 1)""",
                    (fingerprint, source, subject, severity, title, detail, now, now, now, now),
                )
                incident_id = cur.lastrowid
                action = "opened"
            else:
                incident_id = row["id"]
                prior_status = row["status"]
                prior_severity = row["severity"]
                changed = (
                    prior_severity != severity
                    or row["title"] != title
                    or row["detail"] != detail
                    or row["subject"] != subject
                    or row["source"] != source
                )
                if prior_status == "resolved":
                    if int(row["suppress_until_clear"] or 0):
                        db.execute(
                            """UPDATE incidents
                               SET source=?, subject=?, severity=?, title=?, detail=?,
                                   last_seen_at=?, updated_at=?, occurrences=occurrences+1
                               WHERE id=?""",
                            (source, subject, severity, title, detail, now, now, incident_id),
                        )
                        action = "suppressed"
                    else:
                        db.execute(
                            """UPDATE incidents
                               SET source=?, subject=?, severity=?, status='open', title=?, detail=?,
                                   opened_at=?, last_seen_at=?, updated_at=?, occurrences=occurrences+1,
                                   acknowledged_at=NULL, acknowledged_by='', resolved_at=NULL,
                                   resolved_by='', resolution='', suppress_until_clear=0
                               WHERE id=?""",
                            (source, subject, severity, title, detail, now, now, now, incident_id),
                        )
                        action = "reopened"
                else:
                    db.execute(
                        """UPDATE incidents
                           SET source=?, subject=?, severity=?, title=?, detail=?,
                               last_seen_at=?, updated_at=?, occurrences=occurrences+1
                           WHERE id=?""",
                        (source, subject, severity, title, detail, now, now, incident_id),
                    )
                    action = "severity_changed" if prior_severity != severity else ("updated" if changed else "unchanged")

            result = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()

            setting = db.execute(
                "SELECT value FROM app_settings WHERE key='incident_retention_days'"
            ).fetchone()
            try:
                retention_days = int(setting["value"] if setting else "30")
            except (TypeError, ValueError):
                retention_days = 30
            retention_days = max(7, min(retention_days, 365))
            db.execute(
                """DELETE FROM incidents
                   WHERE status='resolved'
                     AND resolved_at IS NOT NULL
                     AND datetime(resolved_at) < datetime('now', ?)""",
                (f"-{retention_days} days",),
            )

        return {**dict(result), "action": action}

    def list_incidents(self, *, include_resolved=False, limit=100):
        try:
            limit = max(1, min(int(limit), 500))
        except (TypeError, ValueError):
            limit = 100
        where = "" if include_resolved else "WHERE status <> 'resolved'"
        with self._db() as db:
            rows = db.execute(
                f"""SELECT * FROM incidents {where}
                    ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                             CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,
                             updated_at DESC, id DESC
                    LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_incident(self, incident_id):
        with self._db() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (int(incident_id),)).fetchone()
        return self._incident_row(row)

    def incident_counts(self):
        with self._db() as db:
            rows = db.execute(
                """SELECT status, severity, count(*) AS n
                   FROM incidents GROUP BY status, severity"""
            ).fetchall()
        result = {
            "active": 0,
            "open": 0,
            "acknowledged": 0,
            "resolved": 0,
            "critical": 0,
            "warning": 0,
            "info": 0,
        }
        for row in rows:
            status = row["status"]
            severity = row["severity"]
            count = int(row["n"] or 0)
            result[status] = result.get(status, 0) + count
            if status != "resolved":
                result["active"] += count
                result[severity] = result.get(severity, 0) + count
        return result

    def acknowledge_incident(self, incident_id, actor):
        incident_id = int(incident_id)
        actor = str(actor or "unknown").strip()[:100]
        now = self._incident_now_iso()
        with self._db() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                raise ValueError("Incident does not exist")
            if row["status"] == "resolved":
                raise ValueError("Resolved incidents cannot be acknowledged")
            db.execute(
                """UPDATE incidents SET status='acknowledged', acknowledged_at=?,
                   acknowledged_by=?, updated_at=? WHERE id=?""",
                (now, actor, now, incident_id),
            )
            result = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return dict(result)

    def resolve_incident(self, incident_id, actor, resolution="Resolved by operator", suppress_until_clear=True):
        incident_id = int(incident_id)
        actor = str(actor or "unknown").strip()[:100]
        resolution = str(resolution or "Resolved by operator").strip()[:500]
        suppress_value = 1 if suppress_until_clear else 0
        now = self._incident_now_iso()
        with self._db() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                raise ValueError("Incident does not exist")
            db.execute(
                """UPDATE incidents SET status='resolved', resolved_at=?, resolved_by=?,
                   resolution=?, suppress_until_clear=?, updated_at=? WHERE id=?""",
                (now, actor, resolution, suppress_value, now, incident_id),
            )
            result = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return dict(result)

    def resolve_inactive_incidents(self, source, active_fingerprints, actor="system:incident-monitor"):
        source = str(source or "").strip()[:120]
        active = {str(item) for item in (active_fingerprints or set())}
        if not source:
            return []
        now = self._incident_now_iso()
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM incidents WHERE source=?",
                (source,),
            ).fetchall()
            resolved = []
            for row in rows:
                if row["fingerprint"] in active:
                    continue
                if row["status"] != "resolved":
                    db.execute(
                        """UPDATE incidents SET status='resolved', resolved_at=?, resolved_by=?,
                           resolution='Signal cleared by successful incident scan',
                           suppress_until_clear=0, updated_at=?
                           WHERE id=?""",
                        (now, actor, now, row["id"]),
                    )
                    resolved.append({**dict(row), "status": "resolved", "resolved_at": now})
                elif int(row["suppress_until_clear"] or 0):
                    db.execute(
                        "UPDATE incidents SET suppress_until_clear=0, updated_at=? WHERE id=?",
                        (now, row["id"]),
                    )
        return resolved

    def save_incident_settings(
        self,
        enabled="1",
        interval_seconds="60",
        bypass_min_status="elevated",
        retention_days="30",
        *,
        expected_revision=None,
        actor="system:policy-store",
    ):
        enabled = "1" if str(enabled).strip().lower() in {"1", "true", "yes", "on"} else "0"
        interval = str(interval_seconds or "60").strip()
        if interval not in {"30", "60", "120", "300"}:
            raise ValueError("Incident scan interval must be 30, 60, 120 or 300 seconds")
        bypass_min_status = str(bypass_min_status or "elevated").strip().lower()
        if bypass_min_status not in {"watch", "elevated", "high"}:
            raise ValueError("Bypass incident threshold must be watch, elevated or high")
        try:
            retention = int(retention_days)
        except (TypeError, ValueError) as exc:
            raise ValueError("Incident retention must be a whole number of days") from exc
        if retention not in {7, 14, 30, 60, 90, 180, 365}:
            raise ValueError("Incident retention must be 7, 14, 30, 60, 90, 180 or 365 days")
        values = {
            "incident_monitor_enabled": enabled,
            "incident_scan_interval_seconds": interval,
            "incident_bypass_min_status": bypass_min_status,
            "incident_retention_days": str(retention),
        }
        with self.config_write(
            scope="settings:incidents",
            reason="Incident settings updated",
            actor=actor,
            expected_revision=expected_revision,
        ) as db:
            for key, value in values.items():
                db.execute(
                    """INSERT INTO app_settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (key, value),
                )
        return values

    def create_config_snapshot(self, actor="system", reason="Manual snapshot", force=True):
        payload = self.export_config()
        canonical = self._canonical_json(payload)
        digest = self.config_digest(payload)
        actor = str(actor or "system")[:100]
        reason = str(reason or "Configuration snapshot")[:240]
        created_at = self._operations_now_iso()
        with self._db() as db:
            latest = db.execute(
                """SELECT id, created_at, actor, reason, sha256
                   FROM config_snapshots ORDER BY id DESC LIMIT 1"""
            ).fetchone()
            if latest and latest["sha256"] == digest and not force:
                return {
                    "id": latest["id"],
                    "created_at": latest["created_at"],
                    "actor": latest["actor"],
                    "reason": latest["reason"],
                    "sha256": latest["sha256"],
                    "created": False,
                    "unchanged": True,
                }
            cur = db.execute(
                """INSERT INTO config_snapshots
                   (created_at, actor, reason, sha256, payload)
                   VALUES (?, ?, ?, ?, ?)""",
                (created_at, actor, reason, digest, canonical),
            )
            setting = db.execute(
                "SELECT value FROM app_settings WHERE key='snapshot_retention_count'"
            ).fetchone()
            try:
                retention = int(setting["value"] if setting else "30")
            except (TypeError, ValueError):
                retention = 30
            retention = max(5, min(retention, 200))
            db.execute(
                """DELETE FROM config_snapshots
                   WHERE id NOT IN (SELECT id FROM config_snapshots ORDER BY id DESC LIMIT ?)""",
                (retention,),
            )
            snapshot_id = cur.lastrowid
        return {
            "id": snapshot_id,
            "created_at": created_at,
            "actor": actor,
            "reason": reason,
            "sha256": digest,
            "created": True,
            "unchanged": False,
        }

    def list_config_snapshots(self, limit=20):
        try:
            limit = max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            limit = 20
        with self._db() as db:
            rows = db.execute(
                """SELECT id, created_at, actor, reason, sha256, length(payload) AS payload_bytes
                   FROM config_snapshots ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_config_snapshot(self, snapshot_id, include_payload=False):
        try:
            snapshot_id = int(snapshot_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid configuration snapshot id") from exc
        with self._db() as db:
            row = db.execute(
                """SELECT id, created_at, actor, reason, sha256, payload
                   FROM config_snapshots WHERE id=?""",
                (snapshot_id,),
            ).fetchone()
        if not row:
            raise ValueError("Configuration snapshot not found")
        result = {
            "id": row["id"],
            "created_at": row["created_at"],
            "actor": row["actor"],
            "reason": row["reason"],
            "sha256": row["sha256"],
            "payload_bytes": len(row["payload"].encode("utf-8")),
        }
        if include_payload:
            result["payload"] = json.loads(row["payload"])
        return result

    def restore_config_snapshot(self, snapshot_id, actor="system"):
        snapshot = self.get_config_snapshot(snapshot_id, include_payload=True)
        safety = self.create_config_snapshot(
            actor, f"Automatic pre-restore safety snapshot before #{snapshot['id']}", force=True
        )
        self.import_config(snapshot["payload"])
        restored_digest = self.config_digest()
        if restored_digest != snapshot["sha256"]:
            raise ValueError(
                "Configuration snapshot restore completed but digest verification failed"
            )
        return {
            "restored": snapshot["id"],
            "sha256": restored_digest,
            "safety_snapshot": safety["id"],
        }

    def database_integrity_report(self):
        required = {
            "profiles", "device_policy", "policy_templates", "bandwidth_presets",
            "services", "schedule_plans", "service_groups", "aggregate_policy_groups", "schedule_templates",
            "date_exceptions", "app_settings", "reward_accounts", "reward_ledger",
            "reward_redemptions", "discovery_cache", "audit_log", "config_snapshots",
            "summary_deliveries", "policy_state_history", "managed_device_identity",
            "config_revision_state", "config_revisions", "outbox_events",
            "background_jobs", "background_scope_locks", "background_worker_metrics",
            "prepared_views", "reconciliation_requests",
        }
        try:
            with sqlite3.connect(self.path, timeout=5.0) as db:
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA busy_timeout=5000")
                quick = [row[0] for row in db.execute("PRAGMA quick_check").fetchall()]
                tables = {
                    row[0] for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                missing = sorted(required - tables)
                counts = {}
                for table in sorted(required & tables):
                    counts[table] = int(
                        db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                    )
            ok = quick == ["ok"] and not missing
            return {
                "ok": ok,
                "quick_check": quick,
                "missing_tables": missing,
                "table_counts": counts,
                "path": self.path,
                "size_bytes": os.path.getsize(self.path) if os.path.exists(self.path) else 0,
            }
        except Exception as exc:
            return {
                "ok": False,
                "quick_check": [],
                "missing_tables": sorted(required),
                "table_counts": {},
                "path": self.path,
                "size_bytes": os.path.getsize(self.path) if os.path.exists(self.path) else 0,
                "error": str(exc),
            }

    @staticmethod
    def _validate_mode(mode: str, allow_inherit=False):
        allowed = {"normal", "slow", "blocked"}
        if allow_inherit:
            allowed.add("inherit")
        if mode not in allowed:
            raise ValueError("Invalid desired mode")
        return mode

    def _validate_services(self, values):
        allowed = {item["key"] for item in self.list_services()} | set(self.policy_group_keys())
        return sorted({str(v).strip().lower() for v in values if str(v).strip().lower() in allowed})

    def _validate_preset(self, value):
        if not any(p["key"] == value for p in self.list_bandwidth_presets()):
            raise ValueError("Invalid bandwidth preset")
        return value

    def list_profiles(self):
        with self._db() as db:
            rows = db.execute("SELECT * FROM profiles ORDER BY name COLLATE NOCASE").fetchall()
        return [self._profile_dict(row) for row in rows]

    def get_profile(self, profile_id: int):
        with self._db() as db:
            row = db.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        return self._profile_dict(row) if row else None

    def create_profile(
        self,
        name,
        desired_mode,
        bandwidth_preset,
        notes="",
        blocked_services=(),
        daily_quota_mb=0,
        daily_quota_action="blocked",
        service_quotas=None,
    ):
        name = name.strip()
        if not name or len(name) > 50:
            raise ValueError("Profile name must be 1-50 characters")
        desired_mode = self._validate_mode(desired_mode)
        bandwidth_preset = self._validate_preset(bandwidth_preset)
        blocked = self._validate_services(blocked_services)
        daily_quota_mb = normalize_quota_mb(daily_quota_mb, field="Daily data quota")
        daily_quota_action = normalize_quota_action(daily_quota_action)
        service_quotas = normalize_service_quotas(
            service_quotas or {}, supported_service_keys=self.routeros_supported_service_keys() | self.policy_group_keys()
        )
        with self.config_write(scope="profiles", reason="Profile created") as db:
            try:
                cur = db.execute(
                    """INSERT INTO profiles
                       (name, desired_mode, bandwidth_preset, notes, blocked_services,
                        daily_quota_mb, daily_quota_action, service_quotas)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        name, desired_mode, bandwidth_preset, notes.strip()[:250],
                        json.dumps(blocked), daily_quota_mb, daily_quota_action,
                        json.dumps(service_quotas, sort_keys=True),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A profile with that name already exists") from exc
        return self.get_profile(cur.lastrowid)

    def update_profile(
        self,
        profile_id,
        name,
        desired_mode,
        bandwidth_preset,
        notes="",
        blocked_services=(),
        daily_quota_mb=0,
        daily_quota_action="blocked",
        service_quotas=None,
    ):
        name = name.strip()
        if not name or len(name) > 50:
            raise ValueError("Profile name must be 1-50 characters")
        desired_mode = self._validate_mode(desired_mode)
        bandwidth_preset = self._validate_preset(bandwidth_preset)
        blocked = self._validate_services(blocked_services)
        daily_quota_mb = normalize_quota_mb(daily_quota_mb, field="Daily data quota")
        daily_quota_action = normalize_quota_action(daily_quota_action)
        service_quotas = normalize_service_quotas(
            service_quotas or {}, supported_service_keys=self.routeros_supported_service_keys() | self.policy_group_keys()
        )
        with self.config_write(scope="profiles", reason="Profile updated") as db:
            try:
                cur = db.execute(
                    """UPDATE profiles
                       SET name=?, desired_mode=?, bandwidth_preset=?, notes=?, blocked_services=?,
                           daily_quota_mb=?, daily_quota_action=?, service_quotas=?
                       WHERE id=?""",
                    (
                        name, desired_mode, bandwidth_preset, notes.strip()[:250],
                        json.dumps(blocked), daily_quota_mb, daily_quota_action,
                        json.dumps(service_quotas, sort_keys=True), profile_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A profile with that name already exists") from exc
            if cur.rowcount != 1:
                raise ValueError("Profile not found")
        return self.get_profile(profile_id)

    def delete_profile(self, profile_id):
        with self.config_write(scope="profiles", reason="Profile deleted") as db:
            db.execute("UPDATE device_policy SET profile_id=NULL WHERE profile_id=?", (profile_id,))
            cur = db.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
            if cur.rowcount != 1:
                raise ValueError("Profile not found")

    def list_device_policy(self):
        with self._db() as db:
            rows = db.execute(
                """SELECT d.*, p.name AS profile_name
                   FROM device_policy d
                   LEFT JOIN profiles p ON p.id=d.profile_id
                   ORDER BY d.ip"""
            ).fetchall()
        return {row["ip"]: dict(row) for row in rows}

    @staticmethod
    def _managed_identity_name(alias, ip):
        alias = str(alias or "").strip()
        return alias[:50] if alias else str(ip)

    def _ensure_managed_device_identity(self, db, ip, alias=""):
        row = db.execute(
            "SELECT * FROM managed_device_identity WHERE ip=?", (str(ip),)
        ).fetchone()
        current_name = self._managed_identity_name(alias, ip)
        if row:
            if str(row["current_name"] or "") != current_name:
                db.execute(
                    "UPDATE managed_device_identity SET current_name=? WHERE ip=?",
                    (current_name, str(ip)),
                )
            return {
                "ip": str(row["ip"]),
                "identity_id": str(row["identity_id"]),
                "managed_since": str(row["managed_since"]),
                "current_name": current_name,
            }
        identity = {
            "ip": str(ip),
            "identity_id": f"mdi_{uuid.uuid4().hex}",
            "managed_since": self._operations_now_iso(),
            "current_name": current_name,
        }
        db.execute(
            """INSERT INTO managed_device_identity
               (ip, identity_id, managed_since, current_name)
               VALUES (?, ?, ?, ?)""",
            (
                identity["ip"], identity["identity_id"],
                identity["managed_since"], identity["current_name"],
            ),
        )
        return identity

    def get_managed_device_identity(self, ip):
        ip = str(ip or "").strip()
        if not ip:
            return None
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM managed_device_identity WHERE ip=?", (ip,)
            ).fetchone()
        return dict(row) if row else None

    def update_device(
        self,
        ip,
        alias="",
        notes="",
        profile_id=None,
        mode_override="inherit",
        category="other",
        favourite=False,
    ):
        mode_override = self._validate_mode(mode_override, allow_inherit=True)
        alias = alias.strip()[:50]
        notes = notes.strip()[:250]
        categories = {key for key, _ in DEVICE_CATEGORIES}
        if category not in categories:
            category = "other"

        if profile_id in ("", None, 0, "0"):
            profile_id = None
        else:
            profile_id = int(profile_id)
            if not self.get_profile(profile_id):
                raise ValueError("Selected profile does not exist")

        with self.config_write(scope="devices", reason="Managed device policy updated") as db:
            db.execute(
                """INSERT INTO device_policy
                   (ip, alias, notes, category, favourite, profile_id, mode_override)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                     alias=excluded.alias,
                     notes=excluded.notes,
                     category=excluded.category,
                     favourite=excluded.favourite,
                     profile_id=excluded.profile_id,
                     mode_override=excluded.mode_override""",
                (
                    ip,
                    alias,
                    notes,
                    category,
                    1 if favourite else 0,
                    profile_id,
                    mode_override,
                ),
            )
            self._ensure_managed_device_identity(db, ip, alias)

    def bulk_update_devices(self, ips, profile_id=None, mode_override="inherit", category=None):
        if not ips:
            raise ValueError("Select at least one device")
        mode_override = self._validate_mode(mode_override, allow_inherit=True)
        if profile_id in ("", None, 0, "0"):
            profile_id = None
        else:
            profile_id = int(profile_id)
            if not self.get_profile(profile_id):
                raise ValueError("Selected profile does not exist")

        valid_categories = {key for key, _ in DEVICE_CATEGORIES}
        with self.config_write(scope="devices", reason="Managed device policies bulk updated") as db:
            for ip in ips:
                row = db.execute("SELECT * FROM device_policy WHERE ip=?", (ip,)).fetchone()
                alias = row["alias"] if row else ""
                notes = row["notes"] if row else ""
                fav = row["favourite"] if row else 0
                current_cat = row["category"] if row else "other"
                new_cat = category if category in valid_categories else current_cat
                db.execute(
                    """INSERT INTO device_policy
                       (ip, alias, notes, category, favourite, profile_id, mode_override)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(ip) DO UPDATE SET
                         category=excluded.category,
                         profile_id=excluded.profile_id,
                         mode_override=excluded.mode_override""",
                    (ip, alias, notes, new_cat, fav, profile_id, mode_override),
                )
                self._ensure_managed_device_identity(db, ip, alias)

    def list_templates(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM policy_templates ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [self._template_dict(row) for row in rows]

    def save_template_from_profile(self, name, profile_id):
        profile = self.get_profile(int(profile_id))
        if not profile:
            raise ValueError("Profile not found")
        name = name.strip()
        if not name or len(name) > 50:
            raise ValueError("Template name must be 1-50 characters")

        with self.config_write(scope="templates", reason="Policy template created") as db:
            try:
                cur = db.execute(
                    """INSERT INTO policy_templates
                       (name, desired_mode, bandwidth_preset, notes, blocked_services,
                        daily_quota_mb, daily_quota_action, service_quotas)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        name,
                        profile["desired_mode"],
                        profile["bandwidth_preset"],
                        profile["notes"],
                        json.dumps(profile["blocked_services"]),
                        int(profile.get("daily_quota_mb", 0) or 0),
                        profile.get("daily_quota_action", "blocked"),
                        json.dumps(profile.get("service_quotas", {}), sort_keys=True),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A template with that name already exists") from exc
        return cur.lastrowid

    def apply_template(self, template_id, profile_id):
        with self.config_write(scope="profiles", reason="Policy template applied") as db:
            template = db.execute(
                "SELECT * FROM policy_templates WHERE id=?", (template_id,)
            ).fetchone()
            if not template:
                raise ValueError("Template not found")
            cur = db.execute(
                """UPDATE profiles
                   SET desired_mode=?, bandwidth_preset=?, notes=?, blocked_services=?,
                       daily_quota_mb=?, daily_quota_action=?, service_quotas=?
                   WHERE id=?""",
                (
                    template["desired_mode"],
                    template["bandwidth_preset"],
                    template["notes"],
                    template["blocked_services"],
                    int(template["daily_quota_mb"] or 0),
                    template["daily_quota_action"],
                    template["service_quotas"],
                    profile_id,
                ),
            )
            if cur.rowcount != 1:
                raise ValueError("Profile not found")

    def delete_template(self, template_id):
        with self.config_write(scope="templates", reason="Policy template deleted") as db:
            cur = db.execute("DELETE FROM policy_templates WHERE id=?", (template_id,))
            if cur.rowcount != 1:
                raise ValueError("Template not found")

    def list_bandwidth_presets(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM bandwidth_presets ORDER BY builtin DESC, name COLLATE NOCASE"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_bandwidth_preset(self, key):
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM bandwidth_presets WHERE key=?",
                (str(key),),
            ).fetchone()
        return dict(row) if row else None

    def save_bandwidth_preset(self, key, name, upload, download, description=""):
        key = re.sub(r"[^a-z0-9_]+", "_", key.strip().lower()).strip("_")
        if not key or len(key) > 40:
            raise ValueError("Preset key must contain letters/numbers")
        if not name.strip():
            raise ValueError("Preset name is required")

        try:
            upload = normalize_rate(upload)
            download = normalize_rate(download)
        except BandwidthRateError as exc:
            raise ValueError(str(exc)) from exc

        with self.config_write(scope="bandwidth-presets", reason="Bandwidth preset saved") as db:
            existing = db.execute("SELECT builtin FROM bandwidth_presets WHERE key=?", (key,)).fetchone()
            if existing and existing["builtin"]:
                raise ValueError("Built-in presets cannot be replaced")
            db.execute(
                """INSERT INTO bandwidth_presets
                   (key, name, upload, download, description, builtin)
                   VALUES (?, ?, ?, ?, ?, 0)
                   ON CONFLICT(key) DO UPDATE SET
                     name=excluded.name,
                     upload=excluded.upload,
                     download=excluded.download,
                     description=excluded.description""",
                (key, name.strip()[:50], upload, download, description.strip()[:160]),
            )

    def delete_bandwidth_preset(self, key):
        with self.config_write(scope="bandwidth-presets", reason="Bandwidth preset deleted") as db:
            row = db.execute("SELECT builtin FROM bandwidth_presets WHERE key=?", (key,)).fetchone()
            if not row:
                raise ValueError("Preset not found")
            if row["builtin"]:
                raise ValueError("Built-in presets cannot be deleted")
            used = db.execute(
                "SELECT COUNT(*) AS n FROM profiles WHERE bandwidth_preset=?",
                (key,),
            ).fetchone()["n"]
            if used:
                raise ValueError("Preset is in use by a profile")
            db.execute("DELETE FROM bandwidth_presets WHERE key=?", (key,))

    @staticmethod
    def _service_list(value):
        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if str(item).strip()]
        try:
            parsed = json.loads(str(value or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = []
        return [str(item).strip() for item in parsed if str(item).strip()] if isinstance(parsed, list) else []

    @staticmethod
    def _normalize_dns_suffixes(values):
        if isinstance(values, str):
            values = re.split(r"[,\n\r\t ]+", values)
        normalized = []
        for raw in values or []:
            value = str(raw or "").strip().lower().rstrip(".")
            value = value.removeprefix("https://").removeprefix("http://").split("/", 1)[0]
            if value.startswith("*."):
                value = value[2:]
            if not value:
                continue
            if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
                raise ValueError(f"Invalid DNS suffix: {raw}")
            if value not in normalized:
                normalized.append(value)
        return normalized[:80]

    @staticmethod
    def _normalize_tls_patterns(values):
        if isinstance(values, str):
            values = re.split(r"[,\n\r\t ]+", values)
        normalized = []
        for raw in values or []:
            value = str(raw or "").strip().lower()
            if not value:
                continue
            if len(value) > 200 or not re.fullmatch(r"[a-z0-9.*_-]+", value):
                raise ValueError(f"Invalid TLS/SNI pattern: {raw}")
            if value not in normalized:
                normalized.append(value)
        return normalized[:40]

    def list_services(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM services ORDER BY builtin DESC, name COLLATE NOCASE"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["dns_suffixes"] = self._service_list(item.get("dns_suffixes"))
            item["tls_patterns"] = self._service_list(item.get("tls_patterns"))
            item["classifier_enabled"] = bool(item.get("classifier_enabled", 1))
            item["enforcement_approved"] = bool(item.get("enforcement_approved", 0))
            item["routeros_managed"] = bool(
                item.get("key") in SERVICE_ENFORCEMENT
                or item.get("enforcement_approved")
            )
            metadata = builtin_service_metadata(item.get("key"))
            if metadata:
                item["coverage_note"] = metadata.get("coverage_note", "")
                item["source_list"] = metadata.get("source_list", "")
                item["detector_lists"] = metadata.get("detector_lists", [])
            elif item.get("enforcement_approved"):
                try:
                    contract = build_custom_service_contract(item)
                    item["coverage_note"] = contract.get("coverage_note", "")
                    item["source_list"] = contract.get("source_list", "")
                    item["detector_lists"] = contract.get("detector_lists", [])
                except ValueError as exc:
                    item["provisioning_error"] = str(exc)
            result.append(item)
        return result

    def get_service(self, key):
        key = str(key or "").strip().lower()
        return next((item for item in self.list_services() if item["key"] == key), None)

    def routeros_service_catalog(self):
        """Return built-ins plus operator-approved custom RouterOS contracts."""
        catalog = {key: dict(value) for key, value in SERVICE_ENFORCEMENT.items()}
        for item in self.list_services():
            if item.get("builtin") or not item.get("enforcement_approved"):
                continue
            try:
                catalog[item["key"]] = build_custom_service_contract(item)
            except ValueError:
                # Corrupt/legacy approved metadata must never take down the whole
                # runtime catalogue or become write authority. list_services()
                # retains provisioning_error so Service Health can surface the
                # individual contract as degraded/fail-closed.
                continue
        return catalog

    def routeros_supported_service_keys(self):
        return frozenset(self.routeros_service_catalog())

    def set_service_enforcement_approved(self, key, approved):
        key = str(key or "").strip().lower()
        service = self.get_service(key)
        if not service:
            raise ValueError("Service not found")
        if service.get("builtin"):
            raise ValueError("Built-in RouterOS contracts are manually owned and cannot be reprovisioned")
        if approved:
            build_custom_service_contract(service)
        with self.config_write(scope="services", reason="Service enforcement approval changed") as db:
            db.execute(
                """UPDATE services
                   SET enforcement_approved=?, enforcement_approved_at=?
                   WHERE key=?""",
                (
                    1 if approved else 0,
                    datetime.now(timezone.utc).isoformat(timespec="seconds") if approved else "",
                    key,
                ),
            )
        return self.get_service(key)

    def save_service(
        self, key, name, description="", category="other",
        dns_suffixes=(), tls_patterns=(), classifier_enabled=True,
    ):
        key = re.sub(r"[^a-z0-9_]+", "_", key.strip().lower()).strip("_")
        if not key or len(key) > 40:
            raise ValueError("Service key must contain letters/numbers")
        if not name.strip():
            raise ValueError("Service name is required")
        category = re.sub(r"[^a-z0-9_-]+", "", str(category or "other").strip().lower()) or "other"
        if len(category) > 30:
            raise ValueError("Service category is too long")
        dns_suffixes = self._normalize_dns_suffixes(dns_suffixes)
        tls_patterns = self._normalize_tls_patterns(tls_patterns)
        enabled = 1 if classifier_enabled else 0
        with self.config_write(scope="services", reason="Custom service saved") as db:
            existing = db.execute(
                "SELECT builtin, tls_patterns, enforcement_approved FROM services WHERE key=?",
                (key,),
            ).fetchone()
            if existing and existing["builtin"]:
                raise ValueError("Built-in services cannot be replaced")
            if existing and existing["enforcement_approved"]:
                existing_tls = self._service_list(existing["tls_patterns"])
                if existing_tls != tls_patterns:
                    raise ValueError(
                        "Remove the approved RouterOS contract before changing TLS/SNI patterns"
                    )
            db.execute(
                """INSERT INTO services
                   (key, name, description, builtin, category, dns_suffixes, tls_patterns, classifier_enabled)
                   VALUES (?, ?, ?, 0, ?, ?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET
                     name=excluded.name,
                     description=excluded.description,
                     category=excluded.category,
                     dns_suffixes=excluded.dns_suffixes,
                     tls_patterns=excluded.tls_patterns,
                     classifier_enabled=excluded.classifier_enabled""",
                (
                    key, name.strip()[:50], description.strip()[:160], category,
                    json.dumps(dns_suffixes), json.dumps(tls_patterns), enabled,
                ),
            )
        return next(item for item in self.list_services() if item["key"] == key)

    def service_usage(self, key):
        """Return live policy/configuration references to one concrete service key."""
        key = str(key or "").strip().lower()
        usage = dict(self.policy_group_usage(key))
        aggregate_refs = [
            {"key": item["key"], "name": item["name"]}
            for item in self.list_policy_groups()
            if key in set(item.get("members") or [])
        ]
        usage["aggregate_groups"] = aggregate_refs
        usage["total"] = int(usage.get("total", 0)) + len(aggregate_refs)
        usage["in_use"] = bool(usage["total"])
        return usage

    def delete_service(self, key):
        key = str(key or "").strip().lower()
        with self._db() as db:
            row = db.execute(
                "SELECT builtin, enforcement_approved FROM services WHERE key=?",
                (key,),
            ).fetchone()
            if not row:
                raise ValueError("Service not found")
            if row["builtin"]:
                raise ValueError("Built-in services cannot be deleted")
            if row["enforcement_approved"]:
                raise ValueError(
                    "Remove the custom RouterOS enforcement contract before deleting this service"
                )
        usage = self.service_usage(key)
        if usage["in_use"]:
            labels = []
            for field, label in (
                ("profiles", "profile"),
                ("quotas", "service quota"),
                ("templates", "policy template"),
                ("schedules", "schedule"),
                ("collections", "reusable service collection"),
                ("aggregate_groups", "aggregate policy group"),
            ):
                count = len(usage.get(field) or [])
                if count:
                    labels.append(label + ("s" if count != 1 else ""))
            raise ValueError(
                f"Custom service is still referenced by {usage['total']} policy/configuration "
                f"reference(s) ({', '.join(labels)}); remove those references before deleting it"
            )
        with self.config_write(scope="services", reason="Custom service deleted") as db:
            cur = db.execute("DELETE FROM services WHERE key=?", (key,))
            if cur.rowcount != 1:
                raise ValueError("Service not found")

    def export_service_catalog(self, path):
        """Atomically publish enabled classifier metadata for telemetry consumers."""
        payload = {
            "version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "services": [
                {
                    "key": item["key"],
                    "name": item["name"],
                    "category": item.get("category") or "other",
                    "dns_suffixes": list(item.get("dns_suffixes") or []),
                    "tls_patterns": list(item.get("tls_patterns") or []),
                    "routeros_managed": bool(item.get("routeros_managed")),
                    "enforcement_approved": bool(item.get("enforcement_approved")),
                }
                for item in self.list_services()
                if item.get("classifier_enabled")
                and (item.get("dns_suffixes") or item.get("tls_patterns"))
            ],
        }
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, target)
        return payload

    @staticmethod
    def _target_specificity(target_type: str) -> int:
        return {"all": 1, "profile": 2, "device": 3}.get(target_type, 0)

    @staticmethod
    def _weekday_code(day: date) -> str:
        return ["mon", "tue", "wed", "thu", "fri", "sat", "sun"][day.weekday()]

    def _policy_datetime_details(self, at=None):
        settings = self.get_settings()
        timezone_name = settings.get("policy_timezone") or os.getenv(
            "POLICY_TIMEZONE", "Europe/London"
        )
        try:
            tz = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(
                f"Policy timezone '{timezone_name}' is not available"
            ) from exc

        if at is None:
            value = datetime.now(tz)
            resolution = {
                "requested_local": value.replace(tzinfo=None).isoformat(timespec="minutes"),
                "resolved_local": value.isoformat(timespec="minutes"),
                "adjusted": False,
                "kind": "current",
                "ambiguous": bool(value.fold),
                "nonexistent": False,
            }
        else:
            value, resolution = normalize_policy_datetime(at, tz)
        return value, timezone_name, resolution

    def _policy_datetime(self, at=None):
        value, timezone_name, _ = self._policy_datetime_details(at)
        return value, timezone_name

    def get_policy_clock(self):
        value, timezone_name = self._policy_datetime()
        return {
            "timezone": timezone_name,
            "iso": value.isoformat(timespec="minutes"),
            "date": value.date().isoformat(),
            "time": value.strftime("%H:%M"),
            "weekday": value.strftime("%A"),
        }

    def _validate_schedule_target(self, target_type, target_value):
        target_type = str(target_type or "").strip().lower()
        target_value = str(target_value or "").strip()
        if target_type not in {"all", "profile", "device"}:
            raise ValueError("Invalid schedule target")
        if target_type == "all":
            return target_type, ""
        if target_type == "profile":
            try:
                profile_id = int(target_value)
            except (TypeError, ValueError) as exc:
                raise ValueError("Select a valid profile target") from exc
            if not self.get_profile(profile_id):
                raise ValueError("Schedule profile target does not exist")
            return target_type, str(profile_id)
        try:
            ip = str(ipaddress.ip_address(target_value))
        except ValueError as exc:
            raise ValueError("Schedule device target must be a valid IP address") from exc
        return target_type, ip

    def _normalize_service_schedule_action(self, action_value):
        raw = str(action_value or "").strip().lower()
        if ":" not in raw:
            raise ValueError(
                "Service schedule action must use service:block or service:allow"
            )
        service_key, state = [part.strip() for part in raw.split(":", 1)]
        valid_services = {item["key"] for item in self.list_services()} | set(self.policy_group_keys())
        if service_key not in valid_services:
            raise ValueError(f"Unknown scheduled service '{service_key}'")
        state_map = {
            "block": "block",
            "blocked": "block",
            "deny": "block",
            "allow": "allow",
            "allowed": "allow",
        }
        normalized_state = state_map.get(state)
        if not normalized_state:
            raise ValueError("Service schedule state must be block or allow")
        return f"{service_key}:{normalized_state}", service_key, normalized_state

    def _target_matches(self, target_type, target_value, ip, profile_id):
        if target_type == "all":
            return True
        if target_type == "device":
            return str(target_value) == str(ip)
        if target_type == "profile":
            return profile_id is not None and str(target_value) == str(profile_id)
        return False

    def _select_schedule_candidate(self, candidates, dimension):
        if not candidates:
            return None
        latest_at = max(utc_instant(item["occurrence"]) for item in candidates)
        latest = [
            item for item in candidates
            if utc_instant(item["occurrence"]) == latest_at
        ]
        best_specificity = max(item["specificity"] for item in latest)
        winners = [
            item for item in latest if item["specificity"] == best_specificity
        ]
        values = {item["value"] for item in winners}
        if len(values) > 1:
            labels = ", ".join(sorted({item["label"] for item in winners}))
            raise ValueError(
                f"Ambiguous {dimension} schedules at "
                f"{latest[0]['occurrence'].strftime('%a %H:%M')}: {labels}"
            )
        return sorted(winners, key=lambda item: item.get("id", 0))[-1]

    def _schedule_occurrences(self, ip, profile_id, at, future=False):
        results = []
        plans = [p for p in self.list_schedule_plans() if p.get("enabled", 1)]
        offsets = range(0, 8)
        for plan in plans:
            if not self._target_matches(
                plan["target_type"], plan["target_value"], ip, profile_id
            ):
                continue
            try:
                hour, minute = [int(part) for part in plan["clock_time"].split(":", 1)]
            except Exception as exc:
                raise ValueError(
                    f"Schedule '{plan['label']}' has an invalid time"
                ) from exc

            if plan["action_type"] == "mode":
                value = self._validate_mode(str(plan["action_value"]).lower())
                service_key = None
                state = None
            elif plan["action_type"] == "service":
                value, service_key, state = self._normalize_service_schedule_action(
                    plan["action_value"]
                )
            else:
                raise ValueError(
                    f"Schedule '{plan['label']}' has unsupported action type"
                )

            for offset in offsets:
                day = at.date() + timedelta(days=offset if future else -offset)
                if self._weekday_code(day) not in plan["days"]:
                    continue
                occurrence, wall_resolution = resolve_local_wall_time(
                    day, dt_time(hour=hour, minute=minute), at.tzinfo
                )
                occurrence_instant = utc_instant(occurrence)
                at_instant = utc_instant(at)
                if future and occurrence_instant <= at_instant:
                    continue
                if not future and occurrence_instant > at_instant:
                    continue
                results.append(
                    {
                        "id": plan["id"],
                        "label": plan["label"],
                        "occurrence": occurrence,
                        "specificity": self._target_specificity(plan["target_type"]),
                        "target_type": plan["target_type"],
                        "action_type": plan["action_type"],
                        "value": value,
                        "service_key": service_key,
                        "state": state,
                        "requested_time": plan["clock_time"],
                        "wall_resolution": wall_resolution,
                    }
                )
        return results

    def _resolve_regular_schedule(self, ip, profile_id, at):
        past = self._schedule_occurrences(ip, profile_id, at, future=False)
        mode_candidate = self._select_schedule_candidate(
            [item for item in past if item["action_type"] == "mode"],
            "mode",
        )

        service_candidates = {}
        for item in past:
            if item["action_type"] != "service":
                continue
            service_candidates.setdefault(item["service_key"], []).append(item)
        service_state = {
            key: self._select_schedule_candidate(values, f"{key} service")
            for key, values in service_candidates.items()
        }

        future = self._schedule_occurrences(ip, profile_id, at, future=True)
        next_candidate = None
        if future:
            next_at = min(utc_instant(item["occurrence"]) for item in future)
            same_time = [
                item for item in future
                if utc_instant(item["occurrence"]) == next_at
            ]
            best_specificity = max(item["specificity"] for item in same_time)
            same_time = [
                item for item in same_time
                if item["specificity"] == best_specificity
            ]
            next_candidate = sorted(same_time, key=lambda item: item.get("id", 0))[0]

        return mode_candidate, service_state, next_candidate

    def _matching_exception(self, ip, date_iso, profile_id=None):
        # Consume the resolver's explicit profile context.  Simulation may be
        # evaluating an unsaved assignment, so re-reading the persisted device
        # profile here would split schedule and exception precedence across two
        # different policy contexts.
        if profile_id is None:
            cfg = self.list_device_policy().get(ip, {})
            profile_id = cfg.get("profile_id")
        matches = []
        for ex in self.list_date_exceptions():
            if not (ex["start_date"] <= date_iso <= ex["end_date"]):
                continue
            if not self._target_matches(
                ex["target_type"], ex["target_value"], ip, profile_id
            ):
                continue
            matches.append(
                {
                    **ex,
                    "specificity": self._target_specificity(ex["target_type"]),
                }
            )
        if not matches:
            return None
        best_specificity = max(item["specificity"] for item in matches)
        winners = [item for item in matches if item["specificity"] == best_specificity]
        signatures = {(item["mode"], item.get("template_id")) for item in winners}
        if len(signatures) > 1:
            labels = ", ".join(sorted(item["label"] for item in winners))
            raise ValueError(
                f"Conflicting date exceptions for {ip} on {date_iso}: {labels}"
            )
        return sorted(
            winners,
            key=lambda item: (item["start_date"], item["id"]),
        )[-1]

    def _template_candidates(self, template, at, start_date, end_date, future=False):
        results = []
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
        for entry_index, entry in enumerate(template["entries"]):
            hour, minute = [int(part) for part in entry["time"].split(":", 1)]
            for offset in range(0, 8):
                day = at.date() + timedelta(days=offset if future else -offset)
                if day < start or day > end:
                    continue
                if self._weekday_code(day) not in entry["days"]:
                    continue
                occurrence, wall_resolution = resolve_local_wall_time(
                    day, dt_time(hour=hour, minute=minute), at.tzinfo
                )
                occurrence_instant = utc_instant(occurrence)
                at_instant = utc_instant(at)
                if future and occurrence_instant <= at_instant:
                    continue
                if not future and occurrence_instant > at_instant:
                    continue
                results.append(
                    {
                        "id": entry_index,
                        "label": template["name"],
                        "occurrence": occurrence,
                        "specificity": 4,
                        "target_type": "template",
                        "action_type": "mode",
                        "value": entry["mode"],
                        "service_key": None,
                        "state": None,
                        "requested_time": entry["time"],
                        "wall_resolution": wall_resolution,
                    }
                )
        return results

    def _resolve_exception_template(self, exception, at):
        template = next(
            (
                t for t in self.list_schedule_templates()
                if t["id"] == exception.get("template_id")
            ),
            None,
        )
        if not template:
            raise ValueError(
                f"Date exception '{exception['label']}' references a missing template"
            )
        past = self._template_candidates(
            template,
            at,
            exception["start_date"],
            exception["end_date"],
            future=False,
        )
        current = self._select_schedule_candidate(past, "template mode")
        future = self._template_candidates(
            template,
            at,
            exception["start_date"],
            exception["end_date"],
            future=True,
        )
        next_candidate = None
        if future:
            next_at = min(utc_instant(item["occurrence"]) for item in future)
            next_candidate = sorted(
                [item for item in future if utc_instant(item["occurrence"]) == next_at],
                key=lambda item: item["id"],
            )[0]
        return template, current, next_candidate

    @staticmethod
    def _format_policy_action(candidate):
        if not candidate:
            return None
        if candidate["action_type"] == "service":
            summary = f"{candidate['service_key']}:{candidate['state']}"
        else:
            summary = candidate["value"]
        return {
            "at": candidate["occurrence"].isoformat(timespec="minutes"),
            "date": candidate["occurrence"].date().isoformat(),
            "time": candidate["occurrence"].strftime("%H:%M"),
            "type": candidate["action_type"],
            "value": summary,
            "mode": candidate["value"] if candidate["action_type"] == "mode" else None,
            "service": candidate.get("service_key"),
            "state": candidate.get("state"),
            "label": candidate["label"],
            "requested_time": candidate.get("requested_time"),
            "wall_resolution": candidate.get("wall_resolution") or {
                "adjusted": False, "kind": "exact"
            },
        }

    def get_device_quota_config(self, ip):
        devices = self.list_device_policy()
        cfg = devices.get(ip, {})
        profile = self.get_profile(cfg.get("profile_id")) if cfg.get("profile_id") else None
        settings = self.get_settings()
        service_quotas = dict(profile.get("service_quotas", {})) if profile else {}
        daily_quota_mb = int(profile.get("daily_quota_mb", 0) or 0) if profile else 0
        configured = bool(daily_quota_mb or service_quotas)
        return {
            "configured": configured,
            "engine_enabled": str(settings.get("quota_engine_enabled", "0")) == "1",
            "warning_percent": int(settings.get("quota_warning_percent", "80") or 80),
            "profile_id": profile.get("id") if profile else None,
            "profile_name": profile.get("name") if profile else None,
            "daily_quota_mb": daily_quota_mb,
            "daily_quota_action": profile.get("daily_quota_action", "blocked") if profile else "blocked",
            "service_quotas": service_quotas,
        }

    @staticmethod
    def _quota_mode_rank(mode):
        return {"normal": 0, "slow": 1, "blocked": 2}.get(str(mode or "normal"), 0)

    def _evaluate_quota_state(self, profile, desired_mode, blocked, quota_usage, policy_groups=None):
        settings = self.get_settings()
        policy_groups = normalized_group_catalog(policy_groups or self.policy_group_catalog())
        policy_group_keys = frozenset(policy_groups)
        enabled = str(settings.get("quota_engine_enabled", "0")) == "1"
        try:
            warning_percent = int(settings.get("quota_warning_percent", "80") or 80)
        except (TypeError, ValueError):
            warning_percent = 80
        warning_percent = max(50, min(warning_percent, 95))

        daily_limit_mb = int(profile.get("daily_quota_mb", 0) or 0) if profile else 0
        service_limits = dict(profile.get("service_quotas", {})) if profile else {}
        configured = bool(daily_limit_mb or service_limits)
        action = profile.get("daily_quota_action", "blocked") if profile else "blocked"
        profile_name = profile.get("name") if profile else None

        state = {
            "configured": configured,
            "enabled": enabled,
            "available": True,
            "profile_name": profile_name,
            "day": None,
            "timezone": None,
            "warning_percent": warning_percent,
            "active": False,
            "mode_active": False,
            "service_active": False,
            "telemetry_error": None,
            "daily": {
                "limit_mb": daily_limit_mb,
                "limit_bytes": bytes_for_mb(daily_limit_mb),
                "action": action,
                "used_bytes": 0,
                "used_human": format_quota_bytes(0),
                "percent": 0.0,
                "warning": False,
                "exhausted": False,
            },
            "services": [],
            "active_service_blocks": [],
        }

        if not configured:
            return state, desired_mode, blocked, None
        if not enabled:
            state["available"] = False
            state["telemetry_error"] = "Quota engine is disabled in Settings"
            return state, desired_mode, blocked, None
        if not quota_usage or not quota_usage.get("available"):
            state["available"] = False
            state["telemetry_error"] = (quota_usage or {}).get(
                "error", "Telemetry usage is unavailable; quota policy is fail-open"
            )
            return state, desired_mode, blocked, None

        state["day"] = quota_usage.get("day")
        state["timezone"] = quota_usage.get("timezone")
        total_used = int(quota_usage.get("total_bytes") or 0)
        daily = state["daily"]
        daily["used_bytes"] = total_used
        daily["used_human"] = format_quota_bytes(total_used)
        daily["percent"] = percent_used(total_used, daily_limit_mb)
        daily["warning"] = bool(daily_limit_mb and daily["percent"] >= warning_percent)
        daily["exhausted"] = bool(
            daily_limit_mb and total_used >= bytes_for_mb(daily_limit_mb)
        )

        quota_source = None
        if daily["exhausted"]:
            state["mode_active"] = True
            state["active"] = True
            if self._quota_mode_rank(action) > self._quota_mode_rank(desired_mode):
                desired_mode = action
                quota_source = f"daily quota: {profile_name or 'profile'}"

        service_used = quota_usage.get("service_bytes") or {}
        for service_key, limit_mb in sorted(service_limits.items()):
            limit_mb = int(limit_mb or 0)
            if not limit_mb:
                continue
            is_group = service_key in policy_group_keys
            members = list(group_members(service_key, policy_groups)) if is_group else [service_key]
            used = sum(int(service_used.get(member, 0) or 0) for member in members)
            pct = percent_used(used, limit_mb)
            exhausted = used >= bytes_for_mb(limit_mb)
            entry = {
                "key": service_key,
                "kind": "group" if is_group else "service",
                "name": (
                    policy_groups[service_key]["name"]
                    if is_group
                    else service_key
                ),
                "members": members,
                "limit_mb": limit_mb,
                "limit_bytes": bytes_for_mb(limit_mb),
                "used_bytes": used,
                "used_human": format_quota_bytes(used),
                "percent": pct,
                "warning": pct >= warning_percent,
                "exhausted": exhausted,
            }
            state["services"].append(entry)
            if exhausted:
                blocked.update(members)
                state["active_service_blocks"].append(service_key)

        if state["active_service_blocks"]:
            state["service_active"] = True
            state["active"] = True
        return state, desired_mode, blocked, quota_source

    def _compute_effective_policy_from_context(
        self, ip, cfg, profile, profile_id, at=None, quota_usage=None,
        supported_service_keys=None,
    ):
        """Resolve effective policy from explicit in-memory context.

        Live reconciliation and what-if simulation both use this function so
        simulation cannot drift into a second policy engine.
        """
        policy_groups = self.policy_group_catalog()
        policy_group_keys = frozenset(policy_groups)
        base_mode = cfg.get("mode_override", "inherit")
        base_source = "device override"
        if base_mode == "inherit":
            base_mode = profile["desired_mode"] if profile else "normal"
            base_source = f"profile: {profile['name']}" if profile else "default"

        bandwidth = profile["bandwidth_preset"] if profile else "normal"
        bandwidth_details = self.get_bandwidth_preset(bandwidth)
        if not bandwidth_details:
            raise ValueError(
                f"Bandwidth preset '{bandwidth}' referenced by {ip} does not exist"
            )

        base_blocked = sorted(set(profile["blocked_services"] if profile else []))
        desired_mode = base_mode
        source = base_source
        requested_blocked = set(base_blocked)
        conflicts = []
        if cfg.get("mode_override") not in (None, "", "inherit") and profile:
            if cfg["mode_override"] != profile["desired_mode"]:
                conflicts.append(
                    f"Device override {cfg['mode_override'].upper()} overrides "
                    f"profile {profile['desired_mode'].upper()}"
                )

        policy_at, timezone_name, policy_time_resolution = self._policy_datetime_details(at)
        mode_schedule, service_schedules, next_regular = self._resolve_regular_schedule(
            ip, profile_id, policy_at
        )
        exception = self._matching_exception(
            ip, policy_at.date().isoformat(), profile_id=profile_id
        )
        next_candidate = next_regular
        schedule_reason = None

        if exception:
            if exception["mode"] in {"normal", "slow", "blocked"}:
                desired_mode = exception["mode"]
                source = f"date exception: {exception['label']}"
                schedule_reason = source
                end_transition, end_resolution = local_midnight(
                    date.fromisoformat(exception["end_date"]) + timedelta(days=1),
                    policy_at.tzinfo,
                )
                if utc_instant(end_transition) > utc_instant(policy_at):
                    next_candidate = {
                        "id": 0,
                        "label": f"{exception['label']} ends",
                        "occurrence": end_transition,
                        "specificity": 4,
                        "target_type": "exception",
                        "action_type": "mode",
                        "value": "re-evaluate",
                        "service_key": None,
                        "state": None,
                        "requested_time": "00:00",
                        "wall_resolution": end_resolution,
                    }
            elif exception["mode"] == "template":
                template, template_current, template_next = self._resolve_exception_template(
                    exception, policy_at
                )
                schedule_reason = f"date exception template: {exception['label']}"
                if template_current:
                    desired_mode = template_current["value"]
                    source = schedule_reason
                else:
                    source = f"{base_source}; awaiting {template['name']}"
                next_candidate = template_next
                if not next_candidate:
                    end_transition, end_resolution = local_midnight(
                        date.fromisoformat(exception["end_date"]) + timedelta(days=1),
                        policy_at.tzinfo,
                    )
                    if utc_instant(end_transition) > utc_instant(policy_at):
                        next_candidate = {
                            "id": 0,
                            "label": f"{exception['label']} ends",
                            "occurrence": end_transition,
                            "specificity": 4,
                            "target_type": "exception",
                            "action_type": "mode",
                            "value": "re-evaluate",
                            "service_key": None,
                            "state": None,
                            "requested_time": "00:00",
                            "wall_resolution": end_resolution,
                        }
        elif mode_schedule:
            desired_mode = mode_schedule["value"]
            source = f"schedule: {mode_schedule['label']}"
            schedule_reason = source

        service_overrides = []
        concrete_schedule_overrides = {}
        for service_key, candidate in sorted(service_schedules.items()):
            if candidate["state"] == "block":
                requested_blocked.add(service_key)
            else:
                requested_blocked.discard(service_key)
            if service_key not in policy_group_keys:
                concrete_schedule_overrides[service_key] = candidate["state"]
            service_overrides.append(
                {
                    "service": service_key,
                    "state": candidate["state"],
                    "label": candidate["label"],
                    "at": candidate["occurrence"].isoformat(timespec="minutes"),
                    "policy_group": service_key in policy_group_keys,
                }
            )

        # While a date exception owns the mode, regular service schedules remain
        # active. If a service transition happens before the exception/template
        # mode transition, surface it as the next effective-policy event.
        if exception:
            future_services = [
                item for item in self._schedule_occurrences(ip, profile_id, policy_at, future=True)
                if item["action_type"] == "service"
            ]
            if future_services:
                service_next = min(
                    future_services, key=lambda item: utc_instant(item["occurrence"])
                )
                if (
                    not next_candidate
                    or utc_instant(service_next["occurrence"])
                    < utc_instant(next_candidate["occurrence"])
                ):
                    next_candidate = service_next

        if supported_service_keys is None:
            supported_service_keys = self.routeros_supported_service_keys()
        expanded = expand_policy_keys(
            requested_blocked, supported_service_keys=supported_service_keys,
            policy_groups=policy_groups,
        )
        blocked = set(expanded["effective_services"])

        # A concrete service schedule is more specific than an aggregate group
        # membership. This allows, for example, Gaming=BLOCK with Roblox=ALLOW
        # without weakening the rest of the group. Quota exhaustion is applied
        # after this step and therefore remains authoritative over schedules.
        for service_key, state in concrete_schedule_overrides.items():
            if state == "block":
                blocked.add(service_key)
            else:
                blocked.discard(service_key)

        pre_quota_mode = desired_mode
        pre_quota_source = source
        quota_state, desired_mode, blocked, quota_source = self._evaluate_quota_state(
            profile, desired_mode, blocked, quota_usage, policy_groups=policy_groups
        )
        if quota_source:
            source = quota_source
        quota_state["mode_before_quota"] = pre_quota_mode
        quota_state["mode_source_before_quota"] = pre_quota_source

        quota_active_groups = [
            key for key in quota_state.get("active_service_blocks", [])
            if key in policy_group_keys
        ]
        service_names = {item["key"]: item["name"] for item in self.list_services()}
        group_states = policy_group_states(
            expanded["groups"], blocked, quota_active_groups,
            policy_groups=policy_groups, service_names=service_names,
        )

        return {
            "mode": desired_mode,
            "mode_source": source,
            "base_mode": base_mode,
            "base_mode_source": base_source,
            "bandwidth_preset": bandwidth,
            "bandwidth_name": bandwidth_details["name"],
            "bandwidth_upload": bandwidth_details["upload"],
            "bandwidth_download": bandwidth_details["download"],
            "blocked_services": sorted(blocked),
            "requested_blocked_services": expanded["requested"],
            "blocked_policy_groups": expanded["groups"],
            "policy_group_states": group_states,
            "unsupported_policy_keys": expanded["unsupported"],
            "unsupported_policy_group_members": expanded.get("unsupported_group_members", []),
            "base_blocked_services": base_blocked,
            "scheduled_service_overrides": service_overrides,
            "schedule_active": bool(
                exception or mode_schedule or service_overrides
            ),
            "schedule_reason": schedule_reason,
            "active_date_exception": exception,
            "next_policy_action": self._format_policy_action(next_candidate),
            "policy_timezone": timezone_name,
            "policy_at": policy_at.isoformat(timespec="minutes"),
            "policy_time_resolution": policy_time_resolution,
            "quota_state": quota_state,
            "quota_active": bool(quota_state.get("active")),
            "conflicts": conflicts,
        }


    def compute_effective_policy(self, ip, at=None, quota_usage=None, supported_service_keys=None):
        devices = self.list_device_policy()
        cfg = dict(devices.get(ip, {}) or {})
        profile_id = cfg.get("profile_id")
        profile = self.get_profile(profile_id) if profile_id else None
        return self._compute_effective_policy_from_context(
            ip, cfg, profile, profile_id, at=at, quota_usage=quota_usage,
            supported_service_keys=supported_service_keys,
        )

    def build_profile_candidate(
        self, profile_id, name, desired_mode, bandwidth_preset, notes="",
        blocked_services=(), daily_quota_mb=0, daily_quota_action="blocked",
        service_quotas=None,
    ):
        """Validate an unsaved profile proposal without touching SQLite."""
        current = self.get_profile(int(profile_id))
        if not current:
            raise ValueError("Profile not found")
        name = str(name or "").strip()
        if not name or len(name) > 50:
            raise ValueError("Profile name must be 1-50 characters")
        desired_mode = self._validate_mode(desired_mode)
        bandwidth_preset = self._validate_preset(bandwidth_preset)
        blocked = self._validate_services(blocked_services)
        daily_quota_mb = normalize_quota_mb(daily_quota_mb, field="Daily data quota")
        daily_quota_action = normalize_quota_action(daily_quota_action)
        service_quotas = normalize_service_quotas(
            service_quotas or {}, supported_service_keys=self.routeros_supported_service_keys() | self.policy_group_keys()
        )
        return {
            **current,
            "id": int(profile_id),
            "name": name,
            "desired_mode": desired_mode,
            "bandwidth_preset": bandwidth_preset,
            "notes": str(notes or "").strip()[:250],
            "blocked_services": blocked,
            "daily_quota_mb": daily_quota_mb,
            "daily_quota_action": daily_quota_action,
            "service_quotas": service_quotas,
        }

    def simulate_effective_policy(
        self, ip, at=None, profile_id=None, mode_override=None,
        profile_candidate=None, quota_usage=None, supported_service_keys=None,
        keep_profile=True, keep_mode=True,
    ):
        """Resolve a proposed device/profile scenario entirely in memory."""
        devices = self.list_device_policy()
        cfg = dict(devices.get(ip, {}) or {})
        if not keep_profile:
            if profile_id in (None, "", 0, "0"):
                cfg["profile_id"] = None
            else:
                profile_id = int(profile_id)
                if not self.get_profile(profile_id):
                    raise ValueError("Selected profile does not exist")
                cfg["profile_id"] = profile_id
        profile_id = cfg.get("profile_id")
        if not keep_mode:
            cfg["mode_override"] = self._validate_mode(mode_override) if mode_override != "inherit" else "inherit"
        profile = None
        if profile_id:
            if profile_candidate and int(profile_candidate.get("id") or 0) == int(profile_id):
                profile = dict(profile_candidate)
            else:
                profile = self.get_profile(profile_id)
        return self._compute_effective_policy_from_context(
            ip, cfg, profile, profile_id, at=at, quota_usage=quota_usage,
            supported_service_keys=supported_service_keys,
        )

    def list_schedule_plans(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM schedule_plans ORDER BY clock_time, label COLLATE NOCASE"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["days"] = json.loads(item["days"] or "[]")
            item["enabled"] = bool(item.get("enabled", 1))
            if item["action_type"] == "service":
                try:
                    _, service_key, state = self._normalize_service_schedule_action(
                        item["action_value"]
                    )
                    item["action_service"] = service_key
                    item["action_state"] = state
                except ValueError:
                    item["action_service"] = ""
                    item["action_state"] = "invalid"
            result.append(item)
        return result

    def create_schedule_plan(
        self,
        label,
        target_type,
        target_value,
        action_type,
        action_value,
        clock_time,
        days,
    ):
        target_type, target_value = self._validate_schedule_target(
            target_type, target_value
        )
        action_type = str(action_type or "").strip().lower()
        if action_type not in {"mode", "service"}:
            raise ValueError("Invalid schedule action")
        if not label.strip():
            raise ValueError("Schedule label is required")
        clean_days = []
        for day in days:
            day = str(day).lower().strip()
            if day in {"mon", "tue", "wed", "thu", "fri", "sat", "sun"} and day not in clean_days:
                clean_days.append(day)
        if not clean_days:
            raise ValueError("Select at least one day")
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", clock_time):
            raise ValueError("Time must be HH:MM")

        if action_type == "mode":
            action_value = self._validate_mode(str(action_value).strip().lower())
        else:
            action_value, _, _ = self._normalize_service_schedule_action(action_value)

        with self.config_write(scope="schedules", reason="Schedule plan created") as db:
            cur = db.execute(
                """INSERT INTO schedule_plans
                   (label, target_type, target_value, action_type, action_value, clock_time, days)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    label.strip()[:60],
                    target_type,
                    target_value,
                    action_type,
                    action_value,
                    clock_time,
                    json.dumps(clean_days),
                ),
            )
        return cur.lastrowid

    def set_schedule_plan_enabled(self, plan_id, enabled):
        with self.config_write(scope="schedules", reason="Schedule plan state updated") as db:
            cur = db.execute(
                "UPDATE schedule_plans SET enabled=? WHERE id=?",
                (1 if enabled else 0, int(plan_id)),
            )
            if cur.rowcount != 1:
                raise ValueError("Schedule plan not found")

    def delete_schedule_plan(self, plan_id):
        with self.config_write(scope="schedules", reason="Schedule plan deleted") as db:
            cur = db.execute("DELETE FROM schedule_plans WHERE id=?", (plan_id,))
            if cur.rowcount != 1:
                raise ValueError("Schedule plan not found")

    def detect_schedule_conflicts(self):
        plans = [p for p in self.list_schedule_plans() if p.get("enabled")]
        conflicts = []
        for i, a in enumerate(plans):
            for b in plans[i+1:]:
                same_target = (
                    a["target_type"] == b["target_type"]
                    and a["target_value"] == b["target_value"]
                )
                overlap = set(a["days"]) & set(b["days"])
                same_time = a["clock_time"] == b["clock_time"]
                same_dimension = a["action_type"] == b["action_type"]
                if a["action_type"] == "service" and b["action_type"] == "service":
                    same_dimension = (
                        a.get("action_service") == b.get("action_service")
                    )
                contradictory = a["action_value"] != b["action_value"]
                if same_target and overlap and same_time and same_dimension and contradictory:
                    conflicts.append(
                        f"{a['label']} conflicts with {b['label']} "
                        f"at {a['clock_time']} on {', '.join(sorted(overlap))}"
                    )
        return conflicts

    def detect_date_exception_conflicts(self):
        exceptions = self.list_date_exceptions()
        conflicts = []
        for i, a in enumerate(exceptions):
            for b in exceptions[i + 1:]:
                same_target = (
                    a["target_type"] == b["target_type"]
                    and str(a["target_value"]) == str(b["target_value"])
                )
                overlaps = not (
                    a["end_date"] < b["start_date"]
                    or b["end_date"] < a["start_date"]
                )
                contradictory = (a["mode"], a.get("template_id")) != (
                    b["mode"], b.get("template_id")
                )
                if same_target and overlaps and contradictory:
                    conflicts.append(
                        f"Date exception {a['label']} overlaps {b['label']} "
                        f"for {a['target_type']} {a['target_value'] or 'all'}"
                    )
        return conflicts


    def list_policy_groups(self):
        """Return the operator-managed aggregate policy-group catalogue."""
        services = {item["key"]: item for item in self.list_services()}
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM aggregate_policy_groups ORDER BY name COLLATE NOCASE"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["members"] = sorted({
                str(value).strip().lower()
                for value in json.loads(item.get("members") or "[]")
                if str(value).strip()
            })
            item["builtin"] = bool(item.get("builtin"))
            item["member_names"] = [
                services.get(key, {}).get("name") or key for key in item["members"]
            ]
            result.append(item)
        return result

    def policy_group_catalog(self):
        return normalized_group_catalog({item["key"]: item for item in self.list_policy_groups()})

    def policy_group_keys(self):
        return frozenset(self.policy_group_catalog())

    def _validate_policy_group_members(self, members, *, current_key=""):
        groups = self.policy_group_catalog()
        services = {item["key"]: item for item in self.list_services()}
        group_keys = set(groups)
        clean = sorted({
            str(value or "").strip().lower()
            for value in (members or ())
            if str(value or "").strip()
        })
        if not clean:
            raise ValueError("Aggregate policy group must contain at least one concrete service")
        nested = sorted(set(clean) & group_keys)
        if nested:
            raise ValueError(
                "Aggregate policy groups cannot contain other aggregate groups: "
                + ", ".join(nested)
            )
        missing = sorted(key for key in clean if key not in services)
        if missing:
            raise ValueError("Unknown concrete service(s): " + ", ".join(missing))
        return clean

    def _new_policy_group_key(self, name):
        base = re.sub(r"[^a-z0-9_]+", "_", str(name or "").strip().lower()).strip("_")
        if not base:
            base = "group"
        base = base[:32]
        reserved = {item["key"] for item in self.list_services()} | set(self.policy_group_keys())
        if base not in reserved:
            return base
        for suffix in range(2, 1000):
            candidate = f"{base[:27]}_{suffix}"
            if candidate not in reserved:
                return candidate
        raise ValueError("Unable to allocate a unique aggregate policy-group key")

    def create_policy_group(self, name, description="", members=()):
        name = str(name or "").strip()
        if not name or len(name) > 50:
            raise ValueError("Aggregate policy group name must be 1-50 characters")
        existing_names = {item["name"].casefold() for item in self.list_policy_groups()}
        if name.casefold() in existing_names:
            raise ValueError("An aggregate policy group with that name already exists")
        clean = self._validate_policy_group_members(members)
        key = self._new_policy_group_key(name)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.config_write(scope="policy-groups", reason="Aggregate policy group created") as db:
            try:
                db.execute(
                    """INSERT INTO aggregate_policy_groups
                       (key, name, description, members, builtin, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 0, ?, ?)""",
                    (key, name, str(description or "").strip()[:250], json.dumps(clean), now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("An aggregate policy group with that name already exists") from exc
        return next(item for item in self.list_policy_groups() if item["key"] == key)

    def update_policy_group(self, key, name, description="", members=()):
        key = str(key or "").strip().lower()
        current = next((item for item in self.list_policy_groups() if item["key"] == key), None)
        if not current:
            raise ValueError("Aggregate policy group not found")
        name = str(name or "").strip()
        if not name or len(name) > 50:
            raise ValueError("Aggregate policy group name must be 1-50 characters")
        duplicate = next(
            (item for item in self.list_policy_groups()
             if item["key"] != key and item["name"].casefold() == name.casefold()),
            None,
        )
        if duplicate:
            raise ValueError("An aggregate policy group with that name already exists")
        clean = self._validate_policy_group_members(members, current_key=key)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.config_write(scope="policy-groups", reason="Aggregate policy group updated") as db:
            try:
                cur = db.execute(
                    """UPDATE aggregate_policy_groups
                       SET name=?, description=?, members=?, updated_at=? WHERE key=?""",
                    (name, str(description or "").strip()[:250], json.dumps(clean), now, key),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("An aggregate policy group with that name already exists") from exc
            if cur.rowcount != 1:
                raise ValueError("Aggregate policy group not found")
        return next(item for item in self.list_policy_groups() if item["key"] == key)

    def policy_group_usage(self, key):
        key = str(key or "").strip().lower()
        profile_refs = []
        quota_refs = []
        for profile in self.list_profiles():
            if key in set(profile.get("blocked_services") or []):
                profile_refs.append({"id": profile["id"], "name": profile["name"], "kind": "blocked"})
            if key in set((profile.get("service_quotas") or {}).keys()):
                quota_refs.append({"id": profile["id"], "name": profile["name"], "kind": "quota"})
        template_refs = []
        for item in self.list_templates():
            if key in set(item.get("blocked_services") or []) or key in set((item.get("service_quotas") or {}).keys()):
                template_refs.append({"id": item["id"], "name": item["name"]})
        schedule_refs = []
        for item in self.list_schedule_plans():
            if item.get("action_type") != "service":
                continue
            action_key = str(item.get("action_service") or "")
            if not action_key:
                action_key = str(item.get("action_value") or "").split(":", 1)[0]
            if action_key == key:
                schedule_refs.append({"id": item["id"], "name": item["label"]})
        collection_refs = []
        for item in self.list_service_groups():
            if key in set(item.get("services") or []):
                collection_refs.append({"id": item["id"], "name": item["name"]})
        total = len(profile_refs) + len(quota_refs) + len(template_refs) + len(schedule_refs) + len(collection_refs)
        return {
            "key": key,
            "total": total,
            "profiles": profile_refs,
            "quotas": quota_refs,
            "templates": template_refs,
            "schedules": schedule_refs,
            "collections": collection_refs,
            "in_use": bool(total),
        }

    def delete_policy_group(self, key):
        key = str(key or "").strip().lower()
        current = next((item for item in self.list_policy_groups() if item["key"] == key), None)
        if not current:
            raise ValueError("Aggregate policy group not found")
        if current.get("builtin"):
            raise ValueError("Built-in aggregate policy groups cannot be deleted; rename or update their membership instead")
        usage = self.policy_group_usage(key)
        if usage["in_use"]:
            raise ValueError(
                f"Aggregate policy group is still referenced by {usage['total']} policy reference(s); remove those references before deleting it"
            )
        with self.config_write(scope="policy-groups", reason="Aggregate policy group deleted") as db:
            cur = db.execute("DELETE FROM aggregate_policy_groups WHERE key=?", (key,))
            if cur.rowcount != 1:
                raise ValueError("Aggregate policy group not found")

    def list_service_groups(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM service_groups ORDER BY name COLLATE NOCASE"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["services"] = json.loads(item["services"] or "[]")
            result.append(item)
        return result

    def save_service_group(self, name, description="", services=()):
        name = name.strip()
        if not name or len(name) > 50:
            raise ValueError("Service group name must be 1-50 characters")
        valid = {s["key"] for s in self.list_services()} | set(self.policy_group_keys())
        clean = sorted({str(s).strip().lower() for s in services if str(s).strip().lower() in valid})
        with self.config_write(scope="service-groups", reason="Service collection created") as db:
            try:
                cur = db.execute(
                    """INSERT INTO service_groups (name, description, services)
                       VALUES (?, ?, ?)""",
                    (name, description.strip()[:200], json.dumps(clean)),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A service group with that name already exists") from exc
        return cur.lastrowid

    def apply_service_group(self, group_id, profile_id, action):
        action = str(action or "").strip().lower()
        if action not in {"block", "allow"}:
            raise ValueError("Service collection action must be block or allow")
        group_id = int(group_id)
        profile_id = int(profile_id)
        group = next(
            (item for item in self.list_service_groups() if item["id"] == group_id),
            None,
        )
        if not group:
            raise ValueError("Service collection not found")
        profile = self.get_profile(profile_id)
        if not profile:
            raise ValueError("Profile not found")

        current = set(profile.get("blocked_services") or [])
        members = {str(item).strip().lower() for item in group.get("services", [])}
        expanded = expand_policy_keys(
            members, supported_service_keys=self.routeros_supported_service_keys(),
            policy_groups=self.policy_group_catalog(),
        )
        if action == "block":
            # Preserve built-in group keys so the profile retains aggregate
            # policy intent; custom unsupported services remain visible as
            # staged desired policy rather than being silently discarded.
            current.update(members)
        else:
            current.difference_update(members)
            current.difference_update(expanded["effective_services"])

        return self.update_profile(
            profile_id,
            profile["name"],
            profile["desired_mode"],
            profile["bandwidth_preset"],
            profile.get("notes", ""),
            sorted(current),
            profile.get("daily_quota_mb", 0),
            profile.get("daily_quota_action", "blocked"),
            profile.get("service_quotas", {}),
        )

    def delete_service_group(self, group_id):
        with self.config_write(scope="service-groups", reason="Service collection deleted") as db:
            cur = db.execute("DELETE FROM service_groups WHERE id=?", (group_id,))
            if cur.rowcount != 1:
                raise ValueError("Service group not found")

    def list_schedule_templates(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM schedule_templates ORDER BY name COLLATE NOCASE"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["entries"] = json.loads(item["entries"] or "[]")
            result.append(item)
        return result

    @staticmethod
    def _normalize_schedule_template_entries(entries):
        if not isinstance(entries, (list, tuple)):
            raise ValueError("Schedule template entries must be a list")
        clean = []
        slot_modes = {}
        valid_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Each schedule template entry must be an object")
            days = []
            for raw_day in entry.get("days", []) or []:
                day = str(raw_day).strip().lower()
                if day in valid_days and day not in days:
                    days.append(day)
            clock_time = str(entry.get("time", "")).strip()
            mode = str(entry.get("mode", "")).strip().lower()
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", clock_time):
                raise ValueError("Template times must use a valid 24-hour HH:MM value")
            if mode not in {"normal", "slow", "blocked"}:
                raise ValueError("Template modes must be normal, slow or blocked")
            if not days:
                raise ValueError("Each template entry needs at least one day")
            for day in days:
                slot = (day, clock_time)
                previous = slot_modes.get(slot)
                if previous is not None and previous != mode:
                    raise ValueError(
                        "Schedule template has conflicting modes for "
                        f"{day.upper()} at {clock_time}: {previous.upper()} and {mode.upper()}"
                    )
                slot_modes[slot] = mode
            clean.append({"days": days, "time": clock_time, "mode": mode})
        if not clean:
            raise ValueError("A schedule template needs at least one entry")
        return clean

    def save_schedule_template(self, name, description, entries):
        name = name.strip()
        if not name or len(name) > 50:
            raise ValueError("Template name must be 1-50 characters")
        clean = self._normalize_schedule_template_entries(entries)
        with self.config_write(scope="schedule-templates", reason="Schedule template created") as db:
            try:
                cur = db.execute(
                    """INSERT INTO schedule_templates (name, description, entries)
                       VALUES (?, ?, ?)""",
                    (name, description.strip()[:200], json.dumps(clean)),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A schedule template with that name already exists") from exc
        return cur.lastrowid

    def delete_schedule_template(self, template_id):
        with self.config_write(scope="schedule-templates", reason="Schedule template deleted") as db:
            in_use = db.execute(
                "SELECT COUNT(*) AS count FROM date_exceptions WHERE template_id=?",
                (int(template_id),),
            ).fetchone()["count"]
            if in_use:
                raise ValueError(
                    "Schedule template is used by a date exception; remove the exception first"
                )
            cur = db.execute("DELETE FROM schedule_templates WHERE id=?", (template_id,))
            if cur.rowcount != 1:
                raise ValueError("Schedule template not found")

    def list_date_exceptions(self):
        with self._db() as db:
            rows = db.execute(
                """SELECT e.*, t.name AS template_name
                   FROM date_exceptions e
                   LEFT JOIN schedule_templates t ON t.id=e.template_id
                   ORDER BY start_date, label COLLATE NOCASE"""
            ).fetchall()
        return [dict(r) for r in rows]

    def save_date_exception(
        self,
        label,
        start_date,
        end_date,
        target_type,
        target_value,
        mode,
        template_id=None,
        notes="",
    ):
        label = label.strip()
        if not label:
            raise ValueError("Exception label is required")
        target_type, target_value = self._validate_schedule_target(
            target_type, target_value
        )
        if mode not in {"normal","slow","blocked","template"}:
            raise ValueError("Invalid exception mode")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", start_date) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", end_date):
            raise ValueError("Dates must use YYYY-MM-DD")
        try:
            start_obj = date.fromisoformat(start_date)
            end_obj = date.fromisoformat(end_date)
        except ValueError as exc:
            raise ValueError("Date exception contains an invalid calendar date") from exc
        if end_obj < start_obj:
            raise ValueError("End date must not be before start date")
        if mode == "template":
            if not template_id:
                raise ValueError("Select a schedule template")
            template_id = int(template_id)
            if not any(t["id"] == template_id for t in self.list_schedule_templates()):
                raise ValueError("Schedule template not found")
        else:
            template_id = None

        with self.config_write(scope="date-exceptions", reason="Date exception created") as db:
            cur = db.execute(
                """INSERT INTO date_exceptions
                   (label, start_date, end_date, target_type, target_value, mode, template_id, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    label[:60], start_date, end_date, target_type, target_value,
                    mode, template_id, notes.strip()[:200]
                ),
            )
        return cur.lastrowid

    def delete_date_exception(self, exception_id):
        with self.config_write(scope="date-exceptions", reason="Date exception deleted") as db:
            cur = db.execute("DELETE FROM date_exceptions WHERE id=?", (exception_id,))
            if cur.rowcount != 1:
                raise ValueError("Date exception not found")

    def simulate_policy(self, ip, date_iso, clock_time):
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(date_iso)):
            raise ValueError("Simulation date must use YYYY-MM-DD")
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", str(clock_time)):
            raise ValueError("Simulation time must use HH:MM")
        try:
            date.fromisoformat(str(date_iso))
        except ValueError as exc:
            raise ValueError("Simulation date is invalid") from exc

        result = self.compute_effective_policy(
            ip, at=f"{date_iso}T{clock_time}:00"
        )
        result = dict(result)
        result["date"] = str(date_iso)
        result["time"] = str(clock_time)
        result["reason"] = result.get("mode_source", "default")
        result["next_action"] = result.get("next_policy_action")
        return result

    def export_config(self):
        return {
            "version": 1,
            "profiles": self.list_profiles(),
            "device_policy": list(self.list_device_policy().values()),
            "policy_templates": self.list_templates(),
            "bandwidth_presets": self.list_bandwidth_presets(),
            "services": self.list_services(),
            "aggregate_policy_groups": self.list_policy_groups(),
            "service_groups": self.list_service_groups(),
            "schedule_plans": self.list_schedule_plans(),
            "schedule_templates": self.list_schedule_templates(),
            "date_exceptions": self.list_date_exceptions(),
            "app_settings": self.get_settings(),
        }

    @staticmethod
    def _canonical_import_policy_key(value):
        return str(value or "").strip().lower()

    @staticmethod
    def _validate_import_policy_references(payload, allowed_keys):
        """Reject unresolved policy/group references before destructive restore.

        Profile/template/service-collection writers historically filtered unknown
        block keys while restoring. That is acceptable for interactive form
        normalization, but not for backup restore: silently dropping a stable
        aggregate-group key changes desired policy while making the import look
        successful.
        """
        allowed = set(allowed_keys or ())

        def check(values, context):
            if values is None:
                return
            if isinstance(values, dict):
                values = values.keys()
            if isinstance(values, str):
                values = [values]
            unknown = sorted({
                PolicyStore._canonical_import_policy_key(value)
                for value in (values or ())
                if PolicyStore._canonical_import_policy_key(value) not in allowed
            })
            if unknown:
                raise ValueError(
                    f"Configuration {context} references unknown service or aggregate policy group(s): "
                    + ", ".join(unknown)
                )

        for profile in payload.get("profiles", []) or []:
            if not isinstance(profile, dict):
                continue
            check(profile.get("blocked_services", []), "profile")
            check(profile.get("service_quotas", {}), "profile quota")

        for template in payload.get("policy_templates", []) or []:
            if not isinstance(template, dict):
                continue
            check(template.get("blocked_services", []), "policy template")
            check(template.get("service_quotas", {}), "policy template quota")

        for collection in payload.get("service_groups", []) or []:
            if not isinstance(collection, dict):
                continue
            check(collection.get("services", []), "reusable service collection")

        for plan in payload.get("schedule_plans", []) or []:
            if not isinstance(plan, dict) or str(plan.get("action_type") or "").strip().lower() != "service":
                continue
            raw = str(plan.get("action_value") or "").strip().lower()
            if ":" not in raw:
                raise ValueError(
                    "Configuration service schedule action must use service:block or service:allow"
                )
            key, state = [part.strip() for part in raw.split(":", 1)]
            check([key], "service schedule")
            if state not in {"block", "blocked", "deny", "allow", "allowed"}:
                raise ValueError(
                    "Configuration service schedule state must be block or allow"
                )

    def _preflight_import_schedule_contract(self, payload):
        """Reject ambiguous schedule-template identity before restore mutation."""
        templates = payload.get("schedule_templates", []) or []
        exceptions = payload.get("date_exceptions", []) or []
        if not isinstance(templates, list):
            raise ValueError("Configuration schedule templates must be a list")
        if not isinstance(exceptions, list):
            raise ValueError("Configuration date exceptions must be a list")

        template_ids = set()
        template_names = set()
        for index, item in enumerate(templates):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Configuration schedule template #{index + 1} must be an object"
                )
            name = str(item.get("name") or "").strip()
            if not name or len(name) > 50:
                raise ValueError("Template name must be 1-50 characters")
            name_key = name.casefold()
            if name_key in template_names:
                raise ValueError(
                    f"Configuration contains duplicate schedule template name '{name}'"
                )
            template_names.add(name_key)
            template_id = item.get("id")
            if template_id is not None:
                identity = str(template_id)
                if identity in template_ids:
                    raise ValueError(
                        f"Configuration contains duplicate schedule template id '{identity}'"
                    )
                template_ids.add(identity)
            self._normalize_schedule_template_entries(item.get("entries", []))

        for index, item in enumerate(exceptions):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Configuration date exception #{index + 1} must be an object"
                )
            if str(item.get("mode") or "").strip().lower() != "template":
                continue
            template_id = item.get("template_id")
            if template_id is None or str(template_id) not in template_ids:
                label = str(item.get("label") or f"#{index + 1}")
                raise ValueError(
                    f"Configuration date exception '{label}' references a missing schedule template"
                )

    def _preflight_import_policy_groups(self, payload):
        """Validate aggregate-group identity and references before import mutation.

        The v0.48 restore contract is deliberately stricter than interactive
        form cleanup. Stable machine keys are configuration identity: restore
        must never truncate, silently rename, silently omit or partially merge
        them. A pre-v0.35 export is recognized only by the complete absence of
        the aggregate-policy-group section and retains the documented default
        built-in reset behavior.
        """
        has_group_section = "aggregate_policy_groups" in payload
        raw_groups = payload.get("aggregate_policy_groups") if has_group_section else []
        if has_group_section and not isinstance(raw_groups, list):
            raise ValueError("Configuration aggregate policy groups must be a list")

        current_builtin_rows = [
            item for item in self.list_services() if item.get("builtin")
        ]
        current_builtin_services = {
            str(item.get("key") or "").strip().lower()
            for item in current_builtin_rows
            if str(item.get("key") or "").strip()
        }
        current_builtin_names = {
            str(item.get("name") or "").strip()
            for item in current_builtin_rows
            if str(item.get("name") or "").strip()
        }
        imported_services = payload.get("services", []) or []
        if not isinstance(imported_services, list):
            raise ValueError("Configuration services must be a list")
        imported_service_keys = set()
        imported_service_names = set()
        for index, item in enumerate(imported_services):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Configuration service #{index + 1} must be an object"
                )
            if item.get("builtin"):
                key = self._canonical_import_policy_key(item.get("key"))
                if key:
                    imported_service_keys.add(key)
                continue

            raw_key = str(item.get("key") or "").strip()
            key = self._canonical_import_policy_key(raw_key)
            if raw_key != key or not re.fullmatch(r"[a-z0-9][a-z0-9_]{0,39}", key):
                raise ValueError(
                    f"Imported custom service stable key '{raw_key}' is invalid"
                )
            if key in current_builtin_services or key in imported_service_keys:
                raise ValueError(
                    f"Configuration contains duplicate or built-in-conflicting custom service key '{key}'"
                )

            name = str(item.get("name") or "").strip()
            if not name or len(name) > 50:
                raise ValueError(
                    f"Imported custom service '{key}' name must be 1-50 characters"
                )
            name_identity = name
            if name_identity in current_builtin_names or name_identity in imported_service_names:
                raise ValueError(
                    f"Configuration contains duplicate or built-in-conflicting custom service name '{name}'"
                )
            description = str(item.get("description") or "").strip()
            if len(description) > 160:
                raise ValueError(
                    f"Imported custom service '{key}' description exceeds 160 characters"
                )
            category = str(item.get("category") or "other").strip().lower() or "other"
            if len(category) > 30 or not re.fullmatch(r"[a-z0-9_-]+", category):
                raise ValueError(
                    f"Imported custom service '{key}' category is invalid"
                )
            dns_suffixes = self._normalize_dns_suffixes(item.get("dns_suffixes", []))
            tls_patterns = self._normalize_tls_patterns(item.get("tls_patterns", []))
            if item.get("enforcement_approved"):
                try:
                    build_custom_service_contract({
                        "key": key,
                        "name": name,
                        "description": description,
                        "category": category,
                        "dns_suffixes": dns_suffixes,
                        "tls_patterns": tls_patterns,
                        "builtin": False,
                    })
                except ValueError as exc:
                    raise ValueError(
                        f"Imported custom service '{key}' RouterOS contract is invalid: {exc}"
                    ) from exc
            imported_service_keys.add(key)
            imported_service_names.add(name_identity)

        restored_service_keys = current_builtin_services | imported_service_keys

        if not has_group_section:
            group_keys = set(POLICY_GROUPS)
            self._validate_import_policy_references(
                payload, restored_service_keys | group_keys
            )
            return {
                "legacy": True,
                "groups": [],
                "group_keys": frozenset(group_keys),
            }

        canonical = []
        seen_keys = set()
        seen_names = set()
        for index, raw in enumerate(raw_groups):
            if not isinstance(raw, dict):
                raise ValueError(
                    f"Configuration aggregate policy group #{index + 1} must be an object"
                )
            raw_key = str(raw.get("key") or "").strip()
            key = self._canonical_import_policy_key(raw_key)
            if (
                raw_key != key
                or not re.fullmatch(r"[a-z0-9][a-z0-9_]{0,39}", key)
            ):
                raise ValueError(
                    f"Imported aggregate policy-group stable key '{raw_key}' is invalid; keys must be canonical lowercase identifiers up to 40 characters"
                )
            if key in seen_keys:
                raise ValueError(
                    f"Configuration contains duplicate aggregate policy-group key '{key}'"
                )
            seen_keys.add(key)

            name = str(raw.get("name") or "").strip()
            if not name or len(name) > 50:
                raise ValueError(
                    f"Imported aggregate policy group '{key}' name must be 1-50 characters"
                )
            name_identity = name.casefold()
            if name_identity in seen_names:
                raise ValueError(
                    f"Configuration contains duplicate aggregate policy-group name '{name}'"
                )
            seen_names.add(name_identity)

            description = str(raw.get("description") or "").strip()
            if len(description) > 250:
                raise ValueError(
                    f"Imported aggregate policy group '{key}' description exceeds 250 characters"
                )

            expected_builtin = key in POLICY_GROUPS
            supplied_builtin = bool(raw.get("builtin"))
            if supplied_builtin != expected_builtin:
                role = "built-in" if expected_builtin else "custom"
                raise ValueError(
                    f"Imported aggregate policy-group stable key '{key}' has invalid built-in identity; it must remain {role}"
                )
            if not expected_builtin and key in restored_service_keys:
                raise ValueError(
                    f"Imported aggregate policy-group stable key '{key}' conflicts with a concrete service"
                )

            members = raw.get("members", [])
            if not isinstance(members, (list, tuple)):
                raise ValueError(
                    f"Imported aggregate policy group '{key}' members must be a list"
                )
            normalized_members = [
                self._canonical_import_policy_key(value)
                for value in members
                if self._canonical_import_policy_key(value)
            ]
            if not normalized_members:
                raise ValueError(
                    f"Imported aggregate policy group '{key}' must contain at least one concrete service"
                )
            if len(normalized_members) != len(set(normalized_members)):
                raise ValueError(
                    f"Imported aggregate policy group '{key}' contains duplicate concrete-service members"
                )

            canonical.append({
                "key": key,
                "name": name,
                "description": description,
                "members": sorted(normalized_members),
                "builtin": expected_builtin,
            })

        builtin_keys = {item["key"] for item in canonical if item["builtin"]}
        expected_builtin_keys = set(POLICY_GROUPS)
        if builtin_keys != expected_builtin_keys:
            missing = sorted(expected_builtin_keys - builtin_keys)
            extra = sorted(builtin_keys - expected_builtin_keys)
            detail = []
            if missing:
                detail.append("missing " + ", ".join(missing))
            if extra:
                detail.append("unexpected " + ", ".join(extra))
            raise ValueError(
                "Configuration must contain the complete built-in aggregate policy groups"
                + (": " + "; ".join(detail) if detail else "")
            )

        group_keys = {item["key"] for item in canonical}
        for item in canonical:
            nested = sorted(set(item["members"]) & group_keys)
            if nested:
                raise ValueError(
                    "Aggregate policy groups cannot contain other aggregate groups: "
                    + ", ".join(nested)
                )
            missing = sorted(
                member for member in item["members"]
                if member not in restored_service_keys
            )
            if missing:
                raise ValueError(
                    f"Imported aggregate policy group '{item['key']}' references unknown concrete service(s): "
                    + ", ".join(missing)
                )

        self._validate_import_policy_references(
            payload, restored_service_keys | group_keys
        )
        return {
            "legacy": False,
            "groups": canonical,
            "group_keys": frozenset(group_keys),
        }

    def import_config(self, payload):
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError("Unsupported configuration format")

        self._preflight_import_schedule_contract(payload)
        aggregate_restore = self._preflight_import_policy_groups(payload)

        with self._db() as db:
            # Only container-local policy tables are replaced.
            for table in [
                "profiles","device_policy","policy_templates","service_groups",
                "schedule_plans","schedule_templates","date_exceptions"
            ]:
                db.execute(f"DELETE FROM {table}")

            # Custom presets/services/groups are replaced; built-ins are retained.
            db.execute("DELETE FROM bandwidth_presets WHERE builtin=0")
            db.execute("DELETE FROM services WHERE builtin=0")
            db.execute("DELETE FROM aggregate_policy_groups WHERE builtin=0")

        # Recreate data through public methods where possible. Custom bandwidth
        # presets must exist before profiles that reference them are restored.
        for bp in payload.get("bandwidth_presets", []):
            if not bp.get("builtin"):
                self.save_bandwidth_preset(
                    bp["key"], bp["name"], bp["upload"], bp["download"], bp.get("description","")
                )

        # Restore custom service definitions before profiles so profile blocks and
        # service quotas retain custom keys. Restoring recorded approval changes
        # local desired state only; PolicyStore never writes RouterOS authority.
        for svc in payload.get("services", []):
            if not svc.get("builtin"):
                self.save_service(
                    svc["key"], svc["name"], svc.get("description", ""),
                    svc.get("category", "other"), svc.get("dns_suffixes", []),
                    svc.get("tls_patterns", []), svc.get("classifier_enabled", True),
                )
                if svc.get("enforcement_approved"):
                    self.set_service_enforcement_approved(svc["key"], True)

        # Aggregate policy groups are restored before profiles because profile
        # blocked-service/quota state can reference their stable machine keys.
        imported_policy_groups = aggregate_restore["groups"]
        if aggregate_restore["legacy"]:
            # Backward-compatible restore from pre-v0.35 exports: reset built-ins
            # to the product defaults instead of carrying unrelated current-state
            # membership into the restored configuration.
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with self._db() as db:
                for key, group in POLICY_GROUPS.items():
                    db.execute(
                        """UPDATE aggregate_policy_groups
                           SET name=?, description=?, members=?, updated_at=? WHERE key=?""",
                        (group["name"], group.get("description", ""), json.dumps(sorted(group.get("members") or [])), now, key),
                    )
        for group in imported_policy_groups:
            key = str(group.get("key") or "").strip().lower()
            name = str(group.get("name") or "").strip()
            if not key or not name:
                continue
            clean = self._validate_policy_group_members(group.get("members", []), current_key=key)
            builtin = bool(group.get("builtin")) and key in POLICY_GROUPS
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with self._db() as db:
                if builtin:
                    db.execute(
                        """UPDATE aggregate_policy_groups
                           SET name=?, description=?, members=?, updated_at=? WHERE key=?""",
                        (name[:50], str(group.get("description") or "")[:250], json.dumps(clean), now, key),
                    )
                else:
                    service_keys = {item["key"] for item in self.list_services()}
                    if key in service_keys or key in POLICY_GROUPS:
                        raise ValueError(f"Imported aggregate policy-group key '{key}' conflicts with a service or built-in group")
                    db.execute(
                        """INSERT INTO aggregate_policy_groups
                           (key, name, description, members, builtin, created_at, updated_at)
                           VALUES (?, ?, ?, ?, 0, ?, ?)""",
                        (key, name, str(group.get("description") or ""), json.dumps(clean), now, now),
                    )

        profile_map = {}
        for p in payload.get("profiles", []):
            new = self.create_profile(
                p["name"], p["desired_mode"], p["bandwidth_preset"],
                p.get("notes",""), p.get("blocked_services",[]),
                p.get("daily_quota_mb", 0),
                p.get("daily_quota_action", "blocked"),
                p.get("service_quotas", {}),
            )
            profile_map[str(p.get("id"))] = new["id"]

        # Policy templates are independent reusable profile presets. Older
        # import code exported them but did not restore them; this closes that
        # backup/restore gap while remaining backward compatible with older exports.
        with self._db() as db:
            for template in payload.get("policy_templates", []):
                name = str(template.get("name") or "").strip()
                if not name:
                    continue
                db.execute(
                    """INSERT INTO policy_templates
                       (name, desired_mode, bandwidth_preset, notes, blocked_services,
                        daily_quota_mb, daily_quota_action, service_quotas)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        name[:50],
                        self._validate_mode(template.get("desired_mode", "normal")),
                        self._validate_preset(template.get("bandwidth_preset", "normal")),
                        str(template.get("notes") or "")[:250],
                        json.dumps(self._validate_services(template.get("blocked_services", []))),
                        normalize_quota_mb(template.get("daily_quota_mb", 0), field="Template daily data quota"),
                        normalize_quota_action(template.get("daily_quota_action", "blocked")),
                        json.dumps(normalize_service_quotas(
                            template.get("service_quotas", {}),
                            supported_service_keys=self.routeros_supported_service_keys() | self.policy_group_keys(),
                        ), sort_keys=True),
                    ),
                )

        for d in payload.get("device_policy", []):
            mapped_profile = profile_map.get(str(d.get("profile_id"))) if d.get("profile_id") else None
            self.update_device(
                d["ip"], d.get("alias",""), d.get("notes",""), mapped_profile,
                d.get("mode_override","inherit"), d.get("category","other"),
                bool(d.get("favourite",0))
            )

        for g in payload.get("service_groups", []):
            self.save_service_group(g["name"], g.get("description",""), g.get("services",[]))

        for sp in payload.get("schedule_plans", []):
            target_value = sp.get("target_value","")
            if sp.get("target_type") == "profile" and target_value:
                target_value = str(profile_map.get(str(target_value), target_value))
            new_plan_id = self.create_schedule_plan(
                sp["label"], sp["target_type"], target_value, sp["action_type"],
                sp["action_value"], sp["clock_time"], sp.get("days",[])
            )
            if not bool(sp.get("enabled", 1)):
                self.set_schedule_plan_enabled(new_plan_id, False)

        template_map = {}
        for st in payload.get("schedule_templates", []):
            new_id = self.save_schedule_template(
                st["name"], st.get("description",""), st.get("entries",[])
            )
            template_map[str(st.get("id"))] = new_id

        for ex in payload.get("date_exceptions", []):
            target_value = ex.get("target_value","")
            if ex.get("target_type") == "profile" and target_value:
                target_value = str(profile_map.get(str(target_value), target_value))
            template_id = template_map.get(str(ex.get("template_id"))) if ex.get("template_id") else None
            self.save_date_exception(
                ex["label"], ex["start_date"], ex["end_date"], ex["target_type"],
                target_value, ex["mode"], template_id, ex.get("notes","")
            )

        imported_settings = payload.get("app_settings") or {}
        if imported_settings:
            current_settings = self.get_settings()
            imported_default_profile = imported_settings.get(
                "default_profile_id", current_settings.get("default_profile_id", "")
            )
            if imported_default_profile:
                imported_default_profile = str(
                    profile_map.get(
                        str(imported_default_profile), imported_default_profile
                    )
                )
            self.save_settings(
                imported_default_profile,
                imported_settings.get("default_category", current_settings.get("default_category", "other")),
                imported_settings.get("default_bandwidth_preset", current_settings.get("default_bandwidth_preset", "normal")),
                imported_settings.get("default_temp_minutes", current_settings.get("default_temp_minutes", "30")),
                imported_settings.get("policy_timezone", current_settings.get("policy_timezone", "Europe/London")),
                imported_settings.get("auto_reconcile_mode", current_settings.get("auto_reconcile_mode", "off")),
                imported_settings.get("auto_reconcile_interval_seconds", current_settings.get("auto_reconcile_interval_seconds", "30")),
                imported_settings.get("auto_reconcile_failure_threshold", current_settings.get("auto_reconcile_failure_threshold", "3")),
                imported_settings.get("auto_reconcile_cooldown_seconds", current_settings.get("auto_reconcile_cooldown_seconds", "300")),
            )
            self.save_reward_settings(
                imported_settings.get("reward_bank_enabled", current_settings.get("reward_bank_enabled", "1")),
                imported_settings.get("reward_bank_max_minutes", current_settings.get("reward_bank_max_minutes", "240")),
                imported_settings.get("reward_default_grant_minutes", current_settings.get("reward_default_grant_minutes", "30")),
                imported_settings.get("reward_max_redeem_minutes", current_settings.get("reward_max_redeem_minutes", "60")),
            )
            self.save_quota_settings(
                imported_settings.get("quota_engine_enabled", current_settings.get("quota_engine_enabled", "0")),
                imported_settings.get("quota_warning_percent", current_settings.get("quota_warning_percent", "80")),
            )
            self.save_incident_settings(
                imported_settings.get("incident_monitor_enabled", current_settings.get("incident_monitor_enabled", "1")),
                imported_settings.get("incident_scan_interval_seconds", current_settings.get("incident_scan_interval_seconds", "60")),
                imported_settings.get("incident_bypass_min_status", current_settings.get("incident_bypass_min_status", "elevated")),
                imported_settings.get("incident_retention_days", current_settings.get("incident_retention_days", "30")),
            )
            self.save_summary_delivery_settings(
                imported_settings.get("summary_delivery_enabled", current_settings.get("summary_delivery_enabled", "0")),
                imported_settings.get("summary_delivery_time", current_settings.get("summary_delivery_time", "07:00")),
                imported_settings.get("summary_delivery_period", current_settings.get("summary_delivery_period", "yesterday")),
                imported_settings.get("summary_delivery_email_enabled", current_settings.get("summary_delivery_email_enabled", "0")),
                imported_settings.get("summary_delivery_email_to", current_settings.get("summary_delivery_email_to", "")),
                imported_settings.get("summary_delivery_webhook_enabled", current_settings.get("summary_delivery_webhook_enabled", "0")),
                imported_settings.get("summary_delivery_webhook_url", current_settings.get("summary_delivery_webhook_url", "")),
                imported_settings.get("summary_delivery_retry_limit", current_settings.get("summary_delivery_retry_limit", "3")),
                imported_settings.get("summary_delivery_retention_days", current_settings.get("summary_delivery_retention_days", "90")),
            )

    def save_summary_delivery_settings(
        self,
        enabled="0",
        delivery_time="07:00",
        period="yesterday",
        email_enabled="0",
        email_to="",
        webhook_enabled="0",
        webhook_url="",
        retry_limit="3",
        retention_days="90",
        *,
        expected_revision=None,
        actor="system:policy-store",
    ):
        enabled = "1" if str(enabled).strip().lower() in {"1", "true", "yes", "on"} else "0"
        email_enabled = "1" if str(email_enabled).strip().lower() in {"1", "true", "yes", "on"} else "0"
        webhook_enabled = "1" if str(webhook_enabled).strip().lower() in {"1", "true", "yes", "on"} else "0"
        delivery_time = normalize_delivery_time(delivery_time)
        period = str(period or "yesterday").strip().lower()
        if period not in {"today", "yesterday"}:
            raise ValueError("Summary delivery period must be today or yesterday")
        recipients = normalize_email_recipients(email_to)
        webhook_url = normalize_webhook_url(webhook_url)
        if email_enabled == "1" and not recipients:
            raise ValueError("Email summary delivery requires at least one recipient")
        if webhook_enabled == "1" and not webhook_url:
            raise ValueError("Webhook summary delivery requires a URL")
        if enabled == "1" and email_enabled != "1" and webhook_enabled != "1":
            raise ValueError("Enable at least one summary delivery channel")
        retry_limit = str(retry_limit or "3").strip()
        if retry_limit not in {"1", "2", "3", "5"}:
            raise ValueError("Summary retry limit must be 1, 2, 3 or 5 attempts")
        retention_days = str(retention_days or "90").strip()
        if retention_days not in {"30", "90", "180", "365"}:
            raise ValueError("Summary delivery retention must be 30, 90, 180 or 365 days")
        values = {
            "summary_delivery_enabled": enabled,
            "summary_delivery_time": delivery_time,
            "summary_delivery_period": period,
            "summary_delivery_email_enabled": email_enabled,
            "summary_delivery_email_to": ", ".join(recipients),
            "summary_delivery_webhook_enabled": webhook_enabled,
            "summary_delivery_webhook_url": webhook_url,
            "summary_delivery_retry_limit": retry_limit,
            "summary_delivery_retention_days": retention_days,
        }
        with self.config_write(
            scope="settings:summary-delivery",
            reason="Summary delivery settings updated",
            actor=actor,
            expected_revision=expected_revision,
        ) as db:
            for key, value in values.items():
                db.execute(
                    """INSERT INTO app_settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (key, value),
                )
        return values

    @staticmethod
    def _summary_delivery_now_iso():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def enqueue_summary_delivery(
        self, *, report_date, period, channel, destination, payload, kind="scheduled", unique_suffix=""
    ):
        report_date = str(report_date or "").strip()
        period = str(period or "").strip().lower()
        channel = str(channel or "").strip().lower()
        kind = str(kind or "scheduled").strip().lower()
        destination = str(destination or "").strip()[:1000]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", report_date):
            raise ValueError("Summary delivery report date must use YYYY-MM-DD")
        if period not in {"today", "yesterday"}:
            raise ValueError("Summary delivery period must be today or yesterday")
        if channel not in {"email", "webhook"}:
            raise ValueError("Summary delivery channel must be email or webhook")
        if kind not in {"scheduled", "test"}:
            raise ValueError("Summary delivery kind must be scheduled or test")
        if not destination:
            raise ValueError("Summary delivery destination is required")
        if kind == "scheduled":
            idempotency_key = f"scheduled:{report_date}:{period}:{channel}"
        else:
            suffix = str(unique_suffix or self._summary_delivery_now_iso())[:80]
            idempotency_key = f"test:{report_date}:{period}:{channel}:{suffix}"
        now = self._summary_delivery_now_iso()
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        with self._db() as db:
            existing = db.execute(
                "SELECT * FROM summary_deliveries WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing:
                if existing["status"] != "sent":
                    db.execute(
                        """UPDATE summary_deliveries
                           SET destination=?, payload_json=?, updated_at=?
                           WHERE id=?""",
                        (destination, payload_json, now, existing["id"]),
                    )
                    existing = db.execute(
                        "SELECT * FROM summary_deliveries WHERE id=?", (existing["id"],)
                    ).fetchone()
                return {**dict(existing), "created": False}
            cur = db.execute(
                """INSERT INTO summary_deliveries
                   (kind, report_date, period, channel, destination, payload_json,
                    idempotency_key, status, attempts, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)""",
                (kind, report_date, period, channel, destination, payload_json,
                 idempotency_key, now, now),
            )
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (cur.lastrowid,)
            ).fetchone()
        return {**dict(row), "created": True}

    def scheduled_summary_deliveries(self, report_date, period):
        with self._db() as db:
            rows = db.execute(
                """SELECT * FROM summary_deliveries
                   WHERE kind='scheduled' AND report_date=? AND period=?""",
                (str(report_date), str(period)),
            ).fetchall()
        return {row["channel"]: dict(row) for row in rows}

    def update_summary_delivery_destination(self, delivery_id, destination):
        destination = str(destination or "").strip()[:1000]
        if not destination:
            raise ValueError("Summary delivery destination is required")
        now = self._summary_delivery_now_iso()
        with self._db() as db:
            db.execute(
                """UPDATE summary_deliveries SET destination=?, updated_at=?
                   WHERE id=? AND status!='sent'""",
                (destination, now, int(delivery_id)),
            )
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
        if not row:
            raise ValueError("Summary delivery not found")
        return dict(row)

    def cancel_summary_delivery(self, delivery_id, reason="Delivery disabled"):
        now = self._summary_delivery_now_iso()
        with self._db() as db:
            db.execute(
                """UPDATE summary_deliveries
                   SET status='cancelled', updated_at=?, next_attempt_at='', error=?
                   WHERE id=? AND status!='sent'""",
                (now, str(reason or "Delivery disabled")[:500], int(delivery_id)),
            )
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
        if not row:
            raise ValueError("Summary delivery not found")
        return dict(row)

    def cancel_disabled_summary_deliveries(self, *, scheduled_enabled, enabled_channels):
        enabled_channels = {str(item) for item in (enabled_channels or [])}
        now = self._summary_delivery_now_iso()
        with self._db() as db:
            rows = db.execute(
                """SELECT id, kind, channel FROM summary_deliveries
                   WHERE status IN ('pending','retry','sending')"""
            ).fetchall()
            cancel_ids = []
            for row in rows:
                if row["channel"] not in enabled_channels:
                    cancel_ids.append(row["id"])
                elif row["kind"] == "scheduled" and not scheduled_enabled:
                    cancel_ids.append(row["id"])
            for delivery_id in cancel_ids:
                db.execute(
                    """UPDATE summary_deliveries
                       SET status='cancelled', updated_at=?, next_attempt_at='',
                           error='Cancelled after delivery configuration changed'
                       WHERE id=? AND status!='sent'""",
                    (now, delivery_id),
                )
        return len(cancel_ids)

    def recover_summary_deliveries(self):
        now = self._summary_delivery_now_iso()
        with self._db() as db:
            rows = db.execute(
                "SELECT id FROM summary_deliveries WHERE status='sending'"
            ).fetchall()
            if rows:
                db.execute(
                    """UPDATE summary_deliveries
                       SET status='retry', next_attempt_at='', updated_at=?,
                           error=CASE WHEN error='' THEN 'Recovered after interrupted delivery attempt' ELSE error END
                       WHERE status='sending'""",
                    (now,),
                )
        return len(rows)

    def claim_summary_deliveries(self, limit=10, retry_limit=3):
        try:
            limit = max(1, min(int(limit), 50))
            retry_limit = max(1, min(int(retry_limit), 10))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid summary delivery claim limits") from exc
        now = self._summary_delivery_now_iso()
        with self._db() as db:
            rows = db.execute(
                """SELECT * FROM summary_deliveries
                   WHERE status IN ('pending','retry')
                     AND attempts < ?
                     AND (next_attempt_at='' OR next_attempt_at<=?)
                   ORDER BY id ASC LIMIT ?""",
                (retry_limit, now, limit),
            ).fetchall()
            claimed = []
            for row in rows:
                db.execute(
                    """UPDATE summary_deliveries
                       SET status='sending', attempts=attempts+1,
                           last_attempt_at=?, updated_at=?
                       WHERE id=? AND status IN ('pending','retry')""",
                    (now, now, row["id"]),
                )
                current = db.execute(
                    "SELECT * FROM summary_deliveries WHERE id=?", (row["id"],)
                ).fetchone()
                if current and current["status"] == "sending":
                    claimed.append(dict(current))
        return claimed

    def defer_summary_delivery(self, delivery_id, error, delay_seconds=300):
        try:
            delay_seconds = max(30, min(int(delay_seconds), 3600))
        except (TypeError, ValueError):
            delay_seconds = 300
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat(timespec="seconds")
        next_attempt = (now_dt + timedelta(seconds=delay_seconds)).isoformat(timespec="seconds")
        with self._db() as db:
            db.execute(
                """UPDATE summary_deliveries
                   SET status='retry', attempts=CASE WHEN attempts>0 THEN attempts-1 ELSE 0 END,
                       next_attempt_at=?, updated_at=?, error=?
                   WHERE id=? AND status='sending'""",
                (next_attempt, now, str(error or "")[:500], int(delivery_id)),
            )
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
        if not row:
            raise ValueError("Summary delivery not found")
        return dict(row)

    def complete_summary_delivery(self, delivery_id):
        now = self._summary_delivery_now_iso()
        with self._db() as db:
            db.execute(
                """UPDATE summary_deliveries
                   SET status='sent', sent_at=?, updated_at=?, next_attempt_at='', error=''
                   WHERE id=? AND status='sending'""",
                (now, now, int(delivery_id)),
            )
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
        if not row:
            raise ValueError("Summary delivery not found")
        return dict(row)

    def fail_summary_delivery(self, delivery_id, error, retry_limit=3):
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat(timespec="seconds")
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
            if not row:
                raise ValueError("Summary delivery not found")
            attempts = int(row["attempts"] or 0)
            terminal = attempts >= int(retry_limit)
            delay = min(60 * (5 ** max(0, attempts - 1)), 1800)
            next_attempt = "" if terminal else (now_dt + timedelta(seconds=delay)).isoformat(timespec="seconds")
            status = "failed" if terminal else "retry"
            db.execute(
                """UPDATE summary_deliveries
                   SET status=?, next_attempt_at=?, updated_at=?, error=?
                   WHERE id=?""",
                (status, next_attempt, now, str(error or "")[:500], int(delivery_id)),
            )
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
        return dict(row)

    def retry_summary_delivery(self, delivery_id):
        now = self._summary_delivery_now_iso()
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
            if not row:
                raise ValueError("Summary delivery not found")
            if row["status"] == "sent":
                raise ValueError("Sent summary deliveries cannot be retried")
            db.execute(
                """UPDATE summary_deliveries
                   SET status='pending', attempts=0, next_attempt_at='', error='', updated_at=?
                   WHERE id=?""",
                (now, int(delivery_id)),
            )
            row = db.execute(
                "SELECT * FROM summary_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
        return dict(row)

    def list_summary_deliveries(self, limit=50):
        try:
            limit = max(1, min(int(limit), 200))
        except (TypeError, ValueError):
            limit = 50
        with self._db() as db:
            rows = db.execute(
                """SELECT id, kind, report_date, period, channel, destination,
                          idempotency_key, status, attempts, created_at, updated_at,
                          next_attempt_at, last_attempt_at, sent_at, error
                   FROM summary_deliveries ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def summary_delivery_stats(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
        with self._db() as db:
            counts = {
                row["status"]: int(row["c"])
                for row in db.execute(
                    "SELECT status, COUNT(*) AS c FROM summary_deliveries GROUP BY status"
                ).fetchall()
            }
            recent = db.execute(
                """SELECT
                     SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END) AS sent,
                     SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed
                   FROM summary_deliveries WHERE created_at>=?""",
                (cutoff,),
            ).fetchone()
        sent = int((recent["sent"] if recent else 0) or 0)
        failed = int((recent["failed"] if recent else 0) or 0)
        completed = sent + failed
        return {
            "pending": counts.get("pending", 0) + counts.get("retry", 0) + counts.get("sending", 0),
            "sent": counts.get("sent", 0),
            "failed": counts.get("failed", 0),
            "cancelled": counts.get("cancelled", 0),
            "sent_30d": sent,
            "failed_30d": failed,
            "success_percent_30d": round(sent * 100 / completed, 1) if completed else None,
        }

    def prune_summary_deliveries(self, retention_days=90):
        try:
            retention_days = int(retention_days)
        except (TypeError, ValueError):
            retention_days = 90
        retention_days = max(30, min(retention_days, 365))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(timespec="seconds")
        with self._db() as db:
            cur = db.execute(
                """DELETE FROM summary_deliveries
                   WHERE created_at<? AND status IN ('sent','failed','cancelled')""",
                (cutoff,),
            )
        return int(cur.rowcount or 0)

    def stage_legacy_migration(self, source, payload, actor=""):
        """Persist a non-active migration proposal without touching desired policy."""
        source = str(source or "").strip().lower()
        if source != "mikrotik_kid_control":
            raise ValueError("Unsupported legacy migration source")
        if not isinstance(payload, dict) or payload.get("schema") != "zen_kid_control_migration_v1":
            raise ValueError("Unsupported legacy migration payload")
        fingerprint = str(payload.get("source_fingerprint") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("Legacy migration payload has no valid source fingerprint")
        if str(payload.get("source") or "").strip().lower() != source:
            raise ValueError("Legacy migration payload source does not match staging source")

        staged = json.loads(json.dumps(payload))
        staged["state"] = "staged"
        staged.setdefault("authority", {})
        staged["authority"].update({
            "router_reads": True,
            "router_writes": 0,
            "legacy_modified": False,
            "zen_enforcement_active": False,
        })
        staged_at = self._operations_now_iso()
        actor = str(actor or "").strip()[:80]
        encoded = json.dumps(staged, sort_keys=True, separators=(",", ":"))
        with self._db() as db:
            db.execute(
                """INSERT INTO legacy_migration_staging
                   (source, source_fingerprint, staged_at, actor, payload)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(source) DO UPDATE SET
                     source_fingerprint=excluded.source_fingerprint,
                     staged_at=excluded.staged_at,
                     actor=excluded.actor,
                     payload=excluded.payload""",
                (source, fingerprint, staged_at, actor, encoded),
            )
        return self.get_legacy_migration_stage(source)

    def get_legacy_migration_stage(self, source):
        source = str(source or "").strip().lower()
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM legacy_migration_staging WHERE source=?", (source,)
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["state"] = "staged"
        item["payload"] = json.loads(item.get("payload") or "{}")
        return item

    def list_legacy_migration_stages(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM legacy_migration_staging ORDER BY staged_at DESC, source"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["state"] = "staged"
            item["payload"] = json.loads(item.get("payload") or "{}")
            result.append(item)
        return result

    def clear_legacy_migration_stage(self, source):
        source = str(source or "").strip().lower()
        with self._db() as db:
            cur = db.execute("DELETE FROM legacy_migration_staging WHERE source=?", (source,))
        return bool(cur.rowcount)

    def record_legacy_migration_cutover(self, source, state, source_fingerprint, actor="", evidence=None):
        source = str(source or "").strip().lower()
        state = str(state or "").strip().lower()
        if source != "mikrotik_kid_control":
            raise ValueError("Unsupported legacy migration source")
        if state not in {"prepared", "authoritative", "rolled_back", "failed"}:
            raise ValueError("Unsupported legacy migration cutover state")
        fingerprint = str(source_fingerprint or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("Legacy migration cutover fingerprint is invalid")
        actor = str(actor or "").strip()[:80]
        payload = json.dumps(evidence or {}, sort_keys=True, separators=(",", ":"))
        recorded_at = self._operations_now_iso()
        with self._db() as db:
            cur = db.execute(
                """INSERT INTO legacy_migration_cutover_events
                   (source, source_fingerprint, state, recorded_at, actor, evidence)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (source, fingerprint, state, recorded_at, actor, payload),
            )
        return self.get_legacy_migration_cutover(source, event_id=cur.lastrowid)

    def get_legacy_migration_cutover(self, source, event_id=None):
        source = str(source or "").strip().lower()
        with self._db() as db:
            if event_id is None:
                row = db.execute(
                    """SELECT * FROM legacy_migration_cutover_events
                       WHERE source=? ORDER BY id DESC LIMIT 1""",
                    (source,),
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT * FROM legacy_migration_cutover_events WHERE source=? AND id=?",
                    (source, int(event_id)),
                ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item.get("evidence") or "{}")
        return item

    def list_legacy_migration_cutover_events(self, source="mikrotik_kid_control", limit=50):
        source = str(source or "").strip().lower()
        limit = max(1, min(int(limit or 50), 200))
        with self._db() as db:
            rows = db.execute(
                """SELECT * FROM legacy_migration_cutover_events
                   WHERE source=? ORDER BY id DESC LIMIT ?""",
                (source, limit),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item.get("evidence") or "{}")
            result.append(item)
        return result

    @staticmethod
    def _kid_control_profile_matches(existing, proposed):
        return (
            str(existing.get("name") or "").strip() == str(proposed.get("name") or "").strip()
            and str(existing.get("desired_mode") or "").lower() == str(proposed.get("desired_mode") or "").lower()
            and str(existing.get("bandwidth_preset") or "").lower() == str(proposed.get("bandwidth_preset") or "").lower()
            and sorted(existing.get("blocked_services") or []) == sorted(proposed.get("blocked_services") or [])
            and int(existing.get("daily_quota_mb") or 0) == int(proposed.get("daily_quota_mb") or 0)
            and str(existing.get("daily_quota_action") or "blocked").lower() == str(proposed.get("daily_quota_action") or "blocked").lower()
            and dict(existing.get("service_quotas") or {}) == dict(proposed.get("service_quotas") or {})
        )

    def materialize_kid_control_replacement(self, staged):
        """Create/reuse the staged ZEN profile, schedules and device assignments.

        This changes local desired policy only.  It performs no RouterOS writes.
        The returned artifact ledger is sufficient to restore the exact local
        policy state if authority transfer later fails or is rolled back.
        """
        if not isinstance(staged, dict):
            raise ValueError("Staged Kid Control migration is required")
        payload = staged.get("payload") if isinstance(staged.get("payload"), dict) else {}
        if payload.get("schema") != "zen_kid_control_migration_v1":
            raise ValueError("Unsupported staged Kid Control migration payload")
        fingerprint = str(staged.get("source_fingerprint") or payload.get("source_fingerprint") or "").strip().lower()
        if fingerprint != str(payload.get("source_fingerprint") or "").strip().lower():
            raise ValueError("Staged Kid Control fingerprint is inconsistent")
        if int((payload.get("summary") or {}).get("warnings") or 0):
            raise ValueError("Staged Kid Control migration still contains review warnings")

        artifacts = {
            "source_fingerprint": fingerprint,
            "profiles": [],
            "schedules": [],
            "devices": [],
        }
        profile_ids = {}
        try:
            existing_profiles = {item["name"]: item for item in self.list_profiles()}
            for item in payload.get("profiles", []) or []:
                proposed = dict(item.get("proposed") or {})
                name = str(proposed.get("name") or "").strip()
                if not name:
                    raise ValueError("Staged profile has no name")
                existing = existing_profiles.get(name)
                created = False
                if existing:
                    if not self._kid_control_profile_matches(existing, proposed):
                        raise ValueError(f"Existing ZEN profile '{name}' conflicts with staged Kid Control replacement")
                    profile = existing
                else:
                    profile = self.create_profile(
                        name,
                        proposed.get("desired_mode", "blocked"),
                        proposed.get("bandwidth_preset", "normal"),
                        proposed.get("notes", ""),
                        proposed.get("blocked_services", []),
                        proposed.get("daily_quota_mb", 0),
                        proposed.get("daily_quota_action", "blocked"),
                        proposed.get("service_quotas", {}),
                    )
                    created = True
                    existing_profiles[name] = profile
                profile_ids[name] = int(profile["id"])
                artifacts["profiles"].append({"id": int(profile["id"]), "name": name, "created": created})

                for event in proposed.get("schedule", []) or []:
                    days = list(event.get("days") or [])
                    clock = str(event.get("time") or "").strip()
                    mode = str(event.get("mode") or "").strip().lower()
                    matching = [
                        plan for plan in self.list_schedule_plans()
                        if plan.get("target_type") == "profile"
                        and str(plan.get("target_value")) == str(profile["id"])
                        and plan.get("action_type") == "mode"
                        and str(plan.get("action_value") or "").lower() == mode
                        and str(plan.get("clock_time") or "") == clock
                        and set(plan.get("days") or []) == set(days)
                        and bool(plan.get("enabled", 1))
                    ]
                    if len(matching) > 1:
                        raise ValueError(f"Multiple equivalent ZEN schedules already exist for profile '{name}'")
                    if matching:
                        plan_id = int(matching[0]["id"])
                        schedule_created = False
                    else:
                        plan_id = int(self.create_schedule_plan(
                            f"Kid Control migration · {name} · {mode.upper()}",
                            "profile", str(profile["id"]), "mode", mode, clock, days,
                        ))
                        schedule_created = True
                    artifacts["schedules"].append({"id": plan_id, "profile_id": int(profile["id"]), "created": schedule_created})

            current_devices = self.list_device_policy()
            for item in payload.get("devices", []) or []:
                identity = item.get("identity") or {}
                if str(identity.get("state") or "").lower() != "matched":
                    raise ValueError(f"Device '{item.get('legacy_name') or item.get('mac')}' is not uniquely matched")
                ip = str(identity.get("ipv4") or "").strip()
                proposed = item.get("proposed") or {}
                profile_name = str(proposed.get("profile_name") or "").strip()
                if not ip or profile_name not in profile_ids:
                    raise ValueError(f"Device '{item.get('legacy_name') or item.get('mac')}' has unresolved cutover identity")
                previous = dict(current_devices[ip]) if ip in current_devices else None
                previous_identity = self.get_managed_device_identity(ip)
                target_profile_id = profile_ids[profile_name]
                if previous and previous.get("profile_id") not in (None, "", 0, target_profile_id):
                    raise ValueError(f"Existing ZEN device policy for {ip} is assigned to a different profile")
                if previous and str(previous.get("mode_override") or "inherit").lower() != "inherit":
                    raise ValueError(f"Existing ZEN device policy for {ip} has a mode override; clear it before cutover")
                self.update_device(
                    ip,
                    alias=(previous or {}).get("alias") or proposed.get("alias") or item.get("legacy_name") or "",
                    notes=(previous or {}).get("notes") or "Migrated from MikroTik Kid Control",
                    profile_id=target_profile_id,
                    mode_override="inherit",
                    category=(previous or {}).get("category") or proposed.get("category") or "other",
                    favourite=bool((previous or {}).get("favourite", False)),
                )
                artifacts["devices"].append({
                    "ip": ip,
                    "mac": str(item.get("mac") or ""),
                    "name": str(item.get("legacy_name") or ""),
                    "profile_id": target_profile_id,
                    "previous": previous,
                    "previous_identity": previous_identity,
                })
            return artifacts
        except Exception:
            self.rollback_kid_control_materialization(artifacts)
            raise

    def rollback_kid_control_materialization(self, artifacts):
        """Restore only local objects changed/created by materialisation."""
        artifacts = artifacts or {}
        for item in reversed(artifacts.get("devices", []) or []):
            ip = str(item.get("ip") or "").strip()
            previous = item.get("previous")
            if not ip:
                continue
            if previous:
                self.update_device(
                    ip,
                    alias=previous.get("alias", ""),
                    notes=previous.get("notes", ""),
                    profile_id=previous.get("profile_id"),
                    mode_override=previous.get("mode_override", "inherit"),
                    category=previous.get("category", "other"),
                    favourite=bool(previous.get("favourite", False)),
                )
            else:
                with self._db() as db:
                    db.execute("DELETE FROM device_policy WHERE ip=?", (ip,))
                    if not item.get("previous_identity"):
                        db.execute("DELETE FROM managed_device_identity WHERE ip=?", (ip,))

        for item in reversed(artifacts.get("schedules", []) or []):
            if item.get("created"):
                try:
                    self.delete_schedule_plan(int(item["id"]))
                except ValueError:
                    pass
        for item in reversed(artifacts.get("profiles", []) or []):
            if item.get("created"):
                try:
                    self.delete_profile(int(item["id"]))
                except ValueError:
                    pass
        return True

    def get_settings(self):
        with self._db() as db:
            rows = db.execute("SELECT key, value FROM app_settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def save_settings(
        self,
        default_profile_id="",
        default_category="other",
        default_bandwidth_preset="normal",
        default_temp_minutes="30",
        policy_timezone="Europe/London",
        auto_reconcile_mode="off",
        auto_reconcile_interval_seconds="30",
        auto_reconcile_failure_threshold="3",
        auto_reconcile_cooldown_seconds="300",
        *,
        expected_revision=None,
        actor="system:policy-store",
    ):
        if default_profile_id not in ("", None):
            if not self.get_profile(int(default_profile_id)):
                raise ValueError("Default profile does not exist")
            default_profile_id = str(int(default_profile_id))
        else:
            default_profile_id = ""

        valid_categories = {k for k, _ in DEVICE_CATEGORIES}
        if default_category not in valid_categories:
            raise ValueError("Invalid default device category")
        self._validate_preset(default_bandwidth_preset)
        if str(default_temp_minutes) not in {"15", "30", "60"}:
            raise ValueError("Default temporary access must be 15, 30 or 60 minutes")
        policy_timezone = str(policy_timezone or "").strip()
        if not policy_timezone or len(policy_timezone) > 80:
            raise ValueError("Policy timezone is required")
        try:
            ZoneInfo(policy_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(
                "Policy timezone must be a valid IANA timezone such as Europe/London"
            ) from exc

        auto_reconcile_mode = str(auto_reconcile_mode or "off").strip().lower()
        if auto_reconcile_mode not in {"off", "observe", "enforce"}:
            raise ValueError("Automatic reconciliation mode must be off, observe or enforce")

        auto_reconcile_interval_seconds = str(auto_reconcile_interval_seconds or "30").strip()
        if auto_reconcile_interval_seconds not in {"15", "30", "60", "120", "300"}:
            raise ValueError("Automatic reconciliation interval must be 15, 30, 60, 120 or 300 seconds")

        auto_reconcile_failure_threshold = str(auto_reconcile_failure_threshold or "3").strip()
        if auto_reconcile_failure_threshold not in {"1", "2", "3", "5", "10"}:
            raise ValueError("Automatic reconciliation failure threshold must be 1, 2, 3, 5 or 10")

        auto_reconcile_cooldown_seconds = str(auto_reconcile_cooldown_seconds or "300").strip()
        if auto_reconcile_cooldown_seconds not in {"60", "300", "600", "1800"}:
            raise ValueError("Automatic reconciliation cooldown must be 60, 300, 600 or 1800 seconds")

        values = {
            "default_profile_id": default_profile_id,
            "default_category": default_category,
            "default_bandwidth_preset": default_bandwidth_preset,
            "default_temp_minutes": str(default_temp_minutes),
            "policy_timezone": policy_timezone,
            "auto_reconcile_mode": auto_reconcile_mode,
            "auto_reconcile_interval_seconds": auto_reconcile_interval_seconds,
            "auto_reconcile_failure_threshold": auto_reconcile_failure_threshold,
            "auto_reconcile_cooldown_seconds": auto_reconcile_cooldown_seconds,
        }
        with self.config_write(
            scope="settings",
            reason="Global settings updated",
            actor=actor,
            expected_revision=expected_revision,
        ) as db:
            for key, value in values.items():
                db.execute(
                    """INSERT INTO app_settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (key, value),
                )
        return values


    def save_quota_settings(self, enabled="0", warning_percent="80", *, expected_revision=None, actor="system:policy-store"):
        enabled = "1" if str(enabled).strip().lower() in {"1", "true", "yes", "on"} else "0"
        try:
            warning = int(warning_percent)
        except (TypeError, ValueError) as exc:
            raise ValueError("Quota warning threshold must be a whole percentage") from exc
        if warning not in {50, 60, 70, 75, 80, 85, 90, 95}:
            raise ValueError("Quota warning threshold must be 50, 60, 70, 75, 80, 85, 90 or 95 percent")
        values = {
            "quota_engine_enabled": enabled,
            "quota_warning_percent": str(warning),
        }
        with self.config_write(
            scope="settings:quota",
            reason="Quota settings updated",
            actor=actor,
            expected_revision=expected_revision,
        ) as db:
            for key, value in values.items():
                db.execute(
                    """INSERT INTO app_settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (key, value),
                )
        return values

    @staticmethod
    def _reward_now_iso():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def save_reward_settings(
        self,
        enabled="1",
        max_minutes="240",
        default_grant_minutes="30",
        max_redeem_minutes="60",
        *,
        expected_revision=None,
        actor="system:policy-store",
    ):
        enabled = "1" if str(enabled).strip().lower() in {"1", "true", "yes", "on"} else "0"
        try:
            max_minutes_i = int(max_minutes)
            default_grant_i = int(default_grant_minutes)
            max_redeem_i = int(max_redeem_minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("Reward settings must be whole minutes") from exc

        if max_minutes_i not in {120, 240, 480, 720, 1440}:
            raise ValueError("Reward bank maximum must be 120, 240, 480, 720 or 1440 minutes")
        if default_grant_i not in {15, 30, 60}:
            raise ValueError("Default reward grant must be 15, 30 or 60 minutes")
        if max_redeem_i not in {15, 30, 60}:
            raise ValueError("Maximum reward redemption must be 15, 30 or 60 minutes")
        if max_redeem_i > max_minutes_i:
            raise ValueError("Maximum reward redemption cannot exceed the bank maximum")

        values = {
            "reward_bank_enabled": enabled,
            "reward_bank_max_minutes": str(max_minutes_i),
            "reward_default_grant_minutes": str(default_grant_i),
            "reward_max_redeem_minutes": str(max_redeem_i),
        }
        with self.config_write(
            scope="settings:rewards",
            reason="Reward settings updated",
            actor=actor,
            expected_revision=expected_revision,
        ) as db:
            for key, value in values.items():
                db.execute(
                    """INSERT INTO app_settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (key, value),
                )
        return values

    def _reward_limits(self):
        settings = self.get_settings()
        try:
            max_minutes = int(settings.get("reward_bank_max_minutes", "240"))
        except (TypeError, ValueError):
            max_minutes = 240
        try:
            max_redeem = int(settings.get("reward_max_redeem_minutes", "60"))
        except (TypeError, ValueError):
            max_redeem = 60
        return {
            "enabled": str(settings.get("reward_bank_enabled", "1")) == "1",
            "max_minutes": max_minutes,
            "max_redeem_minutes": max_redeem,
        }

    def get_reward_account(self, ip, ledger_limit=8):
        ip = str(ip).strip()
        if not ip:
            raise ValueError("Reward account requires a device IP")
        try:
            ledger_limit = max(0, min(int(ledger_limit), 50))
        except (TypeError, ValueError):
            ledger_limit = 8
        limits = self._reward_limits()
        with self._db() as db:
            row = db.execute(
                "SELECT ip, balance_minutes, updated_at FROM reward_accounts WHERE ip=?",
                (ip,),
            ).fetchone()
            ledger = []
            if ledger_limit:
                ledger = [
                    dict(item)
                    for item in db.execute(
                        """SELECT id, delta_minutes, balance_after, kind, reason,
                                  actor, reference, created_at
                           FROM reward_ledger
                           WHERE ip=? ORDER BY id DESC LIMIT ?""",
                        (ip, ledger_limit),
                    ).fetchall()
                ]
            pending = [
                dict(item)
                for item in db.execute(
                    """SELECT id, minutes, actor, status, created_at, updated_at,
                              restore_at, note
                       FROM reward_redemptions
                       WHERE ip=? AND status='reserved'
                       ORDER BY id DESC""",
                    (ip,),
                ).fetchall()
            ]
        return {
            "ip": ip,
            "balance_minutes": int(row["balance_minutes"]) if row else 0,
            "updated_at": row["updated_at"] if row else None,
            "enabled": limits["enabled"],
            "max_minutes": limits["max_minutes"],
            "max_redeem_minutes": limits["max_redeem_minutes"],
            "ledger": ledger,
            "pending_redemptions": pending,
        }

    def adjust_reward_minutes(
        self,
        ip,
        delta_minutes,
        *,
        reason="",
        actor="",
        kind="adjustment",
        reference="",
        allow_above_cap=False,
    ):
        ip = str(ip).strip()
        try:
            delta = int(delta_minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("Reward adjustment must be whole minutes") from exc
        if not ip:
            raise ValueError("Reward account requires a device IP")
        if delta == 0 or abs(delta) > 1440:
            raise ValueError("Reward adjustment must be between -1440 and 1440 minutes and not zero")

        limits = self._reward_limits()
        if not limits["enabled"]:
            raise ValueError("Reward bank is disabled")
        now = self._reward_now_iso()
        reason = str(reason or "").strip()[:200]
        actor = str(actor or "").strip()[:80]
        kind = str(kind or "adjustment").strip()[:40]
        reference = str(reference or "").strip()[:120]

        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT balance_minutes FROM reward_accounts WHERE ip=?",
                (ip,),
            ).fetchone()
            before = int(row["balance_minutes"]) if row else 0
            after = before + delta
            if after < 0:
                raise ValueError(
                    f"Insufficient reward balance: {before} minutes available"
                )
            if after > limits["max_minutes"] and not allow_above_cap:
                raise ValueError(
                    f"Reward bank maximum is {limits['max_minutes']} minutes; "
                    f"this adjustment would produce {after} minutes"
                )
            db.execute(
                """INSERT INTO reward_accounts (ip, balance_minutes, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                     balance_minutes=excluded.balance_minutes,
                     updated_at=excluded.updated_at""",
                (ip, after, now),
            )
            cur = db.execute(
                """INSERT INTO reward_ledger
                   (ip, delta_minutes, balance_after, kind, reason, actor, reference, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ip, delta, after, kind, reason, actor, reference, now),
            )
        return {
            "id": cur.lastrowid,
            "ip": ip,
            "before_minutes": before,
            "delta_minutes": delta,
            "balance_minutes": after,
            "kind": kind,
            "reason": reason,
            "actor": actor,
            "reference": reference,
            "created_at": now,
        }

    def reserve_reward_redemption(self, ip, minutes, *, actor="", reason="reward access"):
        ip = str(ip).strip()
        try:
            minutes = int(minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("Reward redemption must be whole minutes") from exc
        limits = self._reward_limits()
        if not limits["enabled"]:
            raise ValueError("Reward bank is disabled")
        if minutes not in {15, 30, 60}:
            raise ValueError("Reward access supports 15, 30 or 60 minutes")
        if minutes > limits["max_redeem_minutes"]:
            raise ValueError(
                f"Reward redemption is limited to {limits['max_redeem_minutes']} minutes"
            )
        now = self._reward_now_iso()
        actor = str(actor or "").strip()[:80]
        reason = str(reason or "reward access").strip()[:200]

        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            pending = db.execute(
                "SELECT id FROM reward_redemptions WHERE ip=? AND status='reserved' ORDER BY id LIMIT 1",
                (ip,),
            ).fetchone()
            if pending:
                raise ValueError(
                    f"Reward redemption {pending['id']} is still pending recovery for {ip}; "
                    "resolve it before spending more reward minutes"
                )
            row = db.execute(
                "SELECT balance_minutes FROM reward_accounts WHERE ip=?",
                (ip,),
            ).fetchone()
            before = int(row["balance_minutes"]) if row else 0
            if before < minutes:
                raise ValueError(
                    f"Insufficient reward balance: {before} minutes available, {minutes} required"
                )
            after = before - minutes
            cur = db.execute(
                """INSERT INTO reward_redemptions
                   (ip, minutes, actor, status, created_at, updated_at, restore_at, note)
                   VALUES (?, ?, ?, 'reserved', ?, ?, '', ?)""",
                (ip, minutes, actor, now, now, reason),
            )
            redemption_id = int(cur.lastrowid)
            reference = f"redemption:{redemption_id}"
            db.execute(
                """INSERT INTO reward_accounts (ip, balance_minutes, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                     balance_minutes=excluded.balance_minutes,
                     updated_at=excluded.updated_at""",
                (ip, after, now),
            )
            db.execute(
                """INSERT INTO reward_ledger
                   (ip, delta_minutes, balance_after, kind, reason, actor, reference, created_at)
                   VALUES (?, ?, ?, 'redeem', ?, ?, ?, ?)""",
                (ip, -minutes, after, reason, actor, reference, now),
            )
        return {
            "id": redemption_id,
            "ip": ip,
            "minutes": minutes,
            "actor": actor,
            "status": "reserved",
            "balance_minutes": after,
            "created_at": now,
        }

    def complete_reward_redemption(self, redemption_id, *, restore_at="", note=""):
        redemption_id = int(redemption_id)
        now = self._reward_now_iso()
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM reward_redemptions WHERE id=?",
                (redemption_id,),
            ).fetchone()
            if not row:
                raise ValueError("Reward redemption not found")
            if row["status"] == "applied":
                return dict(row)
            if row["status"] != "reserved":
                raise ValueError(
                    f"Reward redemption is already {row['status']}"
                )
            db.execute(
                """UPDATE reward_redemptions
                   SET status='applied', updated_at=?, restore_at=?, note=?
                   WHERE id=?""",
                (
                    now,
                    str(restore_at or "").strip()[:80],
                    str(note or row["note"] or "").strip()[:200],
                    redemption_id,
                ),
            )
            updated = db.execute(
                "SELECT * FROM reward_redemptions WHERE id=?",
                (redemption_id,),
            ).fetchone()
        return dict(updated)

    def refund_reward_redemption(self, redemption_id, *, note=""):
        redemption_id = int(redemption_id)
        now = self._reward_now_iso()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM reward_redemptions WHERE id=?",
                (redemption_id,),
            ).fetchone()
            if not row:
                raise ValueError("Reward redemption not found")
            if row["status"] == "refunded":
                return dict(row)
            if row["status"] != "reserved":
                raise ValueError(
                    f"Only reserved reward redemptions can be refunded (current: {row['status']})"
                )
            account = db.execute(
                "SELECT balance_minutes FROM reward_accounts WHERE ip=?",
                (row["ip"],),
            ).fetchone()
            before = int(account["balance_minutes"]) if account else 0
            after = before + int(row["minutes"])
            db.execute(
                """INSERT INTO reward_accounts (ip, balance_minutes, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                     balance_minutes=excluded.balance_minutes,
                     updated_at=excluded.updated_at""",
                (row["ip"], after, now),
            )
            reason = str(note or "Reward redemption failed; minutes returned").strip()[:200]
            reference = f"redemption:{redemption_id}"
            db.execute(
                """INSERT INTO reward_ledger
                   (ip, delta_minutes, balance_after, kind, reason, actor, reference, created_at)
                   VALUES (?, ?, ?, 'refund', ?, ?, ?, ?)""",
                (
                    row["ip"],
                    int(row["minutes"]),
                    after,
                    reason,
                    str(row["actor"] or "")[:80],
                    reference,
                    now,
                ),
            )
            db.execute(
                """UPDATE reward_redemptions
                   SET status='refunded', updated_at=?, note=? WHERE id=?""",
                (now, reason, redemption_id),
            )
            updated = db.execute(
                "SELECT * FROM reward_redemptions WHERE id=?",
                (redemption_id,),
            ).fetchone()
        return dict(updated)

    def list_pending_reward_redemptions(self, ip=None):
        """Return unconfirmed reward redemptions in durable order.

        Startup recovery must consider all reserved rows, not only rows older than
        an arbitrary timeout: an application restart itself proves no in-process
        redemption transaction is still running. Operator rechecks may scope the
        same evidence-led recovery to one managed IP.
        """
        ip = str(ip or "").strip()
        with self._db() as db:
            if ip:
                rows = db.execute(
                    """SELECT * FROM reward_redemptions
                       WHERE status='reserved' AND ip=? ORDER BY id""",
                    (ip,),
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM reward_redemptions
                       WHERE status='reserved' ORDER BY id"""
                ).fetchall()
            return [dict(row) for row in rows]

    def recover_stale_reward_redemptions(self, max_age_seconds=300):
        try:
            max_age_seconds = max(60, min(int(max_age_seconds), 3600))
        except (TypeError, ValueError):
            max_age_seconds = 300
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        ).isoformat(timespec="seconds")
        with self._db() as db:
            rows = db.execute(
                """SELECT id FROM reward_redemptions
                   WHERE status='reserved' AND created_at <= ?
                   ORDER BY id""",
                (cutoff,),
            ).fetchall()
        recovered = []
        for row in rows:
            recovered.append(
                self.refund_reward_redemption(
                    row["id"],
                    note="Recovered stale unconfirmed reward redemption after application restart",
                )
            )
        return recovered

    def delete_reward_account(self, ip):
        ip = str(ip).strip()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM reward_redemptions WHERE ip=?", (ip,))
            db.execute("DELETE FROM reward_ledger WHERE ip=?", (ip,))
            db.execute("DELETE FROM reward_accounts WHERE ip=?", (ip,))

    def retire_device_state(self, ip):
        """Remove live per-IP configuration when a device leaves management.

        Historical telemetry, audit records and policy-state history are retained.
        Device-targeted schedules/exceptions and reward state are live authority
        keyed by IP and must not leak to a different device if that address is
        later reused.
        """
        ip = str(ip).strip()
        if not ip:
            raise ValueError("Device IP is required")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            device_policy = db.execute(
                "DELETE FROM device_policy WHERE ip=?", (ip,)
            ).rowcount
            schedule_plans = db.execute(
                "DELETE FROM schedule_plans WHERE target_type='device' AND target_value=?",
                (ip,),
            ).rowcount
            date_exceptions = db.execute(
                "DELETE FROM date_exceptions WHERE target_type='device' AND target_value=?",
                (ip,),
            ).rowcount
            reward_redemptions = db.execute(
                "DELETE FROM reward_redemptions WHERE ip=?", (ip,)
            ).rowcount
            reward_ledger = db.execute(
                "DELETE FROM reward_ledger WHERE ip=?", (ip,)
            ).rowcount
            reward_accounts = db.execute(
                "DELETE FROM reward_accounts WHERE ip=?", (ip,)
            ).rowcount
            management_identity = db.execute(
                "DELETE FROM managed_device_identity WHERE ip=?", (ip,)
            ).rowcount
        return {
            "device_policy": int(device_policy or 0),
            "schedule_plans": int(schedule_plans or 0),
            "date_exceptions": int(date_exceptions or 0),
            "reward_redemptions": int(reward_redemptions or 0),
            "reward_ledger": int(reward_ledger or 0),
            "reward_accounts": int(reward_accounts or 0),
            "management_identity": int(management_identity or 0),
        }

    def clone_profile(self, profile_id, new_name):
        source = self.get_profile(int(profile_id))
        if not source:
            raise ValueError("Profile not found")
        return self.create_profile(
            new_name,
            source["desired_mode"],
            source["bandwidth_preset"],
            source.get("notes", ""),
            source.get("blocked_services", []),
            source.get("daily_quota_mb", 0),
            source.get("daily_quota_action", "blocked"),
            source.get("service_quotas", {}),
        )

    def clone_schedule_template(self, template_id, new_name):
        source = next(
            (t for t in self.list_schedule_templates() if t["id"] == int(template_id)),
            None,
        )
        if not source:
            raise ValueError("Schedule template not found")
        return self.save_schedule_template(
            new_name, source.get("description", ""), source.get("entries", [])
        )

    def copy_device_policy(self, source_ip, target_ip):
        policies = self.list_device_policy()
        source = policies.get(source_ip)
        if not source:
            raise ValueError("Source device has no staged policy")
        self.update_device(
            target_ip,
            policies.get(target_ip, {}).get("alias", ""),
            source.get("notes", ""),
            source.get("profile_id"),
            source.get("mode_override", "inherit"),
            source.get("category", "other"),
            bool(source.get("favourite", 0)),
        )

    def update_discovery_cache(self, devices):
        import datetime as _dt
        now = _dt.datetime.now().isoformat(timespec="seconds")
        with self._db() as db:
            for d in devices:
                ip = d.get("address", "")
                if not ip:
                    continue
                db.execute(
                    """INSERT INTO discovery_cache
                       (ip, mac, name, host_name, comment, status, source, last_seen, seen_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(ip) DO UPDATE SET
                         mac=excluded.mac,
                         name=excluded.name,
                         host_name=excluded.host_name,
                         comment=excluded.comment,
                         status=excluded.status,
                         source=excluded.source,
                         last_seen=excluded.last_seen,
                         seen_at=excluded.seen_at""",
                    (
                        ip,
                        d.get("mac",""),
                        d.get("name",""),
                        d.get("host_name",""),
                        d.get("comment",""),
                        d.get("status",""),
                        d.get("source",""),
                        d.get("last_seen",""),
                        now,
                    ),
                )

    def list_discovery_cache(self):
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM discovery_cache ORDER BY ip"
            ).fetchall()
        return [dict(r) for r in rows]

    def build_policy_summary(self, known_devices):
        policies = self.list_device_policy()
        profiles = {p["id"]: p["name"] for p in self.list_profiles()}
        rows = []
        for d in known_devices:
            ip = d.get("ip") or d.get("address")
            if not ip:
                continue
            cfg = policies.get(ip, {})
            eff = self.compute_effective_policy(ip)
            rows.append(
                {
                    "ip": ip,
                    "name": cfg.get("alias") or d.get("name") or d.get("host_name") or "Unknown",
                    "profile": profiles.get(cfg.get("profile_id"), "Unassigned"),
                    "category": cfg.get("category", "other"),
                    "favourite": bool(cfg.get("favourite", 0)),
                    "desired_mode": eff.get("mode", "normal"),
                    "mode_source": eff.get("mode_source", "default"),
                    "bandwidth": eff.get("bandwidth_preset", "normal"),
                    "blocked_services": eff.get("blocked_services", []),
                    "conflicts": eff.get("conflicts", []),
                }
            )
        return sorted(rows, key=lambda x: (not x["favourite"], x["name"].lower(), x["ip"]))

    def preview_import(self, payload):
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError("Unsupported configuration format")

        current = self.export_config()
        sections = [
            "profiles",
            "device_policy",
            "policy_templates",
            "bandwidth_presets",
            "services",
            "service_groups",
            "schedule_plans",
            "schedule_templates",
            "date_exceptions",
            "app_settings",
        ]
        diff = []
        for section in sections:
            old_items = current.get(section, []) or []
            new_items = payload.get(section, []) or []
            old_count = len(old_items)
            new_count = len(new_items)
            changed = json.dumps(old_items, sort_keys=True, default=str) != json.dumps(
                new_items, sort_keys=True, default=str
            )
            diff.append(
                {
                    "section": section,
                    "current": old_count,
                    "incoming": new_count,
                    "changed": changed,
                }
            )
        return diff
    @staticmethod
    def _profile_dict(row):
        if row is None:
            return None
        item = dict(row)
        item["blocked_services"] = json.loads(item["blocked_services"] or "[]")
        item["daily_quota_mb"] = int(item.get("daily_quota_mb", 0) or 0)
        item["daily_quota_action"] = item.get("daily_quota_action") or "blocked"
        item["service_quotas"] = json.loads(item.get("service_quotas") or "{}")
        return item

    @staticmethod
    def _template_dict(row):
        item = dict(row)
        item["blocked_services"] = json.loads(item["blocked_services"] or "[]")
        item["daily_quota_mb"] = int(item.get("daily_quota_mb", 0) or 0)
        item["daily_quota_action"] = item.get("daily_quota_action") or "blocked"
        item["service_quotas"] = json.loads(item.get("service_quotas") or "{}")
        return item
