BEGIN TRANSACTION;
CREATE TABLE aggregate_policy_groups (
                    key TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    members TEXT NOT NULL DEFAULT '[]',
                    builtin INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT ''
                );
INSERT INTO "aggregate_policy_groups" VALUES('gaming','Gaming','Aggregate policy for the concrete gaming services currently backed by RouterOS. It does not claim to block every game or gaming protocol.','["playstation", "roblox", "steam", "xbox"]',1,'2026-09-13T11:25:31+00:00','2026-09-13T11:25:31+00:00');
INSERT INTO "aggregate_policy_groups" VALUES('social_media','Social media','Conservative social/communications aggregate using the concrete TikTok and Discord contracts. Other social platforms can be added when they have trusted classifiers.','["discord", "tiktok"]',1,'2026-09-13T11:25:31+00:00','2026-09-13T11:25:31+00:00');
CREATE TABLE app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
INSERT INTO "app_settings" VALUES('default_profile_id','');
INSERT INTO "app_settings" VALUES('default_category','other');
INSERT INTO "app_settings" VALUES('default_bandwidth_preset','normal');
INSERT INTO "app_settings" VALUES('default_temp_minutes','30');
INSERT INTO "app_settings" VALUES('policy_timezone','Europe/London');
INSERT INTO "app_settings" VALUES('auto_reconcile_mode','off');
INSERT INTO "app_settings" VALUES('auto_reconcile_interval_seconds','30');
INSERT INTO "app_settings" VALUES('auto_reconcile_failure_threshold','3');
INSERT INTO "app_settings" VALUES('auto_reconcile_cooldown_seconds','300');
INSERT INTO "app_settings" VALUES('reward_bank_enabled','1');
INSERT INTO "app_settings" VALUES('reward_bank_max_minutes','240');
INSERT INTO "app_settings" VALUES('reward_default_grant_minutes','30');
INSERT INTO "app_settings" VALUES('reward_max_redeem_minutes','60');
INSERT INTO "app_settings" VALUES('quota_engine_enabled','0');
INSERT INTO "app_settings" VALUES('quota_warning_percent','80');
INSERT INTO "app_settings" VALUES('snapshot_retention_count','30');
INSERT INTO "app_settings" VALUES('audit_retention_events','5000');
INSERT INTO "app_settings" VALUES('incident_monitor_enabled','1');
INSERT INTO "app_settings" VALUES('incident_scan_interval_seconds','60');
INSERT INTO "app_settings" VALUES('incident_bypass_min_status','elevated');
INSERT INTO "app_settings" VALUES('incident_retention_days','30');
INSERT INTO "app_settings" VALUES('summary_delivery_enabled','0');
INSERT INTO "app_settings" VALUES('summary_delivery_time','07:00');
INSERT INTO "app_settings" VALUES('summary_delivery_period','yesterday');
INSERT INTO "app_settings" VALUES('summary_delivery_email_enabled','0');
INSERT INTO "app_settings" VALUES('summary_delivery_email_to','');
INSERT INTO "app_settings" VALUES('summary_delivery_webhook_enabled','0');
INSERT INTO "app_settings" VALUES('summary_delivery_webhook_url','');
INSERT INTO "app_settings" VALUES('summary_delivery_retry_limit','3');
INSERT INTO "app_settings" VALUES('summary_delivery_retention_days','90');
INSERT INTO "app_settings" VALUES('policy_history_retention_days','365');
INSERT INTO "app_settings" VALUES('notification_enabled','1');
INSERT INTO "app_settings" VALUES('notification_min_severity','info');
INSERT INTO "app_settings" VALUES('notification_quiet_hours_enabled','0');
INSERT INTO "app_settings" VALUES('notification_quiet_start','22:00');
INSERT INTO "app_settings" VALUES('notification_quiet_end','07:00');
INSERT INTO "app_settings" VALUES('notification_timezone','Europe/London');
INSERT INTO "app_settings" VALUES('notification_critical_bypass_quiet','1');
INSERT INTO "app_settings" VALUES('notification_cooldown_seconds','300');
INSERT INTO "app_settings" VALUES('notification_muted_sources','[]');
INSERT INTO "app_settings" VALUES('notification_muted_subjects','[]');
INSERT INTO "app_settings" VALUES('notification_disabled_events','[]');
INSERT INTO "app_settings" VALUES('notification_escalation_enabled','1');
INSERT INTO "app_settings" VALUES('notification_warning_escalate_seconds','1800');
INSERT INTO "app_settings" VALUES('notification_repeat_escalate_count','5');
INSERT INTO "app_settings" VALUES('notification_digest_min_items','2');
INSERT INTO "app_settings" VALUES('notification_digest_window_minutes','60');
CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'info'
                );
CREATE TABLE background_jobs (
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
CREATE TABLE background_scope_locks (
                    scope TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    token TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
CREATE TABLE background_worker_metrics (
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
CREATE TABLE bandwidth_presets (
                    key TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    upload TEXT NOT NULL,
                    download TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    builtin INTEGER NOT NULL DEFAULT 0
                );
INSERT INTO "bandwidth_presets" VALUES('normal','Normal','Unlimited','Unlimited','No additional bandwidth restriction.',1);
INSERT INTO "bandwidth_presets" VALUES('slow','Slow','128k','256k','Very limited browsing; streaming should struggle.',1);
INSERT INTO "bandwidth_presets" VALUES('very_slow','Very slow','64k','128k','Barely usable connectivity.',1);
INSERT INTO "bandwidth_presets" VALUES('homework','Homework','512k','2M','Useful web access without comfortable HD streaming.',1);
INSERT INTO "bandwidth_presets" VALUES('basic','Basic','1M','5M','General browsing and messaging with constrained video.',1);
CREATE TABLE config_revision_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    revision INTEGER NOT NULL DEFAULT 0,
                    digest TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT ''
                );
INSERT INTO "config_revision_state" VALUES(1,0,'','','','');
CREATE TABLE config_revisions (
                    revision INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    scope TEXT NOT NULL DEFAULT 'config',
                    digest TEXT NOT NULL DEFAULT ''
                );
CREATE TABLE config_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
CREATE TABLE date_exceptions (
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
CREATE TABLE device_policy (
                    ip TEXT PRIMARY KEY,
                    alias TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT 'other',
                    favourite INTEGER NOT NULL DEFAULT 0,
                    profile_id INTEGER NULL,
                    mode_override TEXT NOT NULL DEFAULT 'inherit',
                    FOREIGN KEY(profile_id) REFERENCES profiles(id)
                );
INSERT INTO "device_policy" VALUES('192.0.2.56','Fixture Tablet','retain-me','tablet',1,1,'inherit');
CREATE TABLE discovery_cache (
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
CREATE TABLE incidents (
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
CREATE TABLE legacy_migration_cutover_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    source_fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    evidence TEXT NOT NULL DEFAULT '{}'
                );
CREATE TABLE legacy_migration_staging (
                    source TEXT PRIMARY KEY,
                    source_fingerprint TEXT NOT NULL,
                    staged_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL
                );
CREATE TABLE managed_device_identity (
                    ip TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL UNIQUE,
                    managed_since TEXT NOT NULL,
                    current_name TEXT NOT NULL DEFAULT ''
                );
CREATE TABLE notification_external_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id INTEGER NOT NULL DEFAULT 0,
                    channel TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    destination_key TEXT NOT NULL,
                    occurrence INTEGER NOT NULL DEFAULT 1,
                    kind TEXT NOT NULL DEFAULT 'notification',
                    idempotency_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 5,
                    available_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    claimed_at TEXT NOT NULL DEFAULT '',
                    sent_at TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    http_status INTEGER NOT NULL DEFAULT 0
                );
CREATE TABLE notification_external_delivery_settings (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    webhook_enabled INTEGER NOT NULL DEFAULT 0,
                    webhook_name TEXT NOT NULL DEFAULT 'Webhook',
                    webhook_url TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL DEFAULT ''
                );
INSERT INTO "notification_external_delivery_settings" VALUES(1,0,'Webhook','','','');
CREATE TABLE notification_push_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id INTEGER NOT NULL DEFAULT 0,
                    subscription_id INTEGER NOT NULL,
                    occurrence INTEGER NOT NULL DEFAULT 1,
                    kind TEXT NOT NULL DEFAULT 'notification',
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    available_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    claimed_at TEXT NOT NULL DEFAULT '',
                    sent_at TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    UNIQUE(notification_id, subscription_id, occurrence, kind)
                );
CREATE TABLE notification_push_subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint TEXT NOT NULL UNIQUE,
                    endpoint_hash TEXT NOT NULL UNIQUE,
                    p256dh TEXT NOT NULL,
                    auth TEXT NOT NULL,
                    username TEXT NOT NULL DEFAULT '',
                    user_agent TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    last_success_at TEXT NOT NULL DEFAULT '',
                    last_failure_at TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    failures INTEGER NOT NULL DEFAULT 0,
                    disabled_at TEXT NOT NULL DEFAULT ''
                );
CREATE TABLE notification_timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    detail_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
CREATE TABLE notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedupe_key TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'info',
                    state TEXT NOT NULL DEFAULT 'unread',
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    source_ref TEXT NOT NULL DEFAULT '',
                    target_url TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    read_at TEXT,
                    read_by TEXT NOT NULL DEFAULT '',
                    acknowledged_at TEXT,
                    acknowledged_by TEXT NOT NULL DEFAULT '',
                    dismissed_at TEXT,
                    dismissed_by TEXT NOT NULL DEFAULT '',
                    resolved_at TEXT,
                    resolved_by TEXT NOT NULL DEFAULT '',
                    resolution TEXT NOT NULL DEFAULT '',
                    attention_eligible_at TEXT NOT NULL DEFAULT '',
                    source_severity TEXT NOT NULL DEFAULT '',
                    correlation_key TEXT NOT NULL DEFAULT '',
                    escalation_level INTEGER NOT NULL DEFAULT 0,
                    escalated_at TEXT NOT NULL DEFAULT '',
                    escalation_reason TEXT NOT NULL DEFAULT '',
                    reopen_count INTEGER NOT NULL DEFAULT 0
                );
INSERT INTO "notifications" VALUES(1,'fixture:v056','system:fixture','upgrade','192.0.2.56','warning','unread','v056 fixture','','','','2026-09-13T09:00:00+00:00','2026-09-13T09:00:00+00:00','2026-09-13T09:00:00+00:00','2026-09-13T09:00:00+00:00',1,NULL,'',NULL,'',NULL,'',NULL,'','','','warning','subject:192.0.2.56',0,'','',0);
CREATE TABLE outbox_events (
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
CREATE TABLE policy_state_history (
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
CREATE TABLE policy_templates (
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
CREATE TABLE prepared_views (
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
CREATE TABLE profiles (
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
INSERT INTO "profiles" VALUES(1,'Fixture Child','normal','normal','v056 retained','["youtube"]',120,'blocked','{}');
CREATE TABLE reconciliation_requests (
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
CREATE TABLE reward_accounts (
                    ip TEXT PRIMARY KEY,
                    balance_minutes INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
CREATE TABLE reward_ledger (
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
CREATE TABLE reward_redemptions (
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
CREATE TABLE schedule_plans (
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
CREATE TABLE schedule_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    entries TEXT NOT NULL DEFAULT '[]'
                );
CREATE TABLE service_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    services TEXT NOT NULL DEFAULT '[]'
                );
CREATE TABLE services (
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
INSERT INTO "services" VALUES('youtube','YouTube','',1,'video','["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com"]','["*youtube*", "*googlevideo*"]',1,0,'');
INSERT INTO "services" VALUES('netflix','Netflix','',1,'video','["netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxso.net"]','["*netflix*", "*nflx*"]',1,0,'');
INSERT INTO "services" VALUES('prime_video','Prime Video','',1,'video','["primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net"]','["*primevideo*", "*amazonvideo*", "*aiv-cdn*"]',1,0,'');
INSERT INTO "services" VALUES('bbc_iplayer','BBC iPlayer','',1,'video','["bbc.co.uk", "bbc.com", "bbci.co.uk", "bbcmedia.co.uk", "bbcmedia.net"]','["*iplayer*", "*bbcfmt*", "*bbcmedia*"]',1,0,'');
INSERT INTO "services" VALUES('chatgpt','ChatGPT','',1,'ai','["chatgpt.com", "oaistatic.com", "oaiusercontent.com"]','["*chatgpt*"]',1,0,'');
INSERT INTO "services" VALUES('openai','OpenAI','',1,'ai','["openai.com"]','["*openai*"]',1,0,'');
INSERT INTO "services" VALUES('gaming','Gaming','',1,'other','[]','[]',1,0,'');
INSERT INTO "services" VALUES('social_media','Social media','',1,'other','[]','[]',1,0,'');
INSERT INTO "services" VALUES('tiktok','TikTok','',1,'social','["tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "muscdn.com", "musical.ly"]','["*tiktok*", "*musical.ly*", "*muscdn*"]',1,0,'');
INSERT INTO "services" VALUES('discord','Discord','',1,'social','["discord.com", "discord.gg", "discordapp.com", "discordapp.net"]','["*discord*"]',1,0,'');
INSERT INTO "services" VALUES('roblox','Roblox','',1,'gaming','["roblox.com", "rbxcdn.com"]','["*roblox*", "*rbxcdn*"]',1,0,'');
INSERT INTO "services" VALUES('steam','Steam','',1,'gaming','["steampowered.com", "steamcommunity.com", "steamcontent.com", "steamstatic.com"]','["*steam*"]',1,0,'');
INSERT INTO "services" VALUES('xbox','Xbox','',1,'gaming','["xboxlive.com", "xbox.com", "xboxservices.com"]','["*xbox*"]',1,0,'');
INSERT INTO "services" VALUES('playstation','PlayStation','',1,'gaming','["playstation.net", "playstation.com", "sonyentertainmentnetwork.com"]','["*playstation*", "*sonyentertainmentnetwork*"]',1,0,'');
CREATE TABLE summary_deliveries (
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
CREATE INDEX idx_audit_log_id
                    ON audit_log(id DESC);
CREATE INDEX idx_policy_state_history_ip_time
                    ON policy_state_history(ip, captured_at, id);
CREATE INDEX idx_summary_deliveries_status_next
                    ON summary_deliveries(status, next_attempt_at, id);
CREATE INDEX idx_summary_deliveries_report
                    ON summary_deliveries(report_date DESC, channel, id DESC);
CREATE INDEX idx_config_snapshots_id
                    ON config_snapshots(id DESC);
CREATE INDEX idx_legacy_migration_cutover_source
                    ON legacy_migration_cutover_events(source, id DESC);
CREATE INDEX idx_incidents_status_updated
                    ON incidents(status, updated_at DESC);
CREATE INDEX idx_incidents_source_status
                    ON incidents(source, status);
CREATE INDEX idx_notifications_state_updated
                    ON notifications(state, updated_at DESC);
CREATE INDEX idx_notifications_source_event
                    ON notifications(source, event_type, updated_at DESC);
CREATE INDEX idx_notifications_resolved_updated
                    ON notifications(resolved_at, updated_at DESC);
CREATE INDEX idx_notification_timeline_notification
                    ON notification_timeline(notification_id, id DESC);
CREATE INDEX idx_notification_timeline_event
                    ON notification_timeline(event, created_at DESC);
CREATE INDEX idx_notification_push_subscriptions_user
                    ON notification_push_subscriptions(username, enabled, updated_at DESC);
CREATE INDEX idx_notification_push_deliveries_claim
                    ON notification_push_deliveries(status, available_at, id);
CREATE INDEX idx_notification_push_deliveries_notification
                    ON notification_push_deliveries(notification_id, status, id);
CREATE INDEX idx_notification_external_deliveries_claim
                    ON notification_external_deliveries(status, available_at, id);
CREATE INDEX idx_notification_external_deliveries_notification
                    ON notification_external_deliveries(notification_id, status, id);
CREATE INDEX idx_notification_external_deliveries_channel
                    ON notification_external_deliveries(channel, status, id);
CREATE INDEX idx_reward_ledger_ip_id
                    ON reward_ledger(ip, id DESC);
CREATE INDEX idx_reward_redemptions_ip_id
                    ON reward_redemptions(ip, id DESC);
CREATE INDEX idx_outbox_status_id
                    ON outbox_events(status, id);
CREATE INDEX idx_background_jobs_claim
                    ON background_jobs(status, available_at, id);
CREATE INDEX idx_reconciliation_requests_status_id
                    ON reconciliation_requests(status, id);
CREATE INDEX idx_reconciliation_requests_target_id
                    ON reconciliation_requests(target, id DESC);
CREATE INDEX idx_prepared_views_kind_scope
                    ON prepared_views(kind, scope);
CREATE INDEX idx_notifications_correlation ON notifications(correlation_key, resolved_at, updated_at DESC);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('notification_timeline',0);
INSERT INTO "sqlite_sequence" VALUES('profiles',1);
INSERT INTO "sqlite_sequence" VALUES('notifications',1);
COMMIT;
