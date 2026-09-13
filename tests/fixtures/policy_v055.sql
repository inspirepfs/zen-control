BEGIN TRANSACTION;
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
 attention_eligible_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_notifications_state_updated ON notifications(state, updated_at DESC);
CREATE INDEX idx_notifications_source_event ON notifications(source, event_type, updated_at DESC);
CREATE INDEX idx_notifications_resolved_updated ON notifications(resolved_at, updated_at DESC);
INSERT INTO notifications(
 dedupe_key,source,event_type,subject,severity,state,title,
 created_at,first_seen_at,last_seen_at,updated_at
) VALUES(
 'fixture:v055','telemetry:flow','incident','192.0.2.55','warning','unread','v055 retained notification',
 '2026-09-12T20:00:00+00:00','2026-09-12T20:00:00+00:00','2026-09-12T20:00:00+00:00','2026-09-12T20:00:00+00:00'
);
COMMIT;
