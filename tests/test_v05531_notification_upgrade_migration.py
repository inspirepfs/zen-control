import os
import sqlite3
import tempfile
import unittest

from app.policy_store import PolicyStore


class NotificationUpgradeMigrationTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-v0552-upgrade-", suffix=".db")
        os.close(fd)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def _create_v0552_notification_schema(self):
        db = sqlite3.connect(self.path)
        db.executescript(
            """
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
            CREATE INDEX idx_notifications_state_updated
                ON notifications(state, updated_at DESC);
            CREATE INDEX idx_notifications_source_event
                ON notifications(source, event_type, updated_at DESC);
            CREATE INDEX idx_notifications_resolved_updated
                ON notifications(resolved_at, updated_at DESC);
            """
        )
        stamp = "2026-09-12T20:00:00+00:00"
        db.execute(
            """INSERT INTO notifications
               (dedupe_key, source, event_type, subject, severity, state, title,
                created_at, first_seen_at, last_seen_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ("telemetry:upgrade", "telemetry:flow", "incident", "192.168.2.26",
             "warning", "unread", "Upgrade fixture", stamp, stamp, stamp, stamp),
        )
        db.commit()
        db.close()

    def test_existing_v0552_database_migrates_before_correlation_index_is_created(self):
        self._create_v0552_notification_schema()
        store = PolicyStore(self.path)
        with store._db() as db:
            columns = {row["name"] for row in db.execute("PRAGMA table_info(notifications)")}
            indexes = {row["name"] for row in db.execute("PRAGMA index_list(notifications)")}
            row = db.execute(
                "SELECT source_severity, correlation_key, escalation_level, reopen_count FROM notifications"
            ).fetchone()
            timeline = db.execute(
                "SELECT event FROM notification_timeline WHERE notification_id=1 ORDER BY id"
            ).fetchall()
        self.assertIn("correlation_key", columns)
        self.assertIn("idx_notifications_correlation", indexes)
        self.assertEqual("warning", row["source_severity"])
        self.assertEqual("subject:192.168.2.26", row["correlation_key"])
        self.assertEqual(0, row["escalation_level"])
        self.assertEqual(0, row["reopen_count"])
        self.assertEqual(["baseline"], [item["event"] for item in timeline])


if __name__ == "__main__":
    unittest.main()
