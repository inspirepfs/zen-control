import tempfile
import time
import unittest
from pathlib import Path
from app.auth import fresh_auth_valid, shared_display_privilege_valid
from app.policy_store import PolicyStore


class AuthenticationLifecycleClosureTests(unittest.TestCase):
    def test_shared_display_unlock_expires_by_time(self):
        self.assertFalse(shared_display_privilege_valid(
            shared_display_mode=True, privileged_until=time.time() - 1,
            privileged_boot_id="boot-a", process_boot_id="boot-a",
        ))

    def test_process_restart_invalidates_shared_display_unlock(self):
        self.assertFalse(shared_display_privilege_valid(
            shared_display_mode=True, privileged_until=time.time() + 300,
            privileged_boot_id="previous-process", process_boot_id="current-process",
        ))

    def test_current_process_unlock_remains_valid_until_deadline(self):
        self.assertTrue(shared_display_privilege_valid(
            shared_display_mode=True, privileged_until=time.time() + 120,
            privileged_boot_id="current-process", process_boot_id="current-process",
        ))

    def test_non_shared_display_does_not_require_process_unlock_token(self):
        self.assertTrue(shared_display_privilege_valid(
            shared_display_mode=False, privileged_until=0,
            privileged_boot_id=None, process_boot_id="current-process",
        ))




    def test_fresh_step_up_is_process_bound_and_time_bounded(self):
        now = time.time()
        self.assertTrue(fresh_auth_valid(
            fresh_auth_at=now - 10, fresh_auth_boot_id="boot-a",
            process_boot_id="boot-a", now=now,
        ))
        self.assertFalse(fresh_auth_valid(
            fresh_auth_at=now - 10, fresh_auth_boot_id="old-boot",
            process_boot_id="boot-a", now=now,
        ))
        self.assertFalse(fresh_auth_valid(
            fresh_auth_at=now - 91, fresh_auth_boot_id="boot-a",
            process_boot_id="boot-a", now=now,
        ))

    def test_legacy_unversioned_sessions_fail_closed_in_main_contract(self):
        root = Path(__file__).resolve().parents[1]
        main_source = (root / "app" / "main.py").read_text()
        block = main_source[main_source.index("def current_user"):main_source.index("def session_auth_state")]
        self.assertIn('session_generation is None or int(session_generation) != generation', block)
        self.assertIn('request.session.clear()', block)
        self.assertNotIn('request.session["auth_generation"] = generation', block)

    def test_main_imports_runtime_auth_helpers_used_by_session_state(self):
        root = Path(__file__).resolve().parents[1]
        main_source = (root / "app" / "main.py").read_text()
        self.assertIn(
            "from app.auth import AuthManager, AuthError, fresh_auth_valid, shared_display_privilege_valid",
            main_source,
        )
        session_block = main_source[
            main_source.index("def session_auth_state"):
            main_source.index("def require_role")
        ]
        self.assertIn("shared_display_privilege_valid(", session_block)
        self.assertIn("fresh_auth_valid(", session_block)

    def test_main_binds_unlock_to_current_process_and_clears_on_manual_lock(self):
        root = Path(__file__).resolve().parents[1]
        main_source = (root / "app" / "main.py").read_text()
        self.assertIn("PROCESS_BOOT_ID = secrets.token_urlsafe(18)", main_source)
        self.assertIn('request.session["privileged_boot_id"] = PROCESS_BOOT_ID', main_source)
        self.assertIn('request.session["fresh_auth_boot_id"] = PROCESS_BOOT_ID', main_source)
        self.assertIn('request.session.pop("fresh_auth_boot_id", None)', main_source)
        self.assertIn('request.session.pop("privileged_boot_id", None)', main_source)

class DeviceLifecycleClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "policy.db")
        self.store = PolicyStore(self.db_path)
        self.ip = "192.168.2.102"

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_per_ip_state(self):
        self.store.update_device(
            self.ip,
            alias="Old tablet",
            notes="belongs to previous hardware",
            profile_id=None,
            mode_override="blocked",
            category="tablet",
            favourite=True,
        )
        with self.store._db() as db:
            db.execute(
                "INSERT INTO schedule_plans (label,target_type,target_value,action_type,action_value,clock_time,days,enabled) VALUES (?,?,?,?,?,?,?,1)",
                ("Old bedtime", "device", self.ip, "mode", "blocked", "20:00", '[0,1,2,3,4]'),
            )
            db.execute(
                "INSERT INTO date_exceptions (label,start_date,end_date,target_type,target_value,mode,template_id,notes) VALUES (?,?,?,?,?,?,NULL,?)",
                ("Old holiday", "2026-09-01", "2026-09-02", "device", self.ip, "normal", "old device"),
            )
            db.execute(
                "INSERT INTO reward_accounts (ip,balance_minutes,updated_at) VALUES (?,?,?)",
                (self.ip, 45, "2026-09-09T00:00:00+00:00"),
            )
            db.execute(
                """INSERT INTO policy_state_history
                   (captured_at,ip,state_hash,source,desired_mode,mode_source,bandwidth_preset,blocked_services,policy_groups,schedule_active,schedule_reason,active_date_exception,quota_state,policy_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("2026-09-09T00:00:00+00:00", self.ip, "abc", "test", "blocked", "test", "normal", "[]", "[]", 0, "", "{}", "{}", "2026-09-09T00:00:00+00:00"),
            )

    def test_retire_device_removes_live_ip_authority_but_keeps_history(self):
        self._seed_per_ip_state()
        result = self.store.retire_device_state(self.ip)
        self.assertEqual(result["device_policy"], 1)
        self.assertEqual(result["schedule_plans"], 1)
        self.assertEqual(result["date_exceptions"], 1)
        self.assertEqual(result["reward_accounts"], 1)
        self.assertNotIn(self.ip, self.store.list_device_policy())
        with self.store._db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM schedule_plans WHERE target_type='device' AND target_value=?", (self.ip,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM date_exceptions WHERE target_type='device' AND target_value=?", (self.ip,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reward_accounts WHERE ip=?", (self.ip,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM policy_state_history WHERE ip=?", (self.ip,)).fetchone()[0], 1)

    def test_ip_reuse_starts_with_clean_local_policy(self):
        self._seed_per_ip_state()
        self.store.retire_device_state(self.ip)
        self.store.update_device(self.ip)
        row = self.store.list_device_policy()[self.ip]
        self.assertEqual(row["alias"], "")
        self.assertEqual(row["notes"], "")
        self.assertIsNone(row["profile_id"])
        self.assertEqual(row["mode_override"], "inherit")
        self.assertEqual(row["category"], "other")
        self.assertEqual(row["favourite"], 0)


    def test_main_remove_route_retires_live_ip_keyed_state(self):
        root = Path(__file__).resolve().parents[1]
        main_source = (root / "app" / "main.py").read_text()
        start = main_source.index('@app.post("/devices/remove")')
        end = main_source.index('@app.post("/web-policy")', start)
        block = main_source[start:end]
        self.assertIn("cancel_device_temporary_access(ip, restore=False)", block)
        self.assertIn("remove_restricted_device(ip)", block)
        self.assertIn("policy_store.retire_device_state(ip)", block)
        self.assertNotIn("delete_reward_account(ip)", block)

    def test_retire_device_does_not_remove_other_devices(self):
        self.store.update_device(self.ip, alias="Old")
        other = "192.168.2.103"
        self.store.update_device(other, alias="Keep")
        self.store.retire_device_state(self.ip)
        policies = self.store.list_device_policy()
        self.assertNotIn(self.ip, policies)
        self.assertEqual(policies[other]["alias"], "Keep")


class SharedDisplayUxClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.index = (root / "app" / "templates" / "index.html").read_text()

    def test_help_is_top_nav_after_settings_and_root_strip_is_removed(self):
        settings = self.index.index('data-tab="settings"')
        help_item = self.index.index('data-tab="help"')
        self.assertGreater(help_item, settings)
        self.assertNotIn('{% include "_context_help.jinja" %}', self.index)
        self.assertIn('>Help</a>', self.index)
        self.assertIn('topic={{ zen_help_for_context(active_view, active_section).key }}', self.index)

    def test_unlock_state_is_compact_in_header_without_page_banner(self):
        header = self.index.split("</header>", 1)[0]
        self.assertIn('header-parent-unlock-form', header)
        self.assertIn('header-parent-countdown', header)
        self.assertIn('Lock now', header)
        self.assertNotIn('parent-unlock-banner', self.index)
        self.assertIn('aria-label="Parent unlock time remaining"', header)

    def test_shared_display_forms_preserve_current_context(self):
        self.assertGreaterEqual(
            self.index.count('name="next_tab" value="{{ active_view }}/{{ active_section }}"'),
            2,
        )


if __name__ == "__main__":
    unittest.main()
