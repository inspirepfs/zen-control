import tempfile
import time
import unittest
from pathlib import Path

from app.auth import (
    AuthManager,
    extend_shared_display_deadline,
    shared_display_extension_allowed,
)


class ParentOtpLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.auth = AuthManager(
            str(Path(self.tmp.name) / "policy.db"),
            encryption_material="v0502-test-key",
            issuer="ZEN Control Test",
        )
        self.user = "parent"
        pending = self.auth.begin_enrollment(self.user, "Parent phone")
        detail = self.auth.enrollment(self.user, pending["token"])
        self.secret = detail["secret"]
        now = time.time()
        code, _ = self.auth.totp(self.secret, at=now)
        self.auth.confirm_enrollment(self.user, pending["token"], code)
        self.base = now

    def tearDown(self):
        self.tmp.cleanup()

    def test_exact_totp_value_remains_single_use(self):
        at = self.base + 60
        code, _ = self.auth.totp(self.secret, at=at)
        self.assertIsNotNone(self.auth.verify_totp(self.user, code, at=at))
        self.assertIsNone(self.auth.verify_totp(self.user, code, at=at))

    def test_later_totp_window_is_not_blocked_by_previous_use(self):
        first_at = self.base + 60
        first, first_counter = self.auth.totp(self.secret, at=first_at)
        self.assertEqual(first_counter, self.auth.verify_totp(self.user, first, at=first_at)["counter"])

        later_at = self.base + 300
        later, later_counter = self.auth.totp(self.secret, at=later_at)
        result = self.auth.verify_totp(self.user, later, at=later_at)
        self.assertIsNotNone(result)
        self.assertEqual(later_counter, result["counter"])
        self.assertGreater(later_counter, first_counter)


class SharedDisplayExtensionPolicyTests(unittest.TestCase):
    def test_extension_only_available_near_end_of_active_current_process_window(self):
        now = 1_800_000_000.0
        self.assertTrue(shared_display_extension_allowed(
            shared_display_mode=True,
            privileged_until=now + 60,
            privileged_boot_id="boot-a",
            process_boot_id="boot-a",
            now=now,
        ))
        self.assertFalse(shared_display_extension_allowed(
            shared_display_mode=True,
            privileged_until=now + 91,
            privileged_boot_id="boot-a",
            process_boot_id="boot-a",
            now=now,
        ))

    def test_locked_expired_or_wrong_process_window_cannot_extend(self):
        now = 1_800_000_000.0
        for kwargs in (
            dict(shared_display_mode=True, privileged_until=now - 1, privileged_boot_id="boot-a", process_boot_id="boot-a"),
            dict(shared_display_mode=True, privileged_until=now + 60, privileged_boot_id="old", process_boot_id="boot-a"),
            dict(shared_display_mode=False, privileged_until=now + 60, privileged_boot_id="boot-a", process_boot_id="boot-a"),
        ):
            self.assertFalse(shared_display_extension_allowed(now=now, **kwargs))

    def test_extension_adds_one_configured_window_without_shortening_existing_time(self):
        now = 1_800_000_000.0
        self.assertEqual(
            now + 60 + 300,
            extend_shared_display_deadline(
                privileged_until=now + 60,
                unlock_minutes=5,
                now=now,
            ),
        )
        self.assertEqual(
            now + 300,
            extend_shared_display_deadline(
                privileged_until=now - 1,
                unlock_minutes=5,
                now=now,
            ),
        )


class ParentUnlockExtensionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.main = (cls.root / "app/main.py").read_text(encoding="utf-8")
        cls.index = (cls.root / "app/templates/index.html").read_text(encoding="utf-8")
        cls.help = (cls.root / "app/help_content.py").read_text(encoding="utf-8")
        cls.readme = (cls.root / "README.md").read_text(encoding="utf-8") + "\n" + (cls.root / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_more_time_route_requires_role_csrf_active_window_and_fresh_parent_code(self):
        block = self.main.split('@app.post("/auth/extend")', 1)[1].split('@app.post("/auth/lock")', 1)[0]
        self.assertIn('user["role"] not in {"admin", "operator"}', block)
        self.assertIn("csrf_ok(request, csrf)", block)
        self.assertIn("shared_display_extension_allowed(", block)
        self.assertIn("auth_manager.verify_otp_or_recovery", block)
        self.assertLess(block.index("shared_display_extension_allowed("), block.index("verify_otp_or_recovery"))
        self.assertIn('fail_key = f"extend:', block)
        self.assertIn("extend_shared_display_deadline(", block)
        self.assertIn('"PARENT_UNLOCK_EXTENDED"', block)

    def test_more_time_cannot_be_a_code_free_button(self):
        header = self.index.split("</header>", 1)[0]
        form = header.split('action="/auth/extend"', 1)[1].split("</form>", 1)[0]
        self.assertIn('name="otp"', form)
        self.assertIn("required", form)
        self.assertIn("Fresh OTP", form)
        self.assertIn(">More time</button>", form)

    def test_more_time_is_revealed_only_in_final_minute_and_preserves_context(self):
        self.assertIn("data-parent-extend-form", self.index)
        self.assertIn("left > 0 && left <= 60", self.index)
        self.assertIn("node.hidden", self.index)
        header = self.index.split("</header>", 1)[0]
        self.assertIn('name="next_tab" value="{{ active_view }}/{{ active_section }}"', header)
        css = (self.root / "app/static/activity.css").read_text(encoding="utf-8")
        self.assertIn(".header-parent-extend-form[hidden]{display:none!important}", css)

    def test_unlock_failure_explains_single_use_without_relaxing_replay_protection(self):
        unlock = self.main.split('@app.post("/auth/unlock")', 1)[1].split('@app.post("/auth/extend")', 1)[0]
        self.assertIn("Authenticator codes are single-use", unlock)
        auth_source = (self.root / "app/auth.py").read_text(encoding="utf-8")
        self.assertIn("if counter <= int(last_used_counter):", auth_source)

    def test_help_and_release_document_security_boundary(self):
        self.assertIn("single-use replay-protected", self.help)
        self.assertIn("cannot be stacked early", self.help)
        self.assertIn("v0.50.2", self.readme)
        self.assertIn("No RouterOS authority", self.readme)

    def test_release_readiness_matrix_records_parent_unlock_hardening(self):
        release = (self.root / "app/release_readiness.py").read_text(encoding="utf-8")
        self.assertIn('("parent_unlock", "Parent unlock & time-extension hardening", "0.50.2")', release)

    def test_release_version_and_pwa_assets_are_current(self):
        self.assertIn('version="0.55.4"', self.main)
        self.assertIn('/static/app.css?v=0.55.4', self.index)
        self.assertIn("const RELEASE = '0.55.4'", (self.root / "app/static/pwa.js").read_text())
        self.assertIn("PWA_RELEASE = \"0.55.4\"", (self.root / "app/pwa.py").read_text())


if __name__ == "__main__":
    unittest.main()
