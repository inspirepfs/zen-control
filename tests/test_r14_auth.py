import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from app.auth import AuthError, AuthManager


class AuthManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "policy.db")
        self.auth = AuthManager(
            self.db_path,
            encryption_material="test-encryption-key-that-is-stable",
            issuer="ZEN Control Test",
        )
        self.user = "parent"

    def tearDown(self):
        self.tmp.cleanup()

    def enroll(self, name="Phone"):
        pending = self.auth.begin_enrollment(self.user, name)
        detail = self.auth.enrollment(self.user, pending["token"])
        self.assertIsNotNone(detail)
        code, _ = self.auth.totp(detail["secret"])
        result = self.auth.confirm_enrollment(self.user, pending["token"], code)
        return result, detail

    def test_rfc4226_hotp_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(self.auth.hotp(secret, 0), "755224")
        self.assertEqual(self.auth.hotp(secret, 1), "287082")

    def test_default_account_preserves_password_login(self):
        account = self.auth.account(self.user)
        self.assertEqual(account["login_mode"], "password")
        self.assertFalse(account["shared_display_mode"])
        self.assertEqual(account["unlock_minutes"], 5)
        self.assertEqual(self.auth.active_totp_count(self.user), 0)

    def test_enrollment_secret_is_encrypted_and_qr_is_local_data_uri(self):
        pending = self.auth.begin_enrollment(self.user, "Kitchen parent phone")
        detail = self.auth.enrollment(self.user, pending["token"])
        self.assertTrue(detail["qr_data_uri"].startswith("data:image/png;base64,"))
        self.assertIn("otpauth://totp/", detail["otpauth_uri"])
        with sqlite3.connect(self.db_path) as db:
            row = db.execute(
                "SELECT secret_enc FROM auth_totp_enrollments WHERE username=?",
                (self.user,),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn(detail["secret"], row[0])

    def test_multiple_authenticators_are_independent_and_replay_is_rejected(self):
        first, first_detail = self.enroll("Primary parent phone")
        second, second_detail = self.enroll("Second parent phone")
        self.assertEqual(self.auth.active_totp_count(self.user), 2)
        self.assertNotEqual(first_detail["secret"], second_detail["secret"])

        future = time.time() + 60
        code1, _ = self.auth.totp(first_detail["secret"], at=future)
        code2, _ = self.auth.totp(second_detail["secret"], at=future)
        used1 = self.auth.verify_totp(self.user, code1, at=future)
        self.assertEqual(used1["device_name"], "Primary parent phone")
        self.assertIsNone(self.auth.verify_totp(self.user, code1, at=future))
        used2 = self.auth.verify_totp(self.user, code2, at=future)
        self.assertEqual(used2["device_name"], "Second parent phone")

    def test_first_enrollment_creates_recovery_codes_and_codes_are_one_use(self):
        result, _ = self.enroll("Phone")
        codes = result["recovery_codes"]
        self.assertEqual(len(codes), 10)
        self.assertEqual(self.auth.remaining_recovery_codes(self.user), 10)
        self.assertTrue(self.auth.verify_recovery_code(self.user, codes[0]))
        self.assertFalse(self.auth.verify_recovery_code(self.user, codes[0]))
        self.assertEqual(self.auth.remaining_recovery_codes(self.user), 9)

    def test_otp_only_and_shared_display_require_enrolled_authenticator(self):
        with self.assertRaises(AuthError):
            self.auth.save_account_settings(
                self.user,
                login_mode="totp_only",
                shared_display_mode=False,
                unlock_minutes=5,
            )
        with self.assertRaises(AuthError):
            self.auth.save_account_settings(
                self.user,
                login_mode="password",
                shared_display_mode=True,
                unlock_minutes=5,
            )

        self.enroll("Phone")
        account = self.auth.save_account_settings(
            self.user,
            login_mode="totp_only",
            shared_display_mode=True,
            unlock_minutes=10,
        )
        self.assertEqual(account["login_mode"], "totp_only")
        self.assertTrue(account["shared_display_mode"])
        self.assertEqual(account["unlock_minutes"], 10)

    def test_cannot_revoke_final_device_while_it_is_authentication_authority(self):
        result, _ = self.enroll("Only phone")
        device_id = result["device"]["id"]
        self.auth.save_account_settings(
            self.user,
            login_mode="totp_only",
            shared_display_mode=True,
            unlock_minutes=5,
        )
        with self.assertRaises(AuthError):
            self.auth.revoke_totp_device(self.user, device_id)

        self.auth.save_account_settings(
            self.user,
            login_mode="password",
            shared_display_mode=False,
            unlock_minutes=5,
        )
        revoked = self.auth.revoke_totp_device(self.user, device_id)
        self.assertIsNotNone(revoked["revoked_at"])

    def test_revoke_all_sessions_bumps_server_side_generation(self):
        self.assertEqual(self.auth.session_generation(self.user), 0)
        self.assertEqual(self.auth.revoke_all_sessions(self.user), 1)
        self.assertEqual(self.auth.revoke_all_sessions(self.user), 2)

    def test_expired_enrollment_is_rejected(self):
        pending = self.auth.begin_enrollment(self.user, "Expired phone")
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "UPDATE auth_totp_enrollments SET expires_at='2000-01-01T00:00:00+00:00'"
            )
            db.commit()
        self.assertIsNone(self.auth.enrollment(self.user, pending["token"]))

    def test_wrong_encryption_key_fails_closed_but_recovery_codes_remain_break_glass(self):
        result, _ = self.enroll("Phone")
        recovery = result["recovery_codes"][0]
        pending = self.auth.begin_enrollment(self.user, "Second phone")
        other = AuthManager(
            self.db_path,
            encryption_material="different-key",
            issuer="ZEN Control Test",
        )
        with self.assertRaises(AuthError):
            other.enrollment(self.user, pending["token"])
        self.assertEqual(other.verify_otp_or_recovery(self.user, recovery)["method"], "recovery")


if __name__ == "__main__":
    unittest.main()
