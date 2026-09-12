import tempfile
import unittest
from pathlib import Path

from app.policy_store import PolicyStore


class IncidentSuppressionRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_manual_resolve_stays_resolved_until_clear_then_can_reopen(self):
        first = self.store.upsert_incident(
            fingerprint="bypass:192.168.2.22",
            source="bypass",
            severity="warning",
            title="Managed-device bypass risk is ELEVATED",
            detail="signal present",
            subject="192.168.2.22",
        )
        resolved = self.store.resolve_incident(first["id"], "parent", "reviewed")
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["suppress_until_clear"], 1)

        still_present = self.store.upsert_incident(
            fingerprint="bypass:192.168.2.22",
            source="bypass",
            severity="warning",
            title="Managed-device bypass risk is ELEVATED",
            detail="signal still present",
            subject="192.168.2.22",
        )
        self.assertEqual(still_present["action"], "suppressed")
        self.assertEqual(still_present["status"], "resolved")
        self.assertEqual(self.store.incident_counts()["active"], 0)

        self.store.resolve_inactive_incidents("bypass", set())
        cleared = self.store.get_incident(first["id"])
        self.assertEqual(cleared["suppress_until_clear"], 0)

        returned = self.store.upsert_incident(
            fingerprint="bypass:192.168.2.22",
            source="bypass",
            severity="warning",
            title="Managed-device bypass risk is ELEVATED",
            detail="new signal after clear",
            subject="192.168.2.22",
        )
        self.assertEqual(returned["action"], "reopened")
        self.assertEqual(returned["status"], "open")


if __name__ == "__main__":
    unittest.main()
