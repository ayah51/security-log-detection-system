
import unittest
import pandas as pd

from main import (
    detect_repeated_failed_logins,
    detect_multiple_account_attempts,
)


class TestDetectionRules(unittest.TestCase):

    def setUp(self):
        self.logs = pd.DataFrame({
            "timestamp": pd.to_datetime([
                "2026-10-14 09:00:00",
                "2026-10-14 09:01:00",
                "2026-10-14 09:02:00",
                "2026-10-14 09:03:00",
                "2026-10-14 09:04:00",
            ]),
            "source_ip": ["192.0.2.20"] * 5,
            "username": ["admin"] * 5,
            "event_type": ["login"] * 5,
            "status": ["failed"] * 5,
        })

    def test_repeated_failed_logins(self):
        alerts = []

        detect_repeated_failed_logins(self.logs, alerts)

        self.assertTrue(
            any(
                alert["alert_type"] == "Repeated Failed Login Attempts"
                for alert in alerts
            )
        )

    def test_multiple_account_targeting(self):
        logs = self.logs.copy()
        logs["username"] = [
            "admin", "aya", "mona", "ahmed", "admin"
        ]

        alerts = []

        detect_multiple_account_attempts(logs, alerts)

        self.assertTrue(
            any(
                alert["alert_type"] == "Multiple Account Targeting"
                for alert in alerts
            )
        )

    def test_no_alert_below_failed_login_threshold(self):
        logs = self.logs.iloc[:4].copy()
        alerts = []

        detect_repeated_failed_logins(logs, alerts)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)