
import unittest
import pandas as pd

from main import detect_anomalies_with_ml


class TestMachineLearning(unittest.TestCase):

    def test_ml_skips_small_dataset(self):
        logs = pd.DataFrame({
            "source_ip": ["192.0.2.1", "192.0.2.2"],
            "status": ["success", "failed"],
            "username": ["aya", "admin"],
            "event_type": ["login", "login"],
        })

        alerts = []

        detect_anomalies_with_ml(logs, alerts)

        # The current implementation skips ML below five IPs.
        self.assertEqual(alerts, [])

    def test_ml_runs_with_enough_distinct_ips(self):
        logs = pd.DataFrame({
            "source_ip": [
                "192.0.2.1",
                "192.0.2.2",
                "192.0.2.3",
                "192.0.2.4",
                "192.0.2.5",
                "192.0.2.6",
            ],
            "status": [
                "success",
                "success",
                "success",
                "success",
                "failed",
                "failed",
            ],
            "username": [
                "aya",
                "mona",
                "ahmed",
                "sara",
                "admin",
                "admin",
            ],
            "event_type": ["login"] * 6,
        })

        alerts = []

        detect_anomalies_with_ml(logs, alerts)

        # ML should run without raising an exception.
        # It is not guaranteed to flag an anomaly.
        self.assertIsInstance(alerts, list)

    def test_ml_handles_empty_dataset(self):
        logs = pd.DataFrame(columns=[
            "source_ip",
            "status",
            "username",
            "event_type",
        ])

        alerts = []

        detect_anomalies_with_ml(logs, alerts)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)