
import unittest
from unittest.mock import patch

import pandas as pd

from main import detect_anomalies_with_ml


class TestMLDetection(unittest.TestCase):

    def setUp(self):
        self.logs = pd.DataFrame({
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
                "failed",
                "failed",
                "success",
            ],
            "username": [
                "aya",
                "mona",
                "ahmed",
                "admin",
                "admin",
                "sara",
            ],
            "event_type": ["login"] * 6,
        })

    @patch("main.IsolationForest")
    def test_ml_anomaly_generates_alert(self, mock_isolation_forest):
        model = mock_isolation_forest.return_value

        # Simulate the model flagging the first IP as anomalous.
        model.fit_predict.return_value = [
            -1, 1, 1, 1, 1, 1
        ]

        alerts = []

        detect_anomalies_with_ml(self.logs, alerts)

        ml_alerts = [
            alert for alert in alerts
            if alert["alert_type"] == "ML Anomaly"
        ]

        self.assertEqual(len(ml_alerts), 1)
        self.assertEqual(
            ml_alerts[0]["source_ip"], "192.0.2.1"
        )
        self.assertEqual(ml_alerts[0]["severity"], "Review")

        # Verify that the expected features were passed to the model.
        features = model.fit_predict.call_args.args[0]

        expected_columns = {
            "total_events",
            "failed_logins",
            "successful_logins",
            "unique_usernames",
            "unique_event_types",
            "failed_ratio",
        }

        self.assertEqual(set(features.columns), expected_columns)
        self.assertEqual(len(features), 6)

    @patch("main.IsolationForest")
    def test_no_ml_alert_when_model_finds_no_anomalies(
        self, mock_isolation_forest
    ):
        model = mock_isolation_forest.return_value
        model.fit_predict.return_value = [1, 1, 1, 1, 1, 1]

        alerts = []

        detect_anomalies_with_ml(self.logs, alerts)

        self.assertFalse(
            any(
                alert["alert_type"] == "ML Anomaly"
                for alert in alerts
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)