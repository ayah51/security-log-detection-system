
import csv
import tempfile
import unittest
from pathlib import Path

from main import load_and_validate_logs


FIELDS = [
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "status",
]


class TestInputValidation(unittest.TestCase):

    def write_csv(self, folder, rows, fields=FIELDS):
        path = Path(folder) / "test_logs.csv"

        with path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fields,
            )
            writer.writeheader()
            writer.writerows(rows)

        return str(path)

    def test_valid_record(self):
        """A valid log record should be accepted."""

        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, [{
                "timestamp": "2026-10-14 09:00:00",
                "source_ip": "192.0.2.10",
                "username": "aya",
                "event_type": "login",
                "status": "success",
            }])

            df, invalid = load_and_validate_logs(path)

            self.assertEqual(len(df), 1)
            self.assertEqual(invalid, 0)

    def test_invalid_timestamp_is_skipped(self):
        """An invalid timestamp should be rejected."""

        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, [{
                "timestamp": "not-a-date",
                "source_ip": "192.0.2.10",
                "username": "aya",
                "event_type": "login",
                "status": "success",
            }])

            df, invalid = load_and_validate_logs(path)

            self.assertEqual(len(df), 0)
            self.assertEqual(invalid, 1)

    def test_invalid_ip_is_skipped(self):
        """An invalid IP address should be rejected."""

        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, [{
                "timestamp": "2026-10-14 09:00:00",
                "source_ip": "invalid-ip",
                "username": "aya",
                "event_type": "login",
                "status": "success",
            }])

            df, invalid = load_and_validate_logs(path)

            self.assertEqual(len(df), 0)
            self.assertEqual(invalid, 1)

    def test_missing_required_column(self):
        """Missing required columns should stop processing."""

        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(
                folder,
                [],
                fields=["timestamp", "source_ip", "status"],
            )

            with self.assertRaises(SystemExit):
                load_and_validate_logs(path)

    def test_empty_csv(self):
        """A completely empty CSV file should be rejected."""

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "empty.csv"
            path.write_text("", encoding="utf-8")

            with self.assertRaises(SystemExit):
                load_and_validate_logs(str(path))

    def test_missing_required_value(self):
        """A record with a missing username should be rejected."""

        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, [{
                "timestamp": "2026-10-14 09:00:00",
                "source_ip": "192.0.2.10",
                "username": "",
                "event_type": "login",
                "status": "success",
            }])

            df, invalid = load_and_validate_logs(path)

            self.assertEqual(len(df), 0)
            self.assertEqual(invalid, 1)

    def test_alternative_timestamp_format_is_rejected(self):
        """Dates outside the required format should be rejected."""

        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, [{
                "timestamp": "10/14/2026 09:00",
                "source_ip": "192.0.2.10",
                "username": "aya",
                "event_type": "login",
                "status": "success",
            }])

            df, invalid = load_and_validate_logs(path)

            self.assertEqual(len(df), 0)
            self.assertEqual(invalid, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)