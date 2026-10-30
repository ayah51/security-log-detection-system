
import csv
import ipaddress
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


# =========================
# Configuration
# =========================

FILE_NAME = "Sample_security_logs.csv"
ALERTS_FILE = "detection_alerts.csv"

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

FAILED_LOGIN_THRESHOLD = 5
WINDOW_MINUTES = 5

# Additional rule: one IP targeting multiple accounts
MULTI_ACCOUNT_THRESHOLD = 3

# ML is skipped when there are too few distinct IPs
MIN_IPS_FOR_ML = 5
ANOMALY_CONTAMINATION = "auto"

REQUIRED_FIELDS = {
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "status",
}

VALID_STATUSES = {"success", "failed"}


# =========================
# Input Validation
# =========================

def load_and_validate_logs(filename):
    """Load CSV logs and report invalid records."""

    try:
        df = pd.read_csv(filename, dtype=str)
    except FileNotFoundError:
        raise SystemExit(f"ERROR: File not found: {filename}")
    except pd.errors.EmptyDataError:
        raise SystemExit("ERROR: CSV file is empty or has no header.")
    except (pd.errors.ParserError, OSError) as error:
        raise SystemExit(f"ERROR: Could not read CSV: {error}")

    df.columns = [str(col).strip().lower() for col in df.columns]

    if len(df.columns) != len(set(df.columns)):
        raise SystemExit("ERROR: Duplicate column names found.")

    missing = REQUIRED_FIELDS - set(df.columns)

    if missing:
        raise SystemExit(
            f"ERROR: Missing required columns: {sorted(missing)}"
        )

    if df.empty:
        print("WARNING: CSV contains a header but no records.")
        return pd.DataFrame(columns=sorted(REQUIRED_FIELDS)), 0

    valid_records = []
    invalid_count = 0

    for row_number, row in df.iterrows():
        errors = []

        record = {
            str(key).strip().lower(): (
                value.strip() if isinstance(value, str) else ""
            )
            for key, value in row.items()
        }

        # Check required values
        for field in REQUIRED_FIELDS:
            if not record.get(field):
                errors.append(f"{field} is missing")

        # Validate timestamp
        if not any("timestamp is missing" in e for e in errors):
            try:
                pd.to_datetime(
                    record["timestamp"],
                    format=TIME_FORMAT,
                    errors="raise",
                )
            except (ValueError, TypeError):
                errors.append("invalid timestamp format")

        # Validate IP address
        if not any("source_ip is missing" in e for e in errors):
            try:
                ipaddress.ip_address(record["source_ip"])
            except ValueError:
                errors.append("invalid source IP")

        # Normalize values
        record["status"] = record.get("status", "").lower()
        record["event_type"] = record.get("event_type", "").lower()

        if record.get("status") and record["status"] not in VALID_STATUSES:
            errors.append("invalid status")

        if errors:
            print(
                f"Invalid CSV row {row_number + 2}: "
                + ", ".join(errors)
            )
            invalid_count += 1
            continue

        valid_records.append(record)

    clean_df = pd.DataFrame(valid_records)

    if not clean_df.empty:
        clean_df["timestamp"] = pd.to_datetime(
            clean_df["timestamp"],
            format=TIME_FORMAT,
        )

    return clean_df, invalid_count


# =========================
# Alert Management
# =========================

def create_alert(alerts, alert_type, source_ip, severity, reason,
                 event_count=0, username=""):
    alerts.append({
        "alert_type": alert_type,
        "source_ip": source_ip,
        "username": username,
        "event_count": event_count,
        "severity": severity,
        "reason": reason,
    })


# =========================
# Rule-Based Detection
# =========================

def detect_repeated_failed_logins(df, alerts):
    """Detect threshold failed logins within a time window."""

    failed = df[
        (df["event_type"] == "login")
        & (df["status"] == "failed")
    ]

    window = timedelta(minutes=WINDOW_MINUTES)

    for source_ip, group in failed.groupby("source_ip"):
        timestamps = sorted(group["timestamp"].tolist())
        left = 0

        for right, current_time in enumerate(timestamps):
            while current_time - timestamps[left] > window:
                left += 1

            attempts = right - left + 1

            if attempts >= FAILED_LOGIN_THRESHOLD:
                create_alert(
                    alerts,
                    "Repeated Failed Login Attempts",
                    source_ip,
                    "Medium",
                    (
                        f"{attempts} failed logins within "
                        f"{WINDOW_MINUTES} minutes"
                    ),
                    attempts,
                )
                break


def detect_multiple_account_attempts(df, alerts):
    """Detect failed login activity targeting multiple accounts."""

    failed = df[
        (df["event_type"] == "login")
        & (df["status"] == "failed")
    ]

    for source_ip, group in failed.groupby("source_ip"):
        usernames = group["username"].nunique()

        if usernames >= MULTI_ACCOUNT_THRESHOLD:
            create_alert(
                alerts,
                "Multiple Account Targeting",
                source_ip,
                "Medium",
                (
                    f"Failed logins targeted {usernames} "
                    "different accounts"
                ),
                len(group),
            )


# =========================
# Machine Learning
# =========================

def detect_anomalies_with_ml(df, alerts):
    """
    Use Isolation Forest to flag unusual IP-level activity.

    This identifies statistical anomalies, not confirmed attacks.
    """

    if df.empty:
        print("ML skipped: no valid records.")
        return

    ip_features = df.groupby("source_ip").agg(
        total_events=("source_ip", "size"),
        failed_logins=(
            "status",
            lambda values: (values == "failed").sum(),
        ),
        successful_logins=(
            "status",
            lambda values: (values == "success").sum(),
        ),
        unique_usernames=("username", "nunique"),
        unique_event_types=("event_type", "nunique"),
    )

    ip_features["failed_ratio"] = (
        ip_features["failed_logins"]
        / ip_features["total_events"]
    )

    if len(ip_features) < MIN_IPS_FOR_ML:
        print(
            "ML skipped: need at least "
            f"{MIN_IPS_FOR_ML} distinct IP addresses; "
            f"found {len(ip_features)}."
        )
        print(
            "Use a larger dataset for meaningful "
            "anomaly detection."
        )
        return

    model = IsolationForest(
        n_estimators=100,
        contamination=ANOMALY_CONTAMINATION,
        random_state=42,
    )

    predictions = model.fit_predict(ip_features)

    for source_ip, prediction in zip(
        ip_features.index, predictions
    ):
        if prediction == -1:
            features = ip_features.loc[source_ip]

            create_alert(
                alerts,
                "ML Anomaly",
                source_ip,
                "Review",
                (
                    "Unusual IP-level activity detected by "
                    "Isolation Forest; investigate before "
                    "classifying as malicious"
                ),
                int(features["total_events"]),
            )


# =========================
# Main Program
# =========================

def main():
    print("=" * 50)
    print("SECURITY LOG DETECTION SYSTEM - WEEK 3")
    print("=" * 50)

    df, invalid_count = load_and_validate_logs(FILE_NAME)

    print(f"\nValid log events: {len(df)}")
    print(f"Invalid log events skipped: {invalid_count}")

    if df.empty:
        print("No valid records available for detection.")
        return

    print(
        "Successful logins:",
        int((df["status"] == "success").sum()),
    )
    print(
        "Failed logins:",
        int((df["status"] == "failed").sum()),
    )
    print(
        "Distinct source IPs:",
        df["source_ip"].nunique(),
    )

    alerts = []

    print("\nRunning rule-based detection...")
    detect_repeated_failed_logins(df, alerts)
    detect_multiple_account_attempts(df, alerts)

    print("Running ML anomaly detection...")
    detect_anomalies_with_ml(df, alerts)

    print("\n" + "=" * 50)
    print("DETECTION RESULTS")
    print("=" * 50)

    if alerts:
        alerts_df = pd.DataFrame(alerts)

        for number, alert in enumerate(alerts, start=1):
            print(f"\nAlert #{number}")
            for key, value in alert.items():
                print(f"{key}: {value}")

        output_path = Path(ALERTS_FILE)
        alerts_df.to_csv(
            output_path,
            index=False,
            encoding="utf-8-sig",
            quoting=csv.QUOTE_MINIMAL,
        )

        print(f"\nAlerts saved to: {output_path.resolve()}")
        print(f"Total alerts: {len(alerts)}")
    else:
        print("No alerts generated.")
        print("No alert CSV was created because there are no alerts.")


if __name__ == "__main__":
    main()