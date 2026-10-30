Security Log Detection System (MVP)
A hybrid Python cybersecurity detection engine that combines deterministic sliding-window security rules with unsupervised Machine Learning (Isolation Forest) to detect authentication threats, brute-force attempts, and credential spraying in security logs.
Key Features & Capabilities
Automated Log Parsing & Schema Validation: Checks for required fields (`timestamp`, `source_ip`, `username`, `event_type`, `status`), normalizes whitespace, parses ISO timestamps, and discards corrupt/malformed records.
Deterministic Brute-Force Detection: Detects $\ge 5$ failed login attempts from the same source IP within a rolling 5-minute sliding time window.
Password Spraying Detection: Identifies source IPs targeting $\ge 3$ distinct user accounts to prevent single-account lockout evasion.
Unsupervised Anomaly Detection: Applies an `IsolationForest` model (scikit-learn) on behavioral aggregations (failure ratio, target account cardinality, event counts) to flag non-linear statistical outliers.
Structured Alert Output: Exports findings into a standardized CSV report (`detection_alerts.csv`) with severity ratings and detection reasoning.
Accuracy & Detection Reliability Safeguards
To ensure accurate detection results and minimize False Positive / False Negative rates, the engine integrates the following safeguards:
Pre-Filter Data Cleaning: Malformed IP syntax and corrupted timestamps are isolated and ignored prior to detection evaluation, preventing polluted inputs from triggering false alarms.
Rolling Window Precision: Dynamic time-delta calculations track sliding minute boundaries precisely, avoiding blind spots caused by static hour-chunking.
Statistical ML Guardrail: The Isolation Forest model automatically skips execution if the log dataset contains fewer than 5 distinct IP addresses (`MIN_IPS_FOR_ML = 5`), preventing false anomaly spikes on small sample sizes.
Alert Deduplication: Consecutive attacks originating from the same IP within the same timeframe are grouped to reduce alert fatigue for SOC analysts.
Repository Structure
```
security-log-detection-system/
│
├── main.py                    # Primary detection engine & ML algorithm
├── Sample_security_logs.csv                     # Primary sample dataset for execution
├── Sample_security_logs2.csv                    # Additional test log dataset
├── Sample_security_logs3.csv                    # Additional test log dataset
├── Sample_security_logs4.csv                    # Additional test log dataset
├── Sample_security_logs5.csv                    # Additional test log dataset
├── detection_alerts.csv                         # Auto-generated alert report output
├── Project Design.docx                          # Architecture & system design document
├── Test Results Report.docx                     # Detailed test execution & validation report
├── Security Log Detection System - Project...pdf # Final 2-Page Technical Project Report
├── Week 1 - Problem Identification...docx       # Phase 1 project documentation
├── Week 3 - Further Development and Testi...docx# Phase 3 project documentation
├── test_detection.py                            # Test suite: Rule-based logic
├── test_main.py                                 # Test suite: System workflow
├── test_ml.py                                   # Test suite: Isolation Forest ML
├── test_ml_detection.py                         # Combined validation test suite
└── README.md                                    # Project documentation
```
Installation & Execution
Clone the repository:
```bash
   git clone https://github.com/ayah51/security-log-detection-system.git
   cd security-log-detection-system
   ```
Install dependencies:
```bash
   pip install pandas scikit-learn
   ```
Run the detection script:
```bash
   python main.py
   ```
Empirical Test Suite Results
The system was evaluated against controlled synthetic log datasets representing normal and malicious authentication behaviors:
Test Case	Scenario Description	Condition	Result
TC-01	Threshold Exceeded	5 failed logins within 5 mins	PASS
TC-02	Below Threshold	4 failed logins within 5 mins	PASS
TC-03	Distributed IPs	5 failed logins spread across 3 IPs	PASS
TC-04	Time Window Drift	5 failed logins spread over 8 mins	PASS
TC-05	Boundary Condition	Exactly 5 failed logins at 5:00 min	PASS
License & Acknowledgments
Developed for educational and security research purposes as part of the CyberFox Society Cybersecurity R&D Internship.
