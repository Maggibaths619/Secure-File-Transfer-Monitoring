# Secure File Transfer Monitoring System
## Project Report — Cybersecurity Internship

**Organization:** UnifiedMentor  
**Domain:** Cybersecurity  
**Project Title:** Secure File Transfer Monitoring System  
**Technologies:** Python 3.13, watchdog, hashlib, psutil, Flask, SQLite, Chart.js

---

## Abstract

This project presents the design, implementation, and testing of a **Secure File Transfer Monitoring System (SFTMS)** — a comprehensive Blue Team cybersecurity toolkit built in Python. The system provides real-time file system activity monitoring, multi-algorithm cryptographic integrity verification, DLP (Data Loss Prevention) policy enforcement, automated threat detection, and a live SOC (Security Operations Center) web dashboard. The system detects unauthorized data exfiltration, in-transit file tampering, mass bulk transfer anomalies, and critical file destruction events.

---

## 1. Problem Statement

Organizations face constant threats from:
- **Insider threats**: Employees copying sensitive data to USB drives, cloud sync folders, or personal storage.
- **Malware tampering**: Ransomware or APT (Advanced Persistent Threat) actors modifying files in transit.
- **Data exfiltration**: Unauthorized bulk transfer of confidential records (financial, HR, customer data).
- **Shadow IT**: Unmonitored use of sync tools (Dropbox, OneDrive) for data staging.
- **Destructive attacks**: Malicious deletion of critical cryptographic keys, databases, or backups.

Without active monitoring, these events go undetected until a security breach is confirmed — often hours or days later, when significant damage has already occurred.

---

## 2. Project Objectives

1. Monitor all file transfers on the system in real-time.
2. Detect unauthorized movement of sensitive or restricted files.
3. Implement file integrity checks using SHA-256, SHA3-256, and MD5 hashing.
4. Generate automated alerts on policy violations.
5. Produce detailed audit logs and security reports.
6. Provide a live SOC web dashboard for Blue Team analysts.

---

## 3. System Architecture

The SFTMS is structured into 6 interconnected modules:

### 3.1 File Monitor (`file_monitor.py`)
The entry point for all system activity. Uses the Python **watchdog** library to register filesystem event handlers across all configured monitoring directories. Events are debounced to prevent duplicate OS notifications and routed through the full detection pipeline.

**Events handled:**
- `FILE_CREATED` — new file created in monitored zone
- `FILE_MODIFIED` — existing file content or metadata changed
- `FILE_MOVED` — file renamed or relocated
- `FILE_DELETED` — file removed from monitored zone

### 3.2 DLP Classifier (`classifier_engine.py`)
Assigns one of five sensitivity tiers to each file using a cascading rules engine:

| Tier | Sensitivity | Examples |
|------|-------------|---------|
| HIGHLY_SENSITIVE | Critical | `.key`, `.pem`, `.kdbx`, `.pfx`, `.ppk` |
| CONFIDENTIAL | High | `.sql`, `.db`, `.env`, `.bak` |
| RESTRICTED | Medium | `.docx`, `.pdf`, `.xlsx`, `.csv` |
| INTERNAL | Low | `.json`, `.xml`, `.yaml`, `.cfg` |
| UNCLASSIFIED | None | Everything else |

**Three classification strategies (applied in priority order):**
1. **Path-segment matching** — file lives in a sensitive directory (e.g., `sensitive_vault/`, `credentials/`, `financial/`)
2. **Extension matching** — file has a sensitive extension
3. **Content keyword scanning** — first 4KB of file text is scanned for sensitive patterns (e.g., `CONFIDENTIAL`, `API_KEY`, `BEGIN RSA PRIVATE KEY`, `SSN`)

### 3.3 Integrity Engine (`integrity_engine.py`)
Provides cryptographic file verification using chunk-based reading (64KB chunks) for memory-safe processing of large files.

**Workflow:**
1. **Pre-transfer**: Compute SHA-256, SHA3-256, and MD5 of source file and store in SQLite hash baseline registry.
2. **Transfer occurs** (monitored in real-time).
3. **Post-transfer**: Compute hashes of destination/modified file.
4. **Verify**: Compare pre vs. post hashes across all three algorithms.
5. **Result**: `integrity_ok=True` (clean) or `tampered=True` (mismatch detected).

This approach detects:
- In-transit file injection/modification by malware
- Bit-rot or storage corruption
- Silent file replacement attacks

### 3.4 Policy Engine (`policy_engine.py`)
Evaluates each file event against 6 DLP rules:

| Rule | Trigger | Severity |
|------|---------|---------|
| 1. Integrity Violation | Pre/post hash mismatch | CRITICAL |
| 2. DLP Violation | Sensitive file → unauthorized destination | CRITICAL |
| 3. Protected Zone | Sensitive file leaving protected source | HIGH |
| 4. Burst Exfiltration | >10 transfers in 10 seconds | CRITICAL |
| 5. Destructive Action | Deletion of sensitive/classified file | HIGH |
| 6. Suspicious Process | cmd.exe, powershell.exe, rclone.exe, etc. | MEDIUM |

Rules are evaluated independently and violations are combined. The highest severity across all triggered rules determines the final alert level.

### 3.5 Alert Manager (`alert_manager.py`)
Centralized alert dispatcher with:
- **5 severity levels**: INFO, LOW, MEDIUM, HIGH, CRITICAL
- **Thread-safe FIFO queue** for SSE streaming to the web dashboard
- **Color-coded console output** via colorama
- **Subscriber callbacks** for custom integrations
- **In-memory alert history** with bounded size

### 3.6 Audit Logger (`logger_engine.py`)
Multi-channel structured logging to four simultaneous outputs:
1. `logs/transfers.json` — Machine-readable JSON Lines (one event per line)
2. `logs/audit.csv` — Spreadsheet-compatible CSV with all fields
3. `logs/system.log` — Human-readable formatted log file
4. `logs/audit_vault.db` — SQLite database for querying, reporting, and dashboard APIs

---

## 4. Implementation Details

### 4.1 Technologies Used

| Technology | Version | Purpose |
|-----------|---------|---------|
| Python | 3.13.3 | Core implementation language |
| watchdog | 6.0.0 | Filesystem event monitoring |
| hashlib | stdlib | SHA-256, SHA3-256, MD5 computation |
| psutil | 7.2.2 | Process tracking and attribution |
| Flask | 3.1.2 | SOC web dashboard server |
| sqlite3 | stdlib | Audit database storage |
| colorama | 0.4.6 | Colored terminal output |
| PyYAML | 6.0.3 | Configuration loading |
| pytest | 9.1.1 | Automated testing |

### 4.2 Configuration System
All system parameters are centralized in `config/config.yaml`, supporting:
- Multiple monitored directory paths
- Sensitive extension and keyword lists
- Unauthorized destination rules
- Burst detection thresholds
- Web server settings

### 4.3 SOC Web Dashboard
Built with Flask + vanilla JavaScript (no framework dependencies):
- **Server-Sent Events (SSE)** for live event streaming without WebSocket complexity
- **Chart.js** for real-time severity distribution and event type charts
- **Drag-and-drop file integrity verifier** — compute and compare hashes client-side via Flask API
- **One-click simulation trigger** — run all 5 attack scenarios from the browser
- **Audit report download** — export JSON or CSV reports on demand

---

## 5. Security Concepts Demonstrated

### 5.1 Data Loss Prevention (DLP)
The system implements a layered DLP architecture that classifies data sensitivity and enforces movement policies. This mirrors enterprise DLP solutions like Symantec DLP, Forcepoint, and Microsoft Purview.

### 5.2 Hash-Based Integrity Checking
SHA-256 is the industry-standard algorithm for file integrity verification (NIST FIPS 180-4). The system uses pre/post transfer comparison — the same technique used by secure file transfer protocols (SFTP, SCP) and blockchain systems to ensure data hasn't been altered.

**SHA-256 properties demonstrated:**
- Collision resistance (computationally infeasible to find two inputs with same hash)
- Avalanche effect (1-bit change → completely different hash)
- Deterministic (same input always produces same output)

### 5.3 Burst Exfiltration Detection
Uses a **sliding time-window algorithm** to detect mass file transfers — a common pattern in:
- Ransomware staging (encrypting/copying large volumes of files)
- Data harvesting (employee copying bulk records before resignation)
- Automated exfiltration tools (rclone, robocopy misuse)

### 5.4 Process Attribution
Associates file operations with running process context using psutil. This enables:
- Identifying which application performed a suspicious transfer
- Flagging known risky tools (cmd.exe, powershell.exe, rclone.exe)
- Building user behavior baselines for insider threat detection

---

## 6. Test Results

### 6.1 Simulation Results

| Scenario | Detection | Alert Severity | Category |
|----------|-----------|---------------|---------|
| 1. Authorized Transfer | ✅ Verified | INFO | AUTHORIZED_TRANSFER |
| 2. USB Exfiltration | ✅ Detected | CRITICAL | DLP_VIOLATION |
| 3. In-Transit Tampering | ✅ Detected | CRITICAL | INTEGRITY_VIOLATION |
| 4. Mass Exfiltration Burst | ✅ Detected | CRITICAL | BURST_EXFILTRATION |
| 5. File Deletion | ✅ Detected | HIGH | DESTRUCTIVE_ACTION |

**Detection Rate: 100% (5/5 scenarios)**

### 6.2 Unit Test Coverage

| Module | Tests | Coverage Areas |
|--------|-------|----------------|
| integrity_engine | 12 | Hash computation, baseline registry, tamper detection |
| classifier_engine | 16 | Extension, path, keyword classification |
| policy_engine | 14 | All 6 DLP rules |
| alert_manager + logger | 20 | Dispatch, history, multi-channel logging, reports |

---

## 7. Blue Team Learning Outcomes

1. **File system monitoring** — Understanding how OS events are generated and intercepted at the inotify/ReadDirectoryChanges level.
2. **Cryptographic integrity** — Practical application of SHA-256 for tamper detection.
3. **DLP architecture** — How enterprise DLP systems classify, monitor, and enforce data movement policies.
4. **Insider threat detection** — Behavioral analytics through transfer frequency and destination analysis.
5. **SOC operations** — Real-time event triage, alert prioritization, and audit trail maintenance.
6. **Incident response data** — Structured audit logs that support forensic investigation.

---

## 8. Future Enhancements

1. **Email/SMS alerting** integration (Twilio, SendGrid) for out-of-band critical notifications.
2. **Machine learning anomaly detection** — user behavior baseline + deviation scoring.
3. **Network share monitoring** — detect SMB/NFS transfer events.
4. **Active blocking** — quarantine files or terminate processes on critical violations.
5. **SIEM integration** — CEF/Syslog output for Splunk, QRadar, or Elastic SIEM.
6. **Digital forensics mode** — automatic file carving and evidence preservation on detection.
7. **Cloud DLP APIs** — integration with AWS Macie, Azure Purview for cloud-native monitoring.

---

## 9. Conclusion

The Secure File Transfer Monitoring System successfully demonstrates a complete Blue Team DLP and integrity monitoring toolkit. It detects all five simulated attack scenarios with 100% accuracy, provides a real-time SOC dashboard for live threat visibility, and generates structured audit trails for post-incident forensics. The system implements industry-standard security techniques including SHA-256 hashing, behavioral anomaly detection, and multi-layer DLP classification — providing practical hands-on experience with real-world cybersecurity defense mechanisms.
