# Presentation Slides — Secure File Transfer Monitoring System
## 12-Slide Deck for Final Internship Review

---

## Slide 1 — Title Slide

**Title:** Secure File Transfer Monitoring System (SFTMS)  
**Subtitle:** Blue Team DLP & File Integrity Verification Toolkit  
**Presenter:** Bathvar Mayurkumar .R  
**Organization:** UnifiedMentor Cybersecurity Internship  
**Date:** September 2026

*Visual: Dark cyber background with hex grid, animated shield icon*

**Speaker Notes:**  
"Good morning/afternoon. My name is Bathvar Mayurkumar .R, and today I'll be presenting my internship project — a Secure File Transfer Monitoring System built for real-time Data Loss Prevention and file integrity verification."

---

## Slide 2 — The Problem

**Heading:** Why File Transfer Monitoring Matters

**Key Statistics:**
- 60% of data breaches involve an insider (Verizon DBIR)
- Average cost of a data breach: $4.45 million (IBM 2023)
- 95% of cybersecurity incidents involve human error

**Real-world attack examples:**
- 🔴 Edward Snowden: copied 1.5M classified NSA documents to USB
- 🔴 Capital One breach: 100M customer records exfiltrated via cloud misconfiguration
- 🔴 Ransomware: encrypts files after staging bulk copies externally

**Speaker Notes:**  
"Organizations face constant threats from insider data theft, malware, and unauthorized transfers. Without monitoring, these events go undetected until a full breach is confirmed."

---

## Slide 3 — Project Objectives

**Heading:** What This System Achieves

✅ Real-time file system monitoring (create, modify, move, delete)  
✅ Multi-tier DLP classification of sensitive files  
✅ Cryptographic integrity verification (SHA-256, SHA3-256, MD5)  
✅ 6-rule DLP policy enforcement engine  
✅ Burst exfiltration anomaly detection  
✅ Live SOC Web Dashboard  
✅ Automated attack simulation for testing  
✅ Full audit trail (JSON, CSV, SQLite)

**Speaker Notes:**  
"The system covers the entire defensive pipeline — from raw file system event detection all the way through to analyst-facing dashboard and downloadable audit reports."

---

## Slide 4 — System Architecture

**Heading:** Architecture Overview

*[Show ARCHITECTURE_DIAGRAMS.md — Diagram 1]*

**5 Core Layers:**
1. **Event Layer** — watchdog captures OS filesystem events
2. **Classification** — 5-tier DLP sensitivity scoring
3. **Integrity** — SHA-256 pre/post hash comparison
4. **Policy** — 6-rule DLP evaluation engine
5. **Output** — Alerts, audit logs, SOC dashboard, reports

**Speaker Notes:**  
"The architecture is modular — each component can be independently upgraded or replaced. Events flow from the file system through classification, integrity checking, and policy evaluation before being logged and displayed."

---

## Slide 5 — DLP Classification

**Heading:** 5-Tier File Sensitivity Classification

| Tier | Examples | Action |
|------|---------|--------|
| 🔴 HIGHLY_SENSITIVE | `.key`, `.pem`, `.kdbx` | Immediate alert on any movement |
| 🟠 CONFIDENTIAL | `.sql`, `.db`, `.env` | Alert if leaving protected zone |
| 🟡 RESTRICTED | `.docx`, `.pdf`, `.xlsx` | Alert if going to USB/cloud |
| 🔵 INTERNAL | `.json`, `.cfg`, `.yaml` | Log only |
| 🟢 UNCLASSIFIED | Everything else | Log only |

**3 Detection Strategies:**
- Path segment matching (sensitive_vault/, credentials/)
- File extension matching
- Content keyword scanning (API_KEY, CONFIDENTIAL, BEGIN RSA PRIVATE)

**Speaker Notes:**  
"Files are classified using three overlapping strategies. The highest matching tier wins. This prevents a database file renamed as .txt from escaping detection."

---

## Slide 6 — File Integrity Verification

**Heading:** Hash-Based Tamper Detection

*[Show Diagram 5 — Integrity State Machine]*

**Algorithm:** SHA-256 (primary), SHA3-256, MD5

**Workflow:**
```
1. Pre-Transfer: Hash(original_file) → stored in SQLite
2. Transfer occurs
3. Post-Transfer: Hash(transferred_file)
4. Compare: if Pre ≠ Post → CRITICAL alert
```

**Real-world use case:**
> An attacker modifies a `.env` file mid-transfer to inject a backdoor credential.  
> SFTMS detects the hash mismatch and fires a `CRITICAL INTEGRITY_VIOLATION` alert.

**Speaker Notes:**  
"This is the same technique used in secure file transfer protocols like SFTP and blockchain transaction verification. Any single byte change completely changes the hash output."

---

## Slide 7 — DLP Policy Engine (6 Rules)

**Heading:** Automated Threat Detection Rules

| # | Rule | Severity |
|---|------|---------|
| 1 | Integrity/Hash mismatch | 🚨 CRITICAL |
| 2 | Sensitive file → USB/Cloud | 🚨 CRITICAL |
| 3 | Sensitive file leaving protected zone | 🔴 HIGH |
| 4 | Burst transfer anomaly (>10 files/10s) | 🚨 CRITICAL |
| 5 | Critical file deleted | 🔴 HIGH |
| 6 | Suspicious process (cmd.exe, rclone.exe) | ⚠️ MEDIUM |

*[Show DLP Flowchart — Diagram 3]*

**Speaker Notes:**  
"Rules are evaluated independently and combined. A single event can trigger multiple rules — for example, a powershell.exe copying a .key file to a USB drive would trigger rules 2, 5, and 6 simultaneously."

---

## Slide 8 — Attack Simulation Scenarios

**Heading:** 5 Realistic Threat Scenarios

| # | Scenario | Expected Response |
|---|----------|-----------------|
| 1 | Authorized internal transfer | ✅ AUTHORIZED — Verified |
| 2 | USB exfiltration (insider threat) | 🚨 CRITICAL — DLP_VIOLATION |
| 3 | In-transit file tampering | 🚨 CRITICAL — INTEGRITY_VIOLATION |
| 4 | Mass bulk exfiltration (15 files) | 🚨 CRITICAL — BURST_EXFILTRATION |
| 5 | Cryptographic key file deletion | 🔴 HIGH — DESTRUCTIVE_ACTION |

**Detection Rate: 100% (5/5)**

**Speaker Notes:**  
"All five scenarios were designed to mirror real-world attack patterns. Scenario 3 specifically simulates malware injecting malicious content into a configuration file during a transfer — a technique used in supply chain attacks."

---

## Slide 9 — SOC Web Dashboard (Live Demo)

**Heading:** Real-Time Security Operations Dashboard

**Features shown:**
- 📡 Live file transfer feed with instant severity badges
- 🔔 Alert notification panel with sound/visual pings
- 📊 Severity distribution donut chart (Chart.js)
- 📈 Event type bar chart (created/modified/moved/deleted)
- 🔐 Interactive file integrity verifier (drag & drop)
- 📥 One-click audit report download (JSON/CSV)
- ⚡ Built-in attack simulation trigger

*[LIVE DEMO — start monitor → run simulation → show dashboard]*

**Speaker Notes:**  
"The dashboard connects to the Flask server via Server-Sent Events — a lightweight alternative to WebSockets that provides true real-time streaming without complex infrastructure."

---

## Slide 10 — Audit Trail & Reports

**Heading:** Comprehensive Audit Logging

**4 simultaneous output channels:**

```
logs/
├── transfers.json    ← JSON Lines (machine-readable, SIEM-ready)
├── audit.csv         ← Spreadsheet (Excel/Google Sheets)
├── system.log        ← Human-readable log
└── audit_vault.db    ← SQLite (queryable, permanent)
```

**Each audit record contains:**
- Timestamp, event type, file path, file name, extension
- Classification tier, sensitivity flag, classification reasons
- Pre/post SHA-256 hash, integrity_ok, tampered flag
- Username, hostname, process name, PID
- Alert severity, category, message, is_authorized flag

**Speaker Notes:**  
"This audit trail is forensically valuable — it can answer who moved what file, when, from where, using which process, and whether the file was tampered with. This is exactly the data needed during a security incident investigation."

---

## Slide 11 — Security Concepts Learned

**Heading:** Blue Team Skills Demonstrated

| Concept | Implementation |
|---------|---------------|
| **Data Loss Prevention (DLP)** | Multi-tier classifier + policy enforcement |
| **Cryptographic Hashing** | SHA-256, SHA3-256, MD5 integrity verification |
| **Behavioral Analytics** | Burst transfer anomaly detection |
| **Process Attribution** | psutil process-to-file association |
| **Insider Threat Detection** | USB/cloud movement monitoring |
| **SIEM-Ready Logging** | JSON Lines structured audit trail |
| **SOC Operations** | Real-time dashboard with alert triage |
| **Incident Response Data** | Full audit trail for forensic investigation |

**Speaker Notes:**  
"This project gave me hands-on experience with the same fundamental techniques used in enterprise security products like Symantec DLP, CrowdStrike Falcon, and Microsoft Purview."

---

## Slide 12 — Conclusion & Future Work

**Heading:** Summary & Next Steps

**✅ Achieved:**
- Complete DLP + integrity monitoring system in Python
- Real-time SOC dashboard with live streaming
- 100% detection on 5 attack scenarios
- 62+ automated unit and integration tests
- Full documentation and architecture diagrams

**🚀 Future Enhancements:**
- Email/SMS alerting (Twilio/SendGrid)
- Machine learning anomaly scoring
- Network share (SMB/NFS) monitoring
- SIEM integration (Splunk/Elastic CEF output)
- Active blocking (quarantine files, kill processes)
- Digital forensics evidence preservation mode

**Thank you — Questions?**

*[Contact: your.email@example.com | GitHub: github.com/yourprofile]*

**Speaker Notes:**  
"To summarize: this system provides a complete Blue Team monitoring solution that detects file exfiltration, tampering, bulk data theft, and destructive actions in real time. The modular architecture makes it extensible for production enterprise use. Thank you for your attention — I'm happy to take any questions."
