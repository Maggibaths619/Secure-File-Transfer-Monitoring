# Secure File Transfer Monitoring System (SFTMS)

<div align="center">

```
  ███████╗███████╗████████╗███╗   ███╗███████╗
  ██╔════╝██╔════╝╚══██╔══╝████╗ ████║██╔════╝
  ███████╗█████╗     ██║   ██╔████╔██║███████╗
  ╚════██║██╔══╝     ██║   ██║╚██╔╝██║╚════██║
  ███████║██║        ██║   ██║ ╚═╝ ██║███████║
  ╚══════╝╚═╝        ╚═╝   ╚═╝     ╚═╝╚══════╝
```

**Blue Team DLP & File Integrity Verification Toolkit**

![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?style=flat&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1%2B-000000?style=flat&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)

</div>

---

## Overview

The **Secure File Transfer Monitoring System (SFTMS)** is a comprehensive Blue Team cybersecurity toolkit for real-time Data Loss Prevention (DLP), file integrity verification, and insider threat detection. It monitors file system activity across configured directories, classifies sensitivity, verifies cryptographic integrity, evaluates transfers against DLP policy, and provides a live SOC Web Dashboard.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Live File Monitor** | watchdog-based real-time detection of create/modify/move/delete events |
| 🔐 **Integrity Engine** | SHA-256, SHA3-256, MD5 chunk-based hashing with pre/post transfer verification |
| 🏷️ **DLP Classifier** | 5-tier sensitivity classification (HIGHLY_SENSITIVE → UNCLASSIFIED) |
| 🚨 **Policy Engine** | 6-rule DLP evaluator: exfiltration, tampering, burst anomaly, destructive actions |
| 📊 **SOC Dashboard** | Dark-mode real-time web UI with live SSE event streaming and charts |
| ⚡ **Attack Simulator** | 5 realistic insider threat/attack scenarios for testing and demonstration |
| 📋 **Audit Logger** | Multi-channel: JSON Lines, CSV, human log, and SQLite database |
| 🖥️ **CLI Interface** | Full-featured interactive terminal with colour-coded output |
| 🧪 **Test Suite** | pytest unit and integration tests for all core modules |

---

## Quick Start

### Prerequisites

```powershell
python --version  # Requires Python 3.10+
```

### Installation

```powershell
cd "Secure File Transfer Monitoring System"
pip install -r requirements.txt
```

### Run the SOC Web Dashboard

```powershell
python -m src.web.app
```
→ Opens automatically at **http://127.0.0.1:5000**

### Run the Interactive CLI

```powershell
python src/cli/main.py
```

### Run Attack Simulation Scenarios

```powershell
python -m src.simulator.simulate_scenarios
```

### Run Tests

```powershell
pytest -v
```

---

## Architecture

```
Secure File Transfer Monitoring System/
│
├── config/
│   └── config.yaml               # Central configuration
│
├── monitored_storage/             # Auto-created monitoring zones
│   ├── source_zone/
│   ├── sensitive_vault/
│   ├── usb_drive_sim/
│   ├── cloud_sync_sim/
│   └── quarantine_zone/
│
├── src/
│   ├── core/
│   │   ├── integrity_engine.py   # Cryptographic hashing & verification
│   │   ├── classifier_engine.py  # DLP file classification
│   │   ├── process_tracker.py    # Process/user attribution
│   │   ├── policy_engine.py      # DLP rule evaluation
│   │   ├── logger_engine.py      # Multi-channel audit logging
│   │   ├── alert_manager.py      # Alert dispatching & streaming
│   │   └── file_monitor.py       # Watchdog orchestrator
│   │
│   ├── simulator/
│   │   └── simulate_scenarios.py # 5 attack/threat scenarios
│   │
│   ├── cli/
│   │   └── main.py               # Interactive terminal UI
│   │
│   └── web/
│       ├── app.py                # Flask SOC dashboard server
│       └── templates/
│           └── dashboard.html    # Dark-mode SOC UI
│
├── tests/
│   ├── test_integrity.py
│   ├── test_classifier.py
│   ├── test_policy.py
│   └── test_monitor.py
│
├── logs/                          # Auto-created
│   ├── transfers.json
│   ├── audit.csv
│   ├── system.log
│   └── audit_vault.db
│
└── docs/
    ├── PROJECT_REPORT.md
    ├── ARCHITECTURE_DIAGRAMS.md
    ├── drawio_architecture.xml
    └── PRESENTATION_SLIDES.md
```

---

## Simulation Scenarios

| # | Scenario | Expected Alert |
|---|----------|---------------|
| 1 | Authorized Internal Transfer | `INFO` — Verified |
| 2 | USB Exfiltration (Insider Threat) | `CRITICAL` — DLP_VIOLATION |
| 3 | In-Transit File Tampering | `CRITICAL` — INTEGRITY_VIOLATION |
| 4 | Mass Exfiltration Burst Anomaly | `CRITICAL` — BURST_EXFILTRATION |
| 5 | Critical File Deletion | `HIGH` — DESTRUCTIVE_ACTION |

---

## DLP Classification Tiers

| Tier | Examples | Color |
|------|---------|-------|
| 🔴 HIGHLY_SENSITIVE | `.key`, `.pem`, `.kdbx`, `.pfx` | Red |
| 🟠 CONFIDENTIAL | `.sql`, `.db`, `.env`, `.bak` | Orange |
| 🟡 RESTRICTED | `.docx`, `.pdf`, `.xlsx`, `.csv` | Yellow |
| 🔵 INTERNAL | `.json`, `.xml`, `.yaml`, `.cfg` | Cyan |
| 🟢 UNCLASSIFIED | everything else | Green |

---

## Configuration

Edit `config/config.yaml` to customize:
- **Monitored paths** — directories to watch
- **Sensitive extensions** — file types to classify
- **Unauthorized destinations** — USB/cloud paths that trigger DLP alerts
- **Burst thresholds** — max transfers per time window
- **Web server** — host, port, auto-open browser

---

## Security Techniques Demonstrated

- ✅ File system activity monitoring (watchdog)
- ✅ Hash-based tamper detection (SHA-256, SHA3-256, MD5)
- ✅ DLP policy enforcement engine
- ✅ Insider threat detection via burst anomaly analysis
- ✅ Sensitive data classification
- ✅ Real-time SOC alerting and audit trail
- ✅ Process and user attribution
- ✅ Data Loss Prevention (DLP) architecture

---

## Internship Project — UnifiedMentor Cybersecurity

**Submitted by:** [Your Name]  
**Program:** Cybersecurity Internship  
**Project:** Secure File Transfer Monitoring System  
**Technologies:** Python 3.13, watchdog, hashlib, psutil, Flask, SQLite, Chart.js  
