# Architecture Diagrams
## Secure File Transfer Monitoring System

---

## Diagram 1 — High-Level System Architecture

```mermaid
flowchart TD
    subgraph Host ["🖥 Host System"]
        FS["📁 File System Events\n(Create / Modify / Move / Delete)"]
        PROC["⚙ Running Processes\n(psutil / win32api)"]
        ZONES["📂 Monitored Zones\nsource_zone / sensitive_vault\nusb_drive_sim / cloud_sync_sim"]
    end

    subgraph Core ["🔧 Core Detection Engine"]
        WM["👁 Watchdog Observer\nfile_monitor.py"]
        CL["🏷 DLP Classifier\nclassifier_engine.py"]
        IE["🔐 Integrity Engine\nintegrity_engine.py"]
        PT["👤 Process Tracker\nprocess_tracker.py"]
        PE["🚦 Policy Engine\npolicy_engine.py"]
    end

    subgraph Output ["📤 Output & Response Layer"]
        AL["🔔 Alert Manager\nalert_manager.py"]
        LOG["📋 Audit Logger\nJSON · CSV · SQLite · Log"]
        WEB["🌐 SOC Dashboard\nFlask + SSE + Chart.js"]
        CLI["💻 Interactive CLI\ncli/main.py"]
        REP["📄 Audit Reports\nHTML · JSON · CSV"]
    end

    FS --> WM
    PROC --> PT
    ZONES -.->|"monitored"| WM
    WM --> CL
    WM --> IE
    PT --> PE
    CL --> PE
    IE --> PE
    PE --> AL
    PE --> LOG
    AL --> WEB
    AL --> CLI
    LOG --> WEB
    LOG --> REP
```

---

## Diagram 2 — File Event Processing Pipeline (Sequence Diagram)

```mermaid
sequenceDiagram
    participant FS as File System
    participant WD as Watchdog Observer
    participant CL as Classifier Engine
    participant IE as Integrity Engine
    participant PT as Process Tracker
    participant PE as Policy Engine
    participant AM as Alert Manager
    participant DB as Audit Logger (SQLite)
    participant UI as SOC Dashboard

    FS->>WD: File Event (create/move/modify/delete)
    WD->>WD: Debounce & filter system files
    WD->>CL: classify(file_path)
    CL-->>WD: { tier, is_sensitive, reasons }
    WD->>IE: snapshot_pre(file_path)
    IE-->>WD: { sha256, sha3_256, md5 }
    Note over IE: Hash stored in SQLite baseline
    WD->>PT: attribute_event(file_path)
    PT-->>WD: { username, hostname, process_name, pid }
    WD->>PE: evaluate(event, classification, integrity, attribution)
    PE->>PE: Run 6 DLP Rules
    alt VIOLATION detected
        PE->>AM: dispatch(CRITICAL/HIGH, category, message)
        AM->>UI: SSE push (live alert stream)
        AM->>UI: Toast notification
    else AUTHORIZED
        PE->>AM: dispatch(INFO, AUTHORIZED_TRANSFER)
    end
    PE-->>WD: PolicyDecision { outcome, severity }
    WD->>DB: log(audit_entry)
    DB->>DB: Write JSON Lines
    DB->>DB: Write CSV row
    DB->>DB: INSERT INTO audit_events
    UI->>UI: Refresh feed table & charts
```

---

## Diagram 3 — DLP Policy Rule Evaluation

```mermaid
flowchart TD
    START([File Event Received]) --> R1

    R1{Rule 1:\nFile Tampered?}
    R1 -->|Yes| A1[🚨 CRITICAL\nINTEGRITY_VIOLATION]
    R1 -->|No| R2

    R2{Rule 2:\nSensitive file →\nUnauthorized Destination?}
    R2 -->|Yes| A2[🚨 CRITICAL\nDLP_VIOLATION]
    R2 -->|No| R3

    R3{Rule 3:\nProtected Zone\nViolation?}
    R3 -->|Yes| A3[🔴 HIGH\nPROTECTED_ZONE_VIOLATION]
    R3 -->|No| R4

    R4{Rule 4:\nBurst Exfiltration\nAnomaly?}
    R4 -->|Yes| A4[🚨 CRITICAL\nBURST_EXFILTRATION]
    R4 -->|No| R5

    R5{Rule 5:\nCritical File\nDeleted?}
    R5 -->|Yes| A5[🔴 HIGH\nDESTRUCTIVE_ACTION]
    R5 -->|No| R6

    R6{Rule 6:\nSuspicious Process\nActor?}
    R6 -->|Yes| A6[⚠ MEDIUM\nSUSPICIOUS_PROCESS]
    R6 -->|No| AUTH[✅ AUTHORIZED\nLog at INFO]

    A1 & A2 & A3 & A4 & A5 & A6 --> VIOLATION[❌ VIOLATION\nAlert Dispatched\nAudit Logged]
    AUTH --> LOG[📋 Audit Log\nINFO Entry]
```

---

## Diagram 4 — File Classification Decision Tree

```mermaid
flowchart TD
    FILE([File Event]) --> PATH

    PATH{Sensitive\nPath Segment?}
    PATH -->|Yes| HS[HIGHLY_SENSITIVE 🔴]
    PATH -->|No| EXT

    EXT{File Extension?}
    EXT -->|.key .pem .kdbx .pfx| HS2[HIGHLY_SENSITIVE 🔴]
    EXT -->|.sql .db .env .bak| CONF[CONFIDENTIAL 🟠]
    EXT -->|.docx .pdf .xlsx .csv| REST[RESTRICTED 🟡]
    EXT -->|.json .xml .yaml .cfg| INT[INTERNAL 🔵]
    EXT -->|Other| KW

    KW{Sensitive Keywords\nin Content?}
    KW -->|CONFIDENTIAL\nAPI_KEY\npassword etc.| CONF2[CONFIDENTIAL 🟠]
    KW -->|None| UNCL[UNCLASSIFIED 🟢]
```

---

## Diagram 5 — Integrity Verification Workflow

```mermaid
stateDiagram-v2
    [*] --> FileDetected : Watchdog Event

    FileDetected --> ComputePreHash : File exists
    ComputePreHash --> StoreBaseline : SHA256 + SHA3-256 + MD5
    StoreBaseline --> TransferOccurs : Saved to SQLite

    TransferOccurs --> ComputePostHash : File copied/moved
    ComputePostHash --> CompareHashes : Post-transfer snapshot

    CompareHashes --> VERIFIED : Pre == Post (all algorithms)
    CompareHashes --> TAMPERED : Pre ≠ Post (any algorithm)

    VERIFIED --> LogAuthorized : Log as integrity_ok=True
    TAMPERED --> AlertCritical : CRITICAL INTEGRITY_VIOLATION alert
    AlertCritical --> LogViolation : Log as tampered=True

    LogAuthorized --> [*]
    LogViolation --> [*]
```

---

## Diagram 6 — Data Flow & Storage Architecture

```mermaid
flowchart LR
    MON["🔍 File Monitor\n(Watchdog Observer)"]

    subgraph LOG_CHANNELS ["📦 Audit Log Channels"]
        J["📄 transfers.json\nJSON Lines"]
        C["📊 audit.csv\nSpreadsheet"]
        L["📝 system.log\nHuman Readable"]
        D[("🗄 audit_vault.db\nSQLite Database")]
    end

    subgraph CONSUMERS ["📤 Data Consumers"]
        WEB["🌐 SOC Dashboard\nFlask REST APIs"]
        REPORT["📋 Report Generator\nJSON / CSV Export"]
        TESTS["🧪 Test Suite\npytest"]
    end

    MON --> J & C & L & D
    D --> WEB
    D --> REPORT
    D --> TESTS
    J --> REPORT
    C --> REPORT
```
