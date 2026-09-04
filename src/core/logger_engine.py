"""
logger_engine.py
=================
Structured multi-channel audit logger.

Output channels:
  1. logs/transfers.json  – Machine-readable JSON Lines (one event per line)
  2. logs/audit.csv       – Spreadsheet-friendly CSV
  3. logs/system.log      – Formatted human-readable log file
  4. logs/audit_vault.db  – SQLite persistent audit database

All channels are written with a rotating strategy.
Thread-safe via a lock.
"""

import csv
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sftms.logger_engine")

# ---------------------------------------------------------------------------
# Log directories
# ---------------------------------------------------------------------------

_LOG_DIR = "logs"

CSV_FIELDNAMES = [
    "id", "timestamp", "event_type", "file_path", "source_path",
    "destination_path", "file_name", "extension", "file_size_bytes",
    "classification_tier", "is_sensitive", "is_authorized",
    "integrity_ok", "tampered", "sha256_pre", "sha256_post",
    "username", "hostname", "process_name", "pid",
    "alert_severity", "alert_category", "alert_message",
    "extra_json",
]


# ---------------------------------------------------------------------------
# Log event builder (convenience factory)
# ---------------------------------------------------------------------------

def build_log_entry(
    event_type: str,
    file_path: str,
    source_path: str = "",
    destination_path: str = "",
    classification: Optional[Dict] = None,
    integrity: Optional[Dict] = None,
    attribution: Optional[Dict] = None,
    alert_severity: str = "INFO",
    alert_category: str = "FILE_EVENT",
    alert_message: str = "",
    is_authorized: bool = True,
    extra: Optional[Dict] = None,
) -> Dict:
    """
    Construct a normalized audit log entry dict.

    Args:
        event_type:       e.g. 'FILE_CREATED', 'FILE_MOVED', 'FILE_DELETED', 'FILE_MODIFIED'
        file_path:        Absolute path of the file involved.
        source_path:      Source path (for move events).
        destination_path: Destination path (for copy/move events).
        classification:   Result dict from FileClassifier.classify().
        integrity:        Result dict from IntegrityVerifier.verify().
        attribution:      Result dict from ProcessTracker.attribute_event().
        alert_severity:   Severity of any associated alert.
        alert_category:   Category label of any associated alert.
        alert_message:    Human-readable alert message.
        is_authorized:    Whether the event was authorized by DLP policy.
        extra:            Additional arbitrary metadata.

    Returns:
        Normalized dict ready to be written to all log channels.
    """
    p = Path(file_path)
    try:
        file_size = p.stat().st_size
    except OSError:
        file_size = None

    classification = classification or {}
    integrity      = integrity      or {}
    attribution    = attribution    or {}
    extra          = extra          or {}

    algo_results = integrity.get("algorithm_results", {})
    sha256_info  = algo_results.get("sha256", {})

    return {
        "timestamp":          datetime.now().isoformat(),
        "event_type":         event_type,
        "file_path":          str(file_path),
        "file_name":          p.name,
        "extension":          p.suffix.lower(),
        "file_size_bytes":    file_size,
        "source_path":        str(source_path),
        "destination_path":   str(destination_path),
        # Classification
        "classification_tier": classification.get("tier", "UNCLASSIFIED"),
        "is_sensitive":        classification.get("is_sensitive", False),
        "classification_reasons": classification.get("reasons", []),
        # Integrity
        "integrity_ok":  integrity.get("integrity_ok", None),
        "tampered":      integrity.get("tampered", False),
        "sha256_pre":    sha256_info.get("pre"),
        "sha256_post":   sha256_info.get("post"),
        # Attribution
        "username":      attribution.get("username", ""),
        "hostname":      attribution.get("hostname", ""),
        "process_name":  attribution.get("process_name", ""),
        "pid":           attribution.get("pid", ""),
        # Alert
        "alert_severity":  alert_severity,
        "alert_category":  alert_category,
        "alert_message":   alert_message,
        "is_authorized":   is_authorized,
        # Extras
        "extra": extra,
    }


# ---------------------------------------------------------------------------
# Multi-channel Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Writes structured audit entries to all configured output channels.

    Usage:
        audit_logger = AuditLogger()
        audit_logger.log(entry)
    """

    def __init__(
        self,
        log_dir: str = _LOG_DIR,
        json_log: str = "transfers.json",
        csv_log: str = "audit.csv",
        system_log: str = "system.log",
        db_path: str = "audit_vault.db",
    ) -> None:
        self.log_dir    = log_dir
        self.json_path  = os.path.join(log_dir, json_log)
        self.csv_path   = os.path.join(log_dir, csv_log)
        self.sys_path   = os.path.join(log_dir, system_log)
        self.db_path    = os.path.join(log_dir, db_path)
        self._lock      = threading.Lock()
        self._entry_id  = 0

        os.makedirs(log_dir, exist_ok=True)

        # Initialise file handlers
        self._init_system_log()
        self._init_csv()
        self._init_db()

        logger.info("AuditLogger ready -> %s", log_dir)

    # ------------------------------------------------------------------
    def _init_system_log(self) -> None:
        """Configure the rotating file handler for system.log."""
        fh = logging.FileHandler(self.sys_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh.setFormatter(fmt)
        # Attach to root logger of sftms so all sub-loggers write here
        sftms_logger = logging.getLogger("sftms")
        sftms_logger.setLevel(logging.DEBUG)
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == fh.baseFilename
                   for h in sftms_logger.handlers):
            sftms_logger.addHandler(fh)

    # ------------------------------------------------------------------
    def _init_csv(self) -> None:
        """Write CSV header if file doesn't exist yet."""
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
                writer.writeheader()

    # ------------------------------------------------------------------
    def _init_db(self) -> None:
        """Create the SQLite audit_events table."""
        with self._db_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp           TEXT,
                    event_type          TEXT,
                    file_path           TEXT,
                    file_name           TEXT,
                    extension           TEXT,
                    file_size_bytes     INTEGER,
                    source_path         TEXT,
                    destination_path    TEXT,
                    classification_tier TEXT,
                    is_sensitive        INTEGER,
                    integrity_ok        INTEGER,
                    tampered            INTEGER,
                    sha256_pre          TEXT,
                    sha256_post         TEXT,
                    username            TEXT,
                    hostname            TEXT,
                    process_name        TEXT,
                    pid                 TEXT,
                    alert_severity      TEXT,
                    alert_category      TEXT,
                    alert_message       TEXT,
                    is_authorized       INTEGER,
                    extra_json          TEXT
                )
            """)
            conn.commit()

    # ------------------------------------------------------------------
    def _db_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # ------------------------------------------------------------------
    def log(self, entry: Dict) -> int:
        """
        Write a single audit entry to all channels.

        Args:
            entry: Dict produced by build_log_entry().

        Returns:
            Auto-incremented entry ID.
        """
        with self._lock:
            self._entry_id += 1
            entry_with_id = dict(entry, id=self._entry_id)
            self._write_json(entry_with_id)
            self._write_csv(entry_with_id)
            self._write_db(entry_with_id)
        return self._entry_id

    # ------------------------------------------------------------------
    def _write_json(self, entry: Dict) -> None:
        """Append a JSON line to transfers.json."""
        try:
            with open(self.json_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error("JSON log write failed: %s", exc)

    # ------------------------------------------------------------------
    def _write_csv(self, entry: Dict) -> None:
        """Append a row to audit.csv."""
        try:
            row = {k: entry.get(k, "") for k in CSV_FIELDNAMES}
            row["extra_json"] = json.dumps(entry.get("extra", {}), default=str)
            # Flatten lists to semicolon-separated strings for CSV
            for k, v in row.items():
                if isinstance(v, list):
                    row[k] = "; ".join(str(i) for i in v)
                elif isinstance(v, bool):
                    row[k] = int(v)
            with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
                writer.writerow(row)
        except OSError as exc:
            logger.error("CSV log write failed: %s", exc)

    # ------------------------------------------------------------------
    def _write_db(self, entry: Dict) -> None:
        """Insert a row into the SQLite audit_events table."""
        try:
            with self._db_conn() as conn:
                conn.execute(
                    """INSERT INTO audit_events (
                        timestamp, event_type, file_path, file_name, extension,
                        file_size_bytes, source_path, destination_path,
                        classification_tier, is_sensitive, integrity_ok, tampered,
                        sha256_pre, sha256_post, username, hostname, process_name, pid,
                        alert_severity, alert_category, alert_message, is_authorized, extra_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.get("timestamp"),
                        entry.get("event_type"),
                        entry.get("file_path"),
                        entry.get("file_name"),
                        entry.get("extension"),
                        entry.get("file_size_bytes"),
                        entry.get("source_path"),
                        entry.get("destination_path"),
                        entry.get("classification_tier"),
                        int(bool(entry.get("is_sensitive"))),
                        int(entry.get("integrity_ok")) if entry.get("integrity_ok") is not None else None,
                        int(bool(entry.get("tampered"))),
                        entry.get("sha256_pre"),
                        entry.get("sha256_post"),
                        entry.get("username"),
                        entry.get("hostname"),
                        entry.get("process_name"),
                        str(entry.get("pid", "")),
                        entry.get("alert_severity"),
                        entry.get("alert_category"),
                        entry.get("alert_message"),
                        int(bool(entry.get("is_authorized", True))),
                        json.dumps(entry.get("extra", {}), default=str),
                    ),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("DB log write failed: %s", exc)

    # ------------------------------------------------------------------
    def get_recent_events(self, limit: int = 100, severity_filter: Optional[str] = None) -> List[Dict]:
        """Query recent audit events from SQLite."""
        query = "SELECT * FROM audit_events"
        params: list = []
        if severity_filter:
            query += " WHERE alert_severity = ?"
            params.append(severity_filter.upper())
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        try:
            with self._db_conn() as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error as exc:
            logger.error("DB query failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics from the SQLite audit store."""
        try:
            with self._db_conn() as conn:
                total = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                by_severity = conn.execute(
                    "SELECT alert_severity, COUNT(*) FROM audit_events GROUP BY alert_severity"
                ).fetchall()
                by_type = conn.execute(
                    "SELECT event_type, COUNT(*) FROM audit_events GROUP BY event_type"
                ).fetchall()
                tampered = conn.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE tampered = 1"
                ).fetchone()[0]
                violations = conn.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE is_authorized = 0"
                ).fetchone()[0]
            return {
                "total_events": total,
                "tampered_files": tampered,
                "policy_violations": violations,
                "by_severity": dict(by_severity),
                "by_event_type": dict(by_type),
            }
        except sqlite3.Error as exc:
            logger.error("Stats query failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    def export_report(self, output_path: str, fmt: str = "json") -> str:
        """
        Export all audit events to a report file.

        Args:
            output_path: Destination file path (without extension).
            fmt:         'json' or 'csv'.

        Returns:
            Absolute path of the created report file.
        """
        events = self.get_recent_events(limit=10000)
        stats  = self.get_stats()
        if fmt == "json":
            report = {"stats": stats, "events": events, "generated_at": datetime.now().isoformat()}
            out = output_path if output_path.endswith(".json") else output_path + ".json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)
        else:
            out = output_path if output_path.endswith(".csv") else output_path + ".csv"
            if events:
                keys = list(events[0].keys())
                with open(out, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(events)
        logger.info("Report exported -> %s", out)
        return os.path.abspath(out)
