"""
test_monitor.py
================
Integration tests for the alert_manager and logger_engine modules.

Tests:
  - AlertManager dispatches alerts with correct severity
  - AlertManager history retrieval and filtering
  - AlertManager statistics
  - AuditLogger writes to all channels (JSON, CSV, SQLite)
  - AuditLogger get_recent_events
  - AuditLogger get_stats
  - AuditLogger export_report
  - build_log_entry creates correct structure
"""

import csv
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.alert_manager import (
    Alert,
    AlertManager,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)
from src.core.logger_engine import AuditLogger, build_log_entry


# ---------------------------------------------------------------------------
# AlertManager Tests
# ---------------------------------------------------------------------------

class TestAlertManager:
    @pytest.fixture
    def mgr(self):
        return AlertManager(console_alerts=False)

    def test_dispatch_returns_alert_object(self, mgr):
        alert = mgr.dispatch(SEVERITY_INFO, "TEST", "Test message")
        assert isinstance(alert, Alert)
        assert alert.severity == SEVERITY_INFO
        assert alert.category == "TEST"

    def test_alert_has_timestamp(self, mgr):
        alert = mgr.dispatch(SEVERITY_MEDIUM, "CAT", "msg")
        assert alert.timestamp is not None
        assert "T" in alert.timestamp or "-" in alert.timestamp

    def test_alert_ids_are_sequential(self, mgr):
        a1 = mgr.dispatch(SEVERITY_INFO, "A", "msg1")
        a2 = mgr.dispatch(SEVERITY_INFO, "B", "msg2")
        assert a2.id > a1.id

    def test_history_contains_dispatched_alerts(self, mgr):
        mgr.dispatch(SEVERITY_HIGH, "VULN", "Vulnerability found")
        history = mgr.get_history()
        assert len(history) > 0
        assert any(a["category"] == "VULN" for a in history)

    def test_history_filter_by_severity(self, mgr):
        mgr.dispatch(SEVERITY_INFO,   "CAT", "info msg")
        mgr.dispatch(SEVERITY_CRITICAL, "CAT", "critical msg")
        crit_only = mgr.get_history(severity_filter="CRITICAL")
        assert all(a["severity"] == "CRITICAL" for a in crit_only)

    def test_stats_track_severity_counts(self, mgr):
        mgr.dispatch(SEVERITY_CRITICAL, "A", "c1")
        mgr.dispatch(SEVERITY_CRITICAL, "A", "c2")
        mgr.dispatch(SEVERITY_HIGH,     "B", "h1")
        stats = mgr.get_stats()
        assert stats.get("CRITICAL", 0) >= 2
        assert stats.get("HIGH", 0) >= 1
        assert stats.get("TOTAL", 0) >= 3

    def test_min_severity_filter_works(self):
        mgr = AlertManager(console_alerts=False, min_severity=SEVERITY_HIGH)
        mgr.dispatch(SEVERITY_INFO,  "A", "info msg")
        mgr.dispatch(SEVERITY_HIGH,  "B", "high msg")
        mgr.dispatch(SEVERITY_CRITICAL, "C", "crit msg")
        history = mgr.get_history()
        assert all(a["severity"] in ("HIGH", "CRITICAL") for a in history)

    def test_subscriber_callback_called(self, mgr):
        received = []
        mgr.subscribe(received.append)
        mgr.dispatch(SEVERITY_MEDIUM, "SUB_TEST", "Subscriber test")
        assert len(received) == 1
        assert received[0].category == "SUB_TEST"

    def test_clear_history(self, mgr):
        mgr.dispatch(SEVERITY_INFO, "X", "msg")
        mgr.clear_history()
        assert len(mgr.get_history()) == 0

    def test_alert_to_dict(self, mgr):
        alert = mgr.dispatch(SEVERITY_HIGH, "DLP", "File exfiltrated", file_path="/path/file.key")
        d = alert.to_dict()
        assert d["severity"]  == "HIGH"
        assert d["category"]  == "DLP"
        assert d["file_path"] == "/path/file.key"
        assert "id"        in d
        assert "timestamp" in d


# ---------------------------------------------------------------------------
# AuditLogger Tests
# ---------------------------------------------------------------------------

class TestAuditLogger:
    @pytest.fixture
    def log_dir(self, tmp_path):
        return str(tmp_path / "logs")

    @pytest.fixture
    def audit_logger(self, log_dir):
        return AuditLogger(log_dir=log_dir)

    @pytest.fixture
    def sample_entry(self, tmp_path):
        f = tmp_path / "sample.docx"
        f.write_text("CONFIDENTIAL data", encoding="utf-8")
        return build_log_entry(
            event_type="FILE_COPIED",
            file_path=str(f),
            destination_path="/usb/sample.docx",
            classification={"tier": "RESTRICTED", "is_sensitive": True, "reasons": ["test"]},
            integrity={"integrity_ok": True, "tampered": False, "algorithm_results": {"sha256": {}}},
            attribution={"username": "testuser", "hostname": "TESTHOST", "process_name": "test.exe", "pid": 99},
            alert_severity="HIGH",
            alert_category="DLP_VIOLATION",
            alert_message="Sensitive file copied to USB",
            is_authorized=False,
        )

    # ── JSON Log ───────────────────────────────────────────────────────
    def test_json_log_file_created(self, audit_logger, sample_entry, log_dir):
        audit_logger.log(sample_entry)
        json_path = os.path.join(log_dir, "transfers.json")
        assert os.path.exists(json_path)

    def test_json_log_contains_valid_json(self, audit_logger, sample_entry, log_dir):
        audit_logger.log(sample_entry)
        json_path = os.path.join(log_dir, "transfers.json")
        with open(json_path, encoding="utf-8") as f:
            for line in f:
                data = json.loads(line.strip())
                assert "timestamp" in data
                assert "event_type" in data

    # ── CSV Log ────────────────────────────────────────────────────────
    def test_csv_log_file_created(self, audit_logger, sample_entry, log_dir):
        audit_logger.log(sample_entry)
        csv_path = os.path.join(log_dir, "audit.csv")
        assert os.path.exists(csv_path)

    def test_csv_has_header_and_data_row(self, audit_logger, sample_entry, log_dir):
        audit_logger.log(sample_entry)
        csv_path = os.path.join(log_dir, "audit.csv")
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
        assert len(reader) >= 1
        assert "event_type" in reader[0]

    # ── SQLite DB ──────────────────────────────────────────────────────
    def test_sqlite_db_created(self, audit_logger, sample_entry, log_dir):
        audit_logger.log(sample_entry)
        db_path = os.path.join(log_dir, "audit_vault.db")
        assert os.path.exists(db_path)

    def test_sqlite_has_audit_events_table(self, audit_logger, sample_entry, log_dir):
        audit_logger.log(sample_entry)
        db_path = os.path.join(log_dir, "audit_vault.db")
        with sqlite3.connect(db_path) as conn:
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t[0] for t in tables]
        assert "audit_events" in table_names

    def test_sqlite_row_count_increases(self, audit_logger, sample_entry, log_dir):
        audit_logger.log(sample_entry)
        audit_logger.log(sample_entry)
        db_path = os.path.join(log_dir, "audit_vault.db")
        with sqlite3.connect(db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        assert count >= 2

    # ── Query Methods ──────────────────────────────────────────────────
    def test_get_recent_events_returns_list(self, audit_logger, sample_entry):
        audit_logger.log(sample_entry)
        events = audit_logger.get_recent_events(limit=10)
        assert isinstance(events, list)
        assert len(events) >= 1

    def test_get_stats_returns_correct_totals(self, audit_logger, sample_entry):
        audit_logger.log(sample_entry)
        stats = audit_logger.get_stats()
        assert stats.get("total_events", 0) >= 1
        assert "tampered_files" in stats
        assert "policy_violations" in stats

    def test_get_stats_counts_violations(self, audit_logger, sample_entry):
        audit_logger.log(sample_entry)  # is_authorized=False
        stats = audit_logger.get_stats()
        assert stats.get("policy_violations", 0) >= 1

    # ── Export ─────────────────────────────────────────────────────────
    def test_export_json_report(self, audit_logger, sample_entry, tmp_path):
        audit_logger.log(sample_entry)
        out = str(tmp_path / "report")
        path = audit_logger.export_report(out, fmt="json")
        assert os.path.exists(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert "events" in data
        assert "stats"  in data

    def test_export_csv_report(self, audit_logger, sample_entry, tmp_path):
        audit_logger.log(sample_entry)
        out = str(tmp_path / "report")
        path = audit_logger.export_report(out, fmt="csv")
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# build_log_entry Tests
# ---------------------------------------------------------------------------

class TestBuildLogEntry:
    def test_required_fields_present(self, tmp_path):
        f = tmp_path / "test.txt"; f.write_text("data", encoding="utf-8")
        entry = build_log_entry("FILE_CREATED", str(f))
        assert "timestamp"          in entry
        assert "event_type"         in entry
        assert "file_path"          in entry
        assert "classification_tier" in entry
        assert "alert_severity"     in entry

    def test_event_type_preserved(self, tmp_path):
        f = tmp_path / "test.txt"; f.write_text("d", encoding="utf-8")
        entry = build_log_entry("FILE_DELETED", str(f))
        assert entry["event_type"] == "FILE_DELETED"

    def test_classification_merged(self, tmp_path):
        f = tmp_path / "test.docx"; f.write_text("d", encoding="utf-8")
        cls = {"tier": "RESTRICTED", "is_sensitive": True, "reasons": ["extension"]}
        entry = build_log_entry("FILE_MOVED", str(f), classification=cls)
        assert entry["classification_tier"] == "RESTRICTED"
        assert entry["is_sensitive"] is True
