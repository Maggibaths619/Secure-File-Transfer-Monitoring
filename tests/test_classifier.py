"""
test_classifier.py
====================
Unit tests for the classifier_engine module.

Tests:
  - Extension-based classification for all 5 tiers
  - Path-segment classification (sensitive directory names)
  - Content keyword scanning
  - Batch classification
  - Tier ordering (_max_tier logic)
  - is_sensitive() convenience method
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.classifier_engine import (
    TIER_CONFIDENTIAL,
    TIER_HIGHLY_SENSITIVE,
    TIER_INTERNAL,
    TIER_RESTRICTED,
    TIER_UNCLASSIFIED,
    FileClassifier,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def clf():
    return FileClassifier()


# ---------------------------------------------------------------------------
# Extension Tests
# ---------------------------------------------------------------------------

class TestExtensionClassification:
    def test_pem_key_is_highly_sensitive(self, clf, tmp_path):
        f = tmp_path / "server.key"
        f.write_text("dummy", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_HIGHLY_SENSITIVE

    def test_pem_cert_is_highly_sensitive(self, clf, tmp_path):
        f = tmp_path / "cert.pem"; f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_HIGHLY_SENSITIVE

    def test_sql_dump_is_confidential(self, clf, tmp_path):
        f = tmp_path / "dump.sql"; f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_CONFIDENTIAL

    def test_env_file_is_confidential(self, clf, tmp_path):
        # Use a named .env file so the .env extension is detected
        f = tmp_path / "prod.env"; f.write_text("SECRET=xxx", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_CONFIDENTIAL

    def test_docx_is_restricted(self, clf, tmp_path):
        f = tmp_path / "report.docx"; f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_RESTRICTED

    def test_csv_is_restricted(self, clf, tmp_path):
        f = tmp_path / "data.csv"; f.write_text("a,b,c", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_RESTRICTED

    def test_json_is_internal(self, clf, tmp_path):
        f = tmp_path / "config.json"; f.write_text("{}", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_INTERNAL

    def test_unknown_extension_is_unclassified(self, clf, tmp_path):
        f = tmp_path / "file.xyz123"; f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_UNCLASSIFIED

    def test_extension_case_insensitive(self, clf, tmp_path):
        f = tmp_path / "CERT.PEM"; f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_HIGHLY_SENSITIVE


# ---------------------------------------------------------------------------
# Path Segment Tests
# ---------------------------------------------------------------------------

class TestPathClassification:
    def test_sensitive_vault_path_escalates(self, clf, tmp_path):
        vault = tmp_path / "sensitive_vault"
        vault.mkdir()
        f = vault / "notes.txt"
        f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_HIGHLY_SENSITIVE
        assert any("path" in reason.lower() for reason in r["reasons"])

    def test_credentials_path_escalates(self, clf, tmp_path):
        cred = tmp_path / "credentials"
        cred.mkdir()
        f = cred / "passwords.txt"
        f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_HIGHLY_SENSITIVE

    def test_normal_path_does_not_escalate(self, clf, tmp_path):
        f = tmp_path / "desktop" / "photo.jpg"
        f.parent.mkdir(exist_ok=True); f.write_bytes(b"\xff\xd8\xff")
        r = clf.classify(str(f), scan_content=False)
        assert r["tier"] == TIER_UNCLASSIFIED


# ---------------------------------------------------------------------------
# Content Keyword Tests
# ---------------------------------------------------------------------------

class TestContentKeywordScan:
    def test_confidential_keyword_escalates(self, clf, tmp_path):
        f = tmp_path / "memo.txt"
        f.write_text("CONFIDENTIAL\nThis document is restricted.", encoding="utf-8")
        r = clf.classify(str(f), scan_content=True)
        assert r["tier"] in (TIER_CONFIDENTIAL, TIER_RESTRICTED, TIER_HIGHLY_SENSITIVE)
        assert r["is_sensitive"] is True

    def test_api_key_keyword_escalates(self, clf, tmp_path):
        f = tmp_path / "settings.txt"
        f.write_text("API_KEY=sk-abcdef1234567890", encoding="utf-8")
        r = clf.classify(str(f), scan_content=True)
        assert r["is_sensitive"] is True

    def test_private_key_keyword_escalates(self, clf, tmp_path):
        f = tmp_path / "key.txt"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----", encoding="utf-8")
        r = clf.classify(str(f), scan_content=True)
        assert r["is_sensitive"] is True

    def test_no_keyword_unclassified(self, clf, tmp_path):
        # .txt matches INTERNAL tier by extension; .dat is not in any tier list
        f = tmp_path / "readme.dat"
        f.write_text("This is a normal file with no sensitive content.", encoding="utf-8")
        r = clf.classify(str(f), scan_content=True)
        assert r["tier"] == TIER_UNCLASSIFIED

    def test_scan_content_false_skips_keywords(self, clf, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("CONFIDENTIAL API_KEY=abc123", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        # Should only match extension (txt = internal)
        # No path segments match either; classified as INTERNAL
        assert r["tier"] in (TIER_INTERNAL, TIER_UNCLASSIFIED)


# ---------------------------------------------------------------------------
# Convenience Methods
# ---------------------------------------------------------------------------

class TestConvenienceMethods:
    def test_is_sensitive_true_for_restricted(self, clf, tmp_path):
        f = tmp_path / "data.docx"; f.write_text("d", encoding="utf-8")
        assert clf.is_sensitive(str(f)) is True

    def test_is_sensitive_false_for_unclassified(self, clf, tmp_path):
        f = tmp_path / "random.xyz123"; f.write_text("d", encoding="utf-8")
        assert clf.is_sensitive(str(f)) is False

    def test_classify_batch(self, clf, tmp_path):
        files = []
        for ext in [".key", ".sql", ".docx", ".json", ".xyz"]:
            f = tmp_path / f"test{ext}"; f.write_text("data", encoding="utf-8")
            files.append(str(f))
        results = clf.classify_batch(files)
        assert len(results) == 5
        tiers = [r["tier"] for r in results]
        assert TIER_HIGHLY_SENSITIVE in tiers
        assert TIER_CONFIDENTIAL      in tiers
        assert TIER_RESTRICTED        in tiers

    def test_reasons_populated_on_match(self, clf, tmp_path):
        f = tmp_path / "cert.pem"; f.write_text("data", encoding="utf-8")
        r = clf.classify(str(f), scan_content=False)
        assert len(r["reasons"]) > 0
