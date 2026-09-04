"""
test_integrity.py
==================
Unit tests for the integrity_engine module.

Tests:
  - Hash computation correctness for SHA-256, SHA3-256, MD5
  - Consistency (same file -> same hash)
  - Different content -> different hash
  - HashBaseline record and retrieve
  - IntegrityVerifier pre/post flow (clean file)
  - IntegrityVerifier detects tampered file
  - Quick verify method
  - Directory scanning
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.integrity_engine import (
    HashBaseline,
    IntegrityVerifier,
    compute_all_hashes,
    compute_hash,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_file(tmp_path):
    """Create a temporary file with known content."""
    f = tmp_path / "test_file.txt"
    f.write_text("Hello, Secure World!\n", encoding="utf-8")
    return f


@pytest.fixture
def tmp_db(tmp_path):
    """Return a path for a temporary SQLite database."""
    return str(tmp_path / "test_baseline.db")


@pytest.fixture
def baseline(tmp_db):
    return HashBaseline(db_path=tmp_db)


@pytest.fixture
def verifier(baseline):
    return IntegrityVerifier(baseline=baseline)


# ---------------------------------------------------------------------------
# Hash Computation Tests
# ---------------------------------------------------------------------------

class TestComputeHash:
    def test_sha256_returns_64_hex_chars(self, tmp_file):
        h = compute_hash(str(tmp_file), "sha256")
        assert h is not None
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha3_256_returns_64_hex_chars(self, tmp_file):
        h = compute_hash(str(tmp_file), "sha3_256")
        assert h is not None
        assert len(h) == 64

    def test_md5_returns_32_hex_chars(self, tmp_file):
        h = compute_hash(str(tmp_file), "md5")
        assert h is not None
        assert len(h) == 32

    def test_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"; f1.write_text("same content", encoding="utf-8")
        f2 = tmp_path / "b.txt"; f2.write_text("same content", encoding="utf-8")
        assert compute_hash(str(f1)) == compute_hash(str(f2))

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"; f1.write_text("content A", encoding="utf-8")
        f2 = tmp_path / "b.txt"; f2.write_text("content B", encoding="utf-8")
        assert compute_hash(str(f1)) != compute_hash(str(f2))

    def test_nonexistent_file_returns_none(self):
        h = compute_hash("/nonexistent/path/file.txt")
        assert h is None

    def test_unsupported_algorithm_returns_none(self, tmp_file):
        h = compute_hash(str(tmp_file), "fakehash999")
        assert h is None

    def test_compute_all_hashes_returns_three_algorithms(self, tmp_file):
        hashes = compute_all_hashes(str(tmp_file))
        assert "sha256"   in hashes
        assert "sha3_256" in hashes
        assert "md5"      in hashes
        assert all(v is not None for v in hashes.values())

    def test_empty_file_hash(self, tmp_path):
        f = tmp_path / "empty.txt"; f.write_bytes(b"")
        h = compute_hash(str(f), "sha256")
        # SHA-256 of empty string is well-known
        assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_large_file_chunked(self, tmp_path):
        """Test that chunk-based reading gives the same result as reading all at once."""
        import hashlib
        content = b"A" * (1024 * 512)  # 512 KB
        f = tmp_path / "large.bin"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert compute_hash(str(f), "sha256", chunk_size=4096) == expected


# ---------------------------------------------------------------------------
# HashBaseline Tests
# ---------------------------------------------------------------------------

class TestHashBaseline:
    def test_record_and_retrieve(self, baseline, tmp_file):
        hashes = baseline.record(str(tmp_file), label="test_label")
        retrieved = baseline.get_latest(str(tmp_file), label="test_label")
        assert retrieved is not None
        assert retrieved["sha256"] == hashes["sha256"]

    def test_get_latest_returns_none_for_missing(self, baseline):
        result = baseline.get_latest("/nonexistent/path.txt", "baseline")
        assert result is None

    def test_record_multiple_labels(self, baseline, tmp_file):
        baseline.record(str(tmp_file), label="pre_transfer")
        baseline.record(str(tmp_file), label="post_transfer")
        pre  = baseline.get_latest(str(tmp_file), "pre_transfer")
        post = baseline.get_latest(str(tmp_file), "post_transfer")
        assert pre  is not None
        assert post is not None

    def test_get_all_returns_all_records(self, baseline, tmp_file):
        baseline.record(str(tmp_file), label="pre_transfer")
        baseline.record(str(tmp_file), label="post_transfer")
        records = baseline.get_all(str(tmp_file))
        assert len(records) == 2


# ---------------------------------------------------------------------------
# IntegrityVerifier Tests
# ---------------------------------------------------------------------------

class TestIntegrityVerifier:
    def test_clean_transfer_verifies_ok(self, verifier, tmp_path):
        # Use SAME path for both pre and post to test the verify() logic properly
        f = tmp_path / "source.txt"
        f.write_text("original content", encoding="utf-8")

        verifier.snapshot_pre(str(f))
        verifier.snapshot_post(str(f))  # same content -> hashes match
        result = verifier.verify(str(f))

        assert result["pre_exists"]  is True
        assert result["post_exists"] is True
        assert result["integrity_ok"] is True
        assert result["tampered"] is False
        assert "algorithm_results" in result

    def test_tampered_file_detected(self, verifier, tmp_path):
        src  = tmp_path / "tampered.txt"
        src.write_text("original content", encoding="utf-8")

        verifier.snapshot_pre(str(src))
        # Tamper the file
        src.write_text("TAMPERED CONTENT - attacker was here", encoding="utf-8")
        verifier.snapshot_post(str(src))

        result = verifier.verify(str(src))
        assert result["tampered"] is True
        assert result["integrity_ok"] is False

    def test_missing_baseline_handled_gracefully(self, verifier, tmp_path):
        f = tmp_path / "no_baseline.txt"
        f.write_text("content", encoding="utf-8")
        result = verifier.verify(str(f))
        # Should not raise; pre/post don't exist
        assert result["pre_exists"]  is False
        assert result["post_exists"] is False
        assert result["tampered"]    is False

    def test_quick_verify_match(self, verifier, tmp_file):
        expected = compute_hash(str(tmp_file), "sha256")
        ok, actual = verifier.quick_verify(str(tmp_file), expected, "sha256")
        assert ok is True
        assert actual == expected

    def test_quick_verify_mismatch(self, verifier, tmp_file):
        ok, actual = verifier.quick_verify(str(tmp_file), "0" * 64, "sha256")
        assert ok is False

    def test_scan_directory(self, verifier, tmp_path):
        # Use a dedicated sub-directory so no SQLite db leaks in
        scan_dir = tmp_path / "scan_zone"
        scan_dir.mkdir()
        (scan_dir / "f1.txt").write_text("file 1", encoding="utf-8")
        (scan_dir / "f2.txt").write_text("file 2", encoding="utf-8")
        results = verifier.scan_directory(str(scan_dir))
        assert len(results) == 2
        assert all(v is not None for v in results.values())
