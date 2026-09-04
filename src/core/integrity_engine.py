"""
integrity_engine.py
====================
Cryptographic file integrity verification engine.

Provides:
  - Multi-algorithm hash computation (SHA-256, SHA3-256, MD5)
  - Chunk-based reading for large files (memory-safe)
  - Hash baseline registry backed by SQLite
  - Pre-transfer / post-transfer comparison with mismatch detection
  - Tamper, corruption, and in-flight modification detection
"""

import hashlib
import os
import sqlite3
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("sftms.integrity")


# ---------------------------------------------------------------------------
# Hash Computation
# ---------------------------------------------------------------------------

def compute_hash(file_path: str, algorithm: str = "sha256", chunk_size: int = 65536) -> Optional[str]:
    """
    Compute a cryptographic hash of a file using the specified algorithm.

    Args:
        file_path: Absolute or relative path to the target file.
        algorithm:  Hash algorithm name (sha256 | sha3_256 | md5).
        chunk_size: Number of bytes to read per chunk (default 64 KB).

    Returns:
        Hex digest string, or None if the file cannot be read.
    """
    algo = algorithm.lower().replace("-", "_")
    try:
        h = hashlib.new(algo)
    except ValueError:
        logger.error("Unsupported hash algorithm: %s", algorithm)
        return None

    try:
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot hash %s: %s", file_path, exc)
        return None


def compute_all_hashes(file_path: str, chunk_size: int = 65536) -> Dict[str, Optional[str]]:
    """Return SHA-256, SHA3-256, and MD5 hashes for a file."""
    return {
        "sha256":   compute_hash(file_path, "sha256",   chunk_size),
        "sha3_256": compute_hash(file_path, "sha3_256", chunk_size),
        "md5":      compute_hash(file_path, "md5",      chunk_size),
    }


# ---------------------------------------------------------------------------
# Hash Baseline Registry (SQLite-backed)
# ---------------------------------------------------------------------------

class HashBaseline:
    """
    Persistent hash baseline registry.

    Stores pre-transfer hashes and allows post-transfer comparison to detect
    file tampering, corruption, or unauthorised modifications.
    """

    def __init__(self, db_path: str = "logs/audit_vault.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hash_baselines (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path   TEXT    NOT NULL,
                    sha256      TEXT,
                    sha3_256    TEXT,
                    md5         TEXT,
                    file_size   INTEGER,
                    recorded_at TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
                    label       TEXT    DEFAULT 'baseline'
                )
            """)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # ------------------------------------------------------------------
    def record(self, file_path: str, label: str = "baseline") -> Dict[str, Optional[str]]:
        """
        Compute and persist hashes for a file.

        Args:
            file_path: Path to the file.
            label:     Descriptive label (e.g. 'pre_transfer', 'post_transfer').

        Returns:
            Dictionary of algorithm -> hex digest.
        """
        hashes = compute_all_hashes(file_path)
        size = Path(file_path).stat().st_size if Path(file_path).exists() else None
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO hash_baselines (file_path, sha256, sha3_256, md5, file_size, label)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    str(file_path),
                    hashes.get("sha256"),
                    hashes.get("sha3_256"),
                    hashes.get("md5"),
                    size,
                    label,
                ),
            )
            conn.commit()
        logger.debug("Recorded %s hashes for: %s", label, file_path)
        return hashes

    # ------------------------------------------------------------------
    def get_latest(self, file_path: str, label: str = "baseline") -> Optional[Dict[str, Optional[str]]]:
        """Retrieve the most recent baseline for a given file path and label."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT sha256, sha3_256, md5 FROM hash_baselines
                   WHERE file_path = ? AND label = ?
                   ORDER BY recorded_at DESC LIMIT 1""",
                (str(file_path), label),
            ).fetchone()
        if row:
            return {"sha256": row[0], "sha3_256": row[1], "md5": row[2]}
        return None

    # ------------------------------------------------------------------
    def get_all(self, file_path: str) -> list:
        """Retrieve all recorded hash baselines for a file."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT label, sha256, sha3_256, md5, file_size, recorded_at
                   FROM hash_baselines WHERE file_path = ?
                   ORDER BY recorded_at DESC""",
                (str(file_path),),
            ).fetchall()
        return [
            {
                "label": r[0],
                "sha256": r[1],
                "sha3_256": r[2],
                "md5": r[3],
                "file_size": r[4],
                "recorded_at": r[5],
            }
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Integrity Verification
# ---------------------------------------------------------------------------

class IntegrityVerifier:
    """
    High-level integrity verification orchestrator.

    Workflow:
      1. snapshot_pre(file_path)  – record hash before a transfer.
      2. snapshot_post(file_path) – record hash after transfer completes.
      3. verify(file_path)        – compare pre vs post; return result dict.
    """

    def __init__(self, baseline: Optional[HashBaseline] = None, db_path: str = "logs/audit_vault.db"):
        self.baseline = baseline or HashBaseline(db_path)

    # ------------------------------------------------------------------
    def snapshot_pre(self, file_path: str) -> Dict[str, Optional[str]]:
        """Record pre-transfer hash baseline."""
        return self.baseline.record(file_path, label="pre_transfer")

    # ------------------------------------------------------------------
    def snapshot_post(self, file_path: str) -> Dict[str, Optional[str]]:
        """Record post-transfer hash baseline."""
        return self.baseline.record(file_path, label="post_transfer")

    # ------------------------------------------------------------------
    def verify(self, file_path: str, pre_file_path: Optional[str] = None) -> Dict:
        """
        Compare pre-transfer and post-transfer hashes.

        Returns:
            {
              "file_path": str,
              "integrity_ok": bool,
              "tampered":     bool,
              "algorithm_results": { algo: { pre, post, match } },
              "pre_exists":   bool,
              "post_exists":  bool,
            }
        """
        lookup_pre_path = pre_file_path if pre_file_path else file_path
        pre  = self.baseline.get_latest(lookup_pre_path, "pre_transfer")
        post = self.baseline.get_latest(file_path, "post_transfer")

        result: Dict = {
            "file_path": str(file_path),
            "pre_exists":  pre  is not None,
            "post_exists": post is not None,
            "integrity_ok": False,
            "tampered": False,
            "algorithm_results": {},
        }

        if not pre or not post:
            result["tampered"] = False  # can't determine – no baseline
            logger.warning("Incomplete baseline for %s (pre=%s, post=%s)", file_path, bool(pre), bool(post))
            return result

        all_match = True
        for algo in ("sha256", "sha3_256", "md5"):
            pre_val  = pre.get(algo)
            post_val = post.get(algo)
            match = (pre_val is not None and post_val is not None and pre_val == post_val)
            result["algorithm_results"][algo] = {
                "pre":  pre_val,
                "post": post_val,
                "match": match,
            }
            if not match:
                all_match = False

        result["integrity_ok"] = all_match
        result["tampered"]     = not all_match
        return result

    # ------------------------------------------------------------------
    def quick_verify(self, file_path: str, expected_hash: str, algorithm: str = "sha256") -> Tuple[bool, Optional[str]]:
        """
        Compare current file hash against a known expected hash.

        Returns:
            (matches: bool, actual_hash: str | None)
        """
        actual = compute_hash(file_path, algorithm)
        return (actual == expected_hash, actual)

    # ------------------------------------------------------------------
    def scan_directory(self, directory: str, algorithm: str = "sha256") -> Dict[str, Optional[str]]:
        """
        Compute hashes for all files in a directory tree.

        Returns:
            { relative_path: hash_digest }
        """
        results = {}
        base = Path(directory)
        for fpath in base.rglob("*"):
            if fpath.is_file():
                rel = str(fpath.relative_to(base))
                results[rel] = compute_hash(str(fpath), algorithm)
        return results
