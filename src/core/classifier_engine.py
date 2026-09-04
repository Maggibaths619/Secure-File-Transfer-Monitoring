"""
classifier_engine.py
=====================
DLP (Data Loss Prevention) file classification engine.

Assigns one of five sensitivity tiers to every monitored file event:

  HIGHLY_SENSITIVE  – cryptographic keys, certificates, password vaults
  CONFIDENTIAL      – databases, backups, environment configs
  RESTRICTED        – documents, spreadsheets, reports with business data
  INTERNAL          – internal config files, JSON data, XML
  UNCLASSIFIED      – everything else

Classification uses three independent strategies (in order of priority):
  1. Path-segment matching (file lives in a sensitive directory)
  2. File extension matching
  3. Content keyword scanning (reads first 4 KB of text files)
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("sftms.classifier")

# ---------------------------------------------------------------------------
# Tier constants (ordered by ascending sensitivity)
# ---------------------------------------------------------------------------
TIER_UNCLASSIFIED    = "UNCLASSIFIED"
TIER_INTERNAL        = "INTERNAL"
TIER_RESTRICTED      = "RESTRICTED"
TIER_CONFIDENTIAL    = "CONFIDENTIAL"
TIER_HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"

TIER_ORDER = {
    TIER_UNCLASSIFIED:     0,
    TIER_INTERNAL:         1,
    TIER_RESTRICTED:       2,
    TIER_CONFIDENTIAL:     3,
    TIER_HIGHLY_SENSITIVE: 4,
}

# ---------------------------------------------------------------------------
# Default classification rules (overridden by config.yaml at runtime)
# ---------------------------------------------------------------------------

_DEFAULT_HIGHLY_SENSITIVE_EXTENSIONS = {
    ".key", ".pem", ".kdbx", ".ppk", ".p12", ".pfx", ".crt", ".cer",
    ".jks", ".keystore",
}

_DEFAULT_CONFIDENTIAL_EXTENSIONS = {
    ".sql", ".db", ".sqlite", ".sqlite3", ".bak", ".dump",
    ".env", ".cfg", ".conf", ".secret",
}

_DEFAULT_RESTRICTED_EXTENSIONS = {
    ".docx", ".doc", ".pdf", ".xlsx", ".xls", ".csv",
    ".pptx", ".ppt", ".odt", ".ods", ".odp",
}

_DEFAULT_INTERNAL_EXTENSIONS = {
    ".json", ".xml", ".yaml", ".yml", ".ini", ".toml",
    ".log", ".txt", ".md",
}

_DEFAULT_SENSITIVE_PATH_SEGMENTS = {
    "sensitive_vault", "passwords", "credentials", "private",
    "secret", "confidential", "restricted", "financial", "hr",
    "legal", "payroll", "classified",
}

_DEFAULT_SENSITIVE_KEYWORDS = [
    r"CONFIDENTIAL",
    r"RESTRICTED",
    r"TOP\s+SECRET",
    r"INTERNAL\s+USE\s+ONLY",
    r"\bSSN\b",
    r"social\s+security",
    r"password",
    r"API[_\-]KEY",
    r"SECRET[_\-]KEY",
    r"private\s+key",
    r"BEGIN RSA PRIVATE",
    r"BEGIN OPENSSH PRIVATE",
    r"credit\s+card",
    r"account\s+number",
    r"routing\s+number",
    r"bearer\s+token",
    r"access[_\-]token",
]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class FileClassifier:
    """
    Multi-strategy DLP file classifier.

    Usage:
        classifier = FileClassifier()
        result = classifier.classify("/path/to/document.pdf")
        print(result["tier"])          # e.g. RESTRICTED
        print(result["reasons"])       # list of matched rules
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Args:
            config: Optional parsed config dict from config.yaml
                    (key: 'classification').  Falls back to built-in defaults.
        """
        cfg = (config or {}).get("classification", {})

        tiers_cfg = cfg.get("tiers", {})

        self.highly_sensitive_exts: set = (
            set(tiers_cfg.get("HIGHLY_SENSITIVE", []))
            or _DEFAULT_HIGHLY_SENSITIVE_EXTENSIONS
        )
        self.confidential_exts: set = (
            set(tiers_cfg.get("CONFIDENTIAL", []))
            or _DEFAULT_CONFIDENTIAL_EXTENSIONS
        )
        self.restricted_exts: set = (
            set(tiers_cfg.get("RESTRICTED", []))
            or _DEFAULT_RESTRICTED_EXTENSIONS
        )
        self.internal_exts: set = (
            set(tiers_cfg.get("INTERNAL", []))
            or _DEFAULT_INTERNAL_EXTENSIONS
        )

        self.sensitive_path_segments: set = (
            set(s.lower() for s in cfg.get("sensitive_paths", []))
            or _DEFAULT_SENSITIVE_PATH_SEGMENTS
        )

        keyword_list = cfg.get("sensitive_keywords", []) or _DEFAULT_SENSITIVE_KEYWORDS
        self._keyword_patterns: List[re.Pattern] = [
            re.compile(kw, re.IGNORECASE) for kw in keyword_list
        ]

        # Extension -> tier lookup (built once for fast access)
        self._ext_tier: Dict[str, str] = {}
        for ext in self.highly_sensitive_exts:
            self._ext_tier[ext.lower()] = TIER_HIGHLY_SENSITIVE
        for ext in self.confidential_exts:
            self._ext_tier.setdefault(ext.lower(), TIER_CONFIDENTIAL)
        for ext in self.restricted_exts:
            self._ext_tier.setdefault(ext.lower(), TIER_RESTRICTED)
        for ext in self.internal_exts:
            self._ext_tier.setdefault(ext.lower(), TIER_INTERNAL)

    # ------------------------------------------------------------------
    def classify(self, file_path: str, scan_content: bool = True) -> Dict:
        """
        Classify a file and return a detailed result dict.

        Args:
            file_path:    Path to the file.
            scan_content: Whether to inspect file content for keywords.

        Returns:
            {
              "file_path":   str,
              "tier":        str,
              "reasons":     list[str],
              "is_sensitive": bool,
              "extension":   str,
            }
        """
        path = Path(file_path)
        reasons: List[str] = []
        current_tier = TIER_UNCLASSIFIED

        extension = path.suffix.lower()

        # ---- Strategy 1: Path segment matching -------------------------
        path_parts = set(p.lower() for p in path.parts)
        matched_segments = path_parts & self.sensitive_path_segments
        if matched_segments:
            tier_from_path = TIER_HIGHLY_SENSITIVE
            reasons.append(f"Sensitive path segment(s): {matched_segments}")
            current_tier = self._max_tier(current_tier, tier_from_path)

        # ---- Strategy 2: Extension matching ----------------------------
        tier_from_ext = self._ext_tier.get(extension)
        if tier_from_ext:
            reasons.append(f"Sensitive extension: {extension} -> {tier_from_ext}")
            current_tier = self._max_tier(current_tier, tier_from_ext)

        # ---- Strategy 3: Content keyword scanning ----------------------
        if scan_content and path.is_file():
            matched_keywords = self._scan_keywords(file_path)
            if matched_keywords:
                reasons.append(f"Sensitive keywords found: {matched_keywords}")
                current_tier = self._max_tier(current_tier, TIER_CONFIDENTIAL)

        is_sensitive = current_tier not in (TIER_UNCLASSIFIED, TIER_INTERNAL)

        logger.debug("Classified %s -> %s (%s)", file_path, current_tier, reasons or "no match")

        return {
            "file_path":    str(file_path),
            "tier":         current_tier,
            "reasons":      reasons,
            "is_sensitive": is_sensitive,
            "extension":    extension,
        }

    # ------------------------------------------------------------------
    def _scan_keywords(self, file_path: str, max_bytes: int = 4096) -> List[str]:
        """
        Read the first `max_bytes` of a file as text and return matched keywords.
        Binary files and unreadable files are silently skipped.
        """
        matched: List[str] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(max_bytes)
            for pattern in self._keyword_patterns:
                if pattern.search(content):
                    matched.append(pattern.pattern)
        except (OSError, PermissionError):
            pass
        return matched

    # ------------------------------------------------------------------
    @staticmethod
    def _max_tier(current: str, candidate: str) -> str:
        """Return whichever tier is more sensitive."""
        if TIER_ORDER.get(candidate, 0) > TIER_ORDER.get(current, 0):
            return candidate
        return current

    # ------------------------------------------------------------------
    def is_sensitive(self, file_path: str) -> bool:
        """Quick boolean check – returns True if file is RESTRICTED or above."""
        result = self.classify(file_path, scan_content=False)
        return result["is_sensitive"]

    # ------------------------------------------------------------------
    def classify_batch(self, file_paths: List[str]) -> List[Dict]:
        """Classify a list of files and return a list of result dicts."""
        return [self.classify(fp) for fp in file_paths]

    # ------------------------------------------------------------------
    def get_tier_color(self, tier: str) -> str:
        """Return an ANSI color code for the tier (used in CLI output)."""
        colors = {
            TIER_HIGHLY_SENSITIVE: "\033[91m",   # Bright Red
            TIER_CONFIDENTIAL:     "\033[31m",   # Red
            TIER_RESTRICTED:       "\033[33m",   # Yellow
            TIER_INTERNAL:         "\033[36m",   # Cyan
            TIER_UNCLASSIFIED:     "\033[32m",   # Green
        }
        return colors.get(tier, "\033[0m")
