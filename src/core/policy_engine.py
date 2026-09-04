"""
policy_engine.py
=================
DLP Policy Enforcement Engine.

Evaluates every file system event against a configurable set of DLP rules
and returns a policy decision:

  - AUTHORIZED   – normal, expected transfer
  - VIOLATION    – unauthorized / suspicious transfer

Rules evaluated (in priority order):
  1. Sensitive file to unauthorized destination (DLP / Exfiltration)
  2. File hash integrity mismatch (Tampering)
  3. Protected source directory movement (Protected Zone Violation)
  4. Burst exfiltration rate anomaly (Mass Transfer / Ransomware staging)
  5. Critical file deletion (Destructive Action)
  6. Suspicious process actor (Risky Process)
"""

import logging
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .alert_manager import (
    AlertManager,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
from .classifier_engine import (
    TIER_UNCLASSIFIED,
    TIER_INTERNAL,
    TIER_RESTRICTED,
    TIER_CONFIDENTIAL,
    TIER_HIGHLY_SENSITIVE,
)

logger = logging.getLogger("sftms.policy_engine")

# ---------------------------------------------------------------------------
# Default policy constants (overridden by config at runtime)
# ---------------------------------------------------------------------------

_DEFAULT_UNAUTHORIZED_DESTINATIONS = {
    "usb_drive_sim", "cloud_sync_sim",
    "onedrive", "dropbox", "google drive", "icloud",
    "appdata\\local\\temp", "\\temp\\", "\\tmp\\",
}

_DEFAULT_PROTECTED_SOURCES = {
    "sensitive_vault", "credentials", "financial",
}

_DEFAULT_SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "robocopy.exe", "xcopy.exe", "7z.exe",
    "winrar.exe", "rclone.exe", "winscp.exe", "nc.exe",
    "ncat.exe", "netcat.exe", "curl.exe", "wget.exe",
}

_BURST_MAX_TRANSFERS = 10
_BURST_WINDOW_SECONDS = 10


# ---------------------------------------------------------------------------
# Policy Decision Result
# ---------------------------------------------------------------------------

class PolicyDecision:
    """Encapsulates the result of a policy evaluation."""

    AUTHORIZED = "AUTHORIZED"
    VIOLATION  = "VIOLATION"

    def __init__(
        self,
        outcome: str,
        reasons: Optional[List[str]] = None,
        alert_severity: str = SEVERITY_INFO,
        alert_category: str = "FILE_EVENT",
        alert_message: str = "",
        is_authorized: bool = True,
    ) -> None:
        self.outcome        = outcome
        self.reasons        = reasons or []
        self.alert_severity = alert_severity
        self.alert_category = alert_category
        self.alert_message  = alert_message
        self.is_authorized  = is_authorized
        self.timestamp      = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            "outcome":        self.outcome,
            "reasons":        self.reasons,
            "alert_severity": self.alert_severity,
            "alert_category": self.alert_category,
            "alert_message":  self.alert_message,
            "is_authorized":  self.is_authorized,
            "timestamp":      self.timestamp,
        }


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluates file events against DLP policies and dispatches alerts.

    Usage:
        engine = PolicyEngine(alert_manager=alert_mgr, config=config)
        decision = engine.evaluate(
            event_type="FILE_MOVED",
            file_path="/path/to/file.key",
            destination_path="/usb_drive_sim/file.key",
            classification={"tier": "HIGHLY_SENSITIVE", "is_sensitive": True},
            integrity={"tampered": False, "integrity_ok": True},
            attribution={"username": "jdoe", "process_name": "explorer.exe"},
        )
    """

    def __init__(
        self,
        alert_manager: Optional[AlertManager] = None,
        config: Optional[Dict] = None,
    ) -> None:
        self.alert_manager = alert_manager
        cfg = (config or {}).get("dlp", {})
        burst_cfg = cfg.get("burst_detection", {})

        self.unauthorized_destinations: set = set(
            d.lower() for d in cfg.get("unauthorized_destinations", [])
        ) or _DEFAULT_UNAUTHORIZED_DESTINATIONS

        self.protected_sources: set = set(
            p.lower() for p in cfg.get("protected_sources", [])
        ) or _DEFAULT_PROTECTED_SOURCES

        self.max_burst_transfers: int = burst_cfg.get("max_transfers", _BURST_MAX_TRANSFERS)
        self.burst_window_seconds: int = burst_cfg.get("window_seconds", _BURST_WINDOW_SECONDS)
        self.burst_alert_severity: str = burst_cfg.get("alert_severity", SEVERITY_CRITICAL)
        self.burst_enabled: bool = burst_cfg.get("enabled", True)

        # Sliding-window transfer timestamps per-user (for burst detection)
        self._burst_windows: Dict[str, deque] = {}
        self._burst_lock = threading.Lock()

        logger.info("PolicyEngine initialised.")

    # ------------------------------------------------------------------
    def evaluate(
        self,
        event_type: str,
        file_path: str,
        destination_path: str = "",
        source_path: str = "",
        classification: Optional[Dict] = None,
        integrity: Optional[Dict] = None,
        attribution: Optional[Dict] = None,
    ) -> PolicyDecision:
        """
        Run all DLP policy rules against the event and return a decision.

        Args:
            event_type:       FILE_CREATED | FILE_MODIFIED | FILE_MOVED |
                              FILE_DELETED | FILE_COPIED
            file_path:        Path of the affected file.
            destination_path: Target path (for move/copy events).
            source_path:      Original path (for move events).
            classification:   Dict from FileClassifier.classify().
            integrity:        Dict from IntegrityVerifier.verify().
            attribution:      Dict from ProcessTracker.attribute_event().

        Returns:
            PolicyDecision object.
        """
        classification = classification or {}
        integrity      = integrity      or {}
        attribution    = attribution    or {}

        tier         = classification.get("tier", TIER_UNCLASSIFIED)
        is_sensitive = classification.get("is_sensitive", False)
        tampered     = integrity.get("tampered", False)
        username     = attribution.get("username", "UNKNOWN")
        process_name = (attribution.get("process_name") or "").lower()

        violations: List[str] = []
        max_severity: str     = SEVERITY_INFO
        category: str         = "FILE_EVENT"

        # ---- Rule 1: Integrity / Tampering --------------------------------
        if tampered:
            violations.append(
                f"[CRITICAL] INTEGRITY VIOLATION: File hash mismatch detected. "
                f"'{file_path}' was modified in-transit or tampered with."
            )
            max_severity = self._escalate(max_severity, SEVERITY_CRITICAL)
            category = "INTEGRITY_VIOLATION"

        # ---- Rule 2: Sensitive file -> Unauthorized destination ------------
        if is_sensitive and destination_path:
            dest_lower = destination_path.lower().replace("/", "\\")
            for bad_dest in self.unauthorized_destinations:
                if bad_dest in dest_lower:
                    violations.append(
                        f"[CRITICAL] DLP VIOLATION: {tier} file '{file_path}' "
                        f"copied/moved to unauthorized destination '{destination_path}'. "
                        f"Potential DATA EXFILTRATION."
                    )
                    max_severity = self._escalate(max_severity, SEVERITY_CRITICAL)
                    category = "DLP_VIOLATION"
                    break

        # ---- Rule 3: Protected source -> any external destination ----------
        if destination_path:
            path_lower = file_path.lower().replace("/", "\\")
            for protected in self.protected_sources:
                if protected in path_lower:
                    if tier not in (TIER_UNCLASSIFIED, TIER_INTERNAL):
                        violations.append(
                            f"[HIGH] PROTECTED ZONE VIOLATION: File '{file_path}' "
                            f"moved OUT of protected source zone '{protected}' "
                            f"-> '{destination_path}'."
                        )
                        max_severity = self._escalate(max_severity, SEVERITY_HIGH)
                        category = "PROTECTED_ZONE_VIOLATION"
                        break

        # ---- Rule 4: Burst exfiltration -----------------------------------
        if self.burst_enabled and event_type in ("FILE_MOVED", "FILE_CREATED", "FILE_COPIED"):
            if self._is_burst(username):
                violations.append(
                    f"[CRITICAL] BURST EXFILTRATION ANOMALY: User '{username}' transferred "
                    f">{self.max_burst_transfers} files in {self.burst_window_seconds}s. "
                    f"Possible mass data theft or ransomware staging."
                )
                max_severity = self._escalate(max_severity, self.burst_alert_severity)
                category = "BURST_EXFILTRATION"

        # ---- Rule 5: Critical file deletion --------------------------------
        if event_type == "FILE_DELETED" and is_sensitive:
            violations.append(
                f"[HIGH] DESTRUCTIVE ACTION: {tier} file '{file_path}' deleted by '{username}'."
            )
            max_severity = self._escalate(max_severity, SEVERITY_HIGH)
            category = "DESTRUCTIVE_ACTION"

        # ---- Rule 6: Suspicious process actor -----------------------------
        if process_name and process_name in _DEFAULT_SUSPICIOUS_PROCESSES:
            severity_bonus = SEVERITY_MEDIUM if not violations else SEVERITY_HIGH
            violations.append(
                f"[MEDIUM] SUSPICIOUS PROCESS: '{process_name}' is performing file "
                f"operations on '{file_path}'."
            )
            max_severity = self._escalate(max_severity, severity_bonus)
            if category == "FILE_EVENT":
                category = "SUSPICIOUS_PROCESS"

        # ---- Build Decision --------------------------------------------
        is_authorized = len(violations) == 0
        if not is_authorized:
            message = " | ".join(violations)
            if self.alert_manager:
                self.alert_manager.dispatch(
                    severity=max_severity,
                    category=category,
                    message=message,
                    file_path=file_path,
                    destination=destination_path,
                    extra={
                        "tier":       tier,
                        "event_type": event_type,
                        "username":   username,
                    },
                )
            logger.warning("POLICY VIOLATION [%s] %s", max_severity, message)
            return PolicyDecision(
                outcome=PolicyDecision.VIOLATION,
                reasons=violations,
                alert_severity=max_severity,
                alert_category=category,
                alert_message=message,
                is_authorized=False,
            )

        # Authorized – log at INFO
        if self.alert_manager:
            self.alert_manager.dispatch(
                severity=SEVERITY_INFO,
                category="AUTHORIZED_TRANSFER",
                message=f"Authorized {event_type}: {file_path}",
                file_path=file_path,
                destination=destination_path,
            )
        return PolicyDecision(
            outcome=PolicyDecision.AUTHORIZED,
            alert_severity=SEVERITY_INFO,
            alert_category="AUTHORIZED_TRANSFER",
            alert_message=f"Authorized {event_type}",
            is_authorized=True,
        )

    # ------------------------------------------------------------------
    def _is_burst(self, username: str) -> bool:
        """
        Sliding-window burst detection.

        Returns True if the user has exceeded the transfer threshold
        within the defined time window.
        """
        now = datetime.now()
        window_start = now - timedelta(seconds=self.burst_window_seconds)

        with self._burst_lock:
            if username not in self._burst_windows:
                self._burst_windows[username] = deque()

            dq = self._burst_windows[username]
            dq.append(now)

            # Evict old entries outside the window
            while dq and dq[0] < window_start:
                dq.popleft()

            count = len(dq)

        return count > self.max_burst_transfers

    # ------------------------------------------------------------------
    @staticmethod
    def _escalate(current: str, candidate: str) -> str:
        """Return whichever severity is higher."""
        order = {
            SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
            SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4,
        }
        return candidate if order.get(candidate, 0) > order.get(current, 0) else current
