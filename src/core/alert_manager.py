"""
alert_manager.py
=================
Real-time alert dispatcher and in-memory event queue.

Severity Levels (ascending):
  INFO < LOW < MEDIUM < HIGH < CRITICAL

Provides:
  - Thread-safe in-memory alert queue for live web dashboard streaming (SSE)
  - Coloured console printing via colorama
  - Alert statistics counters
"""

import logging
import queue
import threading
from collections import Counter
from datetime import datetime
from typing import Callable, Dict, List, Optional

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

logger = logging.getLogger("sftms.alert_manager")

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------

SEVERITY_INFO     = "INFO"
SEVERITY_LOW      = "LOW"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_HIGH     = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER = {
    SEVERITY_INFO:     0,
    SEVERITY_LOW:      1,
    SEVERITY_MEDIUM:   2,
    SEVERITY_HIGH:     3,
    SEVERITY_CRITICAL: 4,
}

SEVERITY_COLORS = {
    SEVERITY_INFO:     Fore.CYAN,
    SEVERITY_LOW:      Fore.GREEN,
    SEVERITY_MEDIUM:   Fore.YELLOW,
    SEVERITY_HIGH:     Fore.RED,
    SEVERITY_CRITICAL: Fore.MAGENTA,
}

SEVERITY_ICONS = {
    SEVERITY_INFO:     "[i]",
    SEVERITY_LOW:      "[+]",
    SEVERITY_MEDIUM:   "[!]",
    SEVERITY_HIGH:     "[!!]",
    SEVERITY_CRITICAL: "[!!!]",
}

# ---------------------------------------------------------------------------
# Alert data class
# ---------------------------------------------------------------------------

class Alert:
    """Represents a single security alert."""

    _id_counter = 0
    _lock = threading.Lock()

    def __init__(
        self,
        severity: str,
        category: str,
        message: str,
        file_path: str = "",
        destination: str = "",
        extra: Optional[Dict] = None,
    ) -> None:
        with Alert._lock:
            Alert._id_counter += 1
            self.id = Alert._id_counter

        self.severity    = severity.upper()
        self.category    = category
        self.message     = message
        self.file_path   = file_path
        self.destination = destination
        self.extra       = extra or {}
        self.timestamp   = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            "id":          self.id,
            "timestamp":   self.timestamp,
            "severity":    self.severity,
            "category":    self.category,
            "message":     self.message,
            "file_path":   self.file_path,
            "destination": self.destination,
            "extra":       self.extra,
        }

    def __repr__(self) -> str:
        return (
            f"Alert(id={self.id}, severity={self.severity}, "
            f"category={self.category}, file={self.file_path!r})"
        )


# ---------------------------------------------------------------------------
# Alert Manager
# ---------------------------------------------------------------------------

class AlertManager:
    """
    Centralized alert dispatcher.

    - Maintains a thread-safe FIFO queue for live SSE streaming.
    - Prints colour-coded alerts to the console.
    - Tracks per-severity counters for dashboard statistics.
    - Supports subscriber callbacks for custom integrations.
    """

    def __init__(
        self,
        max_queue_size: int = 1000,
        min_severity: str = SEVERITY_INFO,
        console_alerts: bool = True,
    ) -> None:
        self.max_queue_size  = max_queue_size
        self.min_severity    = min_severity
        self.console_alerts  = console_alerts

        # Thread-safe queues
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._history: List[Alert] = []
        self._history_lock = threading.Lock()

        # Statistics
        self.stats: Counter = Counter()

        # Callbacks (list of callables accepting an Alert)
        self._subscribers: List[Callable[[Alert], None]] = []

        logger.info("AlertManager initialised (min_severity=%s)", min_severity)

    # ------------------------------------------------------------------
    def dispatch(
        self,
        severity: str,
        category: str,
        message: str,
        file_path: str = "",
        destination: str = "",
        extra: Optional[Dict] = None,
    ) -> Alert:
        """
        Create and dispatch a new alert.

        Args:
            severity:    One of INFO / LOW / MEDIUM / HIGH / CRITICAL.
            category:    Short alert type label (e.g. 'DLP_VIOLATION').
            message:     Human-readable description.
            file_path:   File involved in the event.
            destination: Target path / destination (if applicable).
            extra:       Arbitrary key-value metadata dict.

        Returns:
            The created Alert object.
        """
        alert = Alert(
            severity=severity,
            category=category,
            message=message,
            file_path=file_path,
            destination=destination,
            extra=extra or {},
        )

        # Filter by minimum severity
        if SEVERITY_ORDER.get(alert.severity, 0) < SEVERITY_ORDER.get(self.min_severity, 0):
            return alert

        # Update statistics
        self.stats[alert.severity] += 1
        self.stats["TOTAL"] += 1

        # Store in history (bounded)
        with self._history_lock:
            self._history.append(alert)
            if len(self._history) > self.max_queue_size:
                self._history.pop(0)

        # Push to SSE queue (non-blocking – drop if full)
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            pass

        # Console output
        if self.console_alerts:
            self._print_alert(alert)

        # Subscriber callbacks
        for cb in self._subscribers:
            try:
                cb(alert)
            except Exception as exc:
                logger.warning("Alert subscriber raised exception: %s", exc)

        logger.info(
            "[ALERT] %s | %s | %s | %s",
            alert.severity, alert.category, alert.message, alert.file_path,
        )
        return alert

    # ------------------------------------------------------------------
    def _print_alert(self, alert: Alert) -> None:
        color  = SEVERITY_COLORS.get(alert.severity, "")
        icon   = SEVERITY_ICONS.get(alert.severity, "•")
        reset  = Style.RESET_ALL
        ts     = alert.timestamp[11:19]  # HH:MM:SS

        print(
            f"{color}{icon} [{ts}] [{alert.severity:<8}] [{alert.category}] "
            f"{alert.message}"
            + (f"\n         File: {alert.file_path}" if alert.file_path else "")
            + (f"  ->  Dest: {alert.destination}" if alert.destination else "")
            + reset
        )

    # ------------------------------------------------------------------
    def subscribe(self, callback: Callable[[Alert], None]) -> None:
        """Register a callback function to receive every new alert."""
        self._subscribers.append(callback)

    # ------------------------------------------------------------------
    def get_history(
        self,
        severity_filter: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """
        Return recent alerts as a list of dicts, optionally filtered.

        Args:
            severity_filter: If given, only return alerts of this severity.
            limit:           Maximum number of alerts to return (newest first).
        """
        with self._history_lock:
            alerts = list(self._history)

        if severity_filter:
            alerts = [a for a in alerts if a.severity == severity_filter.upper()]

        return [a.to_dict() for a in reversed(alerts[-limit:])]

    # ------------------------------------------------------------------
    def get_stats(self) -> Dict:
        """Return alert count statistics by severity."""
        return dict(self.stats)

    # ------------------------------------------------------------------
    def stream_alerts(self):
        """
        Generator yielding Alert objects from the queue as they arrive.
        Designed for use in Flask SSE endpoints:

            for alert in manager.stream_alerts():
                yield f"data: {json.dumps(alert.to_dict())}\\n\\n"
        """
        while True:
            try:
                alert = self._queue.get(timeout=1.0)
                yield alert
            except queue.Empty:
                yield None  # Heartbeat – caller should send SSE comment

    # ------------------------------------------------------------------
    def clear_history(self) -> None:
        """Clear the in-memory alert history."""
        with self._history_lock:
            self._history.clear()
        self.stats.clear()


# ---------------------------------------------------------------------------
# Module-level singleton (shared across all subsystems)
# ---------------------------------------------------------------------------

_default_manager: Optional[AlertManager] = None


def get_alert_manager(
    max_queue_size: int = 1000,
    console_alerts: bool = True,
    min_severity: str = SEVERITY_INFO,
) -> AlertManager:
    """Return (or create) the module-level singleton AlertManager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = AlertManager(
            max_queue_size=max_queue_size,
            min_severity=min_severity,
            console_alerts=console_alerts,
        )
    return _default_manager
