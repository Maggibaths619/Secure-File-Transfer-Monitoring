"""
file_monitor.py
================
Watchdog-based filesystem event monitor.

Orchestrates:
  - watchdog Observer for all configured watch paths
  - Event debouncing (prevents duplicate OS notifications)
  - Routing of each event through the full detection pipeline:
      FileClassifier -> IntegrityVerifier -> ProcessTracker -> PolicyEngine -> AuditLogger
  - Thread-safe operation
"""

import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from .alert_manager import AlertManager, get_alert_manager
from .classifier_engine import FileClassifier
from .integrity_engine import IntegrityVerifier, HashBaseline
from .logger_engine import AuditLogger, build_log_entry
from .policy_engine import PolicyEngine
from .process_tracker import ProcessTracker

logger = logging.getLogger("sftms.file_monitor")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml")


def load_config() -> Dict:
    """Load YAML configuration from config/config.yaml."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("Could not load config (%s). Using defaults.", exc)
        return {}


# ---------------------------------------------------------------------------
# Event Handler
# ---------------------------------------------------------------------------

class SecureFileEventHandler(FileSystemEventHandler):
    """
    Handles watchdog filesystem events and routes them through
    the full DLP detection pipeline.
    """

    def __init__(
        self,
        classifier: FileClassifier,
        verifier: IntegrityVerifier,
        tracker: ProcessTracker,
        policy: PolicyEngine,
        audit_logger: AuditLogger,
        debounce_seconds: float = 0.5,
        on_event_callback: Optional[Callable[[Dict], None]] = None,
    ) -> None:
        super().__init__()
        self.classifier    = classifier
        self.verifier      = verifier
        self.tracker       = tracker
        self.policy        = policy
        self.audit_logger  = audit_logger
        self.debounce      = debounce_seconds
        self.on_event_cb   = on_event_callback

        # Debounce: track last seen timestamp per path
        self._last_seen: Dict[str, float] = {}
        self._debounce_lock = threading.Lock()

    # ------------------------------------------------------------------
    def _is_debounced(self, path: str) -> bool:
        """Return True if this path was processed within debounce window."""
        now = time.time()
        with self._debounce_lock:
            last = self._last_seen.get(path, 0.0)
            if now - last < self.debounce:
                return True
            self._last_seen[path] = now
        return False

    # ------------------------------------------------------------------
    def _should_ignore(self, path: str) -> bool:
        """Ignore log files, temp OS files, and hidden system files."""
        p = Path(path)
        name = p.name.lower()
        ignore_exts = {".tmp", ".lnk", ".part", ".crdownload", ".swp"}
        ignore_names = {".ds_store", "thumbs.db", "desktop.ini"}
        return (
            name.startswith("~$")          # Office temp files
            or p.suffix.lower() in ignore_exts
            or name in ignore_names
            or "\\logs\\" in path.lower()
            or "/logs/" in path.lower()
        )

    # ------------------------------------------------------------------
    def _process_event(
        self,
        event_type: str,
        src_path: str,
        dest_path: str = "",
    ) -> None:
        """Run the full detection pipeline for a single file event."""
        if self._should_ignore(src_path):
            return
        if self._is_debounced(src_path):
            return

        logger.debug("EVENT %-16s %s", event_type, src_path)

        # ---- 1. Classify -----------------------------------------------
        classification = self.classifier.classify(src_path)

        # ---- 2. Integrity snapshot -------------------------------------
        integrity: Dict = {}
        if os.path.isfile(src_path):
            if event_type in ("FILE_CREATED", "FILE_MODIFIED"):
                self.verifier.snapshot_pre(src_path)
            elif event_type in ("FILE_MOVED", "FILE_COPIED") and dest_path and os.path.isfile(dest_path):
                pre = self.verifier.snapshot_pre(src_path)
                post = self.verifier.snapshot_post(dest_path)
                integrity = self.verifier.verify(dest_path)

        # ---- 3. Attribution --------------------------------------------
        attribution = self.tracker.attribute_event(src_path)

        # ---- 4. Policy evaluation --------------------------------------
        decision = self.policy.evaluate(
            event_type=event_type,
            file_path=src_path,
            destination_path=dest_path,
            source_path=src_path,
            classification=classification,
            integrity=integrity,
            attribution=attribution,
        )

        # ---- 5. Audit log entry ----------------------------------------
        entry = build_log_entry(
            event_type=event_type,
            file_path=src_path,
            source_path=src_path,
            destination_path=dest_path,
            classification=classification,
            integrity=integrity,
            attribution=attribution,
            alert_severity=decision.alert_severity,
            alert_category=decision.alert_category,
            alert_message=decision.alert_message,
            is_authorized=decision.is_authorized,
        )
        entry_id = self.audit_logger.log(entry)
        entry["id"] = entry_id

        # ---- 6. Optional callback (live UI) ----------------------------
        if self.on_event_cb:
            try:
                self.on_event_cb(entry)
            except Exception as exc:
                logger.warning("on_event_callback raised: %s", exc)

    # ------------------------------------------------------------------
    def on_created(self, event):
        if not event.is_directory:
            self._process_event("FILE_CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event("FILE_MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event("FILE_DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process_event("FILE_MOVED", event.src_path, event.dest_path)


# ---------------------------------------------------------------------------
# Monitor Orchestrator
# ---------------------------------------------------------------------------

class FileMonitor:
    """
    Top-level monitor that orchestrates all subsystems.

    Usage:
        monitor = FileMonitor()
        monitor.start()
        ...
        monitor.stop()
    """

    def __init__(
        self,
        config: Optional[Dict] = None,
        on_event_callback: Optional[Callable[[Dict], None]] = None,
    ) -> None:
        self.config = config or load_config()
        self.on_event_callback = on_event_callback
        self._observer: Optional[Observer] = None
        self._running = False

        mon_cfg = self.config.get("monitoring", {})
        log_cfg = self.config.get("logging", {})

        # Resolve watch paths relative to CWD
        raw_paths = mon_cfg.get("watch_paths", ["monitored_storage"])
        self.watch_paths: List[str] = [
            os.path.abspath(p) for p in raw_paths
        ]
        self.recursive: bool = mon_cfg.get("recursive", True)

        db_path = log_cfg.get("database", "logs/audit_vault.db")

        # Initialise subsystems
        self.alert_manager = get_alert_manager(console_alerts=True)
        self.classifier    = FileClassifier(config=self.config)
        self.baseline      = HashBaseline(db_path=db_path)
        self.verifier      = IntegrityVerifier(baseline=self.baseline)
        self.tracker       = ProcessTracker()
        self.policy        = PolicyEngine(
            alert_manager=self.alert_manager,
            config=self.config,
        )
        self.audit_logger  = AuditLogger(
            json_log=os.path.basename(log_cfg.get("json_log", "transfers.json")),
            csv_log=os.path.basename(log_cfg.get("csv_log", "audit.csv")),
            system_log=os.path.basename(log_cfg.get("system_log", "system.log")),
            db_path=os.path.basename(db_path),
        )

    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start the watchdog observer on all configured paths."""
        if self._running:
            logger.warning("Monitor is already running.")
            return

        # Ensure all watch paths exist
        for path in self.watch_paths:
            os.makedirs(path, exist_ok=True)

        handler = SecureFileEventHandler(
            classifier=self.classifier,
            verifier=self.verifier,
            tracker=self.tracker,
            policy=self.policy,
            audit_logger=self.audit_logger,
            on_event_callback=self.on_event_callback,
        )

        self._observer = Observer()
        for path in self.watch_paths:
            self._observer.schedule(handler, path=path, recursive=self.recursive)
            logger.info("👁  Watching: %s", path)

        self._observer.start()
        self._running = True

        from colorama import Fore, Style
        print(
            f"\n{Fore.GREEN}{'='*60}\n"
            f"  [SHIELD] SECURE FILE TRANSFER MONITOR - ACTIVE\n"
            f"  Watching {len(self.watch_paths)} path(s) recursively\n"
            f"{'='*60}{Style.RESET_ALL}\n"
        )
        logger.info("FileMonitor started -- %d watch path(s).", len(self.watch_paths))

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Stop the watchdog observer."""
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join()
            self._running = False
            logger.info("FileMonitor stopped.")
            print("\n[Monitor] Stopped.")

    # ------------------------------------------------------------------
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    def get_stats(self) -> Dict:
        return {
            "monitor_running":  self._running,
            "watch_paths":      self.watch_paths,
            "alert_stats":      self.alert_manager.get_stats(),
            "audit_stats":      self.audit_logger.get_stats(),
        }

    # ------------------------------------------------------------------
    def run_forever(self) -> None:
        """Start the monitor and block until keyboard interrupt."""
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Monitor] KeyboardInterrupt received. Shutting down…")
        finally:
            self.stop()
