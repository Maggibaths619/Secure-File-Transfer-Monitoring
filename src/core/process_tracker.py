"""
process_tracker.py
===================
Windows / cross-platform process and user attribution tracker.

Associates file system events with:
  - The current logged-in username
  - Active process list (PID, name, executable path, command line)
  - Hostname and session metadata

Uses psutil (cross-platform) and optionally pywin32 on Windows for
richer process ownership details.
"""

import os
import platform
import socket
import logging
from datetime import datetime
from typing import Dict, List, Optional

import psutil

logger = logging.getLogger("sftms.process_tracker")

# Detect platform
IS_WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_current_user() -> str:
    """Return the name of the currently logged-in OS user."""
    try:
        return os.getlogin()
    except OSError:
        try:
            import getpass
            return getpass.getuser()
        except Exception:
            return "UNKNOWN_USER"


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "UNKNOWN_HOST"


# ---------------------------------------------------------------------------
# Process Snapshot
# ---------------------------------------------------------------------------

def get_process_snapshot() -> List[Dict]:
    """
    Return a lightweight snapshot of all currently running processes.

    Each entry contains:
        pid, name, exe, cmdline, username, status, create_time
    """
    snapshot: List[Dict] = []
    for proc in psutil.process_iter(
        attrs=["pid", "name", "exe", "cmdline", "username", "status", "create_time"]
    ):
        try:
            info = proc.info
            snapshot.append(
                {
                    "pid":         info.get("pid"),
                    "name":        info.get("name", ""),
                    "exe":         info.get("exe") or "",
                    "cmdline":     " ".join(info.get("cmdline") or [])[:256],
                    "username":    info.get("username") or "",
                    "status":      info.get("status", ""),
                    "create_time": datetime.fromtimestamp(
                        info.get("create_time", 0)
                    ).isoformat(),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return snapshot


def find_process_by_name(name: str) -> List[Dict]:
    """
    Find running processes whose name contains the given string (case-insensitive).

    Returns list of matching process dicts.
    """
    name_lower = name.lower()
    return [
        p for p in get_process_snapshot()
        if name_lower in (p.get("name") or "").lower()
    ]


def get_processes_with_open_file(file_path: str) -> List[Dict]:
    """
    Find processes that currently have the specified file open.

    Note: Requires elevated privileges on some systems.
    Returns list of { pid, name, username }.
    """
    result: List[Dict] = []
    target = os.path.normcase(os.path.abspath(file_path))

    for proc in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            for open_file in proc.open_files():
                if os.path.normcase(open_file.path) == target:
                    result.append(
                        {
                            "pid":      proc.info["pid"],
                            "name":     proc.info["name"],
                            "username": proc.info.get("username", ""),
                        }
                    )
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return result


# ---------------------------------------------------------------------------
# Session Context
# ---------------------------------------------------------------------------

class SessionContext:
    """
    Captures and caches static session metadata (user, host, platform)
    to attach to every audit log entry without repeated OS calls.
    """

    _instance: Optional["SessionContext"] = None

    def __new__(cls) -> "SessionContext":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self.username  = _get_current_user()
        self.hostname  = _get_hostname()
        self.os_name   = platform.system()
        self.os_version = platform.version()
        self.python_version = platform.python_version()
        self.started_at = datetime.now().isoformat()
        logger.info(
            "Session: user=%s host=%s os=%s %s",
            self.username, self.hostname, self.os_name, self.os_version,
        )

    def to_dict(self) -> Dict:
        return {
            "username":       self.username,
            "hostname":       self.hostname,
            "os_name":        self.os_name,
            "os_version":     self.os_version,
            "python_version": self.python_version,
            "started_at":     self.started_at,
        }


# ---------------------------------------------------------------------------
# Event Attribution
# ---------------------------------------------------------------------------

class ProcessTracker:
    """
    Attach process/user context to file system events.

    For each file event the tracker:
      1. Provides current user & host from the cached SessionContext.
      2. Optionally attempts to identify which process modified the file
         (heuristic – finds processes with the file open at event time).
      3. Returns an attribution dict ready to be merged into log entries.
    """

    def __init__(self) -> None:
        self.session = SessionContext()
        # Cache of recently seen suspicious processes for quick re-lookup
        self._suspicious_cache: Dict[str, List[Dict]] = {}

    # ------------------------------------------------------------------
    def attribute_event(self, file_path: str, try_open_file_lookup: bool = False) -> Dict:
        """
        Build an attribution dict for a file system event.

        Args:
            file_path:               Path involved in the event.
            try_open_file_lookup:    If True, attempt to find which process
                                     has the file open (may be slow/requires
                                     privileges).

        Returns:
            {
              "username":     str,
              "hostname":     str,
              "process_name": str | None,
              "pid":          int | None,
              "process_exe":  str | None,
            }
        """
        attribution: Dict = {
            "username":     self.session.username,
            "hostname":     self.session.hostname,
            "process_name": None,
            "pid":          None,
            "process_exe":  None,
        }

        if try_open_file_lookup:
            try:
                procs = get_processes_with_open_file(file_path)
                if procs:
                    p = procs[0]
                    attribution["pid"]          = p.get("pid")
                    attribution["process_name"] = p.get("name")
            except Exception as exc:
                logger.debug("Open-file lookup failed for %s: %s", file_path, exc)

        return attribution

    # ------------------------------------------------------------------
    def is_suspicious_process(self, process_name: str) -> bool:
        """
        Heuristic: flag known high-risk process names.

        In a production environment this would query a threat-intelligence
        feed or a curated allowlist/blocklist.
        """
        suspicious = {
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
            "bitsadmin.exe", "robocopy.exe", "xcopy.exe", "7z.exe",
            "winrar.exe", "rclone.exe", "winscp.exe", "pscp.exe",
            "nc.exe", "ncat.exe", "netcat.exe", "curl.exe", "wget.exe",
        }
        return process_name.lower() in suspicious

    # ------------------------------------------------------------------
    def get_active_transfer_agents(self) -> List[Dict]:
        """
        Identify currently running processes that are known to perform
        bulk file transfers (backup tools, sync clients, FTP clients, etc.).
        """
        transfer_agents = [
            "robocopy", "xcopy", "rsync", "rclone", "winscp", "filezilla",
            "dropbox", "onedrive", "googledrivefs", "backblaze",
            "cobian", "teracopy", "fastcopy",
        ]
        active: List[Dict] = []
        snapshot = get_process_snapshot()
        for proc in snapshot:
            name_lower = (proc.get("name") or "").lower()
            for agent in transfer_agents:
                if agent in name_lower:
                    active.append(proc)
                    break
        return active
