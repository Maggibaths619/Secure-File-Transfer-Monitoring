"""
main.py - Interactive CLI for the Secure File Transfer Monitoring System
=========================================================================
Provides a full-featured terminal interface for:
  • Starting / stopping the live file system monitor
  • Running the attack / insider threat simulator
  • Computing and verifying file hashes on demand
  • Exporting audit reports (JSON / CSV)
  • Launching the SOC Web Dashboard
  • Viewing live alert feed and system statistics
"""

import os
import sys
import threading
import time
from pathlib import Path

# Ensure project root is on Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

from src.core.file_monitor import FileMonitor, load_config
from src.core.integrity_engine import compute_all_hashes, compute_hash
from src.core.alert_manager import get_alert_manager


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = f"""
{Fore.CYAN}
  ███████╗███████╗████████╗███╗   ███╗███████╗
  ██╔════╝██╔════╝╚══██╔══╝████╗ ████║██╔════╝
  ███████╗█████╗     ██║   ██╔████╔██║███████╗
  ╚════██║██╔══╝     ██║   ██║╚██╔╝██║╚════██║
  ███████║██║        ██║   ██║ ╚═╝ ██║███████║
  ╚══════╝╚═╝        ╚═╝   ╚═╝     ╚═╝╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  Secure File Transfer Monitoring System{Style.RESET_ALL}
{Fore.YELLOW}  Blue Team DLP & Integrity Verification Toolkit{Style.RESET_ALL}
{Fore.MAGENTA}  ─────────────────────────────────────────────{Style.RESET_ALL}
"""


def print_banner() -> None:
    print(BANNER)


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

MENU = f"""
{Fore.CYAN}  ┌─────────────────────────────────────────────────┐
  │               MAIN MENU                         │
  ├─────────────────────────────────────────────────┤
  │  {Fore.GREEN}1{Fore.CYAN}  Start Live File System Monitor               │
  │  {Fore.GREEN}2{Fore.CYAN}  Run Attack / Threat Simulation Scenarios     │
  │  {Fore.GREEN}3{Fore.CYAN}  Compute File Hash (Integrity Check)          │
  │  {Fore.GREEN}4{Fore.CYAN}  View Recent Audit Events                     │
  │  {Fore.GREEN}5{Fore.CYAN}  Export Audit Report                          │
  │  {Fore.GREEN}6{Fore.CYAN}  Launch SOC Web Dashboard                     │
  │  {Fore.GREEN}7{Fore.CYAN}  View System Statistics                       │
  │  {Fore.GREEN}8{Fore.CYAN}  View Live Alert Feed                         │
  │  {Fore.RED}0{Fore.CYAN}  Exit                                          │
  └─────────────────────────────────────────────────┘{Style.RESET_ALL}
"""


def print_menu() -> None:
    print(MENU)


# ---------------------------------------------------------------------------
# CLI actions
# ---------------------------------------------------------------------------

def action_start_monitor(monitor: FileMonitor) -> None:
    """Start the live file monitor in a background thread."""
    if monitor.is_running():
        print(f"{Fore.YELLOW}Monitor is already running.{Style.RESET_ALL}")
        return

    t = threading.Thread(target=monitor.start, daemon=True)
    t.start()
    time.sleep(0.5)
    print(f"\n{Fore.GREEN}[OK] Monitor started.{Style.RESET_ALL}")
    print(f"  Watching {len(monitor.watch_paths)} path(s).")
    print(f"  Press {Fore.YELLOW}Ctrl+C{Style.RESET_ALL} or choose option {Fore.RED}0{Style.RESET_ALL} to stop.")


def action_run_simulation() -> None:
    """Run all attack simulation scenarios."""
    print(f"\n{Fore.CYAN}Starting simulation engine…{Style.RESET_ALL}\n")
    try:
        from src.simulator.simulate_scenarios import run_simulation
        run_simulation()
    except Exception as exc:
        print(f"{Fore.RED}Simulation error: {exc}{Style.RESET_ALL}")


def action_compute_hash() -> None:
    """Interactively compute hashes for a file."""
    print(f"\n{Fore.CYAN}── File Hash Verification ──{Style.RESET_ALL}")
    path = input("  Enter full file path: ").strip().strip('"')
    if not os.path.isfile(path):
        print(f"{Fore.RED}File not found: {path}{Style.RESET_ALL}")
        return
    print(f"\n  Computing hashes for: {Fore.YELLOW}{path}{Style.RESET_ALL}")
    hashes = compute_all_hashes(path)
    for algo, digest in hashes.items():
        label = algo.upper().replace("_", "-")
        print(f"  {Fore.GREEN}{label:<12}{Style.RESET_ALL}  {digest or 'ERROR'}")

    # Optional comparison
    compare = input("\n  Compare against known hash? (y/n): ").strip().lower()
    if compare == "y":
        known = input("  Enter expected hash: ").strip()
        algo_name = input("  Algorithm (sha256/md5/sha3_256) [sha256]: ").strip() or "sha256"
        actual = hashes.get(algo_name.lower())
        if actual and actual.lower() == known.lower():
            print(f"\n  {Fore.GREEN}[OK] INTEGRITY VERIFIED - hashes match!{Style.RESET_ALL}")
        else:
            print(f"\n  {Fore.RED}✘ INTEGRITY FAILURE - hash mismatch!{Style.RESET_ALL}")
            print(f"  Expected: {known}")
            print(f"  Actual:   {actual}")


def action_view_audit_events(monitor: FileMonitor) -> None:
    """Display recent audit events from the database."""
    print(f"\n{Fore.CYAN}── Recent Audit Events ──{Style.RESET_ALL}")
    try:
        events = monitor.audit_logger.get_recent_events(limit=20)
        if not events:
            print(f"  {Fore.YELLOW}No events recorded yet.{Style.RESET_ALL}")
            return

        print(f"\n  {'#':<4} {'Timestamp':<22} {'Event':<16} {'Severity':<10} {'File'}")
        print(f"  {'─'*90}")
        for ev in events:
            sev   = ev.get("alert_severity", "INFO")
            color = Fore.RED if sev in ("CRITICAL", "HIGH") else (Fore.YELLOW if sev == "MEDIUM" else Fore.GREEN)
            fname = Path(ev.get("file_path", "")).name[:35]
            ts    = (ev.get("timestamp") or "")[:19]
            print(
                f"  {ev.get('id', ''):<4} {ts:<22} {ev.get('event_type',''):<16} "
                f"{color}{sev:<10}{Style.RESET_ALL} {fname}"
            )
    except Exception as exc:
        print(f"{Fore.RED}Error reading audit log: {exc}{Style.RESET_ALL}")


def action_export_report(monitor: FileMonitor) -> None:
    """Export the full audit report to JSON or CSV."""
    print(f"\n{Fore.CYAN}── Export Audit Report ──{Style.RESET_ALL}")
    fmt = input("  Format (json/csv) [json]: ").strip().lower() or "json"
    out = input(f"  Output path (without extension) [logs/audit_report]: ").strip() or "logs/audit_report"
    try:
        out_path = monitor.audit_logger.export_report(out, fmt=fmt)
        print(f"\n  {Fore.GREEN}[OK] Report exported -> {out_path}{Style.RESET_ALL}")
    except Exception as exc:
        print(f"{Fore.RED}Export error: {exc}{Style.RESET_ALL}")


def action_launch_dashboard() -> None:
    """Launch the Flask SOC web dashboard."""
    print(f"\n{Fore.CYAN}Launching SOC Web Dashboard…{Style.RESET_ALL}")
    try:
        import subprocess
        subprocess.Popen(
            [sys.executable, "-m", "src.web.app"],
            cwd=str(PROJECT_ROOT),
        )
        time.sleep(2)
        import webbrowser
        webbrowser.open("http://127.0.0.1:5000")
        print(f"  {Fore.GREEN}[OK] Dashboard opened at http://127.0.0.1:5000{Style.RESET_ALL}")
    except Exception as exc:
        print(f"  {Fore.RED}Could not launch dashboard: {exc}{Style.RESET_ALL}")
        print(f"  Run manually: {Fore.YELLOW}python -m src.web.app{Style.RESET_ALL}")


def action_show_stats(monitor: FileMonitor) -> None:
    """Display system-wide statistics."""
    print(f"\n{Fore.CYAN}── System Statistics ──{Style.RESET_ALL}")
    stats = monitor.get_stats()
    alert_stats = stats.get("alert_stats", {})
    audit_stats = stats.get("audit_stats", {})

    print(f"\n  Monitor Status : {'🟢 RUNNING' if stats.get('monitor_running') else '🔴 STOPPED'}")
    print(f"  Watch Paths    : {len(stats.get('watch_paths', []))}")
    print(f"\n  {Fore.YELLOW}Alert Statistics:{Style.RESET_ALL}")
    for k, v in alert_stats.items():
        print(f"    {k:<12} {v}")
    print(f"\n  {Fore.YELLOW}Audit Database:{Style.RESET_ALL}")
    print(f"    Total Events   : {audit_stats.get('total_events', 0)}")
    print(f"    Tampered Files : {audit_stats.get('tampered_files', 0)}")
    print(f"    Policy Violat. : {audit_stats.get('policy_violations', 0)}")
    bysev = audit_stats.get("by_severity", {})
    if bysev:
        print(f"\n  {Fore.YELLOW}Events by Severity:{Style.RESET_ALL}")
        for sev, count in bysev.items():
            c = Fore.RED if sev in ("CRITICAL", "HIGH") else Fore.YELLOW
            print(f"    {c}{sev:<12}{Style.RESET_ALL} {count}")


def action_live_alert_feed(monitor: FileMonitor) -> None:
    """Display incoming alerts in real-time until Ctrl+C."""
    print(f"\n{Fore.CYAN}── Live Alert Feed (press Ctrl+C to stop) ──{Style.RESET_ALL}\n")
    alert_manager = monitor.alert_manager
    seen_ids = set()
    try:
        while True:
            history = alert_manager.get_history(limit=200)
            for alert in history:
                aid = alert.get("id")
                if aid not in seen_ids:
                    seen_ids.add(aid)
                    sev   = alert.get("severity", "INFO")
                    color = Fore.RED if sev in ("CRITICAL", "HIGH") else Fore.YELLOW if sev == "MEDIUM" else Fore.CYAN
                    print(
                        f"  {color}[{sev:<8}]{Style.RESET_ALL} "
                        f"{alert.get('timestamp','')[:19]}  "
                        f"{alert.get('category','')} | "
                        f"{alert.get('message','')[:60]}"
                    )
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Alert feed stopped.{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    os.chdir(PROJECT_ROOT)
    print_banner()

    config  = load_config()
    monitor = FileMonitor(config=config)

    while True:
        print_menu()
        choice = input(f"{Fore.WHITE}  Select option: {Style.RESET_ALL}").strip()

        if choice == "1":
            action_start_monitor(monitor)
        elif choice == "2":
            action_run_simulation()
        elif choice == "3":
            action_compute_hash()
        elif choice == "4":
            action_view_audit_events(monitor)
        elif choice == "5":
            action_export_report(monitor)
        elif choice == "6":
            action_launch_dashboard()
        elif choice == "7":
            action_show_stats(monitor)
        elif choice == "8":
            action_live_alert_feed(monitor)
        elif choice == "0":
            print(f"\n{Fore.YELLOW}Shutting down…{Style.RESET_ALL}")
            monitor.stop()
            sys.exit(0)
        else:
            print(f"{Fore.RED}  Invalid option. Please try again.{Style.RESET_ALL}")

        input(f"\n  {Fore.CYAN}[Press ENTER to continue]{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
