"""
simulate_scenarios.py
======================
Attack & Insider Threat Simulation Engine.

Generates realistic file transfer scenarios to test all detection capabilities
of the Secure File Transfer Monitoring System.

Scenarios:
  1. Authorized Internal Transfer (baseline normal activity)
  2. Insider Threat Data Exfiltration (sensitive file -> USB/Cloud)
  3. In-Transit File Tampering (hash mismatch detection)
  4. Mass Exfiltration Burst Anomaly (ransomware staging / data harvesting)
  5. Unauthorized Critical File Deletion (destructive action)

Each scenario:
  - Creates realistic test files in monitored_storage directories
  - Executes the transfer action
  - Routes through the full DLP pipeline
  - Prints a colour-coded result with alert details
  - Returns a result dict for automated testing
"""

import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Ensure the project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# Core subsystems
from src.core.alert_manager import AlertManager
from src.core.classifier_engine import FileClassifier
from src.core.integrity_engine import IntegrityVerifier, HashBaseline, compute_hash
from src.core.logger_engine import AuditLogger, build_log_entry
from src.core.policy_engine import PolicyEngine
from src.core.process_tracker import ProcessTracker, SessionContext

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------

BASE_DIR          = PROJECT_ROOT / "monitored_storage"
SOURCE_ZONE       = BASE_DIR / "source_zone"
SENSITIVE_VAULT   = BASE_DIR / "sensitive_vault"
USB_DRIVE_SIM     = BASE_DIR / "usb_drive_sim"
CLOUD_SYNC_SIM    = BASE_DIR / "cloud_sync_sim"
QUARANTINE_ZONE   = BASE_DIR / "quarantine_zone"

ALL_DIRS = [SOURCE_ZONE, SENSITIVE_VAULT, USB_DRIVE_SIM, CLOUD_SYNC_SIM, QUARANTINE_ZONE]


def ensure_directories() -> None:
    for d in ALL_DIRS:
        d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _banner(title: str) -> None:
    width = 66
    print(f"\n{Fore.CYAN}{'-'*width}")
    print(f"  [>>] {title}")
    print(f"{'-'*width}{Style.RESET_ALL}")


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _result_line(label: str, value: str, ok: bool = True) -> None:
    icon  = "v" if ok else "x"
    color = Fore.GREEN if ok else Fore.RED
    print(f"  {color}{icon}{Style.RESET_ALL}  {label}: {value}")


def _print_decision(decision) -> None:
    """Pretty-print a PolicyDecision."""
    color = Fore.RED if not decision.is_authorized else Fore.GREEN
    status = "VIOLATION" if not decision.is_authorized else "AUTHORIZED"
    print(f"\n  {color}* OUTCOME: {status}{Style.RESET_ALL}")
    if decision.reasons:
        for reason in decision.reasons:
            print(f"    {Fore.YELLOW}{reason}{Style.RESET_ALL}")
    print(f"  Severity : {decision.alert_severity}")
    print(f"  Category : {decision.alert_category}")


# ---------------------------------------------------------------------------
# Simulator class
# ---------------------------------------------------------------------------

class AttackSimulator:
    """
    Runs all 5 attack and insider threat simulation scenarios.
    """

    def __init__(
        self,
        alert_manager: Optional[AlertManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        quiet: bool = False,
    ) -> None:
        ensure_directories()

        self.quiet   = quiet
        self.results: List[Dict] = []

        self.alert_manager = alert_manager or AlertManager(console_alerts=not quiet)
        self.classifier    = FileClassifier()
        self.baseline      = HashBaseline(db_path=str(PROJECT_ROOT / "logs" / "audit_vault.db"))
        self.verifier      = IntegrityVerifier(baseline=self.baseline)
        self.tracker       = ProcessTracker()
        self.policy        = PolicyEngine(alert_manager=self.alert_manager)
        self.audit_logger  = audit_logger or AuditLogger(
            log_dir=str(PROJECT_ROOT / "logs"),
        )
        self.session       = SessionContext()

    # ------------------------------------------------------------------
    def run_all(self) -> List[Dict]:
        """Execute all 5 scenarios in sequence. Returns results list."""
        scenarios = [
            self.scenario_1_authorized_transfer,
            self.scenario_2_usb_exfiltration,
            self.scenario_3_in_transit_tampering,
            self.scenario_4_mass_exfiltration_burst,
            self.scenario_5_critical_file_deletion,
        ]
        self.results = []
        for fn in scenarios:
            try:
                result = fn()
                self.results.append(result)
            except Exception as exc:
                self.results.append({"scenario": fn.__name__, "error": str(exc)})
            time.sleep(0.3)

        self._print_summary()
        return self.results

    # ------------------------------------------------------------------
    def scenario_1_authorized_transfer(self) -> Dict:
        """
        SCENARIO 1 - Authorized Internal Transfer
        Normal internal document transferred from source_zone -> quarantine_zone
        with full integrity verification. Should pass ALL checks.
        """
        name = "Scenario 1 - Authorized Internal Transfer"
        _banner(name)

        src  = SOURCE_ZONE / "internal_memo_Q3.txt"
        dest = QUARANTINE_ZONE / "internal_memo_Q3.txt"
        _write_file(src, "INTERNAL USE ONLY\n\nQ3 Project Roadmap\n\nAll timelines are on track.\n")

        # Record pre-transfer hash
        self.verifier.snapshot_pre(str(src))

        # Simulate transfer (copy)
        shutil.copy2(str(src), str(dest))

        # Record post-transfer hash (on destination)
        self.verifier.snapshot_post(str(dest))
        integrity = self.verifier.verify(str(dest), pre_file_path=str(src))

        classification = self.classifier.classify(str(src))
        attribution    = self.tracker.attribute_event(str(src))
        decision       = self.policy.evaluate(
            event_type="FILE_MOVED",
            file_path=str(src),
            destination_path=str(dest),
            classification=classification,
            integrity=integrity,
            attribution=attribution,
        )

        entry = build_log_entry(
            event_type="FILE_MOVED",
            file_path=str(src),
            destination_path=str(dest),
            classification=classification,
            integrity=integrity,
            attribution=attribution,
            alert_severity=decision.alert_severity,
            alert_category=decision.alert_category,
            alert_message=decision.alert_message,
            is_authorized=decision.is_authorized,
        )
        self.audit_logger.log(entry)

        _result_line("File", src.name)
        _result_line("Source", str(SOURCE_ZONE))
        _result_line("Destination", str(QUARANTINE_ZONE))
        _result_line("Classification", classification["tier"])
        _result_line("Integrity", "v VERIFIED" if integrity.get("integrity_ok") else "x MISMATCH",
                     ok=integrity.get("integrity_ok", False))
        _result_line("SHA-256 (Pre)", integrity.get("algorithm_results", {}).get("sha256", {}).get("pre", "N/A")[:32] + "...")
        _print_decision(decision)

        return {
            "scenario": name,
            "authorized": decision.is_authorized,
            "integrity_ok": integrity.get("integrity_ok"),
            "severity": decision.alert_severity,
        }

    # ------------------------------------------------------------------
    def scenario_2_usb_exfiltration(self) -> Dict:
        """
        SCENARIO 2 - Insider Threat: Data Exfiltration to USB Drive
        Employee copies confidential financial records to simulated USB drive.
        Should trigger CRITICAL DLP_VIOLATION alert.
        """
        name = "Scenario 2 - Insider Threat: USB Exfiltration"
        _banner(name)

        src  = SENSITIVE_VAULT / "financial_records_2024.xlsx"
        dest = USB_DRIVE_SIM  / "financial_records_2024.xlsx"
        _write_file(src,
            "CONFIDENTIAL - RESTRICTED\n\n"
            "Account Number: 1234-5678-9012\n"
            "Routing Number: 021000021\n"
            "Q4 Revenue: $14,200,000\n"
            "Payroll Data: [REDACTED]\n"
        )

        self.verifier.snapshot_pre(str(src))
        shutil.copy2(str(src), str(dest))
        self.verifier.snapshot_post(str(dest))
        integrity = self.verifier.verify(str(dest), pre_file_path=str(src))

        classification = self.classifier.classify(str(src))
        attribution    = self.tracker.attribute_event(str(src))
        attribution["process_name"] = "explorer.exe"

        decision = self.policy.evaluate(
            event_type="FILE_COPIED",
            file_path=str(src),
            destination_path=str(dest),
            classification=classification,
            integrity=integrity,
            attribution=attribution,
        )

        entry = build_log_entry(
            event_type="FILE_COPIED",
            file_path=str(src),
            destination_path=str(dest),
            classification=classification,
            integrity=integrity,
            attribution=attribution,
            alert_severity=decision.alert_severity,
            alert_category=decision.alert_category,
            alert_message=decision.alert_message,
            is_authorized=decision.is_authorized,
        )
        self.audit_logger.log(entry)

        _result_line("File", src.name)
        _result_line("Sensitivity", classification["tier"], ok=False)
        _result_line("USB Destination", str(USB_DRIVE_SIM))
        _result_line("Process Actor", attribution.get("process_name", "Unknown"))
        _print_decision(decision)

        return {
            "scenario": name,
            "authorized": decision.is_authorized,
            "severity": decision.alert_severity,
            "expected_violation": True,
            "detected": not decision.is_authorized,
        }

    # ------------------------------------------------------------------
    def scenario_3_in_transit_tampering(self) -> Dict:
        """
        SCENARIO 3 - In-Transit File Tampering (Hash Mismatch)
        File is modified after hash is recorded, simulating malware injection
        or man-in-the-middle file tampering during transfer.
        Should trigger CRITICAL INTEGRITY_VIOLATION alert.
        """
        name = "Scenario 3 - In-Transit File Tampering"
        _banner(name)

        src  = SENSITIVE_VAULT / "deployment_config.env"
        dest = SOURCE_ZONE     / "deployment_config.env"
        original_content = (
            "# Deployment Config\n"
            "API_KEY=prod_abc123xyz\n"
            "SECRET_KEY=s3cr3t_p@ss\n"
            "DATABASE_URL=postgresql://admin:pass@db.internal/prod\n"
        )
        _write_file(src, original_content)

        # Record pre-transfer baseline (ORIGINAL content)
        pre_hash = self.verifier.snapshot_pre(str(src))

        # Simulate transfer
        shutil.copy2(str(src), str(dest))

        # ⚠ SIMULATE TAMPERING: inject malicious content AFTER copy
        dest.write_text(
            original_content + "\n# INJECTED BY ATTACKER\nDROP TABLE users;\n",
            encoding="utf-8",
        )

        # Record post-transfer hash (TAMPERED destination)
        self.verifier.snapshot_post(str(dest))
        integrity = self.verifier.verify(str(dest), pre_file_path=str(src))

        classification = self.classifier.classify(str(src))
        attribution    = self.tracker.attribute_event(str(src))
        decision       = self.policy.evaluate(
            event_type="FILE_MOVED",
            file_path=str(src),
            destination_path=str(dest),
            classification=classification,
            integrity=integrity,
            attribution=attribution,
        )

        entry = build_log_entry(
            event_type="FILE_MOVED",
            file_path=str(src),
            destination_path=str(dest),
            classification=classification,
            integrity=integrity,
            attribution=attribution,
            alert_severity=decision.alert_severity,
            alert_category=decision.alert_category,
            alert_message=decision.alert_message,
            is_authorized=decision.is_authorized,
        )
        self.audit_logger.log(entry)

        sha256_results = integrity.get("algorithm_results", {}).get("sha256", {})
        tampered       = integrity.get("tampered", False)
        _result_line("File", src.name)
        _result_line("Pre-Transfer SHA-256",  (sha256_results.get("pre") or "N/A")[:40] + "...")
        _result_line("Post-Transfer SHA-256", (sha256_results.get("post") or "N/A")[:40] + "...")
        _result_line("Hashes Match", str(sha256_results.get("match")), ok=not tampered)
        _result_line("TAMPERED", str(tampered), ok=not tampered)
        _print_decision(decision)

        return {
            "scenario": name,
            "authorized": decision.is_authorized,
            "tampered_detected": tampered,
            "severity": decision.alert_severity,
            "expected_violation": True,
            "detected": tampered,
        }

    # ------------------------------------------------------------------
    def scenario_4_mass_exfiltration_burst(self) -> Dict:
        """
        SCENARIO 4 - Mass Exfiltration Burst (Ransomware Staging / Data Harvesting)
        Rapidly copies 15 files in under 10 seconds, exceeding the burst threshold.
        Should trigger CRITICAL BURST_EXFILTRATION alert.
        """
        name = "Scenario 4 - Mass Exfiltration Burst Anomaly"
        _banner(name)

        file_count = 15
        src_files  = []
        print(f"  Generating {file_count} files and executing rapid transfer...")

        triggered_violation = False
        final_decision = None

        for i in range(1, file_count + 1):
            fname = f"customer_record_{i:03d}.csv"
            src   = SOURCE_ZONE / fname
            dest  = USB_DRIVE_SIM / fname
            _write_file(src, f"SSN,Name,Email\n55{i:04d}-XX-XXXX,Customer{i},c{i}@corp.com\n")
            shutil.copy2(str(src), str(dest))

            classification = self.classifier.classify(str(src))
            attribution    = self.tracker.attribute_event(str(src))
            decision       = self.policy.evaluate(
                event_type="FILE_COPIED",
                file_path=str(src),
                destination_path=str(dest),
                classification=classification,
                attribution=attribution,
            )

            entry = build_log_entry(
                event_type="FILE_COPIED",
                file_path=str(src),
                destination_path=str(dest),
                classification=classification,
                attribution=attribution,
                alert_severity=decision.alert_severity,
                alert_category=decision.alert_category,
                alert_message=decision.alert_message,
                is_authorized=decision.is_authorized,
            )
            self.audit_logger.log(entry)
            src_files.append(fname)
            final_decision = decision
            if not decision.is_authorized:
                triggered_violation = True

        print(f"\n  Files transferred: {file_count}")
        _result_line("Burst Detected", str(triggered_violation), ok=False)
        if final_decision:
            _print_decision(final_decision)

        return {
            "scenario": name,
            "files_transferred": file_count,
            "burst_detected": triggered_violation,
            "severity": (final_decision.alert_severity if final_decision else "INFO"),
            "expected_violation": True,
            "detected": triggered_violation,
        }

    # ------------------------------------------------------------------
    def scenario_5_critical_file_deletion(self) -> Dict:
        """
        SCENARIO 5 - Unauthorized Critical File Deletion
        Deletion of a highly sensitive cryptographic key file.
        Should trigger HIGH/CRITICAL DESTRUCTIVE_ACTION alert.
        """
        name = "Scenario 5 - Unauthorized Critical File Deletion"
        _banner(name)

        target = SENSITIVE_VAULT / "server_private.key"
        _write_file(target,
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAkNg...\n"
            "-----END RSA PRIVATE KEY-----\n"
        )

        classification = self.classifier.classify(str(target))
        attribution    = self.tracker.attribute_event(str(target))
        attribution["process_name"] = "cmd.exe"  # suspicious actor

        decision = self.policy.evaluate(
            event_type="FILE_DELETED",
            file_path=str(target),
            classification=classification,
            attribution=attribution,
        )

        # Perform the actual deletion
        if target.exists():
            target.unlink()

        entry = build_log_entry(
            event_type="FILE_DELETED",
            file_path=str(target),
            classification=classification,
            attribution=attribution,
            alert_severity=decision.alert_severity,
            alert_category=decision.alert_category,
            alert_message=decision.alert_message,
            is_authorized=decision.is_authorized,
        )
        self.audit_logger.log(entry)

        _result_line("File", target.name)
        _result_line("Classification", classification["tier"], ok=False)
        _result_line("Actor Process", attribution.get("process_name", "Unknown"), ok=False)
        _result_line("File Deleted", str(not target.exists()), ok=False)
        _print_decision(decision)

        return {
            "scenario": name,
            "authorized": decision.is_authorized,
            "severity": decision.alert_severity,
            "expected_violation": True,
            "detected": not decision.is_authorized,
        }

    # ------------------------------------------------------------------
    def _print_summary(self) -> None:
        """Print a summary table of all scenario results."""
        print(f"\n{Fore.CYAN}{'='*66}")
        print("  [*] SIMULATION SUMMARY")
        print(f"{'='*66}{Style.RESET_ALL}")
        print(f"  {'#':<3} {'Scenario':<42} {'Detected':<10} {'Severity'}")
        print(f"  {'-'*62}")
        for i, r in enumerate(self.results, 1):
            name     = r.get("scenario", "Unknown")[:40]
            detected = r.get("detected", r.get("authorized") is False)
            severity = r.get("severity", "INFO")
            d_str    = f"{Fore.GREEN}v YES{Style.RESET_ALL}" if detected else f"{Fore.RED}x NO{Style.RESET_ALL}"
            sev_color = Fore.RED if severity in ("CRITICAL", "HIGH") else Fore.YELLOW
            print(f"  {i:<3} {name:<42} {d_str:<20} {sev_color}{severity}{Style.RESET_ALL}")
        print(f"\n  {Fore.CYAN}Logs saved to: logs/{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Dashboard:     http://127.0.0.1:5000{Style.RESET_ALL}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_simulation(quiet: bool = False) -> List[Dict]:
    """Run all simulation scenarios and return results."""
    sim = AttackSimulator(quiet=quiet)
    return sim.run_all()


if __name__ == "__main__":
    run_simulation()
