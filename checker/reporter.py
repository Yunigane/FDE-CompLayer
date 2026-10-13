"""
Compliance Audit Reporter.
Renders formatted terminal summary tables and emits structured JSON reports.
Enforces consistent verdict semantics across terminal and CI JSON modes:
- Exit 0: All P0 checks PASS (SAFE TO SHIP)
- Exit 1: Any P0 check FAIL (DEPLOYMENT BLOCKED)
- Exit 2: No FAIL, but a P0 check was SKIPPED (INCOMPLETE: NOT SAFE TO SHIP)
- (--strict flag upgrades any P1 WARN to exit 1)
"""
import json
import sys
import os
from typing import List, Dict, Any, Tuple

from checker.models import Target, CheckResult, Severity, Status

# ANSI Color Codes (honors NO_COLOR environment variable)
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")

GREEN = "\033[92m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
BLUE = "\033[94m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""


def compute_verdict(results: List[CheckResult], strict: bool = False) -> Tuple[int, str]:
    """
    Computes exit code and human-readable verdict.
    Shared identically between terminal and JSON reporters.
    """
    has_p0_fail = any(r.severity == Severity.P0 and r.status == Status.FAIL for r in results)
    has_p0_skipped = any(r.severity == Severity.P0 and r.status == Status.SKIPPED for r in results)
    has_warn = any(r.status == Status.WARN for r in results)

    if has_p0_fail:
        return 1, "DEPLOYMENT BLOCKED (P0 Violations Detected)"
    if strict and has_warn:
        return 1, "DEPLOYMENT BLOCKED (Strict Mode: Warnings Detected)"
    if has_p0_skipped:
        return 2, "INCOMPLETE: NOT SAFE TO SHIP (P0 Checks Skipped)"
    return 0, "SAFE TO SHIP"


class ComplianceReporter:
    def __init__(self, target: Target, results: List[CheckResult], strict: bool = False):
        self.target = target
        self.results = results
        self.strict = strict

    def render_terminal(self) -> int:
        """
        Prints formatted terminal report table and returns exit code.
        """
        exit_code, verdict = compute_verdict(self.results, self.strict)

        print(f"\n{BOLD}{CYAN}=================================================================================={RESET}")
        print(f"{BOLD}{CYAN}                 AI COMPLIANCE LAYER: AUTOMATED AUDIT REPORT                      {RESET}")
        print(f"{BOLD}{CYAN}=================================================================================={RESET}\n")

        print(f"{BOLD}Target URL:{RESET}       {self.target.url}")
        print(f"{BOLD}Discovered Route:{RESET} {self.target.endpoint or 'None discovered'}")
        print(f"{BOLD}Auth Scheme:{RESET}      {self.target.auth_type.upper()}")
        print(f"{BOLD}Service Name:{RESET}     {self.target.service_name or 'N/A'}")
        if self.target.payload_field:
            print(f"{BOLD}Payload Field:{RESET}    {self.target.payload_field}")
        print()

        # Table formatting
        col_pillar = 38
        col_sev = 10
        col_status = 12
        col_details = 40

        header = f"{'PILLAR / COMPLIANCE GATE':<{col_pillar}} {'SEVERITY':<{col_sev}} {'STATUS':<{col_status}} {'DETAILS'}"
        print(f"{BOLD}{header}{RESET}")
        print("-" * 82)

        counts = {Status.PASS: 0, Status.FAIL: 0, Status.WARN: 0, Status.SKIPPED: 0}

        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1

            if r.status == Status.PASS:
                status_str = f"{GREEN}{BOLD}PASS{RESET}"
            elif r.status == Status.FAIL:
                status_str = f"{RED}{BOLD}FAIL{RESET}"
            elif r.status == Status.WARN:
                status_str = f"{YELLOW}{BOLD}WARN{RESET}"
            else:
                status_str = f"{BLUE}{BOLD}SKIPPED{RESET}"

            # Pad raw status (without ANSI) to maintain table alignment
            pad = " " * (col_status - len(r.status.value))
            short_msg = r.message[:col_details] + ("..." if len(r.message) > col_details else "")
            print(f"{r.title:<{col_pillar}} {r.severity.value:<{col_sev}} {status_str}{pad} {short_msg}")

            if r.status == Status.FAIL and r.evidence:
                first_evidence = r.evidence.splitlines()[0][:75]
                print(f"  {RED}↳ Evidence: {first_evidence}{RESET}")
            if r.status in (Status.FAIL, Status.SKIPPED) and r.hint:
                print(f"  {CYAN}↳ Hint: {r.hint.splitlines()[0]}{RESET}")

        print("-" * 82)
        summary_line = (
            f"{BOLD}Summary:{RESET} "
            f"{GREEN}{counts[Status.PASS]} Passed{RESET} | "
            f"{RED}{counts[Status.FAIL]} Failed{RESET} | "
            f"{YELLOW}{counts[Status.WARN]} Warnings{RESET} | "
            f"{BLUE}{counts[Status.SKIPPED]} Skipped{RESET}\n"
        )
        print(summary_line)

        if exit_code == 0:
            print(f"{GREEN}{BOLD}>>> COMPLIANCE STATUS: {verdict} (Exit Code 0) <<<{RESET}\n")
        elif exit_code == 2:
            print(f"{BLUE}{BOLD}>>> COMPLIANCE STATUS: {verdict} (Exit Code 2) <<<{RESET}\n")
        else:
            print(f"{RED}{BOLD}>>> COMPLIANCE STATUS: {verdict} (Exit Code 1) <<<{RESET}\n")

        if self.strict and counts[Status.WARN] > 0 and exit_code == 1:
            print(f"{YELLOW}[STRICT MODE ENFORCED]: Build failed due to active warnings.{RESET}\n", file=sys.stderr)

        return exit_code

    def render_json(self) -> int:
        """Emits pure JSON output to stdout for CI/CD pipelines."""
        exit_code, verdict = compute_verdict(self.results, self.strict)
        payload = {
            "target": {
                "url": self.target.url,
                "endpoint": self.target.endpoint,
                "auth_type": self.target.auth_type,
                "service_name": self.target.service_name,
            },
            "verdict": verdict,
            "exit_code": exit_code,
            "summary": {
                "passed": sum(1 for r in self.results if r.status == Status.PASS),
                "failed": sum(1 for r in self.results if r.status == Status.FAIL),
                "warn": sum(1 for r in self.results if r.status == Status.WARN),
                "skipped": sum(1 for r in self.results if r.status == Status.SKIPPED),
            },
            "checks": [r.to_dict() for r in self.results],
        }
        print(json.dumps(payload, indent=2))

        if self.strict and any(r.status == Status.WARN for r in self.results):
            print("[STRICT MODE ENFORCED]: Warnings treated as errors.", file=sys.stderr)

        return exit_code
