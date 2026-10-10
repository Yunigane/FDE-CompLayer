"""
Compliance Audit Reporter.
Renders formatted ANSI color terminal summary tables and emits structured JSON reports.
"""
import json
import sys
from typing import Dict, Any, List

# ANSI Color Codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class ComplianceReporter:
    def __init__(self, target_info: Dict[str, Any], results: Dict[str, Any]):
        self.target_info = target_info
        self.results = results

    def render_terminal(self) -> int:
        """
        Prints formatted ANSI report table and returns process exit code (0 or 1).
        """
        print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
        print(f"{BOLD}{CYAN}          AI COMPLIANCE LAYER: AUTOMATED AUDIT REPORT                   {RESET}")
        print(f"{BOLD}{CYAN}========================================================================{RESET}\n")

        print(f"{BOLD}Target URL:{RESET}     {self.target_info.get('url', 'N/A')}")
        print(f"{BOLD}Discovered Route:{RESET}{self.target_info.get('endpoint', 'N/A')} [{self.target_info.get('discovery_source', 'N/A')}]")
        print(f"{BOLD}Service Name:{RESET}   {self.target_info.get('service_name', 'N/A')}")
        print(f"{BOLD}Owner Team:{RESET}     {self.target_info.get('owner_team', 'N/A')}")
        print(f"{BOLD}Operational Tier:{RESET}{self.target_info.get('operational_tier', 'N/A')}\n")

        header_fmt = f"{BOLD}{'PILLAR / CHECK':<30} {'SEVERITY':<10} {'STATUS':<10} {'DETAILS':<35}{RESET}"
        print(header_fmt)
        print("-" * 88)

        passed_count = 0
        failed_count = 0
        warn_count = 0

        # Ordered list of checks to display
        check_keys = [
            ("Static Secrets Scan", "static_secrets"),
            ("Service Manifest", "static_manifest"),
            ("Health & Liveness", "dynamic_health"),
            ("Observability & Tracing", "dynamic_tracing"),
            ("Access Control & Auth", "dynamic_auth"),
            ("AI Safety & Guardrails", "safety_eval"),
        ]

        for display_name, key in check_keys:
            check_data = self.results.get(key)
            if not check_data:
                continue

            status = check_data.get("status", "UNKNOWN")
            severity = check_data.get("severity", "P0")
            msg = check_data.get("message", "")

            if status == "PASS":
                status_str = f"{GREEN}{BOLD}PASS{RESET}"
                passed_count += 1
            elif status == "FAIL":
                status_str = f"{RED}{BOLD}FAIL{RESET}"
                failed_count += 1
            else:
                status_str = f"{YELLOW}{BOLD}WARN{RESET}"
                warn_count += 1

            # Format row
            short_msg = msg[:45] + "..." if len(msg) > 45 else msg
            print(f"{display_name:<30} {severity:<10} {status_str:<19} {short_msg:<35}")

            # Print sub-findings if secrets failed
            if key == "static_secrets" and check_data.get("findings"):
                for finding in check_data["findings"]:
                    print(f"  {RED}↳ Leaked in {finding['file']}:{finding['line']} ({finding['description']}){RESET}")

        print("-" * 88)
        print(f"{BOLD}Summary:{RESET} {GREEN}{passed_count} Passed{RESET} | {RED}{failed_count} Failed{RESET} | {YELLOW}{warn_count} Warnings\n")

        if failed_count == 0:
            print(f"{GREEN}{BOLD}>>> COMPLIANCE STATUS: SAFE TO SHIP (Exit Code 0) <<<{RESET}\n")
            return 0
        else:
            print(f"{RED}{BOLD}>>> COMPLIANCE STATUS: DEPLOYMENT BLOCKED (Exit Code 1) <<<{RESET}\n")
            return 1

    def render_json(self) -> int:
        """Emits pure JSON output for automated CI/CD pipelines."""
        payload = {
            "target": self.target_info,
            "results": self.results,
            "passed": all(c.get("status") == "PASS" for c in self.results.values() if c.get("severity") == "P0")
        }
        print(json.dumps(payload, indent=2))
        return 0 if payload["passed"] else 1
