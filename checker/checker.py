"""
Universal Compliance Checker CLI.
Entrypoint for automated validation of internal AI applications.
Executes static analysis, automated contract discovery, dynamic HTTP testing,
and adversarial AI safety probing.
"""
import sys
import argparse
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from checker.static_scanner import StaticScanner
from checker.discovery import ServiceDiscovery
from checker.dynamic_prober import DynamicProber
from checker.safety_evaluator import SafetyEvaluator
from checker.reporter import ComplianceReporter


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated AI Compliance Layer Validator. Evaluates internal AI micro-apps against the platform compliance bar."
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Base URL of the running application (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--repo-path",
        default=".",
        help="Path to the repository root for static analysis (default: .)"
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Explicit path to service.yaml (auto-discovered if omitted)"
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Explicit endpoint override (e.g. /v1/chat). Discovered automatically via OpenAPI/AST if omitted."
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Explicit bearer token for testing authorized routes (discovered automatically from .env if omitted)."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of the formatted terminal table."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings (P1) as blocking failures (Exit 1)."
    )
    return parser.parse_args()


def main():
    args = parse_args()
    repo_path = Path(args.repo_path).resolve()

    # 1. Static Security & Manifest Scan
    static_scanner = StaticScanner(str(repo_path), args.manifest)
    static_results = static_scanner.run_all()

    manifest_data = static_results["checks"]["static_manifest"].get("data", {})

    # 2. Automated Service & Contract Discovery
    discovery = ServiceDiscovery(args.url, str(repo_path))
    contract = discovery.discover()

    # Apply optional manual overrides if specified
    if args.endpoint:
        contract["endpoint"] = args.endpoint
        contract["source"] = "manual_cli_override"
    if args.auth_token:
        contract["token"] = args.auth_token

    # 3. Dynamic HTTP Probing (Health, Tracing, Auth Gate)
    dynamic_prober = DynamicProber(args.url, contract)
    dynamic_results = dynamic_prober.run_all()

    # 4. AI Safety & Red-Teaming Probing
    safety_evaluator = SafetyEvaluator(args.url, contract)
    safety_results = safety_evaluator.run_all()

    # Aggregate Results
    all_results = {
        "static_secrets": static_results["checks"]["static_secrets"],
        "static_manifest": static_results["checks"]["static_manifest"],
        "dynamic_health": dynamic_results["checks"]["dynamic_health"],
        "dynamic_tracing": dynamic_results["checks"]["dynamic_tracing"],
        "dynamic_auth": dynamic_results["checks"]["dynamic_auth"],
        "safety_eval": safety_results,
    }

    target_info = {
        "url": args.url,
        "endpoint": contract["endpoint"],
        "discovery_source": contract.get("source", "unknown"),
        "service_name": manifest_data.get("service_name", "Unknown"),
        "owner_team": manifest_data.get("owner_team", "Unknown"),
        "operational_tier": manifest_data.get("operational_tier", "Unknown")
    }

    # 5. Render Compliance Report
    reporter = ComplianceReporter(target_info, all_results)
    if args.json:
        exit_code = reporter.render_json()
    else:
        exit_code = reporter.render_terminal()

    # Enforce --strict mode if enabled
    if args.strict and any(c.get("status") == "WARN" for c in all_results.values()):
        print("\n[STRICT MODE] Warnings detected. Failing build.")
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
