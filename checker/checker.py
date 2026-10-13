"""
Universal Compliance Checker CLI.
Entrypoint for automated validation of internal AI applications.
Executes static analysis, automated contract discovery, dynamic HTTP testing,
adversarial AI safety probing, and optional LLM-as-a-judge evaluation.
"""
import sys
import argparse
from pathlib import Path
from typing import List, Tuple, Optional
import httpx

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from checker.models import Target, CheckResult, Severity, Status
from checker.static_scanner import StaticScanner, generate_manifest_template
from checker.discovery import ServiceDiscovery
from checker.dynamic_prober import DynamicProber
from checker.safety_evaluator import SafetyEvaluator
from checker.reporter import ComplianceReporter, compute_verdict


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
        "--init-manifest",
        action="store_true",
        help="Generate a pre-filled service.yaml template in the repository root and exit."
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Explicit endpoint override (e.g. /api/v1/explain-sql). Discovered automatically via OpenAPI/AST if omitted."
    )
    parser.add_argument(
        "--auth-type",
        default=None,
        choices=["bearer", "basic", "api_key", "none"],
        help="Authentication scheme: bearer (default), basic, or api_key."
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Credential token for Bearer or API-Key auth."
    )
    parser.add_argument(
        "--basic-user",
        default=None,
        help="Username for HTTP Basic auth."
    )
    parser.add_argument(
        "--basic-pass",
        default=None,
        help="Password for HTTP Basic auth."
    )
    parser.add_argument(
        "--api-key-header",
        default=None,
        help="Header name for API Key auth (default: X-API-Key)."
    )
    parser.add_argument(
        "--payload-field",
        default=None,
        help="JSON field name for prompt payload (e.g. query, prompt, message)."
    )
    parser.add_argument(
        "--payload-template",
        default=None,
        help="Custom JSON payload template with {{PROMPT}} placeholder."
    )
    parser.add_argument(
        "--canary",
        default=None,
        help="Expected canary token string to assert non-disclosure."
    )
    parser.add_argument(
        "--judge",
        action="store_true",
        help="Enable advisory LLM-as-a-judge (P1 WARN) using configured API key."
    )
    parser.add_argument(
        "--judge-provider",
        default=None,
        choices=["openai", "anthropic", "gemini"],
        help="Model provider for advisory LLM judge (default: auto-detect from env: OpenAI, Anthropic, or Gemini)."
    )
    parser.add_argument(
        "--judge-model",
        default=None,
        help="Model identifier for advisory judge (e.g. gpt-4o-mini, claude-3-5-haiku-20241022, gemini-1.5-flash)."
    )
    parser.add_argument(
        "--judge-api-key",
        default=None,
        help="API key for advisory LLM judge."
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


def run_compliance_suite(
    target: Target,
    client: Optional[httpx.Client] = None,
    manifest_path: Optional[str] = None,
    enable_judge: bool = False,
    judge_api_key: Optional[str] = None,
    judge_provider: Optional[str] = None,
    judge_model: Optional[str] = None,
) -> List[CheckResult]:
    """
    Executes all static, discovery, dynamic, and safety checks against the target.
    Accepts an optional injected httpx.Client (e.g. starlette.testclient.TestClient).
    """
    results: List[CheckResult] = []
    close_client = False
    if client is None:
        client = httpx.Client(base_url=target.url, timeout=10.0)
        close_client = True

    try:
        # 1. Static Security, Manifest & AST Capability Scan
        static_scanner = StaticScanner(target.repo_path, manifest_path)
        results.extend(static_scanner.run_all())

        # Extract declared canary from manifest if present
        manifest_file = static_scanner.find_manifest()
        if manifest_file and not target.canary:
            try:
                from ruamel.yaml import YAML
                y = YAML(typ="safe")
                with open(manifest_file, "r", encoding="utf-8") as mf:
                    mdata = y.load(mf)
                if isinstance(mdata, dict):
                    target.canary = mdata.get("safety", {}).get("canary")
            except Exception:
                pass

        # 2. Dynamic HTTP Probing (Health, Tracing, Auth Gate)
        dynamic_prober = DynamicProber(target, client=client)
        results.extend(dynamic_prober.run_all())

        # 3. AI Safety & Red-Teaming Probing
        safety_evaluator = SafetyEvaluator(
            target,
            client=client,
            enable_judge=enable_judge,
            judge_api_key=judge_api_key,
            judge_provider=judge_provider,
            judge_model=judge_model,
        )
        results.extend(safety_evaluator.run_all())

    finally:
        if close_client:
            client.close()

    return results


def main():
    args = parse_args()
    repo_path = Path(args.repo_path).resolve()

    # Handle --init-manifest flag
    if args.init_manifest:
        target_manifest = repo_path / "service.yaml"
        if target_manifest.exists():
            print(f"Error: {target_manifest} already exists.", file=sys.stderr)
            sys.exit(1)
        template = generate_manifest_template(service_name=repo_path.name)
        with open(target_manifest, "w", encoding="utf-8") as f:
            f.write(template)
        print(f"Created pre-filled service.yaml at {target_manifest}")
        sys.exit(0)

    # 1. Automated Discovery
    discovery = ServiceDiscovery(args.url, str(repo_path))
    try:
        target = discovery.discover_target(
            endpoint_override=args.endpoint,
            auth_type_override=args.auth_type,
            auth_token_override=args.auth_token,
            basic_user_override=args.basic_user,
            basic_pass_override=args.basic_pass,
            api_key_header_override=args.api_key_header,
            payload_field_override=args.payload_field,
            payload_template_override=args.payload_template,
            canary_override=args.canary,
        )
    finally:
        discovery.close()

    # 2. Execute Compliance Suite
    results = run_compliance_suite(
        target,
        manifest_path=args.manifest,
        enable_judge=args.judge,
        judge_api_key=args.judge_api_key,
        judge_provider=args.judge_provider,
        judge_model=args.judge_model,
    )

    # 3. Render Report
    reporter = ComplianceReporter(target, results, strict=args.strict)
    if args.json:
        exit_code = reporter.render_json()
    else:
        exit_code = reporter.render_terminal()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
