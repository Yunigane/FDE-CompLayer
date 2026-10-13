"""
Automated Test Suite for the AI Compliance Layer.
Verifies that:
1. Static scanner accurately catches multi-provider secrets, comments, and invalid manifests.
2. Service discovery introspects contracts statically via Python AST.
3. Dynamic HTTP probers correctly validate health, trace correlation, and negative auth.
4. AI safety evaluator confirms prompt injection defenses, computed tokens, and canary secrecy.
5. Exit codes and reporter verdicts maintain strict semantic compliance.
"""
import pytest
import tempfile
from pathlib import Path
from starlette.testclient import TestClient

from checker.models import Target, Severity, Status, CheckResult
from checker.static_scanner import StaticScanner
from checker.discovery import ServiceDiscovery
from checker.dynamic_prober import DynamicProber
from checker.safety_evaluator import SafetyEvaluator
from checker.reporter import compute_verdict
from app.main import app as reference_app
from tests.vulnerable_app.main import app as vulnerable_app

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_reference_app_passes_static_secrets():
    """Confirms reference application code has zero hardcoded credentials."""
    scanner = StaticScanner(str(PROJECT_ROOT / "app"))
    result = scanner.scan_secrets()
    assert result.status == Status.PASS
    assert "Zero hardcoded" in result.message


def test_reference_app_passes_manifest_validation():
    """Confirms reference app declares a valid service.yaml with EU AI Act alignment."""
    scanner = StaticScanner(str(PROJECT_ROOT / "app"))
    result = scanner.validate_manifest()
    assert result.status == Status.PASS
    assert result.metadata["owner_team"] == "analytics-eng"
    assert result.metadata["operational_tier"] == "tier_2_self_service"
    assert result.metadata["eu_ai_act_risk_tier"] == "minimal_risk"


def test_vulnerable_app_catches_leaked_secret():
    """Confirms static scanner catches the hardcoded API key in vulnerable_app."""
    vuln_path = PROJECT_ROOT / "tests" / "vulnerable_app"
    scanner = StaticScanner(str(vuln_path))
    result = scanner.scan_secrets()
    assert result.status == Status.FAIL
    findings = result.metadata["findings"]
    assert any("OpenAI API Key signature" in f["description"] for f in findings)


def test_vulnerable_app_catches_missing_manifest():
    """Confirms scanner flags repositories missing service.yaml."""
    vuln_path = PROJECT_ROOT / "tests" / "vulnerable_app"
    scanner = StaticScanner(str(vuln_path))
    result = scanner.validate_manifest()
    assert result.status == Status.FAIL
    assert "Missing service.yaml" in result.message


def test_secret_scanner_catches_commented_keys():
    """Confirms secrets in code comments are caught and not silently ignored."""
    sample_key = "sk-proj-" + "12345678901234567890123456789012"
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "config.py"
        test_file.write_text(f"# OPENAI_KEY = '{sample_key}'\n")
        scanner = StaticScanner(tmpdir)
        result = scanner.scan_secrets()
        assert result.status == Status.FAIL
        assert len(result.metadata["findings"]) == 1


def test_multi_provider_secrets_detection():
    """Confirms scanner flags Anthropic, Google Gemini, Groq, and Hugging Face keys."""
    ant_key = "sk-ant-" + "api03-1234567890abcdef1234567890abcdef"
    gem_key = "AIza" + "SyD1234567890abcdef1234567890abcd"
    grq_key = "gsk_" + "1234567890abcdef1234567890abcdef1234567890abcdef"
    hf_tok = "hf_" + "1234567890abcdef1234567890abcdef12"

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "providers.py"
        test_file.write_text(
            f'KEY1 = "{ant_key}"\nKEY2 = "{gem_key}"\nKEY3 = "{grq_key}"\nKEY4 = "{hf_tok}"\n'
        )
        scanner = StaticScanner(tmpdir)
        result = scanner.scan_secrets()
        assert result.status == Status.FAIL
        descriptions = [f["description"] for f in result.metadata["findings"]]
        assert any("Anthropic Claude API Key" in d for d in descriptions)
        assert any("Google AI / Gemini API Key" in d for d in descriptions)
        assert any("Groq Cloud API Key" in d for d in descriptions)
        assert any("Hugging Face Access Token" in d for d in descriptions)


def test_eu_ai_act_prohibited_risk_blocked():
    """Confirms that an application declared as prohibited risk is rejected immediately (Article 5)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest = Path(tmpdir) / "service.yaml"
        manifest.write_text(
            """service_name: "social-scoring-bot"
owner_team: "growth"
operational_tier: "tier_2_self_service"
contact: "growth@company.com"
regulatory_compliance:
  eu_ai_act_risk_tier: "prohibited_risk"
"""
        )
        scanner = StaticScanner(tmpdir)
        result = scanner.validate_manifest()
        assert result.status == Status.FAIL
        assert "Prohibited AI practice" in result.evidence


def test_service_discovery_ast_parsing():
    """Confirms AST parsing discovers the reference app route and query field."""
    discovery = ServiceDiscovery("http://testserver", str(PROJECT_ROOT / "app"))
    ast_res = discovery.discover_via_ast()
    assert ast_res is not None
    assert ast_res["endpoint"] == "/api/v1/explain-sql"
    assert ast_res["payload_field"] == "query"


def test_reference_app_dynamic_probes_pass():
    """Confirms DynamicProber passes health, tracing, and auth on reference app."""
    client = TestClient(reference_app)
    target = Target(
        url="http://testserver",
        endpoint="/api/v1/explain-sql",
        all_endpoints=[{"path": "/api/v1/explain-sql", "method": "POST", "auth_required": True}],
        auth_type="bearer",
        auth_token="mock-compliance-test-token",
        payload_field="query",
    )
    prober = DynamicProber(target, client=client)

    health_res = prober.probe_health()
    assert health_res.status == Status.PASS

    trace_res = prober.probe_observability_tracing()
    assert trace_res.status == Status.PASS

    auth_res = prober.probe_auth_enforcement()
    assert auth_res.status == Status.PASS


def test_vulnerable_app_dynamic_probes_fail():
    """Confirms DynamicProber flags missing health and unauthenticated route on vulnerable app."""
    client = TestClient(vulnerable_app)
    target = Target(
        url="http://testserver",
        endpoint="/api/v1/chat",
        all_endpoints=[{"path": "/api/v1/chat", "method": "POST", "auth_required": True}],
        auth_type="bearer",
        auth_token=None,
        payload_field="message",
    )
    prober = DynamicProber(target, client=client)

    health_res = prober.probe_health()
    assert health_res.status == Status.FAIL

    auth_res = prober.probe_auth_enforcement()
    assert auth_res.status == Status.FAIL


def test_reference_app_safety_evaluator_passes():
    """Confirms SafetyEvaluator passes on reference app with active guardrails."""
    client = TestClient(reference_app)
    target = Target(
        url="http://testserver",
        endpoint="/api/v1/explain-sql",
        auth_type="bearer",
        auth_token="mock-compliance-test-token",
        payload_field="query",
        canary="CORP_CANARY_SQL_V1_SECRET",
    )
    evaluator = SafetyEvaluator(target, client=client)
    results = evaluator.run_all()
    assert len(results) == 1
    assert results[0].status == Status.PASS


def test_vulnerable_app_safety_evaluator_fails():
    """Confirms SafetyEvaluator catches jailbreak and canary disclosure on vulnerable app."""
    client = TestClient(vulnerable_app)
    target = Target(
        url="http://testserver",
        endpoint="/api/v1/chat",
        auth_type="none",
        payload_field="message",
        canary="TOP_SECRET_DEV_CANARY_TOKEN_9999",
    )
    evaluator = SafetyEvaluator(target, client=client)
    results = evaluator.run_all()
    assert len(results) == 1
    assert results[0].status == Status.FAIL


def test_verdict_semantics():
    """Confirms exit code logic: 0 for all pass, 1 for P0 fail, 2 for P0 skipped."""
    pass_res = CheckResult(id="1", title="T1", severity=Severity.P0, status=Status.PASS, message="ok")
    fail_res = CheckResult(id="2", title="T2", severity=Severity.P0, status=Status.FAIL, message="err")
    skip_res = CheckResult(id="3", title="T3", severity=Severity.P0, status=Status.SKIPPED, message="skip")
    warn_res = CheckResult(id="4", title="T4", severity=Severity.P1, status=Status.WARN, message="warn")

    # All P0 pass -> exit 0
    code, verdict = compute_verdict([pass_res, warn_res], strict=False)
    assert code == 0
    assert "SAFE TO SHIP" in verdict

    # Strict mode with warn -> exit 1
    code, verdict = compute_verdict([pass_res, warn_res], strict=True)
    assert code == 1

    # P0 fail -> exit 1
    code, verdict = compute_verdict([pass_res, fail_res], strict=False)
    assert code == 1
    assert "DEPLOYMENT BLOCKED" in verdict

    # P0 skipped (incomplete) -> exit 2
    code, verdict = compute_verdict([pass_res, skip_res], strict=False)
    assert code == 2
    assert "INCOMPLETE" in verdict


def test_safety_evaluator_skips_when_unauthenticated():
    """Confirms SafetyEvaluator returns SKIPPED when target endpoint rejects unauthenticated requests with 401."""
    client = TestClient(reference_app)
    target = Target(
        url="http://testserver",
        endpoint="/api/v1/explain-sql",
        auth_type="none",  # No credentials provided
        payload_field="query",
    )
    evaluator = SafetyEvaluator(target, client=client)
    results = evaluator.run_all()
    assert len(results) == 1
    assert results[0].status == Status.SKIPPED
    assert "rejected unauthenticated probes" in results[0].message
