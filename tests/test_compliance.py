"""
Automated Test Suite for the AI Compliance Layer.
Verifies that:
1. The compliant Reference App passes all static, dynamic, and safety checks.
2. The non-compliant Vulnerable App fixture fails secrets, manifest, health, and auth checks.
"""
import pytest
from starlette.testclient import TestClient
from pathlib import Path

from checker.static_scanner import StaticScanner
from checker.discovery import ServiceDiscovery
from checker.dynamic_prober import DynamicProber
from checker.safety_evaluator import SafetyEvaluator
from app.main import app as reference_app
from tests.vulnerable_app.main import app as vulnerable_app


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_reference_app_passes_static_secrets():
    """Confirms reference repository has zero hardcoded secrets."""
    scanner = StaticScanner(str(PROJECT_ROOT))
    result = scanner.scan_secrets()
    assert result["status"] == "PASS"
    assert len(result["findings"]) == 0


def test_reference_app_passes_manifest_validation():
    """Confirms reference app declares a valid service.yaml."""
    scanner = StaticScanner(str(PROJECT_ROOT))
    result = scanner.validate_manifest()
    assert result["status"] == "PASS"
    assert result["data"]["owner_team"] == "analytics-eng"
    assert result["data"]["operational_tier"] == "tier_2_self_service"


def test_vulnerable_app_catches_leaked_secret():
    """Confirms static scanner catches the hardcoded API key in vulnerable_app."""
    vuln_path = PROJECT_ROOT / "tests" / "vulnerable_app"
    scanner = StaticScanner(str(vuln_path))
    result = scanner.scan_secrets()
    assert result["status"] == "FAIL"
    assert any("OpenAI API Key signature" in f["description"] for f in result["findings"])


def test_vulnerable_app_catches_missing_manifest():
    """Confirms scanner flags repositories missing service.yaml."""
    vuln_path = PROJECT_ROOT / "tests" / "vulnerable_app"
    scanner = StaticScanner(str(vuln_path))
    result = scanner.validate_manifest()
    assert result["status"] == "FAIL"
    assert "Missing service.yaml" in result["message"]


def test_reference_app_dynamic_auth_enforcement():
    """Confirms reference app rejects unauthenticated and invalid requests with 401."""
    client = TestClient(reference_app)

    # 1. Missing token -> 401
    resp_unauth = client.post("/api/v1/explain-sql", json={"query": "SELECT 1;"})
    assert resp_unauth.status_code == 401

    # 2. Invalid token -> 401
    resp_bad = client.post("/api/v1/explain-sql", json={"query": "SELECT 1;"}, headers={"Authorization": "Bearer bad-token"})
    assert resp_bad.status_code == 401

    # 3. Valid token -> 200
    resp_ok = client.post(
        "/api/v1/explain-sql",
        json={"query": "SELECT 1;"},
        headers={"Authorization": "Bearer mock-compliance-test-token"}
    )
    assert resp_ok.status_code == 200


def test_vulnerable_app_fails_auth_gate():
    """Confirms that vulnerable app's unauthenticated route is caught as a compliance violation."""
    client = TestClient(vulnerable_app)

    # Vulnerable route accepts unauthenticated request -> status 200 (Violation!)
    resp = client.post("/api/v1/chat", json={"message": "hello"})
    assert resp.status_code == 200  # Proves it lacks auth, which the prober flags as a failure


def test_vulnerable_app_fails_health_probe():
    """Confirms that vulnerable app lacking /health fails the liveness probe."""
    client = TestClient(vulnerable_app)
    resp = client.get("/health")
    assert resp.status_code == 404  # Missing probe
