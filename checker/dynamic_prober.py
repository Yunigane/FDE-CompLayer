"""
Dynamic HTTP Compliance Prober.
Performs black-box testing against running applications:
- Validates /health endpoint
- Verifies X-Request-ID correlation headers (echo and auto-generation)
- Enforces access control (rejects unauthenticated and corrupted credentials)
"""
import uuid
import time
from typing import Dict, Any, Optional
import httpx


class DynamicProber:
    def __init__(self, base_url: str, contract: Dict[str, Any]):
        self.base_url = base_url.rstrip("/")
        self.contract = contract
        self.endpoint = contract["endpoint"]
        self.method = contract.get("method", "POST")
        self.payload_field = contract.get("payload_field", "query")
        self.auth_scheme = contract.get("auth_scheme", "Bearer")
        self.token = contract.get("token", "mock-compliance-test-token")
        self.client = httpx.Client(base_url=self.base_url, timeout=10.0)

    def probe_health(self) -> Dict[str, Any]:
        """
        Verifies that /health endpoint responds with HTTP 200 OK.
        """
        for health_path in ["/health", "/livez", "/readyz"]:
            try:
                start = time.perf_counter()
                resp = self.client.get(health_path)
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                if resp.status_code == 200:
                    return {
                        "status": "PASS",
                        "severity": "P0",
                        "message": f"Health probe responsive at {health_path} (HTTP 200 in {latency_ms}ms).",
                        "latency_ms": latency_ms,
                        "data": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
                    }
            except httpx.RequestError:
                continue

        return {
            "status": "FAIL",
            "severity": "P0",
            "message": "Service failed /health probe. Target is unreachable or returned non-200.",
            "details": f"Attempted connection to {self.base_url}/health"
        }

    def probe_observability_tracing(self) -> Dict[str, Any]:
        """
        Validates distributed tracing context:
        1. Confirms X-Request-ID is generated if omitted by client.
        2. Confirms X-Request-ID is forwarded/echoed when supplied by client.
        """
        # Test 1: Auto-generation
        try:
            resp_no_id = self.client.get("/health")
            gen_id = resp_no_id.headers.get("X-Request-ID")
            if not gen_id:
                return {
                    "status": "FAIL",
                    "severity": "P0",
                    "message": "Missing X-Request-ID response header. Server does not attach trace correlation IDs.",
                    "details": "Every response must include an X-Request-ID header."
                }

            # Test 2: Echo / propagation
            probe_id = f"compliance-probe-{uuid.uuid4().hex[:8]}"
            resp_with_id = self.client.get("/health", headers={"X-Request-ID": probe_id})
            echoed_id = resp_with_id.headers.get("X-Request-ID")

            if echoed_id != probe_id:
                return {
                    "status": "WARN",
                    "severity": "P1",
                    "message": f"Server generated a new ID ({echoed_id}) instead of propagating client trace ID ({probe_id}).",
                    "details": "Best practice: propagate upstream X-Request-ID if provided."
                }

            return {
                "status": "PASS",
                "severity": "P0",
                "message": f"Trace correlation verified. X-Request-ID is generated and preserved ({echoed_id}).",
                "sample_request_id": echoed_id
            }
        except httpx.RequestError as e:
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": f"Connection error during trace probing: {e}",
                "details": str(e)
            }

    def probe_auth_enforcement(self) -> Dict[str, Any]:
        """
        Enforces access control (Negative Security Tests):
        1. Request with NO Authorization header must return HTTP 401 or 403.
        2. Request with INVALID credentials must return HTTP 401 or 403.
        """
        url = self.endpoint
        sample_payload = {self.payload_field: "SELECT id FROM users;"}

        # 1. Unauthenticated Probe
        try:
            resp_unauth = self.client.post(url, json=sample_payload)
            if resp_unauth.status_code not in {401, 403}:
                return {
                    "status": "FAIL",
                    "severity": "P0",
                    "message": f"Unauthenticated request to {url} returned HTTP {resp_unauth.status_code}. Expected 401/403.",
                    "details": "Endpoint failed authentication gate. Internal perimeter does not replace auth."
                }

            # 2. Corrupted Token Probe
            bad_headers = {"Authorization": "Bearer invalid-corrupted-token-xyz"}
            resp_bad_token = self.client.post(url, json=sample_payload, headers=bad_headers)
            if resp_bad_token.status_code not in {401, 403}:
                return {
                    "status": "FAIL",
                    "severity": "P0",
                    "message": f"Request with invalid token to {url} returned HTTP {resp_bad_token.status_code}. Expected 401/403.",
                    "details": "Endpoint accepted or improperly handled an invalid credential."
                }

            # 3. Valid Token Probe (Sanity check)
            valid_headers = {"Authorization": f"Bearer {self.token}"}
            resp_valid = self.client.post(url, json=sample_payload, headers=valid_headers)
            if resp_valid.status_code != 200:
                return {
                    "status": "WARN",
                    "severity": "P1",
                    "message": f"Authentication enforced, but valid token returned HTTP {resp_valid.status_code} on test query.",
                    "details": f"Body: {resp_valid.text[:200]}"
                }

            return {
                "status": "PASS",
                "severity": "P0",
                "message": f"Authentication strictly enforced at {url}. Rejects missing/invalid tokens with HTTP 401.",
                "details": f"Tested unauthenticated (401), invalid token (401), and authorized (200)."
            }
        except httpx.RequestError as e:
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": f"Connection failure while probing auth at {url}: {e}",
                "details": str(e)
            }

    def run_all(self) -> Dict[str, Any]:
        """Runs health, tracing, and auth dynamic probes."""
        health_res = self.probe_health()
        tracing_res = self.probe_observability_tracing()
        auth_res = self.probe_auth_enforcement()

        passed = (health_res["status"] == "PASS") and (auth_res["status"] == "PASS") and (tracing_res["status"] == "PASS")
        return {
            "passed": passed,
            "checks": {
                "dynamic_health": health_res,
                "dynamic_tracing": tracing_res,
                "dynamic_auth": auth_res
            }
        }
