"""
Dynamic HTTP Compliance Prober.
Performs black-box testing against running applications:
- Validates /health endpoint
- Verifies X-Request-ID correlation headers (echo and auto-generation)
- Enforces access control across all exposed routes (rejects unauthenticated/invalid requests)
"""
import uuid
import time
from typing import Optional, List
import httpx

from checker.models import Target, CheckResult, Severity, Status


class DynamicProber:
    def __init__(self, target: Target, client: Optional[httpx.Client] = None):
        self.target = target
        self._owned_client = client is None
        self.client = client if client is not None else httpx.Client(base_url=self.target.url, timeout=10.0)

    def close(self):
        if self._owned_client and self.client:
            self.client.close()

    def probe_health(self) -> CheckResult:
        """
        Verifies that /health, /livez, or /readyz endpoint responds with HTTP 200 OK.
        """
        for health_path in ["/health", "/livez", "/readyz"]:
            try:
                start = time.perf_counter()
                resp = self.client.get(health_path)
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                if resp.status_code == 200:
                    return CheckResult(
                        id="health",
                        title="Health & Liveness [Resilience]",
                        severity=Severity.P0,
                        status=Status.PASS,
                        message=f"Health probe responsive at {health_path} (HTTP 200 in {latency_ms}ms).",
                        evidence=f"GET {health_path} -> 200 OK ({latency_ms}ms)",
                        metadata={"latency_ms": latency_ms, "health_path": health_path},
                    )
            except httpx.RequestError:
                continue

        return CheckResult(
            id="health",
            title="Health & Liveness [Resilience]",
            severity=Severity.P0,
            status=Status.FAIL,
            message=f"Service failed /health probe. Target is unreachable or returned non-200.",
            evidence=f"Attempted connection to {self.target.url}/health",
            hint="Ensure the service implements a standard GET /health or /livez endpoint returning HTTP 200.",
        )

    def probe_observability_tracing(self) -> CheckResult:
        """
        Validates distributed tracing context:
        1. Confirms X-Request-ID is generated if omitted by client.
        2. Confirms X-Request-ID is forwarded/echoed when supplied by client.
        """
        probe_path = "/health"
        try:
            # Test 1: Auto-generation
            resp_no_id = self.client.get(probe_path)
            gen_id = resp_no_id.headers.get("X-Request-ID")
            if not gen_id:
                return CheckResult(
                    id="observability",
                    title="Observability [Audit Tracing]",
                    severity=Severity.P0,
                    status=Status.FAIL,
                    message="Missing X-Request-ID response header. Server does not attach trace correlation IDs.",
                    evidence=f"GET {probe_path} response headers: {dict(resp_no_id.headers)}",
                    hint="Add middleware that injects or propagates 'X-Request-ID' on all responses.",
                )

            # Test 2: Echo / propagation
            probe_id = f"compliance-trace-{uuid.uuid4().hex[:8]}"
            resp_with_id = self.client.get(probe_path, headers={"X-Request-ID": probe_id})
            echoed_id = resp_with_id.headers.get("X-Request-ID")

            if echoed_id != probe_id:
                return CheckResult(
                    id="observability",
                    title="Observability [Audit Tracing]",
                    severity=Severity.P1,
                    status=Status.WARN,
                    message=f"Server generated a new ID ({echoed_id}) instead of propagating client trace ID ({probe_id}).",
                    evidence=f"Sent: {probe_id}, Received: {echoed_id}",
                    hint="Prefer propagating upstream X-Request-ID rather than generating a new one when present.",
                )

            return CheckResult(
                id="observability",
                title="Observability [Audit Tracing]",
                severity=Severity.P0,
                status=Status.PASS,
                message=f"Trace correlation verified. X-Request-ID is generated and preserved ({echoed_id}).",
                evidence=f"Echo confirmed: {echoed_id}",
            )
        except httpx.RequestError as e:
            return CheckResult(
                id="observability",
                title="Observability [Audit Tracing]",
                severity=Severity.P0,
                status=Status.FAIL,
                message=f"Connection error during trace probing: {e}",
                evidence=str(e),
                hint=f"Verify target {self.target.url} is up and accepting connections.",
            )

    def probe_auth_enforcement(self) -> CheckResult:
        """
        Enforces access control across discovered endpoints (Negative Security Tests):
        1. Probes all declared protected operations unauthenticated. Must return 401/403.
        2. Probes target AI endpoint with corrupted credentials. Must return 401/403.
        3. Probes target AI endpoint with valid credentials if available.
        """
        target_endpoint = self.target.endpoint
        if not target_endpoint:
            return CheckResult(
                id="auth",
                title="Access Control & Auth [Gateway]",
                severity=Severity.P0,
                status=Status.SKIPPED,
                message="Endpoint not discovered. Skipping dynamic authentication test.",
                hint="Pass --endpoint /your-api-path to run authentication verification.",
            )

        # Collect routes to probe unauthenticated
        routes_to_probe = [
            ep for ep in self.target.all_endpoints
            if ep.get("auth_required") and ep.get("path") not in {"/health", "/docs", "/openapi.json"}
        ]
        if not routes_to_probe:
            routes_to_probe = [{"path": target_endpoint, "method": "POST"}]

        # 1. Probe all routes unauthenticated
        for ep in routes_to_probe:
            path = ep["path"]
            method = ep.get("method", "POST").upper()
            dummy_payload = self.target.build_payload("test auth") if method in {"POST", "PUT"} else None
            try:
                if method == "POST":
                    resp = self.client.post(path, json=dummy_payload)
                elif method == "PUT":
                    resp = self.client.put(path, json=dummy_payload)
                elif method == "DELETE":
                    resp = self.client.delete(path)
                else:
                    resp = self.client.get(path)

                if resp.status_code not in {401, 403}:
                    return CheckResult(
                        id="auth",
                        title="Access Control & Auth [Gateway]",
                        severity=Severity.P0,
                        status=Status.FAIL,
                        message=f"Unauthenticated request to {method} {path} returned HTTP {resp.status_code}. Expected 401/403.",
                        evidence=f"{method} {path} returned status {resp.status_code}",
                        hint="All exposed operational routes must reject unauthenticated requests with HTTP 401 or 403.",
                    )
            except httpx.RequestError as e:
                return CheckResult(
                    id="auth",
                    title="Access Control & Auth [Gateway]",
                    severity=Severity.P0,
                    status=Status.FAIL,
                    message=f"Connection failure while probing unauthenticated {method} {path}: {e}",
                    evidence=str(e),
                )

        # 2. Corrupted credential probe on primary endpoint
        bad_headers = {"Authorization": "Bearer invalid-corrupted-token-xyz"}
        if self.target.auth_type == "basic":
            bad_headers = {"Authorization": "Basic aW52YWxpZDpiYWQ="}
        elif self.target.auth_type == "api_key":
            bad_headers = {self.target.api_key_header: "invalid-secret-key-123"}

        sample_payload = self.target.build_payload("SELECT 1;")
        try:
            resp_bad = self.client.post(target_endpoint, json=sample_payload, headers=bad_headers)
            if resp_bad.status_code not in {401, 403}:
                return CheckResult(
                    id="auth",
                    title="Access Control & Auth [Gateway]",
                    severity=Severity.P0,
                    status=Status.FAIL,
                    message=f"Request with invalid credentials to {target_endpoint} returned HTTP {resp_bad.status_code}. Expected 401/403.",
                    evidence=f"Headers sent: {bad_headers} -> Status {resp_bad.status_code}",
                    hint="Ensure auth middleware validates credential signature/token before executing handler.",
                )
        except httpx.RequestError as e:
            return CheckResult(
                id="auth",
                title="Access Control & Auth [Gateway]",
                severity=Severity.P0,
                status=Status.FAIL,
                message=f"Connection failure while probing invalid credentials: {e}",
                evidence=str(e),
            )

        # 3. Valid credential sanity check (if credentials provided)
        auth_headers = self.target.get_auth_headers()
        if not auth_headers:
            return CheckResult(
                id="auth",
                title="Access Control & Auth [Gateway]",
                severity=Severity.P0,
                status=Status.PASS,
                message=f"Negative auth verified across {len(routes_to_probe)} route(s). (Authorized check SKIPPED: no credentials supplied).",
                evidence=f"Unauthenticated and corrupted credential tests returned 401/403 across {len(routes_to_probe)} endpoint(s).",
                hint="Pass --auth-token, --basic-user/pass, or configure .env to run authorized sanity check.",
            )

        try:
            resp_valid = self.client.post(target_endpoint, json=sample_payload, headers=auth_headers)
            if resp_valid.status_code != 200:
                return CheckResult(
                    id="auth",
                    title="Access Control & Auth [Gateway]",
                    severity=Severity.P1,
                    status=Status.WARN,
                    message=f"Authentication enforced (401/403), but valid credentials returned HTTP {resp_valid.status_code}.",
                    evidence=f"Body snippet: {resp_valid.text[:200]}",
                    hint="Check that the supplied credentials have appropriate permissions for the endpoint.",
                )

            return CheckResult(
                id="auth",
                title="Access Control & Auth [Gateway]",
                severity=Severity.P0,
                status=Status.PASS,
                message=f"Authentication strictly enforced across {len(routes_to_probe)} route(s) and confirmed working at {target_endpoint}.",
                evidence=f"Negative tests: 401/403. Authorized test: HTTP 200.",
            )
        except httpx.RequestError as e:
            return CheckResult(
                id="auth",
                title="Access Control & Auth [Gateway]",
                severity=Severity.P0,
                status=Status.FAIL,
                message=f"Connection failure while testing authorized request: {e}",
                evidence=str(e),
            )

    def run_all(self) -> List[CheckResult]:
        return [
            self.probe_health(),
            self.probe_observability_tracing(),
            self.probe_auth_enforcement(),
        ]
