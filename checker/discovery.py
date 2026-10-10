"""
Automated Service & Contract Discovery Engine.
Introspects target applications dynamically via OpenAPI/Swagger schemas and statically
via source code AST/regex parsing. Enables zero-config compliance testing.
"""
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
import httpx


class ServiceDiscovery:
    def __init__(self, base_url: str, repo_path: str):
        self.base_url = base_url.rstrip("/")
        self.repo_path = Path(repo_path).resolve()
        self.client = httpx.Client(base_url=self.base_url, timeout=5.0)

    def discover_credentials(self) -> Optional[str]:
        """
        Discovers test credentials from repository .env or .env.example files.
        """
        candidates = [self.repo_path / ".env", self.repo_path / ".env.example"]
        for env_file in candidates:
            if env_file.is_file():
                try:
                    with open(env_file, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#") or "=" not in line:
                                continue
                            key, val = line.split("=", 1)
                            key_clean = key.strip().upper()
                            if key_clean in {"APP_BEARER_TOKEN", "BEARER_TOKEN", "AUTH_TOKEN", "API_KEY"}:
                                clean_val = val.strip().strip("'\"")
                                if clean_val:
                                    return clean_val
                except Exception:
                    continue
        return None

    def discover_via_openapi(self) -> Optional[Dict[str, Any]]:
        """
        Pulls and parses /openapi.json to discover endpoints, schemas, and auth.
        """
        for spec_path in ["/openapi.json", "/swagger.json", "/api/v1/openapi.json"]:
            try:
                resp = self.client.get(spec_path)
                if resp.status_code == 200:
                    spec = resp.json()
                    paths = spec.get("paths", {})

                    # Look for candidate POST/PUT AI endpoints
                    candidate_endpoint = None
                    payload_field = "prompt"
                    auth_scheme = "Bearer"

                    # 1. Discover Auth Schemes
                    components = spec.get("components", {})
                    sec_schemes = components.get("securitySchemes", {})
                    for name, scheme in sec_schemes.items():
                        if scheme.get("type") == "http" and scheme.get("scheme") == "bearer":
                            auth_scheme = "Bearer"
                        elif scheme.get("type") == "apiKey":
                            auth_scheme = scheme.get("name", "X-API-Key")

                    # 2. Discover Endpoints & Request Schema
                    for path, methods in paths.items():
                        if path in {"/health", "/livez", "/readyz", "/metrics"}:
                            continue
                        for method, details in methods.items():
                            if method.lower() in {"post", "put"}:
                                # Check requestBody schema for expected field
                                body_content = details.get("requestBody", {}).get("content", {})
                                json_schema = body_content.get("application/json", {}).get("schema", {})
                                ref = json_schema.get("$ref")
                                if ref and "#/components/schemas/" in ref:
                                    schema_name = ref.split("/")[-1]
                                    props = components.get("schemas", {}).get(schema_name, {}).get("properties", {})
                                    for prop in ["query", "prompt", "message", "text", "input", "sql"]:
                                        if prop in props:
                                            payload_field = prop
                                            break

                                candidate_endpoint = path
                                # Prioritize routes matching AI terms
                                if any(term in path.lower() for term in ["explain", "sql", "chat", "generate", "ai", "llm"]):
                                    return {
                                        "source": "openapi",
                                        "endpoint": path,
                                        "method": method.upper(),
                                        "payload_field": payload_field,
                                        "auth_scheme": auth_scheme
                                    }

                    if candidate_endpoint:
                        return {
                            "source": "openapi",
                            "endpoint": candidate_endpoint,
                            "method": "POST",
                            "payload_field": payload_field,
                            "auth_scheme": auth_scheme
                        }
            except Exception:
                continue
        return None

    def discover_via_static_code(self) -> Optional[Dict[str, Any]]:
        """
        Fallback: Statically parses python source files for route decorators
        like @app.post('/...') or @app.route('/...', methods=['POST']).
        """
        route_patterns = [
            r"@app\.post\(\s*['\"]([^'\"]+)['\"]",
            r"@app\.route\(\s*['\"]([^'\"]+)['\"].*methods=.*POST",
            r"router\.post\(\s*['\"]([^'\"]+)['\"]"
        ]
        field_patterns = [
            r"request\.(?:json|form)\.get\(\s*['\"]([^'\"]+)['\"]",
            r"req\.([a-zA-Z0-9_]+)",
        ]

        found_endpoint = None
        found_field = "prompt"

        for py_file in self.repo_path.glob("**/*.py"):
            if any(part in py_file.parts for part in [".venv", "venv", "__pycache__", "tests", "checker"]):
                continue
            try:
                with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for pattern in route_patterns:
                        match = re.search(pattern, content)
                        if match:
                            path = match.group(1)
                            if path not in {"/health", "/metrics", "/livez"}:
                                found_endpoint = path
                                break

                    for pattern in field_patterns:
                        match = re.search(pattern, content)
                        if match:
                            candidate_field = match.group(1)
                            if candidate_field in {"query", "prompt", "message", "text", "input"}:
                                found_field = candidate_field
                                break
            except Exception:
                continue

        if found_endpoint:
            return {
                "source": "static_ast",
                "endpoint": found_endpoint,
                "method": "POST",
                "payload_field": found_field,
                "auth_scheme": "Bearer"
            }
        return None

    def discover(self) -> Dict[str, Any]:
        """
        Orchestrates auto-discovery across OpenAPI, static code, and environment configs.
        Returns a complete service contract.
        """
        # 1. Discover Credentials
        token = self.discover_credentials() or "mock-compliance-test-token"

        # 2. Try OpenAPI Discovery
        openapi_contract = self.discover_via_openapi()
        if openapi_contract:
            openapi_contract["token"] = token
            return openapi_contract

        # 3. Fallback: Static Code Discovery
        static_contract = self.discover_via_static_code()
        if static_contract:
            static_contract["token"] = token
            return static_contract

        # 4. Default Heuristic Fallback
        return {
            "source": "heuristic_fallback",
            "endpoint": "/api/v1/explain-sql",
            "method": "POST",
            "payload_field": "query",
            "auth_scheme": "Bearer",
            "token": token
        }
