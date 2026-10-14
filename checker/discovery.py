"""
Automated Service & Contract Discovery Engine.
Introspects target applications dynamically via OpenAPI/Swagger schemas and statically
via  Python AST parsing. Enables zero-config compliance testing.
"""
import ast
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import httpx

from checker.models import Target


def is_localhost(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        return hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    except Exception:
        return False


class ServiceDiscovery:
    def __init__(self, base_url: str, repo_path: Optional[str] = None, client: Optional[httpx.Client] = None):
        self.base_url = base_url.rstrip("/")
        self.repo_path = Path(repo_path).resolve() if repo_path else None
        self._owned_client = client is None
        self.client = client if client is not None else httpx.Client(base_url=self.base_url, timeout=5.0)

    def close(self):
        if self._owned_client and self.client:
            self.client.close()

    def discover_credentials(self) -> Optional[str]:
        """
        Discovers test credentials from repository .env or .env.example files.
        Safeguard: only auto-reads local .env when targeting localhost to avoid
        exfiltrating local secrets to remote hosts.
        """
        if not self.repo_path or not is_localhost(self.base_url):
            return None

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
                            if key_clean in {
                                "APP_BEARER_TOKEN", "BEARER_TOKEN", "AUTH_TOKEN", "API_KEY",
                                "OPENAI_API_KEY", "SERVICE_TOKEN", "ACCESS_TOKEN", "SECRET_KEY", "API_SECRET"
                            }:
                                clean_val = val.strip().strip("'\"")
                                if clean_val:
                                    return clean_val
                except Exception:
                    continue
        return None

    def discover_via_openapi(self) -> Optional[Dict[str, Any]]:
        """
        Pulls and parses /openapi.json or /swagger.json to discover endpoints,
        request schemas, security schemes, and all exposed operations.
        """
        for spec_path in ["/openapi.json", "/swagger.json", "/api/v1/openapi.json"]:
            try:
                resp = self.client.get(spec_path)
                if resp.status_code == 200:
                    spec = resp.json()
                    paths = spec.get("paths", {})
                    components = spec.get("components", {})
                    schemas = components.get("schemas", {})
                    sec_schemes = components.get("securitySchemes", {})

                    # 1. Discover Auth Scheme
                    auth_type = "bearer"
                    api_key_header = "X-API-Key"
                    for _, scheme in sec_schemes.items():
                        stype = scheme.get("type", "")
                        if stype == "http":
                            if scheme.get("scheme") == "bearer":
                                auth_type = "bearer"
                            elif scheme.get("scheme") == "basic":
                                auth_type = "basic"
                        elif stype == "apiKey":
                            auth_type = "api_key"
                            api_key_header = scheme.get("name", "X-API-Key")

                    # 2. Extract all exposed operations
                    all_endpoints: List[Dict[str, Any]] = []
                    candidate_ai_endpoint = None
                    candidate_field = "query"

                    for path, methods in paths.items():
                        if not isinstance(methods, dict):
                            continue
                        for method, details in methods.items():
                            if method.lower() not in {"get", "post", "put", "delete", "patch"}:
                                continue
                            if not isinstance(details, dict):
                                continue

                            # Check if security requirement is declared
                            has_sec = bool(details.get("security") or spec.get("security"))
                            all_endpoints.append({
                                "path": path,
                                "method": method.upper(),
                                "auth_required": has_sec or (path not in {"/health", "/livez", "/readyz", "/metrics", "/docs", "/openapi.json"}),
                                "summary": details.get("summary", ""),
                            })

                            if method.lower() in {"post", "put"} and path not in {"/health", "/metrics", "/livez", "/readyz"}:
                                # Check payload schema
                                body_content = details.get("requestBody", {}).get("content", {})
                                json_schema = body_content.get("application/json", {}).get("schema", {})
                                ref = json_schema.get("$ref")
                                payload_field = "prompt"
                                payload_type = "flat"
                                if ref and "#/components/schemas/" in ref:
                                    sname = ref.split("/")[-1]
                                    props = schemas.get(sname, {}).get("properties", {})
                                    if "messages" in props:
                                        payload_type = "chat"
                                        payload_field = "messages"
                                    else:
                                        for prop in ["query", "prompt", "message", "text", "input", "sql", "question"]:
                                            if prop in props:
                                                payload_field = prop
                                                break
                                elif "properties" in json_schema:
                                    props = json_schema["properties"]
                                    if "messages" in props:
                                        payload_type = "chat"
                                        payload_field = "messages"
                                    else:
                                        for prop in ["query", "prompt", "message", "text", "input", "sql", "question"]:
                                            if prop in props:
                                                payload_field = prop
                                                break

                                if candidate_ai_endpoint is None:
                                    candidate_ai_endpoint = path
                                    candidate_field = payload_field
                                    candidate_type = payload_type

                                # Prioritize routes with AI indicators in name
                                if any(term in path.lower() for term in ["explain", "sql", "chat", "generate", "ai", "llm", "predict", "ask"]):
                                    candidate_ai_endpoint = path
                                    candidate_field = payload_field
                                    candidate_type = payload_type

                    return {
                        "source": "openapi",
                        "endpoint": candidate_ai_endpoint,
                        "all_endpoints": all_endpoints,
                        "payload_field": candidate_field,
                        "payload_type": candidate_type if 'candidate_type' in locals() else "flat",
                        "auth_type": auth_type,
                        "api_key_header": api_key_header,
                        "service_name": spec.get("info", {}).get("title"),
                    }
            except (httpx.ConnectError, httpx.ConnectTimeout):
                # Target server is unreachable; break immediately to avoid compounding timeouts
                break
            except Exception:
                continue
        return None

    def discover_via_ast(self) -> Optional[Dict[str, Any]]:
        """
        Parses Python source files using Python's standard `ast` module.
        Detects FastAPI/Flask route decorators and Pydantic/dict payload fields.
        """
        if not self.repo_path:
            return None

        found_endpoint = None
        found_field = "prompt"
        all_endpoints: List[Dict[str, Any]] = []

        for py_file in self.repo_path.glob("**/*.py"):
            try:
                rel_parts = py_file.resolve().relative_to(self.repo_path).parts
            except ValueError:
                rel_parts = py_file.parts

            if any(part in rel_parts for part in [".venv", "venv", "env", "__pycache__", ".pytest_cache", "site-packages"]):
                continue
            if len(rel_parts) > 1 and rel_parts[0] in {"tests", "checker"} and self.repo_path.name not in {"tests", "vulnerable_app"}:
                continue

            try:
                with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                tree = ast.parse(content, filename=str(py_file))

                # 1. Collect Pydantic / Schema class definitions
                request_models: Dict[str, List[str]] = {}
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        fields = []
                        for item in node.body:
                            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                                fields.append(item.target.id)
                        if fields:
                            request_models[node.name] = fields

                # 2. Inspect route functions and decorators
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        is_route = False
                        for decorator in node.decorator_list:
                            route_path = None
                            method = "POST"
                            # Case: @app.post("/path") or @router.post("/path")
                            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                                attr_name = decorator.func.attr.lower()
                                if attr_name in {"post", "get", "put", "delete", "route"}:
                                    if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                                        route_path = decorator.args[0].value
                                        method = attr_name.upper() if attr_name != "route" else "POST"

                            if route_path:
                                is_route = True
                                is_standard_public = route_path in {
                                    "/health", "/healthz", "/metrics", "/livez", "/readyz",
                                    "/ping", "/status", "/docs", "/openapi.json"
                                }
                                all_endpoints.append({
                                    "path": route_path,
                                    "method": method,
                                    "auth_required": not is_standard_public
                                })
                                if not is_standard_public:
                                    if found_endpoint is None:
                                        found_endpoint = route_path
                                    if any(term in route_path.lower() for term in ["explain", "sql", "chat", "generate", "ai", "llm"]):
                                        found_endpoint = route_path

                        # If route function, correlate param types with request models
                        if is_route:
                            for arg in node.args.args:
                                if arg.annotation and isinstance(arg.annotation, ast.Name):
                                    tname = arg.annotation.id
                                    if tname in request_models:
                                        for kw in ["query", "prompt", "message", "text", "input", "sql", "question"]:
                                            if kw in request_models[tname]:
                                                found_field = kw
                                                break

                # Fallback: inspect direct field access in route body
                if found_field == "prompt":
                    for kw in ["query", "prompt", "message", "text", "input", "sql"]:
                        if f".{kw}" in content or f'["{kw}"]' in content or f"['{kw}']" in content:
                            found_field = kw
                            break
            except Exception:
                continue

        # Small fallback regex for JS/Express routes
        if not found_endpoint:
            for js_file in self.repo_path.glob("**/*.js"):
                if "node_modules" in js_file.parts:
                    continue
                try:
                    with open(js_file, "r", encoding="utf-8", errors="ignore") as f:
                        js_text = f.read()
                    m = re.search(r"(?:app|router)\.(post|put)\(\s*['\"]([^'\"]+)['\"]", js_text)
                    if m:
                        found_endpoint = m.group(2)
                        all_endpoints.append({"path": found_endpoint, "method": m.group(1).upper(), "auth_required": True})
                        break
                except Exception:
                    continue

        if found_endpoint:
            return {
                "source": "static_ast",
                "endpoint": found_endpoint,
                "all_endpoints": all_endpoints,
                "payload_field": found_field,
                "auth_type": "bearer",
                "api_key_header": "X-API-Key",
                "service_name": None,
            }
        return None

    def discover_target(
        self,
        endpoint_override: Optional[str] = None,
        auth_type_override: Optional[str] = None,
        auth_token_override: Optional[str] = None,
        basic_user_override: Optional[str] = None,
        basic_pass_override: Optional[str] = None,
        api_key_header_override: Optional[str] = None,
        payload_field_override: Optional[str] = None,
        payload_template_override: Optional[str] = None,
        canary_override: Optional[str] = None,
    ) -> Target:
        """
        Orchestrates auto-discovery across OpenAPI, static AST, and environment configs.
        1. Checks service.yaml for optional declarative api_contract.
        2. Unions routes from both OpenAPI and AST to catch routes with include_in_schema=False.
        3. Applies explicit CLI flag overrides when provided.
        """
        # 1. Check service.yaml for declarative api_contract
        contract = {}
        if self.repo_path:
            for candidate in [self.repo_path / "service.yaml", self.repo_path / "app" / "service.yaml"]:
                if candidate.is_file():
                    try:
                        from ruamel.yaml import YAML
                        y = YAML(typ="safe")
                        with open(candidate, "r", encoding="utf-8") as cf:
                            mdata = y.load(cf)
                        if isinstance(mdata, dict) and "api_contract" in mdata and isinstance(mdata["api_contract"], dict):
                            contract = mdata["api_contract"]
                            break
                    except Exception:
                        pass

        # 2. Auto-discover credentials
        discovered_token = self.discover_credentials()

        # 3. Discover routes via OpenAPI and AST in parallel (Union Mode)
        openapi_data = self.discover_via_openapi()
        ast_data = self.discover_via_ast()

        all_endpoints_map = {}
        if openapi_data:
            for ep in openapi_data.get("all_endpoints", []):
                all_endpoints_map[(ep["path"], ep.get("method", "POST"))] = ep
        if ast_data:
            for ep in ast_data.get("all_endpoints", []):
                key = (ep["path"], ep.get("method", "POST"))
                if key not in all_endpoints_map:
                    all_endpoints_map[key] = ep

        all_endpoints = list(all_endpoints_map.values())

        # Select primary endpoint and properties
        primary_endpoint = endpoint_override or contract.get("primary_endpoint")
        payload_field = payload_field_override or contract.get("payload_field")
        payload_type = contract.get("payload_type", "flat")
        payload_template = payload_template_override or contract.get("payload_template")
        auth_type = auth_type_override or contract.get("auth_type")
        api_key_header = api_key_header_override or contract.get("api_key_header")
        service_name = None
        health_path = contract.get("health_path")

        if openapi_data:
            if not primary_endpoint:
                primary_endpoint = openapi_data.get("endpoint")
            if not payload_field:
                payload_field = openapi_data.get("payload_field")
            if not payload_type or payload_type == "flat":
                payload_type = openapi_data.get("payload_type", "flat")
            if not auth_type:
                auth_type = openapi_data.get("auth_type")
            if not api_key_header:
                api_key_header = openapi_data.get("api_key_header")
            service_name = openapi_data.get("service_name")

        if ast_data:
            if not primary_endpoint:
                primary_endpoint = ast_data.get("endpoint")
            if not payload_field:
                payload_field = ast_data.get("payload_field")
            if not auth_type:
                auth_type = ast_data.get("auth_type")
            if not service_name:
                service_name = ast_data.get("service_name")

        target = Target(
            url=self.base_url,
            repo_path=str(self.repo_path) if self.repo_path else None,
            endpoint=primary_endpoint,
            all_endpoints=all_endpoints,
            auth_type=(auth_type or "bearer").lower(),
            auth_token=auth_token_override or contract.get("auth_token") or discovered_token,
            basic_user=basic_user_override or contract.get("basic_user"),
            basic_pass=basic_pass_override or contract.get("basic_pass"),
            api_key_header=api_key_header or "X-API-Key",
            payload_field=payload_field or "query",
            payload_template=payload_template,
            payload_type=payload_type or "flat",
            health_path=health_path,
            service_name=service_name,
            canary=canary_override or contract.get("canary"),
        )
        return target
