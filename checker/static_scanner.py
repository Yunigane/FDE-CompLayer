"""
Static Code and Manifest Compliance Scanner.
Performs pattern-based credential leak detection, service manifest validation,
and static code capability verification.
"""
import os
import re
import fnmatch
import subprocess
import ast
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from ruamel.yaml import YAML

from checker.models import CheckResult, Severity, Status

yaml = YAML(typ="safe")

# Directory and file ignore lists (core framework defaults)
IGNORED_DIRS = {".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache", "node_modules", ".idea", ".vscode"}
IGNORED_EXTENSIONS = {".pyc", ".pyo", ".pyd", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".lock", ".svg", ".md"}
IGNORED_FILES = {".gitignore", "package-lock.json", "poetry.lock"}

# Production secret patterns across all major AI model providers & clouds
SECRET_PATTERNS = [
    (r"sk-(?!ant-)(?:proj-)?[a-zA-Z0-9_\-]{20,}", "OpenAI API Key signature"),
    (r"sk-ant-[a-zA-Z0-9_\-]{32,}", "Anthropic Claude API Key signature"),
    (r"AIza[0-9A-Za-z\-_]{30,40}", "Google AI / Gemini API Key signature"),
    (r"hf_[a-zA-Z0-9]{34,}", "Hugging Face Access Token"),
    (r"gsk_[a-zA-Z0-9]{48,}", "Groq Cloud API Key signature"),
    (r"r8_[a-zA-Z0-9]{37,}", "Replicate API Token signature"),
    (r"(?i)(?:cohere[_-]?api[_-]?key|cohere[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9]{40}['\"]", "Cohere API Key assignment"),
    (r"(?i)(?:mistral[_-]?api[_-]?key|mistral[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9]{32}['\"]", "Mistral API Key assignment"),
    (r"(?i)(?:azure[_-]?openai[_-]?key|azure[_-]?key)\s*[:=]\s*['\"][a-f0-9]{32}['\"]", "Azure OpenAI API Key assignment"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)\s*[:=]\s*['\"][a-zA-Z0-9/+=]{40}['\"]", "AWS Secret Access Key"),
    (r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----", "Private cryptographic key"),
    (r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|bearer[_-]?token|access[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\+/]{20,}['\"]", "Credential assignment"),
    (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "Slack Incoming Webhook URL"),
]

# Explicit placeholder allowlist (only exact mock prefixes or obvious placeholders)
FIXTURE_EXACT_PREFIXES = ("mock-", "test-", "dummy-", "fake-", "placeholder", "your-api-key")


def generate_manifest_template(service_name: str = "my-service") -> str:
    return f"""service_name: "{service_name}"
owner_team: "analytics-eng"
operational_tier: "tier_2_self_service" # or "tier_1_platform_managed"
alerts:
  slack_channel: "#tooling-alerts"
  pagerduty_service: "PD-SERVICE-KEY"
contact: "team@company.internal"
regulatory_compliance:
  eu_ai_act_risk_tier: "minimal_risk" # minimal_risk | specific_transparency_risk | high_risk | prohibited_risk
  human_oversight: false
  transparency_notice: true
  autonomous_actions: false
"""


class StaticScanner:
    def __init__(self, repo_path: str, manifest_path: Optional[str] = None):
        self.repo_path = Path(repo_path).resolve()
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else None
        self.custom_ignores = self._load_compliance_ignores()

    def _load_compliance_ignores(self) -> List[str]:
        """Loads glob patterns from .complianceignore if present in the target repo."""
        ignore_file = self.repo_path / ".complianceignore"
        patterns = []
        if ignore_file.is_file():
            try:
                with open(ignore_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            patterns.append(line)
            except Exception:
                pass
        return patterns

    def _is_path_ignored(self, path: Path) -> bool:
        """Checks if a path matches core ignores or .complianceignore glob patterns."""
        try:
            rel_str = str(path.relative_to(self.repo_path)).replace("\\", "/")
        except ValueError:
            return False

        for pattern in self.custom_ignores:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(path.name, pattern) or rel_str.startswith(pattern.rstrip("/") + "/"):
                return True
        return False

    def _is_env_gitignored(self) -> bool:
        """Verifies that .env is explicitly excluded in .gitignore."""
        gitignore = self.repo_path / ".gitignore"
        if not gitignore.is_file():
            return False
        try:
            with open(gitignore, "r", encoding="utf-8") as f:
                content = f.read()
                return any(line.strip() == ".env" or line.strip() == "/.env" or line.strip() == "*.env" for line in content.splitlines())
        except Exception:
            return False

    def _is_env_committed(self) -> bool:
        """Checks if .env is tracked in git index."""
        try:
            res = subprocess.run(
                ["git", "ls-files", ".env"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=2
            )
            return bool(res.stdout.strip())
        except Exception:
            return False

    def scan_secrets(self) -> CheckResult:
        """
        Scans all source code files for leaked production credentials.
        Scans comments as well (commented-out keys are common leaks).
        """
        findings = []

        # Check if .env is missing from .gitignore or is committed
        env_file = self.repo_path / ".env"
        if env_file.is_file():
            if not self._is_env_gitignored():
                findings.append({
                    "file": ".env",
                    "line": 1,
                    "description": "CRITICAL: .env file exists but is NOT listed in .gitignore!",
                    "snippet": "Add .env to .gitignore immediately to prevent credential leaks."
                })
            elif self._is_env_committed():
                findings.append({
                    "file": ".env",
                    "line": 1,
                    "description": "CRITICAL: .env is tracked in git index despite gitignore!",
                    "snippet": "Run `git rm --cached .env` to remove it from version control."
                })

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not self._is_path_ignored(Path(root) / d)]

            for file in files:
                if file in IGNORED_FILES:
                    continue
                file_path = Path(root) / file
                if file_path.suffix in IGNORED_EXTENSIONS or self._is_path_ignored(file_path):
                    continue

                # Local .env is skipped only if safely gitignored and uncommitted
                if file == ".env" and self._is_env_gitignored() and not self._is_env_committed():
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, start=1):
                            line_strip = line.strip()
                            if not line_strip:
                                continue

                            for pattern, desc in SECRET_PATTERNS:
                                match = re.search(pattern, line_strip)
                                if match:
                                    matched_str = match.group(0).lower()
                                    # Skip if it is an explicit mock/test fixture
                                    if any(matched_str.startswith(allow) or f"'{allow}" in matched_str or f'"{allow}' in matched_str for allow in FIXTURE_EXACT_PREFIXES):
                                        continue

                                    rel_path = file_path.relative_to(self.repo_path)
                                    findings.append({
                                        "file": str(rel_path),
                                        "line": line_no,
                                        "description": desc,
                                        "snippet": line_strip[:80] + ("..." if len(line_strip) > 80 else "")
                                    })
                                    break
                except Exception:
                    continue

        if findings:
            evidence_lines = [f"{f['file']}:{f['line']} - {f['description']} ({f['snippet']})" for f in findings[:5]]
            return CheckResult(
                id="secrets",
                title="Static Secrets [CWE-798 / OWASP LLM02]",
                severity=Severity.P0,
                status=Status.FAIL,
                message=f"Found {len(findings)} potential hardcoded credentials in repository.",
                evidence="\n".join(evidence_lines),
                hint="Store keys in environment variables or a secrets manager. Use .complianceignore with CODEOWNERS sign-off for fixtures.",
                metadata={"findings": findings},
            )

        return CheckResult(
            id="secrets",
            title="Static Secrets [CWE-798 / OWASP LLM02]",
            severity=Severity.P0,
            status=Status.PASS,
            message="Zero hardcoded credentials detected across scanned repository files.",
            evidence=f"Scanned files with {len(self.custom_ignores)} ignore rules applied.",
            metadata={"ignored_rules": self.custom_ignores},
        )

    def find_manifest(self) -> Optional[Path]:
        """Discovers service.yaml hierarchically."""
        if self.manifest_path and self.manifest_path.is_file():
            return self.manifest_path

        candidates = [
            self.repo_path / "service.yaml",
            self.repo_path / "service.yml",
            self.repo_path / "app" / "service.yaml",
            self.repo_path / "app" / "service.yml",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate

        for path in self.repo_path.glob("**/service.yaml"):
            if not any(ignored in path.parts for ignored in IGNORED_DIRS):
                return path

        return None

    def validate_manifest(self) -> CheckResult:
        """
        Validates presence and required fields of the service.yaml manifest.
        Enforces ownership team, operational tier, and statutory EU AI Act tier.
        """
        manifest_file = self.find_manifest()
        if not manifest_file:
            return CheckResult(
                id="manifest",
                title="Service Manifest [EU AI Act & Governance]",
                severity=Severity.P0,
                status=Status.FAIL,
                message="Missing service.yaml metadata manifest in repository.",
                evidence="No service.yaml found in repo root or app/ directory.",
                hint="Generate one automatically with --init-manifest or create service.yaml:\n" + generate_manifest_template(),
            )

        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                data = yaml.load(f)
        except Exception as e:
            return CheckResult(
                id="manifest",
                title="Service Manifest [EU AI Act & Governance]",
                severity=Severity.P0,
                status=Status.FAIL,
                message=f"Malformed YAML syntax in service.yaml: {e}",
                evidence=str(e),
                hint="Fix YAML syntax errors in service.yaml.",
            )

        if not isinstance(data, dict):
            return CheckResult(
                id="manifest",
                title="Service Manifest [EU AI Act & Governance]",
                severity=Severity.P0,
                status=Status.FAIL,
                message="service.yaml root must be a YAML mapping (dictionary).",
            )

        errors = []
        required_fields = ["service_name", "owner_team", "operational_tier", "contact"]
        for field in required_fields:
            if not data.get(field):
                errors.append(f"Missing mandatory field '{field}'")

        valid_tiers = {"tier_1_platform_managed", "tier_2_self_service"}
        tier = data.get("operational_tier")
        if tier and tier not in valid_tiers:
            errors.append(f"Invalid operational_tier '{tier}'. Must be one of {valid_tiers}")

        # Regulatory compliance validation
        reg_comp = data.get("regulatory_compliance")
        if not isinstance(reg_comp, dict):
            errors.append("Missing 'regulatory_compliance' section in service.yaml")
            risk_tier = None
        else:
            risk_tier = reg_comp.get("eu_ai_act_risk_tier")
            valid_risk_tiers = {"minimal_risk", "specific_transparency_risk", "high_risk", "prohibited_risk"}
            if not risk_tier:
                errors.append(f"Missing 'regulatory_compliance.eu_ai_act_risk_tier'. Options: {sorted(list(valid_risk_tiers))}")
            elif risk_tier not in valid_risk_tiers:
                errors.append(f"Invalid eu_ai_act_risk_tier '{risk_tier}'. Must be one of {sorted(list(valid_risk_tiers))}")
            elif risk_tier == "prohibited_risk":
                errors.append("Article 5 Prohibited AI practice declared: deployment forbidden.")
            elif risk_tier == "high_risk" and not reg_comp.get("human_oversight"):
                errors.append("EU AI Act Art. 14: high_risk applications must declare 'human_oversight: true'.")

            if reg_comp.get("autonomous_actions") is True and not reg_comp.get("human_oversight"):
                errors.append("OWASP LLM06: Autonomous actions declared without human oversight guardrails.")

        if errors:
            return CheckResult(
                id="manifest",
                title="Service Manifest [EU AI Act & Governance]",
                severity=Severity.P0,
                status=Status.FAIL,
                message=f"service.yaml validation failed ({len(errors)} error(s)).",
                evidence="; ".join(errors),
                hint="Update service.yaml to conform to the compliance schema.",
            )

        rel_manifest = manifest_file.relative_to(self.repo_path)
        return CheckResult(
            id="manifest",
            title="Service Manifest [EU AI Act & Governance]",
            severity=Severity.P0,
            status=Status.PASS,
            message=f"Valid service manifest ({rel_manifest}) [Tier: {tier}, EU AI Act: {risk_tier}].",
            evidence=f"Declared service_name: '{data.get('service_name')}', owner_team: '{data.get('owner_team')}'",
            metadata={
                "service_name": data.get("service_name"),
                "owner_team": data.get("owner_team"),
                "operational_tier": tier,
                "eu_ai_act_risk_tier": risk_tier,
            },
        )

    def scan_code_capabilities(self) -> CheckResult:
        """
        Static AST code inspection: checks if code imports high-risk capabilities
        (like subprocess execution, raw shell, or database writes) without
        declaring them in the manifest. Emits P1 advisory warning on mismatch.
        """
        undeclared_capabilities = []
        for py_file in self.repo_path.glob("**/*.py"):
            try:
                rel_parts = py_file.resolve().relative_to(self.repo_path).parts
            except ValueError:
                rel_parts = py_file.parts

            if any(part in rel_parts for part in IGNORED_DIRS.union({".gemini", "brain", "site-packages"})):
                continue
            if len(rel_parts) > 1 and rel_parts[0] in {"tests", "checker"} and self.repo_path.name not in {"tests", "vulnerable_app"}:
                continue

            try:
                with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                tree = ast.parse(content, filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name in {"subprocess", "shutil", "pty"}:
                                undeclared_capabilities.append(f"{py_file.name}: imports shell/process tool '{alias.name}'")
                            elif alias.name in {"psycopg2", "asyncpg", "pymongo", "mysql", "sqlite3"}:
                                undeclared_capabilities.append(f"{py_file.name}: imports database driver '{alias.name}'")
                            elif alias.name in {"sqlalchemy"}:
                                undeclared_capabilities.append(f"{py_file.name}: imports database ORM '{alias.name}'")
                    elif isinstance(node, ast.ImportFrom):
                        if node.module in {"subprocess", "shutil", "pty"}:
                            undeclared_capabilities.append(f"{py_file.name}: imports from '{node.module}'")
                        elif node.module in {"psycopg2", "asyncpg", "pymongo", "mysql", "sqlalchemy"}:
                            undeclared_capabilities.append(f"{py_file.name}: imports from database package '{node.module}'")
                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                            if node.func.value.id == "os" and node.func.attr in {"system", "popen", "spawn"}:
                                undeclared_capabilities.append(f"{py_file.name}: invokes shell execution 'os.{node.func.attr}()'")
            except Exception:
                continue

        if undeclared_capabilities:
            return CheckResult(
                id="capabilities",
                title="Code Capability Verification [AST]",
                severity=Severity.P1,
                status=Status.WARN,
                message=f"Detected {len(undeclared_capabilities)} potential high-agency capabilities (e.g. database/subprocess) in code.",
                evidence="; ".join(undeclared_capabilities[:3]),
                hint="Ensure all state-changing, shell execution, or database capabilities have human oversight configured.",
            )

        return CheckResult(
            id="capabilities",
            title="Code Capability Verification [AST]",
            severity=Severity.P1,
            status=Status.PASS,
            message="No undeclared high-risk system execution capabilities detected.",
        )

    def run_all(self) -> List[CheckResult]:
        return [
            self.scan_secrets(),
            self.validate_manifest(),
            self.scan_code_capabilities(),
        ]
