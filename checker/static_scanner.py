"""
Static Code and Manifest Compliance Scanner.
Performs regex-based credential leak detection, service manifest validation,
and static code observability analysis.
"""
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from ruamel.yaml import YAML

yaml = YAML(typ="safe")

# Directory and file ignore lists (core framework defaults)
IGNORED_DIRS = {".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache", "node_modules", ".idea", ".vscode"}
IGNORED_EXTENSIONS = {".pyc", ".pyo", ".pyd", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".lock", ".svg"}
IGNORED_FILES = {".gitignore", "package-lock.json", "poetry.lock"}

# High-entropy production secret signatures
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9_-]{24,}", "OpenAI API Key signature"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----", "Private cryptographic key"),
    (r"(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]", "High-entropy credential assignment"),
]

# Patterns explicitly whitelisted as test fixtures to prevent false positives
FIXTURE_ALLOWLIST = [
    r"mock[-_]",
    r"test[-_]",
    r"dummy[-_]",
    r"fake[-_]",
    r"placeholder",
    r"example",
]


class StaticScanner:
    def __init__(self, repo_path: str, manifest_path: Optional[str] = None):
        self.repo_path = Path(repo_path).resolve()
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else None
        self.custom_ignores = self._load_compliance_ignores()

    def _load_compliance_ignores(self) -> set:
        """Loads custom patterns from .complianceignore if present in the target repo."""
        ignore_file = self.repo_path / ".complianceignore"
        patterns = set()
        if ignore_file.is_file():
            try:
                with open(ignore_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().rstrip("/")
                        if line and not line.startswith("#"):
                            patterns.add(line)
            except Exception:
                pass
        return patterns

    def _is_path_ignored(self, path: Path) -> bool:
        """Checks if a path matches core ignores or .complianceignore rules."""
        rel_str = str(path.relative_to(self.repo_path)).replace("\\", "/")
        for pattern in self.custom_ignores:
            if pattern in rel_str or rel_str.startswith(pattern):
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
                return ".env" in content
        except Exception:
            return False

    def scan_secrets(self) -> Dict[str, Any]:
        """
        Scans all source code files for leaked production credentials.
        Excludes explicit test fixtures (mock-*, test-*, dummy-*).
        """
        findings = []

        # Check if .env is missing from .gitignore
        env_file = self.repo_path / ".env"
        if env_file.is_file() and not self._is_env_gitignored():
            findings.append({
                "file": ".env",
                "line": 1,
                "description": "CRITICAL: .env file exists in repository root but is NOT listed in .gitignore!",
                "snippet": "Add .env to .gitignore immediately to prevent credential leaks."
            })

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not self._is_path_ignored(Path(root) / d)]

            for file in files:
                if file in IGNORED_FILES:
                    continue
                file_path = Path(root) / file
                if file_path.suffix in IGNORED_EXTENSIONS or self._is_path_ignored(file_path):
                    continue

                # Local .env is skipped only if safely gitignored
                if file == ".env" and self._is_env_gitignored():
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, start=1):
                            line_strip = line.strip()
                            if not line_strip or line_strip.startswith("#") or line_strip.startswith("//"):
                                continue

                            for pattern, desc in SECRET_PATTERNS:
                                match = re.search(pattern, line_strip)
                                if match:
                                    matched_str = match.group(0).lower()
                                    # Check if match is a test fixture
                                    if any(re.search(allow, matched_str) for allow in FIXTURE_ALLOWLIST):
                                        continue

                                    rel_path = file_path.relative_to(self.repo_path)
                                    findings.append({
                                        "file": str(rel_path),
                                        "line": line_no,
                                        "description": desc,
                                        "snippet": line_strip[:80] + ("..." if len(line_strip) > 80 else "")
                                    })
                except Exception:
                    continue

        if findings:
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": f"Found {len(findings)} potential hardcoded secrets in repository.",
                "findings": findings
            }
        return {
            "status": "PASS",
            "severity": "P0",
            "message": "Zero hardcoded secrets detected across scanned files.",
            "findings": []
        }

    def find_manifest(self) -> Optional[Path]:
        """
        Discovers service.yaml hierarchically:
        1. Explicit manifest_path argument
        2. Root service.yaml or service.yml
        3. app/service.yaml or services/*/service.yaml
        """
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

    def validate_manifest(self) -> Dict[str, Any]:
        """
        Validates presence and required fields of the service.yaml manifest.
        Enforces ownership team, operational tier, and alerting contacts.
        """
        manifest_file = self.find_manifest()
        if not manifest_file:
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": "Missing service.yaml metadata manifest in repository.",
                "details": "Every service must declare ownership, tier, and contact in a service.yaml file."
            }

        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                data = yaml.load(f)
        except Exception as e:
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": f"Malformed service.yaml: {e}",
                "details": str(e)
            }

        if not isinstance(data, dict):
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": "service.yaml must contain a YAML mapping (dictionary).",
                "details": None
            }

        required_fields = ["service_name", "owner_team", "operational_tier", "contact"]
        missing = [field for field in required_fields if not data.get(field)]
        if missing:
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": f"service.yaml missing mandatory fields: {', '.join(missing)}",
                "details": f"Missing: {missing}"
            }

        valid_tiers = {"tier_1_platform_managed", "tier_2_self_service"}
        tier = data.get("operational_tier")
        if tier not in valid_tiers:
            return {
                "status": "FAIL",
                "severity": "P0",
                "message": f"Invalid operational_tier: '{tier}'. Must be one of {valid_tiers}.",
                "details": f"Provided tier: {tier}"
            }

        rel_manifest = manifest_file.relative_to(self.repo_path)
        return {
            "status": "PASS",
            "severity": "P0",
            "message": f"Valid service manifest detected ({rel_manifest}) for owner '{data.get('owner_team')}'.",
            "data": {
                "service_name": data.get("service_name"),
                "owner_team": data.get("owner_team"),
                "operational_tier": tier,
                "contact": data.get("contact")
            }
        }

    def run_all(self) -> Dict[str, Any]:
        """Runs all static checks and aggregates results."""
        secrets_res = self.scan_secrets()
        manifest_res = self.validate_manifest()

        passed = (secrets_res["status"] == "PASS") and (manifest_res["status"] == "PASS")
        return {
            "passed": passed,
            "checks": {
                "static_secrets": secrets_res,
                "static_manifest": manifest_res
            }
        }
