from dataclasses import dataclass, field
from enum import Enum
import base64
import json
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    P0 = "P0"  # Must pass for "Safe to Ship"
    P1 = "P1"  # Advisory / Warning


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIPPED = "SKIPPED"


@dataclass
class CheckResult:
    id: str
    title: str
    severity: Severity
    status: Status
    message: str
    evidence: str = ""
    hint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "message": self.message,
            "evidence": self.evidence,
            "hint": self.hint,
            "metadata": self.metadata,
        }


@dataclass
class Target:
    url: str
    repo_path: str = "."
    endpoint: Optional[str] = None
    all_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    auth_type: str = "bearer"  # "bearer", "basic", "api_key", "none"
    auth_token: Optional[str] = None
    basic_user: Optional[str] = None
    basic_pass: Optional[str] = None
    api_key_header: str = "X-API-Key"
    payload_field: Optional[str] = None
    payload_template: Optional[str] = None
    service_name: Optional[str] = None
    canary: Optional[str] = None

    def get_auth_headers(self) -> Dict[str, str]:
        """Generate authentication headers based on configured auth_type."""
        auth_type_norm = (self.auth_type or "bearer").lower()
        if auth_type_norm == "bearer":
            if self.auth_token:
                return {"Authorization": f"Bearer {self.auth_token}"}
            return {}
        elif auth_type_norm == "basic":
            user = self.basic_user or ""
            pwd = self.basic_pass or ""
            creds = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
            return {"Authorization": f"Basic {creds}"}
        elif auth_type_norm in ("api_key", "apikey"):
            if self.auth_token:
                header_name = self.api_key_header or "X-API-Key"
                return {header_name: self.auth_token}
            return {}
        return {}

    def build_payload(self, prompt: str) -> Dict[str, Any]:
        """
        Construct request body. If payload_template is defined (JSON with {{PROMPT}}),
        substitute prompt. Otherwise use payload_field or default to 'query'.
        """
        if self.payload_template:
            try:
                raw = self.payload_template.replace("{{PROMPT}}", json.dumps(prompt)[1:-1])
                return json.loads(raw)
            except Exception:
                pass
        field_name = self.payload_field or "query"
        return {field_name: prompt}
