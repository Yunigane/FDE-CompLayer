"""
Minimal Compliant Reference App: Internal SQL Explainer Service
Complies with platform baseline:
- Enforces Bearer token authentication (fails fast on missing secret configuration)
- Generates and forwards X-Request-ID correlation headers
- Uses monotonic time.perf_counter() for precise, drift-resistant latency logging
- Emits structured JSON logs
- Rejects prompt injections with HTTP 400 Bad Request
- Fails loudly with HTTP 502 Bad Gateway on upstream LLM outages
- Provides /health liveness probe
"""
import os
import sys
import time
import uuid
import json
import logging
from typing import Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Security, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from app.mock_llm import generate_sql_explanation, PromptInjectionError, UpstreamLLMError

# --- Load Environment Configuration ---
load_dotenv()

# --- Structured JSON Logger Setup ---
class JSONLogFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "request_id": getattr(record, "request_id", None)
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

logger = logging.getLogger("sql_explainer")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONLogFormatter())
logger.handlers = [handler]
logger.propagate = False

# --- App Initialization ---
app = FastAPI(
    title="SQL Explainer Service",
    description="Internal AI assistant that explains SQL queries.",
    version="1.0.0"
)

# --- Authentication Configuration (Fail Fast on Startup) ---
VALID_BEARER_TOKEN = os.environ.get("APP_BEARER_TOKEN")
if not VALID_BEARER_TOKEN:
    raise RuntimeError(
        "FATAL: APP_BEARER_TOKEN environment variable must be set. "
        "Application will not start without valid authentication configuration."
    )

security = HTTPBearer(auto_error=False)

def verify_bearer_token(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)):
    """
    Enforces Bearer authentication. Returns 401 if missing or invalid.
    """
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. Expected 'Bearer <token>'."
        )
    if credentials.credentials != VALID_BEARER_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Invalid or unauthorized Bearer token."
        )
    return credentials.credentials

# --- Observability Middleware ---
@app.middleware("http")
async def correlation_id_and_logging_middleware(request: Request, call_next):
    # Extract or generate X-Request-ID
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    
    # Monotonic high-resolution timer (resilient to NTP clock drift)
    start_time = time.perf_counter()

    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # Attach correlation header to outgoing response
    response.headers["X-Request-ID"] = request_id

    # Emit structured JSON access log
    logger.info(
        f"{request.method} {request.url.path} returned {response.status_code} in {duration_ms}ms",
        extra={"request_id": request_id}
    )
    return response

# --- Schemas ---
class ExplainRequest(BaseModel):
    query: str = Field(..., description="The SQL query to explain", min_length=3)

class ExplainResponse(BaseModel):
    status: str
    explanation: Optional[str]
    model: str
    flagged_injection: bool

# --- Endpoints ---
@app.get("/health", tags=["Observability"])
def health_check():
    """Unauthenticated health probe endpoint for container orchestrators."""
    return {
        "status": "healthy",
        "service": "sql-explainer",
        "version": "1.0.0"
    }

@app.post("/api/v1/explain-sql", response_model=ExplainResponse, tags=["AI Service"])
def explain_sql(req: ExplainRequest, response: Response, token: str = Depends(verify_bearer_token)):
    """
    Analyzes and explains a SQL query. Requires valid Bearer authentication.
    Rejects prompt injections with HTTP 400 Bad Request.
    Fails loudly with HTTP 502 Bad Gateway on upstream LLM outages.
    """
    try:
        result = generate_sql_explanation(req.query)
        return ExplainResponse(**result)
    except PromptInjectionError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Security Guardrail Violation: {exc}",
            headers={"X-Guardrail-Action": "blocked"}
        ) from exc
    except UpstreamLLMError as exc:
        logger.error(f"Upstream LLM Provider Failure: {exc}")
        raise HTTPException(
            status_code=502,
            detail="Upstream AI provider unavailable. Failed to generate explanation."
        ) from exc
