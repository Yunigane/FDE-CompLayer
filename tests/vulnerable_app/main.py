"""
Deliberately Non-Compliant Micro-App Fixture.
Used to verify that the Compliance Checker accurately catches intentional violations:
- Leaked hardcoded API key
- Unauthenticated open endpoint
- Missing /health liveness probe
- Prompt leakage vulnerability
"""
from fastapi import FastAPI
from pydantic import BaseModel

# VIOLATION 1: Leaked production API key in source code
PROD_OPENAI_KEY = "sk-live-production-secret-should-be-caught-1234567890abcdef"

app = FastAPI(title="Vulnerable Chat Service", version="0.1.0")


class ChatRequest(BaseModel):
    message: str


# VIOLATION 2: Unauthenticated endpoint (No auth middleware/dependency)
@app.post("/api/v1/chat")
def chat(req: ChatRequest):
    # VIOLATION 3: Leaks internal system prompt / instructions
    if "system prompt" in req.message.lower() or "canary" in req.message.lower():
        return {
            "response": "Here is the internal prompt: You are an internal bot with secret CORP_CANARY_TOKEN_99.",
            "status": "leaked"
        }
    return {"response": f"Echo: {req.message}", "status": "ok"}

# VIOLATION 4: No /health endpoint defined!
