import os
import logging
import json
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from security import parse_and_validate, safe_token_compare
from access_control import AccessManager, get_current_user_payload
from nanobot_service import NanoBotService, bridge_risk_to_nanobot
import jwt
from datetime import datetime, timedelta, timezone
import base64
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ps2-api")

API_USERNAME = os.environ.get("API_USERNAME", "admin")
API_PASSWORD = os.environ.get("API_PASSWORD", "supersecurepassword")
API_JWT_SECRET = os.environ.get("API_JWT_SECRET", "super-secret-risk-governance-key")

# ── Decision Bridge: Stores last decision per session for simplified chat ─────
# In a real enterprise app, use Redis/Postgres. For this challenge: in-memory.
DECISION_STORE: dict[str, dict] = {}

app = FastAPI(docs_url=None, redoc_url=None)  # disable swagger in prod

# Layer 1: Enhanced rate limit key (fix X-Forwarded-For bypass)
def get_real_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Take only the LAST entry — attacker controls earlier ones
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"

limiter = Limiter(key_func=get_real_ip)
app.state.limiter = limiter

# ── Global exception handler — no stack traces leak ──────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {type(exc).__name__}: {str(exc)}")
    return JSONResponse(status_code=500, content={"error": "Invalid metric input"})

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Hide details even for 401/422 to prevent brute-forcing/discovery
    return JSONResponse(status_code=exc.status_code, content={"error": "Invalid metric input"})

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})

# Host validation removed for simplified manual setup

# ── Middleware: strip version headers ─────────────────────────────────────────
@app.middleware("http")
async def strip_info_headers(request: Request, call_next):
    response = await call_next(request)
    if "server" in response.headers:
        del response.headers["server"]
    if "x-powered-by" in response.headers:
        del response.headers["x-powered-by"]
    return response

# Auth dependency removed in favor of access_control.py

# ── Main endpoint ─────────────────────────────────────────────────────────────
@app.post("/api/token")
@limiter.limit("10/minute")
async def login(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Missing or invalid Basic auth header")
    
    try:
        # Decode the Base64 credentials
        b64_creds = authorization[6:]
        decoded_creds = base64.b64decode(b64_creds).decode("utf-8")
        username, password = decoded_creds.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Basic auth format")
        
    if not safe_token_compare(username, API_USERNAME) or not safe_token_compare(password, API_PASSWORD):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Generate JWT token valid for 1 hour with Role
    token_data = {
        "sub": username,
        "role": "ADMIN" if username == "admin" else "USER"
    }
    encoded_jwt = AccessManager.create_access_token(token_data)
    
    return {"access_token": encoded_jwt, "token_type": "bearer"}

@app.post("/api/analyze")
@limiter.limit("20/minute")
async def analyze(request: Request, authorization: str = Header(..., alias="Authorization")):
    # Verify and check permission
    user_payload = get_current_user_payload(authorization)
    AccessManager.check_permissions(user_payload, "analyze")

    raw = await request.body()
    try:
        metrics = parse_and_validate(raw)        # raises on any violation
    except Exception as e:
        logger.warning(f"Validation fail: {e}")
        return JSONResponse(status_code=422, content={"error": "Invalid metric input"})
        
    from risk_engine import calculate_risk
    # Get the deterministic score + audit trace
    decision = calculate_risk(metrics)
    
    # Audit log (append-only mock)
    logger.info(f"AUDIT | Decision {decision['decision_id']} made by {user_payload.get('sub')} at {decision['timestamp']}")
    logger.info(f"TRACE | Decision {decision['decision_id']}: {json.dumps(decision['rule_trace'])}")

    # Store for simplified chat bridge
    session_id = metrics.get("session_id", "default_session")
    DECISION_STORE[session_id] = decision

    return {
        "status": "ok",
        "decision": decision
    }

@app.post("/api/explain")
@limiter.limit("20/minute")
async def explain(request: Request, authorization: str = Header(..., alias="Authorization")):
    # Verify and check permission (Read-Only)
    user_payload = get_current_user_payload(authorization)
    
    body = await request.json()
    
    # Support both "question" and "message" keys for user convenience
    user_context = body.get("message") or body.get("question", "")
    session_id   = body.get("session_id")
    decision_snapshot = body.get("decision")

    # If no decision snapshot provided, try to look up from DecisionStore via session_id
    if not decision_snapshot and session_id:
        decision_snapshot = DECISION_STORE.get(session_id)
        if not decision_snapshot:
            raise HTTPException(status_code=404, detail="No recent decision found for this session_id. Run analysis first.")

    if not decision_snapshot:
        raise HTTPException(status_code=400, detail="Missing decision snapshot or session_id")

    # Strict isolation: Use the read-only bridge
    safe_snapshot = bridge_risk_to_nanobot(decision_snapshot)
    
    # Generate explanation via NanoBot Service
    explanation = await NanoBotService.explain_decision(safe_snapshot, user_context)

    # Log explanation event
    logger.info(f"AUDIT | NanoBot accessed decision {safe_snapshot.get('decision_id')} requested by {user_payload.get('sub')}")

    return {
        "status": "ok",
        "decision_id": safe_snapshot.get("decision_id"),
        "explanation": explanation
    }

@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.1.0"}