import os
import logging
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from security import parse_and_validate, safe_token_compare

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ps2-api")

API_TOKEN    = os.environ.get("API_BEARER_TOKEN", "giggso-ps2-secret-token")
# ALLOWED_HOST removed for simplicity

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
    response.headers.pop("server", None)
    response.headers.pop("x-powered-by", None)
    return response

# ── Auth dependency ───────────────────────────────────────────────────────────
def require_auth(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid metric input")
    token = authorization[7:]
    if not safe_token_compare(token, API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid metric input")

# ── Main endpoint ─────────────────────────────────────────────────────────────
@app.post("/api/analyze")
@limiter.limit("5/minute")
async def analyze(request: Request, authorization: str = Header(...)):
    require_auth(authorization)
    raw = await request.body()
    try:
        metrics = parse_and_validate(raw)        # raises on any violation
    except ValueError as e:
        logger.warning(f"Validation fail: {e}")
        return JSONResponse(status_code=422, content={"error": "Invalid metric input"})
        
    from risk_engine import calculate_risk
    # We use the calculate_risk helper which expects a dict
    risk_score = calculate_risk(metrics)
    
    return {
        "status": "ok",
        "risk_score": risk_score,
        "metrics": metrics
    }

@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.1.0"}