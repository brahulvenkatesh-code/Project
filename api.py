"""
api.py — Public POST Endpoint (Submission Requirement)
Run alongside Streamlit: uvicorn api:app --port 8001
"""
import os, json, time, re, logging
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ps2-api")

from security import validate_json_input, run_risk_engine, build_llm_safe_payload, SecurityError

BEARER_TOKEN = os.environ.get("API_BEARER_TOKEN", "giggso-ps2-secret-token")
RATE_LIMIT   = 5
_rate: dict  = defaultdict(list)

app = FastAPI(title="PS2 Public API", version="3.0.0", docs_url=None, redoc_url=None)

def auth(authorization: str = Header(...)):
    if not authorization.startswith("Bearer ") or authorization.split(" ",1)[1].strip() != BEARER_TOKEN:
        raise HTTPException(401, detail="Invalid metric input")

def rate(ip: str):
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now-t < 60]
    if len(_rate[ip]) >= RATE_LIMIT:
        raise HTTPException(429, detail="Invalid metric input")
    _rate[ip].append(now)

class AnalyzeReq(BaseModel):
    metrics_json: str

    @field_validator("metrics_json")
    @classmethod
    def chk(cls, v):
        if len(v.encode()) > 10_000:
            raise ValueError("Invalid metric input")
        try: json.loads(v)
        except: raise ValueError("Invalid metric input")
        return v

@app.post("/analyze")
async def analyze(req: AnalyzeReq, request: Request,
                  authorization: str = Header(...)):
    auth(authorization)
    rate(request.client.host)
    logger.info(f"POST /analyze ip={request.client.host} size={len(req.metrics_json.encode())}B")
    try:
        cleaned = validate_json_input(req.metrics_json)
        risk    = run_risk_engine(cleaned)
        payload = build_llm_safe_payload(cleaned)
    except SecurityError as e:
        logger.warning(f"Validation fail: {e.internal}")
        raise HTTPException(422, detail="Invalid metric input")
    return {
        "status":       "ok",
        "risk_level":   risk["level"],
        "triggered_rules": risk["triggered"],
        "recommendations": risk["recommendations"],
        "metrics_keys": list(cleaned.keys()),
        "llm_payload_preview": payload[:200] + "..." if len(payload) > 200 else payload,
        "note": "Full explanation available via Streamlit UI. Risk determined by deterministic engine.",
    }

@app.get("/health")
async def health():
    return {"status": "ok", "service": "PS2-ModelPerformanceExplainer",
            "bot": "NanoBot", "version": "3.0.0"}

@app.exception_handler(Exception)
async def handler(req, exc):
    logger.error(f"Unhandled: {exc}")
    return JSONResponse(500, content={"detail": "Invalid metric input"})