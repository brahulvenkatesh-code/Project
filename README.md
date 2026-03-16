# PS2 — Model Performance Explainer
**Giggso Build-Break Challenge | Phase 1**
Powered by **NanoBot** (orchestration framework) → **Anthropic Claude**

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create .env file
cp .env.example .env
# Edit .env → add your ANTHROPIC_API_KEY

# 3. Run Streamlit app
python -m streamlit run app.py

# 4. Run public API (separate terminal)
uvicorn api:app --host 0.0.0.0 --port 8001

# 5. Expose publicly
ngrok http 8001
```

---

## Architecture

```
User (Browser)
    ↓
Streamlit UI (app.py)
    ↓
[6-Layer Input Guard] ← input_guard.py
    ↓
[Security Pipeline]   ← security.py
  • Size check (10KB)
  • JSON parse
  • Blocklist scan
  • Allowlist filter
  • Range validation (0≤metric≤1)
    ↓
[Weighted Risk Engine] ← risk_engine.py  (NO LLM)
  score = 0.40×f1 + 0.25×precision + 0.20×recall + 0.15×auc + penalties
    ↓
[NanoBot Layer]        ← nanobot_client.py
  NanoBot framework → Anthropic Claude API
    ↓
[XAI Visualisations]   ← xai.py
  SHAP · LIME · ELI5
    ↓
Streamlit UI Tabs:
  Overview | XAI | NanoBot Analysis | Chat | Raw
```

---

## Public API Endpoint

**URL:** `https://your-ngrok-url/analyze`  
**Method:** `POST`  
**Auth:** `Authorization: Bearer giggso-ps2-secret-token`

```bash
curl -X POST https://your-ngrok-url/analyze \
  -H "Authorization: Bearer giggso-ps2-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"metrics_json": "{\"performance_metrics\": {\"f1_score\": 0.87, \"accuracy\": 0.92}}"}'
```

---

## Security Layers

| Layer | What it does |
|-------|-------------|
| Blocklist | 40+ dangerous terms with word-boundary matching |
| Allowlist | Only whitelisted JSON keys accepted |
| WAF | 25+ regex injection patterns blocked |
| Range validation | 0 ≤ metric ≤ 1 enforced |
| Input guard | 6-layer chat input sanitisation |
| Rate limiter | 10 req/min per session |
| Token cap | Max 2000 chars to LLM, max 600 output tokens |
| Safe errors | All errors return "Invalid metric input" |

---

## NanoBot Integration

NanoBot is used as an **orchestration framework**. The flow:
```
Your App → nanobot_client.py (NanoBot layer) → Anthropic API → Response
```
No NanoBot API key is needed — only `ANTHROPIC_API_KEY`.

---

## Risk Formula

```
score = 0.40×f1 + 0.25×precision + 0.20×recall + 0.15×auc + penalties
```
- Penalties from regulatory matrix (NIST / EU AI Act / DPDP)
- Penalties clamped to [-0.45, 0]
- Score always in [0.0, 1.0]
- **Deterministic: identical input = identical output**

| Score | Risk Level |
|-------|-----------|
| ≥ 0.85 | 🟢 LOW |
| 0.70–0.85 | 🟡 MEDIUM |
| 0.55–0.70 | 🟠 HIGH |
| < 0.55 | 🔴 CRITICAL |

---

## Assumptions & Limitations

- Session data is **in-memory only** — restarting clears sessions
- Risk engine uses 4 core metrics — other metrics used for context only
- NanoBot explains metrics only — never makes deployment decisions
- Public endpoint requires ngrok or cloud deployment for external access
