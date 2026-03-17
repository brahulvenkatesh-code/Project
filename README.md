# PS2 — Model Performance Explainer
**Giggso Build-Break Challenge | Phase 1**
Powered by **NanoBot** (orchestration layer) → **Google Gemini**

---

## 🚀 How to Run the Project

Follow these steps to set up and run the analysis tool on your local machine.

### 1. Environment Setup
We recommend using a virtual environment to manage dependencies.

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Mac/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Create a `.env` file in the root directory by copying the example.

```bash
cp .env.example .env
```
Open `.env` and add your **Google Gemini API Key**:
`GOOGLE_API_KEY=your_key_here`

### 3. Start the Backend API
The FastAPI backend handles metric validation and the deterministic risk engine.

```powershell
uvicorn api:app --host 127.0.0.1 --port 8001
```

### 4. Start the Streamlit UI
In a **new terminal** (ensure the virtual environment is activated):

```powershell
streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true
```

### 5. Expose Locally (Optional)
To share your local instance with reviewers, use `ngrok`:

```powershell
ngrok http 8501
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
  NanoBot framework → Google Gemini API
    ↓
[XAI Visualisations]   ← xai.py
  SHAP · LIME · ELI5
    ↓
Streamlit UI Tabs:
  Overview | XAI | NanoBot Analysis | Chat | Raw
```

---

## Public API Endpoint

The system provides a secure endpoint for automated metric submission.

**URL:** `https://your-ngrok-url/api/analyze`  
**Method:** `POST`  
**Auth:** `Authorization: Bearer giggso-ps2-secret-token`

```bash
curl -X POST https://your-ngrok-url/api/analyze \
  -H "Authorization: Bearer giggso-ps2-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"performance_metrics": {"f1_score": 0.87, "precision": 0.92, "recall": 0.85, "roc_auc": 0.90}}'
```

---

## Security Features

| Layer | Implementation |
|-------|-------------|
| **Input Guard** | 6-layer chat sanitisation (Injection detection, blocklist) |
| **Security Pipeline** | JSON structural validation & key allowlisting |
| **Rate Limiter** | Strictly enforced 10 req/min for API, 1 msg/sec for Chat |
| **Deterministic Risk** | Risk engine is 100% rule-based (Giggso requirement) |
| **WAF** | Integrated regex-based Web Application Firewall |

---

## Assumptions & Limitations

- **Stateless Analysis**: Model explanations are generated per session.
- **Metric Scoping**: The NanoBot Chat is strictly scoped to the loaded ML metrics.
- **Quota Management**: Free tier Gemini keys are subject to standard Google quotas.
- **Manual Sign-off**: Risk levels are advisory; final deployment requires human expert review.
