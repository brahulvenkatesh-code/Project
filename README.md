# ⚡ NanoBot: Enterprise ML Model Explainer
### **Giggso Build-Break Challenge | PS2 — Phase 1 (Hardened Edition)**

[![Railway Deployed](https://img.shields.io/badge/Railway-Live-0B0D0E?logo=railway)](https://project-production-a63b.up.railway.app/)
[![Groq Powered](https://img.shields.io/badge/Groq-14k_RPD-f55036?logo=groq)](https://groq.com/)
[![Google Gemini](https://img.shields.io/badge/Powered%20by-Google%20Gemini-4285F4?logo=googlegemini)](https://ai.google.dev/)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)

**NanoBot** is a high-security, professional ML metrics analysis dashboard. It uses a **Triple-Tier Fallback Orchestration** system to provide uninterrupted, high-quality metric analysis even under heavy load.

---

## 🚀 Live Demo
**URL**: [project-production-a63b.up.railway.app](https://project-production-a63b.up.railway.app/)

---

## 🌟 Key Features

- **🛡️ 6-Layer Security Pipeline**: Hardened input validation, JSON allowlisting, and regex-based WAF.
- **🛡️ 3-Tier AI Fallback**:
    - **Tier 1**: Gemini 3 Flash (Primary - High Quality)
    - **Tier 2**: Groq Llama 3.3 70B (High Availability - 14,400 Requests/Day)
    - **Tier 3**: Gemini 1.5 Flash (Tertiary - Reliable Safety Net)
- **⚖️ Deterministic Risk Engine**: A 100% rule-based engine provides reliable risk scoring without LLM hallucination.
- **🔬 XAI Visualization Suite**: Interactive SHAP, LIME, and ELI5 charts for deep-dive explainability.
- **📊 Compliance Ready**: Maps metrics against **NIST**, **EU AI Act**, and **DPDP** regulatory frameworks.

---

## 🏗️ Technical Architecture

```mermaid
graph TD
    A[User Browser] -->|Metrics JSON| B[Streamlit UI]
    B --> C{Security Guard}
    C -->|Sanitized| D[Risk Engine]
    C -->|Sanitized| E[NanoBot Orchestrator]
    
    subgraph AI Orchestration Layer
    E --> F{Triple Tier Check}
    F -->|Tier 1| G[Gemini 3 Flash]
    F -->|Tier 2| H[Groq Llama 3.3]
    F -->|Tier 3| I[Gemini 1.5 Flash]
    end
    
    D --> J[Final Report]
    G -.-> J
    H -.-> J
    I -.-> J
```

---

## 🔌 Public API Reference

The public endpoint is secured using **Bearer Token Authentication**.

- **URL**: `https://project-production-a63b.up.railway.app/api/analyze`
- **Method**: `POST`
- **Header**: `Authorization: Bearer giggso-ps2-secret-token`

### Example Request:
```bash
curl -X POST https://project-production-a63b.up.railway.app/api/analyze \
  -H "Authorization: Bearer giggso-ps2-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "performance_metrics": {
      "f1_score": 0.88,
      "precision": 0.91,
      "recall": 0.85
    }
  }'
```

---

## 🛠️ Local Development

### 1. Setup
```bash
git clone <repo-url>
cd Project
python -m venv .venv
source .venv/bin/activate  # or .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment
Update your `.env` file:
```env
GOOGLE_API_KEY=your_key
GROQ_API_KEY=your_groq_key
API_BEARER_TOKEN=giggso-ps2-secret-token
```

### 3. Run
```bash
# Start Backend
uvicorn api:app --port 8001

# Start Frontend
streamlit run app.py
```

---

## 📋 Operational Assumptions
1. **Deduplication**: SHA256 hashing is used for session-level metric caching.
2. **Quota Handling**: The orchestrator automatically catches `429` errors and shifts to the next tier.
3. **Draft Advisory**: NanoBot provides insights; final deployment is a human decision.

---
*Developed for the Giggso Build-Break Challenge 2026. Stability. Security. Speed.*
