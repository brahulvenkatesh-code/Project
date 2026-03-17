# ⚡ NanoBot: Model Performance Explainer
### **Giggso Build-Break Challenge | PS2 — Phase 1**

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-109989?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35.0-FF4B4B?logo=streamlit)](https://streamlit.io/)
[![Google Gemini](https://img.shields.io/badge/Powered%20by-Google%20Gemini-4285F4?logo=googlegemini)](https://ai.google.dev/)

**NanoBot** is a high-security, professional ML metrics analysis dashboard designed for the Giggso Build-Break Challenge. It combines a deterministic risk engine with advanced LLM orchestration (NanoBot Layer) to provide human-readable insights from complex Trinity ML metrics.

---

## 🌟 Key Features

- **🛡️ 6-Layer Security Pipeline**: Hardened input validation, JSON allowlisting, and regex-based WAF (Web Application Firewall).
- **🤖 NanoBot AI Layer**: Orchestrates Google Gemini to translate raw numeric metrics into professional regulatory-compliant reports.
- **⚖️ Deterministic Risk Engine**: A 100% rule-based engine that calculates risk scores without LLM hallucination risk.
- **🔬 XAI Visualization Suite**: Interactive SHAP, LIME, and ELI5-style explainability charts powered by Plotly.
- **🔐 Enterprise Auth**: Secure Public API endpoint protected by Bearer Token Authentication.
- **📊 Compliance Ready**: Maps metrics against NIST, EU AI Act, and DPDP regulatory frameworks.

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have Python 3.12+ installed.

```bash
# Clone the repository
git clone <repo-url>
cd Project

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # Windows
source .venv/bin/activate     # Mac/Linux

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Create a `.env` file in the root directory:
```bash
GOOGLE_API_KEY=your_gemini_api_key
API_BEARER_TOKEN=giggso-ps2-secret-token
ALLOWED_HOST=your-ngrok-url.ngrok-free.app  # Optional for production
```

### 3. Execution
Run the dual-service architecture:

**Terminal 1 (Backend API):**
```bash
uvicorn api:app --host 127.0.0.1 --port 8001
```

**Terminal 2 (Streamlit UI):**
```bash
streamlit run app.py
```

---

## 🏗️ Technical Architecture

NanoBot follows a strictly decoupled, modular architecture to ensure security and performance.

```mermaid
graph TD
    A[User Browser] -->|Metrics JSON| B[Streamlit UI]
    B --> C{Input Guard}
    C -->|Sanitized| D[Security Pipeline]
    D --> E[Deterministic Risk Engine]
    D --> F[NanoBot AI Orchestrator]
    F -->|System Prompt Locked| G[Google Gemini API]
    E --> H[Consolidated Report]
    G --> H
    H --> I[XAI Visualization Layer]
    I --> J[Professional Dashboard]
```

### Security Layers
| Layer | Component | Description |
| :--- | :--- | :--- |
| **1** | `input_guard.py` | Injection detection, homoglyph normalization, character filtering. |
| **2** | `security.py` | JSON depth checks, key allowlisting, and strict range validation. |
| **3** | `prompts.py` | Context-locked system instructions preventing prompt injection. |
| **4** | `api.py` | Rate limiting (10 req/min) and Bearer auth. |
| **5** | `xai.py` | Derived explanations — NO raw user data passed through. |

---

## 🔌 Public API Reference

Submit metrics programmatically to the hardened endpoint.

**Endpoint:** `POST /api/analyze`  
**Authentication:** `Authorization: Bearer giggso-ps2-secret-token`

**Example Request:**
```bash
curl -X POST http://localhost:8001/api/analyze \
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

## 📋 Assumptions & Constraints

1. **Stateless Operations**: To maintain maximum security, metrics are processed in-memory and not persisted.
2. **Standardized Metrics**: The system expects Trinity-compliant JSON structures.
3. **Draft Advisory**: All risk levels are advisory; final deployment **must** be confirmed by a human ML engineer.
4. **Quota Management**: Free-tier Gemini keys are subject to Google's daily RPM/TPM limits.

---

## 🤝 Contributing
This project is part of a timed challenge. For structural improvements or security disclosures, please open an issue in the repository.

---
*Developed for the Giggso Build-Break Challenge 2026.*
