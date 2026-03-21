"""
pages/chat.py — NanoBot Chat Interface
Standalone marketplace page — accessible at /chat
Strictly read-only: NanoBot explains metrics, never influences risk scores.
"""

import streamlit as st
import json, uuid, asyncio, logging, os
from datetime import datetime, UTC

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ps2-chat")

from security import (
    validate_json_input, run_risk_engine,
    build_llm_safe_payload, check_rate_limit, SecurityError, MAX_JSON_BYTES,
)
from input_guard import unbreakable_input_guard
from nanobot_client import call_nanobot
from prompts import chat_system
from risk_engine import run_weighted_risk

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NanoBot Chat — Model Risk Explainer",
    page_icon="💬",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Premium CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; background: #080a10; }
  .stApp { background: #080a10; color: #e2e8f0; }
  .block-container { padding: 0 !important; max-width: 100%; }

  /* ── Top bar ── */
  .chat-topbar {
    display: flex; align-items: center; gap: 14px;
    padding: 12px 28px; background: #0d0f18;
    border-bottom: 1px solid #1e2233;
    position: sticky; top: 0; z-index: 100;
  }
  .nb-dot { width:9px; height:9px; border-radius:50%; background:#00e5ff;
    animation: pulse 2s infinite; flex-shrink: 0; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.25} }
  .nb-logo { font-family:'IBM Plex Mono',monospace; color:#00e5ff;
    font-size:15px; letter-spacing:.1em; font-weight:500; }
  .nb-badge { background:#7b61ff; color:#fff; font-size:10px;
    padding:3px 9px; border-radius:3px; font-family:'IBM Plex Mono',monospace; }
  .nb-tagline { margin-left:auto; font-size:11px; color:#4b5675;
    font-family:'IBM Plex Mono',monospace; }

  /* ── Risk pill ── */
  .risk-CRITICAL { background:#3a0000;color:#ff8080;border:1px solid #E24B4A;padding:4px 14px;border-radius:20px;font-size:12px;font-family:'IBM Plex Mono',monospace;font-weight:600; }
  .risk-HIGH { background:#2a1200;color:#ff9955;border:1px solid #BA7517;padding:4px 14px;border-radius:20px;font-size:12px;font-family:'IBM Plex Mono',monospace;font-weight:600; }
  .risk-MEDIUM { background:#1a1500;color:#ffd966;border:1px solid #c8a000;padding:4px 14px;border-radius:20px;font-size:12px;font-family:'IBM Plex Mono',monospace;font-weight:600; }
  .risk-LOW { background:#001510;color:#4dffb4;border:1px solid #1D9E75;padding:4px 14px;border-radius:20px;font-size:12px;font-family:'IBM Plex Mono',monospace;font-weight:600; }

  /* ── Chat area ── */
  .chat-area { max-width: 820px; margin: 0 auto; padding: 24px 16px 120px; }
  .chat-label { font-family:'IBM Plex Mono',monospace; font-size:10px; color:#4b5675; margin-bottom:4px; letter-spacing:.06em; }
  .chat-user {
    background: linear-gradient(135deg, #2d1f5e, #1e1640);
    border: 1px solid #4a3a9e; border-radius: 18px 18px 4px 18px;
    padding: 12px 16px; margin: 8px 0 8px 60px;
    font-size: 14px; line-height: 1.65; color: #ddd6fe;
  }
  .chat-bot {
    background: #0d0f18; border: 1px solid #1e2233;
    border-radius: 18px 18px 18px 4px;
    padding: 12px 16px; margin: 8px 60px 8px 0;
    font-size: 14px; line-height: 1.65; color: #e2e8f0;
    box-shadow: 0 2px 12px rgba(0,229,255,.04);
  }
  .chat-bot strong { color: #00e5ff; }
  .chat-bot code { background: #1a1f2e; padding: 1px 5px; border-radius: 3px;
    font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: #7b61ff; }

  /* ── Suggestions ── */
  .sugg-label { font-size:12px; font-weight:600; text-transform:uppercase;
    letter-spacing:.1em; color:#4b5675; margin: 20px 0 10px; }
  .stButton>button {
    background: #0d0f18 !important; border: 1px solid #252a38 !important;
    color: #a5b4fc !important; border-radius: 10px !important;
    font-size: 13px !important; text-align: left !important;
    padding: 10px 14px !important; width: 100% !important;
    transition: border-color .2s, background .2s !important;
    min-height: 52px !important; white-space: normal !important;
  }
  .stButton>button:hover { border-color: #7b61ff !important; background: #12142a !important; color: #c4b5fd !important; }
  .stButton>button[kind="primary"] {
    background: #7b61ff !important; border: none !important;
    color: #fff !important; border-radius: 10px !important;
    font-weight: 600 !important;
  }
  .stButton>button[kind="primary"]:hover { background: #9b7fff !important; }

  /* ── Input bar ── */
  .input-bar {
    position: fixed; bottom: 0; left: 0; right: 0;
    background: #080a10; border-top: 1px solid #1e2233;
    padding: 14px 16px;
  }
  .input-inner { max-width: 820px; margin: 0 auto; display: flex; gap: 10px; }
  .stTextInput input {
    background: #0d0f18 !important; border: 1px solid #252a38 !important;
    color: #e2e8f0 !important; border-radius: 12px !important;
    font-size: 14px !important; padding: 10px 16px !important;
  }
  .stTextInput input:focus { border-color: #7b61ff !important; box-shadow: 0 0 0 2px rgba(123,97,255,.2) !important; }

  /* ── Empty state ── */
  .empty-state { text-align: center; margin-top: 60px; padding: 0 20px; }
  .empty-icon { font-size: 52px; margin-bottom: 14px; }
  .empty-title { font-size: 22px; font-weight: 600; color: #e2e8f0; margin-bottom: 8px; }
  .empty-sub { font-size: 14px; color: #4b5675; line-height: 1.7; }

  /* Hide default sidebar toggle */
  [data-testid="collapsedControl"] { display: none; }
  div[data-testid="stSidebar"] { display: none; }
  .section-title { font-size:11px; font-weight:600; text-transform:uppercase;
    letter-spacing:.1em; color:#4b5675; margin:16px 0 8px; border-bottom:1px solid #1e2233; padding-bottom:6px; }
</style>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
for k, v in {
    "session_id": str(uuid.uuid4()),
    "metrics_clean": None,
    "metrics_llm": None,
    "risk": None,
    "chat_history": [],
    "log": [],
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

SAMPLE_JSONS = {
    "Classification — Fraud Detector": "sample_metrics/sample1_classification.json",
    "Regression — Loan Risk Scorer":   "sample_metrics/sample2_regression.json",
    "NLP — Support Ticket Classifier": "sample_metrics/sample3_nlp_multiclass.json",
}

SUGGESTIONS = [
    "What does the F1 score tell us about this model?",
    "Is the PSI drift score concerning?",
    "What are the top 3 risks before deployment?",
    "Explain the false negative rate in plain English.",
    "What does the train-test gap indicate?",
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def run_async(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)

def load_metrics(raw_json: str) -> bool:
    try:
        check_rate_limit(st.session_state.session_id)
        cleaned     = validate_json_input(raw_json)
        llm_payload = build_llm_safe_payload(cleaned)
        risk        = run_weighted_risk(cleaned)
        st.session_state.metrics_clean = cleaned
        st.session_state.metrics_llm   = llm_payload
        st.session_state.risk          = risk
        st.session_state.chat_history  = []
        return True
    except SecurityError as e:
        st.error(e.public_msg)
        return False
    except Exception as e:
        st.error(f"Failed to load metrics: {str(e)[:120]}")
        return False

def send_message(msg: str):
    msg = msg.strip()
    if not msg or not st.session_state.metrics_clean:
        return
    try:
        check_rate_limit(st.session_state.session_id)
        safe_msg = unbreakable_input_guard(msg)
    except SecurityError as e:
        st.error(e.public_msg)
        return

    st.session_state.chat_history.append({"role": "user", "content": safe_msg})

    safe_hist = [m for m in st.session_state.chat_history[-6:] if m["role"] in ("user", "assistant")]
    history_text = "\n".join(
        f"{'USER' if m['role']=='user' else 'NANOBOT'}: {m['content']}" for m in safe_hist
    )
    context = f"Conversation so far:\n{history_text}\n\nRespond to the latest USER message only."[:2000]

    risk_summary = {
        "risk_level":    st.session_state.risk.get("level"),
        "risk_score":    st.session_state.risk.get("weighted_breakdown", {}).get("final_score"),
        "risk_summary":  st.session_state.risk.get("summary"),
        "triggered_rules": [r["message"] for r in st.session_state.risk.get("triggered", [])],
        "recommendations": st.session_state.risk.get("recommendations", []),
    }
    combined     = {"metrics": st.session_state.metrics_clean, "risk_analysis": risk_summary}
    chat_context = json.dumps(combined, indent=2)
    if len(chat_context) > 4000:
        chat_context = json.dumps({
            "metrics":    st.session_state.metrics_llm,
            "risk_level": st.session_state.risk.get("level"),
        }, indent=2)

    system = chat_system(chat_context)
    with st.spinner("NanoBot is thinking…"):
        try:
            reply = run_async(call_nanobot(system, context))
            st.session_state.chat_history.append({"role": "assistant", "content": reply})
        except Exception as e:
            err = str(e)
            st.error("Rate limit hit — wait a moment." if "429" in err else f"NanoBot unavailable: {err[:100]}")
            st.session_state.chat_history.pop()

# ── Top bar ───────────────────────────────────────────────────────────────────
risk = st.session_state.risk
risk_pill = ""
if risk:
    lvl = risk["level"]
    risk_pill = f'<span class="risk-{lvl}">{risk["color"]} {lvl} &nbsp;·&nbsp; {risk.get("weighted_breakdown",{}).get("final_score","—")}</span>'

st.markdown(f"""
<div class="chat-topbar">
  <div class="nb-dot"></div>
  <span class="nb-logo">NANOBOT</span>
  <span class="nb-badge">Chat Interface</span>
  {risk_pill}
  <span class="nb-tagline">Explanations only &nbsp;·&nbsp; Risk determined by deterministic engine</span>
</div>
""", unsafe_allow_html=True)

# ── Load panel (collapsible) ──────────────────────────────────────────────────
with st.expander("📂 Load Metrics JSON", expanded=not bool(st.session_state.metrics_clean)):
    tab_upload, tab_sample, tab_paste = st.tabs(["Upload File", "Sample Dataset", "Paste JSON"])

    with tab_upload:
        uploaded = st.file_uploader("Upload Trinity metrics JSON", type=["json"], label_visibility="collapsed")
        if uploaded:
            if uploaded.size > MAX_JSON_BYTES:
                st.error(f"File too large (max {MAX_JSON_BYTES//1000} KB).")
            else:
                raw = uploaded.read().decode("utf-8", errors="replace")
                st.caption(f"📄 {uploaded.name} — {uploaded.size:,} bytes")
                if st.button("⬆ Load File", key="load_upload", type="primary"):
                    if load_metrics(raw):
                        st.success("Metrics loaded — start chatting below!")
                        st.rerun()

    with tab_sample:
        choice = st.selectbox("Select a sample", list(SAMPLE_JSONS.keys()), label_visibility="collapsed")
        if st.button("⬆ Load Sample", key="load_sample", type="primary"):
            path = SAMPLE_JSONS[choice]
            if os.path.exists(path):
                with open(path) as f:
                    if load_metrics(f.read()):
                        st.success(f"Loaded: {choice}")
                        st.rerun()
            else:
                st.error("Sample file not found.")

    with tab_paste:
        pasted = st.text_area("Paste JSON here", height=180,
                              placeholder='{"performance_metrics": {"accuracy": 0.92, ...}}',
                              label_visibility="collapsed")
        if st.button("⬆ Load JSON", key="load_paste", type="primary"):
            if pasted.strip():
                if load_metrics(pasted):
                    st.success("Metrics loaded — start chatting below!")
                    st.rerun()
            else:
                st.warning("Please paste a JSON first.")

# ── Process pending suggestion click ─────────────────────────────────────────
if st.session_state.get("_pending_chat"):
    pending = st.session_state.pop("_pending_chat")
    send_message(pending)
    st.rerun()

# ── Main chat area ─────────────────────────────────────────────────────────────
st.markdown('<div class="chat-area">', unsafe_allow_html=True)

if not st.session_state.metrics_clean:
    # ── Empty state ──
    st.markdown("""
    <div class="empty-state">
      <div class="empty-icon">💬</div>
      <div class="empty-title">Chat with NanoBot</div>
      <div class="empty-sub">
        Load a Trinity metrics JSON above to begin.<br/>
        NanoBot will explain your model's performance, risk factors,<br/>
        and deployment readiness in plain English.
      </div>
    </div>
    """, unsafe_allow_html=True)
else:
    # ── Render chat history ──
    import html as _html
    for m in st.session_state.chat_history:
        if m["role"] == "user":
            st.markdown(
                f'<div class="chat-label">YOU</div>'
                f'<div class="chat-user">{_html.escape(m["content"])}</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div class="chat-label">NANOBOT</div>'
                f'<div class="chat-bot">{_html.escape(m["content"])}</div>',
                unsafe_allow_html=True,
            )

    # ── Suggestions (shown when no chat yet) ──
    if not st.session_state.chat_history:
        st.markdown('<div class="sugg-label">Suggested questions</div>', unsafe_allow_html=True)
        cols = st.columns(2)
        for i, q in enumerate(SUGGESTIONS):
            with cols[i % 2]:
                if st.button(q, key=f"sugg_{i}"):
                    st.session_state["_pending_chat"] = q
                    st.rerun()

st.markdown('</div>', unsafe_allow_html=True)

# ── Fixed input bar ───────────────────────────────────────────────────────────
if st.session_state.metrics_clean:
    st.markdown('<div class="input-bar"><div class="input-inner">', unsafe_allow_html=True)
    col_input, col_send = st.columns([7, 1])
    with col_input:
        user_input = st.text_input(
            "chat_input", placeholder="Ask about your metrics…",
            label_visibility="collapsed", key="chat_input_field"
        )
    with col_send:
        send_btn = st.button("Send", type="primary", key="chat_send")
    st.markdown('</div></div>', unsafe_allow_html=True)

    if send_btn and user_input.strip():
        send_message(user_input)
        st.rerun()
    elif send_btn:
        st.warning("Please type a message first.")
