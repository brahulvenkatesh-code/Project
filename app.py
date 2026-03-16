"""
app.py — PS2: Model Performance Explainer
Giggso Build-Break Challenge | Phase 1
Powered by NanoBot + Claude | SHAP · LIME · ELI5 · Deterministic Risk Engine
"""

import streamlit as st
import json, uuid, asyncio, logging, time, os
from datetime import datetime, timezone, timezone, UTC
from dotenv import load_dotenv
import markdown2

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ps2")

from risk_engine import run_weighted_risk
from input_guard import unbreakable_input_guard
from security import (
    validate_json_input,
    run_risk_engine, build_llm_safe_payload,
    check_rate_limit, SecurityError,
    MAX_JSON_BYTES,
)
from prompts import analysis_prompt, chat_system, SYSTEM_PROMPT, ANALYSIS_SYSTEM
from nanobot_client import call_nanobot
from xai import (
    shap_feature_importance, lime_boundary_explanation,
    eli5_weight_table, radar_chart, latency_chart,
    confusion_matrix_chart, per_class_chart, drift_gauge,
)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NanoBot — Model Performance Explainer",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }

  .stApp { background: #0d0f14; color: #e2e8f0; }

  .block-container { padding: 1.5rem 2rem; max-width: 100%; }

  /* Header */
  .nb-header {
    display: flex; align-items: center; gap: 12px;
    padding: 14px 20px; background: #13161e;
    border-bottom: 1px solid #252a38; margin: -1.5rem -2rem 1.5rem;
  }
  .nb-dot { width:10px;height:10px;border-radius:50%;background:#00e5ff;
    animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1}50%{opacity:.3} }
  .nb-logo { font-family:'IBM Plex Mono',monospace;color:#00e5ff;
    font-size:15px;letter-spacing:.1em;font-weight:500; }
  .nb-badge { background:#7b61ff;color:#fff;font-size:10px;
    padding:3px 8px;border-radius:3px;font-family:'IBM Plex Mono',monospace;
    letter-spacing:.05em; }
  .nb-session { margin-left:auto;font-family:'IBM Plex Mono',monospace;
    font-size:11px;color:#6b7694; }

  /* Risk badge */
  .risk-CRITICAL { background:#500; color:#ff8080; border:1px solid #E24B4A;
    padding:6px 16px;border-radius:6px;font-family:'IBM Plex Mono',monospace;
    font-size:13px;font-weight:500;display:inline-block; }
  .risk-HIGH { background:#3a1f00;color:#ff9955;border:1px solid #BA7517;
    padding:6px 16px;border-radius:6px;font-family:'IBM Plex Mono',monospace;
    font-size:13px;font-weight:500;display:inline-block; }
  .risk-MEDIUM { background:#2a2000;color:#ffd966;border:1px solid #ffc800;
    padding:6px 16px;border-radius:6px;font-family:'IBM Plex Mono',monospace;
    font-size:13px;font-weight:500;display:inline-block; }
  .risk-LOW { background:#001a10;color:#4dffb4;border:1px solid #1D9E75;
    padding:6px 16px;border-radius:6px;font-family:'IBM Plex Mono',monospace;
    font-size:13px;font-weight:500;display:inline-block; }

  /* Metric card */
  .metric-card {
    background:#13161e;border:1px solid #252a38;border-radius:10px;
    padding:16px 20px;margin:6px 0;
  }
  .metric-card h4 { margin:0 0 4px;font-size:13px;color:#6b7694;
    font-family:'IBM Plex Mono',monospace;text-transform:uppercase;letter-spacing:.08em; }
  .metric-card .val { font-size:26px;font-weight:600;color:#e2e8f0;
    font-family:'IBM Plex Mono',monospace; }

  /* Chat bubbles */
  .chat-user { background:#2d1f5e;border-radius:12px 12px 3px 12px;
    padding:10px 14px;margin:6px 0 6px 40px;font-size:13px;line-height:1.6; }
  .chat-bot { background:#13161e;border:1px solid #252a38;
    border-radius:12px 12px 12px 3px;padding:10px 14px;
    margin:6px 40px 6px 0;font-size:13px;line-height:1.6; }
  .chat-label { font-family:'IBM Plex Mono',monospace;font-size:10px;
    color:#6b7694;margin-bottom:3px; }

  /* Section divider */
  .section-title { font-size:12px;font-weight:600;text-transform:uppercase;
    letter-spacing:.12em;color:#6b7694;margin:20px 0 10px;
    border-bottom:1px solid #252a38;padding-bottom:6px; }

  /* Stray streamlit defaults */
  .stTextArea textarea { background:#13161e!important;color:#e2e8f0!important;
    border:1px solid #252a38!important;font-family:'IBM Plex Mono',monospace!important;
    font-size:12px!important; }
  .stButton>button { background:#7b61ff!important;color:#fff!important;
    border:none!important;border-radius:6px!important;font-weight:500!important; }
  .stButton>button:hover { background:#9b7fff!important; }
  .stTabs [data-baseweb="tab"] { background:transparent; }
  div[data-testid="stSidebar"] { background:#0d0f14!important;
    border-right:1px solid #252a38!important; }
  .stDataFrame { background:#13161e; }
  
  /* Report styling */
  .report-card {
    background: #13161e;
    border: 1px solid #252a38;
    border-radius: 12px;
    padding: 24px;
    margin: 10px 0;
    line-height: 1.7;
    color: #e2e8f0;
  }
  .report-card h1, .report-card h2, .report-card h3 {
    color: #00e5ff;
    font-family: 'IBM Plex Sans', sans-serif;
  }
</style>
""", unsafe_allow_html=True)

# ── Session state initialisation ──────────────────────────────────────────────
defaults = {
    "session_id":    str(uuid.uuid4()),
    "metrics_raw":   None,
    "metrics_clean": None,
    "metrics_llm":   None,
    "risk":          None,
    "analysis":      None,
    "chat_history":  [],
    "swap_count":    0,
    "analyzed":      False,
    "log":           [],
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Helpers ───────────────────────────────────────────────────────────────────
def log_event(event: str, detail: str = "", error: bool = False):
    entry = {
        "ts":    datetime.now(UTC).isoformat(),
        "event": event,
        "detail": detail,
        "sid":   st.session_state.session_id[:8],
    }
    st.session_state.log.append(entry)
    if error:
        logger.error(f"[{entry['sid']}] {event}: {detail}")
    else:
        logger.info(f"[{entry['sid']}] {event}: {detail}")

def run_async(coro):
    try:
        # Streamlit-safe way to run async in a thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    except Exception as e:
        logger.error(f"Async error: {e}")
        raise

def load_and_validate(raw_json: str) -> bool:
    """Full validation pipeline. Returns True on success."""
    try:
        check_rate_limit(st.session_state.session_id)
    except SecurityError as e:
        st.error(str(e.public_msg))
        log_event("rate_limit", str(e), error=True)
        return False

    try:
        cleaned = validate_json_input(raw_json)
    except SecurityError as e:
        st.error(str(e.public_msg))
        log_event("validation_fail", e.internal, error=True)
        return False

    llm_payload = build_llm_safe_payload(cleaned)
    risk        = run_weighted_risk(cleaned)

    st.session_state.metrics_raw   = raw_json
    st.session_state.metrics_clean = cleaned
    st.session_state.metrics_llm   = llm_payload
    st.session_state.risk          = risk
    st.session_state.analyzed      = False
    st.session_state.analysis      = None
    log_event("loaded", f"risk={risk['level']}, keys={list(cleaned.keys())[:5]}")
    return True

SAMPLE_JSONS = {
    "Classification (fraud detection)": "sample_metrics/sample1_classification.json",
    "Regression (loan risk)":           "sample_metrics/sample2_regression.json",
    "NLP Multi-class (ticket router)":  "sample_metrics/sample3_nlp_multiclass.json",
}

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="nb-header">
  <div class="nb-dot"></div>
  <span class="nb-logo">NANOBOT</span>
  <span class="nb-badge">PS2 — Model Performance Explainer</span>
  <span class="nb-session">Session: {st.session_state.session_id[:12]}…</span>
</div>
""", unsafe_allow_html=True)

# ── Sidebar: Input ────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="section-title">Metrics Source</div>', unsafe_allow_html=True)

    input_mode = st.radio("Input mode", ["Paste JSON", "Upload file", "Load sample"],
                          horizontal=True, label_visibility="collapsed")

    raw_input = None

    if input_mode == "Paste JSON":
        raw_input = st.text_area(
            "Paste Trinity metrics JSON",
            height=260,
            placeholder='{"performance_metrics": {"accuracy": 0.92, ...}}',
            label_visibility="collapsed",
        )

    elif input_mode == "Upload file":
        uploaded = st.file_uploader(
            "Upload JSON", type=["json"],
            accept_multiple_files=False,
            label_visibility="collapsed",
        )
        if uploaded:
            # Step 1: size check before reading
            size = uploaded.size
            if size > MAX_JSON_BYTES:
                st.error(f"Invalid metric input: file too large (max {MAX_JSON_BYTES//1000} KB).")
            else:
                raw_input = uploaded.read().decode("utf-8", errors="replace")
                st.caption(f"📄 {uploaded.name} — {size:,} bytes")

    elif input_mode == "Load sample":
        sample_choice = st.selectbox("Select sample", list(SAMPLE_JSONS.keys()),
                                     label_visibility="collapsed")
        sample_path = SAMPLE_JSONS[sample_choice]
        if os.path.exists(sample_path):
            with open(sample_path) as f:
                raw_input = f.read()
            st.caption(f"📊 Loaded: {sample_choice}")
        else:
            st.warning("Sample file not found.")

    st.divider()

    col_a, col_b = st.columns(2)
    with col_a:
        load_btn = st.button("⬆ Load", width="stretch")
    with col_b:
        swap_btn = st.button("⇄ Swap", width="stretch",
                             disabled=not st.session_state.analyzed)

    if load_btn and raw_input:
        if load_and_validate(raw_input):
            st.success("✅ Metrics loaded and validated.")

    if swap_btn and raw_input:
        st.session_state.swap_count += 1
        if load_and_validate(raw_input):
            st.success(f"✅ Source swapped (#{st.session_state.swap_count}). Re-run analysis.")

    if not raw_input and load_btn:
        st.warning("Please provide a JSON source first.")

    # Show current load status
    st.divider()
    if st.session_state.metrics_clean:
        st.markdown('<div class="section-title">Loaded metrics</div>', unsafe_allow_html=True)
        top_keys = list(st.session_state.metrics_clean.keys())[:8]
        st.caption("  ·  ".join(top_keys))
        if st.session_state.risk:
            lvl = st.session_state.risk["level"]
            col = st.session_state.risk["color"]
            st.markdown(f'<div class="risk-{lvl}">{col} Risk: {lvl}</div>',
                        unsafe_allow_html=True)
    else:
        st.info("No metrics loaded yet.")

    st.divider()
    st.markdown('<div class="section-title">Session log</div>', unsafe_allow_html=True)
    if st.session_state.log:
        for entry in reversed(st.session_state.log[-8:]):
            st.caption(f"`{entry['ts'][11:19]}` {entry['event']}: {entry['detail'][:40]}")
    else:
        st.caption("No events yet.")

# ── Main area ─────────────────────────────────────────────────────────────────
if not st.session_state.metrics_clean:
    st.markdown("""
    <div style='text-align:center;margin-top:80px;color:#6b7694'>
      <div style='font-size:48px;margin-bottom:16px'>⚡</div>
      <div style='font-size:18px;font-weight:500;color:#e2e8f0;margin-bottom:8px'>
        NanoBot Model Performance Explainer
      </div>
      <div style='font-size:14px;line-height:1.8'>
        Load a Trinity metrics JSON from the sidebar to begin.<br/>
        Supports classification, regression, and NLP models.
      </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_overview, tab_xai, tab_analysis, tab_chat, tab_raw = st.tabs([
    "📊 Overview", "🔬 XAI", "🤖 NanoBot Analysis", "💬 Chat", "🔧 Raw"
])

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 1: OVERVIEW
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with tab_overview:
    data   = st.session_state.metrics_clean
    risk   = st.session_state.risk
    breakdown = risk.get("weighted_breakdown", {})

    # ── Section 1: Upload confirmation ───────────────────────────────────────
    st.markdown('<div class="section-title">Metrics Source</div>', unsafe_allow_html=True)
    model_info = data.get("model_info", {})
    if model_info:
        c1, c2, c3 = st.columns(3)
        c1.metric("Model", model_info.get("name", "—"))
        c2.metric("Algorithm", model_info.get("algorithm", "—"))
        c3.metric("Task", model_info.get("task", "—").replace("_", " ").title())
    st.caption("✔ JSON validated · ✔ Unknown fields stripped · ✔ Range-checked · ✔ Injection-scanned")

    st.divider()

    # ── Section 2: Metrics Dashboard ─────────────────────────────────────────
    st.markdown('<div class="section-title">Metrics Dashboard</div>', unsafe_allow_html=True)

    pm = data.get("performance_metrics", {})
    if isinstance(pm, dict) and pm:
        metric_display = {
            "accuracy":        ("Accuracy",    0.90, 0.80),
            "precision":       ("Precision",   0.80, 0.60),
            "recall":          ("Recall",      0.75, 0.60),
            "f1_score":        ("F1 Score",    0.80, 0.70),
            "f1":              ("F1 Score",    0.80, 0.70),
            "auc_roc":         ("AUC-ROC",     0.90, 0.80),
            "roc_auc":         ("AUC-ROC",     0.90, 0.80),
            "balanced_accuracy":("Bal. Accuracy",0.85, 0.70),
            "log_loss":        ("Log Loss",    None, None),
            "false_positive_rate":("FP Rate",  0.10, 0.20),
            "false_negative_rate":("FN Rate",  0.20, 0.40),
            "r2_score":        ("R² Score",    0.85, 0.65),
            "mae":             ("MAE",         None, None),
            "rmse":            ("RMSE",        None, None),
        }

        # Table header
        header = "| Metric | Value | Status | Interpretation |"
        divider = "|--------|-------|--------|----------------|"
        rows = [header, divider]

        for key, (label, good, warn) in metric_display.items():
            val = pm.get(key)
            if val is None:
                continue
            val_f = f"{val:.4f}"
            if good is None:
                status = "ℹ️ Info"
                interp = "Domain-dependent — see full analysis"
            elif key in ("false_positive_rate","false_negative_rate","log_loss","mae","rmse"):
                # Lower is better
                status = "🟢 Good" if val <= good else ("🟡 Warning" if val <= warn else "🔴 Risk")
                interp = "Low ✅" if val <= good else ("Moderate ⚠️" if val <= warn else "High ❌")
            else:
                status = "🟢 Good" if val >= good else ("🟡 Warning" if val >= warn else "🔴 Risk")
                if key == "precision" and val < warn:
                    interp = f"🔴 High False Positive Risk (< {warn})"
                elif key == "recall" and val < warn:
                    interp = f"🔴 High False Negative Risk (< {warn})"
                elif key in ("f1_score","f1") and val < 0.70:
                    interp = "🔴 Model Instability"
                elif key in ("auc_roc","roc_auc") and val < 0.80:
                    interp = "🔴 Poor Class Separation"
                else:
                    interp = "Acceptable" if val >= warn else f"Below threshold ({warn})"

            rows.append(f"| {label} | {val_f} | {status} | {interp} |")

        st.markdown("\n".join(rows))
    else:
        st.info("No performance_metrics found in loaded JSON.")

    st.divider()

    # ── Section 3: Risk Assessment Panel ─────────────────────────────────────
    st.markdown('<div class="section-title">Risk Assessment</div>', unsafe_allow_html=True)

    lvl   = risk["level"]
    color = risk["color"]
    score = breakdown.get("final_score", "—")

    # Risk card
    risk_col1, risk_col2 = st.columns([1, 2])
    with risk_col1:
        st.markdown(f'<div class="risk-{lvl}" style="font-size:18px;padding:14px 24px">'
                    f'{color} {lvl}<br/><small style="font-size:12px">Score: {score}</small></div>',
                    unsafe_allow_html=True)
    with risk_col2:
        st.markdown(f"**{risk['summary']}**")
        st.caption(risk["disclaimer"])

    # Score breakdown
    if breakdown:
        st.markdown("**Score Formula:** `0.40×F1 + 0.25×Precision + 0.20×Recall + 0.15×AUC + penalties`")
        cols = st.columns(5)
        cols[0].metric("F1 (×0.40)",        breakdown.get("f1_contribution", "—"))
        cols[1].metric("Precision (×0.25)",  breakdown.get("precision_contribution", "—"))
        cols[2].metric("Recall (×0.20)",     breakdown.get("recall_contribution", "—"))
        cols[3].metric("AUC (×0.15)",        breakdown.get("auc_contribution", "—"))
        cols[4].metric("Penalties",          breakdown.get("total_penalty", "—"))

    # Triggered rules
    triggered = risk.get("triggered", [])
    if triggered:
        with st.expander(f"🔍 {len(triggered)} risk rule(s) triggered", expanded=lvl in ("CRITICAL","HIGH")):
            for r in triggered:
                icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(r["severity"],"•")
                st.markdown(f"{icon} **{r['severity']}** — {r['message']}")
    else:
        st.success("No risk rules triggered — all metrics within acceptable bounds.")

    # Regulatory hits
    reg_hits = risk.get("regulatory_hits", [])
    if reg_hits:
        st.markdown("**Regulatory & Compliance Violations:**")
        reg_header = "| Metric | Value | Threshold | Regulatory Reference | Risk Label |"
        reg_div    = "|--------|-------|-----------|----------------------|------------|"
        reg_rows   = [reg_header, reg_div]
        for h in reg_hits:
            reg_rows.append(f"| {h['metric']} | {h['value']} | {h['threshold']} | {h['nist_ref']} | {h['risk_label']} |")
        st.markdown("\n".join(reg_rows))

    st.divider()

    # ── Section 4: Recommendations ───────────────────────────────────────────
    st.markdown('<div class="section-title">Recommendations</div>', unsafe_allow_html=True)
    for rec in risk.get("recommendations", []):
        st.markdown(f"- {rec}")

    st.divider()

    # ── Section 5: Visualizations (only confusion matrix + latency if present) 
    st.markdown('<div class="section-title">Visualizations</div>', unsafe_allow_html=True)
    viz_col1, viz_col2 = st.columns(2)
    with viz_col1:
        from xai import confusion_matrix_chart, radar_chart
        fig = confusion_matrix_chart(data)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        else:
            fig = radar_chart(data)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
    with viz_col2:
        from xai import latency_chart, drift_gauge
        fig = drift_gauge(data)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        else:
            fig = latency_chart(data)
            if fig:
                st.plotly_chart(fig, use_container_width=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 2: XAI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with tab_xai:
    data = st.session_state.metrics_clean
    from xai import (shap_feature_importance, lime_boundary_explanation,
                     eli5_weight_table, radar_chart, latency_chart,
                     confusion_matrix_chart, per_class_chart, drift_gauge,
                     roc_curve_chart, pr_curve_chart)

    st.caption(
        "Explainability layer — shows HOW the risk decision was reached. "
        "All analysis is derived from loaded metrics. NanoBot does not influence these charts."
    )

    # ── SHAP ─────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">SHAP — Feature Importance</div>', unsafe_allow_html=True)
    st.caption("Which metric signals contribute most to the overall risk assessment. "
               "Longer bar = higher influence on the final risk score.")
    fig = shap_feature_importance(data)
    if fig:
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Insufficient metric signals for SHAP analysis.")

    st.divider()

    # ── LIME ─────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">LIME — Local Decision Explanation</div>', unsafe_allow_html=True)
    st.caption("Which individual metric factors push toward (green) or away from (red) "
               "deployment readiness at the decision boundary.")
    fig = lime_boundary_explanation(data)
    if fig:
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Insufficient data for LIME explanation.")

    st.divider()

    # ── ELI5 ─────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">ELI5 — Metric Weight Table</div>', unsafe_allow_html=True)
    st.caption("Plain-English breakdown of each metric: its contribution weight, "
               "status (Good/Warning/Risk), and what it means for deployment.")
    df = eli5_weight_table(data)
    if df is not None:
        def color_status(val):
            if "✅" in str(val): return "color: #1D9E75"
            if "⚠️" in str(val): return "color: #BA7517"
            if "❌" in str(val): return "color: #E24B4A"
            return ""
        styled = df.style            .map(color_status, subset=["Status"])            .background_gradient(subset=["Weight"], cmap="RdYlGn", vmin=-1, vmax=1)            .format({"Value": "{:.4f}", "Weight": "{:+.3f}"})
        st.dataframe(styled, use_container_width=True, hide_index=True)
    else:
        st.info("No ELI5-compatible metrics in loaded JSON.")

    st.divider()

    # ── ROC + PR Curves ───────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Performance Curves</div>', unsafe_allow_html=True)
    st.caption("ROC curve shows discrimination ability across all thresholds. "
               "Precision-Recall curve shows the tradeoff at the operating point (★).")
    curve_col1, curve_col2 = st.columns(2)
    with curve_col1:
        fig = roc_curve_chart(data)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("AUC-ROC not present in loaded metrics.")
    with curve_col2:
        fig = pr_curve_chart(data)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Precision/Recall not present in loaded metrics.")

    st.divider()

    # ── Per-class breakdown ───────────────────────────────────────────────────
    fig = per_class_chart(data)
    if fig:
        st.markdown('<div class="section-title">Per-Class Performance</div>', unsafe_allow_html=True)
        st.caption("Precision, Recall and F1 breakdown per class — identifies which classes are underperforming.")
        st.plotly_chart(fig, use_container_width=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 3: NANOBOT ANALYSIS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with tab_analysis:
    st.markdown('<div class="section-title">NanoBot Plain-English Analysis</div>',
                unsafe_allow_html=True)
    st.caption("NanoBot explains the numeric metrics in plain English. Risk is determined separately by the deterministic rule engine — not by the LLM.")

    if not st.session_state.analyzed:
        if st.button("▶ Run NanoBot Analysis", width="content"):
            try:
                check_rate_limit(st.session_state.session_id)
            except SecurityError as e:
                st.error(str(e.public_msg))
                st.stop()

            with st.spinner("NanoBot is analysing your metrics…"):
                try:
                    prompt = analysis_prompt(st.session_state.metrics_llm)
                    result = run_async(call_nanobot(ANALYSIS_SYSTEM, prompt, max_tokens=2048))
                    # Detect truncation — if ends mid-sentence, flag it
                    stripped = result.strip()
                    incomplete_endings = (".", "!", "?", '"', "'", "`")
                    if stripped and stripped[-1] not in incomplete_endings:
                        result += "\n\n---\n*Response may be incomplete — click Re-run Analysis.*"
                    st.session_state.analysis = result
                    st.session_state.analyzed = True
                    log_event("analysis_complete", f"chars={len(result)}")
                    st.rerun()
                except Exception as e:
                    err = str(e)
                    if "429" in err or "quota" in err.lower():
                        st.error("Gemini rate limit hit. Wait 1 minute and try again.")
                    elif "API_KEY" in err or "api key" in err.lower() or "invalid" in err.lower():
                        st.error(f"API key error: {err[:200]}")
                    elif "8192" in err or "token" in err.lower():
                        st.error("Response too long — try with a smaller JSON. Reducing token request...")
                    else:
                        st.error("NanoBot analysis failed. Please check your API key and try again.")
                    log_event("analysis_error", err, error=True)
    else:
        analysis = st.session_state.analysis
        # Convert markdown to HTML for robust rendering inside the styled div
        analysis_html = markdown2.markdown(analysis, extras=["tables", "fenced-code-blocks"])
        st.markdown(f'<div class="report-card">{analysis_html}</div>', unsafe_allow_html=True)
        st.divider()

        # Build full export report
        risk      = st.session_state.risk
        triggered = risk.get("triggered", [])
        reg_hits  = risk.get("regulatory_hits", [])
        breakdown = risk.get("weighted_breakdown", {})

        reg_rows = ""
        for h in reg_hits:
            recs = ", ".join(h.get("remediation", [])[:3])
            reg_rows += f"| {h['metric']} | {h['threshold']} | {h['value']} | {h['nist_ref']} | {h['risk_label']} | {recs} |\n"

        triggered_md = "\n".join(
            f"- **{r['severity']}** — {r['message']}" for r in triggered
        ) or "- No rules triggered"

        recs_md = "\n".join(f"- {r}" for r in risk.get("recommendations", []))

        f1c   = breakdown.get('f1_contribution', '?')
        prec  = breakdown.get('precision_contribution', '?')
        rec   = breakdown.get('recall_contribution', '?')
        aucc  = breakdown.get('auc_contribution', '?')
        pen   = breakdown.get('total_penalty', '?')
        score = breakdown.get('final_score', '?')

        export_md = f"""# NanoBot Model Performance Report
**Generated:** {datetime.now(timezone.utc).isoformat()} UTC
**Session:** {st.session_state.session_id}
**Risk Level:** {risk['level']} {risk['color']}
**Risk Score:** {score}

---

## Risk Score Breakdown

Formula: `score = 0.40×F1 + 0.25×Precision + 0.20×Recall + 0.15×AUC + penalties`

```
= {f1c} + {prec} + {rec} + {aucc} + ({pen}) = {score}
```

---

## Regulatory & Compliance Analysis

| Metric | Threshold | Value | Regulatory Reference | Risk Label | Remediation |
|--------|-----------|-------|----------------------|------------|-------------|
{reg_rows if reg_rows else "| — | — | — | No violations triggered | — | — |"}

---

## Risk Rules Triggered

{triggered_md}

---

## NanoBot Plain-English Analysis

{analysis}

---

## Recommendations

{recs_md}

---

## Disclaimer
*Risk level determined by deterministic weighted rule engine — not LLM inference.*
*Final deployment decision must be made by a qualified ML engineer and domain expert.*
*Report generated by NanoBot PS2 — Giggso Build-Break Challenge*
"""
        # Side-by-side buttons
        btn_col1, btn_col2 = st.columns(2)
        with btn_col1:
            st.download_button(
                "⬇ Download Report (Markdown)",
                data=export_md,
                file_name=f"nanobot_report_{st.session_state.session_id[:8]}.md",
                mime="text/markdown",
                width="stretch"
            )
        with btn_col2:
            if st.button("🔄 Re-run Analysis", width="stretch"):
                st.session_state.analyzed = False
                st.session_state.analysis = None
                st.rerun()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 4: CHAT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with tab_chat:
    st.markdown('<div class="section-title">Chat with NanoBot</div>', unsafe_allow_html=True)
    st.caption("Ask NanoBot anything about the loaded metrics. Responses are strictly scoped to the loaded data.")

    # ── Helper to send a message ──────────────────────────────────────────────
    def send_message(msg: str):
        msg = msg.strip()
        if not msg:
            return
        try:
            check_rate_limit(st.session_state.session_id)
            safe_msg = unbreakable_input_guard(msg)
        except SecurityError as e:
            st.error(str(e.public_msg))
            log_event("chat_blocked", e.internal, error=True)
            return

        st.session_state.chat_history.append({"role": "user", "content": safe_msg})

        safe_hist = [
            m for m in st.session_state.chat_history[-6:]
            if m["role"] in ("user", "assistant")
        ]
        history_text = "\n".join(
            f"{'USER' if m['role']=='user' else 'NANOBOT'}: {m['content']}"
            for m in safe_hist
        )
        context = f"Conversation so far:\n{history_text}\n\nRespond to the latest USER message only."
        context = context[:2000]
        # Build rich chat context: metrics + risk engine output
        import json as _json
        risk_summary = {
            "risk_level":    st.session_state.risk.get("level"),
            "risk_score":    st.session_state.risk.get("weighted_breakdown", {}).get("final_score"),
            "risk_summary":  st.session_state.risk.get("summary"),
            "formula":       st.session_state.risk.get("formula"),
            "triggered_rules": [r["message"] for r in st.session_state.risk.get("triggered", [])],
            "recommendations": st.session_state.risk.get("recommendations", []),
        }
        combined = {
            "metrics":      st.session_state.metrics_clean,
            "risk_analysis": risk_summary,
        }
        chat_context = _json.dumps(combined, indent=2)
        if len(chat_context) > 4000:
            # Fallback: just metrics + risk level
            chat_context = _json.dumps({
                "metrics":     st.session_state.metrics_llm,
                "risk_level":  st.session_state.risk.get("level"),
                "risk_score":  st.session_state.risk.get("weighted_breakdown",{}).get("final_score"),
            }, indent=2)
        system = chat_system(chat_context)

        with st.spinner("NanoBot is thinking…"):
            try:
                reply = run_async(call_nanobot(system, context))
                st.session_state.chat_history.append({"role": "assistant", "content": reply})
                log_event("chat", f"q={safe_msg[:40]}")
            except Exception as e:
                err_msg = str(e)
                if "429" in err_msg:
                    st.error("Rate limit hit. Please wait a moment and try again.")
                else:
                    st.error(f"NanoBot unavailable: {err_msg[:120]}")
                log_event("chat_error", err_msg, error=True)
                st.session_state.chat_history.pop()  # remove unanswered user msg

    # ── Process pending message (from suggestion buttons) ─────────────────────
    if st.session_state.get("_pending_chat"):
        pending = st.session_state.pop("_pending_chat")
        send_message(pending)
        st.rerun()

    # ── Render chat history ───────────────────────────────────────────────────
    for msg in st.session_state.chat_history:
        if msg["role"] == "user":
            import html as _html
            safe_content = _html.escape(msg["content"])
            st.markdown(
                f'<div class="chat-label">You</div>'
                f'<div class="chat-user">{safe_content}</div>',
                unsafe_allow_html=True,
            )
        else:
            import html as _html
            bot_content = _html.escape(msg["content"])
            st.markdown(
                f'<div class="chat-label">NanoBot</div>'
                f'<div class="chat-bot">{bot_content}</div>',
                unsafe_allow_html=True,
            )

    # ── Suggested questions (only when no history) ────────────────────────────
    if not st.session_state.chat_history:
        st.markdown("**Suggested questions:**")
        suggestions = [
            "What does the F1 score tell us about this model?",
            "Is the PSI drift score concerning?",
            "What are the top 3 risks before deployment?",
            "Explain the false negative rate in plain English.",
            "What does the train-test gap indicate?",
        ]
        cols = st.columns(2)
        for i, q in enumerate(suggestions):
            with cols[i % 2]:
                if st.button(q, key=f"sugg_{i}", use_container_width=True):
                    st.session_state["_pending_chat"] = q
                    st.rerun()

    # ── Chat input form ───────────────────────────────────────────────────────
    with st.form("chat_form", clear_on_submit=True):
        col_inp, col_btn = st.columns([5, 1])
        with col_inp:
            user_input = st.text_input(
                "Message",
                placeholder="Ask about your metrics…",
                label_visibility="collapsed",
            )
        with col_btn:
            send = st.form_submit_button("Send", use_container_width=True)

    if send and user_input:
        send_message(user_input)
        st.rerun()

    # ── Clear history ─────────────────────────────────────────────────────────
    if st.session_state.chat_history:
        if st.button("🗑 Clear chat history"):
            st.session_state.chat_history = []
            st.rerun()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 5: RAW
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with tab_raw:
    st.markdown('<div class="section-title">Cleaned Metrics (post-whitelist)</div>',
                unsafe_allow_html=True)
    st.caption("Unknown fields have been stripped. Only allowlisted keys are shown.")
    st.json(st.session_state.metrics_clean, expanded=False)

    st.divider()
    st.markdown('<div class="section-title">LLM-safe Payload (numeric only)</div>',
                unsafe_allow_html=True)
    st.caption("Only these numeric values are ever sent to NanoBot.")
    st.code(st.session_state.metrics_llm, language="json")

    st.divider()
    st.markdown('<div class="section-title">Risk Engine Output</div>',
                unsafe_allow_html=True)
    st.json(st.session_state.risk, expanded=True)

    st.divider()
    st.markdown('<div class="section-title">Full Session Log</div>',
                unsafe_allow_html=True)
    if st.session_state.log:
        import pandas as pd
        st.dataframe(pd.DataFrame(st.session_state.log), width="stretch")
    else:
        st.caption("No events logged yet.")