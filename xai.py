"""
xai.py — Explainability Layer (SHAP, LIME, ELI5)
Generates feature importance and explanation visuals from metrics JSON.
Works without the original model — reconstructs importance from available data.
"""

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# ── SHAP-style: Feature importance from drift + per-class data ────────────────

def shap_feature_importance(data: dict) -> go.Figure | None:
    """
    Build a SHAP-style bar chart from available feature importance signals.
    Uses: drift drifted_features, per_class_metrics, performance_metrics.
    """
    importance_data = {}

    # Extract per-class F1 as feature-level signal
    pcm = data.get("per_class_metrics", {})
    if isinstance(pcm, dict):
        for cls, vals in pcm.items():
            if isinstance(vals, dict) and "f1" in vals:
                importance_data[f"class:{cls}"] = float(vals["f1"])

    # Extract drifted features with PSI-weighted importance
    drift = data.get("drift_metrics", {})
    if isinstance(drift, dict):
        drifted = drift.get("drifted_features", [])
        psi     = drift.get("psi_score", 0.1)
        fds     = drift.get("feature_drift_score", 0.1)
        if isinstance(drifted, list):
            for i, feat in enumerate(drifted[:10]):
                # Assign decaying importance based on drift severity
                importance_data[f"drift:{feat}"] = round(psi * (1 - i * 0.08), 4)

    # Core performance metrics as importance signals
    pm = data.get("performance_metrics", {})
    if isinstance(pm, dict):
        for key in ["f1_score","precision","recall","auc_roc","roc_auc","balanced_accuracy"]:
            if key in pm:
                importance_data[f"metric:{key}"] = float(pm[key])

    if not importance_data:
        return None

    df = pd.DataFrame(
        {"feature": list(importance_data.keys()),
         "importance": list(importance_data.values())}
    ).sort_values("importance", ascending=True).tail(15)

    colors = []
    for f in df["feature"]:
        if f.startswith("drift:"): colors.append("#E24B4A")
        elif f.startswith("class:"): colors.append("#378ADD")
        else: colors.append("#1D9E75")

    fig = go.Figure(go.Bar(
        x=df["importance"], y=df["feature"],
        orientation="h",
        marker_color=colors,
        hovertemplate="<b>%{y}</b><br>Importance: %{x:.4f}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text="SHAP-style Feature Importance", font=dict(size=15)),
        xaxis_title="Importance Score",
        yaxis_title="",
        height=max(300, len(df) * 28 + 80),
        margin=dict(l=20, r=20, t=50, b=40),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
        legend_title_text="Type",
    )
    # Legend annotation
    fig.add_annotation(
        x=0.98, y=0.02, xref="paper", yref="paper", showarrow=False,
        text="🔴 Drift  🔵 Per-class  🟢 Core metric",
        font=dict(size=10), align="right"
    )
    return fig


# ── LIME-style: Local explanation for a single prediction boundary ────────────

def lime_boundary_explanation(data: dict) -> go.Figure | None:
    """
    LIME-style local explanation showing which metric factors push the
    model toward or away from a positive prediction at the decision boundary.
    """
    pm   = data.get("performance_metrics", {})
    thr  = data.get("threshold_analysis", {})
    cal  = data.get("calibration", {})
    gen  = data.get("generalization", {})

    factors = {}

    # Build factor contributions (positive = pushes toward deployment,
    # negative = pushes against)
    def get(d, *keys):
        for k in keys:
            if isinstance(d, dict) and k in d:
                return d[k]
        return None

    f1  = get(pm, "f1_score", "f1", "macro_f1")
    auc = get(pm, "auc_roc", "roc_auc")
    prec = get(pm, "precision", "macro_precision")
    rec  = get(pm, "recall", "macro_recall")
    ece  = get(cal, "expected_calibration_error")
    gap  = get(gen, "train_test_gap")
    opt_thr = get(thr, "optimal_threshold")
    def_thr = get(thr, "default_threshold")

    if f1   is not None: factors["F1 Score"]       = (f1 - 0.75) * 2
    if auc  is not None: factors["AUC-ROC"]         = (auc - 0.80) * 3
    if prec is not None: factors["Precision"]       = (prec - 0.75) * 1.5
    if rec  is not None: factors["Recall"]          = (rec - 0.70) * 1.5
    if ece  is not None: factors["Calibration ECE"] = -(ece - 0.05) * 5
    if gap  is not None: factors["Overfit Gap"]     = -(gap - 0.03) * 8
    if opt_thr and def_thr:
        factors["Threshold Delta"] = -(abs(opt_thr - def_thr)) * 3

    if not factors:
        return None

    items = sorted(factors.items(), key=lambda x: abs(x[1]), reverse=True)[:10]
    labels = [i[0] for i in items]
    values = [i[1] for i in items]
    colors = ["#1D9E75" if v > 0 else "#E24B4A" for v in values]

    fig = go.Figure(go.Bar(
        x=values, y=labels,
        orientation="h",
        marker_color=colors,
        hovertemplate="<b>%{y}</b><br>Contribution: %{x:.3f}<extra></extra>",
    ))
    fig.add_vline(x=0, line_width=1.5, line_color="gray")
    fig.update_layout(
        title=dict(text="LIME-style Local Explanation (Decision Boundary)", font=dict(size=15)),
        xaxis_title="← Against Deployment | For Deployment →",
        height=max(280, len(labels) * 30 + 80),
        margin=dict(l=20, r=20, t=50, b=40),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
    )
    return fig


# ── ELI5-style: Weight table explaining each metric's contribution ────────────

def eli5_weight_table(data: dict) -> pd.DataFrame | None:
    """
    ELI5-style weight table: each metric, its value, weight/contribution,
    plain-English explanation, and risk flag.
    """
    rows = []

    metric_meta = {
        # key: (display_name, good_thresh, bad_thresh, higher_is_better, explanation_template)
        "accuracy":        ("Accuracy", 0.90, 0.80, True,  "% of all predictions correct"),
        "precision":       ("Precision", 0.80, 0.65, True,  "Of predicted positives, % actually positive (false alarm rate)"),
        "recall":          ("Recall", 0.75, 0.60, True,  "Of actual positives, % correctly found (miss rate)"),
        "f1_score":        ("F1 Score", 0.80, 0.70, True,  "Harmonic mean of precision & recall — balance metric"),
        "f1":              ("F1 Score", 0.80, 0.70, True,  "Harmonic mean of precision & recall"),
        "auc_roc":         ("AUC-ROC", 0.90, 0.75, True,  "Discrimination ability across all thresholds"),
        "roc_auc":         ("AUC-ROC", 0.90, 0.75, True,  "Discrimination ability across all thresholds"),
        "log_loss":        ("Log Loss", 0.3, 0.6, False, "Penalises confident wrong predictions"),
        "false_negative_rate": ("False Negative Rate", 0.20, 0.40, False, "Proportion of positives incorrectly classified as negative"),
        "false_positive_rate": ("False Positive Rate", 0.10, 0.20, False, "Proportion of negatives incorrectly classified as positive"),
        "psi_score":       ("PSI (Drift)", 0.10, 0.20, False, "Population Stability Index — measures distribution shift"),
        "feature_drift_score": ("Feature Drift", 0.15, 0.30, False, "Overall feature distribution shift score"),
        "train_test_gap":  ("Train-Test Gap", 0.02, 0.05, False, "Accuracy difference between train and test — overfitting signal"),
        "cross_val_std":   ("CV Std Dev", 0.005, 0.010, False, "Stability across cross-validation folds"),
        "expected_calibration_error": ("Calibration ECE", 0.03, 0.07, False, "How well confidence scores match actual probabilities"),
        "mae":             ("MAE", None, None, False, "Mean Absolute Error — average prediction deviation"),
        "rmse":            ("RMSE", None, None, False, "Root Mean Squared Error — penalises large errors more"),
        "r2_score":        ("R² Score", 0.85, 0.65, True,  "Proportion of target variance explained by the model"),
        "demographic_parity_diff": ("Fairness (DPD)", 0.05, 0.10, False, "Difference in positive prediction rates across groups"),
    }

    def _extract_flat(d: dict, prefix: str = "") -> dict:
        out = {}
        for k, v in d.items():
            if isinstance(v, dict):
                out.update(_extract_flat(v, f"{prefix}.{k}" if prefix else k))
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                out[k] = v
        return out

    flat = _extract_flat(data)

    seen = set()
    for key, meta in metric_meta.items():
        if key in flat and key not in seen:
            seen.add(key)
            val   = flat[key]
            name, good, bad, hib, expl = meta

            # Weight = normalised distance from thresholds
            if good is not None and bad is not None:
                if hib:
                    weight = (val - bad) / max(good - bad, 0.01)
                else:
                    weight = (bad - val) / max(bad - good, 0.01)
                weight = round(max(-1.0, min(1.0, weight)), 3)
                if hib:
                    status = "✅ Good" if val >= good else ("⚠️ Fair" if val >= bad else "❌ Poor")
                else:
                    status = "✅ Good" if val <= good else ("⚠️ Fair" if val <= bad else "❌ Poor")
            else:
                weight = 0.0
                status = "ℹ️ Info"

            rows.append({
                "Metric":       name,
                "Value":        round(val, 4),
                "Weight":       weight,
                "Status":       status,
                "Explanation":  expl,
            })

    if not rows:
        return None
    return pd.DataFrame(rows).sort_values("Weight", ascending=False)


# ── Radar chart: multi-metric overview ───────────────────────────────────────

def radar_chart(data: dict) -> go.Figure | None:
    pm = data.get("performance_metrics", {})
    if not isinstance(pm, dict): return None

    candidates = {
        "Accuracy":  pm.get("accuracy") or pm.get("balanced_accuracy"),
        "Precision": pm.get("precision") or pm.get("macro_precision"),
        "Recall":    pm.get("recall") or pm.get("macro_recall"),
        "F1":        pm.get("f1_score") or pm.get("f1") or pm.get("macro_f1"),
        "AUC-ROC":   pm.get("auc_roc") or pm.get("roc_auc"),
    }
    metrics = {k: v for k, v in candidates.items() if v is not None}
    if len(metrics) < 3: return None

    cats   = list(metrics.keys()) + [list(metrics.keys())[0]]
    values = list(metrics.values()) + [list(metrics.values())[0]]

    fig = go.Figure(go.Scatterpolar(
        r=values, theta=cats, fill="toself",
        fillcolor="rgba(29,158,117,0.2)",
        line=dict(color="#1D9E75", width=2),
        hovertemplate="<b>%{theta}</b>: %{r:.3f}<extra></extra>",
    ))
    fig.add_trace(go.Scatterpolar(
        r=[0.8]*len(cats), theta=cats,
        mode="lines",
        line=dict(color="rgba(186,117,23,0.5)", width=1.5, dash="dot"),
        name="Threshold (0.80)",
        hoverinfo="skip",
    ))
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
        title=dict(text="Performance Radar", font=dict(size=15)),
        showlegend=True,
        height=380,
        margin=dict(l=30, r=30, t=60, b=30),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
    )
    return fig


# ── Latency distribution bar chart ───────────────────────────────────────────

def latency_chart(data: dict) -> go.Figure | None:
    lat = data.get("latency_ms", {})
    if not isinstance(lat, dict): return None
    pts = {k: v for k, v in lat.items() if isinstance(v, (int, float)) and k in ("p50","p95","p99","mean")}
    if not pts: return None

    labels = list(pts.keys())
    values = list(pts.values())
    colors = []
    for v in values:
        if v < 100:   colors.append("#1D9E75")
        elif v < 200: colors.append("#BA7517")
        elif v < 500: colors.append("#E24B4A")
        else:         colors.append("#791F1F")

    fig = go.Figure(go.Bar(
        x=labels, y=values,
        marker_color=colors,
        text=[f"{v}ms" for v in values],
        textposition="outside",
        hovertemplate="<b>%{x}</b>: %{y}ms<extra></extra>",
    ))
    fig.add_hline(y=200, line_dash="dot", line_color="#BA7517",
                  annotation_text="200ms SLA")
    fig.add_hline(y=500, line_dash="dot", line_color="#E24B4A",
                  annotation_text="500ms critical")
    fig.update_layout(
        title=dict(text="Latency Distribution (ms)", font=dict(size=15)),
        yaxis_title="Latency (ms)",
        height=320,
        margin=dict(l=20, r=20, t=50, b=40),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
    )
    return fig


# ── Confusion matrix heatmap ──────────────────────────────────────────────────

def confusion_matrix_chart(data: dict) -> go.Figure | None:
    cm = data.get("confusion_matrix", {})
    if not isinstance(cm, dict): return None
    tp = cm.get("true_positive")
    tn = cm.get("true_negative")
    fp = cm.get("false_positive")
    fn = cm.get("false_negative")
    if any(v is None for v in [tp, tn, fp, fn]): return None

    z      = [[tn, fp], [fn, tp]]
    labels = [["TN", "FP"], ["FN", "TP"]]
    text   = [[f"TN\n{tn:,}", f"FP\n{fp:,}"], [f"FN\n{fn:,}", f"TP\n{tp:,}"]]

    fig = go.Figure(go.Heatmap(
        z=z, text=text, texttemplate="%{text}",
        colorscale=[[0,"#FAECE7"],[0.5,"#F0997B"],[1,"#993C1D"]],
        showscale=True,
        hovertemplate="<b>%{text}</b><br>Count: %{z:,}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text="Confusion Matrix", font=dict(size=15)),
        xaxis=dict(tickvals=[0,1], ticktext=["Predicted Negative","Predicted Positive"]),
        yaxis=dict(tickvals=[0,1], ticktext=["Actual Negative","Actual Positive"]),
        height=320,
        margin=dict(l=20, r=20, t=50, b=60),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
    )
    return fig


# ── Per-class performance bar chart ──────────────────────────────────────────

def per_class_chart(data: dict) -> go.Figure | None:
    pcm = data.get("per_class_metrics", {})
    if not isinstance(pcm, dict) or not pcm: return None

    classes, precisions, recalls, f1s = [], [], [], []
    for cls, vals in pcm.items():
        if not isinstance(vals, dict): continue
        classes.append(cls)
        precisions.append(vals.get("precision", 0))
        recalls.append(vals.get("recall", 0))
        f1s.append(vals.get("f1", 0))

    if not classes: return None

    fig = go.Figure()
    fig.add_trace(go.Bar(name="Precision", x=classes, y=precisions,
                         marker_color="#378ADD", opacity=0.85))
    fig.add_trace(go.Bar(name="Recall",    x=classes, y=recalls,
                         marker_color="#1D9E75", opacity=0.85))
    fig.add_trace(go.Bar(name="F1",        x=classes, y=f1s,
                         marker_color="#BA7517", opacity=0.85))
    fig.update_layout(
        barmode="group",
        title=dict(text="Per-Class Performance", font=dict(size=15)),
        yaxis=dict(title="Score", range=[0, 1.05]),
        height=360,
        margin=dict(l=20, r=20, t=50, b=60),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    return fig


# ── Drift gauge ───────────────────────────────────────────────────────────────

def drift_gauge(data: dict) -> go.Figure | None:
    drift = data.get("drift_metrics", {})
    if not isinstance(drift, dict): return None
    psi = drift.get("psi_score")
    if psi is None: return None

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=psi,
        delta={"reference": 0.10},
        title={"text": "Population Stability Index (PSI)"},
        gauge={
            "axis": {"range": [0, 0.4], "tickwidth": 1},
            "bar":  {"color": "#378ADD"},
            "steps": [
                {"range": [0,    0.10], "color": "#EAF3DE"},
                {"range": [0.10, 0.20], "color": "#FAEEDA"},
                {"range": [0.20, 0.40], "color": "#FCEBEB"},
            ],
            "threshold": {
                "line": {"color": "#E24B4A", "width": 3},
                "thickness": 0.8, "value": 0.20,
            },
        },
        number={"suffix": "", "valueformat": ".3f"},
    ))
    fig.update_layout(
        height=280,
        margin=dict(l=20, r=20, t=60, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
    )
    return fig


# ── ROC Curve (approximated from AUC + threshold data) ───────────────────────

def roc_curve_chart(data: dict):
    """Approximate ROC curve from AUC-ROC value."""
    import numpy as np
    pm  = data.get("performance_metrics", {})
    auc = pm.get("auc_roc") or pm.get("roc_auc")
    if auc is None:
        return None

    # Generate approximate ROC curve from AUC using beta distribution
    fpr = np.linspace(0, 1, 100)
    # Approximate TPR curve that gives the stated AUC
    tpr = np.power(fpr, (1 - auc) / auc) if auc > 0.5 else fpr

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=fpr.tolist(), y=tpr.tolist(),
        mode="lines", name=f"Model (AUC={auc:.3f})",
        line=dict(color="#1D9E75", width=2.5),
        fill="tozeroy", fillcolor="rgba(29,158,117,0.08)",
        hovertemplate="FPR: %{x:.3f}<br>TPR: %{y:.3f}<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=[0, 1], y=[0, 1],
        mode="lines", name="Random (AUC=0.50)",
        line=dict(color="#888780", width=1.5, dash="dot"),
        hoverinfo="skip",
    ))
    fig.add_annotation(
        x=0.6, y=0.35, showarrow=False,
        text=f"AUC-ROC = {auc:.3f}",
        font=dict(size=13, color="#1D9E75"),
    )
    fig.update_layout(
        title=dict(text="ROC Curve", font=dict(size=15)),
        xaxis_title="False Positive Rate",
        yaxis_title="True Positive Rate",
        xaxis=dict(range=[0, 1]),
        yaxis=dict(range=[0, 1.05]),
        height=340,
        margin=dict(l=20, r=20, t=50, b=50),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
        legend=dict(x=0.6, y=0.1),
    )
    return fig


# ── Precision-Recall Curve ────────────────────────────────────────────────────

def pr_curve_chart(data: dict):
    """Precision-Recall curve from available metrics."""
    import numpy as np
    pm        = data.get("performance_metrics", {})
    precision = pm.get("precision") or pm.get("macro_precision")
    recall    = pm.get("recall")    or pm.get("macro_recall")
    f1        = pm.get("f1_score")  or pm.get("f1") or pm.get("macro_f1")
    auc_pr    = pm.get("auc_pr")

    if precision is None or recall is None:
        return None

    # Plot the operating point + approximate curve
    recalls    = np.linspace(0.01, 1.0, 100)
    # Approximate P-R tradeoff: higher recall → lower precision
    baseline   = precision * recall / (0.5 * (precision + recall)) if (precision + recall) > 0 else 0.5
    precisions = np.clip(baseline / (recalls + 1e-6) * recall, 0, 1)

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=recalls.tolist(), y=precisions.tolist(),
        mode="lines", name="P-R curve",
        line=dict(color="#378ADD", width=2),
        fill="tozeroy", fillcolor="rgba(55,138,221,0.08)",
        hovertemplate="Recall: %{x:.3f}<br>Precision: %{y:.3f}<extra></extra>",
    ))
    # Mark the operating point
    fig.add_trace(go.Scatter(
        x=[recall], y=[precision],
        mode="markers+text",
        name=f"Operating point (F1={f1:.3f})" if f1 else "Operating point",
        marker=dict(size=12, color="#E24B4A", symbol="star"),
        text=[f"  F1={f1:.3f}" if f1 else ""],
        textposition="middle right",
    ))
    if auc_pr:
        fig.add_annotation(
            x=0.5, y=0.85, showarrow=False,
            text=f"AUC-PR = {auc_pr:.3f}",
            font=dict(size=12, color="#378ADD"),
        )
    fig.update_layout(
        title=dict(text="Precision-Recall Curve", font=dict(size=15)),
        xaxis_title="Recall",
        yaxis_title="Precision",
        xaxis=dict(range=[0, 1]),
        yaxis=dict(range=[0, 1.05]),
        height=340,
        margin=dict(l=20, r=20, t=50, b=50),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
        legend=dict(x=0.3, y=0.1),
    )
    return fig