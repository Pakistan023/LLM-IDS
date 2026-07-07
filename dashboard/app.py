"""
LLM-IDS Dashboard — Streamlit UI.

Run with:
    streamlit run dashboard/app.py

Panels:
  - Live/simulated traffic overview + severity gauges
  - Side-by-side detector comparison (Signature vs ML vs LLM)
  - LLM-generated natural-language threat reports (the headline feature)
  - Alert timeline & table with filters
  - Shift digest (NLP summarizer)
  - Voice/text security assistant chat box
  - Accuracy benchmark panel (runs src/evaluation/compare_accuracy)
"""

import os
import sys
import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.alerts.alert_manager import AlertManager
from src.alerts.nlp_summarizer import AlertSummarizer
from src.capture.traffic_simulator import TrafficSimulator
from src.db.database import AlertStore
from src.utils.config_loader import load_config

# --------------------------------------------------------------------- #
# Page config & theme
# --------------------------------------------------------------------- #
st.set_page_config(
    page_title="LLM-IDS | AI-Powered Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

SEVERITY_COLORS = {
    "info": "#4a90d9", "low": "#3ba55d", "medium": "#e6b800",
    "high": "#e6772e", "critical": "#d64545",
}

CUSTOM_CSS = """
<style>
    .block-container { padding-top: 1.6rem; }
    .metric-card {
        background: linear-gradient(145deg, #12151c, #191d27);
        border: 1px solid #262b38;
        border-radius: 12px;
        padding: 18px 20px;
    }
    .badge {
        display: inline-block; padding: 3px 10px; border-radius: 999px;
        font-size: 0.75rem; font-weight: 600; letter-spacing: 0.02em;
        text-transform: uppercase;
    }
    h1, h2, h3 { letter-spacing: -0.01em; }
    .stTabs [data-baseweb="tab-list"] { gap: 4px; }
    .llm-report {
        background: #14181f; border-left: 3px solid #4a90d9;
        border-radius: 8px; padding: 14px 18px; margin-bottom: 10px;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------- #
# Cached resources
# --------------------------------------------------------------------- #
@st.cache_resource
def get_alert_manager(use_llm: bool, use_rag: bool):
    return AlertManager(use_llm=use_llm, use_rag=use_rag)


@st.cache_resource
def get_store():
    return AlertStore()


def severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#888")
    return f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55;">{sev}</span>'


# --------------------------------------------------------------------- #
# Sidebar — controls
# --------------------------------------------------------------------- #
st.sidebar.markdown("## 🛡️ LLM-IDS Control Panel")
st.sidebar.caption("AI-Powered Intrusion Detection System")

data_source = st.sidebar.radio("Traffic source", ["Simulated (synthetic)", "Live capture (scapy)"], index=0)
use_llm = st.sidebar.checkbox("Enable LLM analyzer (Claude/GPT-4)", value=True)
use_rag = st.sidebar.checkbox("Enable RAG threat-intel grounding", value=True)
attack_ratio = st.sidebar.slider("Simulated attack ratio", 0.0, 0.6, 0.15, 0.05)
batch_size = st.sidebar.slider("Flows per window", 10, 100, 30, 5)

st.sidebar.divider()
run_once = st.sidebar.button("▶ Analyze one window", use_container_width=True)
clear_db = st.sidebar.button("🗑 Clear alert history", use_container_width=True)

st.sidebar.divider()
st.sidebar.markdown(
    "**Provider:** " + os.getenv("LLM_PROVIDER", "anthropic").capitalize()
    + "\n\n**Model:** " + os.getenv("ANTHROPIC_MODEL", os.getenv("OPENAI_MODEL", "not set"))
)
st.sidebar.caption("Configure API keys in `.env` (see `.env.example`).")

store = get_store()
if clear_db:
    store.clear()
    st.sidebar.success("Alert history cleared.")

# --------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------- #
col_title, col_status = st.columns([3, 1])
with col_title:
    st.title("🛡️ LLM-IDS")
    st.caption("Natural-language intrusion detection — Signature Engine vs. ML Classifier vs. LLM Analyzer")
with col_status:
    st.metric("Detectors active", f"{2 + int(use_llm)} / 3")

# --------------------------------------------------------------------- #
# Run detection on demand
# --------------------------------------------------------------------- #
if run_once:
    with st.spinner("Capturing traffic window and running all detectors..."):
        sim = TrafficSimulator(attack_ratio=attack_ratio)
        flows = sim.generate_window(n=batch_size)
        manager = get_alert_manager(use_llm, use_rag)
        result = manager.process_window(flows)
        st.session_state["last_result"] = result
        st.session_state["last_flows"] = flows
    st.success(f"Window analyzed — {len(flows)} flows processed.")

# --------------------------------------------------------------------- #
# Tabs
# --------------------------------------------------------------------- #
tab_overview, tab_compare, tab_llm, tab_alerts, tab_digest, tab_assistant, tab_bench = st.tabs(
    ["📊 Overview", "⚖️ Detector Comparison", "🧠 LLM Threat Reports",
     "🚨 Alert Log", "📰 Shift Digest", "🎙️ Security Assistant", "🏁 Accuracy Benchmark"]
)

# ---- Overview ---- #
with tab_overview:
    recent = store.fetch_recent(limit=500)
    df = pd.DataFrame(recent)

    c1, c2, c3, c4 = st.columns(4)
    total = len(df)
    critical_n = (df["severity"] == "critical").sum() if total else 0
    high_n = (df["severity"] == "high").sum() if total else 0
    detectors_n = df["detector"].nunique() if total else 0

    with c1:
        st.markdown(f'<div class="metric-card"><h3>{total}</h3>Total alerts stored</div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><h3 style="color:#d64545">{critical_n}</h3>Critical severity</div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="metric-card"><h3 style="color:#e6772e">{high_n}</h3>High severity</div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="metric-card"><h3>{detectors_n}</h3>Detectors reporting</div>', unsafe_allow_html=True)

    st.write("")
    if total:
        col_a, col_b = st.columns(2)
        with col_a:
            fig = px.pie(df, names="severity", title="Alerts by severity",
                         color="severity", color_discrete_map=SEVERITY_COLORS, hole=0.45)
            st.plotly_chart(fig, use_container_width=True)
        with col_b:
            fig2 = px.bar(df.groupby("detector").size().reset_index(name="count"),
                          x="detector", y="count", title="Alerts by detector",
                          color="detector")
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No alerts yet — click **Analyze one window** in the sidebar to generate traffic and run detection.")

# ---- Detector comparison ---- #
with tab_compare:
    st.subheader("Side-by-side detector output for the last analyzed window")
    if "last_result" not in st.session_state:
        st.info("Run an analysis window from the sidebar to populate this view.")
    else:
        result = st.session_state["last_result"]
        flows = st.session_state["last_flows"]
        flow_by_id = {f.flow_id: f for f in flows}

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("### 🪧 Signature Engine")
            st.caption("Fixed rules — fast, explainable, misses novel attacks")
            sig = result["signature"]
            if not sig:
                st.write("No signature matches.")
            for m in sig:
                st.markdown(
                    f'<div class="llm-report" style="border-left-color:#e6772e">'
                    f'<b>{m.rule_name}</b> {severity_badge(m.severity)}<br>'
                    f'<small>{m.mitre}</small><br>{m.description}</div>',
                    unsafe_allow_html=True,
                )
        with c2:
            st.markdown("### 📈 ML Classifier")
            st.caption("RandomForest — statistical pattern match, no explanation")
            ml_flagged = [(f, p, pred) for f, p, pred in result["ml"] if pred == "malicious"]
            if not ml_flagged:
                st.write("No anomalies flagged.")
            for f, p, pred in ml_flagged:
                st.markdown(
                    f'<div class="llm-report" style="border-left-color:#3ba55d">'
                    f'<b>{f.src_ip} → {f.dst_ip}:{f.dst_port}</b><br>'
                    f'Anomaly probability: <b>{p:.2f}</b></div>',
                    unsafe_allow_html=True,
                )
        with c3:
            st.markdown("### 🧠 LLM Analyzer")
            st.caption("Claude/GPT-4 + RAG — contextual, explains *why*")
            llm_result = result["llm"]
            if not llm_result or not llm_result.findings:
                st.write("No malicious/suspicious findings.")
            else:
                for finding in llm_result.findings:
                    if finding.verdict == "benign":
                        continue
                    st.markdown(
                        f'<div class="llm-report">'
                        f'<b>{finding.attack_technique or "Unclassified anomaly"}</b> '
                        f'{severity_badge(llm_result.overall_severity)}<br>'
                        f'<small>{finding.mitre_id or ""} · confidence {finding.confidence:.0%}</small><br>'
                        f'{finding.explanation}<br>'
                        f'<i>→ {finding.recommended_action}</i></div>',
                        unsafe_allow_html=True,
                    )

# ---- LLM full reports ---- #
with tab_llm:
    st.subheader("🧠 Natural-language threat report")
    if "last_result" not in st.session_state or not st.session_state["last_result"].get("llm"):
        st.info("Run an analysis window (with LLM analyzer enabled) from the sidebar.")
    else:
        llm_result = st.session_state["last_result"]["llm"]
        st.markdown(f"**Overall window severity:** {severity_badge(llm_result.overall_severity)}", unsafe_allow_html=True)
        st.write("")
        st.markdown("#### Executive summary")
        st.write(llm_result.executive_summary)
        st.write("")
        st.markdown("#### Per-flow findings")
        for f in llm_result.findings:
            with st.expander(f"{f.flow_id} — {f.verdict.upper()} ({f.confidence:.0%} confidence)"):
                st.write(f"**Technique:** {f.attack_technique or 'n/a'}  |  **MITRE:** {f.mitre_id or 'n/a'}")
                st.write(f"**Explanation:** {f.explanation}")
                st.write(f"**Recommended action:** {f.recommended_action}")
        with st.expander("Raw LLM JSON response (debug)"):
            st.code(llm_result.raw_response or "(empty)")

# ---- Alert log ---- #
with tab_alerts:
    st.subheader("🚨 Alert log")
    recent = store.fetch_recent(limit=500)
    if not recent:
        st.info("No alerts stored yet.")
    else:
        df = pd.DataFrame(recent)
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            sev_filter = st.multiselect("Severity", sorted(df["severity"].dropna().unique()), default=None)
        with col_f2:
            det_filter = st.multiselect("Detector", sorted(df["detector"].dropna().unique()), default=None)
        with col_f3:
            search = st.text_input("Search src/dst IP")

        filtered = df.copy()
        if sev_filter:
            filtered = filtered[filtered["severity"].isin(sev_filter)]
        if det_filter:
            filtered = filtered[filtered["detector"].isin(det_filter)]
        if search:
            filtered = filtered[
                filtered["src_ip"].str.contains(search, na=False) |
                filtered["dst_ip"].str.contains(search, na=False)
            ]

        st.dataframe(
            filtered[["timestamp", "detector", "severity", "verdict", "src_ip", "dst_ip",
                      "dst_port", "technique", "confidence", "explanation"]],
            use_container_width=True, height=420,
        )

# ---- Shift digest ---- #
with tab_digest:
    st.subheader("📰 SOC shift digest")
    st.caption("LLM-generated natural-language summary of recent alerts for shift handoff.")
    if st.button("Generate digest"):
        with st.spinner("Summarizing recent alerts..."):
            alerts = store.fetch_recent(limit=100)
            summarizer = AlertSummarizer()
            digest = summarizer.summarize(alerts)
        st.markdown(digest)

# ---- Security assistant ---- #
with tab_assistant:
    st.subheader("🎙️ Voice-driven security assistant")
    st.caption("Ask about recent alerts in plain English. Voice I/O works when run locally with a microphone; text works everywhere.")

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    for role, msg in st.session_state["chat_history"]:
        with st.chat_message(role):
            st.write(msg)

    user_q = st.chat_input("e.g. 'summarize critical alerts from the last hour'")
    if user_q:
        st.session_state["chat_history"].append(("user", user_q))
        with st.chat_message("user"):
            st.write(user_q)
        from src.voice.voice_assistant import VoiceSecurityAssistant
        assistant = VoiceSecurityAssistant()
        with st.spinner("Thinking..."):
            answer = assistant.ask_text(user_q)
        st.session_state["chat_history"].append(("assistant", answer))
        with st.chat_message("assistant"):
            st.write(answer)

# ---- Accuracy benchmark ---- #
with tab_bench:
    st.subheader("🏁 Detector accuracy benchmark")
    st.caption("Runs all three detectors against the same labeled synthetic traffic set for a fair comparison.")
    n_flows = st.slider("Number of flows to evaluate", 50, 1000, 200, 50)
    include_llm_bench = st.checkbox("Include LLM analyzer in benchmark (uses API calls)", value=False)

    if st.button("Run benchmark"):
        from src.evaluation.compare_accuracy import evaluate
        with st.spinner("Running benchmark — this may take a while if the LLM is included..."):
            results = evaluate(n_flows=n_flows, include_llm=include_llm_bench)

        cols = st.columns(len(results))
        for col, (key, res) in zip(cols, results.items()):
            with col:
                if "error" in res:
                    st.error(f"{key}: {res['error']}")
                    continue
                st.markdown(f"**{res['name']}**")
                st.metric("Accuracy", f"{res['accuracy']*100:.1f}%")
                st.metric("Precision", f"{res['precision']*100:.1f}%")
                st.metric("Recall", f"{res['recall']*100:.1f}%")
                st.metric("F1 score", f"{res['f1_score']*100:.1f}%")

        # Comparison chart
        chart_rows = []
        for key, res in results.items():
            if "error" in res:
                continue
            for metric in ["accuracy", "precision", "recall", "f1_score"]:
                chart_rows.append({"detector": res["name"], "metric": metric, "value": res[metric]})
        if chart_rows:
            chart_df = pd.DataFrame(chart_rows)
            fig = px.bar(chart_df, x="metric", y="value", color="detector", barmode="group",
                         title="Detector comparison")
            st.plotly_chart(fig, use_container_width=True)

st.sidebar.divider()
st.sidebar.caption("LLM-IDS · Built with Python, Scapy, scikit-learn, Streamlit, Anthropic/OpenAI APIs.")
