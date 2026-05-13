import streamlit as st
import requests
import os
import time
import uuid
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────────
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

st.set_page_config(
    page_title="SentraGuard Lite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap');

html, body, [class*="css"] { font-family: 'Syne', sans-serif; }

.stApp { background: #f4f6f9; color: #0f172a; }

#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 2rem 2.5rem 4rem; max-width: 1400px; }

::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #f4f6f9; }
::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }

/* ── Header ── */
.header-bar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1.2rem 0 2rem; border-bottom: 2px solid #e2e8f0; margin-bottom: 2.5rem;
}
.header-logo { display: flex; align-items: center; gap: 14px; }
.header-logo-icon {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, #f97316, #dc2626);
    border-radius: 12px; display: flex; align-items: center;
    justify-content: center; font-size: 22px;
    box-shadow: 0 4px 16px rgba(249,115,22,0.25);
}
.header-title { font-size: 1.4rem; font-weight: 800; letter-spacing: -0.02em; color: #0f172a; }
.header-subtitle {
    font-size: 0.7rem; color: #94a3b8; letter-spacing: 0.12em;
    text-transform: uppercase; font-family: 'JetBrains Mono', monospace;
}
.header-status {
    display: flex; align-items: center; gap: 8px;
    background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px;
    padding: 8px 16px; font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace; color: #64748b;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
.status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #22c55e; box-shadow: 0 0 6px #22c55e;
    animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

/* ── Section labels ── */
.section-label {
    font-size: 0.68rem; font-weight: 700; letter-spacing: 0.15em;
    text-transform: uppercase; color: #94a3b8;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 0.8rem; display: flex; align-items: center; gap: 8px;
}
.section-label::after { content: ''; flex: 1; height: 1px; background: #e2e8f0; }

/* ── Inputs ── */
.stTextArea textarea {
    background: #ffffff !important; border: 1.5px solid #e2e8f0 !important;
    border-radius: 10px !important; color: #0f172a !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: 0.88rem !important;
    padding: 1rem !important; box-shadow: 0 1px 4px rgba(0,0,0,0.04) !important;
}
.stTextArea textarea:focus {
    border-color: #f97316 !important;
    box-shadow: 0 0 0 3px rgba(249,115,22,0.12) !important;
}
.stTextInput input {
    background: #ffffff !important; border: 1.5px solid #e2e8f0 !important;
    border-radius: 8px !important; color: #0f172a !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: 0.84rem !important;
    box-shadow: 0 1px 4px rgba(0,0,0,0.04) !important;
}
.stTextInput input:focus {
    border-color: #f97316 !important;
    box-shadow: 0 0 0 3px rgba(249,115,22,0.12) !important;
}
.stNumberInput input {
    background: #ffffff !important; border: 1.5px solid #e2e8f0 !important;
    color: #0f172a !important; font-family: 'JetBrains Mono', monospace !important;
    box-shadow: 0 1px 4px rgba(0,0,0,0.04) !important;
}
label { color: #64748b !important; font-size: 0.78rem !important;
        font-family: 'JetBrains Mono', monospace !important; letter-spacing: 0.05em !important; }

/* ── Button ── */
.stButton > button {
    background: linear-gradient(135deg, #f97316, #dc2626) !important;
    color: white !important; border: none !important; border-radius: 10px !important;
    font-family: 'Syne', sans-serif !important; font-weight: 700 !important;
    font-size: 0.95rem !important; letter-spacing: 0.02em !important;
    padding: 0.7rem 2rem !important; width: 100% !important;
    transition: all 0.2s !important;
    box-shadow: 0 4px 16px rgba(249,115,22,0.28) !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 24px rgba(249,115,22,0.42) !important;
}
.stButton > button:active { transform: translateY(0) !important; }

/* ── Decision banner ── */
.decision-banner {
    border-radius: 14px; padding: 1.4rem 1.8rem;
    display: flex; align-items: center; gap: 16px;
    margin-bottom: 1.5rem; border: 1.5px solid;
}
.decision-allow     { background: #f0fdf4; border-color: #86efac; }
.decision-transform { background: #fefce8; border-color: #fde047; }
.decision-block     { background: #fef2f2; border-color: #fca5a5; }
.decision-icon  { font-size: 2rem; line-height: 1; }
.decision-label { font-size: 0.65rem; font-family: 'JetBrains Mono', monospace;
                  letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 3px; color: #94a3b8; }
.decision-value { font-size: 1.6rem; font-weight: 800; letter-spacing: -0.02em; }
.allow-color    { color: #16a34a; }
.transform-color{ color: #ca8a04; }
.block-color    { color: #dc2626; }

/* ── Risk tags ── */
.tags-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 1.2rem; }
.risk-tag {
    display: inline-flex; align-items: center; gap: 6px;
    background: #fff1f2; border: 1.5px solid #fca5a5; color: #dc2626;
    border-radius: 6px; padding: 5px 12px; font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 0.04em;
}
.no-tags { color: #94a3b8; font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; font-style: italic; }

/* ── Output box ── */
.output-box {
    background: #f8fafc; border: 1.5px solid #e2e8f0; border-radius: 10px;
    padding: 1rem 1.2rem; font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem; color: #334155; white-space: pre-wrap;
    word-break: break-word; max-height: 200px; overflow-y: auto;
    margin-bottom: 1rem; line-height: 1.6;
}

/* ── Evidence ── */
.evidence-item {
    display: flex; gap: 10px; padding: 0.8rem 0;
    border-bottom: 1px solid #f1f5f9;
}
.evidence-tag {
    flex-shrink: 0; background: #fff7ed; border: 1.5px solid #fed7aa;
    color: #ea580c; border-radius: 5px; padding: 3px 10px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; font-weight: 700;
}
.evidence-text { color: #475569; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.5; }

/* ── Expanders ── */
.stExpander {
    background: #ffffff !important; border: 1.5px solid #e2e8f0 !important;
    border-radius: 10px !important; box-shadow: 0 1px 4px rgba(0,0,0,0.04) !important;
}
.stExpander summary { color: #64748b !important; font-family: 'JetBrains Mono', monospace !important; font-size: 0.78rem !important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #ffffff !important; border-right: 1.5px solid #e2e8f0 !important;
    box-shadow: 2px 0 12px rgba(0,0,0,0.04) !important;
}
[data-testid="stSidebar"] .block-container { padding: 1.5rem 1rem; }

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: #ffffff; border: 1.5px solid #e2e8f0;
    border-radius: 10px; padding: 0.8rem 1rem;
    box-shadow: 0 1px 4px rgba(0,0,0,0.04);
}
[data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 1.4rem !important; color: #0f172a !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.7rem !important; color: #94a3b8 !important;
    text-transform: uppercase !important; letter-spacing: 0.1em !important;
}

/* ── History ── */
.history-item {
    display: flex; align-items: center; gap: 10px;
    padding: 0.6rem 0; border-bottom: 1px solid #f1f5f9;
    cursor: default; transition: opacity 0.15s;
}
.history-item:hover { opacity: 0.6; }
.history-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.history-prompt {
    flex: 1; font-size: 0.75rem; font-family: 'JetBrains Mono', monospace;
    color: #64748b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.history-decision { font-size: 0.68rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 0.08em; }

/* ── Score bar ── */
.score-bar-track { height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; margin-bottom: 6px; }
.score-bar-fill  { height: 100%; border-radius: 4px; }
.score-legend    { display: flex; justify-content: space-between; font-size: 0.63rem; font-family: 'JetBrains Mono', monospace; color: #94a3b8; }

hr { border-color: #e2e8f0 !important; }
.stAlert { border-radius: 10px !important; font-family: 'JetBrains Mono', monospace !important; font-size: 0.82rem !important; }
</style>
""", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="header-bar">
  <div class="header-logo">
    <div class="header-logo-icon">🛡️</div>
    <div>
      <div class="header-title">SentraGuard Lite</div>
      <div class="header-subtitle">Guardrails Gateway · Real-time Analysis</div>
    </div>
  </div>
  <div class="header-status">
    <div class="status-dot"></div>
    Gateway Online
  </div>
</div>
""", unsafe_allow_html=True)

# ── Sidebar ─────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="section-label">Gateway Config</div>', unsafe_allow_html=True)
    api_url = st.text_input("API Endpoint", value=API_BASE_URL,
                             label_visibility="collapsed", placeholder="http://localhost:8000")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-label">Detection Layers</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#475569;line-height:2.4;">
        <div>🔴 &nbsp;Prompt Injection</div>
        <div>🟡 &nbsp;PII Redaction</div>
        <div>🟠 &nbsp;RAG Injection</div>
    </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-label">Thresholds</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.76rem;line-height:2.6;">
        <span style="color:#16a34a;">●</span>&nbsp;<span style="color:#64748b;">Allow &nbsp;&nbsp;&nbsp;score &lt; 0.40</span><br>
        <span style="color:#ca8a04;">●</span>&nbsp;<span style="color:#64748b;">Transform  0.40 – 0.79</span><br>
        <span style="color:#dc2626;">●</span>&nbsp;<span style="color:#64748b;">Block &nbsp;&nbsp;score ≥ 0.80</span>
    </div>""", unsafe_allow_html=True)

    if st.session_state.history:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-label">Recent Requests</div>', unsafe_allow_html=True)
        for item in reversed(st.session_state.history[-6:]):
            color = {"allow": "#16a34a", "transform": "#ca8a04", "block": "#dc2626"}.get(
                item["decision"], "#94a3b8"
            )
            st.markdown(f"""
            <div class="history-item">
                <div class="history-dot" style="background:{color};"></div>
                <div class="history-prompt">{item['prompt'][:42]}…</div>
                <div class="history-decision" style="color:{color};">{item['decision'].upper()}</div>
            </div>""", unsafe_allow_html=True)

# ── Two-column layout ──────────────────────────────────────────────────────────
col_input, col_result = st.columns([1, 1], gap="large")

# ── LEFT: Input ────────────────────────────────────────────────────────────────
with col_input:
    st.markdown('<div class="section-label">📡 &nbsp;Input</div>', unsafe_allow_html=True)

    prompt = st.text_area("Prompt", placeholder="Enter prompt to analyze…",
                           height=180, label_visibility="collapsed")

    c1, c2 = st.columns(2)
    with c1:
        user_id = st.text_input("User ID", value="demo_user", placeholder="user_id")
    with c2:
        app_id = st.text_input("App ID", value="streamlit_ui", placeholder="app_id")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-label">📄 &nbsp;Context Documents</div>', unsafe_allow_html=True)
    num_docs = st.number_input("Documents (0–3)", min_value=0, max_value=3,
                                value=0, label_visibility="collapsed")
    context_docs = []
    for i in range(num_docs):
        with st.expander(f"Document {i + 1}", expanded=True):
            dc1, dc2 = st.columns([1, 3])
            with dc1:
                doc_id = st.text_input("ID", value=f"doc-{i+1}", key=f"id_{i}")
            with dc2:
                doc_text = st.text_area("Content", height=80, key=f"text_{i}",
                                         placeholder="Paste document text…")
            context_docs.append({"id": doc_id, "text": doc_text})

    st.markdown("<br>", unsafe_allow_html=True)
    analyze = st.button("⚡  Analyze Request", type="primary", use_container_width=True)

# ── RIGHT: Results ─────────────────────────────────────────────────────────────
with col_result:
    st.markdown('<div class="section-label">📊 &nbsp;Analysis</div>', unsafe_allow_html=True)

    if analyze and not prompt.strip():
        st.warning("Enter a prompt before analyzing.")

    elif analyze and prompt.strip():
        request_id = str(uuid.uuid4())[:8]
        payload = {
            "prompt": prompt,
            "context_docs": context_docs,
            "metadata": {"app_id": app_id, "user_id": user_id, "request_id": request_id},
        }

        with st.spinner("Running detection pipeline…"):
            t0 = time.time()
            try:
                resp = requests.post(f"{api_url}/analyze", json=payload, timeout=30)
                elapsed = time.time() - t0

                if resp.status_code == 200:
                    result = resp.json()
                    st.session_state.history.append({
                        "prompt": prompt,
                        "decision": result["decision"],
                        "score": result["risk_score"],
                    })

                    decision   = result["decision"]
                    score      = result["risk_score"]
                    risk_tags  = result.get("risk_tags", [])
                    reasons    = result.get("reasons", [])
                    san_prompt = result.get("sanitized_prompt", prompt)
                    san_docs   = result.get("sanitized_context_docs", [])

                    # Decision banner
                    icon = {"allow": "✅", "transform": "⚠️", "block": "🚫"}.get(decision, "❓")
                    st.markdown(f"""
                    <div class="decision-banner decision-{decision}">
                        <div class="decision-icon">{icon}</div>
                        <div>
                            <div class="decision-label">Decision</div>
                            <div class="decision-value {decision}-color">{decision.upper()}</div>
                        </div>
                        <div style="margin-left:auto;text-align:right;">
                            <div style="font-family:'JetBrains Mono',monospace;font-size:0.63rem;
                                        color:#94a3b8;margin-bottom:3px;letter-spacing:0.1em;">LATENCY</div>
                            <div style="font-family:'JetBrains Mono',monospace;font-size:0.95rem;
                                        color:#64748b;font-weight:600;">{elapsed*1000:.0f} ms</div>
                        </div>
                    </div>""", unsafe_allow_html=True)

                    # Score gauge
                    pct = int(score * 100)
                    bar_color = (
                        "linear-gradient(90deg,#22c55e,#16a34a)" if score < 0.4
                        else "linear-gradient(90deg,#eab308,#ca8a04)" if score < 0.8
                        else "linear-gradient(90deg,#ef4444,#dc2626)"
                    )
                    score_color = "#16a34a" if score < 0.4 else "#ca8a04" if score < 0.8 else "#dc2626"
                    st.markdown(f"""
                    <div style="background:#ffffff;border:1.5px solid #e2e8f0;border-radius:12px;
                                padding:1.2rem 1.4rem;margin-bottom:1.2rem;
                                box-shadow:0 1px 6px rgba(0,0,0,0.05);">
                        <div style="font-size:0.63rem;font-family:'JetBrains Mono',monospace;
                                    letter-spacing:0.15em;color:#94a3b8;
                                    text-transform:uppercase;margin-bottom:0.9rem;">Risk Score</div>
                        <div style="display:flex;align-items:center;gap:16px;">
                            <div style="font-size:2.8rem;font-weight:800;
                                        font-family:'JetBrains Mono',monospace;
                                        letter-spacing:-0.04em;line-height:1;
                                        min-width:90px;color:{score_color};">{score:.2f}</div>
                            <div style="flex:1;">
                                <div class="score-bar-track">
                                    <div class="score-bar-fill"
                                         style="width:{pct}%;background:{bar_color};"></div>
                                </div>
                                <div class="score-legend">
                                    <span>0.0</span><span>0.4 allow</span>
                                    <span>0.8 block</span><span>1.0</span>
                                </div>
                            </div>
                        </div>
                    </div>""", unsafe_allow_html=True)

                    # Risk tags
                    st.markdown("""
                    <div style="font-size:0.63rem;font-family:'JetBrains Mono',monospace;
                                letter-spacing:0.15em;color:#94a3b8;text-transform:uppercase;
                                margin-bottom:0.7rem;">Risk Tags</div>""", unsafe_allow_html=True)
                    if risk_tags:
                        tags_html = "".join(f'<span class="risk-tag">⚑ {t}</span>' for t in risk_tags)
                        st.markdown(f'<div class="tags-row">{tags_html}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="no-tags" style="margin-bottom:1rem;">No risk tags detected</div>',
                                    unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)

                    # Tabs
                    tab_san, tab_ev, tab_raw = st.tabs(
                        ["🧹  Sanitized Output", "🔍  Evidence", "{ }  Raw JSON"]
                    )

                    with tab_san:
                        st.markdown("""
                        <div style="font-size:0.63rem;font-family:'JetBrains Mono',monospace;
                                    color:#94a3b8;letter-spacing:0.1em;margin-bottom:6px;">
                            SANITIZED PROMPT</div>""", unsafe_allow_html=True)
                        st.markdown(f'<div class="output-box">{san_prompt}</div>', unsafe_allow_html=True)
                        for doc in san_docs:
                            st.markdown(f"""
                            <div style="font-size:0.63rem;font-family:'JetBrains Mono',monospace;
                                        color:#94a3b8;letter-spacing:0.1em;margin:10px 0 6px;">
                                DOC · {doc['id']}</div>""", unsafe_allow_html=True)
                            st.markdown(f'<div class="output-box">{doc["text"]}</div>', unsafe_allow_html=True)

                    with tab_ev:
                        if reasons:
                            for r in reasons:
                                st.markdown(f"""
                                <div class="evidence-item">
                                    <span class="evidence-tag">{r.get('tag','unknown')}</span>
                                    <span class="evidence-text">{r.get('evidence','')}</span>
                                </div>""", unsafe_allow_html=True)
                        else:
                            st.markdown("""
                            <div style="color:#94a3b8;font-family:'JetBrains Mono',monospace;
                                        font-size:0.82rem;padding:1rem 0;font-style:italic;">
                                No evidence — prompt is clean.</div>""", unsafe_allow_html=True)

                    with tab_raw:
                        st.json(result)

                else:
                    st.error(f"API Error {resp.status_code}")
                    try:
                        st.json(resp.json())
                    except Exception:
                        st.code(resp.text)

            except requests.exceptions.ConnectionError:
                st.error(f"Cannot reach API at **{api_url}**")
                st.markdown("""
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;
                            color:#64748b;margin-top:8px;">
                    Start the service:
                    <code style="background:#f1f5f9;padding:2px 8px;border-radius:4px;
                                 color:#f97316;border:1px solid #fed7aa;">
                        docker compose up --build
                    </code>
                </div>""", unsafe_allow_html=True)
            except requests.exceptions.Timeout:
                st.error("Request timed out after 30s.")
            except Exception as e:
                st.error(f"Unexpected error: {e}")

    else:
        # Empty state placeholder
        st.markdown("""
        <div style="height:340px;display:flex;align-items:center;justify-content:center;
                    background:#ffffff;border:1.5px dashed #e2e8f0;border-radius:14px;
                    flex-direction:column;gap:14px;box-shadow:0 1px 6px rgba(0,0,0,0.04);">
            <div style="font-size:3rem;opacity:0.12;">🛡️</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;
                        color:#cbd5e1;letter-spacing:0.14em;">AWAITING REQUEST</div>
        </div>""", unsafe_allow_html=True)

# ── Footer ──────────────────────────────────────────────────────────────────────
st.markdown("<br><br>", unsafe_allow_html=True)
st.markdown("""
<div style="border-top:1.5px solid #e2e8f0;padding-top:1.2rem;
            display:flex;justify-content:space-between;align-items:center;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#cbd5e1;">
        SentraGuard Lite · Guardrails Gateway
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#cbd5e1;">
        Detectors: prompt_injection · pii · rag_injection
    </div>
</div>""", unsafe_allow_html=True)