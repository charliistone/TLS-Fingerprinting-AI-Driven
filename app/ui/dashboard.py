import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(page_title="TLS GUARD | Threat Intel", layout="wide", initial_sidebar_state="expanded")

# --- STYLING CSS & ICON ENGINE ---
st.markdown("""
<style>
    /* Bootstrap Icons Entegrasyonu */
    @import url('https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css');

    :root {
        --bg-main: #313338;
        --bg-secondary: #2B2D31;
        --bg-tertiary: #1E1F22;
        --text-primary: #DBDEE1;
        --blurple: #5865F2;
        --green: #23A559;
        --yellow: #FEE75C;
        --red: #ED4245;
    }

    .stApp { background-color: var(--bg-main); color: var(--text-primary); }
    [data-testid="stSidebar"] { background-color: var(--bg-tertiary) !important; border-right: 1px solid rgba(255,255,255,0.05); }
    
    /* Özel Metrik Kartları */
    .metric-card {
        background-color: var(--bg-secondary);
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid var(--blurple);
        margin-bottom: 1rem;
        box-shadow: 0 4px 10px rgba(0,0,0,0.2);
    }
    .metric-title { color: #949BA4; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
    .metric-value { color: #FFFFFF; font-size: 26px; font-weight: 800; margin-top: 5px; }

    /* Tablo Güzelleştirme */
    [data-testid="stTable"] { background-color: var(--bg-secondary); border-radius: 8px; overflow: hidden; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("<h2 style='text-align: center; color: white;'><i class='bi bi-shield-shaded'></i> TLS GUARD</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; font-size: 0.8rem; color:#949BA4;'>Unified Threat Intelligence System</p>", unsafe_allow_html=True)
    st.divider()
    
    st.markdown("<p style='font-size:11px; text-transform:uppercase; color:#949BA4; font-weight:700; margin-left:5px;'>Monitoring</p>", unsafe_allow_html=True)
    page = st.radio("Navigation", [" live-traffic", " threat-history", " ai-insights"], label_visibility="collapsed")
    
    st.divider()
    st.markdown(f"""
        <div style='display:flex; align-items:center; gap:10px; padding:10px;'>
            <div style='width:10px; height:10px; border-radius:50%; background-color:var(--green);'></div>
            <span style='color:white; font-size:14px; font-weight:500;'>Ahmet Can Cengiz</span>
        </div>
    """, unsafe_allow_html=True)

# --- MAIN PANEL ---
if "live-traffic" in page:
    # HEADER
    st.markdown("<h1><i class='bi bi-activity'></i> Live Traffic Stream</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#949BA4; margin-top:-15px;'>Real-time analysis of encrypted TLS handshakes across host interfaces.</p>", unsafe_allow_html=True)

    # METRİC CARDS
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        st.markdown("<div class='metric-card'><div class='metric-title'><i class='bi bi-boxes'></i> Total Packets</div><div class='metric-value'>14,201</div></div>", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='metric-card'><div class='metric-title'><i class='bi bi-ethernet'></i> Active Flows</div><div class='metric-value'>89</div></div>", unsafe_allow_html=True)
    with c3:
        st.markdown("<div class='metric-card' style='border-left-color:var(--yellow)'><div class='metric-title' style='color:var(--yellow)'><i class='bi bi-exclamation-octagon'></i> Warnings</div><div class='metric-value'>12</div></div>", unsafe_allow_html=True)
    with c4:
        st.markdown("<div class='metric-card' style='border-left-color:var(--red)'><div class='metric-title' style='color:var(--red)'><i class='bi bi-bug'></i> Verified Threats</div><div class='metric-value'>2</div></div>", unsafe_allow_html=True)

    st.write("---")

    # TABLE
    st.markdown("### <i class='bi bi-list-columns-reverse'></i> Recent Analysis Results", unsafe_allow_html=True)
    
    dummy_data = pd.DataFrame({
        "Source IP": ["192.168.1.12", "10.0.0.5", "172.16.0.4", "45.12.5.1"],
        "Destination": ["Google Cloud", "Unknown Node", "Azure API", "C2 Infrastructure"],
        "JA3 Hash": ["771,4865-4866...", "771,49195-49199...", "771,4865-4866...", "d41d8cd98f00..."],
        "Risk Level": ["Low", "Medium", "Low", "Critical 🚩"]
    })
    st.table(dummy_data)

    # GRAFİC
    st.markdown("### <i class='bi bi-graph-up'></i> Network Throughput", unsafe_allow_html=True)
    st.line_chart(np.random.randn(15, 1))

elif "threat-history" in page:
    st.markdown("<h1><i class='bi bi-archive'></i> Threat History</h1>", unsafe_allow_html=True)
    st.info("Historical threat logs are being pulled from PostgreSQL...")