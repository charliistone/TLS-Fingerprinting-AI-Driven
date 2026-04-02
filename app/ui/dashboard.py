import streamlit as st
import pandas as pd
import numpy as np
import sys
import os
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# --- PATH FIX ---
# Ensures Streamlit can find the 'app' module when running from the root
sys.path.append(os.getcwd())

from app.utils.db_handler import DatabaseManager

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="TLS GUARD | Unified Threat Intel", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# --- DATABASE INITIALIZATION ---
@st.cache_resource
def init_db():
    """Initializes the database manager once and caches it."""
    return DatabaseManager()

db = init_db()

# --- DISCORD-STYLE CSS ---
st.markdown("""
<style>
    @import url('https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css');
    :root {
        --bg-main: #313338;
        --bg-secondary: #2B2D31;
        --bg-tertiary: #1E1F22;
        --text-primary: #DBDEE1;
        --blurple: #5865F2;
        --green: #23A559;
        --red: #ED4245;
    }
    .stApp { background-color: var(--bg-main); color: var(--text-primary); }
    [data-testid="stSidebar"] { background-color: var(--bg-tertiary) !important; }
    
    /* Custom Metric Cards */
    .metric-card {
        background-color: var(--bg-secondary);
        padding: 20px; border-radius: 8px; border-left: 4px solid var(--blurple);
        margin-bottom: 1rem; box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    }
    .metric-title { color: #949BA4; font-size: 12px; text-transform: uppercase; font-weight: 700; }
    .metric-value { color: #FFFFFF; font-size: 28px; font-weight: 800; margin-top: 5px; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR NAVIGATION ---
with st.sidebar:
    st.markdown("<h2 style='text-align: center; color: white;'><i class='bi bi-shield-lock-fill'></i> TLS GUARD</h2>", unsafe_allow_html=True)
    st.divider()
    
    st.markdown("<p style='font-size:11px; text-transform:uppercase; color:#949BA4; font-weight:700; margin-left:5px;'>Monitoring</p>", unsafe_allow_html=True)
    
    # THE FIX: Defining 'page' globally within the script run
    page = st.radio(
        "Navigation", 
        ["# live-traffic", "# threat-history", "# ai-insights"], 
        label_visibility="collapsed"
    )
    
    st.divider()
    st.markdown(f"""
        <div style='display:flex; align-items:center; gap:10px; padding:10px;'>
            <div style='width:10px; height:10px; border-radius:50%; background-color:var(--green);'></div>
            <span style='color:white; font-size:14px;'>Ahmet Can Cengiz</span>
        </div>
    """, unsafe_allow_html=True)

# --- MAIN DASHBOARD LOGIC ---
if "# live-traffic" in page:
    st.markdown("<h1><i class='bi bi-broadcast'></i> Live Traffic Stream</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#949BA4; margin-top:-15px;'>Real-time monitoring of TLS metadata from host interface (en0).</p>", unsafe_allow_html=True)

    try:
        # Fetch data from the real Postgres DB
        conn = db.connection_pool.getconn()
        query = "SELECT timestamp, src_ip, dst_ip, ja3_hash, prediction FROM tls_events ORDER BY timestamp DESC LIMIT 20"
        df = pd.read_sql_query(query, conn)
        db.connection_pool.putconn(conn)

        # Real-time Metrics
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"<div class='metric-card'><div class='metric-title'>Total Captured</div><div class='metric-value'>{len(df)}</div></div>", unsafe_allow_html=True)
        with c2:
            # Simple threat logic for the UI
            threats = df[df['prediction'].str.contains('Malicious', na=False)].shape[0]
            st.markdown(f"<div class='metric-card' style='border-left-color:var(--red)'><div class='metric-title' style='color:var(--red)'>Detected Threats</div><div class='metric-value'>{threats}</div></div>", unsafe_allow_html=True)
        with c3:
            st.markdown(f"<div class='metric-card' style='border-left-color:var(--green)'><div class='metric-title' style='color:var(--green)'>System Status</div><div class='metric-value'>ACTIVE</div></div>", unsafe_allow_html=True)

        st.write("---")
        
        # Display the Table
        st.markdown("### <i class='bi bi-list-ul'></i> Recent Events", unsafe_allow_html=True)
        if not df.empty:
            # Formatting the dataframe for better display
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("Waiting for TLS traffic... Try visiting an HTTPS website (e.g., google.com)")

    except Exception as e:
        st.error(f"Failed to fetch data: {e}")
        st.warning("Check if your Docker 'tls_db' container is running.")

    # Refresh functionality
    if st.button("🔄 Refresh Data"):
        st.rerun()

elif "# threat-history" in page:
    st.markdown("<h1><i class='bi bi-archive'></i> Threat Archive</h1>", unsafe_allow_html=True)
    st.info("Historical data module is under construction.")