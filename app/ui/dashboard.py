import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.append(os.getcwd())

from app.utils.db_handler import DatabaseManager 

# ════════════════════════════════════════════════
# PAGE CONFIG
# ════════════════════════════════════════════════

st.set_page_config(
    page_title="TLS GUARD | AI-Driven Fingerprinting",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ════════════════════════════════════════════════
# PLOTLY DARK TEMPLATE
# ════════════════════════════════════════════════

PLOTLY_TEMPLATE = go.layout.Template(
    layout=go.Layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#94a3b8", family="Inter"),
        xaxis=dict(
            gridcolor="rgba(0,212,255,0.06)",
            zerolinecolor="rgba(0,212,255,0.1)",
            tickfont=dict(color="#64748b"),
        ),
        yaxis=dict(
            gridcolor="rgba(0,212,255,0.06)",
            zerolinecolor="rgba(0,212,255,0.1)",
            tickfont=dict(color="#64748b"),
        ),
        colorway=["#00d4ff", "#7c3aed", "#10b981", "#f59e0b", "#f43f5e", "#a78bfa", "#34d399"],
    )
)


# ════════════════════════════════════════════════
# RESOURCE HELPERS
# ════════════════════════════════════════════════

@st.cache_resource
def get_db() -> DatabaseManager:
    return DatabaseManager()


def load_css() -> None:
    css_path = Path("app/ui/style.css")
    if css_path.exists():
        st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def resolve_tshark_path(db: DatabaseManager) -> str:
    return (
        db.get_config("tshark_path")
        or os.environ.get("TSHARK_PATH")
        or shutil.which("tshark")
        or r"C:\Program Files\Wireshark\tshark.exe"
    )


def get_detected_interfaces(db: DatabaseManager) -> List[dict]:
    runtime_file = Path("data/runtime/detected_interfaces.json")
    if runtime_file.exists():
        try:
            data = json.loads(runtime_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass

    tshark_path = resolve_tshark_path(db)
    try:
        result = subprocess.run(
            [tshark_path, "-D"], capture_output=True, text=True, encoding="utf-8"
        )
    except (FileNotFoundError, Exception):
        return []

    if result.returncode != 0:
        return []

    interfaces = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(". ", 1)
        if len(parts) == 2 and parts[0].isdigit():
            interfaces.append({"index": parts[0], "label": parts[1], "display": line})
        else:
            interfaces.append({"index": "", "label": line, "display": line})
    return interfaces


def get_current_config(db: DatabaseManager) -> dict:
    return {
        "capture_interface": db.get_config("capture_interface", "") or "",
        "tshark_path": resolve_tshark_path(db),
        "capture_filter": db.get_config("capture_filter", "") or "",
        "ring_duration": int(db.get_config("ring_duration", "30") or 30),
        "ring_files": int(db.get_config("ring_files", "10") or 10),
        "poll_interval": int(db.get_config("poll_interval", "5") or 5),
        "stable_seconds": int(db.get_config("stable_seconds", "3") or 3),
        "dashboard_port": int(db.get_config("dashboard_port", "8501") or 8501),
    }


def format_file_size(size: Optional[int]) -> str:
    if size is None:
        return "—"
    size = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# ════════════════════════════════════════════════
# UI COMPONENT HELPERS
# ════════════════════════════════════════════════

def metric_card(label: str, value: str, footnote: str = "", color: str = "") -> str:
    color_class = f" {color}" if color else ""
    footnote_html = f'<div class="metric-footnote">{footnote}</div>' if footnote else ""
    return f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value{color_class}">{value}</div>
        {footnote_html}
    </div>
    """


def badge(text: str, kind: str = "neutral") -> str:
    return f'<span class="badge badge-{kind}">{text}</span>'


def empty_state(icon: str, title: str, text: str) -> None:
    st.markdown(
        f"""
        <div class="empty-state">
            <div class="empty-state-icon">{icon}</div>
            <div class="empty-state-title">{title}</div>
            <div class="empty-state-text">{text}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(title: str, note: str = "") -> None:
    st.markdown(
        f'<div class="section-title">{title}</div>'
        + (f'<div class="section-note">{note}</div>' if note else ""),
        unsafe_allow_html=True,
    )


def log_line_html(log: dict) -> str:
    level = str(log.get("level", "INFO")).upper()
    css = "log-info"
    if level == "WARNING":
        css = "log-warning"
    elif level == "ERROR":
        css = "log-error"
    return f"""
    <div class="log-line {css}">
        <div class="log-meta">{log.get("timestamp", "")} &nbsp;|&nbsp; {log.get("component","").upper()} &nbsp;|&nbsp; {level}</div>
        <div>{log.get("message", "")}</div>
    </div>
    """


def no_interface_warning(db: DatabaseManager) -> None:
    if not (db.get_config("capture_interface", "") or ""):
        st.warning(
            "⚠️ Capture interface not configured. Go to **Settings** to select one before starting live capture."
        )


def style_plotly_fig(fig: go.Figure) -> go.Figure:
    fig.update_layout(
        template=PLOTLY_TEMPLATE,
        margin=dict(l=8, r=8, t=24, b=8),
        xaxis_title="",
        legend=dict(font=dict(color="#94a3b8")),
    )
    return fig


# ════════════════════════════════════════════════
# SIDEBAR
# ════════════════════════════════════════════════

def render_sidebar() -> dict:
    with st.sidebar:
        # ── Brand header
        st.markdown(
            """
            <div style="text-align:center; padding: 0.6rem 0 1.4rem;">
                <div style="font-size:2.6rem; line-height:1;">🛡️</div>
                <div style="font-size:1.2rem; font-weight:900; color:#e2e8f0;
                            letter-spacing:-0.02em; margin-top:0.4rem;">TLS GUARD</div>
                <div style="font-size:0.68rem; color:#00d4ff; font-weight:700;
                            letter-spacing:0.12em; text-transform:uppercase; margin-top:0.1rem;">
                    AI · JA3 · TShark
                </div>
                <div style="margin-top:0.75rem;">
                    <span style="background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.35);
                                 color:#10b981; font-size:0.68rem; font-weight:700; letter-spacing:0.06em;
                                 border-radius:999px; padding:0.25rem 0.7rem; text-transform:uppercase;">
                        ● Live
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            '<hr style="border:none; border-top:1px solid rgba(0,212,255,0.1); margin:0 0 1rem;">',
            unsafe_allow_html=True,
        )

        # ── Navigation
        st.markdown(
            '<div style="font-size:0.68rem; font-weight:700; color:#00d4ff; '
            'letter-spacing:0.1em; text-transform:uppercase; '
            'margin-bottom:0.5rem; padding-left:0.2rem;">Navigation</div>',
            unsafe_allow_html=True,
        )

        NAV_ITEMS = [
            ("Overview",                "🏠", "Health summary & key metrics"),
            ("Live Monitor",            "📡", "Real-time capture activity"),
            ("PCAP Explorer",           "📂", "File lifecycle tracker"),
            ("Fingerprint Intelligence","🧬", "JA3 analytics & patterns"),
            ("Whitelist",               "✅", "Trusted signatures"),
            ("Candidates",              "🔍", "Unknown fingerprint queue"),
            ("System Console",          "🖥️",  "Backend logs & debug"),
            ("Settings",                "⚙️",  "TShark & capture config"),
        ]

        page = st.radio(
            "Pages",
            [item[0] for item in NAV_ITEMS],
            label_visibility="collapsed",
            format_func=lambda name: next(
                f"{icon}  {name}" for n, icon, _ in NAV_ITEMS if n == name
            ),
        )

        selected_desc = next((desc for n, _, desc in NAV_ITEMS if n == page), "")
        st.markdown(
            f'<div style="font-size:0.75rem; color:#64748b; margin: 0.3rem 0 1rem 0.3rem;">'
            f'→ {selected_desc}</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            '<hr style="border:none; border-top:1px solid rgba(0,212,255,0.08); margin:0 0 1rem;">',
            unsafe_allow_html=True,
        )

        # ── Display controls
        st.markdown(
            '<div style="font-size:0.68rem; font-weight:700; color:#00d4ff; '
            'letter-spacing:0.1em; text-transform:uppercase; '
            'margin-bottom:0.5rem; padding-left:0.2rem;">🎛️  Display Controls</div>',
            unsafe_allow_html=True,
        )
        table_limit = st.slider("Row limit", 10, 300, 50, 10)

        if st.button("⟳  Refresh", width="stretch"):
            st.rerun()

        st.markdown(
            '<hr style="border:none; border-top:1px solid rgba(0,212,255,0.08); margin:1rem 0;">',
            unsafe_allow_html=True,
        )

        # ── Tips
        st.markdown(
            """
            <div style="font-size:0.68rem; font-weight:700; color:#00d4ff;
                        letter-spacing:0.1em; text-transform:uppercase;
                        margin-bottom:0.5rem; padding-left:0.2rem;">💡  Tips</div>
            <div style="font-size:0.76rem; color:#64748b; line-height:1.7; padding-left:0.2rem;">
                🏠 Overview &rarr; health at a glance<br>
                📡 Live Monitor &rarr; real-time stream<br>
                📂 PCAP Explorer &rarr; file status<br>
                🧬 Intel &rarr; fingerprint analytics<br>
                ⚙️ Settings &rarr; TShark &amp; interface
            </div>
            """,
            unsafe_allow_html=True,
        )

    return {"page": page, "table_limit": table_limit}


def render_hero() -> None:
    st.markdown(
        """
        <div class="tls-hero">
            <div class="hero-badge">
                <div class="hero-badge-dot"></div>
                System Active &nbsp;·&nbsp; JA3 Fingerprinting Engine
            </div>
            <div class="hero-title">AI-Driven <span>TLS Fingerprinting</span></div>
            <div class="hero-subtitle">
                Autonomous characterization, verification and threat-scoring of TLS/SSL application traffic
                using JA3 hashes, PCAP ring-buffer capture, and whitelist-based classification.
            </div>
            <div class="hero-chips">
                <span class="hero-chip">ClientHello Analysis</span>
                <span class="hero-chip">JA3 / JA3S Hashing</span>
                <span class="hero-chip">SQLite Whitelist</span>
                <span class="hero-chip">TShark Ring Buffer</span>
                <span class="hero-chip">PCAP Watcher</span>
                <span class="hero-chip">Candidate Queue</span>
                <span class="hero-chip">Hot Config Reload</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ════════════════════════════════════════════════
# PAGE: OVERVIEW
# ════════════════════════════════════════════════

def render_overview(db: DatabaseManager, table_limit: int) -> None:
    no_interface_warning(db)

    metrics = db.get_summary_metrics()
    recent_events = db.get_recent_events(limit=table_limit)
    event_trend = db.get_event_trend(limit=24)
    top_predictions = db.get_top_predictions(limit=10)
    top_ports = db.get_port_distribution(limit=10)
    top_ja3 = db.get_top_ja3_hashes(limit=10)
    recent_logs = db.get_recent_logs(limit=8)

    last_pcap = metrics.get("last_processed_pcap") or "—"
    capture_state = "Active / Monitoring" if metrics.get("active_pcap_jobs", 0) > 0 else "Idle / Waiting"

    # ── Metric row 1
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card("System Status", "Online", "Dashboard & DB reachable", "emerald"), unsafe_allow_html=True)
    with c2:
        st.markdown(metric_card("Capture / Watcher", capture_state, f"Active jobs: {metrics.get('active_pcap_jobs', 0)}"), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card("Total Events", str(metrics.get("total_events", 0)), f"Processed PCAPs: {metrics.get('processed_pcap_count', 0)}", "cyan"), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card("Last PCAP", last_pcap, "Most recently processed"), unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # ── Metric row 2
    c5, c6, c7, c8 = st.columns(4)
    with c5:
        st.markdown(metric_card("Known Events", str(metrics.get("known_events", 0)), color="emerald"), unsafe_allow_html=True)
    with c6:
        st.markdown(metric_card("Unknown Events", str(metrics.get("unknown_events", 0)), color="amber"), unsafe_allow_html=True)
    with c7:
        st.markdown(metric_card("Candidates", str(metrics.get("candidate_count", 0)), color="purple"), unsafe_allow_html=True)
    with c8:
        st.markdown(metric_card("Whitelist Entries", str(metrics.get("whitelist_count", 0)), color="cyan"), unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Charts
    ch1, ch2 = st.columns(2)
    with ch1:
        section_header("Event Trend", "Hourly TLS event volume from processed captures.")
        if event_trend:
            df = pd.DataFrame(event_trend)
            fig = px.area(df, x="hour_bucket", y="event_count",
                          color_discrete_sequence=["#00d4ff"])
            fig.update_traces(fill="tozeroy", line=dict(width=2),
                              fillcolor="rgba(0,212,255,0.08)")
            st.plotly_chart(style_plotly_fig(fig), width="stretch")
        else:
            empty_state("📈", "No Event Trend", "Hourly event volume will appear here once traffic is processed.")

    with ch2:
        section_header("Top Predictions", "Most frequent application matches from whitelist or heuristics.")
        if top_predictions:
            df = pd.DataFrame(top_predictions)
            fig = px.bar(df, x="hit_count", y="prediction", orientation="h",
                         color_discrete_sequence=["#7c3aed"])
            fig.update_traces(marker_cornerradius=4)
            st.plotly_chart(style_plotly_fig(fig), width="stretch")
        else:
            empty_state("🧠", "No Predictions Yet", "Predictions appear after JA3 records are processed.")

    lo1, lo2 = st.columns(2)
    with lo1:
        section_header("Destination Port Distribution", "Ports most observed in TLS events.")
        if top_ports:
            df = pd.DataFrame(top_ports)
            df["dst_port"] = df["dst_port"].astype(str)
            fig = px.pie(df, names="dst_port", values="hit_count",
                         color_discrete_sequence=["#00d4ff","#7c3aed","#10b981","#f59e0b","#f43f5e","#a78bfa"])
            fig.update_traces(textfont_color="#e2e8f0", hole=0.4)
            st.plotly_chart(style_plotly_fig(fig), width="stretch")
        else:
            empty_state("🔌", "No Port Data", "Port distribution appears after events are logged.")

    with lo2:
        section_header("Top JA3 Fingerprints", "Most frequently seen JA3 hashes in the event log.")
        if top_ja3:
            df = pd.DataFrame(top_ja3)[["ja3_hash", "hit_count", "latest_prediction", "last_seen"]]
            st.dataframe(df, width="stretch", hide_index=True)
        else:
            empty_state("🔑", "No JA3 Hashes", "Detected JA3 fingerprints will be summarized here.")

    # ── Recent events
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    section_header("Recent TLS Detections", "Latest processed TLS events from the pipeline.")
    if recent_events:
        df = pd.DataFrame(recent_events)
        cols = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port", "ja3_hash", "prediction", "confidence", "status"] if c in df.columns]
        st.dataframe(df[cols], width="stretch", hide_index=True)
    else:
        empty_state("📡", "No Detections Yet", "Once capture or PCAP processing begins, TLS events will appear here.")

    # ── Activity feed
    section_header("Recent Platform Activity", "Latest backend logs from capture, watcher, extractor and predictor.")
    if recent_logs:
        for log in recent_logs:
            st.markdown(log_line_html(log), unsafe_allow_html=True)
    else:
        empty_state("📋", "No Logs Yet", "Backend events will appear here after the pipeline starts.")


# ════════════════════════════════════════════════
# PAGE: LIVE MONITOR
# ════════════════════════════════════════════════

def render_live_monitor(db: DatabaseManager, table_limit: int) -> None:
    no_interface_warning(db)

    metrics = db.get_summary_metrics()
    recent_logs = db.get_recent_logs(limit=30)
    recent_events = db.get_recent_events(limit=20)
    last_pcap = db.get_last_processed_pcap()
    cfg_interface = db.get_config("capture_interface", "") or ""

    section_header("Live Monitor", "Real-time operational status of the capture, watcher and JA3 pipeline.")

    # Status row
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown(
            f'<div class="info-panel"><div class="info-title">Backend</div>'
            f'<div class="info-value">{badge("Online", "success")}</div></div>',
            unsafe_allow_html=True,
        )
    with s2:
        active = metrics.get("active_pcap_jobs", 0)
        b_kind = "info" if active > 0 else "neutral"
        b_text = "Watching / Processing" if active > 0 else "Idle / Waiting"
        st.markdown(
            f'<div class="info-panel"><div class="info-title">Watcher Status</div>'
            f'<div class="info-value">{badge(b_text, b_kind)}</div></div>',
            unsafe_allow_html=True,
        )
    with s3:
        st.markdown(
            f'<div class="info-panel"><div class="info-title">Interface</div>'
            f'<div class="info-value">{cfg_interface or "Not Set"}</div></div>',
            unsafe_allow_html=True,
        )
    with s4:
        st.markdown(
            f'<div class="info-panel"><div class="info-title">Total Events</div>'
            f'<div class="info-value">{metrics.get("total_events", 0)}</div></div>',
            unsafe_allow_html=True,
        )

    left, right = st.columns([1, 1])

    with left:
        section_header("Operational State")
        pcap_name = last_pcap["file_name"] if last_pcap else "No processed file yet"
        pcap_time = last_pcap["processed_at"] if last_pcap else "—"
        st.markdown(
            f"""
            <div class="glass-card">
                <div class="status-grid">
                    <div class="status-item"><div class="status-item-label">Last Processed PCAP</div>
                        <div class="status-item-value">{pcap_name}</div></div>
                    <div class="status-item"><div class="status-item-label">Processed At</div>
                        <div class="status-item-value">{pcap_time}</div></div>
                    <div class="status-item"><div class="status-item-label">Known Events</div>
                        <div class="status-item-value">{metrics.get('known_events', 0)}</div></div>
                    <div class="status-item"><div class="status-item-label">Unknown Events</div>
                        <div class="status-item-value">{metrics.get('unknown_events', 0)}</div></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        section_header("Recent Detections", "Latest TLS records observed by the system.")
        if recent_events:
            df = pd.DataFrame(recent_events)
            cols = [c for c in ["timestamp", "dst_ip", "dst_port", "ja3_hash", "prediction", "status"] if c in df.columns]
            st.dataframe(df[cols], width="stretch", hide_index=True)
        else:
            empty_state("📡", "No Detections", "Run the backend with capture enabled or drop a PCAP into the capture directory.")

    with right:
        section_header("Backend Activity Feed", "Most recent system actions across all components.")
        if recent_logs:
            st.markdown('<div class="log-console">', unsafe_allow_html=True)
            for log in recent_logs:
                st.markdown(log_line_html(log), unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            empty_state("📟", "No Activity", "System logs will stream here after the pipeline starts.")


# ════════════════════════════════════════════════
# PAGE: PCAP EXPLORER
# ════════════════════════════════════════════════

def render_pcap_explorer(db: DatabaseManager, table_limit: int) -> None:
    section_header("PCAP Explorer", "Track the lifecycle and processing outcome of captured or imported PCAP files.")

    status_filter = st.selectbox(
        "Filter by status",
        options=["All", "detected", "processing", "processed", "no_tls_records", "error"],
        index=0,
    )

    selected_status = None if status_filter == "All" else status_filter
    pcap_files = db.get_pcap_files(limit=table_limit, status=selected_status)

    if pcap_files:
        df = pd.DataFrame(pcap_files)
        df["size"] = df["file_size"].apply(format_file_size)

        cols = [c for c in [
            "file_name", "status", "size", "first_seen",
            "processed_at", "records_extracted", "records_logged", "error_message",
        ] if c in df.columns]

        st.dataframe(df[cols], width="stretch", hide_index=True)

        # ── Status breakdown chart
        if "status" in df.columns:
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            fig = px.bar(
                status_counts, x="status", y="count",
                color="status",
                color_discrete_map={
                    "processed": "#10b981",
                    "processing": "#00d4ff",
                    "detected": "#7c3aed",
                    "no_tls_records": "#f59e0b",
                    "error": "#f43f5e",
                },
            )
            fig.update_traces(marker_cornerradius=4)
            st.plotly_chart(style_plotly_fig(fig), width="stretch")

        st.markdown("<br>", unsafe_allow_html=True)
        section_header("File Detail View", "Expand individual PCAP records for deeper context.")
        for item in pcap_files[:15]:
            with st.expander(
                f"📦 {item.get('file_name', 'Unnamed')}  ·  {item.get('status', '?')}",
                expanded=False,
            ):
                dc1, dc2 = st.columns(2)
                with dc1:
                    st.markdown(f"**Full Path:** `{item.get('file_path', '—')}`")
                    st.markdown(f"**File Size:** {format_file_size(item.get('file_size'))}")
                    st.markdown(f"**First Seen:** {item.get('first_seen', '—')}")
                    st.markdown(f"**Processed At:** {item.get('processed_at', '—')}")
                with dc2:
                    st.markdown(f"**Extracted Records:** {item.get('records_extracted', 0)}")
                    st.markdown(f"**Logged Records:** {item.get('records_logged', 0)}")
                    err = item.get("error_message") or "—"
                    st.markdown(f"**Error:** {err}")
    else:
        empty_state("📂", "No PCAP Records", "Once the watcher detects files in the captures directory, they will appear here.")


# ════════════════════════════════════════════════
# PAGE: FINGERPRINT INTELLIGENCE
# ════════════════════════════════════════════════

def render_fingerprint_intelligence(db: DatabaseManager, table_limit: int) -> None:
    section_header("Fingerprint Intelligence", "Explore TLS fingerprints, prediction distributions and protocol behavior patterns.")

    top_ja3 = db.get_top_ja3_hashes(limit=15)
    top_predictions = db.get_top_predictions(limit=15)
    unique_fps = db.get_recent_unique_fingerprints(limit=table_limit)
    top_ports = db.get_port_distribution(limit=12)

    r1c1, r1c2 = st.columns(2)
    with r1c1:
        section_header("Top JA3 Fingerprints")
        if top_ja3:
            df = pd.DataFrame(top_ja3)
            # Truncate hash for readability
            df["ja3_short"] = df["ja3_hash"].str[:12] + "…"
            fig = px.bar(df, x="hit_count", y="ja3_short", orientation="h",
                         color="hit_count", color_continuous_scale=["#0f1a3a", "#00d4ff"])
            fig.update_traces(marker_cornerradius=4)
            fig.update_layout(coloraxis_showscale=False)
            st.plotly_chart(style_plotly_fig(fig), width="stretch")
        else:
            empty_state("🔑", "No JA3 Data", "Fingerprint analytics will appear after TLS events are processed.")

    with r1c2:
        section_header("Prediction Distribution")
        if top_predictions:
            df = pd.DataFrame(top_predictions)
            fig = px.bar(df, x="hit_count", y="prediction", orientation="h",
                         color="hit_count", color_continuous_scale=["#1e0a5c", "#7c3aed"])
            fig.update_traces(marker_cornerradius=4)
            fig.update_layout(coloraxis_showscale=False)
            st.plotly_chart(style_plotly_fig(fig), width="stretch")
        else:
            empty_state("🧠", "No Prediction Data", "Prediction analytics appear once fingerprints are classified.")

    r2c1, r2c2 = st.columns(2)
    with r2c1:
        section_header("Destination Port Distribution")
        if top_ports:
            df = pd.DataFrame(top_ports)
            df["dst_port"] = df["dst_port"].astype(str)
            fig = px.treemap(df, path=["dst_port"], values="hit_count",
                             color_discrete_sequence=["#00d4ff", "#7c3aed", "#10b981", "#f59e0b"])
            st.plotly_chart(style_plotly_fig(fig), width="stretch")
        else:
            empty_state("🔌", "No Port Analytics", "Port-level intelligence appears after events are logged.")

    with r2c2:
        section_header("Recent Unique Fingerprints")
        if unique_fps:
            df = pd.DataFrame(unique_fps)
            cols = [c for c in ["ja3_hash", "latest_prediction", "latest_status", "occurrences", "last_seen"] if c in df.columns]
            st.dataframe(df[cols], width="stretch", hide_index=True)
        else:
            empty_state("🧩", "No Unique Fingerprints", "Unique JA3 hashes will be summarized here.")


# ════════════════════════════════════════════════
# PAGE: WHITELIST
# ════════════════════════════════════════════════

def render_whitelist(db: DatabaseManager, table_limit: int) -> None:
    section_header("Whitelist Management", "Known JA3 signatures trusted or mapped by the platform.")

    whitelist = db.get_all_whitelist_entries()

    # Summary chips
    if whitelist:
        df = pd.DataFrame(whitelist)

        wl1, wl2, wl3, _ = st.columns([1, 1, 1, 3])
        with wl1:
            st.markdown(metric_card("Total Entries", str(len(df)), color="cyan"), unsafe_allow_html=True)
        with wl2:
            cats = df["category"].nunique() if "category" in df.columns else 0
            st.markdown(metric_card("Categories", str(cats), color="purple"), unsafe_allow_html=True)
        with wl3:
            sources = df["source"].nunique() if "source" in df.columns else 0
            st.markdown(metric_card("Sources", str(sources), color="emerald"), unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        search_text = st.text_input("🔍 Search by app name or JA3 hash", "", key="wl_search")
        if search_text:
            mask = (
                df["app_name"].astype(str).str.contains(search_text, case=False, na=False)
                | df["ja3_hash"].astype(str).str.contains(search_text, case=False, na=False)
            )
            df = df[mask]

        df = df.head(table_limit)
        cols = [c for c in ["created_at", "app_name", "ja3_hash", "category", "confidence", "source", "notes"] if c in df.columns]
        st.dataframe(df[cols], width="stretch", hide_index=True)
    else:
        empty_state("🔒", "Whitelist Is Empty", "Seed demo entries from Settings, or add mappings via the pipeline after classifying traffic.")


# ════════════════════════════════════════════════
# PAGE: CANDIDATES
# ════════════════════════════════════════════════

def render_candidates(db: DatabaseManager, table_limit: int) -> None:
    section_header("Candidate Queue", "Unknown or inferred JA3 fingerprints awaiting review or promotion.")

    candidates = db.get_candidates(limit=table_limit)

    if candidates:
        df = pd.DataFrame(candidates)

        q1, q2 = st.columns([1, 2])
        with q1:
            min_conf = st.slider("Minimum confidence %", 0, 100, 0, key="cand_conf")
        with q2:
            search_text = st.text_input("🔍 Search by JA3 hash or predicted app", "", key="cand_search")

        if "confidence" in df.columns:
            df = df[df["confidence"] >= min_conf]
        if search_text:
            mask = (
                df["ja3_hash"].astype(str).str.contains(search_text, case=False, na=False)
                | df["predicted_app"].astype(str).str.contains(search_text, case=False, na=False)
            )
            df = df[mask]

        st.markdown(
            f'<div style="color:#64748b;font-size:0.8rem;margin-bottom:0.5rem;">'
            f'Showing {len(df)} candidate(s)</div>',
            unsafe_allow_html=True,
        )

        cols = [c for c in ["last_seen", "ja3_hash", "predicted_app", "confidence", "seen_count", "promoted"] if c in df.columns]
        st.dataframe(df[cols], width="stretch", hide_index=True)

        # Confidence histogram
        if "confidence" in df.columns and len(df) > 1:
            section_header("Confidence Distribution")
            fig = px.histogram(df, x="confidence", nbins=20, color_discrete_sequence=["#7c3aed"])
            fig.update_traces(marker_cornerradius=4)
            st.plotly_chart(style_plotly_fig(fig), width="stretch")
    else:
        empty_state("📌", "No Candidates", "Unknown fingerprints will appear here once the predictor creates candidate records.")


# ════════════════════════════════════════════════
# PAGE: SYSTEM CONSOLE
# ════════════════════════════════════════════════

def render_system_console(db: DatabaseManager, table_limit: int) -> None:
    section_header("System Console", "Backend logs from dashboard, capture, watcher, extractor and predictor.")

    fc1, fc2, fc3 = st.columns([1, 1, 2])
    with fc1:
        level = st.selectbox("Log Level", ["All", "INFO", "WARNING", "ERROR"], key="log_level")
    with fc2:
        component = st.selectbox(
            "Component",
            ["All", "system", "dashboard", "capture", "watcher", "extractor", "predictor"],
            key="log_component",
        )
    with fc3:
        search_text = st.text_input("🔍 Filter message", "", key="log_search")

    log_level = None if level == "All" else level
    log_component = None if component == "All" else component

    logs = db.get_recent_logs(limit=table_limit, level=log_level, component=log_component)

    if search_text:
        logs = [l for l in logs if search_text.lower() in l.get("message", "").lower()]

    if logs:
        # Level breakdown badges
        level_counts = {}
        for l in logs:
            lvl = str(l.get("level", "INFO")).upper()
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        badge_row = " ".join([
            badge(f"{k}: {v}", "success" if k == "INFO" else "warning" if k == "WARNING" else "danger")
            for k, v in level_counts.items()
        ])
        st.markdown(f'<div style="margin-bottom:0.75rem;">{badge_row}</div>', unsafe_allow_html=True)

        st.markdown('<div class="log-console">', unsafe_allow_html=True)
        for log in logs:
            st.markdown(log_line_html(log), unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        empty_state("🔍", "No Logs Matched", "No log entries matched the selected filters.")


# ════════════════════════════════════════════════
# PAGE: SETTINGS
# ════════════════════════════════════════════════

def render_settings(db: DatabaseManager) -> None:
    section_header("Settings & Capture Configuration", "Configure TShark path, interface, and ring-buffer parameters. Changes persist to SQLite.")

    current = get_current_config(db)
    detected_interfaces = get_detected_interfaces(db)
    interface_options = [""] + [item["index"] for item in detected_interfaces]

    interface_label_map = {"": "(Not configured)"}
    for item in detected_interfaces:
        interface_label_map[item["index"]] = item["display"]

    current_interface = current["capture_interface"]
    default_index = 0
    if current_interface in interface_options:
        default_index = interface_options.index(current_interface)

    # ── Interface section
    st.markdown("#### 🌐 Capture Interface")
    if detected_interfaces:
        selected_interface = st.selectbox(
            "Detected Interfaces (via TShark -D)",
            options=interface_options,
            index=default_index,
            format_func=lambda x: interface_label_map.get(x, x),
        )
        detected_df = pd.DataFrame(detected_interfaces)
        st.dataframe(detected_df[["index", "label"]], width="stretch", hide_index=True)
    else:
        st.warning("⚠️ Could not retrieve interfaces. Verify your TShark path below or enter the interface manually.")
        selected_interface = current_interface

    manual_interface = st.text_input(
        "Manual Interface Override",
        value="",
        placeholder="Optional: enter interface name/number manually if dropdown is unavailable",
    )

    # ── Runtime settings
    st.markdown("#### ⚙️ Runtime Settings")
    s1, s2 = st.columns(2)
    with s1:
        tshark_path = st.text_input("TShark Binary Path", value=current["tshark_path"])
        capture_filter = st.text_input("BPF Capture Filter", value=current["capture_filter"], placeholder="e.g. tcp port 443")
        poll_interval = st.number_input("Poll Interval (sec)", min_value=1, max_value=120, value=current["poll_interval"], step=1)
        stable_seconds = st.number_input("Stable Seconds (write-settle)", min_value=1, max_value=120, value=current["stable_seconds"], step=1)
    with s2:
        ring_duration = st.number_input("Ring Duration (sec)", min_value=5, max_value=3600, value=current["ring_duration"], step=5)
        ring_files = st.number_input("Ring File Count", min_value=1, max_value=500, value=current["ring_files"], step=1)
        dashboard_port = st.number_input("Dashboard Port", min_value=1024, max_value=65535, value=current["dashboard_port"], step=1)

    # ── Config summary
    st.markdown("#### 📋 Current Saved Configuration")
    st.markdown(
        f"""
        <div class="glass-card">
            <div class="status-grid">
                <div class="status-item"><div class="status-item-label">Saved Interface</div>
                    <div class="status-item-value">{current_interface or "Not Set"}</div></div>
                <div class="status-item"><div class="status-item-label">TShark Path</div>
                    <div class="status-item-value" style="font-size:0.78rem;word-break:break-all;">{current["tshark_path"]}</div></div>
                <div class="status-item"><div class="status-item-label">Ring Duration</div>
                    <div class="status-item-value">{current["ring_duration"]}s</div></div>
                <div class="status-item"><div class="status-item-label">Ring Files</div>
                    <div class="status-item-value">{current["ring_files"]}</div></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Resolve effective interface
    effective_interface = (manual_interface or "").strip() or (selected_interface or "").strip()

    config_payload = {
        "capture_interface": effective_interface,
        "tshark_path": tshark_path.strip(),
        "capture_filter": capture_filter.strip(),
        "ring_duration": str(ring_duration),
        "ring_files": str(ring_files),
        "poll_interval": str(poll_interval),
        "stable_seconds": str(stable_seconds),
        "dashboard_port": str(dashboard_port),
    }

    st.markdown("#### 💾 Actions")
    b1, b2, b3 = st.columns(3)
    with b1:
        if st.button("💾 Save Only", width="stretch", key="save_only"):
            db.set_many_config(config_payload)
            st.success(f"Settings saved. Interface: {effective_interface or 'Not Set'}")
            st.rerun()
    with b2:
        if st.button("⚡ Save & Apply", width="stretch", key="save_apply"):
            db.set_many_config(config_payload)
            db.enqueue_command("apply_capture_settings")
            st.success("Settings saved. Backend will apply config changes automatically within a few seconds.")
            st.rerun()
    with b3:
        if st.button("🌱 Seed Demo Whitelist", width="stretch", key="seed_demo"):
            db.seed_sample_whitelist()
            st.success("Sample whitelist entries added. Navigate to Whitelist to view them.")

    st.info(
        "💡 **Interface tip:** Interface numbering changes per device. Use the dropdown (populated from `tshark -D`) "
        "or check the host_capture_agent.py status file at `data/runtime/host_capture_status.json`."
    )


# ════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════

def main() -> None:
    load_css()
    db = get_db()

    render_hero()

    state = render_sidebar()
    page = state["page"]
    table_limit = state["table_limit"]

    if page == "Overview":
        render_overview(db, table_limit)
    elif page == "Live Monitor":
        render_live_monitor(db, table_limit)
    elif page == "PCAP Explorer":
        render_pcap_explorer(db, table_limit)
    elif page == "Fingerprint Intelligence":
        render_fingerprint_intelligence(db, table_limit)
    elif page == "Whitelist":
        render_whitelist(db, table_limit)
    elif page == "Candidates":
        render_candidates(db, table_limit)
    elif page == "System Console":
        render_system_console(db, table_limit)
    elif page == "Settings":
        render_settings(db)


if __name__ == "__main__":
    main()