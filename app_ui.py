"""Streamlit dashboard for the CodeAlpha Cyber Defense Console."""

import json
import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

LOG_PATH = r"C:\Users\tilak\Desktop\logs\eve.json"
REFRESH_INTERVAL_SECONDS = 3

st.set_page_config(
    page_title="CodeAlpha Cyber Defense Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .reportview-container { background: #0e1117; }
    .metric-card {
        background-color: #1f2937;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #3b82f6;
        margin-bottom: 15px;
    }
    .metric-critical { border-left-color: #ef4444; }
    .metric-warning { border-left-color: #f59e0b; }
</style>
""",
    unsafe_allow_html=True,
)


def parse_security_logs(file_path):
    """Ingest and translate eve.json telemetry records into a normalized DataFrame."""
    if not os.path.exists(file_path):
        return pd.DataFrame()

    events_pool = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                log_data = json.loads(line)
                if log_data.get("event_type") == "alert":
                    alert_info = log_data.get("alert", {})
                    events_pool.append(
                        {
                            "Timestamp": log_data.get(
                                "timestamp",
                                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            ),
                            "Source IP": log_data.get("src_ip", "UNKNOWN"),
                            "Destination IP": log_data.get("dest_ip", "UNKNOWN"),
                            "Protocol": log_data.get("proto", "UNKNOWN"),
                            "Signature": alert_info.get(
                                "signature",
                                "Generic Anomalous Signature Match",
                            ),
                            "Severity": int(alert_info.get("severity", 3)),
                            "Action Enforced": (
                                "BLOCK / ISOLATE"
                                if int(alert_info.get("severity", 3)) == 1
                                else "PASS / AUDIT"
                            ),
                        }
                    )
            except (json.JSONDecodeError, KeyError, ValueError):
                continue

    return pd.DataFrame(events_pool)


st.sidebar.title("🛡️ SOC Control Engine")
st.sidebar.markdown("---")
st.sidebar.subheader("Telemetry Configurations")
target_log = st.sidebar.text_input("Active Log Target Path:", value=LOG_PATH)

auto_refresh = st.sidebar.checkbox("Enable Live Logging Sync Pipeline", value=True)
if auto_refresh:
    st.sidebar.caption("🔄 Dashboard stream updates every 3 seconds.")

df_logs = parse_security_logs(target_log)

st.title("CodeAlpha Cyber Defense Stack Console")
st.subheader(
    "Automated Infrastructure Visibility, Telemetry Analytics & Active Incident Response Engine"
)
st.markdown("---")

if df_logs.empty:
    st.info(
        "⚠️ Awaiting active intrusion log payloads at the configured path. "
        "Please trigger simulated perimeter attacks to populate analytics components."
    )
    if auto_refresh:
        st.rerun()
else:
    total_alerts = len(df_logs)
    critical_blocks = len(df_logs[df_logs["Severity"] == 1])
    minor_warnings = len(df_logs[df_logs["Severity"] > 1])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(
            (
                '<div class="metric-card">'
                "<h4>Total Ingested Alerts</h4>"
                f"<h2>{total_alerts}</h2>"
                "<p style=\"color:#9ca3af;font-size:0.85rem;\">"
                "Active Packet Violations Recorded</p>"
                "</div>"
            ),
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            (
                '<div class="metric-card metric-critical">'
                "<h4>Automated Host Isolations</h4>"
                f"<h2>{critical_blocks}</h2>"
                "<p style=\"color:#ef4444;font-size:0.85rem;\">"
                "🔥 Severity 1 Firewalls Deployed</p>"
                "</div>"
            ),
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            (
                '<div class="metric-card metric-warning">'
                "<h4>Minor Signature Alerts</h4>"
                f"<h2>{minor_warnings}</h2>"
                "<p style=\"color:#f59e0b;font-size:0.85rem;\">"
                "Passive Monitoring Audits</p>"
                "</div>"
            ),
            unsafe_allow_html=True,
        )

    st.markdown("### 📊 Interactive Intrusion Vector Visualizations")

    graph_col1, graph_col2 = st.columns(2)

    with graph_col1:
        st.markdown("#### Malicious Source Hosts Distribution (Top Threat Actors)")
        src_ip_counts = df_logs["Source IP"].value_counts().reset_index()
        src_ip_counts.columns = ["Source IP", "Incident Count"]
        fig_src = px.bar(
            src_ip_counts.head(10),
            x="Incident Count",
            y="Source IP",
            orientation="h",
            color="Incident Count",
            color_continuous_scale="Reds",
            template="plotly_dark",
        )
        fig_src.update_layout(
            yaxis={"categoryorder": "total ascending"},
            margin=dict(l=20, r=20, t=20, b=20),
        )
        st.plotly_chart(fig_src, use_container_width=True)

    with graph_col2:
        st.markdown("#### Transport Layer Protocol Ingestion Breakdown")
        proto_counts = df_logs["Protocol"].value_counts().reset_index()
        proto_counts.columns = ["Protocol", "Volume"]
        fig_proto = px.pie(
            proto_counts,
            values="Volume",
            names="Protocol",
            hole=0.4,
            color_discrete_sequence=px.colors.sequential.YlOrRd_r,
            template="plotly_dark",
        )
        fig_proto.update_layout(margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(fig_proto, use_container_width=True)

    st.markdown("---")
    st.markdown("### 📜 Real-Time Security Incident Logging Archive Explorer")

    search_query = st.text_input(
        "⚡ Quick Filter Database (Search by Signature, Source IP, or Actions Enforced):",
        "",
    )

    filtered_df = df_logs.copy()
    if search_query:
        filtered_df = filtered_df[
            filtered_df["Signature"].str.contains(search_query, case=False)
            | filtered_df["Source IP"].str.contains(search_query, case=False)
            | filtered_df["Action Enforced"].str.contains(search_query, case=False)
        ]

    st.dataframe(
        filtered_df.sort_values(by="Timestamp", ascending=False),
        use_container_width=True,
        column_config={
            "Timestamp": st.column_config.TextColumn("Ingestion Time"),
            "Severity": st.column_config.NumberColumn("Risk Tier", format="🔴 Tier %d"),
            "Action Enforced": st.column_config.TextColumn("Automated Response Action"),
        },
    )

    if auto_refresh:
        import time

        time.sleep(REFRESH_INTERVAL_SECONDS)
        st.rerun()
