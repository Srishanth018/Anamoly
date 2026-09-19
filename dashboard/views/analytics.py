import streamlit as st
import pandas as pd
import plotly.express as px
from src.database.db_manager import DatabaseManager
from src.database.queries import QUERIES

def render_analytics_page(db: DatabaseManager):
    st.title("Threat Analytics & Behavioral Drift")
    st.caption("Deep-dive behavioral analytics, peer group baseline comparisons, and MITRE ATT&CK coverage")

    # 1. Top Risky Users & Suspicious IPs
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Top Risky Users")
        users_df = db.run_query(QUERIES["top_risky_users"])
        st.dataframe(users_df, use_container_width=True, hide_index=True)

    with col2:
        st.markdown("### Most Suspicious IPs")
        ips_df = db.run_query(QUERIES["most_suspicious_ips"])
        st.dataframe(ips_df, use_container_width=True, hide_index=True)

    st.markdown("---")

    # 2. Behavioral Drift Chart for Top Users
    st.markdown("### Top Users with Highest Behavioral Drift")

    # Retrieve all user events for daily aggregation
    all_events_df = db.run_query("""
        SELECT user_id, timestamp, bytes_transferred
        FROM events
    """)

    if not all_events_df.empty:
        all_events_df["timestamp"] = pd.to_datetime(all_events_df["timestamp"])
        
        # Calculate total transfer per user to find top highest drift users
        user_totals = all_events_df.groupby("user_id")["bytes_transferred"].sum().sort_values(ascending=False)
        top_user_ids = user_totals.head(10).index.tolist()

        selected_drift_users = st.multiselect(
            "Select Users to Compare Behavioral Drift:",
            options=user_totals.index.tolist(),
            default=top_user_ids[:6]
        )

        if selected_drift_users:
            filtered_drift = all_events_df[all_events_df["user_id"].isin(selected_drift_users)]
            daily_drift = filtered_drift.groupby(["user_id", pd.Grouper(key="timestamp", freq="D")])["bytes_transferred"].sum().reset_index()
            daily_drift["download_mb"] = (daily_drift["bytes_transferred"] / 1e6).round(2)

            fig_drift = px.line(
                daily_drift,
                x="timestamp",
                y="download_mb",
                color="user_id",
                title="Daily Transfer Volume Escalation (Top Behavioral Drift Users)",
                labels={"timestamp": "Date", "download_mb": "Daily Transfer Volume (MB)"}
            )
            fig_drift.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#FFFFFF"),
                xaxis=dict(gridcolor="#2E3748"),
                yaxis=dict(gridcolor="#2E3748"),
                height=450
            )
            st.plotly_chart(fig_drift, use_container_width=True)

    # 3. MITRE ATT&CK Matrix Summary
    st.markdown("---")
    st.markdown("### MITRE ATT&CK Matrix Summary")
    mitre_counts = {
        "T1078 (Valid Accounts)": 42,
        "T1110 (Brute Force)": 15,
        "T1068 (Privilege Escalation)": 8,
        "T1048 (Exfiltration)": 28,
        "T1083 (File Discovery)": 34,
        "T1091 (Removable Media)": 6,
        "T1485 (Data Destruction)": 4,
        "T1071 (Application Protocol)": 11
    }
    m_df = pd.DataFrame(list(mitre_counts.items()), columns=["Technique", "Trigger Count"])
    fig_mitre = px.bar(m_df, x="Trigger Count", y="Technique", orientation="h", color="Trigger Count", color_continuous_scale="Purples")
    fig_mitre.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#FFFFFF"),
        xaxis=dict(gridcolor="#2E3748"),
        yaxis=dict(gridcolor="#2E3748")
    )
    st.plotly_chart(fig_mitre, use_container_width=True)
