import streamlit as st
import pandas as pd
import json
from src.database.db_manager import DatabaseManager
from dashboard.components.charts import build_user_radar_chart
from dashboard.components.timeline import render_investigation_timeline

def render_users_page(db: DatabaseManager):
    st.title("User Baseline & Behavioral Profile")
    st.caption("Inspect individual normal working baselines vs active session deviations")

    # Select User
    users_df = db.run_query("SELECT user_id, department, role FROM users ORDER BY user_id")
    if users_df.empty:
        st.warning("No user data found in database.")
        return

    selected_user = st.selectbox("Select Monitored User:", users_df["user_id"].unique())

    user_info = users_df[users_df["user_id"] == selected_user].iloc[0]
    
    # 1. User Header Metadata
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("User ID", user_info["user_id"])
    col2.metric("Department", user_info["department"])
    col3.metric("Role", user_info["role"])
    
    user_alerts = db.run_query("SELECT COUNT(*) AS c, MAX(risk_score) AS max_score FROM alerts WHERE user_id = ?", (selected_user,))
    max_risk = user_alerts["max_score"].iloc[0] if not user_alerts.empty and user_alerts["max_score"].iloc[0] is not None else 0
    col4.metric("Max Risk Score", f"{max_risk:.1f}")

    st.markdown("---")

    # 2. Baseline Profile vs Current Activity Radar
    baseline_df = db.run_query("SELECT * FROM baselines WHERE user_id = ?", (selected_user,))
    
    if not baseline_df.empty:
        b_row = baseline_df.iloc[0]
        
        col_b1, col_b2 = st.columns(2)
        with col_b1:
            st.markdown("### Normal Baseline Profile")
            st.write(f"**Normal Working Hours:** `{b_row['normal_start_hour']:02d}:00 – {b_row['normal_end_hour']:02d}:00`")
            st.write(f"**Primary IP Addresses:** `{b_row['frequent_ips']}`")
            st.write(f"**Authorized Devices:** `{b_row['frequent_devices']}`")
            st.write(f"**Average Daily Download:** `{b_row['avg_daily_download_mb']} MB` (Std: `{b_row['std_daily_download_mb']} MB`)")
            st.write(f"**Normal Resources:** `{b_row['normal_resources_json']}`")

        with col_b2:
            # Generate Radar Chart
            is_anom = max_risk >= 70.0
            metrics = {
                "hour_match": 20 if is_anom else 100,
                "ip_match": 10 if is_anom else 100,
                "device_match": 10 if is_anom else 100,
                "download_match": 15 if is_anom else 95,
                "resource_match": 25 if is_anom else 100
            }
            fig_radar = build_user_radar_chart(selected_user, {}, metrics)
            st.plotly_chart(fig_radar, use_container_width=True)

    # 3. User Activity Events Timeline
    st.markdown("---")
    user_events = db.run_query("SELECT * FROM events WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20", (selected_user,))
    render_investigation_timeline(user_events, session_id=None)
