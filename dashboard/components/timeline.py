import streamlit as st
import pandas as pd

def render_investigation_timeline(events_df: pd.DataFrame, session_id: str = None):
    """Renders a SOC Investigation Timeline for a selected session or user."""
    st.markdown("### SOC Investigation Timeline")

    if events_df.empty:
        st.info("No events found for this session timeline.")
        return

    # Sort events chronologically
    df_sorted = events_df.sort_values(by="timestamp").reset_index(drop=True)

    for idx, row in df_sorted.iterrows():
        ts = row["timestamp"]
        action = row["action"]
        user_id = row["user_id"]
        ip = row["source_ip"]
        dev = row["device_id"]
        res = row["resource"]
        status = row["status"]
        bytes_tx = row["bytes_transferred"]

        # Color badges based on action status
        badge_color = "#FF2B2B" if status == "FAIL" or "ESCALATION" in action or "DELETE" in action or bytes_tx > 100e6 else "#3B82F6"
        
        st.markdown(
            f"""
            <div style="
                border-left: 4px solid {badge_color};
                background-color: #1F2937;
                padding: 12px 16px;
                margin-bottom: 8px;
                border-radius: 4px;
            ">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: bold; color: #F3F4F6; font-size: 15px;">{ts} &nbsp;|&nbsp; {action}</span>
                    <span style="background-color: {badge_color}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{status}</span>
                </div>
                <div style="margin-top: 6px; font-size: 13px; color: #9CA3AF;">
                    <b>User:</b> {user_id} &nbsp;•&nbsp; <b>IP:</b> {ip} &nbsp;•&nbsp; <b>Device:</b> {dev} <br/>
                    <b>Resource:</b> <code style="color: #60A5FA;">{res}</code> &nbsp;•&nbsp; <b>Data Transferred:</b> {bytes_tx / 1e6:.2f} MB
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
