import streamlit as st
import pandas as pd
from src.database.db_manager import DatabaseManager
from src.database.queries import QUERIES

def render_sql_workbench_page(db: DatabaseManager):
    st.title("SQL Security Threat Hunting Workbench")
    st.caption("Execute custom security analytical queries against normalized telemetry, sessions, baselines, and alerts")

    # Template selection
    template_choice = st.selectbox("Select SQL Threat Query Template:", ["Custom Query"] + list(QUERIES.keys()))

    if template_choice != "Custom Query":
        default_query = QUERIES[template_choice]
    else:
        default_query = "SELECT user_id, COUNT(*) AS alert_count, AVG(risk_score) AS avg_risk FROM alerts GROUP BY user_id ORDER BY avg_risk DESC;"

    query_input = st.text_area("SQL Query Editor:", value=default_query, height=160)

    if st.button("Run SQL Query", type="primary"):
        try:
            res_df = db.run_query(query_input)
            st.success(f"Query returned **{len(res_df)}** rows successfully.")
            st.dataframe(res_df, use_container_width=True)

            # Export to CSV option
            csv_data = res_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Results CSV",
                data=csv_data,
                file_name="security_query_results.csv",
                mime="text/csv"
            )
        except Exception as e:
            st.error(f"SQL Execution Error: {str(e)}")

    st.markdown("---")
    st.markdown("### Database Schema Reference")
    with st.expander("View SQLite Database Tables & Schema"):
        st.code("""
-- Tables:
1. users (user_id, department, role, created_at)
2. devices (device_id, user_id, device_type, os_info)
3. events (event_id, timestamp, user_id, source_ip, country, device_id, event_type, resource, action, status, session_id, bytes_transferred, duration)
4. sessions (session_id, user_id, start_time, end_time, event_count, total_bytes, max_risk_score, severity)
5. baselines (user_id, department, avg_daily_events, normal_start_hour, normal_end_hour, frequent_ips, frequent_devices, avg_daily_download_mb, std_daily_download_mb, normal_resources_json)
6. alerts (alert_id, event_id, session_id, user_id, source_ip, risk_score, severity, reasons_json, mitre_techniques_json, timestamp, status)
        """, language="sql")
