import streamlit as st
import pandas as pd
from src.database.db_manager import DatabaseManager
from src.database.queries import QUERIES
from dashboard.components.charts import build_severity_pie_chart, build_risk_distribution_chart, build_peak_hours_chart

def render_overview_page(db: DatabaseManager):
    st.title("Security Monitor & Threat Overview")
    st.caption("Real-time behavioral log anomaly detection & enterprise threat telemetry monitoring")

    # 1. KPI Cards
    kpi_df = db.run_query(QUERIES["security_overview_kpis"])
    if not kpi_df.empty:
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Events", f"{kpi_df['total_events'].iloc[0]:,}")
        col2.metric("Total Alerts", f"{kpi_df['total_alerts'].iloc[0]:,}")
        col3.metric("Critical Incidents", f"{kpi_df['critical_alerts'].iloc[0]}", delta="Requires Action", delta_color="inverse")
        col4.metric("High Severity", f"{kpi_df['high_alerts'].iloc[0]}")
        col5.metric("Monitored Users", f"{kpi_df['active_users'].iloc[0]}")

    st.markdown("---")

    # 2. Charts Row
    col_left, col_right = st.columns(2)

    with col_left:
        alerts_df = db.run_query("SELECT alert_id, risk_score, severity, timestamp FROM alerts")
        fig_pie = build_severity_pie_chart(alerts_df)
        st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": "hover"})

    with col_right:
        fig_hist = build_risk_distribution_chart(alerts_df)
        st.plotly_chart(fig_hist, use_container_width=True, config={"displayModeBar": "hover"})

    # 3. Peak Attack Hours & Department Summary
    col_h1, col_h2 = st.columns(2)
    with col_h1:
        peak_df = db.run_query(QUERIES["peak_attack_hours"])
        fig_peak = build_peak_hours_chart(peak_df)
        st.plotly_chart(fig_peak, use_container_width=True, config={"displayModeBar": "hover"})

    with col_h2:
        st.markdown("### Department Risk Summary")
        dept_df = db.run_query(QUERIES["department_risk_summary"])
        st.dataframe(dept_df, use_container_width=True, hide_index=True)

    # 4. Recent Critical Alerts Table
    st.markdown("---")
    st.markdown("### Recent Critical & High Threats")
    crit_df = db.run_query(QUERIES["recent_critical_alerts"])
    if not crit_df.empty:
        st.dataframe(crit_df, use_container_width=True, hide_index=True)
    else:
        st.success("No active critical alerts detected in system.")
