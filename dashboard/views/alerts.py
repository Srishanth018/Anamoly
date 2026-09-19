import streamlit as st
import pandas as pd
import json
from src.database.db_manager import DatabaseManager
from src.enrichment.mitre_mapper import MITREMapper
from dashboard.components.charts import build_alert_risk_breakdown_chart
from dashboard.components.timeline import render_investigation_timeline

def render_alerts_page(db: DatabaseManager):
    st.title("Alert Triage & Explainable Risk Investigation")
    st.caption("Investigate security alerts, component risk breakdown, session attack timelines, and execute SOAR playbooks")

    # Filter by Severity
    sev_filter = st.multiselect("Filter by Severity:", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
    
    query = "SELECT * FROM alerts"
    if sev_filter:
        placeholders = ",".join(["?"] * len(sev_filter))
        query += f" WHERE severity IN ({placeholders})"
    query += " ORDER BY risk_score DESC, timestamp DESC"

    alerts_df = db.run_query(query, tuple(sev_filter) if sev_filter else ())

    if alerts_df.empty:
        st.info("No security alerts matching the selected filters.")
        return

    st.write(f"Showing **{len(alerts_df)}** matching security alerts:")

    # Select Alert for Deep Investigation
    alert_labels = [
        f"Alert #{r['alert_id']} | User {r['user_id']} | Risk: {r['risk_score']} ({r['severity']}) | Status: {r.get('status', 'OPEN')} | {r['timestamp']}"
        for _, r in alerts_df.iterrows()
    ]
    selected_idx = st.selectbox("Select Alert to Triage:", range(len(alert_labels)), format_func=lambda i: alert_labels[i])

    selected_alert = alerts_df.iloc[selected_idx]
    alert_id = selected_alert["alert_id"]
    current_status = selected_alert.get("status", "OPEN")

    st.markdown("---")

    # 1. Alert Summary Header Card with Status Badge
    sev_color = "#FF2B2B" if selected_alert["severity"] == "CRITICAL" else ("#FF7A00" if selected_alert["severity"] == "HIGH" else "#FFA800")
    status_bg = "#10B981" if "RESOLVED" in current_status else ("#EF4444" if current_status == "OPEN" else "#6B7280")

    st.markdown(
        f"""
        <div style="background-color: #1F2937; padding: 20px; border-radius: 8px; border-left: 6px solid {sev_color};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2 style="margin:0;">Alert ID: {alert_id}</h2>
                <div>
                    <span style="background-color: {status_bg}; color: white; padding: 4px 12px; border-radius: 12px; font-weight: bold; font-size: 14px; margin-right: 8px;">
                        Status: {current_status}
                    </span>
                    <span style="background-color: {sev_color}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 16px;">
                        {selected_alert['severity']} (Risk Score: {selected_alert['risk_score']}/100)
                    </span>
                </div>
            </div>
            <p style="color: #9CA3AF; margin-top: 10px;">
                <b>Target User:</b> {selected_alert['user_id']} &nbsp;•&nbsp; <b>Timestamp:</b> {selected_alert['timestamp']} &nbsp;•&nbsp; <b>Session:</b> {selected_alert['session_id']}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 2. SOAR Automated Response Playbook
    st.markdown("### SOAR Automated Response Playbook")
    col_act1, col_act2, col_act3, col_act4 = st.columns(4)

    with col_act1:
        if st.button("Revoke User Credentials", key=f"rev_{alert_id}"):
            db.update_alert_status(alert_id, "RESOLVED_CREDENTIALS_REVOKED")
            st.success("User credentials revoked in Identity Manager!")
            st.rerun()

    with col_act2:
        if st.button("Block Source IP Address", key=f"blk_{alert_id}"):
            db.update_alert_status(alert_id, "RESOLVED_IP_BLOCKED")
            st.success("Source IP added to perimeter firewall blocklist!")
            st.rerun()

    with col_act3:
        if st.button("Quarantine Endpoint Device", key=f"qua_{alert_id}"):
            db.update_alert_status(alert_id, "RESOLVED_DEVICE_QUARANTINED")
            st.success("Endpoint isolated via EDR agent!")
            st.rerun()

    with col_act4:
        if st.button("Mark as False Positive", key=f"fp_{alert_id}"):
            db.update_alert_status(alert_id, "FALSE_POSITIVE")
            st.info("Alert marked as False Positive.")
            st.rerun()

    st.markdown("---")

    # 3. Explainable Risk Breakdown
    st.markdown("### Why is this Activity Risky? (Explainable Risk Breakdown)")

    reasons_list = json.loads(selected_alert["reasons_json"]) if isinstance(selected_alert["reasons_json"], str) else selected_alert["reasons_json"]
    
    # Render Risk Breakdown Plotly Chart
    fig_breakdown = build_alert_risk_breakdown_chart(reasons_list, float(selected_alert["risk_score"]))
    st.plotly_chart(fig_breakdown, use_container_width=True)

    col_reasons, col_mitre = st.columns(2)

    with col_reasons:
        st.markdown("#### Contributing Risk Factors:")
        for r in reasons_list:
            st.markdown(f"- **{r}**")

    with col_mitre:
        st.markdown("#### Potentially Associated MITRE ATT&CK Techniques:")
        mitre_matches = MITREMapper.map_reasons_to_mitre(reasons_list)
        for m in mitre_matches:
            with st.expander(f"**{m['id']}: {m['name']}** ({m['tactic']})"):
                st.write(m['description'])
                st.info(f"**Mitigation Strategy:** {m['mitigation']}")

    # 4. Session Investigation Timeline
    st.markdown("---")
    session_id = selected_alert["session_id"]
    session_events = db.run_query("SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC", (session_id,))
    render_investigation_timeline(session_events, session_id=session_id)

    # 5. Executive Incident Report Generator
    st.markdown("---")
    st.markdown("### Executive Incident Report Exporter")
    
    report_md = f"""# Executive Incident Report: {alert_id}

## 1. Incident Overview
- **Alert ID:** {alert_id}
- **Timestamp:** {selected_alert['timestamp']}
- **Target User ID:** {selected_alert['user_id']}
- **Session ID:** {selected_alert['session_id']}
- **Assigned Risk Score:** {selected_alert['risk_score']}/100
- **Severity Classification:** {selected_alert['severity']}
- **Current Status:** {current_status}

## 2. Contributing Risk Factors & Behavioral Deviations
"""
    for r in reasons_list:
        report_md += f"- {r}\n"

    report_md += "\n## 3. MITRE ATT&CK Mapping & Mitigations\n"
    for m in mitre_matches:
        report_md += f"### {m['id']}: {m['name']} ({m['tactic']})\n- **Description:** {m['description']}\n- **Recommended Mitigation:** {m['mitigation']}\n\n"

    report_md += f"## 4. Session Telemetry Event Count\nTotal events recorded in session: {len(session_events)}\n"

    st.download_button(
        label="Download Executive Incident Report (.md)",
        data=report_md,
        file_name=f"Executive_Incident_Report_{alert_id}.md",
        mime="text/markdown"
    )
