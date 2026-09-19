"""Pre-defined security analytics SQL queries for threat hunting and dashboard metrics."""

QUERIES = {
    "security_overview_kpis": """
        SELECT
            (SELECT COUNT(*) FROM events) AS total_events,
            (SELECT COUNT(*) FROM alerts) AS total_alerts,
            (SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL') AS critical_alerts,
            (SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH') AS high_alerts,
            (SELECT COUNT(DISTINCT user_id) FROM events) AS active_users,
            (SELECT COUNT(DISTINCT e.source_ip) FROM alerts a JOIN events e ON a.event_id = e.event_id WHERE a.severity IN ('HIGH', 'CRITICAL')) AS suspicious_ips
    """,

    "alerts_by_severity": """
        SELECT severity, COUNT(*) AS alert_count
        FROM alerts
        GROUP BY severity
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
            END;
    """,

    "top_risky_users": """
        SELECT 
            u.user_id,
            u.department,
            u.role,
            COUNT(a.alert_id) AS alert_count,
            ROUND(AVG(a.risk_score), 2) AS avg_risk_score,
            MAX(a.risk_score) AS max_risk_score
        FROM alerts a
        JOIN users u ON a.user_id = u.user_id
        GROUP BY u.user_id, u.department, u.role
        ORDER BY avg_risk_score DESC, alert_count DESC
        LIMIT 10;
    """,

    "most_suspicious_ips": """
        SELECT 
            e.source_ip,
            e.country,
            COUNT(DISTINCT e.user_id) AS targeted_users,
            COUNT(a.alert_id) AS alert_count,
            ROUND(AVG(a.risk_score), 2) AS avg_risk_score
        FROM alerts a
        JOIN events e ON a.event_id = e.event_id
        GROUP BY e.source_ip, e.country
        ORDER BY alert_count DESC, avg_risk_score DESC
        LIMIT 10;
    """,

    "peak_attack_hours": """
        SELECT 
            strftime('%H', timestamp) AS hour,
            COUNT(*) AS alert_count,
            ROUND(AVG(risk_score), 2) AS avg_risk
        FROM alerts
        GROUP BY hour
        ORDER BY hour ASC;
    """,

    "alerts_over_time": """
        SELECT 
            strftime('%Y-%m-%d %H:00:00', timestamp) AS time_bucket,
            severity,
            COUNT(*) AS alert_count
        FROM alerts
        GROUP BY time_bucket, severity
        ORDER BY time_bucket ASC;
    """,

    "repeat_offenders": """
        SELECT 
            user_id, 
            COUNT(*) AS critical_high_alerts,
            ROUND(AVG(risk_score), 1) AS avg_score
        FROM alerts
        WHERE severity IN ('HIGH', 'CRITICAL')
        GROUP BY user_id
        HAVING COUNT(*) >= 2
        ORDER BY critical_high_alerts DESC;
    """,

    "department_risk_summary": """
        SELECT 
            u.department,
            COUNT(DISTINCT u.user_id) AS total_users,
            COUNT(a.alert_id) AS alert_count,
            ROUND(AVG(a.risk_score), 2) AS avg_department_risk
        FROM users u
        LEFT JOIN alerts a ON u.user_id = a.user_id
        GROUP BY u.department
        ORDER BY avg_department_risk DESC;
    """,

    "recent_critical_alerts": """
        SELECT 
            a.alert_id,
            a.timestamp,
            a.user_id,
            u.department,
            a.risk_score,
            a.severity,
            a.reasons_json,
            a.mitre_techniques_json
        FROM alerts a
        JOIN users u ON a.user_id = u.user_id
        WHERE a.severity IN ('HIGH', 'CRITICAL')
        ORDER BY a.timestamp DESC
        LIMIT 20;
    """,

    "after_hours_admin_escalations": """
        SELECT 
            e.event_id,
            e.timestamp,
            e.user_id,
            e.source_ip,
            e.resource,
            e.action,
            a.risk_score,
            a.severity
        FROM events e
        JOIN alerts a ON e.event_id = a.event_id
        WHERE (e.action = 'PRIVILEGE_ESCALATION' OR e.action = 'ADMIN_ACCESS')
          AND (CAST(strftime('%H', e.timestamp) AS INTEGER) >= 22 OR CAST(strftime('%H', e.timestamp) AS INTEGER) < 6)
        ORDER BY a.risk_score DESC;
    """,

    "off_hours_data_exfiltrators": """
        SELECT 
            e.user_id,
            e.source_ip,
            e.resource,
            ROUND(e.bytes_transferred / 1000000.0, 2) AS exfiltration_mb,
            e.timestamp,
            a.risk_score
        FROM events e
        JOIN alerts a ON e.event_id = a.event_id
        WHERE e.bytes_transferred > 50000000
          AND (CAST(strftime('%H', e.timestamp) AS INTEGER) >= 22 OR CAST(strftime('%H', e.timestamp) AS INTEGER) < 6)
        ORDER BY e.bytes_transferred DESC;
    """,

    "mass_file_deletion_events": """
        SELECT 
            e.user_id,
            e.session_id,
            COUNT(*) AS deleted_files_count,
            MIN(e.timestamp) AS start_time,
            MAX(e.timestamp) AS end_time
        FROM events e
        WHERE e.action = 'FILE_DELETE'
        GROUP BY e.user_id, e.session_id
        ORDER BY deleted_files_count DESC;
    """,

    "unusual_country_logins": """
        SELECT 
            e.user_id,
            e.source_ip,
            e.country,
            e.timestamp,
            a.risk_score,
            a.severity
        FROM events e
        JOIN alerts a ON e.event_id = a.event_id
        WHERE e.country IN ('Russia', 'North Korea', 'Romania', 'China', 'Brazil')
        ORDER BY a.risk_score DESC;
    """
}
