import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

def build_severity_pie_chart(df: pd.DataFrame):
    if df.empty or "severity" not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="No Alert Data", showarrow=False, font=dict(color="#FFFFFF", size=16))
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        return fig

    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]

    # Ensure all 4 severity categories exist
    all_severities = pd.DataFrame({"severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]})
    counts = pd.merge(all_severities, counts, on="severity", how="left").fillna(0)
    counts["count"] = counts["count"].astype(int)

    color_map = {
        "CRITICAL": "#FF2B2B",
        "HIGH": "#FF7A00",
        "MEDIUM": "#FFA800",
        "LOW": "#00CC66"
    }

    # Format legend labels with count (e.g. "CRITICAL: 4 alerts") so no values are truncated
    counts["legend_label"] = counts.apply(lambda r: f"{r['severity']}: {r['count']:,}", axis=1)
    label_color_map = {f"{r['severity']}: {r['count']:,}": color_map[r['severity']] for _, r in counts.iterrows()}

    fig = px.pie(
        counts,
        names="legend_label",
        values="count",
        color="legend_label",
        color_discrete_map=label_color_map,
        hole=0.42
    )

    fig.update_traces(
        textinfo="percent+value",
        textposition="inside",
        insidetextfont=dict(size=13, color="#FFFFFF"),
        hovertemplate="Severity: <b>%{label}</b><br>Alert Count: <b>%{value:,}</b><br>Share: <b>%{percent}</b><extra></extra>",
        marker=dict(line=dict(color="#1F2937", width=2))
    )

    fig.update_layout(
        title=dict(text="Alerts by Severity Level", y=0.97, x=0.02, xanchor="left", yanchor="top"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#FFFFFF", size=13),
        height=470,
        margin=dict(l=20, r=20, t=65, b=30),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.22,
            xanchor="center",
            x=0.5,
            font=dict(size=13, color="#F3F4F6")
        )
    )
    return fig

def build_risk_distribution_chart(df: pd.DataFrame):
    if df.empty or "risk_score" not in df.columns:
        return go.Figure()

    bins = list(range(0, 105, 5))
    labels = [f"{b}-{b+5}" for b in range(0, 100, 5)]
    
    df_copy = df.copy()
    df_copy["risk_bin"] = pd.cut(df_copy["risk_score"], bins=bins, labels=labels, right=False, include_lowest=True)
    
    bin_counts = df_copy["risk_bin"].value_counts().reindex(labels, fill_value=0).reset_index()
    bin_counts.columns = ["risk_range", "alert_count"]

    fig = px.bar(
        bin_counts,
        x="risk_range",
        y="alert_count",
        labels={"risk_range": "Risk Score Range", "alert_count": "Alert Count"},
        color="alert_count",
        color_continuous_scale="Oranges"
    )
    
    fig.update_traces(
        hovertemplate="Risk Range: <b>%{x}</b><br>Alert Count: <b>%{y}</b><extra></extra>",
        marker_line_color="#1F2937",
        marker_line_width=1
    )
    
    fig.update_layout(
        title=dict(text="Risk Score Distribution (0–100)", y=0.97, x=0.02, xanchor="left", yanchor="top"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#FFFFFF"),
        xaxis=dict(gridcolor="#2E3748", title="Risk Score Range (0–100)"),
        yaxis=dict(gridcolor="#2E3748", title="Frequency"),
        height=430,
        margin=dict(l=30, r=30, t=65, b=40)
    )
    return fig

def build_peak_hours_chart(peak_df: pd.DataFrame):
    all_hours = pd.DataFrame({"hour": [f"{h:02d}" for h in range(24)]})
    
    if not peak_df.empty:
        df_merged = pd.merge(all_hours, peak_df, on="hour", how="left").fillna(0)
    else:
        df_merged = all_hours.copy()
        df_merged["alert_count"] = 0
        df_merged["avg_risk"] = 0.0

    df_merged["hour_label"] = df_merged["hour"].apply(lambda h: f"{h}:00")

    fig = px.bar(
        df_merged,
        x="hour_label",
        y="alert_count",
        color="avg_risk",
        color_continuous_scale="Reds",
        labels={"hour_label": "Hour of Day (00:00 - 23:00)", "alert_count": "Alert Count", "avg_risk": "Avg Risk Score"}
    )
    
    fig.update_traces(
        hovertemplate="Hour: <b>%{x}</b><br>Alert Count: <b>%{y}</b><br>Avg Risk: <b>%{customdata:.1f}</b><extra></extra>",
        customdata=df_merged["avg_risk"]
    )
    
    fig.update_layout(
        title=dict(text="Peak Threat Activity Hours (All 24 Hours)", y=0.97, x=0.02, xanchor="left", yanchor="top"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#FFFFFF"),
        xaxis=dict(gridcolor="#2E3748", tickangle=-45),
        yaxis=dict(gridcolor="#2E3748"),
        margin=dict(l=20, r=20, t=65, b=40)
    )
    return fig

def build_user_radar_chart(user_id: str, baseline: dict, current_metrics: dict):
    categories = ["Work Hours Match", "IP Consistency", "Device Consistency", "Download Volume", "Resource Normality"]
    
    normal_values = [100, 100, 100, 100, 100]
    
    current_values = [
        current_metrics.get("hour_match", 100),
        current_metrics.get("ip_match", 100),
        current_metrics.get("device_match", 100),
        current_metrics.get("download_match", 100),
        current_metrics.get("resource_match", 100)
    ]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=normal_values,
        theta=categories,
        fill='toself',
        name='Normal Baseline Profile',
        line_color='#00CC66'
    ))
    fig.add_trace(go.Scatterpolar(
        r=current_values,
        theta=categories,
        fill='toself',
        name=f'Current Session ({user_id})',
        line_color='#FF2B2B'
    ))

    fig.update_layout(
        title=dict(text=f"User Baseline vs Current Activity Radar ({user_id})", y=0.97, x=0.02, xanchor="left", yanchor="top"),
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 100], gridcolor="#2E3748"),
            angularaxis=dict(gridcolor="#2E3748")
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#FFFFFF"),
        margin=dict(l=40, r=40, t=65, b=40)
    )
    return fig

def build_alert_risk_breakdown_chart(reasons_list: list, total_risk_score: float):
    if not reasons_list:
        return go.Figure()

    factors = []
    scores = []
    
    point_weights = {
        "off-hours": 12,
        "brute force": 20,
        "unseen ip": 15,
        "unseen device": 12,
        "geographic location": 15,
        "sensitive resource": 18,
        "exfiltration": 22,
        "privilege escalation": 25,
        "removable media": 15,
        "deletion": 18,
        "ml isolation forest": 20,
        "attack sequence": 25,
        "peer group": 15,
        "drift": 15
    }

    for r in reasons_list:
        r_str = str(r).lower()
        assigned_pts = 10
        for kw, w in point_weights.items():
            if kw in r_str:
                assigned_pts = w
                break
        factors.append(r[:45] + ("..." if len(r) > 45 else ""))
        scores.append(assigned_pts)

    df_factors = pd.DataFrame({"Factor": factors, "RiskPoints": scores}).sort_values(by="RiskPoints", ascending=True)

    fig = px.bar(
        df_factors,
        x="RiskPoints",
        y="Factor",
        orientation="h",
        color="RiskPoints",
        color_continuous_scale="Reds",
        labels={"RiskPoints": "Risk Point Contribution", "Factor": "Detection Factor"}
    )

    fig.update_traces(
        hovertemplate="Factor: <b>%{y}</b><br>Points: <b>+%{x}</b><extra></extra>",
        marker_line_color="#1F2937",
        marker_line_width=1
    )

    fig.update_layout(
        title=dict(text=f"Explainable Risk Score Breakdown (Total: {total_risk_score:.0f}/100)", y=0.97, x=0.02, xanchor="left", yanchor="top"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#FFFFFF"),
        xaxis=dict(gridcolor="#2E3748", range=[0, 30]),
        yaxis=dict(gridcolor="#2E3748"),
        height=330,
        margin=dict(l=20, r=20, t=65, b=30)
    )
    return fig
