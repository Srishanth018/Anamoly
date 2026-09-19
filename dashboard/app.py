import sys
import os
import streamlit as st

# Ensure root directory is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database.db_manager import DatabaseManager
from dashboard.views.overview import render_overview_page
from dashboard.views.analytics import render_analytics_page
from dashboard.views.users import render_users_page
from dashboard.views.alerts import render_alerts_page
from dashboard.views.sql_workbench import render_sql_workbench_page

# Page Config
st.set_page_config(
    page_title="Behavioral Security Anomaly & Threat Analytics",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Mode Cyber CSS Styling
st.markdown("""
    <style>
        .stApp {
            background-color: #0E1117;
            color: #F3F4F6;
        }
        [data-testid="stSidebar"] {
            background-color: #161B22;
            border-right: 1px solid #30363D;
        }
        .stMetric {
            background-color: #1F2937;
            border: 1px solid #374151;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        .stMetric label {
            color: #9CA3AF !important;
            font-size: 14px !important;
        }
        .stMetric [data-testid="stMetricValue"] {
            color: #60A5FA !important;
            font-size: 26px !important;
            font-weight: bold;
        }
    </style>
""", unsafe_allow_html=True)

# Initialize Database Manager
@st.cache_resource
def get_db_manager():
    return DatabaseManager(db_path="database/security.db")

db = get_db_manager()

# Sidebar Navigation
st.sidebar.title("SOC Threat Center")
st.sidebar.caption("Behavioral Analytics Platform v1.0")

nav_choice = st.sidebar.radio(
    "Navigation Mode",
    [
        "Security Overview",
        "Threat Analytics",
        "User Investigation",
        "Alert Triage",
        "SQL Workbench"
    ]
)

# Route pages
if nav_choice == "Security Overview":
    render_overview_page(db)
elif nav_choice == "Threat Analytics":
    render_analytics_page(db)
elif nav_choice == "User Investigation":
    render_users_page(db)
elif nav_choice == "Alert Triage":
    render_alerts_page(db)
elif nav_choice == "SQL Workbench":
    render_sql_workbench_page(db)
