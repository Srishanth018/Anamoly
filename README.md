# Behavioral Security Log Anomaly Detection & Threat Analytics Platform

A production-grade cybersecurity analytics platform that learns normal user behavior from authentication and system activity logs, detects behavioral deviations using statistical, rule-based, machine learning (Isolation Forest), and sequence-based methods, assigns explainable risk scores (0–100), maps detections to MITRE ATT&CK techniques, executes automated SOAR playbook responses, and provides an interactive investigation dashboard for SOC security analysts.

---

## 🌟 Key System Capabilities

1. **Multi-Layered Detection Engine**:
   - **Deterministic Heuristic Rules**: Detects brute force bursts, off-hours access, unseen IPs/devices, USB connections, and privilege escalations.
   - **Personalized Statistical Deviation**: Computes per-user $z$-scores and quantile deviations on download volume, duration, and resource access.
   - **Machine Learning (Isolation Forest)**: Trains unsupervised anomaly detection models on normal telemetry baseline activity.
   - **Attack Sequence Analysis**: Detects multi-event attack chains across sessions (e.g. `Brute Force -> Successful Auth -> Sudo Escalation -> Exfiltration`).
2. **Three-Tier Behavioral Baselines**:
   - **Individual Baseline**: Normal working hours, primary IPs, authorized devices, and average daily download volume.
   - **Peer-Group Baseline**: Departmental/role norm comparison to flag out-of-role resource access.
   - **Behavioral Drift Detection**: Tracks 7-day vs 30-day rolling activity to spot gradual volume escalation.
3. **Explainable Risk & Severity Scoring**:
   - Calibrates combined signals into an explainable 0–100 Risk Score categorized into `LOW` (0-25), `MEDIUM` (26-50), `HIGH` (51-75), and `CRITICAL` (76-100).
   - Provides transparent point attribution (+15 Off-hours, +20 ML Anomaly, +25 Exfiltration Volume).
4. **MITRE ATT&CK Mapping & Threat Intelligence**:
   - Automatically tags alerts with relevant MITRE ATT&CK techniques (`T1078 Valid Accounts`, `T1110 Brute Force`, `T1068 Privilege Escalation`, `T1048 Exfiltration`, `T1091 Removable Media`, `T1485 Data Destruction`, `T1071 Application Protocol`).
5. **Automated SOAR Playbook Action Triggers**:
   - Allows analysts to execute real-time mitigation actions (`Revoke Credentials`, `Block Source IP`, `Quarantine Device`, `Mark False Positive`) updating alert statuses live in SQLite.
6. **Executive Incident Report Generator**:
   - Generates and downloads formal Markdown Executive Incident Reports (`.md`) summarizing incident metadata, timeline, risk breakdown, and recommended mitigations.
7. **Real-time Stream API Ingestor**:
   - Ingests arbitrary real-time JSON log payloads directly into the detection pipeline and database (`src/ingestion/api_ingestor.py`).
8. **Interactive Dark-Themed SOC Dashboard**:
   - Multi-page Streamlit dashboard featuring Security Overview, Threat Analytics & Drift, User Profile Investigation, Alert Triage with SOAR triggers, and SQL Threat Hunting.

---

## 📁 Repository Structure

```
behavioral-security-anomaly-detection/
├── config.yaml                     # Risk weights, detection thresholds, parameters
├── requirements.txt                # Python dependencies
├── README.md                       # Documentation
├── run_pipeline.py                 # CLI tool to execute end-to-end telemetry ingestion & alert scoring
│
├── data/
│   ├── generate_data.py            # Synthetic enterprise security telemetry log generator
│   ├── raw/                        # Raw generated log CSVs
│   └── processed/                  # Processed normalized events CSV
│
├── database/
│   ├── schema.sql                  # Database schema (events, users, sessions, alerts, baselines)
│   └── security.db                 # SQLite database storage
│
├── notebooks/
│   └── 01_threat_eda.ipynb         # Exploratory Data Analysis & Model Evaluation Notebook
│
├── src/
│   ├── ingestion/
│   │   ├── log_loader.py           # Multi-format log loader (CSV/JSON/JSONL)
│   │   ├── log_normalizer.py       # Standard event schema normalizer
│   │   └── api_ingestor.py         # Real-time Stream JSON payload ingestor
│   ├── features/
│   │   ├── temporal_features.py    # Work hours, after-hours, weekend indicators
│   │   ├── user_features.py        # Failed login bursts & rolling window counts
│   │   ├── network_features.py     # Unseen IP, alien subnet, and device flags
│   │   ├── session_features.py     # Session byte totals & event counts
│   │   └── deviation_features.py   # Z-score & percentile deviations
│   ├── behavior/
│   │   ├── user_baseline.py        # Individual user baseline modeler
│   │   ├── peer_baseline.py        # Departmental peer group baseline builder
│   │   └── drift_detector.py       # 7-day vs 30-day rolling behavioral drift calculator
│   ├── detection/
│   │   ├── rule_engine.py          # Deterministic security rule engine
│   │   ├── statistical_detector.py # Personalized statistical anomaly engine
│   │   ├── ml_detector.py          # Isolation Forest ML model wrapper
│   │   └── sequence_detector.py    # Multi-event session attack sequence detector
│   ├── scoring/
│   │   ├── risk_engine.py          # Explainable 0-100 risk engine
│   │   └── severity.py             # Risk categorization (LOW, MEDIUM, HIGH, CRITICAL)
│   ├── enrichment/
│   │   └── mitre_mapper.py         # MITRE ATT&CK technique mapper
│   └── database/
│       ├── db_manager.py           # SQLite connection & batch helper manager
│       └── queries.py              # Pre-defined security SQL queries
│
├── models/
│   ├── isolation_forest.pkl        # Serialized Isolation Forest model
│   └── scaler.pkl                  # StandardScaler model file
│
├── dashboard/
│   ├── app.py                      # Streamlit main entrance
│   ├── pages/
│   ├── views/
│   │   ├── overview.py             # Security Overview & KPI Monitor
│   │   ├── analytics.py            # Threat Analytics & Behavioral Drift
│   │   ├── users.py                # User Investigation & Radar Profile
│   │   ├── alerts.py               # Alert Triage & Explainable Breakdown with SOAR triggers
│   │   └── sql_workbench.py        # SQL Threat Hunting Workbench
│   └── components/
│       ├── charts.py               # Plotly graphics builders
│       └── timeline.py             # SOC Investigation Timeline renderer
│
└── tests/
    ├── conftest.py                 # Pytest configuration
    ├── test_features.py            # Feature extraction unit tests
    ├── test_ingestion.py           # Stream API ingestion unit tests
    ├── test_rules.py               # Security rules unit tests
    └── test_scoring.py             # Risk engine unit tests
```

---

## 🚀 Quick Start Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Ingestion & Threat Detection Pipeline
```bash
python run_pipeline.py
```

### 3. Run Automated Test Suite
```bash
python -m pytest tests/
```

### 4. Launch Interactive SOC Dashboard
```bash
streamlit run dashboard/app.py
```
Open `http://localhost:8501` in your browser.
