# Behavioral Security Log Anomaly Detection & Threat Analytics Platform

A production-grade cybersecurity analytics platform that learns normal user behavior from authentication and system activity logs, detects behavioral deviations using statistical, rule-based, machine learning (Isolation Forest), and sequence-based methods, assigns explainable risk scores (0–100), maps detections to MITRE ATT&CK techniques, executes automated SOAR playbook responses, supports **authentic real-world production security log datasets**, and provides an interactive investigation dashboard for SOC security analysts.

---

## Key System Capabilities

1. **Multi-Layered Detection Engine**:
   - **Deterministic Heuristic Rules**: Detects brute force bursts, off-hours access, unseen IPs/devices, USB connections, and privilege escalations.
   - **Personalized Statistical Deviation**: Computes per-user $z$-scores and quantile deviations on download volume, duration, and resource access.
   - **Machine Learning (Isolation Forest)**: Trains unsupervised anomaly detection models on normal telemetry baseline activity.
   - **Attack Sequence Analysis**: Detects multi-event attack chains across sessions (e.g. `Brute Force -> Successful Auth -> Sudo Escalation -> Exfiltration`).
2. **Three-Tier Behavioral Baselines**:
   - **Individual Baseline**: Normal working hours, primary IPs, authorized devices, and average daily download volume.
   - **Peer-Group Baseline**: Departmental/role norm comparison to flag out-of-role resource access.
   - **Behavioral Drift Detection**: Tracks 7-day vs 30-day rolling activity to spot gradual volume escalation.
3. **Authentic Real-World Production Log Ingestion**:
   - Automated fetcher & parser (`data/fetch_real_public_dataset.py`) to download and normalize **authentic real-world production Linux authentication logs (`/var/log/auth.log`)** and **real Windows workstation event logs** from the Loghub Benchmark.
   - Converter (`data/load_real_dataset.py`) to parse **CERT Insider Threat Dataset (r4.2/r5.2)**, **LANL Telemetry**, or arbitrary enterprise security CSVs.
4. **Explainable Risk & Severity Scoring**:
   - Calibrates combined signals into an explainable 0–100 Risk Score categorized into `LOW` (0-25), `MEDIUM` (26-50), `HIGH` (51-75), and `CRITICAL` (76-100).
   - Provides transparent point attribution (+15 Off-hours, +20 ML Anomaly, +25 Exfiltration Volume).
5. **MITRE ATT&CK Mapping & Threat Intelligence**:
   - Automatically tags alerts with relevant MITRE ATT&CK techniques (`T1078 Valid Accounts`, `T1110 Brute Force`, `T1068 Privilege Escalation`, `T1048 Exfiltration`, `T1091 Removable Media`, `T1485 Data Destruction`, `T1071 Application Protocol`).
6. **Automated SOAR Playbook Action Triggers**:
   - Allows analysts to execute real-time mitigation actions (`Revoke Credentials`, `Block Source IP`, `Quarantine Device`, `Mark False Positive`) updating alert statuses live in SQLite.
7. **Executive Incident Report Generator**:
   - Generates and downloads formal Markdown Executive Incident Reports (`.md`) summarizing incident metadata, timeline, risk breakdown, and recommended mitigations.
8. **Real-time Stream API Ingestor**:
   - Ingests arbitrary real-time JSON log payloads directly into the detection pipeline and database (`src/ingestion/api_ingestor.py`).
9. **Interactive Dark-Themed SOC Dashboard**:
   - Multi-page Streamlit dashboard featuring Security Overview, Threat Analytics & Drift, User Profile Investigation, Alert Triage with SOAR triggers, and SQL Threat Hunting.

---

## 🌐 Fetching & Testing Real-World Production Datasets

You can run the entire platform directly on authentic production log data:

### Option A: Fetch & Run on Authentic Real Production Logs (Linux Auth + Windows Logs)
Downloads authentic, real-world production logs from Loghub (LogPAI Benchmark) and runs the entire pipeline:
```bash
python data/fetch_real_public_dataset.py
python run_pipeline.py
```

### Option B: Test using CERT Insider Threat Dataset (r4.2/r5.2)
Download CERT r4.2 / r5.2 (`logon.csv`, `file.csv`, `device.csv`) and run:
```bash
python data/load_real_dataset.py --source cert --path /path/to/cert_directory
python run_pipeline.py
```

### Option C: Test using Custom Real Enterprise Security Logs (CSV/JSON)
```bash
python data/load_real_dataset.py --source custom_csv --path /path/to/your_logs.csv
python run_pipeline.py
```

---

## Quick Start Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Fetch Real Production Telemetry & Run Detection Pipeline
```bash
python data/fetch_real_public_dataset.py
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
