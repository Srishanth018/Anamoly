import os
import yaml
import json
import uuid
import pandas as pd
import numpy as np
from datetime import datetime

# Import ingestion
from src.ingestion.log_loader import LogLoader
from src.ingestion.log_normalizer import LogNormalizer

# Import features
from src.features.temporal_features import extract_temporal_features
from src.features.user_features import extract_user_features
from src.features.network_features import extract_network_features
from src.features.session_features import extract_session_features
from src.features.deviation_features import extract_deviation_features

# Import behavior & baselines
from src.behavior.user_baseline import UserBaselineBuilder
from src.behavior.peer_baseline import PeerGroupBaselineBuilder
from src.behavior.drift_detector import DriftDetector

# Import detection engines
from src.detection.rule_engine import RuleEngine
from src.detection.statistical_detector import StatisticalDetector
from src.detection.ml_detector import MLAnomalyDetector
from src.detection.sequence_detector import SequenceDetector

# Import scoring & enrichment
from src.scoring.risk_engine import ExplainableRiskEngine
from src.scoring.severity import SeverityClassifier
from src.enrichment.mitre_mapper import MITREMapper

# Import database
from src.database.db_manager import DatabaseManager
from data.generate_data import generate_synthetic_data

def run_security_pipeline(config_path="config.yaml"):
    print("=" * 80)
    print("      BEHAVIORAL SECURITY LOG ANOMALY DETECTION & THREAT ANALYTICS")
    print("=" * 80)

    # 1. Load Configuration
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    db_path = config["system"]["db_path"]
    db = DatabaseManager(db_path=db_path, force_reinit=True)

    # 2. Generate or Load Synthetic Data
    raw_path = config["data"]["raw_log_path"]
    if not os.path.exists(raw_path):
        print(f"[+] Generating synthetic enterprise security dataset -> {raw_path}")
        raw_df, users_df, devices_df = generate_synthetic_data(output_path=raw_path)
    else:
        print(f"[+] Loading raw security logs from {raw_path}")
        raw_df = LogLoader.load_logs(raw_path)
        # Generate metadata if not available
        _, users_df, devices_df = generate_synthetic_data(output_path=raw_path)

    # Store users and devices in database
    db.insert_users(users_df)
    db.insert_devices(devices_df)

    # 3. Log Normalization
    print("[+] Normalizing raw security telemetry logs...")
    norm_df = LogNormalizer.normalize(raw_df)
    
    # Save normalized events CSV
    proc_path = config["data"]["processed_log_path"]
    os.makedirs(os.path.dirname(proc_path), exist_ok=True)
    norm_df.to_csv(proc_path, index=False)
    db.insert_events(norm_df)

    # 4. Baseline Computation
    print("[+] Learning individual user and peer group behavioral baselines...")
    user_baselines = UserBaselineBuilder.build_baselines(norm_df, users_df)
    peer_baselines = PeerGroupBaselineBuilder.build_peer_baselines(user_baselines)
    
    baselines_df = UserBaselineBuilder.to_dataframe(user_baselines)
    db.insert_baselines(baselines_df)

    # 5. Feature Engineering
    print("[+] Extracting temporal, user, network, session, and deviation features...")
    feat_df = extract_temporal_features(norm_df, config["detection"]["rule_engine"]["after_hours_start"], config["detection"]["rule_engine"]["after_hours_end"])
    feat_df = extract_user_features(feat_df)
    feat_df = extract_network_features(feat_df, user_baselines)
    feat_df = extract_session_features(feat_df)
    feat_df = extract_deviation_features(feat_df, user_baselines)
    feat_df = DriftDetector.calculate_drift_scores(feat_df)

    # 6. ML Model Training (Isolation Forest)
    print("[+] Training Machine Learning Isolation Forest Anomaly Model...")
    ml_detector = MLAnomalyDetector(
        contamination=config["detection"]["ml_engine"]["contamination"],
        n_estimators=config["detection"]["ml_engine"]["n_estimators"]
    )
    ml_detector.fit(feat_df)
    ml_detector.save(config["system"]["models_dir"])

    _, ml_scores = ml_detector.predict_anomaly_scores(feat_df)
    feat_df["ml_score"] = ml_scores

    # 7. Multi-Layer Detection & Risk Scoring
    print("[+] Executing Rule, Statistical, ML, Sequence, and Peer Detection Engines...")
    rule_engine = RuleEngine(config)
    risk_engine = ExplainableRiskEngine(config)

    alerts = []
    session_risks = {}

    # Pre-calculate session attack sequences
    session_sequences = {}
    for sid, group in feat_df.groupby("session_id"):
        seq_reasons, seq_score = SequenceDetector.evaluate_session_sequence(group)
        session_sequences[sid] = (seq_reasons, seq_score)

    for idx, row in feat_df.iterrows():
        # Rule evaluation
        rule_reasons, rule_score = rule_engine.evaluate_rules(row, user_baselines, peer_baselines)

        # Statistical evaluation
        stat_reasons, stat_score = StatisticalDetector.evaluate_statistical_anomalies(row, user_baselines)

        # Peer anomaly evaluation
        peer_anom = PeerGroupBaselineBuilder.is_peer_anomaly(row, user_baselines, peer_baselines)

        # Session Sequence evaluation
        sid = row["session_id"]
        seq_reasons, seq_score = session_sequences.get(sid, ([], 0.0))

        # Drift evaluation
        drift_score = float(row.get("drift_score", 0.0))
        ml_score = float(row.get("ml_score", 0.0))

        # Risk Score Calculation
        final_risk, reasons, factor_breakdown = risk_engine.calculate_event_risk(
            rule_reasons, rule_score,
            stat_reasons, stat_score,
            ml_score,
            seq_reasons, seq_score,
            peer_anom, drift_score
        )

        severity = SeverityClassifier.get_severity(final_risk)

        # Track max risk per session
        if sid not in session_risks or final_risk > session_risks[sid]["max_risk"]:
            session_risks[sid] = {
                "user_id": row["user_id"],
                "start_time": row["timestamp"],
                "end_time": row["timestamp"],
                "event_count": row["session_event_count"],
                "total_bytes": row["session_total_bytes"],
                "max_risk": final_risk,
                "severity": severity
            }

        # Generate Alert if Risk Score >= 30 (MEDIUM, HIGH, CRITICAL or suspicious LOW)
        if final_risk >= 30.0 or len(reasons) >= 2:
            mitre_matches = MITREMapper.map_reasons_to_mitre(reasons)
            
            alerts.append({
                "alert_id": f"ALT_{uuid.uuid4().hex[:8].upper()}",
                "event_id": row["event_id"],
                "session_id": sid,
                "user_id": row["user_id"],
                "source_ip": row["source_ip"],
                "risk_score": final_risk,
                "severity": severity,
                "reasons_json": json.dumps(reasons),
                "mitre_techniques_json": json.dumps([m["id"] for m in mitre_matches]),
                "timestamp": str(row["timestamp"]),
                "status": "OPEN"
            })

    # Save alerts into SQLite
    alerts_df = pd.DataFrame(alerts)
    if not alerts_df.empty:
        db.insert_alerts(alerts_df)

    # Save sessions into SQLite
    sessions_records = []
    for sid, sdata in session_risks.items():
        sessions_records.append({
            "session_id": sid,
            "user_id": sdata["user_id"],
            "start_time": str(sdata["start_time"]),
            "end_time": str(sdata["end_time"]),
            "event_count": sdata["event_count"],
            "total_bytes": sdata["total_bytes"],
            "max_risk_score": sdata["max_risk"],
            "severity": sdata["severity"]
        })
    db.insert_sessions(pd.DataFrame(sessions_records))

    print("-" * 80)
    print("PIPELINE EXECUTION SUMMARY")
    print("-" * 80)
    print(f"Total Normalized Events Processed: {len(norm_df)}")
    print(f"Total Security Alerts Generated:    {len(alerts_df)}")
    print(f"Critical Alerts (Score 76-100):      {len(alerts_df[alerts_df['severity'] == 'CRITICAL']) if not alerts_df.empty else 0}")
    print(f"High Alerts (Score 51-75):          {len(alerts_df[alerts_df['severity'] == 'HIGH']) if not alerts_df.empty else 0}")
    print(f"Medium Alerts (Score 26-50):        {len(alerts_df[alerts_df['severity'] == 'MEDIUM']) if not alerts_df.empty else 0}")
    print(f"SQLite Database Population:        SUCCESS ({db_path})")
    print("=" * 80)

if __name__ == "__main__":
    run_security_pipeline()
