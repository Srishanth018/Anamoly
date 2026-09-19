import pytest
from src.scoring.risk_engine import ExplainableRiskEngine
from src.scoring.severity import SeverityClassifier

def test_severity_classifier():
    assert SeverityClassifier.get_severity(85.0) == "CRITICAL"
    assert SeverityClassifier.get_severity(60.0) == "HIGH"
    assert SeverityClassifier.get_severity(35.0) == "MEDIUM"
    assert SeverityClassifier.get_severity(10.0) == "LOW"

def test_explainable_risk_engine():
    engine = ExplainableRiskEngine()
    final_score, reasons, breakdown = engine.calculate_event_risk(
        rule_reasons=["Off-hours activity", "Unseen IP"],
        rule_score=35.0,
        stat_reasons=["Data volume 14.2x above baseline"],
        stat_score=40.0,
        ml_score=85.0,
        seq_reasons=["Attack Sequence Match: Credential Stuffing -> Auth"],
        seq_score=25.0,
        peer_anomaly=1.0,
        drift_score=40.0
    )
    
    assert final_score >= 76.0 # Must be CRITICAL
    assert len(reasons) > 0
    assert "Rules Engine" in breakdown
    assert "ML Isolation Forest" in breakdown
