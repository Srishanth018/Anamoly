import pytest
from src.detection.rule_engine import RuleEngine

def test_rule_engine_off_hours_and_unseen_ip():
    rule_engine = RuleEngine()
    user_baselines = {
        "U101": {"ips": ["10.0.1.15"], "devices": ["DEV_101"]}
    }
    
    row = {
        "user_id": "U101",
        "hour": 2, # Off hours
        "source_ip": "185.220.101.4", # Alien IP
        "device_id": "DEV_UNKNOWN", # Alien Device
        "bytes_transferred": 500_000_000, # 500 MB download
        "resource": "/hr/confidential_payroll.xlsx",
        "failed_logins_last_5m": 6
    }
    
    reasons, score = rule_engine.evaluate_rules(row, user_baselines)
    assert score > 50.0
    assert any("Off-hours" in r for r in reasons)
    assert any("Unseen IP" in r for r in reasons)
    assert any("Large data exfiltration" in r for r in reasons)
    assert any("Brute force" in r for r in reasons)
