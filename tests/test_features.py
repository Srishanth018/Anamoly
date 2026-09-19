import pandas as pd
import pytest
from src.features.temporal_features import extract_temporal_features
from src.features.user_features import extract_user_features
from src.features.network_features import extract_network_features

def test_temporal_features():
    df = pd.DataFrame([
        {"timestamp": "2026-09-10 02:15:00"}, # After hours
        {"timestamp": "2026-09-10 14:00:00"}  # Work hours
    ])
    res = extract_temporal_features(df)
    assert res["is_after_hours"].iloc[0] == 1
    assert res["is_after_hours"].iloc[1] == 0
    assert res["hour"].iloc[0] == 2
    assert res["hour"].iloc[1] == 14

def test_user_features():
    df = pd.DataFrame([
        {"user_id": "U101", "event_type": "LOGIN", "status": "FAIL", "timestamp": "2026-09-10 10:00:00"},
        {"user_id": "U101", "event_type": "LOGIN", "status": "FAIL", "timestamp": "2026-09-10 10:01:00"},
        {"user_id": "U101", "event_type": "LOGIN", "status": "FAIL", "timestamp": "2026-09-10 10:02:00"}
    ])
    res = extract_user_features(df)
    assert res["failed_logins_last_5m"].max() == 3

def test_network_features():
    user_baselines = {
        "U101": {"ips": ["10.0.1.15"], "devices": ["DEV_101"]}
    }
    df = pd.DataFrame([
        {"user_id": "U101", "source_ip": "10.0.1.15", "device_id": "DEV_101"},
        {"user_id": "U101", "source_ip": "185.220.101.4", "device_id": "DEV_UNKNOWN"}
    ])
    res = extract_network_features(df, user_baselines)
    assert res["is_new_ip"].iloc[0] == 0
    assert res["is_new_ip"].iloc[1] == 1
    assert res["is_new_device"].iloc[1] == 1
