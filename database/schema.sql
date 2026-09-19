-- Schema for Behavioral Security Log Anomaly Detection Platform

DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS baselines;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_type TEXT NOT NULL,
    os_info TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    user_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    country TEXT NOT NULL,
    device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    resource TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    session_id TEXT NOT NULL,
    bytes_transferred INTEGER DEFAULT 0,
    duration INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    event_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    max_risk_score REAL DEFAULT 0,
    severity TEXT DEFAULT 'LOW',
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE baselines (
    user_id TEXT PRIMARY KEY,
    department TEXT NOT NULL,
    avg_daily_events REAL DEFAULT 0,
    normal_start_hour INTEGER DEFAULT 9,
    normal_end_hour INTEGER DEFAULT 18,
    frequent_ips TEXT, -- Comma-separated or JSON
    frequent_devices TEXT, -- Comma-separated or JSON
    avg_daily_download_mb REAL DEFAULT 0,
    std_daily_download_mb REAL DEFAULT 1,
    normal_resources_json TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    event_id TEXT,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    source_ip TEXT,
    risk_score REAL NOT NULL,
    severity TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    mitre_techniques_json TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    status TEXT DEFAULT 'OPEN',
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

-- Indices for performance
CREATE INDEX idx_events_user_time ON events(user_id, timestamp);
CREATE INDEX idx_events_session ON events(session_id);
CREATE INDEX idx_alerts_user ON alerts(user_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
