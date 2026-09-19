import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class MLAnomalyDetector:
    """Wrapper for Isolation Forest machine learning anomaly detection model."""

    FEATURE_COLS = [
        "hour", "is_weekend", "is_after_hours", "failed_logins_last_5m",
        "failed_login_count", "successful_login_count", "failure_rate",
        "time_since_last_login", "unique_ips", "unique_devices", "unique_resources",
        "connection_count", "unique_destination_ports", "is_new_ip", "is_new_device",
        "download_count", "upload_count", "bytes_transferred", "average_transfer_size",
        "duration", "download_zscore", "hour_deviation", "resource_unusualness",
        "session_duration_deviation"
    ]

    def __init__(self, contamination=0.05, n_estimators=100, random_state=42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        X_df = df.copy()
        for col in self.FEATURE_COLS:
            if col not in X_df.columns:
                X_df[col] = 0
        return X_df[self.FEATURE_COLS].fillna(0).values

    def fit(self, df: pd.DataFrame):
        X = self.prepare_features(df)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

    def predict_anomaly_scores(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Returns raw decision function scores and calibrated 0-100 anomaly scores."""
        if not self.is_fitted:
            raise RuntimeError("ML Anomaly Detector is not fitted yet.")

        X = self.prepare_features(df)
        X_scaled = self.scaler.transform(X)

        # decision_function gives negative values for anomalies, positive for inliers
        raw_scores = self.model.decision_function(X_scaled)

        # Map decision function to 0-100 scale (0 = normal, 100 = highly anomalous)
        # Raw scores typically range from -0.3 to +0.3
        ml_scores = np.clip(50.0 - (raw_scores * 150.0), 0.0, 100.0)
        
        predictions = self.model.predict(X_scaled) # -1 for anomaly, 1 for normal
        return predictions, np.round(ml_scores, 2)

    def save(self, model_dir="models/"):
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(self.model, os.path.join(model_dir, "isolation_forest.pkl"))
        joblib.dump(self.scaler, os.path.join(model_dir, "scaler.pkl"))

    def load(self, model_dir="models/"):
        model_path = os.path.join(model_dir, "isolation_forest.pkl")
        scaler_path = os.path.join(model_dir, "scaler.pkl")
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.is_fitted = True
            return True
        return False
