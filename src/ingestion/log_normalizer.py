import pandas as pd
import numpy as np

class LogNormalizer:
    """Normalizes arbitrary telemetry data into standard schema."""

    REQUIRED_COLUMNS = [
        "event_id", "timestamp", "user_id", "source_ip", "country",
        "device_id", "event_type", "resource", "action", "status",
        "session_id", "bytes_transferred", "duration"
    ]

    @classmethod
    def normalize(cls, df: pd.DataFrame) -> pd.DataFrame:
        norm_df = df.copy()

        # Rename common aliases if present across public datasets (CERT, LANL, EVTX, Sysmon, Okta)
        col_mappings = {
            "id": "event_id",
            "time": "timestamp",
            "date": "timestamp",
            "datetime": "timestamp",
            "user": "user_id",
            "username": "user_id",
            "user_name": "user_id",
            "src_user": "user_id",
            "ip": "source_ip",
            "ip_address": "source_ip",
            "src_ip": "source_ip",
            "source_ip_address": "source_ip",
            "device": "device_id",
            "pc": "device_id",
            "hostname": "device_id",
            "type": "event_type",
            "log_type": "event_type",
            "activity": "action",
            "event_action": "action",
            "file": "resource",
            "filename": "resource",
            "url": "resource",
            "path": "resource",
            "bytes": "bytes_transferred",
            "size": "bytes_transferred",
            "file_size": "bytes_transferred",
            "session": "session_id"
        }
        norm_df = norm_df.rename(columns=col_mappings)

        # Fill missing required columns with default fallbacks
        for col in cls.REQUIRED_COLUMNS:
            if col not in norm_df.columns:
                if col == "country":
                    norm_df[col] = "USA"
                elif col == "source_ip":
                    norm_df[col] = "10.0.0.1"
                elif col == "device_id":
                    norm_df[col] = "DEV_LOCAL"
                elif col in ["bytes_transferred", "duration"]:
                    norm_df[col] = 0
                elif col == "resource":
                    norm_df[col] = "-"
                elif col == "status":
                    norm_df[col] = "SUCCESS"
                else:
                    norm_df[col] = "N/A"

        # Fill NaNs for text and numeric fields
        norm_df["source_ip"] = norm_df["source_ip"].fillna("10.0.0.1").astype(str)
        norm_df["device_id"] = norm_df["device_id"].fillna("DEV_LOCAL").astype(str)
        norm_df["country"] = norm_df["country"].fillna("USA").astype(str)
        norm_df["user_id"] = norm_df["user_id"].fillna("USER_UNKNOWN").astype(str)
        norm_df["event_type"] = norm_df["event_type"].fillna("AUTHENTICATION").astype(str)
        norm_df["action"] = norm_df["action"].fillna("LOGIN_SUCCESS").astype(str)
        norm_df["status"] = norm_df["status"].fillna("SUCCESS").astype(str)
        norm_df["resource"] = norm_df["resource"].fillna("-").astype(str)
        norm_df["session_id"] = norm_df["session_id"].fillna("S_DEFAULT").astype(str)

        # Type cleaning
        norm_df["timestamp"] = pd.to_datetime(norm_df["timestamp"], format="mixed", errors="coerce").fillna(pd.Timestamp("2026-09-10 10:00:00"))
        norm_df["bytes_transferred"] = pd.to_numeric(norm_df["bytes_transferred"], errors="coerce").fillna(0).astype(int)
        norm_df["duration"] = pd.to_numeric(norm_df["duration"], errors="coerce").fillna(0).astype(int)

        # Ensure correct column ordering
        return norm_df[cls.REQUIRED_COLUMNS].sort_values(by="timestamp").reset_index(drop=True)
