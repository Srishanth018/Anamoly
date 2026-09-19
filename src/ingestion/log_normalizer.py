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

        # Rename common aliases if present
        col_mappings = {
            "id": "event_id",
            "time": "timestamp",
            "datetime": "timestamp",
            "user": "user_id",
            "username": "user_id",
            "ip": "source_ip",
            "ip_address": "source_ip",
            "device": "device_id",
            "type": "event_type",
            "bytes": "bytes_transferred",
            "size": "bytes_transferred"
        }
        norm_df = norm_df.rename(columns=col_mappings)

        # Fill missing required columns with default fallbacks
        for col in cls.REQUIRED_COLUMNS:
            if col not in norm_df.columns:
                if col == "country":
                    norm_df[col] = "Unknown"
                elif col in ["bytes_transferred", "duration"]:
                    norm_df[col] = 0
                elif col == "resource":
                    norm_df[col] = "-"
                elif col == "status":
                    norm_df[col] = "SUCCESS"
                else:
                    norm_df[col] = "N/A"

        # Type cleaning
        norm_df["timestamp"] = pd.to_datetime(norm_df["timestamp"])
        norm_df["bytes_transferred"] = pd.to_numeric(norm_df["bytes_transferred"], errors="coerce").fillna(0).astype(int)
        norm_df["duration"] = pd.to_numeric(norm_df["duration"], errors="coerce").fillna(0).astype(int)

        # Ensure correct column ordering
        return norm_df[cls.REQUIRED_COLUMNS].sort_values(by="timestamp").reset_index(drop=True)
