import pandas as pd
import numpy as np

class DriftDetector:
    """Detects gradual behavioral drift by comparing rolling 7-day vs 30-day baseline metrics."""

    @staticmethod
    def calculate_drift_scores(df: pd.DataFrame) -> pd.DataFrame:
        res_df = df.copy()
        res_df["ts"] = pd.to_datetime(res_df["timestamp"])
        
        # Sort by timestamp
        res_df = res_df.sort_values(by=["user_id", "ts"]).reset_index(drop=True)

        res_df["drift_score"] = 0.0

        for uid, group in res_df.groupby("user_id"):
            if len(group) < 10:
                continue

            # Rolling 7-day total bytes vs 30-day historical mean
            group_idx = group.index
            indexer = group.set_index("ts")["bytes_transferred"]
            
            rolling_7d = indexer.rolling("7D").sum()
            rolling_30d = indexer.rolling("30D").sum() / 4.0 # Normalize 30-day to 7-day scale

            drift_ratio = (rolling_7d / (rolling_30d + 1e-5)).fillna(1.0)
            
            # Values > 3.0 ratio indicate significant upward drift in volume/activity
            drift_metric = drift_ratio.apply(lambda r: min(100.0, max(0.0, (r - 1.0) * 20.0)))
            res_df.loc[group_idx, "drift_score"] = drift_metric.values

        return res_df
