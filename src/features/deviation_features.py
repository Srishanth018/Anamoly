import pandas as pd
import numpy as np

def extract_deviation_features(df: pd.DataFrame, user_baselines: dict) -> pd.DataFrame:
    """Calculates z-scores and behavioral deviation metrics as defined in Section 6."""
    res_df = df.copy()

    def calc_download_zscore(row):
        uid = row["user_id"]
        bytes_tx = row["bytes_transferred"]
        if uid in user_baselines:
            mean_b = user_baselines[uid].get("avg_bytes", 5_000_000)
            std_b = max(mean_b * 0.4, 1_000_000)
            z = (bytes_tx - mean_b) / std_b
            return max(0.0, float(z))
        return 0.0

    def calc_hour_deviation(row):
        uid = row["user_id"]
        h = row["hour"]
        if uid in user_baselines:
            sh = user_baselines[uid].get("start_hour", 9)
            eh = user_baselines[uid].get("end_hour", 18)
            if h < sh:
                return float(sh - h)
            elif h > eh:
                return float(h - eh)
        return 0.0

    def calc_resource_unusualness(row):
        uid = row["user_id"]
        res = row["resource"]
        if res == "-" or res == "N/A":
            return 0.0
        if uid in user_baselines:
            normal_res = user_baselines[uid].get("resources", [])
            return 0.0 if any(r in res for r in normal_res) else 1.0
        return 0.0

    def calc_duration_deviation(row):
        uid = row["user_id"]
        dur = row["duration"]
        if uid in user_baselines:
            mean_dur = 15.0 # Average normal event duration
            std_dur = 10.0
            return max(0.0, float((dur - mean_dur) / std_dur))
        return 0.0

    res_df["download_zscore"] = res_df.apply(calc_download_zscore, axis=1)
    res_df["download_deviation"] = res_df["download_zscore"]
    
    res_df["hour_deviation"] = res_df.apply(calc_hour_deviation, axis=1)
    res_df["login_hour_deviation"] = res_df["hour_deviation"]

    res_df["resource_unusualness"] = res_df.apply(calc_resource_unusualness, axis=1)
    res_df["resource_frequency_deviation"] = res_df["resource_unusualness"]

    res_df["session_duration_deviation"] = res_df.apply(calc_duration_deviation, axis=1)

    return res_df
