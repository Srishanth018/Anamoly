import pandas as pd

def extract_temporal_features(df: pd.DataFrame, after_hours_start=22, after_hours_end=6) -> pd.DataFrame:
    """Extracts temporal features from event timestamps."""
    res_df = df.copy()
    ts = pd.to_datetime(res_df["timestamp"])

    res_df["hour"] = ts.dt.hour
    res_df["day_of_week"] = ts.dt.dayofweek
    res_df["is_weekend"] = res_df["day_of_week"].apply(lambda d: 1 if d >= 5 else 0)
    
    res_df["is_after_hours"] = res_df["hour"].apply(
        lambda h: 1 if (h >= after_hours_start or h < after_hours_end) else 0
    )
    return res_df
