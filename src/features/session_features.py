import pandas as pd
import numpy as np

def extract_session_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extracts data movement and session activity metrics as defined in Section 6."""
    res_df = df.copy()

    # Data movement indicators
    res_df["is_download"] = (res_df["action"] == "FILE_DOWNLOAD").astype(int)
    res_df["is_upload"] = (res_df["action"] == "FILE_WRITE").astype(int)

    # Session aggregations
    res_df["download_count"] = res_df.groupby("session_id")["is_download"].transform("sum")
    res_df["upload_count"] = res_df.groupby("session_id")["is_upload"].transform("sum")
    
    session_totals = res_df.groupby("session_id")["bytes_transferred"].transform("sum")
    session_counts = res_df.groupby("session_id")["event_id"].transform("count")
    session_durations = res_df.groupby("session_id")["duration"].transform("mean")

    res_df["total_bytes"] = session_totals
    res_df["session_total_bytes"] = session_totals
    res_df["session_event_count"] = session_counts
    res_df["average_transfer_size"] = (session_totals / (session_counts + 1e-5)).round(2)
    res_df["average_session_duration"] = session_durations.round(2)

    return res_df
