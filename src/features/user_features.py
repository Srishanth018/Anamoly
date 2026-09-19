import pandas as pd
import numpy as np

def extract_user_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extracts user-level aggregated activity metrics as defined in Section 6."""
    res_df = df.copy()

    res_df["ts_dt"] = pd.to_datetime(res_df["timestamp"])
    res_df = res_df.sort_values(by=["user_id", "ts_dt"]).reset_index(drop=True)

    for c in ["source_ip", "device_id", "resource", "event_type", "status", "action"]:
        if c not in res_df.columns:
            res_df[c] = "-"

    # Login indicators
    res_df["is_login_failure"] = (
        (res_df["event_type"].isin(["LOGIN", "AUTHENTICATION"])) & 
        (res_df["status"] == "FAIL")
    ).astype(int)

    res_df["is_login_success"] = (
        (res_df["event_type"].isin(["LOGIN", "AUTHENTICATION"])) & 
        (res_df["status"] == "SUCCESS")
    ).astype(int)

    # Rolling failed logins per user in last 5 minutes
    res_df["failed_logins_last_5m"] = 0
    res_df["failed_login_count"] = 0
    res_df["successful_login_count"] = 0
    res_df["failure_rate"] = 0.0
    res_df["time_since_last_login"] = 0.0
    res_df["unique_ips"] = 1
    res_df["unique_devices"] = 1
    res_df["unique_resources"] = 1

    for uid, group in res_df.groupby("user_id"):
        # Rolling 5m failures
        indexer_5m = group.set_index("ts_dt")["is_login_failure"].rolling("5min").sum()
        res_df.loc[group.index, "failed_logins_last_5m"] = indexer_5m.values

        # Cumulative totals
        cum_fails = group["is_login_failure"].cumsum()
        cum_success = group["is_login_success"].cumsum()
        total_auths = cum_fails + cum_success
        
        res_df.loc[group.index, "failed_login_count"] = cum_fails
        res_df.loc[group.index, "successful_login_count"] = cum_success
        res_df.loc[group.index, "failure_rate"] = (cum_fails / (total_auths + 1e-5)).round(3)

        # Time since last login
        login_events = group[group["event_type"].isin(["LOGIN", "AUTHENTICATION"])]
        if not login_events.empty:
            diffs = group["ts_dt"].diff().dt.total_seconds().fillna(0)
            res_df.loc[group.index, "time_since_last_login"] = diffs

        # Cumulative unique counts
        ips = group["source_ip"].tolist()
        devs = group["device_id"].tolist()
        res = group["resource"].tolist()
        
        seen_ips, seen_devs, seen_res = set(), set(), set()
        u_ips, u_devs, u_res = [], [], []
        
        for i_ip, i_dev, i_r in zip(ips, devs, res):
            seen_ips.add(i_ip)
            seen_devs.add(i_dev)
            seen_res.add(i_r)
            u_ips.append(len(seen_ips))
            u_devs.append(len(seen_devs))
            u_res.append(len(seen_res))

        res_df.loc[group.index, "unique_ips"] = u_ips
        res_df.loc[group.index, "unique_devices"] = u_devs
        res_df.loc[group.index, "unique_resources"] = u_res

    return res_df
