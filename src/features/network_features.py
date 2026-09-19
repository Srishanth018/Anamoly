import pandas as pd
import re

def extract_network_features(df: pd.DataFrame, user_baselines: dict = None) -> pd.DataFrame:
    """Extracts network features such as connection count, destination ports, and alien IP flags."""
    res_df = df.copy()

    for c in ["event_type", "action", "resource", "session_id"]:
        if c not in res_df.columns:
            res_df[c] = "-"

    # Network connection indicators
    res_df["is_network_connection"] = (
        res_df["event_type"].isin(["NETWORK"]) | 
        res_df["action"].isin(["CONNECTION", "PORT_ACCESS", "REMOTE_LOGIN"])
    ).astype(int)

    # Rolling connection count per session
    res_df["connection_count"] = res_df.groupby("session_id")["is_network_connection"].transform("cumsum")

    # Extract destination ports from resource field if formatted as IP:PORT
    def extract_port(res):
        res_str = str(res)
        match = re.search(r":(\d+)", res_str)
        return match.group(1) if match else "0"

    res_df["dest_port"] = res_df["resource"].apply(extract_port)
    res_df["unique_destination_ports"] = res_df.groupby("session_id")["dest_port"].transform(lambda x: len(set(x)))

    if user_baselines:
        def check_new_ip(row):
            uid = row["user_id"]
            ip = row["source_ip"]
            if uid in user_baselines:
                normal_ips = user_baselines[uid].get("ips", [])
                return 0 if ip in normal_ips else 1
            return 0

        def check_new_device(row):
            uid = row["user_id"]
            dev = row["device_id"]
            if uid in user_baselines:
                normal_devs = user_baselines[uid].get("devices", [])
                return 0 if dev in normal_devs else 1
            return 0

        res_df["is_new_ip"] = res_df.apply(check_new_ip, axis=1)
        res_df["new_ip_flag"] = res_df["is_new_ip"]
        res_df["is_new_device"] = res_df.apply(check_new_device, axis=1)
    else:
        res_df["is_new_ip"] = 0
        res_df["new_ip_flag"] = 0
        res_df["is_new_device"] = 0

    return res_df
