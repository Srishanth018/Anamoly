import pandas as pd
import numpy as np
import json

class UserBaselineBuilder:
    """Learns individual user baselines from normal telemetry logs."""

    @staticmethod
    def build_baselines(events_df: pd.DataFrame, users_df: pd.DataFrame = None) -> dict:
        df = events_df.copy()
        df["ts"] = pd.to_datetime(df["timestamp"])
        df["date"] = df["ts"].dt.date
        df["hour"] = df["ts"].dt.hour

        user_dept_map = {}
        if users_df is not None:
            user_dept_map = dict(zip(users_df["user_id"], users_df["department"]))

        baselines = {}
        for uid, group in df.groupby("user_id"):
            dept = user_dept_map.get(uid, "General")
            
            # Normal IP list (IPs appearing in > 10% of user events)
            ip_counts = group["source_ip"].value_counts(normalize=True)
            frequent_ips = ip_counts[ip_counts > 0.10].index.tolist()
            if not frequent_ips and len(ip_counts) > 0:
                frequent_ips = [ip_counts.index[0]]

            # Normal Device list
            dev_counts = group["device_id"].value_counts(normalize=True)
            frequent_devs = dev_counts[dev_counts > 0.10].index.tolist()

            # Normal Working Hours (min & max hour window)
            hours = group["hour"].tolist()
            start_h = int(np.percentile(hours, 5)) if len(hours) > 5 else 9
            end_h = int(np.percentile(hours, 95)) if len(hours) > 5 else 18

            # Daily Bytes Transferred statistics
            daily_bytes = group.groupby("date")["bytes_transferred"].sum()
            avg_bytes = float(daily_bytes.mean()) if len(daily_bytes) > 0 else 5_000_000.0
            std_bytes = float(daily_bytes.std()) if len(daily_bytes) > 1 else max(avg_bytes * 0.4, 1_000_000.0)

            # Normal Resources
            resources = group["resource"].value_counts().head(10).index.tolist()
            resources = [r for r in resources if r != "-"]

            baselines[uid] = {
                "user_id": uid,
                "dept": dept,
                "ips": frequent_ips,
                "devices": frequent_devs,
                "start_hour": max(6, min(start_h, 10)),
                "end_hour": min(22, max(end_h, 17)),
                "avg_bytes": max(avg_bytes, 1_000_000.0),
                "std_bytes": max(std_bytes, 1_000_000.0),
                "resources": resources,
                "avg_daily_events": float(len(group) / max(1, len(group["date"].unique())))
            }

        return baselines

    @staticmethod
    def to_dataframe(baselines: dict) -> pd.DataFrame:
        records = []
        for uid, b in baselines.items():
            records.append({
                "user_id": uid,
                "department": b.get("dept", "General"),
                "avg_daily_events": b.get("avg_daily_events", 20.0),
                "normal_start_hour": b.get("start_hour", 9),
                "normal_end_hour": b.get("end_hour", 18),
                "frequent_ips": ",".join(b.get("ips", [])),
                "frequent_devices": ",".join(b.get("devices", [])),
                "avg_daily_download_mb": round(b.get("avg_bytes", 0) / 1e6, 2),
                "std_daily_download_mb": round(b.get("std_bytes", 0) / 1e6, 2),
                "normal_resources_json": json.dumps(b.get("resources", []))
            })
        return pd.DataFrame(records)
