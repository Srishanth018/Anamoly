import pandas as pd
import numpy as np

class PeerGroupBaselineBuilder:
    """Computes department/peer group activity baselines."""

    @staticmethod
    def build_peer_baselines(user_baselines: dict) -> dict:
        dept_data = {}
        for uid, b in user_baselines.items():
            dept = b.get("dept", "General")
            if dept not in dept_data:
                dept_data[dept] = {
                    "avg_bytes": [],
                    "resources": set(),
                    "users": []
                }
            dept_data[dept]["avg_bytes"].append(b.get("avg_bytes", 5e6))
            dept_data[dept]["resources"].update(b.get("resources", []))
            dept_data[dept]["users"].append(uid)

        peer_baselines = {}
        for dept, data in dept_data.items():
            peer_baselines[dept] = {
                "department": dept,
                "avg_bytes": float(np.mean(data["avg_bytes"])) if data["avg_bytes"] else 5e6,
                "allowed_resources": list(data["resources"]),
                "user_count": len(data["users"])
            }
        return peer_baselines

    @staticmethod
    def is_peer_anomaly(row, user_baselines: dict, peer_baselines: dict) -> float:
        uid = row["user_id"]
        res = row["resource"]
        if res == "-" or res == "N/A":
            return 0.0

        if uid in user_baselines:
            dept = user_baselines[uid].get("dept", "General")
            if dept in peer_baselines:
                peer_res = peer_baselines[dept]["allowed_resources"]
                user_res = user_baselines[uid].get("resources", [])
                
                # Anomaly if resource is neither in user's baseline nor in department baseline
                if not any(r in res for r in user_res) and not any(r in res for r in peer_res):
                    return 1.0
        return 0.0
