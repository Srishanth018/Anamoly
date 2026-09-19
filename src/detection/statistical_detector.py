import pandas as pd
import numpy as np
from typing import Tuple, List, Dict

class StatisticalDetector:
    """Calculates personalized statistical z-score and quantile deviation anomaly scores."""

    @staticmethod
    def evaluate_statistical_anomalies(row, user_baselines: dict) -> Tuple[list, float]:
        reasons = []
        stat_score = 0.0

        uid = row.get("user_id")
        bytes_tx = float(row.get("bytes_transferred", 0))
        hour_dev = float(row.get("hour_deviation", 0.0))
        res_unusual = float(row.get("resource_unusualness", 0.0))

        if uid in user_baselines:
            b = user_baselines[uid]
            mean_b = b.get("avg_bytes", 5_000_000.0)
            std_b = b.get("std_bytes", 2_000_000.0)

            # 1. Transfer size Z-Score
            z_score = (bytes_tx - mean_b) / max(std_b, 1_000_000.0)
            if z_score >= 3.0:
                reasons.append(f"Data volume {z_score:.1f}x standard deviations above user baseline")
                stat_score += min(40.0, z_score * 8.0)

            # 2. Hours deviation
            if hour_dev >= 3.0:
                reasons.append(f"Activity {int(hour_dev)} hours outside user's standard working window")
                stat_score += min(25.0, hour_dev * 5.0)

            # 3. Resource rarity
            if res_unusual > 0.5:
                reasons.append("Accessed resource outside individual normal baseline profile")
                stat_score += 20.0

        return reasons, min(100.0, stat_score)
