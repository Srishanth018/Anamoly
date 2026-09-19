import pandas as pd
import numpy as np
from typing import Dict, List, Tuple

class ExplainableRiskEngine:
    """Combines rule, statistical, ML, sequence, peer, and drift signals into an explainable 0-100 risk score."""

    def __init__(self, config: dict = None):
        self.config = config or {}

    def calculate_event_risk(
        self,
        rule_reasons: list,
        rule_score: float,
        stat_reasons: list,
        stat_score: float,
        ml_score: float,
        seq_reasons: list,
        seq_score: float,
        peer_anomaly: float,
        drift_score: float
    ) -> Tuple[float, List[str], Dict[str, float]]:

        factor_breakdown = {}
        all_reasons = list(set(rule_reasons + stat_reasons + seq_reasons))

        # Base contribution calculation
        if rule_score > 0:
            factor_breakdown["Rules Engine"] = round(rule_score * 0.35, 1)

        if stat_score > 0:
            factor_breakdown["Statistical Deviation"] = round(stat_score * 0.30, 1)

        if ml_score > 55.0:
            ml_contrib = round((ml_score - 50.0) * 0.45, 1)
            factor_breakdown["ML Isolation Forest"] = ml_contrib
            all_reasons.append(f"ML Isolation Forest flagged event as statistical anomaly (Score: {ml_score:.1f})")

        if seq_score > 0:
            factor_breakdown["Attack Sequence Pattern"] = round(seq_score * 0.35, 1)

        if peer_anomaly > 0:
            factor_breakdown["Peer Group Anomaly"] = 15.0
            all_reasons.append("Resource access deviates from departmental peer group baseline")

        if drift_score > 30.0:
            drift_contrib = round(drift_score * 0.20, 1)
            factor_breakdown["Behavioral Drift"] = drift_contrib
            all_reasons.append(f"Significant activity volume drift detected (+{drift_score:.0f}% rolling escalation)")

        # Weighted total calculation capped at 100
        raw_total = sum(factor_breakdown.values())
        
        # Boost score if multiple distinct engines triggered concurrently
        active_engines = len(factor_breakdown)
        synergy_multiplier = 1.0 + (0.10 * max(0, active_engines - 1))
        
        final_risk_score = min(100.0, raw_total * synergy_multiplier)

        return round(final_risk_score, 1), all_reasons, factor_breakdown
