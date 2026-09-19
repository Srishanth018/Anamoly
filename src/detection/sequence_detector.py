import pandas as pd
from typing import List, Tuple

class SequenceDetector:
    """Detects multi-event attack sequence chains across session telemetry."""

    HIGH_RISK_SEQUENCES = [
        (["LOGIN_FAILURE", "LOGIN_SUCCESS", "PRIVILEGE_ESCALATION"], "Credential Stuffing -> Successful Auth -> Privilege Escalation Chain"),
        (["LOGIN_SUCCESS", "PRIVILEGE_ESCALATION", "FILE_DOWNLOAD"], "Auth -> Admin Escalation -> Bulk Exfiltration Chain"),
        (["LOGIN_FAILURE", "LOGIN_SUCCESS", "FILE_DOWNLOAD"], "Failed Auth Burst -> Success -> Bulk File Exfiltration Chain"),
        (["USB_CONNECT", "FILE_READ", "FILE_DELETE"], "Removable Media Connect -> Sensitive File Access -> Destruction Chain"),
        (["PORT_ACCESS", "REMOTE_LOGIN", "FILE_DOWNLOAD"], "Port Scan -> Remote Lateral Login -> Exfiltration Chain")
    ]

    @classmethod
    def evaluate_session_sequence(cls, session_events_df: pd.DataFrame) -> Tuple[List[str], float]:
        reasons = []
        seq_score = 0.0

        actions = session_events_df["action"].tolist()
        event_types = session_events_df["event_type"].tolist()

        combined_chain = actions + event_types

        for pattern, description in cls.HIGH_RISK_SEQUENCES:
            # Check sub-sequence match
            pattern_idx = 0
            for item in combined_chain:
                if item == pattern[pattern_idx]:
                    pattern_idx += 1
                    if pattern_idx == len(pattern):
                        reasons.append(f"Attack Sequence Match: {description}")
                        seq_score += 25.0
                        break

        return reasons, min(100.0, seq_score)
