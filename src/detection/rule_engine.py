import pandas as pd
from typing import List, Dict, Tuple

class RuleEngine:
    """Evaluates deterministic cybersecurity rule violations for event streams."""

    def __init__(self, config: dict = None):
        self.cfg = config.get("detection", {}).get("rule_engine", {}) if config else {}
        self.failed_login_threshold = self.cfg.get("failed_login_threshold", 5)
        self.after_hours_start = self.cfg.get("after_hours_start", 22)
        self.after_hours_end = self.cfg.get("after_hours_end", 6)
        self.large_download_mb = self.cfg.get("large_download_mb", 100)

    def evaluate_rules(self, row, user_baselines: dict, peer_baselines: dict = None) -> Tuple[List[str], float]:
        reasons = []
        rule_score = 0.0

        uid = row.get("user_id")
        event_type = str(row.get("event_type", ""))
        action = str(row.get("action", ""))
        hour = int(row.get("hour", 12))
        ip = str(row.get("source_ip", ""))
        device = str(row.get("device_id", ""))
        bytes_tx = float(row.get("bytes_transferred", 0))
        resource = str(row.get("resource", ""))
        failed_5m = int(row.get("failed_logins_last_5m", 0))

        # 1. Off-hours login/activity
        if hour >= self.after_hours_start or hour < self.after_hours_end:
            reasons.append("Off-hours activity (outside 06:00-22:00 window)")
            rule_score += 12.0

        # 2. Failed login burst / Brute force
        if failed_5m >= self.failed_login_threshold:
            reasons.append(f"Brute force / Failed login burst ({failed_5m} failures in 5 min)")
            rule_score += 20.0

        # 3. Unseen / Alien IP
        if uid in user_baselines:
            normal_ips = user_baselines[uid].get("ips", [])
            if normal_ips and ip not in normal_ips:
                reasons.append(f"Unseen IP address ({ip})")
                rule_score += 15.0

        # 4. Unseen / Alien Device
        if uid in user_baselines:
            normal_devs = user_baselines[uid].get("devices", [])
            if normal_devs and device not in normal_devs:
                reasons.append(f"Unseen device ID ({device})")
                rule_score += 12.0

        # 5. Unusual / Alien Location (Country)
        country = str(row.get("country", "USA"))
        if country in ["Russia", "North Korea", "Romania", "China"]:
            reasons.append(f"High-risk geographic location ({country})")
            rule_score += 15.0

        # 6. Sensitive Resource Access
        if any(keyword in resource.lower() for keyword in ["payroll", "confidential", "board_deck", "syslogs", "sudoers", "master_database"]):
            reasons.append(f"Sensitive resource access ({resource})")
            rule_score += 18.0

        # 7. Large Data Exfiltration / Download
        mb_tx = bytes_tx / 1e6
        if mb_tx >= self.large_download_mb:
            reasons.append(f"Large data exfiltration ({mb_tx:.1f} MB transfer)")
            rule_score += 22.0

        # 8. Privilege Escalation / Sudo Abuse
        if action == "PRIVILEGE_ESCALATION" or "admin" in resource.lower():
            reasons.append("Privilege escalation attempt")
            rule_score += 25.0

        # 9. USB Removable Media Connect
        if action == "USB_CONNECT" or event_type == "DEVICE":
            reasons.append("Removable media (USB) connection")
            rule_score += 15.0

        # 10. Mass File Deletion
        if action == "FILE_DELETE":
            reasons.append("File deletion activity")
            rule_score += 18.0

        return reasons, min(100.0, rule_score)
