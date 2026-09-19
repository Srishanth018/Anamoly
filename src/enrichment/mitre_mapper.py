from typing import List, Dict

class MITREMapper:
    """Maps security alert reasons and event actions to MITRE ATT&CK techniques."""

    MITRE_CATALOG = {
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Initial Access / Persistence",
            "description": "Adversaries may obtain and use credentials of existing accounts to log in off-hours or from unseen locations.",
            "mitigation": "Enforce Multi-Factor Authentication (MFA) and conditional access policies for unknown IPs/devices."
        },
        "T1110": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Adversaries may use brute force techniques to attempt access when credentials are unknown.",
            "mitigation": "Implement account lockout thresholds and IP rate limiting on authentication portals."
        },
        "T1068": {
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "description": "Adversaries may abuse elevated privileges or configuration flaws to gain admin control.",
            "mitigation": "Audit privileged accounts, implement Least Privilege Access (PAM), and restrict sudo commands."
        },
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "description": "Adversaries may steal sensitive data by downloading unusually large volumes over web/FTP protocols.",
            "mitigation": "Deploy Data Loss Prevention (DLP) controls and monitor outbound transfer volume spikes."
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "description": "Adversaries may enumerate sensitive directories, payroll spreadsheets, or executive strategy documents.",
            "mitigation": "Restrict directory permissions with strict Role-Based Access Control (RBAC)."
        },
        "T1091": {
            "name": "Replication Through Removable Media",
            "tactic": "Initial Access / Exfiltration",
            "description": "Adversaries may copy sensitive files directly to connected USB flash drives or external storage.",
            "mitigation": "Enforce endpoint USB device control policies to block unauthorized mass storage devices."
        },
        "T1485": {
            "name": "Data Destruction",
            "tactic": "Impact",
            "description": "Adversaries may delete files or system backups to interrupt business operations.",
            "mitigation": "Maintain immutable off-site backups and mandate multi-party authorization for batch file deletion."
        },
        "T1071": {
            "name": "Application Layer Protocol / Remote Access",
            "tactic": "Command and Control / Lateral Movement",
            "description": "Adversaries may conduct unauthorized remote logins or access unusual database ports.",
            "mitigation": "Restrict database listener ports to authorized management jump boxes via internal firewalls."
        }
    }

    @classmethod
    def map_reasons_to_mitre(cls, reasons: list) -> List[Dict]:
        reasons_text = " ".join(reasons).lower()
        matched_techniques = []

        if any(w in reasons_text for w in ["off-hours", "unseen ip", "unseen device", "geographic location", "login"]):
            matched_techniques.append({"id": "T1078", **cls.MITRE_CATALOG["T1078"]})

        if "brute force" in reasons_text or "failed login" in reasons_text:
            matched_techniques.append({"id": "T1110", **cls.MITRE_CATALOG["T1110"]})

        if "privilege escalation" in reasons_text or "sudoers" in reasons_text:
            matched_techniques.append({"id": "T1068", **cls.MITRE_CATALOG["T1068"]})

        if any(w in reasons_text for w in ["exfiltration", "large data", "z-score", "download"]):
            matched_techniques.append({"id": "T1048", **cls.MITRE_CATALOG["T1048"]})

        if any(w in reasons_text for w in ["resource", "sensitive", "payroll", "board_deck"]):
            matched_techniques.append({"id": "T1083", **cls.MITRE_CATALOG["T1083"]})

        if "removable media" in reasons_text or "usb" in reasons_text:
            matched_techniques.append({"id": "T1091", **cls.MITRE_CATALOG["T1091"]})

        if "deletion" in reasons_text:
            matched_techniques.append({"id": "T1485", **cls.MITRE_CATALOG["T1485"]})

        if any(w in reasons_text for w in ["port access", "remote login", "port scan"]):
            matched_techniques.append({"id": "T1071", **cls.MITRE_CATALOG["T1071"]})

        # Deduplicate matched techniques by ID
        unique_matches = []
        seen_ids = set()
        for tech in matched_techniques:
            if tech["id"] not in seen_ids:
                seen_ids.add(tech["id"])
                unique_matches.append(tech)

        return unique_matches
