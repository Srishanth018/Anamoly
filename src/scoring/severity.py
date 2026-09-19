class SeverityClassifier:
    """Categorizes 0-100 risk score into LOW, MEDIUM, HIGH, CRITICAL levels."""

    @staticmethod
    def get_severity(score: float) -> str:
        if score >= 76.0:
            return "CRITICAL"
        elif score >= 51.0:
            return "HIGH"
        elif score >= 26.0:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def get_severity_color(severity: str) -> str:
        colors = {
            "CRITICAL": "#FF2B2B",
            "HIGH": "#FF7A00",
            "MEDIUM": "#FFA800",
            "LOW": "#00CC66"
        }
        return colors.get(severity.upper(), "#888888")
