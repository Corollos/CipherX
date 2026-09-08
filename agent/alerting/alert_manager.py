from datetime import datetime, timezone
import uuid


class AlertManager:
    def __init__(self):
        self.alerts = []

    def create_alert(
        self,
        title,
        severity,
        description,
        risk_score=None,
        detections=None,
        related_events=None,
    ):
        alert = {
            "event_type": "security_alert",
            "alert_id": f"CX-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "title": title,
            "severity": severity,
            "description": description,
            "risk_score": risk_score,
            "status": "open",
            "detections": detections or [],
            "related_events": related_events or [],
        }

        self.alerts.append(alert)

        return alert

    def get_alerts(self):
        return list(self.alerts)

    def get_open_alerts(self):
        return [
            alert
            for alert in self.alerts
            if alert["status"] == "open"
        ]

    def update_alert_status(
        self,
        alert_id,
        status,
    ):
        valid_statuses = {
            "open",
            "investigating",
            "resolved",
        }

        if status not in valid_statuses:
            raise ValueError(
                f"Invalid alert status: {status}"
            )

        for alert in self.alerts:
            if alert["alert_id"] == alert_id:
                alert["status"] = status
                return alert

        return None