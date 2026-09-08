import uuid
from datetime import datetime, timezone


ALERT_SEVERITY_LEVELS = {
    "low",
    "medium",
    "high",
    "critical",
}


def create_alert(
    title,
    severity,
    description,
    source_event,
):
    severity = severity.lower()

    if severity not in ALERT_SEVERITY_LEVELS:
        severity = "medium"

    return {
        "event_type": "security_alert",
        "alert_id": f"CX-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "title": title,
        "severity": severity,
        "status": "open",
        "description": description,
        "source_event": source_event,
    }


def create_detection_alert(detection_event):
    severity = detection_event.get(
        "risk_level",
        "medium",
    )

    return create_alert(
        title="Suspicious Process Activity",
        severity=severity,
        description=(
            "CIPHER-X detected suspicious process "
            "behavior requiring investigation."
        ),
        source_event=detection_event,
    )


def create_correlation_alert(correlation_event):
    severity = correlation_event.get(
        "severity",
        "high",
    )

    return create_alert(
        title="Correlated Security Activity",
        severity=severity,
        description=correlation_event.get(
            "description",
            "CIPHER-X detected correlated "
            "suspicious activity.",
        ),
        source_event=correlation_event,
    )