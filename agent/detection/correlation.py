from collections import deque


class CorrelationEngine:
    def __init__(self, max_events=20):
        self.recent_events = deque(maxlen=max_events)
        self.generated_alerts = set()

    def add_event(self, event):
        self.recent_events.append(event)

    def get_recent_events(self):
        return list(self.recent_events)

    def generate_correlation_alert(self, rule, threshold=2):
        matches = [
            event
            for event in self.recent_events
            if event.get("rule") == rule
        ]

        event_count = len(matches)

        if event_count < threshold:
            return None

        alert_key = (
            "repeated_behavior",
            rule,
            event_count,
        )

        if alert_key in self.generated_alerts:
            return None

        self.generated_alerts.add(alert_key)

        return {
            "event_type": "correlation_alert",
            "correlation_type": "repeated_behavior",
            "rule": rule,
            "severity": "high",
            "description": (
                f"Repeated suspicious behavior detected: "
                f"'{rule}' occurred {event_count} times."
            ),
            "event_count": event_count,
        }

    def detect_cross_event_behavior(self):
        rules = {
            event.get("rule")
            for event in self.recent_events
            if event.get("rule")
        }

        alerts = []

        if (
            "suspicious_command_line" in rules
            and "suspicious_file_extension" in rules
        ):
            alert_key = (
                "cross_event",
                "command_line_and_file_extension",
            )

            if alert_key not in self.generated_alerts:
                self.generated_alerts.add(alert_key)

                alerts.append({
                    "event_type": "correlation_alert",
                    "correlation_type": "cross_event",
                    "severity": "critical",
                    "description": (
                        "Suspicious command-line activity and "
                        "suspicious file activity were both observed."
                    ),
                    "related_rules": [
                        "suspicious_command_line",
                        "suspicious_file_extension",
                    ],
                })

        return alerts

    def analyze_recent_events(self, threshold=2):
        alerts = []

        rules = {
            event.get("rule")
            for event in self.recent_events
            if event.get("rule")
        }

        for rule in rules:
            alert = self.generate_correlation_alert(
                rule,
                threshold,
            )

            if alert:
                alerts.append(alert)

        alerts.extend(
            self.detect_cross_event_behavior()
        )

        return alerts