"""
CIPHER-X Event Correlation Engine

Tracks recent security detections and identifies
potentially suspicious combinations of behavior.
"""

from collections import deque


class CorrelationEngine:
    """
    Stores recent detections and searches for
    suspicious combinations of activity.
    """

    def __init__(self, max_events=20):
        """
        Initialize the correlation engine.

        Args:
            max_events: Maximum number of recent events
            to keep in memory.
        """

        self.recent_events = deque(maxlen=max_events)

        # Track previously generated alerts so the same
        # repeated behavior does not continuously generate
        # duplicate correlation alerts.
        self.generated_alerts = set()

    def add_event(self, event):
        """
        Add a security event to the recent event history.

        Args:
            event: Security detection event dictionary.
        """

        self.recent_events.append(event)

    def get_recent_events(self):
        """
        Return a list of recently stored events.
        """

        return list(self.recent_events)

    def find_repeated_behavior(self, rule, threshold=2):
        """
        Check whether a detection rule has occurred
        multiple times in recent events.

        Args:
            rule: Detection rule to search for.
            threshold: Number of occurrences required.

        Returns:
            True if the rule occurs at or above the
            specified threshold.
        """

        matches = [
            event
            for event in self.recent_events
            if event.get("rule") == rule
        ]

        return len(matches) >= threshold

    def generate_correlation_alert(self, rule, threshold=2):
        """
        Generate an alert when suspicious behavior
        repeatedly occurs.

        Args:
            rule: Detection rule to evaluate.
            threshold: Number of occurrences required.

        Returns:
            Correlation alert dictionary or None.
        """

        matches = [
            event
            for event in self.recent_events
            if event.get("rule") == rule
        ]

        event_count = len(matches)

        if event_count < threshold:
            return None

        # Create a unique identifier for this specific
        # correlation state.
        alert_key = (rule, event_count)

        # Prevent duplicate alerts for the same event count.
        if alert_key in self.generated_alerts:
            return None

        self.generated_alerts.add(alert_key)

        return {
            "event_type": "correlation_alert",
            "rule": rule,
            "severity": "high",
            "description": (
                f"Repeated suspicious behavior detected: "
                f"'{rule}' occurred {event_count} times."
            ),
            "event_count": event_count,
        }

    def analyze_recent_events(self, threshold=2):
        """
        Analyze all recent events and generate
        correlation alerts for repeated behavior.

        Args:
            threshold: Number of repeated occurrences
            required to trigger an alert.

        Returns:
            List of correlation alert dictionaries.
        """

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

        return alerts