from detection.alert_builder import AlertBuilder
from detection.detection_rule import DetectionRule


class DetectionEngine:
    """Runs registered detection rules against events."""

    def __init__(self, rules: list[DetectionRule]):
        self.rules = rules

    def analyse(self, event: dict) -> list[dict]:
        """Return all alerts generated for an event."""

        alerts = []
        builder = AlertBuilder(event)

        # Evaluate every registered detection rule.
        for rule in self.rules:
            if rule.matches(event):
                alert = builder.build(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                )

                alerts.append(alert)

        return alerts
