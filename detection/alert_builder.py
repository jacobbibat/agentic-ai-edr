class AlertBuilder:
    """Build a consistent security alert from a Sysmon event."""

    def __init__(self, event: dict):
        # Store original event for later use
        self.event = event

    def build(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
    ) -> dict:
        """Create an alert using the event and rule details"""

        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "status": "New",
            "timestamp": self.event.get("UtcTime"),
            "endpoint": self.event.get("Computer"),
            "evidence": {
                "parent_process": self.event.get("ParentImage"),
                "child_process": self.event.get("Image"),
                "command_line": self.event.get("CommandLine"),
            },
        }
