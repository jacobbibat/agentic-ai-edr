from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionRule:
    """Represents a single security detection rule."""

    rule_id: str
    name: str
    severity: str
    condition: Callable[[dict], bool]

    def matches(self, event: dict) -> bool:
        """Check whether the event matches this rule."""
        return self.condition(event)
