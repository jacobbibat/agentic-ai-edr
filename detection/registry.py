from detection.detection_rule import DetectionRule
from detection.rules import *

DETECTION_RULES = [
    DetectionRule(
        rule_id="EDR-001",
        name="Microsoft Word spawning PowerShell",
        severity="High",
        condition=is_word_powershell,
    ),
    DetectionRule(
        rule_id="EDR-002",
        name="Encoded PowerShell execution",
        severity="Medium",
        condition=is_encoded_powershell,
    ),
]
