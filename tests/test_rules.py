from detection.rules import (
    is_word_powershell,
    is_encoded_powershell,
)
from detection.engine import DetectionEngine
from detection.registry import DETECTION_RULES


# ------------------------------------------
# Helper function to create sample events
# ------------------------------------------


def make_event(parent: str, child: str) -> dict:
    return {
        "EventID": 1,
        "ParentImage": parent,
        "Image": child,
        "Computer": "Jacobs-PC",
        "UtcTime": "2026-11-16 14:30:00.000",
    }


# ------------------------------------------
# Testing Rule 1: Word launching PowerShell
# ------------------------------------------


def test_word_launching_powershell():
    event = make_event(
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Windows\System32\powershell.exe",
    )

    assert is_word_powershell(event) is True


def test_explorer_launching_powershell():
    event = make_event(
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32\powershell.exe",
    )

    assert is_word_powershell(event) is False


def test_word_launching_notepad():
    event = make_event(
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Windows\System32\notepad.exe",
    )

    assert is_word_powershell(event) is False


def test_ignores_other_event_ids():
    event = make_event(
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Windows\System32\powershell.exe",
    )

    event["EventID"] = 3

    assert is_word_powershell(event) is False


# ------------------------------------------
# Testing Rule 2: Encoded PowerShell
# ------------------------------------------


def test_encoded_powershell():
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand VABlAHMAdAA=",
    }

    assert is_encoded_powershell(event) is True


def test_powershell_without_encoding():
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
    }

    assert is_encoded_powershell(event) is False


def test_unrelated_process_with_encoded_argument():
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\notepad.exe",
        "CommandLine": "notepad.exe -enc ABC123",
    }

    assert is_encoded_powershell(event) is False


# ------------------------------------------
# Testing the Detection Engine
# ------------------------------------------


def test_alert_generation():
    event = make_event(
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Windows\System32\powershell.exe",
    )

    engine = DetectionEngine(DETECTION_RULES)

    alerts = engine.analyse(event)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "EDR-001"
    assert alerts[0]["severity"] == "High"


def test_multiple_alert_generation():
    # This event should match BOTH EDR-001 and EDR-002.
    event = make_event(
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Windows\System32\powershell.exe",
    )

    event["CommandLine"] = "powershell.exe -EncodedCommand VABlAHMAdAA="

    engine = DetectionEngine(DETECTION_RULES)

    alerts = engine.analyse(event)

    assert len(alerts) == 2

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert rule_ids == {"EDR-001", "EDR-002"}
