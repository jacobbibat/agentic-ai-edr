from detection.rules import *


def test_detects_windows_powershell():
    assert is_powershell_process("powershell.exe")


def test_detects_windows_powershell_insensitive():
    assert is_powershell_process("PowerShell.EXE")


def test_ignore_unrelated_process():
    assert not is_powershell_process("notepad.exe")


# ------------------------------------------#


def make_event(parent: str, child: str) -> dict:
    return {
        "EventID": 1,
        "ParentImage": parent,
        "Image": child,
        "Computer": "Jacobs-PC",
        "UtcTime": "2026-11-16 14:30:00:000",
    }


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


def test_alert_generation():
    event = make_event(
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Windows\System32\powershell.exe",
    )

    alert = generate_alert(event)

    assert alert is not None
    assert alert["rule_id"] == "EDR-001"
    assert alert["severity"] == "High"


def test_ignores_other_event_ids():
    event = make_event(
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Windows\System32\powershell.exe",
    )
    event["EventID"] = 3

    assert is_word_powershell(event) is False


# -----------------------------------------#

# Testing Rule 2, encoded powershell

from detection.rules import is_encoded_powershell


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
