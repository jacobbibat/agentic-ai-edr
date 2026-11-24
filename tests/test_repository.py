import sqlite3

import pytest

from database.connection import initialise_database
from database.repository import SecurityRepository
from detection.engine import DetectionEngine
from detection.registry import DETECTION_RULES


@pytest.fixture
def test_repository(tmp_path):
    # Create a separate database for this test.
    database_path = tmp_path / "test_edr.db"

    initialise_database(database_path)

    return SecurityRepository(database_path)


def test_saves_event_with_two_alerts(test_repository):
    # Word launches PowerShell with an encoded command.
    event = {
        "EventID": 1,
        "UtcTime": "2026-11-24 10:00:00.000",
        "Computer": "WIN11-ENDPOINT",
        "ParentImage": (r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
        "Image": r"C:\Windows\System32\powershell.exe",
        "CommandLine": "powershell.exe -enc ABC123",
    }

    # Generate alerts using our real detection engine.
    engine = DetectionEngine(DETECTION_RULES)
    alerts = engine.analyse(event)

    assert len(alerts) == 2

    # Save event and alerts.
    event_id = test_repository.save_event_with_alerts(
        event,
        alerts,
    )

    assert isinstance(event_id, int)

    # Verify the records were saved.
    connection = sqlite3.connect(test_repository.database_path)

    try:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        alert_count = connection.execute(
            "SELECT COUNT(*) FROM security_alerts"
        ).fetchone()[0]

        assert event_count == 1
        assert alert_count == 2

    finally:
        connection.close()


def test_transaction_rollback(test_repository):
    """Verify failed alert insertion rolls back all changes."""

    event = {
        "EventID": 1,
        "UtcTime": "2026-11-24 10:00:00.000",
        "Computer": "WIN11-ENDPOINT",
        "Image": r"C:\Windows\System32\powershell.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
        "CommandLine": "powershell.exe -enc ABC123",
    }

    # Generate one valid alert.
    engine = DetectionEngine(DETECTION_RULES)
    alerts = engine.analyse(event)

    # Create an invalid second alert.
    invalid_alert = alerts[0].copy()
    invalid_alert["rule_id"] = None

    # Attempt to save both alerts.
    with pytest.raises(sqlite3.IntegrityError):
        test_repository.save_event_with_alerts(
            event,
            [alerts[0], invalid_alert],
        )

    # Check that nothing was saved.
    connection = sqlite3.connect(test_repository.database_path)

    try:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        alert_count = connection.execute(
            "SELECT COUNT(*) FROM security_alerts"
        ).fetchone()[0]

        assert event_count == 0
        assert alert_count == 0

    finally:
        connection.close()


def test_retrieve_event_and_alerts(test_repository):
    event = {
        "EventID": 1,
        "UtcTime": "2026-11-24 10:00:00.000",
        "Computer": "WIN11-ENDPOINT",
        "ParentImage": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        "Image": r"C:\Windows\System32\powershell.exe",
        "CommandLine": "powershell.exe -enc ABC123",
    }

    engine = DetectionEngine(DETECTION_RULES)
    alerts = engine.analyse(event)

    # Save event and matching alerts.
    event_id = test_repository.save_event_with_alerts(event, alerts)

    # Retrieve alerts.
    saved_alerts = test_repository.get_all_alerts()

    assert len(saved_alerts) == 2
    assert {a["rule_id"] for a in saved_alerts} == {
        "EDR-001",
        "EDR-002",
    }

    # Retrieve the original event.
    saved_event = test_repository.get_event_by_id(event_id)

    assert saved_event is not None
    assert saved_event["event_data"]["EventID"] == 1
    assert saved_event["endpoint"] == "WIN11-ENDPOINT"

def test_get_all_events(tmp_path):
    #Create isolated test environment
    database_path = tmp_path / "test_edr.db"

    initialise_database(database_path)
    repository = SecurityRepository(database_path)

    # Sample Sysmon event
    event = {
        "EventID": 1,
        "UtcTime": "2026-11-24 18:00:00",
        "Computer": "WIN-01",
        "Image": r"C:\Windows\System32\notepad.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
        "CommandLine": "notepad.exe",
    }

    # Save an event with no alerts 
    repository.save_event_with_alerts(event, [])

    # Retrieve events
    events = repository.get_all_events()

    # Verify the result
    assert len(events) == 1
    assert events[0]["sysmon_event_id"] == 1
    assert events[0]["endpoint"] == "WIN-01"
    assert events[0]["event_data"]["Image"] == event["Image"]
