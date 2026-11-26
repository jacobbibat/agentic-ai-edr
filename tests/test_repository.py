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
    # Create isolated test environment
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

@pytest.fixture
def live_event():
    """Provide a synthetic real Sysmon event."""

    return {
        "EventID": 1,
        "EventRecordID": 3066,
        "UtcTime": "2026-11-25 21:36:25.475",
        "Computer": "WIN11-ENDPOINT",
        "Image": r"C:\Windows\System32\notepad.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
        "CommandLine": "notepad.exe",
        "System": {
            "Channel": "Microsoft-Windows-Sysmon/Operational",
        },
    }


def test_event_does_not_exist(test_repository, live_event):
    assert test_repository.event_exists(live_event) is False


def test_event_already_exists(test_repository, live_event):
    test_repository.save_event_with_alerts(live_event, [])

    assert test_repository.event_exists(live_event) is True


def test_prevent_duplicate_event(test_repository, live_event):
    test_repository.save_event_with_alerts(live_event, [])

    with pytest.raises(sqlite3.IntegrityError):
        test_repository.save_event_with_alerts(live_event, [])

    assert len(test_repository.get_all_events()) == 1


def test_same_record_different_endpoint(test_repository, live_event):
    test_repository.save_event_with_alerts(live_event, [])

    second_event = live_event.copy()
    second_event["Computer"] = "WIN11-ENDPOINT-02"

    assert test_repository.event_exists(second_event) is False

    test_repository.save_event_with_alerts(second_event, [])

    assert len(test_repository.get_all_events()) == 2


def test_same_record_different_timestamp(test_repository, live_event):
    test_repository.save_event_with_alerts(live_event, [])

    second_event = live_event.copy()
    second_event["UtcTime"] = "2026-11-25 22:40:12.000"

    assert test_repository.event_exists(second_event) is False

    test_repository.save_event_with_alerts(second_event, [])

    assert len(test_repository.get_all_events()) == 2


def test_sample_event_without_record_id(test_repository, live_event):
    sample_event = live_event.copy()
    del sample_event["EventRecordID"]

    test_repository.save_event_with_alerts(sample_event, [])

    assert test_repository.event_exists(sample_event) is False


def test_get_missing_checkpoint(test_repository):
    checkpoint = test_repository.get_checkpoint(
        "WIN-01",
        "Sysmon",
    )

    assert checkpoint == 0


def test_save_checkpoint(test_repository):
    test_repository.save_checkpoint(
        "WIN-01",
        "Sysmon",
        3066,
    )

    checkpoint = test_repository.get_checkpoint(
        "WIN-01",
        "Sysmon",
    )

    assert checkpoint == 3066


def test_update_checkpoint(test_repository):
    test_repository.save_checkpoint("WIN-01", "Sysmon", 3066)
    test_repository.save_checkpoint("WIN-01", "Sysmon", 3076)

    checkpoint = test_repository.get_checkpoint(
        "WIN-01",
        "Sysmon",
    )

    assert checkpoint == 3076


def test_separate_endpoint_checkpoints(test_repository):
    test_repository.save_checkpoint("WIN-01", "Sysmon", 3066)
    test_repository.save_checkpoint("WIN-02", "Sysmon", 1500)

    assert test_repository.get_checkpoint("WIN-01", "Sysmon") == 3066
    assert test_repository.get_checkpoint("WIN-02", "Sysmon") == 1500


def test_checkpoint_persists(test_repository):
    test_repository.save_checkpoint("WIN-01", "Sysmon", 3066)

    # Create a new repository using the same database.
    repository = SecurityRepository(
        test_repository.database_path
    )

    assert repository.get_checkpoint("WIN-01", "Sysmon") == 3066