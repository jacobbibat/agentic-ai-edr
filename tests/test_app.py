import pytest

from app import create_app
from database.repository import SecurityRepository


@pytest.fixture
def client(tmp_path):
    """Create an isolated Flask test client."""

    # Create a temporary database.
    database_path = tmp_path / "test_api.db"

    # Create Flask application using that database.
    app = create_app(database_path)

    app.config["TESTING"] = True

    # Create a client without starting a web server.
    return app.test_client()


def test_get_alerts_empty(client):
    """Check that an empty database returns an empty list."""

    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert response.json == []


def test_get_alerts_with_data(client, tmp_path):
    """Check that stored alerts are returned correctly."""

    # Use the database created by the test client.
    database_path = tmp_path / "test_api.db"
    repository = SecurityRepository(database_path)

    event = {
        "EventID": 1,
        "UtcTime": "2026-11-24 10:00:00.000",
        "Computer": "WIN11-ENDPOINT",
        "ParentImage": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        "Image": r"C:\Windows\System32\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
    }

    alert = {
        "rule_id": "EDR-001",
        "rule_name": "Microsoft Word spawning PowerShell",
        "severity": "High",
        "status": "New",
        "evidence": {
            "parent_process": event["ParentImage"],
            "child_process": event["Image"],
            "command_line": event["CommandLine"],
        },
    }

    repository.save_event_with_alerts(event, [alert])

    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]["rule_id"] == "EDR-001"
    assert response.json[0]["severity"] == "High"
    assert isinstance(response.json[0]["evidence"], dict)


def test_dashboard_page(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"Agentic AI EDR" in response.data
    assert b"Security Dashboard" in response.data


def test_dashboard_stats_empty(client):
    response = client.get("/api/dashboard/stats")

    assert response.status_code == 200

    data = response.get_json()

    assert data["total_events"] == 0
    assert data["total_alerts"] == 0
    assert data["high_severity"] == 0
    assert data["medium_severity"] == 0
    assert data["low_severity"] == 0
