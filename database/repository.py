import json
from contextlib import closing
from pathlib import Path

from database.connection import DATABASE_PATH, get_connection


class SecurityRepository:
    """Store and retrieve security events and alerts."""

    def __init__(self, database_path: str | Path = DATABASE_PATH):
        self.database_path = database_path

    def save_event_with_alerts(
        self,
        event: dict,
        alerts: list[dict],
    ) -> int:
        """Save one event and all its alerts atomically"""

        # Opening the db connection, closing() ensures connection is closed when we're finished, even if we have an error
        with closing(get_connection(self.database_path)) as connection:
            # Start a transaction explicitly
            connection.execute("BEGIN")

            try:
                # Store the original Sysmon event.
                cursor = connection.execute(
                    """
                    INSERT INTO security_events (
                        sysmon_event_id,
                        timestamp,
                        endpoint,
                        event_data
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        event["EventID"],
                        event["UtcTime"],
                        event["Computer"],
                        json.dumps(
                            event
                        ),  # event_data stores text, convert dictionary into JSON so SQLite can store
                    ),
                )

                # Retrieve the new event's database ID.
                event_id = cursor.lastrowid  # Gives a private key generated for that inserted row, i.e SQLite id = 7, we use event_id = 7 when inserting its alerts

                # Ensure SQLite returned a valid event ID
                if event_id is None:
                    raise RuntimeError("Failed to retrieve the inserted event ID.")

                # Save every generated alert
                for alert in alerts:
                    connection.execute(
                        """
                        INSERT INTO security_alerts (
                            event_id,
                            rule_id,
                            rule_name,
                            severity,
                            status,
                            evidence
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            alert["rule_id"],
                            alert["rule_name"],
                            alert["severity"],
                            alert["status"],
                            json.dumps(alert["evidence"]),
                        ),
                    )

                    # Make all changes permanent
                connection.commit()

            except Exception:
                # Undo pending changes if anything fails
                connection.rollback()
                raise

        return event_id

    def get_all_alerts(self) -> list[dict]:
        """Retrieve all alerts with their endpoint information."""

        with closing(get_connection(self.database_path)) as connection:
            rows = connection.execute(
                """
                SELECT
                    a.id,
                    a.event_id,
                    a.rule_id,
                    a.rule_name,
                    a.severity,
                    a.status,
                    a.evidence,
                    e.endpoint,
                    e.timestamp
                FROM security_alerts AS a
                JOIN security_events AS e
                    ON a.event_id = e.id
                ORDER BY a.id DESC
                """
            ).fetchall()  # Retrieves all rows from returned query

            alerts = []

            for row in rows:
                alert = dict(row)

                # Convert the evidence JSON string into a dictionary.
                alert["evidence"] = json.loads(alert["evidence"])

                alerts.append(alert)

            return alerts

    def get_event_by_id(self, event_id: int) -> dict | None:
        """Retrieve a single event using its database ID."""

        with closing(get_connection(self.database_path)) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM security_events
                WHERE id = ?
                """,
                (event_id,),
            ).fetchone()  # Retrieves one row or None if no row exists

            if row is None:
                return None

            event = dict(row)  # converts SQLite row into Python dictionary
            event["event_data"] = json.loads(event["event_data"])

            return event

    def get_all_events(self) -> list[dict]:
        """Retrieve all stored endpoint events."""

        with closing(get_connection(self.database_path)) as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    sysmon_event_id,
                    timestamp,
                    endpoint,
                    event_data
                FROM security_events
                ORDER BY id DESC
                """
            ).fetchall()

        events = []

        for row in rows:
            event = dict(row)

            # Convert stored JSON text back into a Python dictionary.
            event["event_data"] = json.loads(event["event_data"])

            events.append(event)

        return events

    def get_dashboard_stats(self) -> dict:
        """Return statistics for security dashboard"""

        with closing(get_connection(self.database_path)) as connection:
            # Count all stored security events
            total_events = connection.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0]

            # Count all generated alerts
            total_alerts = connection.execute(
                "SELECT COUNT(*) FROM security_alerts"
            ).fetchone()[0]

            # Count all alerts by severity
            severity_rows = connection.execute(
                """
                SELECT severity, COUNT(*) AS total
                FROM security_alerts
                GROUP BY severity
                """
            ).fetchall()

        severity_counts = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }
        for row in severity_rows:
            severity_counts[row["severity"]] = row["total"]

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "high_severity": severity_counts["High"],
            "medium_severity": severity_counts["Medium"],
            "low_severity": severity_counts["Low"],
        }

    def event_exists(self, event: dict) -> bool:
        """Checks whether a real Sysmon event is already stored"""

        record_id = event.get("EventRecordID")
        channel = event.get("System", {}).get("Channel")

        if record_id is None or channel is None:
            return False

        with closing(get_connection(self.database_path)) as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM security_events
                WHERE endpoint = ?
                AND json_extract(event_data, '$.System.Channel') = ?
                AND json_extract(event_data, '$.EventRecordID') = ?
                AND timestamp = ?
                LIMIT 1
                """,
                (
                    event["Computer"],
                    channel,
                    record_id,
                    event["UtcTime"],
                ),
            ).fetchone()

        return row is not None


