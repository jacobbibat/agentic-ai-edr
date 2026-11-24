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
            event["event_data"] = json.loads(
                event["event_data"]
            )  # cconverts JSON text back into Python dictionary

            return event
