import json
from contextlib import closing
from pathlib import Path

from database.connection import DATABASE_PATH, get_connection

class SecurityRepository:
    """Store and retrieve security events and alerts."""

    def __init__(self, database_path: str | Path = DATABASE_PATH):
        self.database_path = database_path

    def save_event_with_alerts (
            self,
            event: dict,
            alerts: list[dict],
    ) -> int:
        """Save one event and all its alerts atomically"""

        # Opening the db connection
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
                        json.dumps(event),
                    ),
                )

                # Retrieve the new event's database ID.
                event_id = cursor.lastrowid

                #Save every generated alert
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
                #Undo pending changes if anything fails
                connection.rollback()
                raise

        return event_id