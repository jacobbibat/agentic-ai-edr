from database.connection import get_connection


def main():
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                a.id,
                a.rule_id,
                a.severity,
                a.status,
                e.endpoint
            FROM security_alerts AS a
            JOIN security_events AS e
                ON a.event_id = e.id
            ORDER BY a.id
            """
        ).fetchall()

        for row in rows:
            print(
                f"Alert {row['id']} | "
                f"{row['rule_id']} | "
                f"{row['severity']} | "
                f"{row['endpoint']}"
            )

    finally:
        connection.close()


if __name__ == "__main__":
    main()
