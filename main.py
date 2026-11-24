from collector.read_events import load_events
from database.connection import initialise_database
from database.repository import SecurityRepository
from detection.engine import DetectionEngine
from detection.registry import DETECTION_RULES


def main():
    # Step 1: Initialise database tables.
    initialise_database()

    # Step 2: Load sample Sysmon events.
    events = load_events()

    # Step 3: Set up the detection engine and repository.
    engine = DetectionEngine(DETECTION_RULES)
    repository = SecurityRepository()

    print(f"Loaded {len(events)} Sysmon events.")

    # Step 4: Process every event.
    for event in events:
        alerts = engine.analyse(event)

        # Step 5: Save the event and any matching alerts.
        event_id = repository.save_event_with_alerts(
            event,
            alerts,
        )

        print(f"Stored event {event_id} with {len(alerts)} alerts.")


if __name__ == "__main__":
    main()
