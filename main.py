from collector.read_events import load_live_events
from database.connection import initialise_database
from database.repository import SecurityRepository
from detection.engine import DetectionEngine
from detection.registry import DETECTION_RULES


def main():
    #Initialise database
    initialise_database()

    # Retrieve real Symon events
    events = load_live_events(2)

    # Set up detection engine and repository
    engine = DetectionEngine(DETECTION_RULES)
    repository = SecurityRepository()

    print(f"Loaded {len(events)} real Sysmon events.")

    # Process every event
    for event in events:
        alerts = engine.analyse(event)

        #Store events with associated alert
        event_id = repository.save_event_with_alerts(event, alerts)

        print(f"Event Record ID: {event['EventRecordID']}")
        print(f"Process: {event['Image']}")
        print(f"Parent: {event['ParentImage']}")
        print(f"Alerts generated: {len(alerts)}")
        print(f"Stored database event ID: {event_id}") # Display ID assigned by SQLite

        for alert in alerts:
            print(alerts)

        print("-" * 80)

if __name__ == "__main__":
    main()
