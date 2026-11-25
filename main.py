from collector.read_events import load_live_events
from database.connection import initialise_database
from database.repository import SecurityRepository
from detection.engine import DetectionEngine
from detection.registry import DETECTION_RULES


def main():
    # Retrieve real Symon events
    events = load_live_events(10)

    # Set up detection engine
    engine = DetectionEngine(DETECTION_RULES)

    print(f"Loaded {len(events)} real Sysmon events.")

    # Process every event
    for event in events:
        alerts = engine.analyse(event)

        print(f"Event Record ID: {event['EventRecordID']}")
        print(f"Process: {event['Image']}")
        print(f"Parent: {event['ParentImage']}")
        print(f"Alerts generated: {len(alerts)}")
        print("-" * 80)

        for alert in alerts:
            print(alerts)

if __name__ == "__main__":
    main()
