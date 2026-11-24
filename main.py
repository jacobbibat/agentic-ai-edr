from collector.read_events import load_events
from detection.engine import DetectionEngine
from detection.registry import DETECTION_RULES
from database.connection import initialise_database


def main():
    # Load sample Sysmon events.
    events = load_events()

    # Create the detection engine with registered rules.
    engine = DetectionEngine(DETECTION_RULES)

    print(f"Loaded {len(events)} Sysmon events.")
    print(f"Registered rules: {len(DETECTION_RULES)}")

    # Process each event.
    for event in events:
        alerts = engine.analyse(event)

        if not alerts:
            print("No detection rules matched.\n")
            continue

        # Display every generated alert.
        for alert in alerts:
            print("\nSECURITY ALERT DETECTED")
            print(f"Rule: {alert['rule_name']}")
            print(f"Severity: {alert['severity']}")
            print(f"Endpoint: {alert['endpoint']}\n")


if __name__ == "__main__":
    main()
    initialise_database()
    print("EDR database initialised successfully.")
