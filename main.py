from collector.read_events import load_events
from detection.rules import generate_alerts


def main():
    # Step 1: Load the Sysmon events.
    events = load_events()

    print(f"Loaded {len(events)} Sysmon events.")

    # Step 2: Check each event against our rules.
    for event in events:
        alerts = generate_alerts(event)

        # Step 3: Display matching alerts.
        if alerts:
            for alert in alerts:
                print("\nSECURITY ALERT DETECTED")
                print(f"Rule: {alert['rule_name']}")
                print(f"Severity: {alert['severity']}")
                print(f"Endpoint: {alert['endpoint']}")
                print(f"Time: {alert['timestamp']}")
        else:
            print("No detection rules matched.")


if __name__ == "__main__":
    main()
