from collector.read_events import load_events
from detection.rules import generate_alert

def main():
    events = load_events()

    print(f"Loaded ({len(events)}) System events.")

    for event in events:
        alert = generate_alert(event)

        if alert is not None:
            print("\nSECURITY ALERT DETECTED")
            print(f"Rule: {alert['rule_name']}")
            print(f"Severity: {alert['severity']}")
            print(f"Endpoint: {alert['endpoint']}")
            print(f"Time: {alert['timestamp']}")
        else:
            print("Event did not match the detection rules")

if __name__ == "__main__":
    
    main()