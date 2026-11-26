import socket

from collector.read_events import load_new_events
from database.connection import initialise_database
from database.repository import SecurityRepository
from detection.engine import DetectionEngine
from detection.registry import DETECTION_RULES


def main():
    #Initialise database
    initialise_database()

    # Set up detection engine and repository
    engine = DetectionEngine(DETECTION_RULES)
    repository = SecurityRepository()

    # Identify the local endpoint and Sysmon Channel
    endpoint = socket.gethostname()
    channel = "Microsoft-Windows-Sysmon/Operational"

    # Retrieve the last processed record ID
    last_record_id = repository.get_checkpoint(endpoint, channel)


    print(f"Endpoint: {endpoint}")
    print(f"Current checkpoint: {last_record_id}")

    #Retrieve new Sysmon events after the checkpoint
    events = load_new_events(last_record_id, limit=10)

    print(f"Loaded {len(events)} new Sysmon events.")

    for event in events:

        record_id = event["EventRecordID"]

        # Check whether this event has already been processed
        if repository.event_exists(event):
            print(f"Skipping duplicate event: {record_id}")

            # Advance checkpoint even if the event already exists
            repository.save_checkpoint(
                endpoint,
                channel,
                record_id,
            )

            continue

        # Analyse the event using detection rules.
        alerts = engine.analyse(event)

        # Store the event and its associated alerts.
        event_id = repository.save_event_with_alerts(event, alerts)

        # Update checkpoint after successful storage
        repository.save_checkpoint(
            endpoint,
            channel,
            record_id,
        )

        print(f"Event Record ID: {event['EventRecordID']}")
        print(f"Process: {event['Image']}")
        print(f"Parent: {event['ParentImage']}")
        print(f"Alerts generated: {len(alerts)}")
        print(f"Stored database event ID: {event_id}")
        print(f"Checkpoint updated: {record_id}")
        print(f"Time: {event['UtcTime']}")

        for alert in alerts:
            print(alert)

        print("-" * 80)

    # Display the final checkpoint
    final_checkpoint = repository.get_checkpoint(
        endpoint,
        channel,
    )

    print(f"Final checkpoint: {final_checkpoint}")

if __name__ == "__main__":
    main()
