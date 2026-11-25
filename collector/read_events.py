import json
from pathlib import Path

from collector.sysmon_parser import SysmonParser


def load_events():
    """Loads sample Sysmon events form a JSON file"""
    file_path = Path(__file__).with_name("sample_events.json")

    with open(file_path, "r", encoding="utf-8") as file:
        events = json.load(file)

    return events

def load_live_events(limit: int = 10) -> list[dict]:
    """Retrieve and parse real Sysmon events."""
    from collector.sysmon_collector import SysmonCollector

    collector = SysmonCollector()
    parser = SysmonParser()

    #Retrieve raw XML events
    raw_events = collector.get_events(limit)

    events = []

    # Convert XML event into dictionary
    for raw_event in raw_events:
        event = parser.parse_event(raw_event)
        events.append(event)

    return events


if __name__ == "__main__":
    events = load_events()

    for event in events:
        print(f"Event ID: {event['EventID']}")
        print(f"Process: {event['Image']}")
        print(f"Parent: {event['ParentImage']}")
        print("-----------------------------")
