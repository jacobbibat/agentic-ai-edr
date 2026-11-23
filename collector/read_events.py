import json
from pathlib import Path


def load_events():
    file_path = Path(__file__).with_name("sample_events.json")

    with open(file_path, "r", encoding="utf-8") as file:
        events = json.load(file)

    return events


if __name__ == "__main__":
    events = load_events()

    for event in events:
        print(f"Event ID: {event['EventID']}")
        print(f"Process: {event['Image']}")
        print(f"Parent: {event['ParentImage']}")
        print("-----------------------------")
