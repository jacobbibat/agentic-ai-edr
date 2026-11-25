import win32evtlog
import json
import win32evtlog

from collector.sysmon_parser import SysmonParser


class SysmonCollector:
    """Retrieve events from the Windows Sysmon event log."""

    def __init__(self):
        self.channel = "Microsoft-Windows-Sysmon/Operational"

    def get_events(self, limit: int = 10) -> list[str]:
        """Retrieve the most recent Sysmon process creation events."""

        # Query Sysmon for Event ID 1 (process creation)
        query = "*[System[EventID=1]]"

        # Retrieve events starting with the newest
        handle = win32evtlog.EvtQuery(
            self.channel,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            query,
        )

        events = []

        # Retrieve the requested number of events
        event_handles = win32evtlog.EvtNext(handle, limit)

        for event_handle in event_handles:
            # Convert the Windows event into XML
            event_xml = win32evtlog.EvtRender(
                event_handle,
                win32evtlog.EvtRenderEventXml,
            )

            events.append(event_xml)

        return events


if __name__ == "__main__":
    collector = SysmonCollector()
    parser = SysmonParser()

    events = collector.get_events(1)

    for event_xml in events:

        #Convert XML into a structured library
        parsed_event = parser.parse_event(event_xml)

        # Display the complete parsed event
        print(json.dumps(parsed_event, indent=4))
