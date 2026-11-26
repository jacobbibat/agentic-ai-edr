import win32evtlog
import json

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

    def get_new_events(self, last_record_id: int, limit: int=100,) -> list[str]:
        """Retrieve Sysmon events after last processed record ID"""
        query =(
            f"*[System[EventID=1 and "
            f"EventRecordID > {last_record_id}]]"
        )

        # Retrieve events from oldest to newest
        handle = win32evtlog.EvtQuery(
            self.channel,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
            query,
        )

        events =[]

        try:
            #Retrieve batch of new events
            event_handles = win32evtlog.EvtNext(handle, limit)

            for event_handle in event_handles:
                #Convert event into raw XML
                event_xml = win32evtlog.EvtRender(
                    event_handle,
                    win32evtlog.EvtRenderEventXml,
                )

                events.append(event_xml)

        finally:
            # Release Windows query handle (for resources)
            handle.Close()

        return events


if __name__ == "__main__":
    collector = SysmonCollector()
    parser = SysmonParser()

    # Temporary checkpoint for testing.
    last_record_id = 3090

    events = collector.get_new_events(
        last_record_id,
        limit=10,
    )

    print(f"Retrieved {len(events)} new events.")

    for event_xml in events:
        parsed_event = parser.parse_event(event_xml)

        print(f"Record ID: {parsed_event['EventRecordID']}")
        print(f"Process: {parsed_event['Image']}")
        print("-" * 80)
