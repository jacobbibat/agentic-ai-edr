import win32evtlog

from collector.sysmon_parser import SysmonParser


class SysmonCollector:
    """Retrieve events from the Windows Sysmon event log."""

    def __init__(self):
        self.channel = "Microsoft-Windows-Sysmon/Operational"

    def _query_events(
        self,
        query: str,
        direction: int,
        limit: int,
    ) -> list[str]:
        """Execute a Sysmon query and return raw XML events."""

        # Create a Windows query handle.
        handle = win32evtlog.EvtQuery(
            self.channel,
            win32evtlog.EvtQueryChannelPath | direction,
            query,
        )

        events = []
        event_handles = []

        try:
            # Retrieve a batch of event handles.
            event_handles = win32evtlog.EvtNext(handle, limit)

            for event_handle in event_handles:

                # Convert each Windows event into XML.
                event_xml = win32evtlog.EvtRender(
                    event_handle,
                    win32evtlog.EvtRenderEventXml,
                )

                events.append(event_xml)

        finally:
            # Release all individual event handles.
            for event_handle in event_handles:
                event_handle.Close()

            # Release the Windows query handle.
            handle.Close()

        return events

    def get_events(self, limit: int = 10) -> list[str]:
        """Retrieve the most recent Sysmon process creation events."""

        query = "*[System[EventID=1]]"

        return self._query_events(
            query,
            win32evtlog.EvtQueryReverseDirection,
            limit,
        )

    def get_new_events(
        self,
        last_record_id: int,
        limit: int = 100,
    ) -> list[str]:
        """Retrieve Sysmon events after the last processed record ID."""

        query = (
            f"*[System[EventID=1 and "
            f"EventRecordID > {last_record_id}]]"
        )

        return self._query_events(
            query,
            win32evtlog.EvtQueryForwardDirection,
            limit,
        )


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