import xml.etree.ElementTree as ET

class SysmonParser:
    """Convert raw Sysmon XML into structured event dictionaries."""

    def __init__(self):
        self.namespace = {
            "ns" : "http://schemas.microsoft.com/win/2004/08/events/event"
        }

    def parse_system(self,root: ET.Element) -> dict:
        """Extract all attributes from Sysmon section"""

        system_data = {}

        system = root.find("ns:System", self.namespace)

        if system is None:
            return system_data

        for element in system:

            #Renove XML namespace from the tag name
            name = element.tag.split("}")[-1]

            #Extract XML attributes
            if element.attrib:
                system_data[name] = dict(element.attrib)

                #Preserve text if the element also contains text
                if element.text and element.text.strip():
                    system_data[name]["Text"] = element.text

            #Extract XML test
            else:
                system_data[name] = element.text

        return system_data

    def parse_event_data(self, root: ET.Element) -> dict:
        """Extract all attributes from the EventData section"""

        event_data = {}

        elements = root.findall(
            "ns:EventData/ns:Data",
            self.namespace,
        )

        for element in elements:
            #Retrieve attribute name and value
            name = element.get("Name")
            value = element.text

            if name is not None:
                event_data[name] = value

        return event_data

    def parse_event(self, event_xml: str) -> dict:
        """Convert a complete Sysmon XML event into a dictionary"""

        # Convert XML into an element tree
        root = ET.fromstring(event_xml)

        # Extract both sections
        system_data = self.parse_system(root)
        event_data = self.parse_event_data(root)

        # Combine the extracted information
        event = {
            **event_data,
            "EventID": int(system_data["EventID"]),
            "EventRecordID": int(system_data["EventRecordID"]),
            "Computer": system_data["Computer"],
            "System": system_data,
            "RawXML": event_xml,
        }

        return event

            
