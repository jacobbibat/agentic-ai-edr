import pytest
import xml.etree.ElementTree as ET

from collector.sysmon_parser import SysmonParser


@pytest.fixture
def sample_xml():
    """Provide a synthetic Sysmon process creation event."""

    return r"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon"/>
            <EventID>1</EventID>
            <EventRecordID>1001</EventRecordID>
            <Computer>WIN11-ENDPOINT</Computer>
            <Version>5</Version>
            <Level>4</Level>
            <Correlation/>
            <Execution ProcessID="100" ThreadID="200"/>
            <TimeCreated SystemTime="2026-11-25T10:00:00Z"/>
        </System>
        <EventData>
            <Data Name="UtcTime">2026-11-25 10:00:00.000</Data>
            <Data Name="ProcessId">1234</Data>
            <Data Name="Image">C:\Windows\System32\notepad.exe</Data>
            <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
            <Data Name="CommandLine">notepad.exe</Data>
            <Data Name="User">LAB\TestUser</Data>
            <Data Name="IntegrityLevel">Medium</Data>
        </EventData>
    </Event>
    """

# --------------------------------- TEST --------------------------------------------#
def test_parse_event_returns_dictionary(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert isinstance(event, dict)


def test_event_id(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert event["EventID"] == 1


def test_event_record_id(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert event["EventRecordID"] == 1001


def test_computer(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert event["Computer"] == "WIN11-ENDPOINT"


def test_process_information(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert event["ProcessId"] == "1234"
    assert event["Image"] == r"C:\Windows\System32\notepad.exe"
    assert event["ParentImage"] == r"C:\Windows\explorer.exe"
    assert event["CommandLine"] == "notepad.exe"
    assert event["User"] == r"LAB\TestUser"


def test_system_attributes(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert event["System"]["Execution"]["ProcessID"] == "100"
    assert event["System"]["Execution"]["ThreadID"] == "200"


def test_empty_system_element(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert event["System"]["Correlation"] is None


def test_raw_xml_preservation(sample_xml):
    parser = SysmonParser()
    event = parser.parse_event(sample_xml)

    assert event["RawXML"] == sample_xml


def test_dynamic_event_attributes(sample_xml):
    parser = SysmonParser()

    # Introduce an additional Sysmon attribute
    modified_xml = sample_xml.replace(
        "</EventData>",
        '<Data Name="AdditionalField">TestValue</Data></EventData>',
    )

    event = parser.parse_event(modified_xml)

    assert event["AdditionalField"] == "TestValue"


def test_malformed_xml():
    parser = SysmonParser()

    with pytest.raises(ET.ParseError):
        parser.parse_event("<Event>")