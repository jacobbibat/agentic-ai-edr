from pathlib import PureWindowsPath
from detection.alert_builder import AlertBuilder


def is_powershell_process(process_name: str) -> bool:
    """Check whether process is Powershell."""
    return process_name.lower() in {"powershell.exe", "pwsh.exe"}


# -------------------------------------------------------------- #


def is_word_powershell(event: dict) -> bool:
    """Detect Microsoft word launching Powershell."""

    if event.get("EventID") != 1:
        return False

    parent_path = event.get("ParentImage", "")
    child_path = event.get("Image", "")

    parent_name = PureWindowsPath(parent_path).name.lower()
    child_name = PureWindowsPath(child_path).name.lower()

    return parent_name == "winword.exe" and child_name in {
        "powershell.exe",
        "pwshe.exe",
    }


def is_encoded_powershell(event: dict) -> bool:
    """Detect PowerShell using an encoded command."""

    # Only examine Sysmon process creation events
    if event.get("EventID") != 1:
        return False

    # Retrieve the process path and its command line
    process_path = event.get("Image", "")
    command_line = event.get("CommandLine", "")

    # Extract the executable name and lower it
    process_name = PureWindowsPath(process_path).name.lower()

    # Check if it is powershell process
    if process_name not in {"powershell.exe", "pwsh.exe"}:
        return False

    # Split the command line into individual arguements
    arguments = command_line.lower().split()

    # Detect supported encoded-command parameter forms
    # Detect supported encoded-command parameter forms.
    encoded_parameters = {
        "-encodedcommand",
        "-enc",
        "-e",
    }

    return any(argument in encoded_parameters for argument in arguments)


# -------------------------------------------------------------- #


def generate_alerts(event: dict) -> dict | None:
    """Generate an alert when a detection rule matches"""

    alerts = []

    # Create builder once for this event
    builder = AlertBuilder(event)

    if is_word_powershell(event):
        alerts.append(
            builder.build(
                rule_id="EDR-001",
                rule_name="Microsoft Word spawning PowerShell",
                severity="High",
            )
        )

    elif is_encoded_powershell(event):
        alerts.append(
            builder.build(
                rule_id="EDR-002",
                rule_name="Encoded PowerShell execution",
                severity="Medium",
            )
        )

    return alerts
