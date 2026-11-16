from pathlib import PureWindowsPath

def is_powershell_process(process_name: str) -> bool:
    """Check whether process is Powershell."""
    return process_name.lower() in {
        "powershell.exe",
        "pwsh.exe"
    }

# -------------------------------------------------------------- #

def is_word_powershell(event: dict) -> bool:
    """Detect Microsoft word launching Powershell."""

    if event.get("EventID") != 1:
        return False

    parent_path = event.get("ParentImage", "")
    child_path = event.get("Image", "")

    parent_name = PureWindowsPath(parent_path).name.lower()
    child_name = PureWindowsPath(child_path).name.lower()

    return (
        parent_name == "winword.exe"
        and child_name in {"powershell.exe", "pwshe.exe"}
    )

# -------------------------------------------------------------- #

def generate_alert(event:dict) -> dict | None:
    """Generate an alert when a detection rule matches"""

    if not is_word_powershell:
        return None

    return {
        "rule_id": "EDR-001",
        "rule_name": "Microsoft Word creates Powershell",
        "severity": "High",
        "status": "New",
        "timestamp": event.get("UtcTime"),
        "endpoint": event.get("Computer"),
        "evidence": {
            "parent_process": event.get("ParentImage"),
            "child_process": event.get("Image"),
            "command_line": event.get("CommandLine"),
        },
    }