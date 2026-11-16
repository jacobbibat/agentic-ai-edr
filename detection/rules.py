def is_powershell_process(process_name: str) -> bool:
    """Check whether process is Powershell."""
    return process_name.lower() in {
        "powershell.exe",
        "pwsh.exe"
    }