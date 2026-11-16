from detection.rules import is_powershell_process

def test_detects_windows_powershell():
    assert is_powershell_process("powershell.exe")

def test_detects_windows_powershell_insensitive():
    assert is_powershell_process("PowerShell.EXE")

def test_ignore_unrelated_process():
    assert not is_powershell_process("notepad.exe")