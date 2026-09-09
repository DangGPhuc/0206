"""
0206 - Windows REM Workstation Provisioner
Phase 13: Generates reproducible provisioning scripts for legal lab installation.
Outputs Chocolatey and Winget scripts without bundling any proprietary binaries.
"""
from pathlib import Path
from typing import Dict, List, Any


class WindowsLabProvisioner:
    """Generates automated lab setup scripts for Windows malware triage VMs."""

    CHOCO_PACKAGES = [
        "sysinternals",
        "procmon",
        "processhacker",
        "regshot",
        "wireshark",
        "x64dbg",
        "pestudio",
        "yara",
        "radare2",
        "7zip",
        "python3"
    ]

    WINGET_PACKAGES = [
        "Microsoft.Sysinternals.ProcessMonitor",
        "Microsoft.Sysinternals.ProcessExplorer",
        "Microsoft.Sysinternals.Autoruns",
        "WiresharkFoundation.Wireshark",
        "WinsiderSeminars.SystemInformer",
        "Python.Python.3.11"
    ]

    @classmethod
    def generate_powershell_script(cls) -> str:
        """Generates a complete, audited PowerShell provisioning script."""
        choco_list = " ".join(cls.CHOCO_PACKAGES)
        script = f"""# =====================================================================
# 0206 - Windows REM Workstation Automated Lab Provisioning Script
# FOR610-style triage workstation configuration
# Run inside an isolated Windows 10/11 Analysis Virtual Machine as Administrator.
# =====================================================================

Write-Host "[*] 0206 Analysis Lab - Initiating Windows REM Provisioning..." -ForegroundColor Cyan

# 1. Install Chocolatey Package Manager if missing
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {{
    Write-Host "[*] Installing Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}}

# 2. Install Standard Forensic & Reverse Engineering Tools
Write-Host "[*] Installing Forensic Tools via Chocolatey..." -ForegroundColor Yellow
choco install -y {choco_list}

# 3. Create Tools Workspace Directory
$ToolsDir = "C:\\Tools"
if (-not (Test-Path $ToolsDir)) {{
    New-Item -Path $ToolsDir -ItemType Directory -Force | Out-Null
}}

# 4. Disable Windows Defender real-time monitoring inside isolated VM
Write-Host "[*] Configuring analysis environment safety policies..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

Write-Host "[+] 0206 Windows REM Workstation Provisioning Complete!" -ForegroundColor Green
Write-Host "[+] Take a baseline snapshot now before malware detonation." -ForegroundColor Magenta
"""
        return script

    @classmethod
    def get_chocolatey_command(cls) -> str:
        """Returns the one-line chocolatey install command."""
        return f"choco install -y {' '.join(cls.CHOCO_PACKAGES)}"

    @classmethod
    def export_script(cls, target_path: Path) -> Path:
        """Exports the provisioning script to disk."""
        target_path = Path(target_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(cls.generate_powershell_script(), encoding="utf-8")
        return target_path

