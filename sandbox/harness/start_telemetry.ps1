# =====================================================================
# 0206 - In-Guest Start Telemetry Script
# Launches Procmon, tshark (PCAP), and initial Regshot baseline snapshot.
# =====================================================================
$ErrorActionPreference = "SilentlyContinue"

$TelemetryDir = "C:\0206\telemetry"
if (-not (Test-Path $TelemetryDir)) {
    New-Item -ItemType Directory -Path $TelemetryDir -Force | Out-Null
}

Write-Host "[*] Starting Procmon capture..."
$procmon = "C:\Tools\procmon\procmon.exe"
if (Test-Path $procmon) {
    Start-Process -FilePath $procmon -ArgumentList "/BackingFile $TelemetryDir\procmon.pml /Quiet /Minimized /AcceptEula"
}

Write-Host "[*] Starting tshark network capture..."
$tshark = "C:\Program Files\Wireshark\tshark.exe"
if (Test-Path $tshark) {
    Start-Process -FilePath $tshark -ArgumentList "-i 1 -w $TelemetryDir\network.pcap -a duration:300"
}

Write-Host "[*] Capturing initial registry baseline (1st shot)..."
$regshot = "C:\Tools\regshot\regshot-x64.exe"
if (Test-Path $regshot) {
    Start-Process -FilePath $regshot -ArgumentList "/s $TelemetryDir\shot1.bin" -Wait
}

Write-Host "[+] Telemetry collection initialized."
