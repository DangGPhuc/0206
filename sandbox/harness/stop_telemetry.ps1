# =====================================================================
# 0206 - In-Guest Stop Telemetry Script
# Stops Procmon and converts PML to CSV; stops tshark; diffs registry with Regshot.
# =====================================================================
$ErrorActionPreference = "SilentlyContinue"
$TelemetryDir = "C:\0206\telemetry"

Write-Host "[*] Terminating Procmon and exporting CSV..."
$procmon = "C:\Tools\procmon\procmon.exe"
if (Test-Path $procmon) {
    Start-Process -FilePath $procmon -ArgumentList "/Terminate" -Wait
    Start-Sleep -Seconds 2
    Start-Process -FilePath $procmon -ArgumentList "/OpenLog $TelemetryDir\procmon.pml /SaveAs $TelemetryDir\procmon.csv" -Wait
}

Write-Host "[*] Stopping network packet capture..."
Stop-Process -Name tshark -Force
Stop-Process -Name dumpcap -Force

Write-Host "[*] Capturing second registry shot and computing diff..."
$regshot = "C:\Tools\regshot\regshot-x64.exe"
if (Test-Path $regshot) {
    Start-Process -FilePath $regshot -ArgumentList "/s $TelemetryDir\shot2.bin" -Wait
    Start-Process -FilePath $regshot -ArgumentList "/c $TelemetryDir\shot1.bin $TelemetryDir\shot2.bin $TelemetryDir\regshot.txt" -Wait
}

Write-Host "[+] Telemetry collection halted and formatted."
