# =====================================================================
# 0206 - In-Guest Stop Telemetry Script
# Stops Procmon and exports PML to CSV; stops tshark; diffs registry with Regshot.
# Verifies expected output files exist before returning.
# =====================================================================
param (
    [string]$TelemetryDir = "C:\0206\telemetry"
)

$ErrorActionPreference = "Stop"

$report = @{
    status = "SUCCESS"
    artifacts = @{}
    errors = @()
}

$toolsConfig = @{}
if (Test-Path "C:\0206\tools_config.json") {
    try {
        $toolsConfig = Get-Content "C:\0206\tools_config.json" -Raw | ConvertFrom-Json
    } catch {}
}

# 1. Stop Procmon and export to CSV
try {
    $procmonPath = if ($toolsConfig.procmon) { $toolsConfig.procmon } else { "C:\Tools\procmon\procmon.exe" }
    if (Test-Path $procmonPath) {
        Start-Process -FilePath $procmonPath -ArgumentList "/Terminate" -Wait
        Start-Sleep -Milliseconds 1500
        $pmlFile = "$TelemetryDir\procmon.pml"
        $csvFile = "$TelemetryDir\procmon.csv"
        if (Test-Path $pmlFile) {
            Start-Process -FilePath $procmonPath -ArgumentList "/OpenLog `"$pmlFile`" /SaveAs `"$csvFile`"" -Wait
        }
    }
} catch {
    $report.errors += "Procmon termination error: $_"
}

# 2. Terminate network capture
try {
    Stop-Process -Name tshark -Force -ErrorAction SilentlyContinue
    Stop-Process -Name dumpcap -Force -ErrorAction SilentlyContinue
} catch {}

# 3. Capture second registry shot and compute diff if shot1 exists
try {
    $regshotPath = if ($toolsConfig.regshot) { $toolsConfig.regshot } else { "C:\Tools\regshot\regshot-x64.exe" }
    $shot1 = "$TelemetryDir\shot1.bin"
    $shot2 = "$TelemetryDir\shot2.bin"
    $regOut = "$TelemetryDir\regshot.txt"
    if ((Test-Path $shot1) -and (Test-Path $regshotPath)) {
        Start-Process -FilePath $regshotPath -ArgumentList "/s `"$shot2`"" -Wait
        Start-Process -FilePath $regshotPath -ArgumentList "/c `"$shot1`" `"$shot2`" `"$regOut`"" -Wait
    }
} catch {
    $report.errors += "Regshot diff error: $_"
}

# 4. Report artifact presence
$report.artifacts["procmon_csv"] = Test-Path "$TelemetryDir\procmon.csv"
$report.artifacts["network_pcap"] = Test-Path "$TelemetryDir\network.pcap"
$report.artifacts["regshot_txt"] = Test-Path "$TelemetryDir\regshot.txt"

$jsonOut = $report | ConvertTo-Json -Depth 4
Write-Output $jsonOut
exit 0
