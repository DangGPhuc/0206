# =====================================================================
# 0206 - In-Guest Start Telemetry Script
# Launches Procmon, tshark (PCAP), and initial Regshot baseline snapshot.
# Fails closed if any required enabled collector fails to start.
# =====================================================================
param (
    [string]$TelemetryDir = "C:\0206\telemetry",
    [switch]$EnableProcmon = $true,
    [switch]$EnablePcap = $true,
    [switch]$EnableRegshot = $false,
    [switch]$RequireProcmon = $true,
    [switch]$RequirePcap = $true,
    [switch]$RequireRegshot = $false
)

$ErrorActionPreference = "Stop"

$report = @{
    status = "SUCCESS"
    collectors = @{}
    errors = @()
}

try {
    if (-not (Test-Path $TelemetryDir)) {
        New-Item -ItemType Directory -Path $TelemetryDir -Force | Out-Null
    }

    # Load resolved tool configurations
    $toolsConfig = @{}
    if (Test-Path "C:\0206\tools_config.json") {
        $toolsConfig = Get-Content "C:\0206\tools_config.json" -Raw | ConvertFrom-Json
    }

    # 1. Procmon Launch
    if ($EnableProcmon) {
        $procmonPath = if ($toolsConfig.procmon) { $toolsConfig.procmon } else { "C:\Tools\procmon\procmon.exe" }
        if (-not (Test-Path $procmonPath)) {
            $cmd = Get-Command "procmon.exe" -ErrorAction SilentlyContinue
            if ($cmd) { $procmonPath = $cmd.Source }
        }

        if ($procmonPath -and (Test-Path $procmonPath)) {
            $procArgs = "/BackingFile `"$TelemetryDir\procmon.pml`" /Quiet /Minimized /AcceptEula"
            $p = Start-Process -FilePath $procmonPath -ArgumentList $procArgs -PassThru
            Start-Sleep -Milliseconds 1500
            $running = (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) -ne $null
            $report.collectors["procmon"] = @{
                started = $running
                pid = $p.Id
                path = $procmonPath
                required = [bool]$RequireProcmon
            }
            if (-not $running -and $RequireProcmon) {
                $report.status = "FAILED"
                $report.errors += "Required collector Procmon failed to maintain running state."
            }
        } else {
            $report.collectors["procmon"] = @{
                started = $false
                pid = $null
                path = $procmonPath
                required = [bool]$RequireProcmon
                error = "Procmon executable not found."
            }
            if ($RequireProcmon) {
                $report.status = "FAILED"
                $report.errors += "Required collector Procmon executable not found."
            }
        }
    }

    # 2. tshark Network Capture
    if ($EnablePcap) {
        $tsharkPath = if ($toolsConfig.tshark) { $toolsConfig.tshark } else { "C:\Program Files\Wireshark\tshark.exe" }
        if (-not (Test-Path $tsharkPath)) {
            $cmd = Get-Command "tshark.exe" -ErrorAction SilentlyContinue
            if ($cmd) { $tsharkPath = $cmd.Source }
        }

        if ($tsharkPath -and (Test-Path $tsharkPath)) {
            $tsharkArgs = "-i 1 -w `"$TelemetryDir\network.pcap`" -a duration:300"
            $p = Start-Process -FilePath $tsharkPath -ArgumentList $tsharkArgs -PassThru
            Start-Sleep -Milliseconds 1500
            $running = (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) -ne $null
            $report.collectors["tshark"] = @{
                started = $running
                pid = $p.Id
                path = $tsharkPath
                required = [bool]$RequirePcap
            }
            if (-not $running -and $RequirePcap) {
                $report.status = "FAILED"
                $report.errors += "Required collector tshark failed to maintain running state."
            }
        } else {
            $report.collectors["tshark"] = @{
                started = $false
                pid = $null
                path = $tsharkPath
                required = [bool]$RequirePcap
                error = "tshark executable not found."
            }
            if ($RequirePcap) {
                $report.status = "FAILED"
                $report.errors += "Required collector tshark executable not found."
            }
        }
    }

    # 3. Regshot Baseline
    if ($EnableRegshot) {
        $regshotPath = if ($toolsConfig.regshot) { $toolsConfig.regshot } else { "C:\Tools\regshot\regshot-x64.exe" }
        $automated = if ($toolsConfig.regshot_automated -ne $null) { $toolsConfig.regshot_automated } else { $false }
        if ($automated -and $regshotPath -and (Test-Path $regshotPath)) {
            $p = Start-Process -FilePath $regshotPath -ArgumentList "/s `"$TelemetryDir\shot1.bin`"" -Wait -PassThru
            $shotOk = Test-Path "$TelemetryDir\shot1.bin"
            $report.collectors["regshot"] = @{
                started = $shotOk
                status = if ($shotOk) { "BASELINE_CAPTURED" } else { "FAILED" }
                required = [bool]$RequireRegshot
            }
            if (-not $shotOk -and $RequireRegshot) {
                $report.status = "FAILED"
                $report.errors += "Required Regshot baseline snapshot failed."
            }
        } else {
            $report.collectors["regshot"] = @{
                started = $false
                status = "PARTIAL/UNAVAILABLE"
                required = [bool]$RequireRegshot
                details = "Regshot headless CLI automation not verified."
            }
            if ($RequireRegshot) {
                $report.status = "FAILED"
                $report.errors += "Required collector Regshot is unavailable for automation."
            }
        }
    }

} catch {
    $report.status = "FAILED"
    $report.errors += $_.Exception.Message
}

$jsonOut = $report | ConvertTo-Json -Depth 4
Write-Output $jsonOut

if ($report.status -ne "SUCCESS") {
    exit 1
}
exit 0
