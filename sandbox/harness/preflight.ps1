# =====================================================================
# 0206 - In-Guest Preflight Readiness Script
# Verifies standard directories, resolves tool paths, and checks network policy.
# CRITICAL SAFETY: NEVER executes untrusted code or samples.
# =====================================================================
param (
    [string]$TraceId = "",
    [string]$NetworkMode = "ISOLATED",
    [string]$SimulatedEndpoint = "192.168.56.1"
)

$ErrorActionPreference = "Stop"

$report = @{
    status = "READY"
    tools = @{}
    network = @{}
    errors = @()
}

try {
    # 1. Base directory provisioning
    $baseDirs = @("C:\0206\tools", "C:\0206\scripts", "C:\0206\sessions")
    foreach ($d in $baseDirs) {
        if (-not (Test-Path $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }

    if ($TraceId -ne "") {
        $sessWork = "C:\0206\sessions\$TraceId\work"
        $sessTelem = "C:\0206\sessions\$TraceId\telemetry"
        if (-not (Test-Path $sessWork)) { New-Item -ItemType Directory -Path $sessWork -Force | Out-Null }
        if (-not (Test-Path $sessTelem)) { New-Item -ItemType Directory -Path $sessTelem -Force | Out-Null }
    }

    # 2. Tool Resolution
    # A. Procmon
    $procmonCandidates = @(
        "C:\0206\tools\procmon.exe",
        "C:\Tools\procmon\procmon.exe",
        "C:\Program Files\Sysinternals\procmon.exe",
        "C:\ProgramData\chocolatey\bin\procmon.exe"
    )
    $procmonPath = $null
    foreach ($c in $procmonCandidates) {
        if (Test-Path $c) { $procmonPath = $c; break }
    }
    if (-not $procmonPath) {
        $cmd = Get-Command "procmon.exe" -ErrorAction SilentlyContinue
        if ($cmd) { $procmonPath = $cmd.Source }
    }
    $procmonVer = if ($procmonPath) { (Get-Item $procmonPath).VersionInfo.ProductVersion } else { $null }
    $report.tools["procmon"] = @{
        installed = [bool]$procmonPath
        path = $procmonPath
        version = $procmonVer
    }

    # B. tshark / Wireshark
    $tsharkCandidates = @(
        "C:\0206\tools\tshark.exe",
        "C:\Program Files\Wireshark\tshark.exe",
        "C:\Program Files (x86)\Wireshark\tshark.exe",
        "C:\ProgramData\chocolatey\bin\tshark.exe"
    )
    $tsharkPath = $null
    foreach ($c in $tsharkCandidates) {
        if (Test-Path $c) { $tsharkPath = $c; break }
    }
    if (-not $tsharkPath) {
        $cmd = Get-Command "tshark.exe" -ErrorAction SilentlyContinue
        if ($cmd) { $tsharkPath = $cmd.Source }
    }
    $tsharkVer = if ($tsharkPath) { (Get-Item $tsharkPath).VersionInfo.ProductVersion } else { $null }
    $report.tools["tshark"] = @{
        installed = [bool]$tsharkPath
        path = $tsharkPath
        version = $tsharkVer
    }

    # C. Regshot
    $regshotCandidates = @(
        "C:\0206\tools\regshot-x64.exe",
        "C:\0206\tools\regshot.exe",
        "C:\Tools\regshot\regshot-x64.exe",
        "C:\Tools\regshot\regshot.exe"
    )
    $regshotPath = $null
    foreach ($c in $regshotCandidates) {
        if (Test-Path $c) { $regshotPath = $c; break }
    }
    if (-not $regshotPath) {
        $cmd = Get-Command "regshot-x64.exe" -ErrorAction SilentlyContinue
        if ($cmd) { $regshotPath = $cmd.Source }
    }
    $regshotVer = if ($regshotPath) { (Get-Item $regshotPath).VersionInfo.ProductVersion } else { $null }
    # Regshot automation check: 1.9.0+ command line mode /s /c
    $regshotAutomated = $false
    if ($regshotPath -and (Test-Path $regshotPath)) {
        # Regshot command-line support is limited/unreliable in standard GUI builds
        $regshotAutomated = $false
    }
    $report.tools["regshot"] = @{
        installed = [bool]$regshotPath
        path = $regshotPath
        version = $regshotVer
        automated = $regshotAutomated
    }

    # Save resolved config for subsequent scripts
    $toolsConfig = @{
        procmon = $procmonPath
        tshark = $tsharkPath
        regshot = $regshotPath
        regshot_automated = $regshotAutomated
    }
    $toolsConfig | ConvertTo-Json | Set-Content -Path "C:\0206\tools_config.json" -Encoding UTF8

    # 3. In-Guest Network Verification
    $defaultRoutes = @()
    try {
        $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($routes) {
            foreach ($r in $routes) {
                $defaultRoutes += $r.NextHop
            }
        }
    } catch {}

    # External egress negative probe (strict 2s timeout)
    $egressDetected = $false
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("1.1.1.1", 80, $null, $null)
        $wh = $iar.AsyncWaitHandle
        $connected = $wh.WaitOne(2000, $false)
        if ($connected) {
            $client.EndConnect($iar)
            $egressDetected = $true
        }
        $client.Close()
    } catch {
        $egressDetected = $false
    }

    # Simulated service positive probe
    $simulatedOk = $false
    if ($NetworkMode -eq "SIMULATED_INTERNET") {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($SimulatedEndpoint, 80, $null, $null)
            $connected = $iar.AsyncWaitHandle.WaitOne(2000, $false)
            if ($connected) {
                $client.EndConnect($iar)
                $simulatedOk = $true
            }
            $client.Close()
        } catch {
            $simulatedOk = $false
        }
    }

    $report.network = @{
        mode = $NetworkMode
        default_gateways = $defaultRoutes
        egress_detected = $egressDetected
        simulated_services_verified = $simulatedOk
    }

    # Validate fail-closed conditions
    if ($NetworkMode -in @("ISOLATED", "HOST_ONLY") -and $egressDetected) {
        $report.status = "FAILED"
        $report.errors += "LEAK_DETECTED: Guest successfully connected to external endpoint 1.1.1.1:80."
    }
    if ($NetworkMode -eq "SIMULATED_INTERNET" -and -not $simulatedOk) {
        $report.status = "FAILED"
        $report.errors += "SIMULATED_UNVERIFIED: Simulated service at $SimulatedEndpoint did not respond."
    }

} catch {
    $report.status = "FAILED"
    $report.errors += $_.Exception.Message
}

$jsonOut = $report | ConvertTo-Json -Depth 4
Write-Output $jsonOut

if ($report.status -ne "READY") {
    exit 1
}
exit 0
