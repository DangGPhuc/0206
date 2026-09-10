# =====================================================================
# 0206 - In-Guest Sample Execution Script
# Executes target binary inside guest and records execution timing/exit code.
# =====================================================================
param (
    [Parameter(Mandatory=$true)]
    [string]$SamplePath,
    [string[]]$Arguments = @()
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Executing target sample: $SamplePath"
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $SamplePath
if ($Arguments.Count -gt 0) {
    $pinfo.Arguments = ($Arguments -join " ")
}
$pinfo.UseShellExecute = $false
$pinfo.WorkingDirectory = Split-Path $SamplePath

$process = [System.Diagnostics.Process]::Start($pinfo)
$pid_val = $process.Id

Write-Host "[*] Sample launched with PID $pid_val. Monitoring execution..."
# Bounded wait up to 120s
$exited = $process.WaitForExit(120000)
$sw.Stop()

$meta = @{
    sample = $SamplePath
    pid = $pid_val
    exited = $exited
    exit_code = if ($exited) { $process.ExitCode } else { "TIMEOUT" }
    duration_ms = $sw.ElapsedMilliseconds
}

Write-Host "[+] Sample execution completed."
$meta | ConvertTo-Json
