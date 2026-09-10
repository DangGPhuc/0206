# =====================================================================
# 0206 - In-Guest Sample Execution Script
# Executes target binary inside guest and records execution timing/exit code.
# Captures guest PID immediately, tracks execution status truthfully.
# =====================================================================
param (
    [Parameter(Mandatory=$true)]
    [string]$SamplePath,
    [string[]]$Arguments = @(),
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

$meta = @{
    sample = $SamplePath
    launch_status = "UNKNOWN"
    execution_status = "UNKNOWN"
    guest_pid = $null
    exited = $false
    exit_code = $null
    timed_out = $false
    duration_ms = 0
    error = $null
}

if (-not (Test-Path $SamplePath)) {
    $meta.launch_status = "START_FAILED"
    $meta.execution_status = "START_FAILED"
    $meta.error = "Sample binary not found at $SamplePath"
    $meta | ConvertTo-Json
    exit 1
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $SamplePath
    if ($Arguments.Count -gt 0) {
        $pinfo.Arguments = ($Arguments -join " ")
    }
    $pinfo.UseShellExecute = $false
    $pinfo.WorkingDirectory = Split-Path $SamplePath

    $process = [System.Diagnostics.Process]::Start($pinfo)
    if (-not $process) {
        $meta.launch_status = "START_FAILED"
        $meta.execution_status = "START_FAILED"
        $meta.error = "Process.Start returned null"
        $meta | ConvertTo-Json
        exit 1
    }

    $meta.launch_status = "STARTED"
    $meta.guest_pid = $process.Id

    $timeoutMs = [Math]::Max(1000, $TimeoutSeconds * 1000)
    $exited = $process.WaitForExit($timeoutMs)
    $sw.Stop()

    $meta.duration_ms = $sw.ElapsedMilliseconds
    $meta.exited = [bool]$exited

    if ($exited) {
        $meta.execution_status = "EXITED"
        $meta.exit_code = $process.ExitCode
        $meta.timed_out = $false
    } else {
        $meta.execution_status = "TIMED_OUT"
        $meta.timed_out = $true
    }

} catch {
    $sw.Stop()
    $meta.launch_status = "START_FAILED"
    $meta.execution_status = "FAILED"
    $meta.error = $_.Exception.Message
    $meta.duration_ms = $sw.ElapsedMilliseconds
    $meta | ConvertTo-Json
    exit 1
}

$meta | ConvertTo-Json
exit 0
