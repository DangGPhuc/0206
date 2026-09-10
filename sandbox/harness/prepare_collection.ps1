# =====================================================================
# 0206 - In-Guest Prepare Collection Script
# Discovers dropped files in session work directory and extracts metadata (SHA256, size, path).
# Never copies executable binaries directly.
# =====================================================================
param (
    [string]$WorkDir = "C:\0206\work",
    [string]$TelemetryDir = "C:\0206\telemetry",
    [string]$TraceId = "",
    [string]$SampleSha256 = ""
)

$ErrorActionPreference = "Stop"

$dropped = @()
if (Test-Path $WorkDir) {
    $files = Get-ChildItem -Path $WorkDir -File -Recurse -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
        $dropped += @{
            filename = $f.Name
            guest_path = $f.FullName
            size = $f.Length
            sha256 = $hash
        }
    }
}

$metadata = @{
    trace_id = $TraceId
    sample_sha256 = $SampleSha256
    collection_time_utc = (Get-Date).ToUniversalTime().ToString("o")
    dropped_files = $dropped
}

$metaJson = $metadata | ConvertTo-Json -Depth 4
Set-Content -Path "$TelemetryDir\execution_metadata.json" -Value $metaJson -Encoding UTF8
Write-Output $metaJson
exit 0
