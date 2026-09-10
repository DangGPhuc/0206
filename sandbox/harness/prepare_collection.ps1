# =====================================================================
# 0206 - In-Guest Prepare Collection Script
# Discovers dropped files in C:\0206\work and extracts metadata (SHA256, size, path).
# Does NOT copy dropped executables directly.
# =====================================================================
$ErrorActionPreference = "SilentlyContinue"

$WorkDir = "C:\0206\work"
$TelemetryDir = "C:\0206\telemetry"

$dropped = @()
if (Test-Path $WorkDir) {
    $files = Get-ChildItem -Path $WorkDir -File -Recurse
    foreach ($f in $files) {
        $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
        $dropped += @{
            filename = $f.Name
            guest_path = $f.FullName
            size = $f.Length
            sha256 = $hash
        }
    }
}

$metadata = @{
    dropped_files = $dropped
    collection_time_utc = (Get-Date).ToUniversalTime().ToString("o")
}

$metadata | ConvertTo-Json -Depth 4 | Set-Content -Path "$TelemetryDir\execution_metadata.json" -Encoding UTF8
Write-Host "[+] Prepared execution metadata with $($dropped.Count) dropped file records."
