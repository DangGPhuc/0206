# =====================================================================
# 0206 - In-Guest Preflight Readiness Script
# Verifies standard directories and tools inside the Windows analysis VM.
# =====================================================================
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] 0206 Guest Preflight: Verifying analysis directories..."
$dirs = @("C:\0206\tools", "C:\0206\work", "C:\0206\telemetry", "C:\0206\scripts")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

Write-Host "[*] Checking telemetry tools..."
$tools = @{
    "Procmon" = "C:\Tools\procmon\procmon.exe"
    "Wireshark_tshark" = "C:\Program Files\Wireshark\tshark.exe"
    "Regshot" = "C:\Tools\regshot\regshot-x64.exe"
}

$status = @{}
foreach ($name in $tools.Keys) {
    $path = $tools[$name]
    $installed = (Test-Path $path) -or (Get-Command $name -ErrorAction SilentlyContinue)
    $status[$name] = [bool]$installed
}

Write-Host "[+] 0206 Guest Preflight Complete."
$status | ConvertTo-Json
