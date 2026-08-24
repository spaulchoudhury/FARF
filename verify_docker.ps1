# verify_docker.ps1
# Run this from the repo root (the folder containing federation_bus.py)
# AFTER `docker compose -f docker/docker-compose.yml up --build` is running
# in another terminal (or after it has finished its startup logs).
#
# It hits the federation-bus container's HTTP API from the host and saves
# a timestamped log you can paste back into the thesis chat.
#
# NOTE: this script was authored and syntax-reviewed by hand -- there is no
# PowerShell available in the sandbox this thesis was written in to execute
# it directly, so it has not been run end-to-end before being handed to you.
# If any line errors, paste the exact error back and it'll get fixed.

$ErrorActionPreference = "Stop"
$logFile = "docker_verification_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Section($title) {
    $line = "`n=== $title ===`n"
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $logFile -Value $line
}

function Invoke-AndLog($url, $label) {
    Write-Section $label
    try {
        $response = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 5
        $json = $response | ConvertTo-Json -Depth 5
        Write-Host $json
        Add-Content -Path $logFile -Value $json
    } catch {
        $msg = "ERROR calling $url : $_"
        Write-Host $msg -ForegroundColor Red
        Add-Content -Path $logFile -Value $msg
    }
}

Write-Host "FARF Docker verification -- logging to $logFile" -ForegroundColor Green

Invoke-AndLog "http://localhost:8000/health" "GET /health"
Invoke-AndLog "http://localhost:8000/status" "GET /status"
Invoke-AndLog "http://localhost:8000/fars"   "GET /fars"

Write-Section "Container list (docker compose ps)"
$psOutput = docker compose -f docker/docker-compose.yml ps
Write-Host $psOutput
Add-Content -Path $logFile -Value $psOutput

Write-Host "`nDone. Open $logFile and paste its contents back into the thesis chat." -ForegroundColor Green
