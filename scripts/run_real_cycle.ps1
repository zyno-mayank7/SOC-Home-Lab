# SOC Home Lab — Real System Logs Only (No Demo / Simulated Data)
param (
    [int]$MaxEvents = 50
)

$ErrorActionPreference = "Stop"
$LabRoot = Split-Path -Parent $PSScriptRoot

Write-Host "=== [1/5] Collecting Real Windows Events (PowerShell, System, Security) ===" -ForegroundColor Cyan
py "$LabRoot\scripts\collect_windows_events.py"

Write-Host "`n=== [2/5] Collecting Real Process & Port Snapshots ===" -ForegroundColor Cyan
py "$LabRoot\scripts\collect_hunts.py"

Write-Host "`n=== [3/5] Capturing Live Network Connections ===" -ForegroundColor Cyan
py "$LabRoot\scripts\network_logger.py"

Write-Host "`n=== [4/5] Ingesting Genuine Logs into SIEM ===" -ForegroundColor Cyan
py "$LabRoot\scripts\mini-siem.py" ingest

Write-Host "`n=== [5/5] SIEM Status & Summary ===" -ForegroundColor Cyan
py "$LabRoot\scripts\mini-siem.py" status

Write-Host "`n=== Ensuring SIEM Dashboard Server is Live ===" -ForegroundColor Green
py "$LabRoot\scripts\start-siem.py"

Write-Host "`n[OK] Pure real logs ingested! Dashboard: http://127.0.0.1:8443" -ForegroundColor Green
