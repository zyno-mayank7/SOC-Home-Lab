# SOC Home Lab — Full Local Run & Detection Cycle (PowerShell)
param (
    [int]$SimulatedEvents = 30
)

$ErrorActionPreference = "Stop"
$LabRoot = Split-Path -Parent $PSScriptRoot

Write-Host "=== [1/6] Initializing SIEM Database & Sigma Rules ===" -ForegroundColor Cyan
python "$LabRoot\scripts\mini-siem.py" init

Write-Host "`n=== [2/6] Running Atomic Red Team Emulation Tests ===" -ForegroundColor Cyan
python "$LabRoot\scripts\atomic_runner.py" run-all

Write-Host "`n=== [3/6] Generating Realistic Auth Logs ($SimulatedEvents events) ===" -ForegroundColor Cyan
python "$LabRoot\scripts\log_simulator.py" $SimulatedEvents

Write-Host "`n=== [4/7] Collecting Process & Port Snapshots ===" -ForegroundColor Cyan
python "$LabRoot\scripts\collect_hunts.py"

Write-Host "`n=== [5/7] Capturing Active Network Connections ===" -ForegroundColor Cyan
python "$LabRoot\scripts\network_logger.py"

Write-Host "`n=== [6/7] Ingesting Logs & Running Detection Engine ===" -ForegroundColor Cyan
python "$LabRoot\scripts\mini-siem.py" ingest

Write-Host "`n=== [7/7] SIEM Status & Summary ===" -ForegroundColor Cyan
python "$LabRoot\scripts\mini-siem.py" status

Write-Host "`n=== Ensuring SIEM Dashboard Server is Live ===" -ForegroundColor Green
python "$LabRoot\scripts\start-siem.py"

Write-Host "`n[OK] Done! Open the dashboard at: http://127.0.0.1:8443" -ForegroundColor Green
