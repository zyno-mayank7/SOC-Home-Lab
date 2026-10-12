#!/usr/bin/env python3
"""
collect_windows_events.py — Collect genuine Windows Event Logs into logs/windows_events.log

Gathers real event telemetry from:
  - Microsoft-Windows-PowerShell/Operational (Event 4104: Scriptblock execution)
  - System (Event 7045: Service installation, etc.)
  - Security (Event 4624: Logon, 4625: Failed Logon, 4720: User creation) [requires Admin for Security log]

Usage:
  python scripts/collect_windows_events.py          # Collect recent events snapshot (default: 30)
  python scripts/collect_windows_events.py --watch  # Live continuous watcher (polls every 5s)
"""
import os
import sys
import time
import json
import subprocess
from datetime import datetime
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = LAB_ROOT / 'logs' / 'windows_events.log'
STATE_FILE = LAB_ROOT / 'var' / 'winevent_state.json'
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding='utf-8'))
        except Exception:
            pass
    return {}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state), encoding='utf-8')


def query_windows_events(max_events=30, last_record_ids=None):
    """Query real Windows Event logs via PowerShell Get-WinEvent."""
    last_record_ids = last_record_ids or {}

    ps_script = '''
    $max = __MAX_EVENTS__
    $events = @()

    # Channels to query
    $channels = @(
        "Microsoft-Windows-PowerShell/Operational",
        "System"
    )

    # Try Security channel if permitted (requires Admin)
    try {
        $test = Get-WinEvent -LogName "Security" -MaxEvents 1 -ErrorAction Stop
        $channels += "Security"
    } catch {
        # Non-admin: skip Security log gracefully
    }

    foreach ($ch in $channels) {
        try {
            $q = Get-WinEvent -LogName $ch -MaxEvents $max -ErrorAction SilentlyContinue
            if ($q) {
                $events += $q | ForEach-Object {
                    $cleanMsg = ($_.Message -replace '[\r\n]+', ' ').Trim()
                    if ($cleanMsg.Length -gt 400) { $cleanMsg = $cleanMsg.Substring(0, 400) + '...' }
                    @{
                        Channel = $ch
                        Id = $_.Id
                        RecordId = $_.RecordId
                        TimeCreated = $_.TimeCreated.ToString("MMM dd HH:mm:ss")
                        Machine = $env:COMPUTERNAME
                        Provider = $_.ProviderName
                        Message = $cleanMsg
                    }
                }
            }
        } catch {}
    }

    $events | ConvertTo-Json -Compress
    '''.replace('__MAX_EVENTS__', str(max_events))

    cmd = ['powershell', '-NoProfile', '-Command', ps_script]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = res.stdout.strip()
        if not out:
            return []
        data = json.loads(out)
        if isinstance(data, dict):
            return [data]
        elif isinstance(data, list):
            return data
    except Exception as e:
        print(f"[!] Error querying Windows events: {e}")
    return []


def write_events_to_log(events, state):
    logged_count = 0
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        for ev in reversed(events):  # chronological order
            channel = ev.get('Channel', 'Windows')
            rec_id = ev.get('RecordId')
            key = f"{channel}:{rec_id}"

            # Skip if we already logged this record
            if key in state:
                continue

            state[key] = True

            ts = ev.get('TimeCreated', datetime.now().strftime('%b %d %H:%M:%S'))
            machine = ev.get('Machine', 'win-host')
            provider = ev.get('Provider', 'Windows').replace(' ', '_')
            event_id = ev.get('Id', 0)
            msg = ev.get('Message', '')

            # Standard syslog format compatible with mini-siem
            line = f"{ts} {machine} {provider}[{event_id}]: {msg}"
            f.write(line + '\n')
            logged_count += 1

    # Keep state compact (last 2000 entries)
    if len(state) > 2000:
        keys = list(state.keys())[-1000:]
        state = {k: True for k in keys}

    return logged_count, state


def snapshot(max_events=30):
    print(f"[+] Querying real Windows events (PowerShell, System, Security)...")
    state = load_state()
    events = query_windows_events(max_events=max_events)
    count, state = write_events_to_log(events, state)
    save_state(state)
    print(f"[+] Found {len(events)} events, logged {count} new entries to {LOG_FILE}")
    print(f"[+] Ingest into SIEM with: py scripts/mini-siem.py ingest")


def watch(interval=5):
    print(f"[+] Watching Windows Event logs continuously (every {interval}s)...")
    print(f"[+] Logging new events to: {LOG_FILE} (Ctrl+C to stop)")
    state = load_state()
    try:
        while True:
            events = query_windows_events(max_events=20)
            count, state = write_events_to_log(events, state)
            save_state(state)
            if count > 0:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Logged {count} new real Windows events")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[+] Stopped watcher.")


if __name__ == '__main__':
    if '--watch' in sys.argv:
        watch()
    else:
        snapshot()
