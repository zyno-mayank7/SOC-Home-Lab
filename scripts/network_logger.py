#!/usr/bin/env python3
"""
network_logger.py — Capture active network connections without requiring Administrator rights.
Queries TCP/UDP connections on Windows via PowerShell Get-NetTCPConnection,
correlates them with active process names, and appends to logs/network.log.

Usage:
  python scripts/network_logger.py          # Run a single snapshot (default: 30 connections)
  python scripts/network_logger.py --watch  # Continuous monitor mode (polls every 3 seconds)
"""
import os
import sys
import time
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = LAB_ROOT / 'logs' / 'network.log'
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

seen_connections = set()


def get_active_connections():
    """Query current network connections without requiring Administrator privileges."""
    cmd = [
        'powershell', '-NoProfile', '-Command',
        '''
        $procs = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs["$($_.Id)"] = $_.ProcessName }
        Get-NetTCPConnection -State Established,Listen,TimeWait,CloseWait -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            ForEach-Object {
                $pidStr = "$($_.OwningProcess)"
                $pName = if ($procs.ContainsKey($pidStr)) { $procs[$pidStr] } else { "System/Unknown" }
                @{
                    Local = "$($_.LocalAddress):$($_.LocalPort)"
                    Remote = "$($_.RemoteAddress):$($_.RemotePort)"
                    State = "$($_.State)"
                    Pid = $_.OwningProcess
                    Process = $pName
                }
            } | ConvertTo-Json -Compress
        '''
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if not res.stdout.strip():
            return []
        data = json.loads(res.stdout)
        if isinstance(data, dict):
            return [data]
        elif isinstance(data, list):
            return data
    except Exception as e:
        print(f"[!] Error reading connections: {e}")
    return []


def log_connections(connections):
    """Write connections to logs/network.log in syslog-compatible format."""
    now_ts = datetime.now().strftime('%b %d %H:%M:%S')
    logged_count = 0
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        for c in connections:
            local = c.get('Local', '')
            remote = c.get('Remote', '')
            proc = c.get('Process', 'Unknown')
            pid = c.get('Pid', 0)
            state = c.get('State', 'Unknown')

            # Deduplicate within same session
            conn_key = (local, remote, proc, state)
            if conn_key in seen_connections:
                continue
            seen_connections.add(conn_key)

            # Format in standard syslog format compatible with mini-siem
            line = f"{now_ts} soc-lab netwatch[{pid}]: TCP connection state={state} process={proc} local={local} remote={remote}"
            f.write(line + '\n')
            logged_count += 1
    return logged_count


def snapshot():
    print(f"[+] Querying network connections (No Admin Required)...")
    conns = get_active_connections()
    count = log_connections(conns)
    print(f"[+] Found {len(conns)} active connections, logged {count} new entries to {LOG_FILE}")
    print(f"[+] Sample connections:")
    for c in conns[:5]:
        print(f"    [{c.get('Process')}:{c.get('Pid')}] {c.get('Local')} -> {c.get('Remote')} ({c.get('State')})")
    print(f"\n[+] Ingest into SIEM with: python scripts/mini-siem.py ingest")


def watch(interval=3):
    print(f"[+] Starting network connection monitor on {LOG_FILE} (Ctrl+C to stop)...")
    try:
        while True:
            conns = get_active_connections()
            count = log_connections(conns)
            if count > 0:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] Logged {count} new connection(s)")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[+] Stopped network monitor.")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ('--watch', '-w'):
        watch()
    else:
        snapshot()
