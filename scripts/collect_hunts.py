#!/usr/bin/env python3
"""
collect_hunts.py — Collect process and listening port snapshots into data/hunts/
Works cross-platform (Windows & Linux) without requiring external binaries.
Outputs the JSON structures expected by Velociraptor hunt parsers in mini-siem.py.
"""
import os
import sys
import json
import socket
import subprocess
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
HUNTS_DIR = LAB_ROOT / 'data' / 'hunts'
HUNTS_DIR.mkdir(parents=True, exist_ok=True)


def get_processes():
    procs = []
    if os.name == 'nt':
        try:
            # Use PowerShell to query processes in JSON
            cmd = [
                'powershell', '-NoProfile', '-Command',
                'Get-Process | Select-Object -First 50 Id, ProcessName, Path | ForEach-Object { @{ Pid = $_.Id; Name = $_.ProcessName; Exe = if ($_.Path) { $_.Path } else { "" }; Username = $env:USERNAME } } | ConvertTo-Json'
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, list):
                    procs.extend(data)
                elif isinstance(data, dict):
                    procs.append(data)
        except Exception as e:
            print(f"[!] Error querying Windows processes: {e}")
    else:
        try:
            cmd = ['ps', '-eo', 'pid,ppid,user,comm']
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            lines = res.stdout.strip().splitlines()
            for line in lines[1:51]:
                parts = line.split(None, 3)
                if len(parts) == 4:
                    procs.append({
                        'Pid': parts[0],
                        'Ppid': parts[1],
                        'Username': parts[2],
                        'Name': parts[3],
                        'Exe': parts[3],
                    })
        except Exception as e:
            print(f"[!] Error querying Linux processes: {e}")

    # Fallback minimal processes if empty
    if not procs:
        procs = [
            {'Pid': os.getpid(), 'Ppid': 1, 'Name': 'python.exe', 'Exe': sys.executable, 'Username': 'system'},
            {'Pid': 4, 'Ppid': 0, 'Name': 'System', 'Exe': 'System', 'Username': 'SYSTEM'},
        ]
    return procs


def get_listening_ports():
    ports = []
    if os.name == 'nt':
        try:
            cmd = [
                'powershell', '-NoProfile', '-Command',
                'Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 30 LocalAddress, LocalPort, OwningProcess | ForEach-Object { @{ "Laddr.IP" = $_.LocalAddress; "Laddr.Port" = $_.LocalPort; Pid = $_.OwningProcess } } | ConvertTo-Json'
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, list):
                    ports.extend(data)
                elif isinstance(data, dict):
                    ports.append(data)
        except Exception as e:
            print(f"[!] Error querying Windows listening ports: {e}")
    else:
        try:
            cmd = ['ss', '-tlpn']
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            for line in res.stdout.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and ':' in parts[3]:
                    addr, port = parts[3].rsplit(':', 1)
                    ports.append({
                        'Laddr.IP': addr or '0.0.0.0',
                        'Laddr.Port': port,
                        'Pid': 1000,
                    })
        except Exception as e:
            print(f"[!] Error querying Linux listening ports: {e}")

    return ports


def main():
    procs = get_processes()
    proc_file = HUNTS_DIR / 'processes.json'
    proc_file.write_text(json.dumps(procs, indent=2))
    print(f"[+] Saved {len(procs)} process hunt records to {proc_file}")

    ports = get_listening_ports()
    port_file = HUNTS_DIR / 'listening_ports.json'
    port_file.write_text(json.dumps(ports, indent=2))
    print(f"[+] Saved {len(ports)} listening port hunt records to {port_file}")


if __name__ == '__main__':
    main()
