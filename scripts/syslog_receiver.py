#!/usr/bin/env python3
"""
syslog_receiver.py — Live UDP Syslog listener to receive real logs from Virtual Machines (Linux / BSD / etc.)

Listens for incoming Syslog messages (RFC 3164 / RFC 5424) over UDP port 1514 (or custom port)
and appends them directly to logs/vm_syslog.log.

Usage:
  py scripts/syslog_receiver.py              # Listens on 0.0.0.0:1514 (no admin needed)
  py scripts/syslog_receiver.py --port 514   # Listens on standard port 514 (requires Admin)
"""
import os
import sys
import socket
from datetime import datetime
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = LAB_ROOT / 'logs' / 'vm_syslog.log'
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def start_receiver(host='0.0.0.0', port=1514):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except PermissionError:
        print(f"[!] Permission denied binding to port {port}. Port < 1024 requires Administrator privileges.")
        print("[!] Using default unprivileged port 1514 instead.")
        port = 1514
        sock.bind((host, port))
    except Exception as e:
        print(f"[!] Error binding to {host}:{port} — {e}")
        return

    # Determine local host IP for user reference
    local_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    print("=" * 65)
    print(f"[+] SOC Lab Syslog Receiver listening on {host}:{port}")
    print(f"[+] Destination log: {LOG_FILE}")
    print(f"[+] Host LAN IP:    {local_ip}")
    print("-" * 65)
    print("To forward logs from a Linux VM (Ubuntu / Kali / Debian):")
    print(f"  1. Edit /etc/rsyslog.conf (or /etc/rsyslog.d/siem.conf):")
    print(f"     *.* @{local_ip}:{port}")
    print(f"  2. Restart rsyslog:")
    print(f"     sudo systemctl restart rsyslog")
    print("=" * 65)
    print("[+] Waiting for incoming VM logs (Ctrl+C to stop)...")

    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                raw_msg = data.decode('utf-8', errors='replace').strip()
                # Clean PRI header like <13> if present
                clean_msg = raw_msg
                if clean_msg.startswith('<') and '>' in clean_msg[:6]:
                    clean_msg = clean_msg.split('>', 1)[1].strip()

                now_ts = datetime.now().strftime('%b %d %H:%M:%S')
                # If message doesn't start with standard syslog timestamp
                if not any(clean_msg.startswith(m) for m in ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']):
                    formatted_line = f"{now_ts} vm-{addr[0]} syslog: {clean_msg}"
                else:
                    formatted_line = clean_msg

                f.write(formatted_line + '\n')
                f.flush()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] From {addr[0]}: {clean_msg[:90]}")
            except KeyboardInterrupt:
                print("\n[+] Syslog receiver stopped.")
                break
            except Exception as e:
                print(f"[!] Error receiving log: {e}")


if __name__ == '__main__':
    port = 1514
    if '--port' in sys.argv:
        idx = sys.argv.index('--port')
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])
    start_receiver(port=port)
