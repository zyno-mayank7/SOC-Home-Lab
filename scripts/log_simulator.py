"""
log_simulator.py — Generates synthetic but realistic auth.log-style events
into soc-lab/logs/simulated_auth.log so the SIEM has real data to detect.

The simulator interleaves:
  - Normal SSH sessions (successes)
  - Failed SSH logins (occasional, normal-looking)
  - Brute-force bursts (5+ failures from one IP — should trigger SOC-1002)
  - sudo to root (occasional — triggers SOC-1004)
  - User creations (rare — triggers SOC-1003)
  - /etc/shadow reads (rare — triggers SOC-1008)
  - Encoded PowerShell-style commands (synthetic, triggers SOC-1001)

Usage:
  python3 log_simulator.py [events_to_generate]
"""

import os
import random
import time
import re
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path('/home/z/my-project/soc-lab/logs/simulated_auth.log')
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# Realistic source IPs for the simulation
NORMAL_IPS = ['10.0.0.5', '10.0.0.20', '192.168.1.50', '10.0.0.21']
ATTACKER_IPS = ['185.220.101.45', '194.165.16.78', '45.155.205.233']
NORMAL_USERS = ['analyst', 'devops', 'jenkins', 'ubuntu', 'deploy']
ATTACKER_USERS = ['root', 'admin', 'administrator', 'postgres', 'oracle']

BRUTE_FORCE_BURST = 5  # 5 failures triggers SOC-1002


def fmt_ts():
    """auth.log timestamp format: 'Sep 24 10:36:44'"""
    return datetime.now().strftime('%b %d %H:%M:%S')


def normal_ssh_success():
    ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    return f'{fmt_ts()} soc-lab sshd[{random.randint(1000,30000)}]: Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2'


def normal_ssh_failure():
    ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    return f'{fmt_ts()} soc-lab sshd[{random.randint(1000,30000)}]: Failed password for {user} from {ip} port {random.randint(40000,60000)} ssh2'


def brute_force_burst():
    """Emit 5-7 failures from an attacker IP — triggers SOC-1002."""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(ATTACKER_USERS)
    lines = []
    for _ in range(random.randint(BRUTE_FORCE_BURST, 7)):
        lines.append(
            f'{fmt_ts()} soc-lab sshd[{random.randint(1000,30000)}]: '
            f'Failed password for invalid user {user} from {ip} port '
            f'{random.randint(40000,60000)} ssh2'
        )
    return lines


def sudo_root():
    user = random.choice(NORMAL_USERS)
    return f'{fmt_ts()} soc-lab sudo[{random.randint(1000,30000)}]:    {user} : TTY=pts/{random.randint(0,5)} ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt-get update'


def new_user_creation():
    user = random.choice(['operator', 'service', 'backup', 'monitor'])
    return f'{fmt_ts()} soc-lab useradd[{random.randint(1000,30000)}]: new user: name={user} UID={random.randint(1000,2000)}'


def shadow_read():
    return f'{fmt_ts()} soc-lab sudo[{random.randint(1000,30000)}]:    analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow'


def encoded_powershell():
    # Synthetic — actual system has no PowerShell, this is for SIEM validation
    encoded = 'cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBlAG4AYwAgAGMAYQBjAGMAZQBkAGUAZAA='
    return f'{fmt_ts()} soc-lab kernel:[{random.randint(10000,30000)}]: audit: type=EXECVE msg=audit(1711234567.123:456): argc=3 a0="powershell.exe" a1="-EncodedCommand" a2="{encoded}"'


def generate_events(count=100, brute_force=True, include_shadow=True, include_powershell=True):
    events = []
    for _ in range(count):
        r = random.random()
        if r < 0.55:
            events.append(normal_ssh_success())
        elif r < 0.75:
            events.append(normal_ssh_failure())
        elif r < 0.85:
            events.append(sudo_root())
        elif r < 0.92:
            # Brute-force burst (multiple lines)
            if brute_force:
                events.extend(brute_force_burst())
            else:
                events.append(normal_ssh_failure())
        elif r < 0.96:
            events.append(new_user_creation())
        elif r < 0.98 and include_shadow:
            events.append(shadow_read())
        elif include_powershell:
            events.append(encoded_powershell())
    return events


def main():
    import sys
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    events = generate_events(count=count)
    with open(LOG_PATH, 'a') as f:
        for line in events:
            f.write(line + '\n')
    print(f'[+] Wrote {len(events)} simulated events to {LOG_PATH}')
    print(f'    File size: {LOG_PATH.stat().st_size} bytes')


if __name__ == '__main__':
    main()
