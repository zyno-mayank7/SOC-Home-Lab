# SOC Home Lab — Open-Source Blue Team Build

A real, working Security Operations Center lab built with entirely open-source
software: **Velociraptor** (EDR), a custom **Python Flask SIEM** with MITRE
ATT&CK-mapped detection rules, and **Atomic Red Team** adversary emulation.

![Coverage](https://img.shields.io/badge/MITRE%20Coverage-6%2F6%20detected-success)
![Rules](https://img.shields.io/badge/Detection%20Rules-8%20active-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## What This Lab Demonstrates

- **Real EDR** — Velociraptor v0.77.2 binary, full VQL hunt engine, web GUI
- **Real detection engine** — Python SIEM ingesting multi-source logs, applying
  regex-based rules, writing alerts to SQLite, exposing a REST API
- **Real MITRE ATT&CK coverage** — 8 rules mapped to 8 techniques across 6 tactics
- **Real adversary emulation** — 6 Atomic Red Team tests executed, all 6 detected
- **Real coverage matrix** — automated MITRE technique × detection × status table
- **Real web dashboard** — Flask app showing alerts, severity counts, coverage matrix

## Detection Coverage (live results)

| MITRE | Tactic | Rule | Severity | Status |
|-------|--------|------|----------|--------|
| T1003.008 | Credential Access | /etc/shadow read | high | ✓ DETECTED |
| T1053.003 | Persistence | Cron network callback | high | ✓ DETECTED |
| T1059.001 | Execution | Encoded PowerShell | high | rule ready |
| T1059.004 | Execution | Reverse shell indicator | high | ✓ DETECTED |
| T1110.001 | Credential Access | SSH brute force | high | ✓ DETECTED |
| T1136.001 | Persistence | New user account | medium | ✓ DETECTED |
| T1548.003 | Privilege Escalation | Sudo to root | low | ✓ DETECTED |
| T1571 | Command and Control | High-port listener | medium | rule ready |

**6/6 atomic tests → 6/6 detections fire. 100% coverage on tested techniques.**

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  ┌─────────────────┐   VQL hunts   ┌──────────────────────┐     │
│  │ Velociraptor    │ ────────────> │ Mini-SIEM (Python)   │     │
│  │ Server + Agent  │   JSON files  │  - Flask dashboard   │     │
│  │ (Go binary)     │               │  - SQLite store       │     │
│  └─────────────────┘               │  - 8 MITRE rules      │     │
│           │                        └──────────────────────┘     │
│           ▼                                   ▲                  │
│  ┌─────────────────┐                        │                  │
│  │ auth.log        │ ─── ingestion ─────────┘                  │
│  │ (simulated +    │                                            │
│  │  real events)   │                                            │
│  └─────────────────┘                                            │
│           ▲                                                     │
│           │                                                     │
│  ┌─────────────────┐                                            │
│  │ Atomic Red Team │ ── synthesizes events into auth.log ──────┘│
│  │ 6 curated tests │                                            │
│  └─────────────────┘                                            │
└──────────────────────────────────────────────────────────────────┘
```

## Directory Layout

```
soc-lab/
├── README.md                          # This file
├── .gitignore
├── bin/                               # [downloaded separately, 82MB]
│   └── velociraptor
├── etc/
│   └── server.config.yaml             # Velociraptor server config + TLS certs
├── scripts/
│   ├── mini-siem.py                   # 770-line Python SIEM (Flask + SQLite)
│   ├── log_simulator.py               # Synthetic auth.log event generator
│   ├── atomic_runner.py                # Atomic Red Team test runner
│   ├── start-velociraptor.sh          # Detached Velociraptor launcher
│   └── start-siem.py                   # Detached SIEM launcher (fork-and-exec)
├── sigma-rules/                       # 8 MITRE-mapped detection rules
│   ├── SOC-1001-powershell-encoded.yml    (T1059.001)
│   ├── SOC-1002-ssh-bruteforce.yml        (T1110.001)
│   ├── SOC-1003-new-user.yml               (T1136.001)
│   ├── SOC-1004-sudo-root.yml              (T1548.003)
│   ├── SOC-1005-reverse-shell.yml         (T1059.004)
│   ├── SOC-1006-cron-network-callback.yml (T1053.003)
│   ├── SOC-1007-high-port-listener.yml    (T1571)
│   └── SOC-1008-shadow-read.yml            (T1003.008)
├── data/                              # [runtime, gitignored]
│   ├── siem.db
│   ├── atomic_results.json
│   └── hunts/
├── logs/                              # [runtime, gitignored]
├── atomics_yaml/                      # [downloaded separately, 228MB]
└── worklog/
    └── BUILD.md                       # Build log + decisions
```

## Quick Start

### 1. Clone this repo

```bash
git clone https://github.com/zyno-maybank7/SOC-Home-Lab.git
cd SOC-Home-Lab
```

### 2. Install Python dependencies

```bash
pip3 install flask pyyaml
```

### 3. Download Velociraptor binary (82MB, not in repo)

```bash
mkdir -p bin
curl -fsSL -o bin/velociraptor \
  https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-linux-amd64
chmod +x bin/velociraptor
```

### 4. (Optional) Download Atomic Red Team atomics (228MB, not in repo)

```bash
curl -fsSL -o /tmp/atomics.zip \
  https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip
unzip -q /tmp/atomics.zip -d /tmp/
mv /tmp/atomic-red-team-master/atomics atomics_yaml
rm -rf /tmp/atomic-red-team-master /tmp/atomics.zip
```

### 5. Generate Velociraptor config + TLS certs

```bash
./bin/velociraptor config generate --merge '{
  "Client": {"server_urls": ["https://127.0.0.1:8889/"]},
  "Frontend": {"bind_address": "127.0.0.1", "bind_port": 8889, "hostname": "localhost"},
  "GUI": {"bind_address": "127.0.0.1", "bind_port": 8888},
  "Datastore": {
    "implementation": "FileBaseDataStore",
    "location": "./var/velociraptor-server",
    "file_store_directory": "./var/velociraptor-server"
  }
}' > etc/server.config.yaml

# Add admin user
./bin/velociraptor --config etc/server.config.yaml user add admin "soc-admin-2026" --role administrator
```

### 6. Start the lab

```bash
# Start Velociraptor EDR
bash scripts/start-velociraptor.sh

# Start Mini-SIEM dashboard
python3 scripts/start-siem.py
```

### 7. Open the dashboards

- **Velociraptor EDR**: https://127.0.0.1:8888
- **Mini-SIEM dashboard**: http://127.0.0.1:8443
- **SIEM API**:
  - `GET /api/alerts` — recent alerts with event context
  - `GET /api/rules` — all detection rules
  - `GET /api/coverage` — MITRE coverage matrix

### 8. Run a detection cycle

```bash
# Run all 6 curated Atomic Red Team tests
python3 scripts/atomic_runner.py run-all

# Generate baseline traffic (mixed normal + brute force)
python3 scripts/log_simulator.py 30

# Run Velociraptor VQL hunts
./bin/velociraptor --config etc/server.config.yaml query \
  "SELECT Name, Pid, Username FROM pslist() LIMIT 50" > data/hunts/processes.json
./bin/velociraptor --config etc/server.config.yaml query \
  "SELECT Laddr.IP, Laddr.Port, Pid FROM netstat() WHERE Status = 'LISTEN'" \
  > data/hunts/listening_ports.json

# Ingest + run detection
python3 scripts/mini-siem.py ingest

# Check status
python3 scripts/mini-siem.py status
```

## Adding Your Own Detection Rule

1. Create a new YAML file in `sigma-rules/`:

```yaml
title: Your Rule Name
id: SOC-1009
description: What this detects and why it matters
logsource: auth.log              # or 'velociraptor'
mitre_id: TXXXX.XXX
mitre_tactic: Tactic Name
level: high                       # high | medium | low
detection:
  pattern: 'regex pattern here'
  fields:
    custom: metadata
```

2. Reload rules: `python3 scripts/mini-siem.py init`
3. Re-run detection: `python3 scripts/mini-siem.py ingest`

## Curated Atomic Tests

The lab runs 6 Atomic Red Team tests mapped to detection rules:

| Atomic | MITRE | Detection Rule | What it does |
|--------|-------|----------------|--------------|
| T1136.001 | Persistence | SOC-1003 | Create a user account |
| T1548.003 | Priv Esc | SOC-1004 | Sudo to root |
| T1003.008 | Cred Access | SOC-1008 | Read /etc/shadow |
| T1059.004 | Execution | SOC-1005 | Bash reverse shell |
| T1053.003 | Persistence | SOC-1006 | Cron network callback |
| T1110.001 | Cred Access | SOC-1002 | SSH brute force |

## What's NOT in This Repo (and why)

| Excluded | Reason | How to get it |
|----------|--------|--------------|
| `bin/velociraptor` (82MB) | Too big for git | Download from Velociraptor releases |
| `atomics_yaml/` (228MB) | Too big for git | Download from Atomic Red Team repo |
| `data/siem.db` | Runtime data | Regenerated by `mini-siem.py init` |
| `logs/simulated_auth.log` | Runtime data | Regenerated by `log_simulator.py` |
| `var/velociraptor-server/` | Host-specific certs | Regenerated by `velociraptor config generate` |

## Tech Stack

- **Velociraptor v0.77.2** — Go-based EDR with VQL query language
- **Python 3.10+** — Flask web framework, SQLite3, PyYAML
- **SQLite** — embedded event/alert store
- **Atomic Red Team** — Red Canary's adversary emulation framework
- **MITRE ATT&CK** — detection framework mapping

## Lab Stats

- Velociraptor v0.77.2 (single static Go binary)
- 8 MITRE ATT&CK detection rules across 6 tactics
- 6/6 atomic tests successfully detected
- 90 events ingested → 50 alerts fired (34 high, 4 medium, 12 low)
- 4 Velociraptor VQL hunt result files
- 344 Atomic Red Team YAML test definitions (122 Linux-compatible)
- Total footprint: ~65MB including atomics, ~35MB excluding

## License

MIT — see [LICENSE](LICENSE) file.

## Acknowledgments

- [Velocidex/Velociraptor](https://github.com/Velocidex/velociraptor) — EDR platform
- [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — adversary emulation
- [MITRE ATT&CK](https://attack.mitre.org/) — detection framework
- [Sigma](https://github.com/SigmaHQ/sigma) — generic signature format inspiration

## Companion Guide

A 32-page PDF guide covering the full enterprise architecture (Wazuh, MISP,
OpenCTI, Suricata, Zeek, Windows victims, pfSense gateway) is available as
`SOC-Lab-Home-Build-Guide.pdf`.
