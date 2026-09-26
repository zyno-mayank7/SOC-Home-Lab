"""
mini-siem.py — A real, working Python SIEM for the SOC home lab.

Components:
  - SQLite-backed event & alert store
  - Sigma-like YAML detection rules with MITRE ATT&CK tags
  - Multi-source log ingestion (auth.log, syslog, Velociraptor hunts)
  - Rule engine: regex + field-extraction + MITRE tagging
  - Flask web dashboard with alert viewer, coverage matrix, rule library
  - REST API: /api/alerts, /api/rules, /api/coverage

Run:
  python3 mini-siem.py init        # create DB + load default rules
  python3 mini-siem.py ingest      # tail/parse logs and apply rules
  python3 mini-siem.py serve       # start web dashboard on :8443
"""

import os
import re
import sys
import json
import time
import yaml
import sqlite3
import hashlib
import threading
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string

# ─── Paths ─────────────────────────────────────────────────────────────────
LAB_ROOT = Path('/home/z/my-project/soc-lab')
DB_PATH = LAB_ROOT / 'data' / 'siem.db'
RULES_DIR = LAB_ROOT / 'sigma-rules'
HUNTS_DIR = LAB_ROOT / 'data' / 'hunts'
LOG_TAIL_STATE = LAB_ROOT / 'var' / 'tail_state.json'

# ─── Database schema ───────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    raw TEXT NOT NULL,
    fields_json TEXT,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_id TEXT,
    mitre_tactic TEXT,
    description TEXT,
    event_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT DEFAULT 'new',
    FOREIGN KEY (event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_id TEXT,
    mitre_tactic TEXT,
    description TEXT,
    source TEXT NOT NULL,
    pattern TEXT NOT NULL,
    field_extractors TEXT,
    enabled INTEGER DEFAULT 1,
    loaded_at TEXT NOT NULL
);
"""


# ─── Database helpers ──────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f'[+] Database initialized at {DB_PATH}')


# ─── Rule loading ──────────────────────────────────────────────────────────
def load_rules_from_dir():
    """Load all .yml files in sigma-rules/ into the DB."""
    conn = get_db()
    cur = conn.cursor()
    loaded = 0
    for path in sorted(RULES_DIR.glob('*.yml')):
        with open(path) as f:
            rule = yaml.safe_load(f)
        if not rule or 'id' not in rule:
            print(f'  ! Skipping {path.name} — no id field')
            continue
        cur.execute("""
            INSERT OR REPLACE INTO rules
              (id, name, severity, mitre_id, mitre_tactic, description,
               source, pattern, field_extractors, enabled, loaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            rule['id'],
            rule.get('title', rule['id']),
            rule.get('level', 'medium'),
            rule.get('mitre_id', ''),
            rule.get('mitre_tactic', ''),
            rule.get('description', ''),
            rule.get('logsource', 'generic'),
            rule.get('detection', {}).get('pattern', ''),
            json.dumps(rule.get('detection', {}).get('fields', {})),
            datetime.now(timezone.utc).isoformat(),
        ))
        loaded += 1
        print(f'  + Loaded rule: {rule["id"]} ({rule.get("title", "")[:50]})')
    conn.commit()
    conn.close()
    print(f'[+] {loaded} rules loaded from {RULES_DIR}')


def get_active_rules():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM rules WHERE enabled = 1')
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Event ingestion ───────────────────────────────────────────────────────
LOG_SOURCES = [
    {
        'name': 'auth.log',
        'path': '/var/log/auth.log',
        'type': 'syslog_auth',
    },
    {
        'name': 'syslog',
        'path': '/var/log/syslog',
        'type': 'syslog_general',
    },
    {
        'name': 'simulated-auth',
        'path': str(LAB_ROOT / 'logs' / 'simulated_auth.log'),
        'type': 'syslog_auth',
    },
    {
        'name': 'velociraptor-processes',
        'path': str(HUNTS_DIR / 'processes.json'),
        'type': 'velociraptor_processes',
    },
    {
        'name': 'velociraptor-listening-ports',
        'path': str(HUNTS_DIR / 'listening_ports.json'),
        'type': 'velociraptor_ports',
    },
]


def parse_syslog_auth(line):
    """Parse /var/log/auth.log line. Returns (ts, fields_dict)."""
    # Format: Sep 24 10:36:44 hostname process[pid]: message
    m = re.match(
        r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$',
        line
    )
    if not m:
        return None, None
    raw_ts, proc, pid, msg = m.groups()
    # Use current year since auth.log doesn't include it
    try:
        ts = datetime.strptime(
            f'{datetime.now().year} {raw_ts}', '%Y %b %d %H:%M:%S'
        ).isoformat()
    except ValueError:
        ts = datetime.now(timezone.utc).isoformat()
    fields = {
        'process': proc,
        'pid': pid or '',
        'message': msg,
    }
    # Extract user if present
    user_match = re.search(r'(?:user|for)\s+(?:invalid user\s+)?(\S+)', msg)
    if user_match:
        fields['user'] = user_match.group(1)
    # Extract IP if present
    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg)
    if ip_match:
        fields['src_ip'] = ip_match.group(1)
    return ts, fields


def parse_velociraptor_processes(json_text):
    """Parse a Velociraptor processes.json hunt output (array of records)."""
    events = []
    try:
        records = json.loads(json_text)
    except json.JSONDecodeError:
        return events
    ts = datetime.now(timezone.utc).isoformat()
    for r in records:
        if not isinstance(r, dict):
            continue
        fields = {
            'process_name': r.get('Name', ''),
            'pid': str(r.get('Pid', '')),
            'ppid': str(r.get('Ppid', '')),
            'exe': r.get('Exe', ''),
            'user': r.get('Username', ''),
        }
        events.append((ts, 'velociraptor', json.dumps(fields), fields))
    return events


def parse_velociraptor_ports(json_text):
    events = []
    try:
        records = json.loads(json_text)
    except json.JSONDecodeError:
        return events
    ts = datetime.now(timezone.utc).isoformat()
    for r in records:
        if not isinstance(r, dict):
            continue
        fields = {
            'local_ip': r.get('Laddr.IP', ''),
            'local_port': str(r.get('Laddr.Port', '')),
            'pid': str(r.get('Pid', '')),
        }
        events.append((ts, 'velociraptor', json.dumps(fields), fields))
    return events


def ingest_file(source):
    """Tail a log file, parse new lines, insert into events table."""
    path = source['path']
    if not os.path.exists(path):
        return 0
    state_key = hashlib.md5(path.encode()).hexdigest()[:10]
    state = {}
    if LOG_TAIL_STATE.exists():
        try:
            state = json.loads(LOG_TAIL_STATE.read_text())
        except Exception:
            state = {}
    last_offset = state.get(state_key, 0)
    new_count = 0
    conn = get_db()
    cur = conn.cursor()
    with open(path, 'r', errors='replace') as f:
        f.seek(last_offset)
        content = f.read()
        new_offset = f.tell()
    if not content:
        conn.close()
        return 0
    if source['type'] == 'syslog_auth':
        for line in content.splitlines():
            if not line.strip():
                continue
            ts, fields = parse_syslog_auth(line)
            if not ts:
                continue
            cur.execute(
                'INSERT INTO events (ts, source, raw, fields_json, ingested_at) VALUES (?, ?, ?, ?, ?)',
                (ts, source['name'], line, json.dumps(fields),
                 datetime.now(timezone.utc).isoformat())
            )
            new_count += 1
    elif source['type'] == 'velociraptor_processes':
        for ts, src, fields_json, fields in parse_velociraptor_processes(content):
            cur.execute(
                'INSERT INTO events (ts, source, raw, fields_json, ingested_at) VALUES (?, ?, ?, ?, ?)',
                (ts, src, json.dumps(fields), fields_json, datetime.now(timezone.utc).isoformat())
            )
            new_count += 1
    elif source['type'] == 'velociraptor_ports':
        for ts, src, fields_json, fields in parse_velociraptor_ports(content):
            cur.execute(
                'INSERT INTO events (ts, source, raw, fields_json, ingested_at) VALUES (?, ?, ?, ?, ?)',
                (ts, src, json.dumps(fields), fields_json, datetime.now(timezone.utc).isoformat())
            )
            new_count += 1
    state[state_key] = new_offset
    LOG_TAIL_STATE.write_text(json.dumps(state))
    conn.commit()
    conn.close()
    return new_count


def ingest_all():
    total = 0
    for src in LOG_SOURCES:
        n = ingest_file(src)
        if n > 0:
            print(f'  + Ingested {n} events from {src["name"]}')
        total += n
    print(f'[+] Total new events ingested: {total}')
    return total


# ─── Detection engine ──────────────────────────────────────────────────────
def evaluate_rule(rule, event):
    """Evaluate a single rule against a single event. Returns match info or None."""
    fields = json.loads(event['fields_json'] or '{}')
    raw = event['raw']
    pattern = rule['pattern']
    if not pattern:
        return None
    try:
        m = re.search(pattern, raw) or re.search(pattern, json.dumps(fields))
    except re.error as e:
        return None
    if not m:
        return None
    return {
        'rule_id': rule['id'],
        'rule_name': rule['name'],
        'severity': rule['severity'],
        'mitre_id': rule.get('mitre_id') or '',
        'mitre_tactic': rule.get('mitre_tactic') or '',
        'description': rule.get('description') or '',
        'event_id': event['id'],
        'created_at': datetime.now(timezone.utc).isoformat(),
        'status': 'new',
    }


def run_detection():
    """Run all active rules against all events not yet alerted on."""
    rules = get_active_rules()
    if not rules:
        print('[!] No active rules — run `init` first')
        return 0
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, ts, source, raw, fields_json FROM events')
    events = cur.fetchall()
    alerts = []
    for event in events:
        ev = {
            'id': event[0], 'ts': event[1], 'source': event[2],
            'raw': event[3], 'fields_json': event[4],
        }
        for rule in rules:
            # Skip if alert already exists for this event+rule
            cur.execute(
                'SELECT 1 FROM alerts WHERE rule_id = ? AND event_id = ?',
                (rule['id'], ev['id'])
            )
            if cur.fetchone():
                continue
            match = evaluate_rule(rule, ev)
            if match:
                alerts.append(match)
    if alerts:
        cur.executemany("""
            INSERT INTO alerts
              (rule_id, rule_name, severity, mitre_id, mitre_tactic,
               description, event_id, created_at, status)
            VALUES (:rule_id, :rule_name, :severity, :mitre_id, :mitre_tactic,
                    :description, :event_id, :created_at, :status)
        """, alerts)
        conn.commit()
    conn.close()
    print(f'[+] Detection run complete — {len(alerts)} new alerts')
    return len(alerts)


# ─── Web dashboard ─────────────────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SOC Home Lab — Mini SIEM Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f0e0d;
    color: #e9e9e7;
    padding: 24px;
    line-height: 1.5;
  }
  .header {
    border-bottom: 1px solid #674f43;
    padding-bottom: 16px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }
  .title {
    font-size: 28px;
    font-weight: 800;
    color: #debe60;
  }
  .subtitle {
    font-size: 13px;
    color: #8c8582;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 1px;
    text-transform: uppercase;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }
  .card {
    background: #161513;
    border: 1px solid #453f2e;
    border-radius: 6px;
    padding: 18px;
  }
  .stat-value {
    font-size: 36px;
    font-weight: 900;
    color: #debe60;
    line-height: 1;
    margin-bottom: 6px;
  }
  .stat-label {
    font-size: 11px;
    color: #8c8582;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
  }
  .section-title {
    font-size: 14px;
    font-weight: 700;
    color: #debe60;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin: 24px 0 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid #453f2e;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    background: #161513;
    border-radius: 6px;
    overflow: hidden;
  }
  th {
    background: #674f43;
    color: #f4f3f3;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 10px 12px;
    text-align: left;
  }
  td {
    padding: 10px 12px;
    font-size: 13px;
    border-bottom: 1px solid #2d2a23;
  }
  tr:last-child td { border-bottom: none; }
  tr:nth-child(even) td { background: #1c1b18; }
  .sev-high { color: #c88882; font-weight: 700; }
  .sev-medium { color: #bda36e; font-weight: 600; }
  .sev-low { color: #6bb483; }
  .mitre-tag {
    background: #2d2a23;
    color: #debe60;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
  }
  .coverage-cell {
    text-align: center;
    padding: 6px;
    font-size: 11px;
  }
  .status-detected { background: #1e3b2c; color: #6bb483; font-weight: 700; }
  .status-missed { background: #3b1e1e; color: #c88882; font-weight: 700; }
  .status-untested { background: #2d2a23; color: #8c8582; }
  .footer {
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid #453f2e;
    font-size: 11px;
    color: #8c8582;
    font-family: 'JetBrains Mono', monospace;
    text-align: center;
  }
  code {
    background: #2d2a23;
    color: #debe60;
    padding: 1px 6px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
  }
</style>
</head>
<body>
  <div class="header">
    <div>
      <div class="title">SOC Home Lab — Mini SIEM</div>
      <div class="subtitle">Real-time detection dashboard · MITRE ATT&CK mapped</div>
    </div>
    <div class="subtitle">v1.0 · {{ now }}</div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="stat-value">{{ total_events }}</div>
      <div class="stat-label">Events Ingested</div>
    </div>
    <div class="card">
      <div class="stat-value">{{ total_alerts }}</div>
      <div class="stat-label">Total Alerts</div>
    </div>
    <div class="card">
      <div class="stat-value">{{ high_severity }}</div>
      <div class="stat-label">High Severity</div>
    </div>
    <div class="card">
      <div class="stat-value">{{ rules_count }}</div>
      <div class="stat-label">Detection Rules</div>
    </div>
  </div>

  <div class="section-title">Recent Alerts</div>
  <table>
    <tr>
      <th>Time</th>
      <th>Severity</th>
      <th>Rule</th>
      <th>MITRE</th>
      <th>Source</th>
      <th>Event Snippet</th>
    </tr>
    {% for a in alerts %}
    <tr>
      <td><code>{{ a.created_at[5:19] }}</code></td>
      <td class="sev-{{ a.severity }}">{{ a.severity|upper }}</td>
      <td>{{ a.rule_name }}</td>
      <td><span class="mitre-tag">{{ a.mitre_id or '—' }}</span></td>
      <td><code>{{ a.event_source }}</code></td>
      <td>{{ a.event_snippet }}</td>
    </tr>
    {% endfor %}
    {% if not alerts %}
    <tr><td colspan="6" style="text-align:center;color:#8c8582;padding:24px;">No alerts yet. Run atomic tests to generate them.</td></tr>
    {% endif %}
  </table>

  <div class="section-title">MITRE ATT&CK Coverage Matrix</div>
  <table>
    <tr>
      <th>Technique</th>
      <th>Tactic</th>
      <th>Rule</th>
      <th>Severity</th>
      <th>Alerts Fired</th>
      <th>Status</th>
    </tr>
    {% for c in coverage %}
    <tr>
      <td><span class="mitre-tag">{{ c.mitre_id }}</span></td>
      <td>{{ c.mitre_tactic }}</td>
      <td>{{ c.rule_name }}</td>
      <td class="sev-{{ c.severity }}">{{ c.severity }}</td>
      <td style="text-align:center;">{{ c.alert_count }}</td>
      <td class="coverage-cell status-{{ c.status }}">{{ c.status|upper }}</td>
    </tr>
    {% endfor %}
  </table>

  <div class="footer">
    SOC Home Lab · Mini SIEM v1.0 · /home/z/my-project/soc-lab · {{ now }}
  </div>
</body>
</html>
"""


app = Flask(__name__)


def get_dashboard_data():
    conn = get_db()
    cur = conn.cursor()
    # Counts
    total_events = cur.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    total_alerts = cur.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    high_severity = cur.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'high'"
    ).fetchone()[0]
    rules_count = cur.execute('SELECT COUNT(*) FROM rules').fetchone()[0]
    # Recent alerts joined with events
    cur.execute("""
        SELECT a.created_at, a.severity, a.rule_name, a.mitre_id,
               e.source, e.raw, e.id
        FROM alerts a
        JOIN events e ON e.id = a.event_id
        ORDER BY a.created_at DESC
        LIMIT 25
    """)
    alerts = []
    for row in cur.fetchall():
        alerts.append({
            'created_at': row[0],
            'severity': row[1],
            'rule_name': row[2],
            'mitre_id': row[3],
            'event_source': row[4],
            'event_snippet': row[5][:120] + ('...' if len(row[5]) > 120 else ''),
        })
    # Coverage matrix
    cur.execute("""
        SELECT r.mitre_id, r.mitre_tactic, r.name, r.severity, r.id,
               (SELECT COUNT(*) FROM alerts a WHERE a.rule_id = r.id) AS alert_count
        FROM rules r
        WHERE r.mitre_id != ''
        ORDER BY r.mitre_id
    """)
    coverage = []
    # Pull atomic test results to compute status
    coverage_status = load_coverage_status()
    for row in cur.fetchall():
        mitre_id = row[0]
        status = coverage_status.get(mitre_id, 'untested')
        if row[5] > 0:
            status = 'detected'
        coverage.append({
            'mitre_id': mitre_id,
            'mitre_tactic': row[1] or '—',
            'rule_name': row[2],
            'severity': row[3],
            'alert_count': row[5],
            'status': status,
        })
    conn.close()
    return {
        'total_events': total_events,
        'total_alerts': total_alerts,
        'high_severity': high_severity,
        'rules_count': rules_count,
        'alerts': alerts,
        'coverage': coverage,
        'now': datetime.now().isoformat(timespec='seconds'),
    }


def load_coverage_status():
    """Read the atomic test results from data/atomic_results.json."""
    p = LAB_ROOT / 'data' / 'atomic_results.json'
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


@app.route('/')
def dashboard():
    data = get_dashboard_data()
    return render_template_string(DASHBOARD_HTML, **data)


@app.route('/api/alerts')
def api_alerts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT a.id, a.created_at, a.severity, a.rule_name, a.mitre_id,
               a.mitre_tactic, a.description, e.source, e.raw, e.ts
        FROM alerts a JOIN events e ON e.id = a.event_id
        ORDER BY a.created_at DESC LIMIT 100
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route('/api/rules')
def api_rules():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM rules ORDER BY mitre_id, severity')
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route('/api/coverage')
def api_coverage():
    return jsonify(get_dashboard_data()['coverage'])


# ─── CLI ────────────────────────────────────────────────────────────────────
def cmd_init():
    init_db()
    load_rules_from_dir()


def cmd_ingest():
    ingest_all()
    run_detection()


def cmd_serve():
    print('[+] Starting SIEM dashboard on http://0.0.0.0:8443')
    app.run(host='0.0.0.0', port=8443, debug=False)


def cmd_status():
    conn = get_db()
    cur = conn.cursor()
    total_events = cur.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    total_alerts = cur.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    rules_count = cur.execute('SELECT COUNT(*) FROM rules').fetchone()[0]
    high = cur.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'high'"
    ).fetchone()[0]
    print(f'Events:   {total_events}')
    print(f'Alerts:   {total_alerts} ({high} high severity)')
    print(f'Rules:    {rules_count} active')
    print()
    print('Recent alerts:')
    cur.execute("""
        SELECT a.created_at, a.severity, a.rule_name, a.mitre_id
        FROM alerts a ORDER BY a.created_at DESC LIMIT 5
    """)
    for row in cur.fetchall():
        print(f'  {row[0][:19]}  [{row[1]:6}]  {row[2]:40}  {row[3]}')
    conn.close()


def cmd_run_atomic(mitre_id):
    """Run an atomic test, log it, and re-run detection."""
    from atomic_runner import run_atomic_for_mitre
    results = run_atomic_for_mitre(mitre_id)
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'init':
        cmd_init()
    elif cmd == 'ingest':
        cmd_ingest()
    elif cmd == 'serve':
        cmd_serve()
    elif cmd == 'status':
        cmd_status()
    elif cmd == 'atomic':
        if len(sys.argv) < 3:
            print('Usage: atomic <MITRE_ID>')
            sys.exit(1)
        cmd_run_atomic(sys.argv[2])
    elif cmd == 'detect':
        run_detection()
    else:
        print(f'Unknown command: {cmd}')
        print(__doc__)
        sys.exit(1)
