#!/usr/bin/env python3
"""Run mini-siem.py serve with proper detachment + auto-restart."""
import os
import sys
import time
import signal
import subprocess

SCRIPT = '/home/z/my-project/soc-lab/scripts/mini-siem.py'
LOGFILE = '/home/z/my-project/soc-lab/logs/siem-web.out'
PIDFILE = '/home/z/my-project/soc-lab/var/siem.pid'

def is_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False

def start():
    # Read PID file
    if os.path.exists(PIDFILE):
        with open(PIDFILE) as f:
            old_pid = int(f.read().strip())
        if is_running(old_pid):
            print(f"[+] SIEM already running (PID {old_pid})")
            return old_pid

    # Start fresh — use setsid + nohup, redirect all stdio
    log_fd = os.open(LOGFILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    null_fd = os.open('/dev/null', os.O_RDONLY)
    pid = os.fork()
    if pid > 0:
        # Parent: just exit
        os.write(log_fd, b'')
        os.close(log_fd)
        os.close(null_fd)
        # Wait briefly
        time.sleep(2)
        if is_running(pid):
            with open(PIDFILE, 'w') as f:
                f.write(str(pid))
            print(f"[+] SIEM started (PID {pid})")
            return pid
        else:
            print(f"[!] SIEM process died immediately")
            return None
    else:
        # Child: become session leader, then exec python
        os.setsid()
        os.dup2(null_fd, 0)  # stdin
        os.dup2(log_fd, 1)    # stdout
        os.dup2(log_fd, 2)    # stderr
        os.close(null_fd)
        os.close(log_fd)
        # Reset signal handlers
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        # Exec into python
        os.execvp('python3', ['python3', SCRIPT, 'serve'])

if __name__ == '__main__':
    start()
