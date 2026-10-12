#!/usr/bin/env python3
"""Run mini-siem.py serve with proper detachment + auto-restart (cross-platform)."""
import os
import sys
import time
import signal
import subprocess
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = LAB_ROOT / 'scripts' / 'mini-siem.py'
LOGFILE = LAB_ROOT / 'logs' / 'siem-web.out'
PIDFILE = LAB_ROOT / 'var' / 'siem.pid'


def is_running(pid):
    if pid <= 0:
        return False
    if os.name == 'nt':
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return exit_code.value == STILL_ACTIVE
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def start():
    # Ensure dirs exist
    LOGFILE.parent.mkdir(parents=True, exist_ok=True)
    PIDFILE.parent.mkdir(parents=True, exist_ok=True)

    # Read PID file
    if os.path.exists(PIDFILE):
        try:
            with open(PIDFILE) as f:
                old_pid = int(f.read().strip())
            if is_running(old_pid):
                print(f"[+] SIEM already running (PID {old_pid}) on http://127.0.0.1:8443")
                return old_pid
        except Exception:
            pass

    if os.name == 'nt':
        # Windows background launch
        out_f = open(LOGFILE, 'w', encoding='utf-8')
        creation_flags = 0
        if hasattr(subprocess, 'CREATE_NEW_PROCESS_GROUP'):
            creation_flags |= subprocess.CREATE_NEW_PROCESS_GROUP
        if hasattr(subprocess, 'DETACHED_PROCESS'):
            creation_flags |= subprocess.DETACHED_PROCESS

        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT), 'serve'],
            stdout=out_f,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            creationflags=creation_flags,
            close_fds=True,
        )
        time.sleep(2)
        if is_running(proc.pid):
            with open(PIDFILE, 'w') as f:
                f.write(str(proc.pid))
            print(f"[+] SIEM started (PID {proc.pid}) on http://127.0.0.1:8443")
            return proc.pid
        else:
            print("[!] SIEM process died immediately. Check logs:")
            if LOGFILE.exists():
                print(LOGFILE.read_text(encoding='utf-8', errors='replace')[:500])
            return None
    else:
        # Linux/macOS fork-and-exec
        log_fd = os.open(str(LOGFILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        null_fd = os.open('/dev/null', os.O_RDONLY)
        pid = os.fork()
        if pid > 0:
            os.close(log_fd)
            os.close(null_fd)
            time.sleep(2)
            if is_running(pid):
                with open(PIDFILE, 'w') as f:
                    f.write(str(pid))
                print(f"[+] SIEM started (PID {pid}) on http://127.0.0.1:8443")
                return pid
            else:
                print("[!] SIEM process died immediately")
                return None
        else:
            os.setsid()
            os.dup2(null_fd, 0)
            os.dup2(log_fd, 1)
            os.dup2(log_fd, 2)
            os.close(null_fd)
            os.close(log_fd)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.execvp(sys.executable, [sys.executable, str(SCRIPT), 'serve'])


def stop():
    if not os.path.exists(PIDFILE):
        print("[-] SIEM not running (no PID file).")
        return
    try:
        with open(PIDFILE) as f:
            pid = int(f.read().strip())
    except Exception:
        print("[-] Invalid PID file.")
        return

    if is_running(pid):
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        print(f"[+] Stopped SIEM (PID {pid})")
    else:
        print(f"[-] Process {pid} was not running.")

    try:
        os.remove(PIDFILE)
    except Exception:
        pass


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'stop':
        stop()
    else:
        start()
