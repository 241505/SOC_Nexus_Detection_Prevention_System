"""
log_monitor.py — System Log Monitoring Module
Monitors journalctl (systemd) and classic /var/log/* files.
Detects:
  - Failed logins (SSH, PAM, sudo)
  - Privilege escalation attempts
  - Service manipulation (systemctl stop/disable)
  - Suspicious cron / at job creation
  - Kernel module loading
  - Capability abuse (setuid, setgid)
  - New user/group creation
"""

import re
import subprocess
import threading
import time
import os
import logging
from config import AUTH_LOG_PATHS, LOG_POLL_INTERVAL
from database import insert_log_event, upsert_ip_score
from utils import parse_ssh_failed, parse_ssh_success, parse_sudo_failure, score_for
import alerts

logger = logging.getLogger("log_monitor")

# ─────────────────────────────────────────────────────────────
# DETECTION PATTERNS
# ─────────────────────────────────────────────────────────────

PATTERNS = [
    # (regex, category, level, message_template, score_key)
    (re.compile(r"Failed password for"),
     "auth", "MEDIUM", "SSH failed password", "ssh_fail"),

    (re.compile(r"authentication failure.*user=(\S+)"),
     "auth", "MEDIUM", "PAM authentication failure", "ssh_fail"),

    (re.compile(r"FAILED SU"),
     "auth", "HIGH", "Failed su attempt", "sudo_fail"),

    (re.compile(r"sudo:.*FAILED"),
     "auth", "HIGH", "sudo authentication failure", "sudo_fail"),

    (re.compile(r"sudo:.*COMMAND=/"),
     "auth", "LOW", "sudo command execution", "ssh_fail"),

    (re.compile(r"useradd|adduser|usermod"),
     "system", "HIGH", "User account modification detected", "sudo_abuse"),

    (re.compile(r"groupadd|groupmod"),
     "system", "MEDIUM", "Group modification detected", "ssh_fail"),

    (re.compile(r"passwd\s+\w"),
     "system", "HIGH", "Password change detected", "sudo_abuse"),

    (re.compile(r"systemctl.*(stop|disable|mask)\s+"),
     "system", "HIGH", "Service manipulation via systemctl", "sudo_abuse"),

    (re.compile(r"insmod|modprobe|rmmod"),
     "system", "CRITICAL", "Kernel module operation detected", "malware_sig"),

    (re.compile(r"chmod\s+[0-7]*[67][0-7][0-7]\s+|chmod\s+\+s\s+"),
     "system", "HIGH", "SUID/SGID bit change detected", "sudo_abuse"),

    (re.compile(r"crontab\s+-[eil]"),
     "system", "MEDIUM", "Crontab modification attempt", "ssh_fail"),

    (re.compile(r"/etc/cron"),
     "system", "MEDIUM", "Cron directory modification", "ssh_fail"),

    (re.compile(r"ptrace|/proc/\d+/mem"),
     "system", "CRITICAL", "Process memory access (ptrace) detected", "malware_sig"),

    (re.compile(r"Accepted publickey|Accepted password"),
     "auth", "INFO", "Successful SSH login", "ssh_fail"),

    (re.compile(r"ROOT LOGIN"),
     "auth", "CRITICAL", "Root login detected", "sudo_abuse"),

    (re.compile(r"iptables|nftables|ufw"),
     "network", "MEDIUM", "Firewall rule modification", "ssh_fail"),

    (re.compile(r"nc\s+-l|netcat|ncat\s+"),
     "network", "HIGH", "Netcat listener started", "malware_sig"),

    (re.compile(r"wget|curl.*http"),
     "network", "LOW", "File download detected", "ssh_fail"),

    (re.compile(r"/bin/bash -i|bash -i|sh -i|/dev/tcp|/dev/udp"),
     "malware", "CRITICAL", "Reverse shell pattern detected", "malware_sig"),
]

# IP extraction regex (IPv4)
_IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

# Username extraction from common patterns
_USER_RE = re.compile(r"for (\S+) from|user=(\S+)|User (\S+) from")


def _extract_ip(line: str) -> str:
    m = _IP_RE.search(line)
    return m.group(0) if m else None


def _extract_user(line: str) -> str:
    m = _USER_RE.search(line)
    if m:
        return m.group(1) or m.group(2) or m.group(3)
    return None


# ─────────────────────────────────────────────────────────────
# JOURNALCTL MONITOR
# ─────────────────────────────────────────────────────────────

class JournalMonitor(threading.Thread):
    """
    Follows systemd journal in real time using journalctl --follow.
    Does not require reading log files — works on systems with only journald.
    """

    def __init__(self, socketio=None):
        super().__init__(daemon=True, name="JournalMonitor")
        self._stop_event = threading.Event()
        self._socketio   = socketio
        self._proc       = None

    def run(self):
        try:
            self._proc = subprocess.Popen(
                ["journalctl", "-f", "-o", "short-iso", "--no-pager",
                 "-n", "0",   # Start from current; don't dump history
                 "-p", "0..6"],  # Emergency to Info
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            logger.info("JournalMonitor: following systemd journal")
            for line in self._proc.stdout:
                if self._stop_event.is_set():
                    break
                self._process_line("journalctl", line.rstrip())
        except FileNotFoundError:
            logger.info("journalctl not available on this system")
        except Exception as e:
            logger.warning("JournalMonitor error: %s", e)

    def stop(self):
        self._stop_event.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _process_line(self, source: str, line: str):
        _classify_and_store(source, line, self._socketio)


# ─────────────────────────────────────────────────────────────
# CLASSIC LOG FILE MONITOR
# ─────────────────────────────────────────────────────────────

class SyslogMonitor(threading.Thread):
    """
    Tails /var/log/auth.log, /var/log/syslog, and /var/log/secure.
    Falls back gracefully on systems where these are absent or unreadable.
    """

    def __init__(self, socketio=None):
        super().__init__(daemon=True, name="SyslogMonitor")
        self._stop_event = threading.Event()
        self._socketio   = socketio
        self._handles    = {}

    def run(self):
        self._open_files()
        while not self._stop_event.is_set():
            for path, fh in list(self._handles.items()):
                self._drain(path, fh)
            time.sleep(LOG_POLL_INTERVAL)
        self._close_all()

    def stop(self):
        self._stop_event.set()

    def _open_files(self):
        for path in AUTH_LOG_PATHS:
            if os.path.isfile(path):
                try:
                    fh = open(path, "r", encoding="utf-8", errors="replace")
                    fh.seek(0, 2)
                    self._handles[path] = fh
                    logger.info("SyslogMonitor: watching %s", path)
                except PermissionError:
                    logger.warning("No permission to read %s", path)

    def _close_all(self):
        for fh in self._handles.values():
            try:
                fh.close()
            except Exception:
                pass

    def _drain(self, path: str, fh):
        try:
            for line in fh:
                _classify_and_store(path, line.rstrip(), self._socketio)
        except OSError as e:
            logger.warning("Syslog read error %s: %s", path, e)


# ─────────────────────────────────────────────────────────────
# SHARED CLASSIFICATION LOGIC
# ─────────────────────────────────────────────────────────────

def _classify_and_store(source: str, line: str, socketio=None):
    """Match line against all patterns and take action."""
    if not line.strip():
        return

    for pattern, category, level, msg_template, score_key in PATTERNS:
        if pattern.search(line):
            ip       = _extract_ip(line)
            username = _extract_user(line)

            # Persist log event
            insert_log_event(
                source=source,
                raw_line=line[:500],
                category=category,
                source_ip=ip,
                username=username
            )

            # Update threat score if IP is known
            if ip:
                upsert_ip_score(ip, delta=score_for(score_key))

            # Fire alert
            alerts.fire(
                level=level,
                category=category,
                message=f"{msg_template} | {line[30:120]}",
                source_ip=ip,
                details={"raw": line[:300], "user": username},
            )

            # Emit to dashboard
            if socketio:
                try:
                    socketio.emit("log_event", {
                        "source":   source,
                        "category": category,
                        "level":    level,
                        "message":  msg_template,
                        "ip":       ip,
                        "user":     username,
                        "raw":      line[:200],
                    })
                except Exception:
                    pass

            break  # One pattern per line is enough


# ─────────────────────────────────────────────────────────────
# COMBINED LOG MONITOR MANAGER
# ─────────────────────────────────────────────────────────────

class LogMonitor:
    """
    Convenience wrapper that starts both journal and syslog monitors.
    """

    def __init__(self, socketio=None):
        self._journal = JournalMonitor(socketio)
        self._syslog  = SyslogMonitor(socketio)

    def start(self):
        self._journal.start()
        self._syslog.start()
        logger.info("LogMonitor started (journal + syslog)")

    def stop(self):
        self._journal.stop()
        self._syslog.stop()