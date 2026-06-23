"""
utils.py — Shared utility functions for the Honeypot System.
Logging setup, IP validation, time helpers, network interface detection, etc.
"""

import logging
import socket
import struct
import re
import os
import subprocess
import ipaddress
from datetime import datetime, timezone
from config import APP_LOG, LOG_DIR

# ─────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────

def setup_logging(name: str = "honeypot", level: int = logging.INFO) -> logging.Logger:
    """
    Configure a named logger that writes to both stdout and the app log file.
    Call once per process; subsequent calls return the cached logger.
    """
    logger = logging.getLogger(name)
    if logger.handlers:          # already configured
        return logger

    logger.setLevel(level)
    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler
    os.makedirs(LOG_DIR, exist_ok=True)
    fh = logging.FileHandler(APP_LOG, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────────────────────
# IP ADDRESS HELPERS
# ─────────────────────────────────────────────────────────────

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_valid_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Return True if ip falls in RFC-1918 / loopback ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    return is_valid_ip(ip) and not is_private_ip(ip)


# ─────────────────────────────────────────────────────────────
# NETWORK INTERFACE DETECTION
# ─────────────────────────────────────────────────────────────

def get_default_interface() -> str:
    """
    Auto-detect the primary network interface by reading /proc/net/route.
    Falls back to 'eth0' if detection fails.
    """
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception:
        pass

    # Try 'ip route' command
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                idx = parts.index("dev") + 1 if "dev" in parts else -1
                if idx > 0:
                    return parts[idx]
    except Exception:
        pass

    return "eth0"


def get_local_ips() -> list:
    """Return all local IP addresses (excluding loopback)."""
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip != "127.0.0.1" and ip != "::1":
                ips.append(ip)
    except Exception:
        pass
    return list(set(ips))


# ─────────────────────────────────────────────────────────────
# TIME HELPERS
# ─────────────────────────────────────────────────────────────

def utcnow_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def ts_to_display(ts: str) -> str:
    """Convert ISO timestamp to human-readable display format."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%d %b %Y %H:%M:%S")
    except Exception:
        return ts


# ─────────────────────────────────────────────────────────────
# LOG LINE PARSERS
# ─────────────────────────────────────────────────────────────

# Matches: "Failed password for [invalid user] <user> from <ip> port <port>"
_SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)"
)
# Matches: "Accepted password for <user> from <ip> port <port>"
_SSH_SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port (\d+)"
)
# Matches sudo: pam_unix(sudo:auth): authentication failure
_SUDO_FAIL_RE = re.compile(r"sudo.*authentication failure.*user=(\S+)")
# Matches: "COMMAND=/bin/..." from sudo logs
_SUDO_CMD_RE  = re.compile(r"sudo:.*COMMAND=(.*)")
# Matches: "Invalid user <user> from <ip>"
_INVALID_USER_RE = re.compile(r"Invalid user (\S+) from ([\d\.]+)")


def parse_ssh_failed(line: str):
    """Return (username, ip, port) or None."""
    m = _SSH_FAILED_RE.search(line)
    if m:
        return m.group(1), m.group(2), int(m.group(3))
    m = _INVALID_USER_RE.search(line)
    if m:
        return m.group(1), m.group(2), None
    return None


def parse_ssh_success(line: str):
    """Return (username, ip, port) or None."""
    m = _SSH_SUCCESS_RE.search(line)
    if m:
        return m.group(1), m.group(2), int(m.group(3))
    return None


def parse_sudo_failure(line: str):
    """Return username or None."""
    m = _SUDO_FAIL_RE.search(line)
    return m.group(1) if m else None


def parse_sudo_command(line: str):
    """Return command string or None."""
    m = _SUDO_CMD_RE.search(line)
    return m.group(1).strip() if m else None


# ─────────────────────────────────────────────────────────────
# FIREWALL / IPTABLES HELPERS
# ─────────────────────────────────────────────────────────────

def iptables_block(ip: str) -> bool:
    """
    Block an IP using iptables INPUT chain.
    Returns True on success, False if iptables unavailable / not root.
    """
    try:
        # Check if rule already exists
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            return True  # Already blocked

        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except PermissionError:
        return False


def iptables_unblock(ip: str) -> bool:
    """Remove iptables DROP rule for an IP."""
    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# FILE HELPERS
# ─────────────────────────────────────────────────────────────

def safe_file_size(path: str) -> int:
    """Return file size in bytes, or 0 if inaccessible."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def is_binary_file(path: str, sample_size: int = 512) -> bool:
    """Heuristic: return True if file looks binary (non-text)."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        return bool(chunk.translate(None, text_chars))
    except OSError:
        return False


# ─────────────────────────────────────────────────────────────
# THREAT SCORING HELPERS
# ─────────────────────────────────────────────────────────────

SEVERITY_SCORES = {
    "ssh_fail":         5,
    "ssh_brute":       30,
    "port_scan":       25,
    "syn_scan":        35,
    "file_modify":      5,
    "file_delete":     10,
    "rapid_change":    40,
    "sudo_fail":       15,
    "sudo_abuse":      20,
    "malware_sig":     50,
    "ti_flagged":      40,
    "honeypot_touch":  20,
}


def score_for(event_type: str) -> int:
    return SEVERITY_SCORES.get(event_type, 5)


# ─────────────────────────────────────────────────────────────
# MISC
# ─────────────────────────────────────────────────────────────

def truncate(text: str, max_len: int = 120) -> str:
    """Truncate a string for display / storage."""
    if text and len(text) > max_len:
        return text[:max_len] + "…"
    return text or ""


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     ADAPTIVE LINUX HONEYPOT + THREAT MONITORING SYSTEM      ║
║                   SOC Dashboard v1.0                        ║
╚══════════════════════════════════════════════════════════════╝
""")