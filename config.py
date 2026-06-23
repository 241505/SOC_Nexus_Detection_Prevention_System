"""
config.py — Central Configuration for Adaptive Honeypot + Threat Monitoring System
All tunable parameters, paths, thresholds, and keys live here.
"""

import os

# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DB_PATH         = os.path.join(BASE_DIR, "database", "honeypot.db")
LOG_DIR         = os.path.join(BASE_DIR, "logs")
APP_LOG         = os.path.join(LOG_DIR, "app.log")
ALERT_LOG       = os.path.join(LOG_DIR, "alerts.log")

# ─────────────────────────────────────────────────────────────
# FLASK / SOCKETIO
# ─────────────────────────────────────────────────────────────
FLASK_HOST      = "0.0.0.0"
FLASK_PORT      = 5000
FLASK_DEBUG     = False
SECRET_KEY      = os.environ.get("SECRET_KEY", "hp-secret-2024-xK9!mZ#qR")

# ─────────────────────────────────────────────────────────────
# HONEYPOT ENGINE
# ─────────────────────────────────────────────────────────────
HONEYPOT_HOST   = "0.0.0.0"
HONEYPOT_SSH_PORT    = 2222   # Fake SSH port (no root needed)
HONEYPOT_FTP_PORT    = 2121   # Fake FTP port
HONEYPOT_TELNET_PORT = 2323   # Fake Telnet port
HONEYPOT_HTTP_PORT   = 8080   # Fake HTTP port

# How many failed attempts before escalation
BRUTE_FORCE_THRESHOLD   = 5
BRUTE_FORCE_WINDOW_SECS = 60   # Sliding window in seconds

# ─────────────────────────────────────────────────────────────
# NETWORK / PACKET SNIFFER
# ─────────────────────────────────────────────────────────────
# Set to None to auto-detect the default interface
SNIFF_INTERFACE  = None
# BPF filter — capture TCP, UDP, ICMP only
SNIFF_FILTER     = "tcp or udp or icmp"
# Packets per batch before emitting to dashboard
SNIFF_BATCH_SIZE = 20
# Port-scan detection: unique ports hit within window
PORTSCAN_THRESHOLD  = 15
PORTSCAN_WINDOW_SECS = 10

# ─────────────────────────────────────────────────────────────
# FILE MONITOR
# ─────────────────────────────────────────────────────────────
MONITORED_DIRS = [
    "/etc",
    "/var/log",
    "/tmp",
    "/usr/bin",
]
# Add project-local fallback dirs that always exist
MONITORED_DIRS_EXTRA = [
    os.path.join(BASE_DIR, "logs"),
    os.path.join(BASE_DIR, "database"),
]
# Rapid-change ransomware heuristic: N changes in T seconds
RAPID_CHANGE_COUNT  = 10
RAPID_CHANGE_WINDOW = 5

# ─────────────────────────────────────────────────────────────
# LOG MONITOR
# ─────────────────────────────────────────────────────────────
AUTH_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",        # RHEL / Fedora
    "/var/log/syslog",
]
JOURNALCTL_UNIT = None  # None = all units; e.g. "sshd"
LOG_POLL_INTERVAL = 2   # seconds between log polls

# ─────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────
# AbuseIPDB — set your key in environment or replace here
ABUSEIPDB_KEY       = os.environ.get("ABUSEIPDB_KEY", "")
ABUSEIPDB_URL       = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE   = 30        # days
TI_CACHE_TTL_SECS   = 3600      # 1 hour cache per IP
TI_SCORE_THRESHOLD  = 25        # abuse confidence % to flag

# Offline blacklist bundled with project
BLACKLIST_FILE = os.path.join(BASE_DIR, "database", "blacklist.txt")

# ─────────────────────────────────────────────────────────────
# GEOIP
# ─────────────────────────────────────────────────────────────
# ip-api.com — free, no key needed (45 req/min)
GEOIP_URL       = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,lat,lon,query"
GEOIP_CACHE_TTL = 86400   # 24 h per IP

# ─────────────────────────────────────────────────────────────
# AUTOMATIC RESPONSE ENGINE
# ─────────────────────────────────────────────────────────────
RESPONSE_ENABLED        = True
# Use iptables to block IPs (requires root); set False to just log
IPTABLES_BLOCK_ENABLED  = os.environ.get("IPTABLES_BLOCK", "false").lower() == "true"
# Quarantine directory for suspicious files
QUARANTINE_DIR          = os.path.join(BASE_DIR, "quarantine")
# Threat score above which auto-block fires
AUTO_BLOCK_SCORE        = 80

# ─────────────────────────────────────────────────────────────
# ALERT SYSTEM
# ─────────────────────────────────────────────────────────────
ALERT_LEVELS = {
    "INFO":     1,
    "LOW":      2,
    "MEDIUM":   3,
    "HIGH":     4,
    "CRITICAL": 5,
}

# ─────────────────────────────────────────────────────────────
# ADAPTIVE ENGINE
# ─────────────────────────────────────────────────────────────
# Each attacker IP accumulates a threat score; thresholds trigger actions
THREAT_LEVEL_WATCH    = 30   # Start tracking carefully
THREAT_LEVEL_SUSPECT  = 60   # Increase logging verbosity
THREAT_LEVEL_BLOCK    = 85   # Auto-block

# ─────────────────────────────────────────────────────────────
# SYSTEM HEALTH POLLING
# ─────────────────────────────────────────────────────────────
HEALTH_POLL_INTERVAL = 3   # seconds

# ─────────────────────────────────────────────────────────────
# ENSURE DIRECTORIES EXIST AT IMPORT TIME
# ─────────────────────────────────────────────────────────────
for _d in [LOG_DIR, os.path.dirname(DB_PATH), QUARANTINE_DIR]:
    os.makedirs(_d, exist_ok=True)