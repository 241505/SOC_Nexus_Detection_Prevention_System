"""
threat_intel.py — Threat Intelligence Module
Checks IPs against AbuseIPDB and a local blacklist file.
Results are cached to avoid hammering APIs.
"""

import time
import logging
import requests
import os
from config import (
    ABUSEIPDB_KEY, ABUSEIPDB_URL, ABUSEIPDB_MAX_AGE,
    TI_CACHE_TTL_SECS, TI_SCORE_THRESHOLD, BLACKLIST_FILE
)
from utils import is_private_ip, is_valid_ip

logger = logging.getLogger("threat_intel")

# In-memory cache: { ip: (timestamp, result_dict) }
_ti_cache: dict = {}

# In-memory blacklist set (loaded once from file)
_blacklist: set = set()

# ─────────────────────────────────────────────────────────────
# BLACKLIST LOADER
# ─────────────────────────────────────────────────────────────

def _load_blacklist():
    """Load IPs from the offline blacklist file into _blacklist set."""
    global _blacklist
    if not os.path.exists(BLACKLIST_FILE):
        # Create an empty blacklist file with some known bad actors
        _seed_blacklist()
    try:
        with open(BLACKLIST_FILE, "r") as f:
            _blacklist = {
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            }
        logger.info("Loaded %d IPs from offline blacklist", len(_blacklist))
    except OSError as e:
        logger.warning("Could not load blacklist: %s", e)


def _seed_blacklist():
    """Write a starter blacklist with known malicious IPs/ranges."""
    seed_ips = [
        "# Adaptive Honeypot — Offline Blacklist",
        "# Add one IP per line. Lines starting with # are comments.",
        "# These are well-known scanner / malware C2 IPs (as of 2024).",
        "185.220.101.0",
        "185.220.101.1",
        "185.220.101.2",
        "89.248.165.0",
        "194.165.16.0",
        "45.95.168.0",
        "198.199.0.0",
        "80.82.77.0",
        "71.6.158.0",
        "66.240.192.138",
        "66.240.205.34",
        "66.240.236.119",
        "82.221.105.6",
        "87.118.122.50",
        "93.174.88.0",
        "94.102.49.190",
        "95.211.230.211",
        "192.241.194.118",
        "192.241.196.134",
        "198.20.69.74",
        "198.20.69.98",
        "205.185.126.17",
        "209.126.110.0",
    ]
    os.makedirs(os.path.dirname(BLACKLIST_FILE), exist_ok=True)
    with open(BLACKLIST_FILE, "w") as f:
        f.write("\n".join(seed_ips) + "\n")
    logger.info("Created seed blacklist at %s", BLACKLIST_FILE)


# Load blacklist at module import
_load_blacklist()


# ─────────────────────────────────────────────────────────────
# ABUSEIPDB QUERY
# ─────────────────────────────────────────────────────────────

def _query_abuseipdb(ip: str) -> dict:
    """
    Query AbuseIPDB v2 API for the given IP.
    Returns a dict with: abuseScore, totalReports, usageType, isp, domain
    Returns empty dict if API key not configured or request fails.
    """
    if not ABUSEIPDB_KEY:
        return {}

    try:
        headers = {
            "Accept":  "application/json",
            "Key":     ABUSEIPDB_KEY,
        }
        params = {
            "ipAddress":   ip,
            "maxAgeInDays": ABUSEIPDB_MAX_AGE,
            "verbose":     "",
        }
        resp = requests.get(ABUSEIPDB_URL, headers=headers,
                            params=params, timeout=8)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuseScore":   data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "usageType":    data.get("usageType", ""),
                "isp":          data.get("isp", ""),
                "domain":       data.get("domain", ""),
                "lastReported": data.get("lastReportedAt", ""),
            }
        elif resp.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit")
        else:
            logger.debug("AbuseIPDB returned %d for %s", resp.status_code, ip)
    except requests.RequestException as e:
        logger.warning("AbuseIPDB request failed: %s", e)

    return {}


# ─────────────────────────────────────────────────────────────
# MAIN THREAT INTEL CHECK
# ─────────────────────────────────────────────────────────────

def check_ip(ip: str) -> dict:
    """
    Full threat-intelligence check for a given IP.
    Returns:
        {
            "ip":            str,
            "is_blacklisted": bool,
            "abuse_score":   int  (0-100),
            "total_reports": int,
            "flagged":       bool,   # True if any check says malicious
            "threat_level":  str,    # NONE / LOW / MEDIUM / HIGH / CRITICAL
            "reason":        str,
            "isp":           str,
            "domain":        str,
        }
    """
    if not is_valid_ip(ip):
        return _empty_result(ip, reason="invalid IP")
    if is_private_ip(ip):
        return _empty_result(ip, reason="private IP")

    # Cache hit?
    if ip in _ti_cache:
        cached_ts, cached_result = _ti_cache[ip]
        if time.time() - cached_ts < TI_CACHE_TTL_SECS:
            return cached_result

    result = _empty_result(ip)
    reasons = []

    # 1. Offline blacklist check (instant)
    if ip in _blacklist:
        result["is_blacklisted"] = True
        result["flagged"]        = True
        reasons.append("found in offline blacklist")
        result["threat_level"]  = "HIGH"

    # 2. AbuseIPDB (if key is configured)
    abuse_data = _query_abuseipdb(ip)
    if abuse_data:
        score = abuse_data.get("abuseScore", 0)
        result["abuse_score"]   = score
        result["total_reports"] = abuse_data.get("totalReports", 0)
        result["isp"]           = abuse_data.get("isp", "")
        result["domain"]        = abuse_data.get("domain", "")

        if score >= TI_SCORE_THRESHOLD:
            result["flagged"] = True
            reasons.append(f"AbuseIPDB score {score}%")
            if score >= 80:
                result["threat_level"] = "CRITICAL"
            elif score >= 50:
                result["threat_level"] = "HIGH"
            elif score >= TI_SCORE_THRESHOLD:
                result["threat_level"] = "MEDIUM"

    result["reason"] = "; ".join(reasons) if reasons else "clean"

    # Cache and return
    _ti_cache[ip] = (time.time(), result)
    return result


def _empty_result(ip: str, reason: str = "not checked") -> dict:
    return {
        "ip":             ip,
        "is_blacklisted": False,
        "abuse_score":    0,
        "total_reports":  0,
        "flagged":        False,
        "threat_level":   "NONE",
        "reason":         reason,
        "isp":            "",
        "domain":         "",
    }


# ─────────────────────────────────────────────────────────────
# BLACKLIST MANAGEMENT
# ─────────────────────────────────────────────────────────────

def add_to_blacklist(ip: str):
    """Add an IP to the in-memory set and persist it to file."""
    _blacklist.add(ip)
    try:
        with open(BLACKLIST_FILE, "a") as f:
            f.write(f"{ip}\n")
        logger.info("Added %s to offline blacklist", ip)
    except OSError as e:
        logger.warning("Could not persist blacklist: %s", e)


def reload_blacklist():
    """Reload the blacklist file from disk (call after manual edits)."""
    _load_blacklist()


def get_blacklist() -> list:
    """Return current blacklist as a sorted list."""
    return sorted(_blacklist)