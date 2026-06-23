"""
response_engine.py — Automatic Threat Response Engine

FIX LOG:
  - _respond() now guards against source_ip being None before calling
    upsert_ip_score / get_ip_score / is_blocked. Previously any alert
    without a source_ip (e.g. file events) crashed with a SQLite NOT NULL
    constraint error on the ip_scores table.
  - manual_unblock now uses upsert_ip_score correctly (no broken import).
"""

import logging
import threading
from datetime import datetime
from config import (
    RESPONSE_ENABLED, IPTABLES_BLOCK_ENABLED,
    AUTO_BLOCK_SCORE, ALERT_LEVELS
)
from database import (
    upsert_ip_score, get_ip_score, block_ip,
    is_blocked, insert_alert
)
from utils import iptables_block, score_for

logger = logging.getLogger("response_engine")

_socketio = None
_lock     = threading.Lock()


def set_socketio(sio):
    global _socketio
    _socketio = sio


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT (called by alerts.py)
# ─────────────────────────────────────────────────────────────

def handle_alert(level: str, category: str, source_ip: str,
                 message: str, details: dict = None):
    if not RESPONSE_ENABLED:
        return
    with _lock:
        try:
            _respond(level, category, source_ip, message, details or {})
        except Exception as e:
            logger.error("Response engine error for %s: %s", source_ip, e)


def _respond(level: str, category: str, source_ip: str,
             message: str, details: dict):

    # FIX: guard against None / empty IP — file events, log events, etc.
    # have no associated IP. Score-based blocking only applies to real IPs.
    if not source_ip or not source_ip.strip():
        logger.debug("Response engine: skipping — no source IP for [%s] %s", level, message)
        return

    source_ip = source_ip.strip()

    # 1. Score delta based on alert level
    level_score_map = {
        "INFO":     0,
        "LOW":      5,
        "MEDIUM":  15,
        "HIGH":    25,
        "CRITICAL": 40,
    }
    delta = level_score_map.get(level, 5)
    upsert_ip_score(source_ip, delta=delta)

    # 2. Fetch current score
    ip_record     = get_ip_score(source_ip)
    current_score = ip_record["threat_score"] if ip_record else delta

    logger.info(
        "Response engine: IP=%s level=%s score=%d category=%s",
        source_ip, level, current_score, category
    )

    # 3. Check if already blocked
    if is_blocked(source_ip):
        logger.debug("IP %s already blocked — no further action", source_ip)
        return

    # 4. Auto-block decision
    should_block = (
        current_score >= AUTO_BLOCK_SCORE
        or level == "CRITICAL"
        or (category == "brute_force" and level == "HIGH")
    )

    if should_block:
        _auto_block(source_ip, current_score, message)
        return

    # 5. Score-based escalation warnings
    if current_score >= 60:
        _escalate_watch(source_ip, current_score)


# ─────────────────────────────────────────────────────────────
# AUTO-BLOCK
# ─────────────────────────────────────────────────────────────

def _auto_block(source_ip: str, score: int, reason: str):
    block_ip(ip=source_ip, reason=reason, method="auto")
    logger.warning("AUTO-BLOCK: %s (score=%d)", source_ip, score)

    iptables_ok = False
    if IPTABLES_BLOCK_ENABLED:
        iptables_ok = iptables_block(source_ip)
        if iptables_ok:
            logger.info("iptables DROP rule added for %s", source_ip)
        else:
            logger.warning("iptables block failed for %s — need root.", source_ip)

    insert_alert(
        level="HIGH",
        category="response",
        message=f"Auto-blocked IP {source_ip} (threat score {score})",
        source_ip=source_ip,
        details=f'{{"score":{score},"iptables":{str(iptables_ok).lower()}}}'
    )

    _emit("ip_blocked", {
        "ip":        source_ip,
        "score":     score,
        "reason":    reason,
        "iptables":  iptables_ok,
        "timestamp": datetime.utcnow().isoformat(),
    })


# ─────────────────────────────────────────────────────────────
# ESCALATION
# ─────────────────────────────────────────────────────────────

def _escalate_watch(source_ip: str, score: int):
    logger.info("ESCALATED WATCH for %s (score=%d)", source_ip, score)
    _emit("ip_escalated", {
        "ip":    source_ip,
        "score": score,
        "level": "SUSPECT" if score < 80 else "HOSTILE",
    })


# ─────────────────────────────────────────────────────────────
# MANUAL BLOCK / UNBLOCK API
# ─────────────────────────────────────────────────────────────

def manual_block(ip: str, reason: str = "manual") -> dict:
    if not ip or not ip.strip():
        return {"success": False, "msg": "IP required"}
    ip = ip.strip()
    if is_blocked(ip):
        return {"success": False, "msg": f"{ip} already blocked"}

    block_ip(ip=ip, reason=reason, method="manual")
    iptables_ok = False
    if IPTABLES_BLOCK_ENABLED:
        iptables_ok = iptables_block(ip)

    _emit("ip_blocked", {
        "ip": ip, "reason": reason,
        "iptables": iptables_ok, "method": "manual",
    })
    return {"success": True, "msg": f"{ip} blocked", "iptables": iptables_ok}


def manual_unblock(ip: str) -> dict:
    if not ip or not ip.strip():
        return {"success": False, "msg": "IP required"}
    ip = ip.strip()
    from database import get_conn
    conn = get_conn()
    conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    conn.commit()
    # Reset blocked flag (delta=0 just updates last_seen)
    upsert_ip_score(ip, delta=0, blocked=False)
    return {"success": True, "msg": f"{ip} unblocked"}


# ─────────────────────────────────────────────────────────────
# SOCKETIO EMIT
# ─────────────────────────────────────────────────────────────

def _emit(event: str, data: dict):
    if _socketio:
        try:
            _socketio.emit(event, data)
        except Exception as e:
            logger.debug("Response emit failed: %s", e)