"""
alerts.py — Centralised Alert Manager
All modules call fire() to raise an alert. The manager:
  1. Writes to SQLite (via database.py)
  2. Appends to the alerts log file
  3. Emits a Socket.IO event to the browser dashboard
  4. Optionally triggers the automatic response engine
"""

import json
import logging
import threading
from datetime import datetime
from config import ALERT_LOG, ALERT_LEVELS
from database import insert_alert

logger = logging.getLogger("alerts")

# Socket.IO server reference — injected by app.py after startup
_socketio = None

# Lock for thread-safe log writes
_log_lock = threading.Lock()


def set_socketio(sio):
    """Called by app.py to inject the Socket.IO instance."""
    global _socketio
    _socketio = sio


def fire(level: str, category: str, message: str,
         source_ip: str = None, details: dict = None,
         auto_respond: bool = True):
    """
    Raise an alert.

    Args:
        level      : INFO / LOW / MEDIUM / HIGH / CRITICAL
        category   : brute_force / port_scan / file_event / log_event /
                     malware / honeypot / network / system
        message    : Human-readable description
        source_ip  : Attacker / event IP (optional)
        details    : Extra structured data (dict) — stored as JSON
        auto_respond: Whether to pass to response engine
    """
    if level not in ALERT_LEVELS:
        level = "INFO"

    details_json = json.dumps(details) if details else None

    # 1. Persist to database
    alert_id = insert_alert(
        level=level,
        category=category,
        message=message,
        source_ip=source_ip,
        details=details_json,
    )

    # 2. Write to alerts log file
    _write_log(level, category, message, source_ip, details)

    # 3. Emit real-time to dashboard
    _emit_socket(alert_id, level, category, message, source_ip, details)

    # 4. Feed to auto-response engine (HIGH/CRITICAL only)
    if auto_respond and level in ("HIGH", "CRITICAL") and source_ip:
        _trigger_response(level, category, source_ip, message, details)

    logger.info("[ALERT][%s][%s] %s | IP: %s", level, category, message, source_ip or "—")
    return alert_id


def _write_log(level, category, message, source_ip, details):
    """Append alert to the flat log file."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = (
        f"[{ts}] [{level}] [{category}] "
        f"{'IP:' + source_ip + ' ' if source_ip else ''}"
        f"{message}"
        f"{' | ' + str(details) if details else ''}\n"
    )
    with _log_lock:
        try:
            with open(ALERT_LOG, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError as e:
            logger.error("Could not write alert log: %s", e)


def _emit_socket(alert_id, level, category, message, source_ip, details):
    """Push alert to all connected dashboard clients via Socket.IO."""
    if _socketio is None:
        return
    payload = {
        "id":        alert_id,
        "timestamp": datetime.utcnow().isoformat(),
        "level":     level,
        "category":  category,
        "message":   message,
        "source_ip": source_ip,
        "details":   details,
    }
    try:
        _socketio.emit("new_alert", payload)
    except Exception as e:
        logger.debug("SocketIO emit failed: %s", e)


def _trigger_response(level, category, source_ip, message, details):
    """Import and call response_engine — import is deferred to avoid circular deps."""
    try:
        from response_engine import handle_alert
        handle_alert(level, category, source_ip, message, details)
    except Exception as e:
        logger.warning("Response engine error: %s", e)