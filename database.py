"""
database.py — SQLite database layer for Adaptive Honeypot System

FIX LOG:
  - upsert_ip_score: the UPDATE statement was built using
    `tuple(filter(lambda x: x is not None, [...]))` which accidentally
    dropped legitimate `0` / `False` values (Python's filter removes all
    falsy values, not just None).  Replaced with an explicit params list
    that only appends optional fields when they are explicitly provided.
  - get_conn: added `timeout=30` to avoid "database is locked" errors
    under heavy concurrent write load from multiple detector threads.
"""

import sqlite3
import threading
import logging
from datetime import datetime
from config import DB_PATH

logger = logging.getLogger("database")

_local = threading.local()


def get_conn() -> sqlite3.Connection:
    """Return a per-thread SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        # FIX: timeout=30 prevents "database is locked" under multi-thread load
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        _local.conn.execute("PRAGMA busy_timeout=10000")
    return _local.conn


def close_conn():
    if hasattr(_local, "conn") and _local.conn:
        _local.conn.close()
        _local.conn = None


# ─────────────────────────────────────────────────────────────
# SCHEMA INITIALISATION
# ─────────────────────────────────────────────────────────────

def init_db():
    conn = get_conn()
    cur  = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        level       TEXT    NOT NULL,
        category    TEXT    NOT NULL,
        source_ip   TEXT,
        message     TEXT    NOT NULL,
        details     TEXT,
        resolved    INTEGER NOT NULL DEFAULT 0
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS attacks (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp     TEXT    NOT NULL,
        attack_type   TEXT    NOT NULL,
        source_ip     TEXT,
        destination   TEXT,
        port          INTEGER,
        protocol      TEXT,
        payload       TEXT,
        threat_score  INTEGER NOT NULL DEFAULT 0,
        blocked       INTEGER NOT NULL DEFAULT 0
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ssh_attempts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT    NOT NULL,
        source_ip  TEXT    NOT NULL,
        username   TEXT,
        password   TEXT,
        success    INTEGER NOT NULL DEFAULT 0,
        port       INTEGER
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS port_scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        source_ip   TEXT    NOT NULL,
        ports_hit   TEXT    NOT NULL,
        scan_type   TEXT,
        threat_score INTEGER NOT NULL DEFAULT 0
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS file_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT    NOT NULL,
        event_type TEXT    NOT NULL,
        path       TEXT    NOT NULL,
        size       INTEGER,
        is_suspect INTEGER NOT NULL DEFAULT 0
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS log_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT    NOT NULL,
        source     TEXT    NOT NULL,
        raw_line   TEXT    NOT NULL,
        category   TEXT,
        source_ip  TEXT,
        username   TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS packet_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        src_ip      TEXT,
        dst_ip      TEXT,
        src_port    INTEGER,
        dst_port    INTEGER,
        protocol    TEXT,
        flags       TEXT,
        size        INTEGER,
        suspicious  INTEGER NOT NULL DEFAULT 0
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ip_scores (
        ip            TEXT    PRIMARY KEY,
        threat_score  INTEGER NOT NULL DEFAULT 0,
        country       TEXT,
        isp           TEXT,
        first_seen    TEXT,
        last_seen     TEXT,
        attack_count  INTEGER NOT NULL DEFAULT 0,
        blocked       INTEGER NOT NULL DEFAULT 0,
        ti_checked    INTEGER NOT NULL DEFAULT 0,
        abuse_score   INTEGER NOT NULL DEFAULT 0
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip          TEXT    PRIMARY KEY,
        timestamp   TEXT    NOT NULL,
        reason      TEXT,
        method      TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS system_health (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        cpu_pct     REAL,
        mem_pct     REAL,
        disk_pct    REAL,
        net_bytes_sent   INTEGER,
        net_bytes_recv   INTEGER,
        active_conns     INTEGER
    )""")

    conn.commit()
    logger.info("Database schema initialised at %s", DB_PATH)


# ─────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────

def _exec(sql: str, params: tuple = (), fetchall: bool = False,
          fetchone: bool = False, lastrowid: bool = False):
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    if fetchall:
        return [dict(r) for r in cur.fetchall()]
    if fetchone:
        row = cur.fetchone()
        return dict(row) if row else None
    if lastrowid:
        return cur.lastrowid
    return None


# ─────────────────────────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────────────────────────

def insert_alert(level, category, message, source_ip=None, details=None):
    return _exec(
        "INSERT INTO alerts (timestamp,level,category,source_ip,message,details) "
        "VALUES (?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), level, category, source_ip, message, details),
        lastrowid=True
    )


def get_alerts(limit=100, level=None):
    if level:
        return _exec("SELECT * FROM alerts WHERE level=? ORDER BY id DESC LIMIT ?",
                     (level, limit), fetchall=True)
    return _exec("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,), fetchall=True)


def get_alert_counts_by_level():
    rows = _exec("SELECT level, COUNT(*) as cnt FROM alerts GROUP BY level", fetchall=True)
    return {r["level"]: r["cnt"] for r in rows}


# ─────────────────────────────────────────────────────────────
# ATTACKS
# ─────────────────────────────────────────────────────────────

def insert_attack(attack_type, source_ip=None, destination=None, port=None,
                  protocol=None, payload=None, threat_score=0):
    return _exec(
        "INSERT INTO attacks (timestamp,attack_type,source_ip,destination,"
        "port,protocol,payload,threat_score) VALUES (?,?,?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), attack_type, source_ip, destination,
         port, protocol, payload, threat_score),
        lastrowid=True
    )


def get_attacks(limit=200):
    return _exec("SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,), fetchall=True)


def get_attack_type_counts():
    return _exec(
        "SELECT attack_type, COUNT(*) as cnt FROM attacks "
        "GROUP BY attack_type ORDER BY cnt DESC",
        fetchall=True
    )


# ─────────────────────────────────────────────────────────────
# SSH ATTEMPTS
# ─────────────────────────────────────────────────────────────

def insert_ssh_attempt(source_ip, username=None, password=None,
                       success=False, port=22):
    return _exec(
        "INSERT INTO ssh_attempts (timestamp,source_ip,username,password,success,port) "
        "VALUES (?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), source_ip, username, password,
         1 if success else 0, port),
        lastrowid=True
    )


def get_ssh_attempts(limit=200):
    return _exec("SELECT * FROM ssh_attempts ORDER BY id DESC LIMIT ?", (limit,), fetchall=True)


def count_ssh_attempts_by_ip(ip, since_ts):
    row = _exec(
        "SELECT COUNT(*) as cnt FROM ssh_attempts WHERE source_ip=? AND timestamp>=?",
        (ip, since_ts), fetchone=True
    )
    return row["cnt"] if row else 0


def get_top_ssh_ips(limit=10):
    return _exec(
        "SELECT source_ip, COUNT(*) as cnt FROM ssh_attempts "
        "GROUP BY source_ip ORDER BY cnt DESC LIMIT ?",
        (limit,), fetchall=True
    )


# ─────────────────────────────────────────────────────────────
# PORT SCANS
# ─────────────────────────────────────────────────────────────

def insert_port_scan(source_ip, ports_hit, scan_type, threat_score=50):
    return _exec(
        "INSERT INTO port_scans (timestamp,source_ip,ports_hit,scan_type,threat_score) "
        "VALUES (?,?,?,?,?)",
        (datetime.utcnow().isoformat(), source_ip, ports_hit, scan_type, threat_score),
        lastrowid=True
    )


def get_port_scans(limit=100):
    return _exec("SELECT * FROM port_scans ORDER BY id DESC LIMIT ?", (limit,), fetchall=True)


# ─────────────────────────────────────────────────────────────
# FILE EVENTS
# ─────────────────────────────────────────────────────────────

def insert_file_event(event_type, path, size=None, is_suspect=False):
    return _exec(
        "INSERT INTO file_events (timestamp,event_type,path,size,is_suspect) "
        "VALUES (?,?,?,?,?)",
        (datetime.utcnow().isoformat(), event_type, path, size,
         1 if is_suspect else 0),
        lastrowid=True
    )


def get_file_events(limit=100):
    return _exec("SELECT * FROM file_events ORDER BY id DESC LIMIT ?", (limit,), fetchall=True)


# ─────────────────────────────────────────────────────────────
# LOG EVENTS
# ─────────────────────────────────────────────────────────────

def insert_log_event(source, raw_line, category=None, source_ip=None, username=None):
    return _exec(
        "INSERT INTO log_events (timestamp,source,raw_line,category,source_ip,username) "
        "VALUES (?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), source, raw_line, category, source_ip, username),
        lastrowid=True
    )


def get_log_events(limit=100):
    return _exec("SELECT * FROM log_events ORDER BY id DESC LIMIT ?", (limit,), fetchall=True)


# ─────────────────────────────────────────────────────────────
# PACKET EVENTS
# ─────────────────────────────────────────────────────────────

def insert_packet_event(src_ip, dst_ip, src_port, dst_port,
                        protocol, flags, size, suspicious=False):
    return _exec(
        "INSERT INTO packet_events (timestamp,src_ip,dst_ip,src_port,dst_port,"
        "protocol,flags,size,suspicious) VALUES (?,?,?,?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), src_ip, dst_ip, src_port, dst_port,
         protocol, flags, size, 1 if suspicious else 0),
        lastrowid=True
    )


def get_packet_events(limit=200):
    return _exec("SELECT * FROM packet_events ORDER BY id DESC LIMIT ?", (limit,), fetchall=True)


def get_packet_protocol_counts():
    return _exec(
        "SELECT protocol, COUNT(*) as cnt FROM packet_events "
        "GROUP BY protocol ORDER BY cnt DESC",
        fetchall=True
    )


# ─────────────────────────────────────────────────────────────
# IP THREAT SCORES
# ─────────────────────────────────────────────────────────────

def upsert_ip_score(ip: str, delta: int = 0, country: str = None,
                    isp: str = None, blocked: bool = None,
                    abuse_score: int = None, ti_checked: bool = None):
    """
    Create or update an IP threat score record.

    FIX: original code used filter(lambda x: x is not None, [...]) which
    accidentally filtered out legitimate 0/False values.  Now uses an
    explicit params list.
    """
    if not ip or not ip.strip():
        return  # FIX: never write a NULL / empty IP to ip_scores
    ip = ip.strip()

    conn = get_conn()
    cur  = conn.cursor()
    now  = datetime.utcnow().isoformat()

    cur.execute("SELECT * FROM ip_scores WHERE ip=?", (ip,))
    row = cur.fetchone()

    if row is None:
        cur.execute(
            "INSERT INTO ip_scores "
            "(ip,threat_score,country,isp,first_seen,last_seen,attack_count,blocked,ti_checked,abuse_score) "
            "VALUES (?,?,?,?,?,?,1,0,0,0)",
            (ip, max(0, delta), country or "", isp or "", now, now)
        )
    else:
        new_score = min(100, max(0, (row["threat_score"] or 0) + delta))

        # FIX: Build SET clause and params explicitly — no None-filter tricks
        set_parts  = ["threat_score=?", "last_seen=?", "attack_count=attack_count+1"]
        set_params = [new_score, now]

        if country is not None:
            set_parts.append("country=?");  set_params.append(country)
        if isp is not None:
            set_parts.append("isp=?");      set_params.append(isp)
        if blocked is not None:
            set_parts.append("blocked=?");  set_params.append(1 if blocked else 0)
        if abuse_score is not None:
            set_parts.append("abuse_score=?"); set_params.append(abuse_score)
        if ti_checked is not None:
            set_parts.append("ti_checked=?");  set_params.append(1 if ti_checked else 0)

        set_params.append(ip)
        sql = f"UPDATE ip_scores SET {', '.join(set_parts)} WHERE ip=?"
        cur.execute(sql, tuple(set_params))

    conn.commit()


def get_ip_score(ip: str) -> dict:
    return _exec("SELECT * FROM ip_scores WHERE ip=?", (ip,), fetchone=True)


def get_top_threat_ips(limit=20):
    return _exec(
        "SELECT * FROM ip_scores ORDER BY threat_score DESC LIMIT ?",
        (limit,), fetchall=True
    )


# ─────────────────────────────────────────────────────────────
# BLOCKED IPS
# ─────────────────────────────────────────────────────────────

def block_ip(ip: str, reason: str, method: str = "auto"):
    now = datetime.utcnow().isoformat()
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip,timestamp,reason,method) VALUES (?,?,?,?)",
        (ip, now, reason, method)
    )
    conn.commit()
    upsert_ip_score(ip, 0, blocked=True)


def is_blocked(ip: str) -> bool:
    row = _exec("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,), fetchone=True)
    return row is not None


def get_blocked_ips():
    return _exec("SELECT * FROM blocked_ips ORDER BY timestamp DESC", fetchall=True)


# ─────────────────────────────────────────────────────────────
# SYSTEM HEALTH
# ─────────────────────────────────────────────────────────────

def insert_health(cpu_pct, mem_pct, disk_pct, net_sent, net_recv, conns):
    _exec(
        "INSERT INTO system_health (timestamp,cpu_pct,mem_pct,disk_pct,"
        "net_bytes_sent,net_bytes_recv,active_conns) VALUES (?,?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), cpu_pct, mem_pct, disk_pct,
         net_sent, net_recv, conns)
    )


def get_health_history(limit=60):
    return _exec(
        "SELECT * FROM system_health ORDER BY id DESC LIMIT ?",
        (limit,), fetchall=True
    )


# ─────────────────────────────────────────────────────────────
# DASHBOARD SUMMARY
# ─────────────────────────────────────────────────────────────

def get_summary() -> dict:
    def scalar(sql, params=()):
        row = _exec(sql, params, fetchone=True)
        if row:
            return list(row.values())[0]
        return 0

    return {
        "total_alerts":     scalar("SELECT COUNT(*) FROM alerts"),
        "critical_alerts":  scalar("SELECT COUNT(*) FROM alerts WHERE level='CRITICAL'"),
        "high_alerts":      scalar("SELECT COUNT(*) FROM alerts WHERE level='HIGH'"),
        "total_attacks":    scalar("SELECT COUNT(*) FROM attacks"),
        "ssh_attempts":     scalar("SELECT COUNT(*) FROM ssh_attempts"),
        "port_scans":       scalar("SELECT COUNT(*) FROM port_scans"),
        "file_events":      scalar("SELECT COUNT(*) FROM file_events"),
        "blocked_ips":      scalar("SELECT COUNT(*) FROM blocked_ips"),
        "unique_attackers": scalar("SELECT COUNT(DISTINCT ip) FROM ip_scores WHERE threat_score>0"),
        "packets_captured": scalar("SELECT COUNT(*) FROM packet_events"),
    }