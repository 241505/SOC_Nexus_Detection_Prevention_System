"""
app.py — Main Flask + Flask-SocketIO Application
Entry point for the Adaptive Honeypot + Threat Monitoring System.

FIX LOG:
  - threat_intel module was imported inconsistently (threatintel vs threat_intel).
    Standardised to: import threat_intel
  - Added None-IP guard in /api/threat-intel/<ip> and /api/geo
  - Added CORS headers for SocketIO compatibility
  - Ensured template/static folders resolve correctly relative to this file
  - Added /api/ping health-check endpoint for quick connectivity test
"""

import os
import sys
import json
import logging
import threading
from datetime import datetime, timedelta

from flask import Flask, render_template, jsonify, request, abort
from flask_socketio import SocketIO, emit

# ── Local modules ─────────────────────────────────────────────
from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG, SECRET_KEY
)
from database import init_db, get_summary, get_alerts, get_attacks
from database import (
    get_ssh_attempts, get_port_scans, get_file_events,
    get_log_events, get_packet_events, get_blocked_ips,
    get_top_threat_ips, get_health_history,
    get_packet_protocol_counts, get_attack_type_counts,
    get_top_ssh_ips, get_alert_counts_by_level
)
from utils   import setup_logging, banner
import alerts
import response_engine

# ── Logging ───────────────────────────────────────────────────
logger = setup_logging("app", logging.INFO)

# ── Flask app ─────────────────────────────────────────────────
# __file__ is always this script; resolve templates/static relative to it
_BASE = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(_BASE, "dashboard", "templates"),
    static_folder=os.path.join(_BASE, "dashboard", "static"),
)
app.config["SECRET_KEY"] = SECRET_KEY

# ── Socket.IO ─────────────────────────────────────────────────
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
    ping_timeout=20,
    ping_interval=10,
)

# Inject Socket.IO into alert and response modules
alerts.set_socketio(socketio)
response_engine.set_socketio(socketio)

# ── Global detector instance ──────────────────────────────────
_detector = None


# ─────────────────────────────────────────────────────────────
# MAIN DASHBOARD PAGE
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main SOC dashboard."""
    return render_template("index.html")


# ─────────────────────────────────────────────────────────────
# QUICK HEALTH CHECK
# ─────────────────────────────────────────────────────────────

@app.route("/api/ping")
def api_ping():
    return jsonify({"ok": True, "ts": datetime.utcnow().isoformat()})


# ─────────────────────────────────────────────────────────────
# REST API — SUMMARY
# ─────────────────────────────────────────────────────────────

@app.route("/api/summary")
def api_summary():
    return jsonify(get_summary())


@app.route("/api/status")
def api_status():
    if _detector:
        return jsonify(_detector.get_status())
    return jsonify({"running": False,
                    "auth_detector": False, "packet_sniffer": False,
                    "file_monitor":  False, "honeypot": False,
                    "summary": get_summary()})


# ─────────────────────────────────────────────────────────────
# REST API — ALERTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 100))
    level = request.args.get("level")
    return jsonify(get_alerts(limit=limit, level=level))


@app.route("/api/alerts/counts")
def api_alert_counts():
    return jsonify(get_alert_counts_by_level())


# ─────────────────────────────────────────────────────────────
# REST API — ATTACKS
# ─────────────────────────────────────────────────────────────

@app.route("/api/attacks")
def api_attacks():
    limit = int(request.args.get("limit", 200))
    return jsonify(get_attacks(limit=limit))


@app.route("/api/attacks/types")
def api_attack_types():
    return jsonify(get_attack_type_counts())


# ─────────────────────────────────────────────────────────────
# REST API — SSH ATTEMPTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/ssh")
def api_ssh():
    limit = int(request.args.get("limit", 200))
    return jsonify(get_ssh_attempts(limit=limit))


@app.route("/api/ssh/top-ips")
def api_ssh_top_ips():
    return jsonify(get_top_ssh_ips(limit=10))


# ─────────────────────────────────────────────────────────────
# REST API — PORT SCANS
# ─────────────────────────────────────────────────────────────

@app.route("/api/portscans")
def api_portscans():
    limit = int(request.args.get("limit", 100))
    return jsonify(get_port_scans(limit=limit))


# ─────────────────────────────────────────────────────────────
# REST API — FILE EVENTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/files")
def api_files():
    limit = int(request.args.get("limit", 100))
    return jsonify(get_file_events(limit=limit))


# ─────────────────────────────────────────────────────────────
# REST API — LOG EVENTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 100))
    return jsonify(get_log_events(limit=limit))


# ─────────────────────────────────────────────────────────────
# REST API — PACKET EVENTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/packets")
def api_packets():
    limit = int(request.args.get("limit", 200))
    return jsonify(get_packet_events(limit=limit))


@app.route("/api/packets/protocols")
def api_packet_protocols():
    return jsonify(get_packet_protocol_counts())


# ─────────────────────────────────────────────────────────────
# REST API — THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────

@app.route("/api/threat-ips")
def api_threat_ips():
    limit = int(request.args.get("limit", 20))
    return jsonify(get_top_threat_ips(limit=limit))


@app.route("/api/threat-intel/<ip>")
def api_threat_intel(ip: str):
    """On-demand threat intel lookup for a specific IP."""
    # FIX: was importing as 'threat_intel' (correct) but module was also
    # referenced as 'threatintel' elsewhere — standardised here.
    import threat_intel
    import geoip
    if not ip:
        return jsonify({"error": "IP required"}), 400
    ti  = threat_intel.check_ip(ip)
    geo = geoip.lookup(ip)
    return jsonify({**ti, "geo": geo})


# ─────────────────────────────────────────────────────────────
# REST API — BLOCKED IPS
# ─────────────────────────────────────────────────────────────

@app.route("/api/blocked")
def api_blocked():
    return jsonify(get_blocked_ips())


@app.route("/api/block", methods=["POST"])
def api_block_ip():
    data   = request.get_json(force=True)
    ip     = (data.get("ip") or "").strip()
    reason = data.get("reason", "manual block from dashboard")
    if not ip:
        return jsonify({"success": False, "msg": "IP required"}), 400
    result = response_engine.manual_block(ip, reason)
    return jsonify(result)


@app.route("/api/unblock", methods=["POST"])
def api_unblock_ip():
    data = request.get_json(force=True)
    ip   = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"success": False, "msg": "IP required"}), 400
    result = response_engine.manual_unblock(ip)
    return jsonify(result)


# ─────────────────────────────────────────────────────────────
# REST API — SYSTEM HEALTH
# ─────────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    limit = int(request.args.get("limit", 60))
    return jsonify(get_health_history(limit=limit))


# ─────────────────────────────────────────────────────────────
# REST API — GEO DATA
# ─────────────────────────────────────────────────────────────

@app.route("/api/geo")
def api_geo():
    import geoip
    top    = get_top_threat_ips(limit=50)
    result = []
    for r in top:
        ip = (r.get("ip") or "").strip()
        if not ip:
            continue   # FIX: skip None/empty IPs that caused lookup errors
        geo = geoip.lookup(ip)
        result.append({
            "ip":           ip,
            "threat_score": r.get("threat_score", 0),
            "attack_count": r.get("attack_count", 0),
            "blocked":      r.get("blocked", 0),
            **geo
        })
    return jsonify(result)


# ─────────────────────────────────────────────────────────────
# REST API — TIMELINE (last 24h attack histogram)
# ─────────────────────────────────────────────────────────────

@app.route("/api/timeline")
def api_timeline():
    from database import get_conn
    conn  = get_conn()
    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    rows  = conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, "
        "COUNT(*) as cnt FROM attacks WHERE timestamp >= ? "
        "GROUP BY hour ORDER BY hour",
        (since,)
    ).fetchall()
    return jsonify([{"hour": r[0], "count": r[1]} for r in rows])


# ─────────────────────────────────────────────────────────────
# SOCKET.IO EVENTS
# ─────────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    logger.info("Dashboard client connected: %s", request.sid)
    emit("init_data", {
        "summary":    get_summary(),
        "alerts":     get_alerts(limit=30),
        "attacks":    get_attacks(limit=30),
        "threat_ips": get_top_threat_ips(limit=10),
        "ssh_top":    get_top_ssh_ips(limit=5),
    })


@socketio.on("disconnect")
def on_disconnect():
    logger.info("Dashboard client disconnected: %s", request.sid)


@socketio.on("request_summary")
def on_request_summary():
    emit("summary_update", get_summary())


@socketio.on("request_geo")
def on_request_geo():
    import geoip
    top    = get_top_threat_ips(limit=30)
    result = []
    for r in top:
        ip = (r.get("ip") or "").strip()
        if not ip:
            continue
        geo = geoip.lookup(ip)
        result.append({
            "ip":           ip,
            "threat_score": r.get("threat_score", 0),
            "attack_count": r.get("attack_count", 0),
            "lat":          geo.get("lat", 0),
            "lon":          geo.get("lon", 0),
            "country":      geo.get("country", "Unknown"),
            "blocked":      r.get("blocked", 0),
        })
    emit("geo_update", {"attackers": result})


# ─────────────────────────────────────────────────────────────
# APPLICATION STARTUP
# ─────────────────────────────────────────────────────────────

def start_monitoring():
    global _detector
    init_db()
    logger.info("Database initialised")
    from detector import ThreatDetector
    _detector = ThreatDetector(socketio)
    _detector.start_all()
    logger.info("All monitoring modules running")


def main():
    banner()
    logger.info("Starting SOC Nexus on %s:%d", FLASK_HOST, FLASK_PORT)
    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()
    socketio.run(
        app,
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":
    main()