
"""
detector.py — Central Detection Orchestrator
Coordinates all monitoring modules:
  - AuthDetector      (SSH brute-force, auth.log)
  - PacketSniffer     (network capture + port scan)
  - FileMonitor       (filesystem watchdog)
  - LogMonitor        (journalctl + syslog)
  - MalwareDetector   (signature scan)
  - HoneypotEngine    (fake services)
Also runs the system health reporter and threat intel enrichment loop.
"""

import time
import threading
import logging
import psutil
from datetime import datetime
from config import HEALTH_POLL_INTERVAL
from database import (
    insert_health, get_summary, upsert_ip_score,
    get_top_threat_ips
)
from auth_detector   import AuthDetector
from packet_sniffer  import PacketSniffer
from file_monitor    import FileMonitor
from log_monitor     import LogMonitor
from malware_detector import MalwareDetector
from honeypot        import HoneypotEngine
import geoip
import threat_intel

logger = logging.getLogger("detector")


class ThreatDetector:
    """
    Master controller for the entire monitoring system.
    Called from app.py at startup.
    """

    def __init__(self, socketio):
        self._sio      = socketio
        self._modules  = []
        self._running  = False

        # Initialise all sub-modules
        self.auth_detector    = AuthDetector(socketio)
        self.packet_sniffer   = PacketSniffer(socketio)
        self.file_monitor     = FileMonitor(socketio)
        self.log_monitor      = LogMonitor(socketio)
        self.malware_detector = MalwareDetector(socketio)
        self.honeypot_engine  = HoneypotEngine(socketio)

        # Background workers
        self._health_thread = threading.Thread(
            target=self._health_loop, daemon=True, name="HealthReporter"
        )
        self._enrich_thread = threading.Thread(
            target=self._enrich_loop, daemon=True, name="ThreatEnricher"
        )
        self._geo_broadcast = threading.Thread(
            target=self._geo_loop, daemon=True, name="GeosBroadcaster"
        )

    # ──────────────────────────────────────────────────────────
    # START / STOP
    # ──────────────────────────────────────────────────────────

    def start_all(self):
        """Start every monitoring module."""
        logger.info("Starting all detection modules…")

        # Threaded monitors
        self.auth_detector.start()
        self.packet_sniffer.start()
        self.honeypot_engine.start()

        # Non-threaded managers (start internally)
        self.file_monitor.start()
        self.log_monitor.start()
        self.malware_detector.start()

        # Background workers
        self._health_thread.start()
        self._enrich_thread.start()
        self._geo_broadcast.start()

        self._running = True
        logger.info("All detection modules started ✓")

    def stop_all(self):
        """Gracefully stop all modules."""
        logger.info("Stopping all detection modules…")
        self.auth_detector.stop()
        self.packet_sniffer.stop()
        self.file_monitor.stop()
        self.log_monitor.stop()
        self.malware_detector.stop()
        self.honeypot_engine.stop()
        self._running = False

    # ──────────────────────────────────────────────────────────
    # SYSTEM HEALTH REPORTER
    # ──────────────────────────────────────────────────────────

    def _health_loop(self):
        """
        Collect CPU / RAM / Disk / Network metrics every N seconds
        and push to DB + dashboard.
        """
        net_prev = psutil.net_io_counters()
        while True:
            try:
                cpu   = psutil.cpu_percent(interval=1)
                mem   = psutil.virtual_memory().percent
                disk  = psutil.disk_usage("/").percent
                net   = psutil.net_io_counters()
                conns = len(psutil.net_connections())

                net_sent  = net.bytes_sent  - net_prev.bytes_sent
                net_recv  = net.bytes_recv  - net_prev.bytes_recv
                net_prev  = net

                insert_health(cpu, mem, disk, net_sent, net_recv, conns)

                self._sio.emit("system_health", {
                    "timestamp":  datetime.utcnow().isoformat(),
                    "cpu":        cpu,
                    "memory":     mem,
                    "disk":       disk,
                    "net_sent":   net_sent,
                    "net_recv":   net_recv,
                    "connections": conns,
                    "pkt_rate":   self.packet_sniffer.packets_per_second(),
                })

            except Exception as e:
                logger.debug("Health reporter error: %s", e)

            time.sleep(HEALTH_POLL_INTERVAL)

    # ──────────────────────────────────────────────────────────
    # THREAT INTELLIGENCE ENRICHMENT LOOP
    # ──────────────────────────────────────────────────────────

    def _enrich_loop(self):
        """
        Periodically enrich top-threat IPs with AbuseIPDB / blacklist data.
        Runs every 5 minutes to respect API rate limits.
        """
        while True:
            try:
                top_ips = get_top_threat_ips(limit=10)
                for record in top_ips:
                    ip = record.get("ip", "")
                    if not ip or record.get("ti_checked"):
                        continue
                    ti = threat_intel.check_ip(ip)
                    upsert_ip_score(
                        ip,
                        delta=ti["abuse_score"] // 4,   # Convert abuse% to score delta
                        abuse_score=ti["abuse_score"],
                        ti_checked=True
                    )
                    if ti["flagged"]:
                        import alerts
                        alerts.fire(
                            level="HIGH",
                            category="threat_intel",
                            message=(
                                f"Threat Intel: {ip} flagged — "
                                f"{ti['reason']} (AbuseScore={ti['abuse_score']}%)"
                            ),
                            source_ip=ip,
                            details=ti,
                        )
                    time.sleep(1.5)   # Gentle pacing between TI calls
            except Exception as e:
                logger.debug("Enrich loop error: %s", e)
            time.sleep(300)   # 5 minutes

    # ──────────────────────────────────────────────────────────
    # GEO BROADCAST LOOP
    # ──────────────────────────────────────────────────────────

    def _geo_loop(self):
        """
        Periodically push geolocation data for top attacker IPs.
        Used to populate the attack map on the dashboard.
        """
        while True:
            try:
                top_ips   = get_top_threat_ips(limit=20)
                geo_data  = []
                for record in top_ips:
                    ip  = record.get("ip", "")
                    geo = geoip.lookup(ip)
                    geo_data.append({
                        "ip":           ip,
                        "threat_score": record.get("threat_score", 0),
                        "attack_count": record.get("attack_count", 0),
                        "country":      geo.get("country", "Unknown"),
                        "region":       geo.get("region", ""),
                        "city":         geo.get("city", ""),
                        "isp":          geo.get("isp", ""),
                        "lat":          geo.get("lat", 0),
                        "lon":          geo.get("lon", 0),
                        "blocked":      record.get("blocked", 0),
                    })
                    time.sleep(0.1)  # Rate limiting

                if geo_data:
                    self._sio.emit("geo_update", {"attackers": geo_data})

            except Exception as e:
                logger.debug("Geo loop error: %s", e)
            time.sleep(30)   # Broadcast every 30 seconds

    # ──────────────────────────────────────────────────────────
    # SUMMARY (for REST endpoint)
    # ──────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "running":         self._running,
            "auth_detector":   self.auth_detector.is_alive(),
            "packet_sniffer":  self.packet_sniffer.is_alive(),
            "file_monitor":    self.file_monitor.is_running,
            "honeypot":        self.honeypot_engine.is_alive(),
            "summary":         get_summary(),
            "pkt_stats":       self.packet_sniffer.get_stats(),
        }