"""
portscan_detector.py — Port Scan Detection Engine
Analyses packets captured by packet_sniffer.py and identifies:
  - TCP SYN scans (classic nmap -sS)
  - FIN / XMAS / NULL scans
  - UDP scans
  - Connect scans
  - Rapid port sweeps
Uses a per-IP sliding window of destination ports.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from config import PORTSCAN_THRESHOLD, PORTSCAN_WINDOW_SECS
from database import insert_port_scan, upsert_ip_score
from utils import score_for
import alerts

logger = logging.getLogger("portscan_detector")


class PortScanDetector:
    """
    Stateful per-IP tracker.
    Feed packets via process_packet(); detections are asynchronous.
    """

    def __init__(self, socketio=None):
        self._socketio = socketio

        # { src_ip: deque([(timestamp, dst_port), ...]) }
        self._port_windows: dict = defaultdict(deque)

        # Prevent duplicate alerts per burst window
        self._alerted: set = set()

        # Cleanup thread
        self._cleaner = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="PScanCleaner"
        )
        self._cleaner.start()

    # ──────────────────────────────────────────────────────────
    # PUBLIC INTERFACE
    # ──────────────────────────────────────────────────────────

    def process_packet(self, src_ip: str, dst_port: int,
                       protocol: str, flags: str):
        """
        Called by packet_sniffer for every TCP/UDP packet.
        Returns True if a scan was detected.
        """
        now = time.time()
        window = self._port_windows[src_ip]
        window.append((now, dst_port))

        # Evict old entries
        cutoff = now - PORTSCAN_WINDOW_SECS
        while window and window[0][0] < cutoff:
            window.popleft()

        # Collect unique ports in window
        unique_ports = {p for _, p in window}

        # Check TCP flag-based scan types
        scan_type = self._classify_scan(flags, protocol)

        if len(unique_ports) >= PORTSCAN_THRESHOLD or scan_type in ("FIN", "XMAS", "NULL"):
            self._on_scan_detected(src_ip, unique_ports, scan_type)
            return True

        return False

    # ──────────────────────────────────────────────────────────
    # SCAN CLASSIFICATION
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _classify_scan(flags: str, protocol: str) -> str:
        """
        Derive scan type from TCP flags string.
        flags is a comma-separated list e.g. "SYN" / "SYN,ACK" / "FIN,URG,PSH"
        """
        if protocol == "UDP":
            return "UDP"
        if not flags:
            return "CONNECT"

        flag_set = set(f.strip().upper() for f in flags.split(","))

        if flag_set == {"SYN"}:
            return "SYN"
        if flag_set == {"FIN"}:
            return "FIN"
        if "FIN" in flag_set and "URG" in flag_set and "PSH" in flag_set:
            return "XMAS"
        if not flag_set or flag_set == set():
            return "NULL"
        if "SYN" in flag_set and "ACK" in flag_set:
            return "CONNECT"
        return "UNKNOWN"

    # ──────────────────────────────────────────────────────────
    # DETECTION HANDLER
    # ──────────────────────────────────────────────────────────

    def _on_scan_detected(self, src_ip: str, ports: set, scan_type: str):
        """Called when a port scan burst is confirmed."""
        # Dedup per burst window
        key = f"{src_ip}:{int(time.time() // PORTSCAN_WINDOW_SECS)}"
        if key in self._alerted:
            return
        self._alerted.add(key)

        ports_list  = sorted(ports)
        ports_str   = ",".join(str(p) for p in ports_list[:50])  # cap at 50
        score       = score_for("syn_scan") if scan_type == "SYN" else score_for("port_scan")

        # Persist to DB
        insert_port_scan(
            source_ip=src_ip,
            ports_hit=ports_str,
            scan_type=scan_type,
            threat_score=score
        )
        upsert_ip_score(src_ip, delta=score)

        # Fire alert
        level = "HIGH" if scan_type in ("SYN", "FIN", "XMAS", "NULL") else "MEDIUM"
        alerts.fire(
            level=level,
            category="port_scan",
            message=(
                f"{scan_type} port scan from {src_ip} — "
                f"{len(ports)} unique ports in {PORTSCAN_WINDOW_SECS}s"
            ),
            source_ip=src_ip,
            details={
                "scan_type":   scan_type,
                "port_count":  len(ports),
                "sample_ports": ports_list[:20],
            },
        )

        # Emit to dashboard
        if self._socketio:
            try:
                self._socketio.emit("port_scan", {
                    "ip":        src_ip,
                    "scan_type": scan_type,
                    "ports":     ports_list[:20],
                    "count":     len(ports),
                })
            except Exception:
                pass

        logger.warning("PORT SCAN [%s]: %s — %d ports", scan_type, src_ip, len(ports))

    # ──────────────────────────────────────────────────────────
    # CLEANUP
    # ──────────────────────────────────────────────────────────

    def _cleanup_loop(self):
        """Periodically purge stale windows and alerted keys."""
        while True:
            time.sleep(60)
            cutoff = time.time() - PORTSCAN_WINDOW_SECS * 2
            for ip in list(self._port_windows.keys()):
                w = self._port_windows[ip]
                while w and w[0][0] < cutoff:
                    w.popleft()
                if not w:
                    del self._port_windows[ip]

            # Keep alerted set bounded
            if len(self._alerted) > 5000:
                self._alerted.clear()