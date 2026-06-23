"""
packet_sniffer.py — Real Network Packet Capture Module
Uses Scapy to sniff live traffic on the system's network interface.
Requires root / CAP_NET_RAW capability.

Feeds:
  - PortScanDetector — for scan detection
  - Database — for packet logging
  - Dashboard — via Socket.IO
"""

import time
import threading
import logging
from collections import defaultdict, deque
from datetime import datetime
from config import SNIFF_INTERFACE, SNIFF_FILTER, SNIFF_BATCH_SIZE
from database import insert_packet_event, upsert_ip_score
from utils import get_default_interface, is_private_ip, score_for
from portscan_detector import PortScanDetector
import alerts

logger = logging.getLogger("packet_sniffer")

# Lazy Scapy import — Scapy prints banners on import so we suppress that
import os as _os
_os.environ.setdefault("SCAPY_SILENCE_WARNINGS", "1")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
    from scapy.layers.inet import TCP as _TCP
    SCAPY_AVAILABLE = True
    conf.verb = 0            # Silence Scapy output
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed. Packet sniffing disabled. pip install scapy")


class PacketSniffer(threading.Thread):
    """
    Background thread that captures packets using Scapy.
    Falls back gracefully if Scapy is unavailable or no root access.
    """

    def __init__(self, socketio=None):
        super().__init__(daemon=True, name="PacketSniffer")
        self._stop_event  = threading.Event()
        self._socketio    = socketio
        self._interface   = SNIFF_INTERFACE or get_default_interface()
        self._scan_detector = PortScanDetector(socketio)

        # Per-IP counters for dashboard bandwidth stats
        self._ip_packet_count: dict = defaultdict(int)
        self._ip_byte_count:   dict = defaultdict(int)

        # Batch buffer: accumulate packets before DB insert + emit
        self._batch:      list = []
        self._batch_lock  = threading.Lock()

        # Rolling packet rate (packets/sec)
        self._pkt_times: deque = deque(maxlen=1000)

        logger.info("PacketSniffer initialised on interface: %s", self._interface)

    # ──────────────────────────────────────────────────────────
    # THREAD MAIN
    # ──────────────────────────────────────────────────────────

    def run(self):
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy unavailable — packet sniffer thread idle")
            self._stop_event.wait()
            return

        logger.info("Starting packet capture on %s (filter: %s)",
                    self._interface, SNIFF_FILTER)
        try:
            sniff(
                iface=self._interface,
                filter=SNIFF_FILTER,
                prn=self._handle_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,      # Don't store in memory
            )
        except PermissionError:
            logger.error(
                "Packet capture requires root / CAP_NET_RAW. "
                "Run with: sudo python app.py"
            )
        except Exception as e:
            logger.error("Packet capture error: %s", e)

    def stop(self):
        self._stop_event.set()

    # ──────────────────────────────────────────────────────────
    # PACKET HANDLER (called per packet from Scapy thread)
    # ──────────────────────────────────────────────────────────

    def _handle_packet(self, pkt):
        """Process a single captured packet."""
        self._pkt_times.append(time.time())

        # We only care about IP packets
        if not pkt.haslayer(IP):
            return

        ip_layer  = pkt[IP]
        src_ip    = ip_layer.src
        dst_ip    = ip_layer.dst
        pkt_size  = len(pkt)

        # Determine protocol and extract ports / flags
        protocol  = "OTHER"
        src_port  = 0
        dst_port  = 0
        flags_str = ""
        suspicious = False

        if pkt.haslayer(TCP):
            protocol  = "TCP"
            tcp       = pkt[TCP]
            src_port  = tcp.sport
            dst_port  = tcp.dport
            flags_str = self._tcp_flags(tcp.flags)

            # Feed port-scan detector
            suspicious = self._scan_detector.process_packet(
                src_ip=src_ip,
                dst_port=dst_port,
                protocol="TCP",
                flags=flags_str
            )

        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp      = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

            # DNS amplification heuristic (large UDP response to port 53)
            if src_port == 53 and pkt_size > 512:
                suspicious = True

            # UDP scan check
            self._scan_detector.process_packet(
                src_ip=src_ip,
                dst_port=dst_port,
                protocol="UDP",
                flags=""
            )

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp     = pkt[ICMP]
            # ICMP flood detection: many pings from same source
            self._ip_packet_count[src_ip] += 1
            if self._ip_packet_count[src_ip] % 100 == 0:
                suspicious = True
                alerts.fire(
                    level="MEDIUM",
                    category="network",
                    message=f"ICMP flood suspected from {src_ip}",
                    source_ip=src_ip,
                    details={"count": self._ip_packet_count[src_ip]},
                )

        # Update counters
        self._ip_packet_count[src_ip] = self._ip_packet_count.get(src_ip, 0) + 1
        self._ip_byte_count[src_ip]   = self._ip_byte_count.get(src_ip, 0) + pkt_size

        # Add to batch
        entry = {
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  protocol,
            "flags":     flags_str,
            "size":      pkt_size,
            "suspicious": suspicious,
        }

        with self._batch_lock:
            self._batch.append(entry)
            if len(self._batch) >= SNIFF_BATCH_SIZE:
                self._flush_batch()

    # ──────────────────────────────────────────────────────────
    # BATCH FLUSH
    # ──────────────────────────────────────────────────────────

    def _flush_batch(self):
        """Persist batch to DB and emit to dashboard. Called with _batch_lock held."""
        if not self._batch:
            return

        batch = self._batch[:]
        self._batch.clear()

        # Persist each packet event to DB
        for e in batch:
            try:
                insert_packet_event(
                    e["src_ip"], e["dst_ip"],
                    e["src_port"], e["dst_port"],
                    e["protocol"], e["flags"],
                    e["size"], e["suspicious"]
                )
            except Exception:
                pass

        # Emit aggregated batch to dashboard
        if self._socketio:
            try:
                self._socketio.emit("packet_batch", {
                    "packets": batch,
                    "pkt_rate": self.packets_per_second(),
                })
            except Exception:
                pass

    # ──────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _tcp_flags(flags_int) -> str:
        """Convert Scapy TCP flags integer to readable string."""
        flag_map = {
            0x01: "FIN",
            0x02: "SYN",
            0x04: "RST",
            0x08: "PSH",
            0x10: "ACK",
            0x20: "URG",
            0x40: "ECE",
            0x80: "CWR",
        }
        active = [name for bit, name in flag_map.items() if flags_int & bit]
        return ",".join(active) if active else ""

    def packets_per_second(self) -> float:
        """Return rolling packets/second over the last 5 seconds."""
        now    = time.time()
        cutoff = now - 5.0
        recent = sum(1 for t in self._pkt_times if t >= cutoff)
        return round(recent / 5.0, 2)

    def get_top_talkers(self, n: int = 10) -> list:
        """Return top N IPs by packet count."""
        return sorted(
            [{"ip": ip, "packets": cnt}
             for ip, cnt in self._ip_packet_count.items()],
            key=lambda x: x["packets"],
            reverse=True
        )[:n]

    def get_stats(self) -> dict:
        return {
            "interface":   self._interface,
            "pkt_per_sec": self.packets_per_second(),
            "top_talkers": self.get_top_talkers(5),
            "scapy_ok":    SCAPY_AVAILABLE,
        }