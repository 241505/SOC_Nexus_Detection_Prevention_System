"""
auth_detector.py — SSH / Auth Brute Force Detector
Tails Linux auth logs in real time and detects:
  - Single failed SSH login attempts
  - Brute-force bursts (N fails in T seconds)
  - Successful logins (potential compromise)
  - Invalid user attempts
  - Root login attempts
"""

import time
import threading
import logging
import os
from collections import defaultdict, deque
from datetime import datetime
from config import (
    AUTH_LOG_PATHS, LOG_POLL_INTERVAL,
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECS
)
from utils import parse_ssh_failed, parse_ssh_success, score_for
from database import insert_ssh_attempt, upsert_ip_score
import alerts

logger = logging.getLogger("auth_detector")


class AuthDetector(threading.Thread):
    """
    Background thread that monitors Linux authentication logs.
    Opens each log file, seeks to end, then continuously reads new lines.
    """

    def __init__(self, socketio=None):
        super().__init__(daemon=True, name="AuthDetector")
        self._stop_event = threading.Event()
        self._socketio   = socketio

        # Per-IP sliding window: { ip: deque([timestamp, ...]) }
        self._fail_windows: dict = defaultdict(deque)

        # Track which IPs triggered brute-force alert (avoid duplicates)
        self._brute_alerted: set = set()

        # { log_path: file_handle }
        self._handles: dict = {}

    # ──────────────────────────────────────────────────────────
    # THREAD MAIN
    # ──────────────────────────────────────────────────────────

    def run(self):
        logger.info("AuthDetector started — monitoring: %s", AUTH_LOG_PATHS)
        self._open_logs()

        while not self._stop_event.is_set():
            for path, fh in list(self._handles.items()):
                self._read_new_lines(path, fh)
            time.sleep(LOG_POLL_INTERVAL)

        self._close_all()

    def stop(self):
        self._stop_event.set()

    # ──────────────────────────────────────────────────────────
    # FILE MANAGEMENT
    # ──────────────────────────────────────────────────────────

    def _open_logs(self):
        """Open every available auth log file and seek to end."""
        for path in AUTH_LOG_PATHS:
            if os.path.isfile(path):
                try:
                    fh = open(path, "r", encoding="utf-8", errors="replace")
                    fh.seek(0, 2)  # Seek to end — only tail new lines
                    self._handles[path] = fh
                    logger.info("Monitoring auth log: %s", path)
                except PermissionError:
                    logger.warning("Permission denied reading %s", path)
            else:
                logger.debug("Auth log not found: %s", path)

        if not self._handles:
            logger.warning(
                "No auth logs accessible. Running without real SSH log monitoring. "
                "Try: sudo python app.py  or  add user to adm group."
            )

    def _close_all(self):
        for fh in self._handles.values():
            try:
                fh.close()
            except Exception:
                pass

    def _read_new_lines(self, path: str, fh):
        """Read any new lines appended to the log file."""
        try:
            while True:
                line = fh.readline()
                if not line:
                    break
                self._process_line(path, line.rstrip())
        except OSError as e:
            logger.warning("Error reading %s: %s — will reopen", path, e)
            try:
                fh.close()
            except Exception:
                pass
            self._reopen(path)

    def _reopen(self, path: str):
        """Reopen a log file (handles log rotation)."""
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
            fh.seek(0, 2)
            self._handles[path] = fh
            logger.info("Reopened rotated log: %s", path)
        except Exception as e:
            logger.warning("Could not reopen %s: %s", path, e)
            del self._handles[path]

    # ──────────────────────────────────────────────────────────
    # LINE PROCESSING
    # ──────────────────────────────────────────────────────────

    def _process_line(self, source: str, line: str):
        """Classify a single log line and act on it."""
        # -- Failed SSH login --
        parsed = parse_ssh_failed(line)
        if parsed:
            username, ip, port = parsed
            self._on_ssh_fail(source, line, ip, username, port)
            return

        # -- Successful SSH login --
        parsed = parse_ssh_success(line)
        if parsed:
            username, ip, port = parsed
            self._on_ssh_success(source, line, ip, username, port)
            return

        # -- Root login attempt --
        if "ROOT LOGIN" in line or "root login" in line.lower():
            logger.warning("Root login attempt detected: %s", line[:120])
            alerts.fire(
                level="HIGH",
                category="auth",
                message="Root login attempt detected",
                details={"line": line[:200]}
            )

    # ──────────────────────────────────────────────────────────
    # EVENT HANDLERS
    # ──────────────────────────────────────────────────────────

    def _on_ssh_fail(self, source: str, line: str, ip: str,
                     username: str, port: int):
        """Handle a single failed SSH authentication."""
        now = time.time()

        # Store in DB
        insert_ssh_attempt(
            source_ip=ip,
            username=username,
            password=None,
            success=False,
            port=port or 22
        )

        # Update threat score
        upsert_ip_score(ip, delta=score_for("ssh_fail"))

        # Emit live event to dashboard
        self._emit("ssh_fail", {
            "ip":       ip,
            "username": username,
            "port":     port,
            "source":   source,
        })

        # Sliding-window brute-force check
        window = self._fail_windows[ip]
        window.append(now)

        # Evict timestamps outside the window
        cutoff = now - BRUTE_FORCE_WINDOW_SECS
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= BRUTE_FORCE_THRESHOLD:
            self._on_brute_force(ip, username, len(window))

    def _on_ssh_success(self, source: str, line: str, ip: str,
                        username: str, port: int):
        """Handle a successful SSH login — possible compromise."""
        insert_ssh_attempt(
            source_ip=ip,
            username=username,
            success=True,
            port=port or 22
        )

        level = "CRITICAL" if username == "root" else "HIGH"
        alerts.fire(
            level=level,
            category="auth",
            message=f"Successful SSH login: user='{username}' from {ip}",
            source_ip=ip,
            details={"username": username, "port": port, "source": source},
        )

        self._emit("ssh_success", {
            "ip": ip, "username": username, "port": port
        })

    def _on_brute_force(self, ip: str, last_user: str, count: int):
        """Triggered when brute-force threshold is exceeded."""
        # Only fire once per attacker per burst
        key = f"{ip}:{int(time.time() // BRUTE_FORCE_WINDOW_SECS)}"
        if key in self._brute_alerted:
            return
        self._brute_alerted.add(key)

        # Bump threat score aggressively
        upsert_ip_score(ip, delta=score_for("ssh_brute"))

        alerts.fire(
            level="HIGH",
            category="brute_force",
            message=(
                f"SSH brute-force detected from {ip} — "
                f"{count} failures in {BRUTE_FORCE_WINDOW_SECS}s"
            ),
            source_ip=ip,
            details={"attempts": count, "last_user": last_user},
        )

        self._emit("brute_force", {
            "ip": ip, "count": count, "last_user": last_user
        })
        logger.warning("BRUTE FORCE: %s — %d attempts", ip, count)

    # ──────────────────────────────────────────────────────────
    # SOCKETIO EMIT
    # ──────────────────────────────────────────────────────────

    def _emit(self, event: str, data: dict):
        if self._socketio:
            try:
                self._socketio.emit(event, data)
            except Exception:
                pass