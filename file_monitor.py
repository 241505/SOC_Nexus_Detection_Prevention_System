"""
file_monitor.py — File System Monitor
Uses the Watchdog library to monitor sensitive directories for:
  - File creation / modification / deletion
  - Rapid mass-change (ransomware heuristic)
  - Known malicious file names / extensions
  - Changes to system binaries in /usr/bin, /etc
"""

import os
import time
import threading
import logging
from collections import defaultdict, deque
from config import (
    MONITORED_DIRS, MONITORED_DIRS_EXTRA,
    RAPID_CHANGE_COUNT, RAPID_CHANGE_WINDOW
)
from database import insert_file_event, upsert_ip_score
from utils import safe_file_size, score_for
import alerts

logger = logging.getLogger("file_monitor")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not installed. File monitoring disabled. pip install watchdog")


# Known malicious / suspicious file extensions
SUSPECT_EXTENSIONS = {
    ".sh", ".py", ".pl", ".rb",       # Script files dropped in /tmp
    ".elf", ".out",                    # ELF binaries dropped in /tmp
    ".locked", ".enc", ".crypted",    # Ransomware suffixes
    ".crypt", ".encrypted", ".ransom",
    ".php", ".jsp", ".asp",           # Web shells
}

# Patterns in filenames that are suspicious
SUSPECT_PATTERNS = [
    "backdoor", "rootkit", "shell", "payload",
    "exploit", "meterpreter", "reverse", "bind",
    "cmd", "c99", "r57", "webshell",
]

# Directories where executables should NOT be created at runtime
EXEC_WATCH_DIRS = ["/tmp", "/var/tmp", "/dev/shm"]


class _HoneypotEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler — passed to Observer for each monitored directory.
    """

    def __init__(self, rapid_tracker, socketio=None):
        super().__init__()
        self._rapid_tracker = rapid_tracker
        self._socketio      = socketio

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle("created", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle("modified", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._handle("deleted", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._handle("moved", event.dest_path)

    def _handle(self, event_type: str, path: str):
        """Classify and store a file event."""
        suspect  = self._is_suspect(path)
        size     = safe_file_size(path) if event_type != "deleted" else 0

        # Persist to DB
        insert_file_event(
            event_type=event_type,
            path=path,
            size=size,
            is_suspect=suspect
        )

        # Emit to dashboard
        payload = {
            "event_type": event_type,
            "path":       path,
            "size":       size,
            "suspect":    suspect,
        }
        if self._socketio:
            try:
                self._socketio.emit("file_event", payload)
            except Exception:
                pass

        # Rapid-change tracking (ransomware heuristic)
        self._rapid_tracker.record(path)

        if suspect:
            alerts.fire(
                level="HIGH",
                category="file_event",
                message=(
                    f"Suspicious file {event_type}: {os.path.basename(path)}"
                ),
                details={"path": path, "size": size, "event": event_type},
            )
            logger.warning("SUSPECT FILE [%s]: %s", event_type.upper(), path)
        else:
            logger.debug("File event [%s]: %s", event_type, path)

    @staticmethod
    def _is_suspect(path: str) -> bool:
        """Return True if the file path looks suspicious."""
        basename   = os.path.basename(path).lower()
        ext        = os.path.splitext(path)[1].lower()
        parent_dir = os.path.dirname(path)

        # Suspicious extension in a watch-exec directory
        if any(path.startswith(d) for d in EXEC_WATCH_DIRS):
            if ext in {".sh", ".py", ".elf", ".out", ".pl", ".rb"}:
                return True

        # Known ransomware extensions anywhere
        if ext in SUSPECT_EXTENSIONS:
            return True

        # Suspicious name patterns
        if any(p in basename for p in SUSPECT_PATTERNS):
            return True

        # Hidden file in /tmp or /var/tmp
        if basename.startswith(".") and any(path.startswith(d) for d in EXEC_WATCH_DIRS):
            return True

        # Executable bit set in system dirs (cannot check on deleted)
        try:
            if (parent_dir in ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
                    and os.access(path, os.X_OK)):
                return True
        except OSError:
            pass

        return False


class RapidChangeTracker:
    """
    Detects ransomware-like rapid file modification bursts.
    Records change timestamps per directory; fires alert when threshold hit.
    """

    def __init__(self, socketio=None):
        self._socketio = socketio
        # { directory: deque([timestamp, ...]) }
        self._dir_windows: dict = defaultdict(deque)
        self._alerted: set = set()

    def record(self, path: str):
        now    = time.time()
        d      = os.path.dirname(path)
        window = self._dir_windows[d]
        window.append(now)

        # Evict old
        cutoff = now - RAPID_CHANGE_WINDOW
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= RAPID_CHANGE_COUNT:
            key = f"{d}:{int(now // RAPID_CHANGE_WINDOW)}"
            if key not in self._alerted:
                self._alerted.add(key)
                self._on_rapid_change(d, len(window))

    def _on_rapid_change(self, directory: str, count: int):
        alerts.fire(
            level="CRITICAL",
            category="malware",
            message=(
                f"Rapid file changes detected in {directory} — "
                f"{count} in {RAPID_CHANGE_WINDOW}s (ransomware heuristic)"
            ),
            details={"directory": directory, "change_count": count},
        )
        if self._socketio:
            try:
                self._socketio.emit("rapid_change", {
                    "directory": directory, "count": count
                })
            except Exception:
                pass
        logger.critical("RAPID CHANGE in %s — %d events! Possible ransomware.", directory, count)


class FileMonitor:
    """
    Top-level file monitoring manager.
    Starts a Watchdog Observer for each accessible monitored directory.
    """

    def __init__(self, socketio=None):
        self._socketio       = socketio
        self._observer       = None
        self._rapid_tracker  = RapidChangeTracker(socketio)
        self._running        = False

    def start(self):
        if not WATCHDOG_AVAILABLE:
            logger.warning("Watchdog unavailable — file monitoring disabled")
            return

        self._observer = Observer()
        handler        = _HoneypotEventHandler(self._rapid_tracker, self._socketio)

        all_dirs = list(MONITORED_DIRS) + list(MONITORED_DIRS_EXTRA)
        scheduled = 0

        for directory in all_dirs:
            if not os.path.isdir(directory):
                logger.debug("Skipping non-existent dir: %s", directory)
                continue
            try:
                self._observer.schedule(handler, directory, recursive=True)
                scheduled += 1
                logger.info("Monitoring directory: %s", directory)
            except (PermissionError, OSError) as e:
                logger.warning("Cannot monitor %s: %s", directory, e)

        if scheduled == 0:
            logger.warning("No directories could be monitored")
            return

        self._observer.start()
        self._running = True
        logger.info("File monitor started — watching %d directories", scheduled)

    def stop(self):
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join()
            self._running = False
            logger.info("File monitor stopped")

    @property
    def is_running(self):
        return self._running