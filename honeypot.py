"""
honeypot.py — Adaptive Honeypot Engine
Runs fake service listeners on non-standard ports:
  - Fake SSH  (port 2222)  — mimics OpenSSH banner, logs credentials
  - Fake FTP  (port 2121)  — mimics vsftpd banner, logs auth attempts
  - Fake HTTP (port 8080)  — mimics Apache, logs suspicious requests
  - Fake Telnet (port 2323) — mimics telnetd, logs credentials
All listeners are async (asyncio) and non-blocking.
Adaptive behaviour: escalates monitoring level per-IP based on attack frequency.
"""

import asyncio
import threading
import logging
import time
from collections import defaultdict
from datetime import datetime
from config import (
    HONEYPOT_HOST, HONEYPOT_SSH_PORT, HONEYPOT_FTP_PORT,
    HONEYPOT_HTTP_PORT, HONEYPOT_TELNET_PORT,
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECS
)
from database import insert_ssh_attempt, insert_attack, upsert_ip_score
from utils import score_for
import alerts
import geoip

logger = logging.getLogger("honeypot")

# ─────────────────────────────────────────────────────────────
# ADAPTIVE TRACKING  (per-IP interaction counts)
# ─────────────────────────────────────────────────────────────

class AdaptiveTracker:
    """
    Tracks per-IP connection counts and assigns monitoring levels.
    Levels: WATCH (1) → SUSPECT (2) → HOSTILE (3)
    """

    def __init__(self):
        self._counts: dict = defaultdict(int)
        self._levels: dict = {}

    def record(self, ip: str):
        self._counts[ip] += 1
        cnt = self._counts[ip]
        if cnt >= 20:
            self._levels[ip] = "HOSTILE"
        elif cnt >= 5:
            self._levels[ip] = "SUSPECT"
        else:
            self._levels[ip] = "WATCH"
        return self._levels[ip]

    def level(self, ip: str) -> str:
        return self._levels.get(ip, "NORMAL")

    def count(self, ip: str) -> int:
        return self._counts.get(ip, 0)


_tracker = AdaptiveTracker()
_socketio_ref = [None]   # mutable container so coroutines can access it


def set_socketio(sio):
    _socketio_ref[0] = sio


def _emit(event: str, data: dict):
    sio = _socketio_ref[0]
    if sio:
        try:
            sio.emit(event, data)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# FAKE SSH HONEYPOT
# ─────────────────────────────────────────────────────────────

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
SSH_PROMPT = b"login as: "

async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer    = writer.get_extra_info("peername")
    src_ip  = peer[0] if peer else "unknown"
    src_port = peer[1] if peer else 0

    logger.info("[SSH-HP] Connection from %s", src_ip)
    level = _tracker.record(src_ip)
    upsert_ip_score(src_ip, delta=score_for("honeypot_touch"))

    # Emit live connection to dashboard
    _emit("honeypot_connect", {
        "service": "SSH", "ip": src_ip, "port": HONEYPOT_SSH_PORT,
        "level": level, "count": _tracker.count(src_ip)
    })

    try:
        # Send SSH banner
        writer.write(SSH_BANNER)
        await writer.drain()

        # Simulate a username/password exchange
        for attempt in range(6):
            writer.write(SSH_PROMPT)
            await writer.drain()

            try:
                username_raw = await asyncio.wait_for(reader.readline(), timeout=15.0)
                username = username_raw.decode(errors="replace").strip()

                # Fake password prompt
                writer.write(b"\r\nPassword: ")
                await writer.drain()

                password_raw = await asyncio.wait_for(reader.readline(), timeout=15.0)
                password = password_raw.decode(errors="replace").strip()

                if not username and not password:
                    break

                logger.warning(
                    "[SSH-HP] Creds from %s: user='%s' pass='%s'",
                    src_ip, username, password
                )

                # Store attempt
                insert_ssh_attempt(
                    source_ip=src_ip,
                    username=username,
                    password=password,
                    success=False,
                    port=HONEYPOT_SSH_PORT
                )
                upsert_ip_score(src_ip, delta=score_for("ssh_fail"))

                # Emit live credential capture
                _emit("credential_capture", {
                    "service":  "SSH",
                    "ip":       src_ip,
                    "username": username,
                    "password": password,
                    "attempt":  attempt + 1,
                })

                # Fire alert after 3rd attempt
                if attempt >= 2:
                    alerts.fire(
                        level="HIGH",
                        category="honeypot",
                        message=(
                            f"SSH honeypot brute-force from {src_ip} — "
                            f"attempt #{attempt+1}: user='{username}'"
                        ),
                        source_ip=src_ip,
                        details={
                            "username": username,
                            "password": password,
                            "attempt":  attempt + 1,
                        },
                    )

                # Always deny
                writer.write(b"\r\nPermission denied, please try again.\r\n")
                await writer.drain()

            except asyncio.TimeoutError:
                break

        writer.write(b"\r\nToo many authentication failures\r\n")
        await writer.drain()

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug("[SSH-HP] Session error from %s: %s", src_ip, e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# FAKE FTP HONEYPOT
# ─────────────────────────────────────────────────────────────

FTP_BANNER   = b"220 (vsFTPd 3.0.3)\r\n"
FTP_USER_OK  = b"331 Please specify the password.\r\n"
FTP_FAIL     = b"530 Login incorrect.\r\n"
FTP_BYE      = b"221 Goodbye.\r\n"

async def handle_ftp(reader, writer):
    peer   = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "unknown"

    _tracker.record(src_ip)
    upsert_ip_score(src_ip, delta=score_for("honeypot_touch"))
    _emit("honeypot_connect", {"service": "FTP", "ip": src_ip, "port": HONEYPOT_FTP_PORT})

    try:
        writer.write(FTP_BANNER)
        await writer.drain()

        username = ""
        for _ in range(10):
            line_raw = await asyncio.wait_for(reader.readline(), timeout=20.0)
            line = line_raw.decode(errors="replace").strip()
            if not line:
                break

            cmd = line.split()[0].upper() if line.split() else ""
            arg = line[len(cmd):].strip() if len(line) > len(cmd) else ""

            if cmd == "USER":
                username = arg
                writer.write(FTP_USER_OK)
            elif cmd == "PASS":
                password = arg
                logger.warning("[FTP-HP] Creds from %s: %s / %s", src_ip, username, password)
                insert_attack(
                    attack_type="ftp_bruteforce",
                    source_ip=src_ip,
                    port=HONEYPOT_FTP_PORT,
                    protocol="TCP",
                    payload=f"user={username} pass={password}",
                    threat_score=20
                )
                _emit("credential_capture", {
                    "service": "FTP", "ip": src_ip,
                    "username": username, "password": password
                })
                writer.write(FTP_FAIL)
            elif cmd == "QUIT":
                writer.write(FTP_BYE)
                break
            else:
                writer.write(b"500 Unknown command.\r\n")

            await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug("[FTP-HP] Error %s: %s", src_ip, e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# FAKE TELNET HONEYPOT
# ─────────────────────────────────────────────────────────────

TELNET_BANNER = b"\r\nUbuntu 22.04 LTS\r\n\r\nlogin: "

async def handle_telnet(reader, writer):
    peer   = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "unknown"

    _tracker.record(src_ip)
    upsert_ip_score(src_ip, delta=score_for("honeypot_touch"))
    _emit("honeypot_connect", {"service": "Telnet", "ip": src_ip, "port": HONEYPOT_TELNET_PORT})

    try:
        writer.write(TELNET_BANNER)
        await writer.drain()

        username_raw = await asyncio.wait_for(reader.readline(), timeout=20.0)
        username = username_raw.decode(errors="replace").strip()

        writer.write(b"Password: ")
        await writer.drain()

        password_raw = await asyncio.wait_for(reader.readline(), timeout=20.0)
        password = password_raw.decode(errors="replace").strip()

        logger.warning("[TELNET-HP] Creds from %s: %s / %s", src_ip, username, password)
        insert_attack(
            attack_type="telnet_attempt",
            source_ip=src_ip,
            port=HONEYPOT_TELNET_PORT,
            protocol="TCP",
            payload=f"user={username} pass={password}",
            threat_score=25
        )
        _emit("credential_capture", {
            "service": "Telnet", "ip": src_ip,
            "username": username, "password": password
        })
        alerts.fire(
            level="HIGH",
            category="honeypot",
            message=f"Telnet honeypot hit from {src_ip}: user='{username}'",
            source_ip=src_ip,
            details={"username": username, "password": password},
        )

        writer.write(b"\r\nLogin incorrect\r\n")
        await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug("[TELNET-HP] Error %s: %s", src_ip, e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# FAKE HTTP HONEYPOT
# ─────────────────────────────────────────────────────────────

HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.52 (Ubuntu)\r\n"
    b"Content-Type: text/html\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<html><body><h1>It works!</h1></body></html>\r\n"
)

# Paths that are suspicious when requested
SUSPECT_HTTP_PATHS = {
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php",
    "/shell", "/cmd", "/webshell", "/.git", "/backup", "/passwd",
    "/etc/passwd", "/proc/self/environ", "/wp-login.php",
    "/xmlrpc.php", "/manager/html", "/solr", "/actuator",
}

async def handle_http(reader, writer):
    peer   = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "unknown"

    _tracker.record(src_ip)
    upsert_ip_score(src_ip, delta=score_for("honeypot_touch"))

    try:
        request_raw = await asyncio.wait_for(reader.read(4096), timeout=10.0)
        request     = request_raw.decode(errors="replace")

        # Extract method and path from first line
        first_line  = request.split("\r\n")[0] if request else ""
        parts       = first_line.split(" ")
        method      = parts[0] if len(parts) > 0 else "?"
        path        = parts[1] if len(parts) > 1 else "/"

        suspect = any(path.startswith(sp) or path == sp for sp in SUSPECT_HTTP_PATHS)
        # Also check for common injection patterns
        if any(pat in request.lower() for pat in
               ["<script", "union select", "../", "eval(", "exec(", "base64_decode"]):
            suspect = True

        logger.info("[HTTP-HP] %s %s from %s (suspect=%s)", method, path, src_ip, suspect)

        insert_attack(
            attack_type="http_probe" if not suspect else "http_exploit_attempt",
            source_ip=src_ip,
            port=HONEYPOT_HTTP_PORT,
            protocol="TCP",
            payload=f"{method} {path}",
            threat_score=10 if not suspect else 40
        )

        _emit("honeypot_connect", {
            "service": "HTTP", "ip": src_ip,
            "path": path, "method": method, "suspect": suspect
        })

        if suspect:
            alerts.fire(
                level="HIGH",
                category="honeypot",
                message=f"HTTP exploit probe from {src_ip}: {method} {path}",
                source_ip=src_ip,
                details={"method": method, "path": path, "suspect": True},
            )

        writer.write(HTTP_RESPONSE)
        await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug("[HTTP-HP] Error %s: %s", src_ip, e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# HONEYPOT MANAGER
# ─────────────────────────────────────────────────────────────

class HoneypotEngine(threading.Thread):
    """
    Runs an asyncio event loop in a background thread to host all fake services.
    """

    def __init__(self, socketio=None):
        super().__init__(daemon=True, name="HoneypotEngine")
        self._socketio = socketio
        self._loop     = None
        set_socketio(socketio)

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_servers())
            self._loop.run_forever()
        except Exception as e:
            logger.error("Honeypot engine error: %s", e)
        finally:
            self._loop.close()

    async def _start_servers(self):
        """Start all fake service servers."""
        services = [
            ("SSH",    HONEYPOT_SSH_PORT,    handle_ssh),
            ("FTP",    HONEYPOT_FTP_PORT,    handle_ftp),
            ("Telnet", HONEYPOT_TELNET_PORT, handle_telnet),
            ("HTTP",   HONEYPOT_HTTP_PORT,   handle_http),
        ]

        for name, port, handler in services:
            try:
                server = await asyncio.start_server(
                    handler, HONEYPOT_HOST, port
                )
                logger.info("Honeypot [%s] listening on port %d", name, port)
            except OSError as e:
                logger.warning(
                    "Could not start honeypot [%s] on port %d: %s", name, port, e
                )

    def stop(self):
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)