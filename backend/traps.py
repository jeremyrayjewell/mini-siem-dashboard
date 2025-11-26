import socket
import threading
import json
from datetime import datetime, timezone
from pathlib import Path

# Paths and limits shared with app.py
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

EVENTS_FILE = DATA_DIR / "events.json"
MAX_EVENTS = 10_000
EVENTS_LOCK = threading.Lock()

# Simple text banners per protocol
BANNERS = {
    "SSH": b"SSH-2.0-OpenSSH_8.9p1 FlyMiniSIEM\r\n",
    "FTP": b"220 FlyMiniSIEM FTP server ready\r\n",
    "RDP": b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x08\x00\x02\x00\x00\x00",  # random junk
    "MySQL": b"\x0aFlyMiniSIEM\0\0\0",  # fake handshake prefix
    "Redis": b"-ERR unknown command 'HELLO' from FlyMiniSIEM\r\n",
    "MongoDB": b"{'ok':0,'errmsg':'Fake Mongo from FlyMiniSIEM'}\r\n",
}


def _now_utc_iso() -> str:
    """Return a timezone-aware ISO 8601 timestamp with trailing Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_events():
    if not EVENTS_FILE.exists():
        return []
    try:
        with EVENTS_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # Corrupt file – start fresh but keep the bad copy around next to it
        backup = EVENTS_FILE.with_suffix(".corrupt.json")
        try:
            EVENTS_FILE.rename(backup)
        except Exception:
            pass
        return []


def _save_events(events):
    with EVENTS_FILE.open("w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)


def append_event(event: dict) -> None:
    """
    Append a single event to EVENTS_FILE with rotation and locking.
    Shared by TCP traps and HTTP logging in app.py.
    """
    event.setdefault("timestamp", _now_utc_iso())

    with EVENTS_LOCK:
        events = _load_events()
        events.append(event)
        if len(events) > MAX_EVENTS:
            # Keep only the newest MAX_EVENTS
            events = events[-MAX_EVENTS:]
        _save_events(events)


def _parse_proxy_header(conn, fallback_ip: str, fallback_src_port: int, listener_port: int):
    """
    If Fly proxy_proto is enabled, the first line on the connection
    will be a PROXY header like:

      PROXY TCP4 198.51.100.23 10.0.0.1 44321 22\r\n
      PROXY TCP6 2a0c:5700::1 2a0c:5700::2 54321 22\r\n

    We sniff and consume that line (if present) and return
    (client_ip, client_src_port, dest_port).

    If there is no PROXY header or anything goes wrong, we fall back
    to (fallback_ip, fallback_src_port, listener_port).
    """
    try:
        conn.settimeout(1.0)
        peek = conn.recv(108, socket.MSG_PEEK)
        if not peek:
            return fallback_ip, fallback_src_port, listener_port

        line, _, _ = peek.partition(b"\r\n")
        if not line.startswith(b"PROXY "):
            return fallback_ip, fallback_src_port, listener_port

        # Consume the header now that we know it's there
        to_consume = len(line) + 2  # +2 for \r\n
        _ = conn.recv(to_consume)

        parts = line.decode("ascii", errors="ignore").split()
        # PROXY TCP4 src_ip dst_ip src_port dst_port
        if len(parts) >= 6:
            src_ip = parts[2]
            try:
                src_port = int(parts[4])
            except ValueError:
                src_port = fallback_src_port
            try:
                dest_port = int(parts[5])
            except ValueError:
                dest_port = listener_port
            return src_ip, src_port, dest_port

        return fallback_ip, fallback_src_port, listener_port
    except Exception:
        return fallback_ip, fallback_src_port, listener_port
    finally:
        try:
            conn.settimeout(None)
        except Exception:
            pass


def _listener_thread(listener_port: int, protocol: str):
    banner = BANNERS.get(protocol)
    try:
        # IPv6 dual-stack, handles IPv4 as well on most Linux distros
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # :: means "all addresses" (both v4 + v6 due to v6only=0 default)
        sock.bind(("::", listener_port))
        sock.listen(50)
    except OSError as e:
        print(f"[TRAP ERROR] Failed to bind {protocol} on port {listener_port}: {e}", flush=True)
        return

    print(f"[TRAP DEBUG] Listener started for {protocol} on port {listener_port}", flush=True)

    while True:
        try:
            conn, addr = sock.accept()
        except Exception as e:
            print(f"[TRAP ERROR] accept() failed on {protocol} port {listener_port}: {e}", flush=True)
            continue

        # addr for AF_INET6: (ip, port, flowinfo, scopeid)
        fallback_ip = addr[0]
        fallback_src_port = addr[1]
        client_ip, client_src_port, dest_port = _parse_proxy_header(
            conn, fallback_ip, fallback_src_port, listener_port
        )

        print(
            f"[TRAP DEBUG] ACCEPTED {protocol} connection from {client_ip}:{client_src_port} "
            f"(external dest port {dest_port}, listener port {listener_port})",
            flush=True,
        )

        event = {
            "timestamp": _now_utc_iso(),
            "event_type": "connection",
            "protocol": protocol,
            # Use the *external* destination port from PROXY header when available
            "port": dest_port,
            "ip": client_ip,
            "raw_ip": client_ip,
            "src_port": client_src_port,
            "banner_sent": bool(banner),
            "user_agent": None,
            "message": f"Connection from {client_ip}:{client_src_port} via {protocol}",
        }
        append_event(event)

        try:
            if banner:
                conn.sendall(banner)
        except Exception as e:
            print(f"[TRAP ERROR] Failed to send banner on {protocol} port {listener_port}: {e}", flush=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass


def start_trap_listeners():
    """
    Spin up background threads for each honeypot TCP port.
    We only use high ports to avoid conflicts with Fly's internal SSH, etc.
    The HTTP /admin route is handled in app.py and does not appear here.
    """
    listeners = [
        (5022, "SSH"),
        (5021, "FTP"),
        (53389, "RDP"),
        (53306, "MySQL"),
        (56379, "Redis"),
        (57017, "MongoDB"),
    ]

    for port, proto in listeners:
        t = threading.Thread(
            target=_listener_thread,
            args=(port, proto),
            daemon=True,
        )
        t.start()
        print(f"[TRAP DEBUG] Starting listener for {proto} on port {port}", flush=True)
