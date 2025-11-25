import re
import socket
import threading
import json
from datetime import datetime
from pathlib import Path
from ipaddress import ip_address

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
EVENTS_FILE = DATA_DIR / "events.json"
EVENTS_LOCK = threading.Lock()
MAX_EVENTS = 10000

BANNERS = {
    5022: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4\r\n",
    5021: b"220 (Fake FTP Service)\r\n",
    53389: b"RDP Protocol Negotiation Failure\r\n",
    53306: b"5.7.26 MySQL Community Server (GPL)\r\n",
    56379: b"+PONG\r\n",
    57017: b"MongoDB shell version v4.4.0\r\n",
    21: b"220 (Fake FTP Service)\r\n",
    22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4\r\n",
    3389: b"RDP Protocol Negotiation Failure\r\n",
    3306: b"5.7.26 MySQL Community Server (GPL)\r\n",
    6379: b"+PONG\r\n",
    27017: b"MongoDB shell version v4.4.0\r\n"
}

SERVICES = [
    {'port': 5022, 'protocol': 'SSH'},
    {'port': 22, 'protocol': 'SSH'},
    {'port': 5021, 'protocol': 'FTP'},
    {'port': 21, 'protocol': 'FTP'},
    {'port': 53389, 'protocol': 'RDP'},
    {'port': 3389, 'protocol': 'RDP'},
    {'port': 53306, 'protocol': 'MySQL'},
    {'port': 3306, 'protocol': 'MySQL'},
    {'port': 56379, 'protocol': 'Redis'},
    {'port': 6379, 'protocol': 'Redis'},
    {'port': 57017, 'protocol': 'MongoDB'},
    {'port': 27017, 'protocol': 'MongoDB'}
]

def prefer_ipv4(ip_list):
    for ip in ip_list:
        if '.' in ip:  # Check for IPv4
            try:
                ip_address(ip)
                return ip
            except ValueError:
                continue
    for ip in ip_list:
        if ':' in ip:
            try:
                ip_address(ip)
                return ip
            except ValueError:
                continue
    return "unknown"

def prefer_ipv4_only(ip_list):
    for ip in ip_list:
        if "." in ip:  # Check for IPv4
            return ip
    return "unknown"

def get_client_from_proxy_or_addr(conn, addr):
    try:
        conn.settimeout(0.5)
        peek = conn.recv(16, socket.MSG_PEEK)
        if not peek.startswith(b"PROXY "):
            conn.settimeout(None)
            ipv4 = prefer_ipv4([addr[0]])
            ipv6 = addr[0] if ":" in addr[0] else None
            print(f"[DEBUG] Connection address resolved: IPv4={ipv4}, IPv6={ipv6}")
            return ipv4, ipv6, addr[1]
        header = b""
        while not header.endswith(b"\r\n"):
            chunk = conn.recv(1)
            if not chunk:
                break
            header += chunk
        conn.settimeout(None)
        m = re.match(rb"^PROXY\s+TCP[46]\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\r\n$", header)
        if m:
            ipv4 = prefer_ipv4([m.group(1).decode()])
            ipv6 = m.group(1).decode() if ":" in m.group(1).decode() else None
            print(f"[DEBUG] PROXY header resolved: IPv4={ipv4}, IPv6={ipv6}")
            return ipv4, ipv6, int(m.group(3))
    except Exception as e:
        print(f"[PROXY ERROR] {e}")
    conn.settimeout(None)
    ipv4 = prefer_ipv4([addr[0]])
    ipv6 = addr[0] if ":" in addr[0] else None
    print(f"[DEBUG] Fallback address resolved: IPv4={ipv4}, IPv6={ipv6}")
    return ipv4, ipv6, addr[1]

def append_event(event):
    with EVENTS_LOCK:
        try:
            if not EVENTS_FILE.exists():
                events = []
            else:
                with EVENTS_FILE.open('r') as f:
                    events = json.load(f)
        except json.JSONDecodeError:
            print("[ERROR] Corrupted events.json file. Resetting log.")
            events = []
        except Exception as e:
            print(f"[ERROR] Failed to read events: {e}")
            events = []

        if not isinstance(event, dict) or not event.get("timestamp") or not event.get("protocol"):
            print(f"[WARNING] Skipping invalid event: {event}")
            return

        events.append(event)
        if len(events) > MAX_EVENTS:
            events = events[-MAX_EVENTS:]

        try:
            with EVENTS_FILE.open('w') as f:
                json.dump(events, f)
        except Exception as e:
            print(f"[ERROR] Failed to write events: {e}")

def handle_connection(conn, addr, protocol, listen_port):
    ipv4, ipv6, client_port = get_client_from_proxy_or_addr(conn, addr)
    ip = ipv4 if ipv4 else "unknown"

    print(f"[DEBUG] New {protocol} connection: ip={ip}, ipv6={ipv6}, client_port={client_port}")

    event = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip": ip,
        "ipv6": ipv6,
        "port": listen_port,       # DESTINATION (service) port, e.g., 21, 22, 3389
        "src_port": client_port,   # SOURCE (attacker) ephemeral port
        "protocol": protocol,
        "event_type": "connection",  # align with HTTP events from app.py
        "message": f"Connection from {addr[0]}:{client_port} via {protocol}",
        "user_agent": None,           # schema compatibility with HTTP events
        "banner_sent": False,         # schema compatibility with HTTP events
    }

    if not event["ip"] or not event["port"]:
        print(f"[WARNING] Skipping invalid event: {event}")
        conn.close()
        return

    append_event(event)

    try:
        print(f"[INFO] {event['message']}")
    except Exception as e:
        print(f"[ERROR] Failed to log event: {e}")
    finally:
        conn.close()

def listener(port, protocol):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', port))
        print(f"[DEBUG] Listener started for {protocol} on port {port}")
    except Exception as e:
        print(f"[TRAP ERROR] Failed to bind {protocol} on port {port}: {e}")
        s.close()
        return

    s.listen(100)
    while True:
        try:
            conn, addr = s.accept()
            print(f"[DEBUG] Connection accepted on {protocol} port {port} from {addr}")
            threading.Thread(
                target=handle_connection,
                args=(conn, addr, protocol, port),  # pass listen_port in
                daemon=True,
            ).start()
        except Exception as e:
            print(f"[LISTENER ERROR] {e}")
            continue

def start_trap_listeners():
    DATA_DIR.mkdir(exist_ok=True)
    if not EVENTS_FILE.exists():
        with EVENTS_FILE.open('w') as f:
            json.dump([], f)
    for svc in SERVICES:
        try:
            print(f"[DEBUG] Starting listener for {svc['protocol']} on port {svc['port']}")
            t = threading.Thread(target=listener, args=(svc['port'], svc['protocol']), daemon=True)
            t.start()
        except Exception as e:
            print(f"[ERROR] Failed to start listener for {svc['protocol']} on port {svc['port']}: {e}")
