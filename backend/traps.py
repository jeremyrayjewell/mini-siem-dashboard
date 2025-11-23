import socket
import threading
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
EVENTS_FILE = DATA_DIR / "events.json"
EVENTS_LOCK = threading.Lock()
MAX_EVENTS = 10000

BANNERS = {
    2222: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4\r\n",
    2121: b"220 (Fake FTP Service)\r\n"
}

SERVICES = [
    {'port': 2222, 'protocol': 'SSH'},
    {'port': 2121, 'protocol': 'FTP'}
]

def append_event(event):
    with EVENTS_LOCK:
        try:
            if not EVENTS_FILE.exists():
                events = []
            else:
                with EVENTS_FILE.open('r') as f:
                    events = json.load(f)
        except Exception:
            events = []
        events.append(event)
        if len(events) > MAX_EVENTS:
            events = events[-MAX_EVENTS:]
        with EVENTS_FILE.open('w') as f:
            json.dump(events, f)

def handle_connection(conn, addr, port, protocol):
    ip = addr[0]
    src_port = addr[1]
    event = {
        "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "event_type": "connection",
        "message": f"Connection from {ip}:{src_port}"
    }
    append_event(event)
    banner = BANNERS.get(port)
    if banner:
        try:
            conn.sendall(banner)
        except Exception:
            pass
    conn.close()

def listener(port, protocol):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(100)
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle_connection, args=(conn, addr, port, protocol), daemon=True).start()
        except Exception:
            continue

def start_trap_listeners():
    DATA_DIR.mkdir(exist_ok=True)
    if not EVENTS_FILE.exists():
        with EVENTS_FILE.open('w') as f:
            json.dump([], f)
    for svc in SERVICES:
        t = threading.Thread(target=listener, args=(svc['port'], svc['protocol']), daemon=True)
        t.start()
