from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os
import atexit
from threading import Lock
from traps import tcp_events, tcp_events_lock, load_tcp_events, start_tcp_listeners as _traps_start_tcp_listeners
import requests

app = Flask(__name__)
app = Flask(__name__)
# Allow the production Netlify origin and common local dev origins so the UI can call /api/stats
CORS(app, resources={r"/api/*": {"origins": [
    "https://mini-siem-dashboard.netlify.app",
    "https://signaltrap.fly.dev",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*"
]}})

# Expose a lightweight wrapper so gunicorn hooks (or other starters) can call start_tcp_listeners()
def start_tcp_listeners():
    """Wrapper that calls the traps module starter (kept here for compatibility with gunicorn hooks)."""
    return _traps_start_tcp_listeners()

MAX_LOGS = 10000
LOG_RETENTION_DAYS = 7
ATTACKS_FILE = '/data/attacks.json'

attacks = []
attacks_lock = Lock()

def load_attacks():
    global attacks
    if os.path.exists(ATTACKS_FILE):
        try:
            with open(ATTACKS_FILE, 'r') as f:
                loaded = json.load(f)
                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
                attacks = [a for a in loaded if a['timestamp'] > cutoff]
        except:
            attacks = []
    else:
        os.makedirs(os.path.dirname(ATTACKS_FILE), exist_ok=True)
        attacks = []

def save_attacks():
    try:
        with attacks_lock:
            with open(ATTACKS_FILE, 'w') as f:
                json.dump(attacks, f)
    except:
        pass

atexit.register(save_attacks)
load_attacks()

SIEM_INGEST_URL = "http://siem-service/ingest"  # Replace with actual SIEM service URL

def log_http_request(req):
    """
    Append a single HTTP request event to ATTACKS_FILE.
    Event fields:
      - timestamp: ISO string (UTC)
      - ip: client IP address
      - path: request.path
      - method: request.method
    Use /data/attacks.json as a JSON list. If the file doesn't exist, create it.
    If the file is corrupt, overwrite it with a new list.
    Truncate the list to MAX_LOGS if needed.
    """
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": req.remote_addr,
        "path": req.path,
        "method": req.method
    }

    try:
        if os.path.exists(ATTACKS_FILE):
            with open(ATTACKS_FILE, "r") as f:
                try:
                    events = json.load(f)
                except json.JSONDecodeError:
                    events = []
        else:
            events = []

        events.append(event)
        if len(events) > MAX_LOGS:
            events = events[-MAX_LOGS:]

        with open(ATTACKS_FILE, "w") as f:
            json.dump(events, f)
    except Exception as e:
        print(f"[ERROR] Failed to log HTTP request: {e}")

@app.before_request
def before_request_handler():
    if request.path in ['/favicon.ico', '/api/stats']:
        return

    log_http_request(request)

    forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)
    client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr

    attack = {
        'timestamp': datetime.utcnow().isoformat(),
        'src_ip': client_ip,
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', ''),
        'additional': {'headers': dict(request.headers)}
    }

    try:
        response = requests.post(SIEM_INGEST_URL, json=attack)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[ERROR] Failed to forward event to SIEM: {e}")

@app.route('/')
def index():
    return "Honeypot Service Running"

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """
    Aggregate HTTP + TCP honeypot events into a single stats payload for the dashboard.
    HTTP events are loaded from ATTACKS_FILE.
    TCP events are read from traps.tcp_events.
    """
    # ---------- Load HTTP events from file ----------
    http_events_raw = []
    if os.path.exists(ATTACKS_FILE):
        try:
            with open(ATTACKS_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    http_events_raw = data
        except Exception:
            # If the file is corrupt, just ignore HTTP events rather than crashing
            http_events_raw = []

    def parse_ts(value):
        """Best-effort ISO8601 parser that returns a datetime or None."""
        if not value:
            return None
        if isinstance(value, str) and value.endswith("Z"):
            value = value[:-1]
        try:
            return datetime.fromisoformat(value)
        except Exception:
            return None

    # ---------- Normalize HTTP events ----------
    normalized_http = []
    for e in http_events_raw:
        ts = parse_ts(e.get("timestamp"))
        if ts is None:
            continue
        normalized_http.append({
            "timestamp": ts,
            "ip": e.get("ip", "unknown"),
            "path": e.get("path", "/"),
            "method": e.get("method", "HTTP"),
        })

    # ---------- Load TCP events from traps ----------
    try:
        load_tcp_events()
    except Exception:
        pass

    with tcp_events_lock:
        tcp_raw = list(tcp_events)

    normalized_tcp = []
    for e in tcp_raw:
        ts = parse_ts(e.get("timestamp"))
        if ts is None:
            continue
        protocol = e.get("protocol", "TCP")
        port = e.get("port", "unknown")
        event_type = e.get("event_type", "TCP")
        normalized_tcp.append({
            "timestamp": ts,
            "ip": e.get("ip", "unknown"),
            "path": f"{protocol}:{port}",
            "method": event_type,
        })

    # ---------- Combine & compute stats ----------
    all_events = normalized_http + normalized_tcp

    if not all_events:
        stats = {
            "totalAttacks": 0,
            "last24h": 0,
            "topIPs": [],
            "topPaths": [],
            "recentAttacks": [],
        }
        return jsonify(stats)

    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)

    total_attacks = len(all_events)
    last_24h = sum(1 for e in all_events if e["timestamp"] >= day_ago)

    # topIPs
    ip_stats = {}
    for e in all_events:
        ip = e["ip"]
        ts = e["timestamp"]
        if ip not in ip_stats:
            ip_stats[ip] = {"count": 0, "last_seen": ts}
        ip_stats[ip]["count"] += 1
        if ts > ip_stats[ip]["last_seen"]:
            ip_stats[ip]["last_seen"] = ts

    top_ips = [
        {
            "ip": ip,
            "count": info["count"],
            "last_seen": info["last_seen"].isoformat()
        }
        for ip, info in ip_stats.items()
    ]
    top_ips.sort(key=lambda x: (-x["count"], x["last_seen"]), reverse=False)

    # topPaths
    path_counts = {}
    for e in all_events:
        path = e["path"]
        path_counts[path] = path_counts.get(path, 0) + 1

    top_paths = [
        {"path": path, "count": count}
        for path, count in path_counts.items()
    ]
    top_paths.sort(key=lambda x: -x["count"])

    # recentAttacks (latest 50)
    sorted_events = sorted(all_events, key=lambda x: x["timestamp"], reverse=True)
    recent_raw = sorted_events[:50]
    recent_attacks = [
        {
            "timestamp": e["timestamp"].isoformat(),
            "ip": e["ip"],
            "path": e["path"],
            "method": e["method"],
        }
        for e in recent_raw
    ]

    stats = {
        "totalAttacks": total_attacks,
        "last24h": last_24h,
        "topIPs": top_ips,
        "topPaths": top_paths,
        "recentAttacks": recent_attacks,
    }

    print("[DEBUG /api/stats] total events in all_events:", len(all_events))
    return jsonify(stats)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)