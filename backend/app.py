from ipaddress import ip_address
import json
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from datetime import datetime, timedelta
from pathlib import Path
from traps import start_trap_listeners, EVENTS_FILE, EVENTS_LOCK, MAX_EVENTS
import ipaddress
import requests

# Directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PUBLIC_DIR = BASE_DIR.parent / "public"

# Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Constants for geolocation
GEO_CACHE_FILE = DATA_DIR / "geo_cache.json"
_geo_cache = {}


def load_geo_cache():
    global _geo_cache
    if GEO_CACHE_FILE.exists():
        try:
            with GEO_CACHE_FILE.open("r") as f:
                _geo_cache = json.load(f)
        except Exception:
            _geo_cache = {}
    else:
        _geo_cache = {}


def save_geo_cache():
    try:
        with GEO_CACHE_FILE.open("w") as f:
            json.dump(_geo_cache, f)
    except Exception:
        pass


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False


def lookup_geo(ip: str):
    """
    Return {ip, country, lat, lon} for public IPs using ipwho.is, or None.
    Uses a local JSON cache to avoid hitting the API repeatedly.
    """
    if not is_public_ip(ip):
        return None

    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        data = resp.json()
        if not data.get("success", False):
            return None

        info = {
            "ip": ip,
            "country": data.get("country"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
        }
        _geo_cache[ip] = info
        save_geo_cache()
        return info
    except Exception:
        return None


# ---------- IP selection (prefer IPv4) ----------

def get_client_ip(req):
    """
    Return best-guess client IP, preferring IPv4 over IPv6.
    """
    candidates = []

    fly_client_ip = req.headers.get("Fly-Client-IP", "")
    if fly_client_ip:
        candidates.append(fly_client_ip.strip())

    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        for part in xff.split(","):
            candidates.append(part.strip())

    if req.remote_addr:
        candidates.append(req.remote_addr)

    ipv4_candidates = [ip for ip in candidates if "." in ip]
    ipv6_candidates = [ip for ip in candidates if ":" in ip]

    for candidate in ipv4_candidates + ipv6_candidates:
        try:
            ip_address(candidate)
            return candidate
        except ValueError:
            continue

    return "unknown"


# ---------- HTTP logging ----------

def log_http_request(req):
    ip = get_client_ip(req)

    fly_client_ip = req.headers.get("Fly-Client-IP", "")
    xff = req.headers.get("X-Forwarded-For", "")
    remote = req.remote_addr

    try:
        host_header = req.host
        port = int(host_header.rsplit(":", 1)[1]) if ":" in host_header else int(req.environ.get("SERVER_PORT", 0))
    except (ValueError, TypeError):
        port = 0

    method = req.method
    path = req.path
    src_port = req.environ.get("REMOTE_PORT", 0)
    user_agent = req.headers.get("User-Agent", "")

    from traps import append_event

    event = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip": ip,
        "port": port,
        "protocol": "HTTP",
        "event_type": "request",
        "method": method,
        "path": path,
        "src_port": src_port,
        "user_agent": user_agent,
        "message": (
            f"HTTP {method} {path} from {ip} "
            f"[fly='{fly_client_ip}' xff='{xff}' remote='{remote}']"
        ),
    }

    if ip == "unknown" or not port:
        print(f"[WARNING] Skipping event due to missing critical data: {event}")
        return

    append_event(event)


@app.before_request
def before_request_logging():
    # Skip internal dashboard noise. If you ALSO want "/" logged, remove that check.
    if request.path in ("/api/stats", "/favicon.ico"):
        return
    if request.path == "/":
        return

    if not hasattr(request, "_logged"):
        log_http_request(request)
        request._logged = True


# ---------- Routes ----------

@app.route("/")
def index():
    index_path = PUBLIC_DIR / "index.html"
    if index_path.exists():
        return send_from_directory(str(PUBLIC_DIR), "index.html")

    # Fallback fake portal
    return """
<html>
<head><title>Welcome</title></head>
<body>
<h2>Welcome to Secure Portal</h2>
<p>Please <a href='/login'>login</a>.</p>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return "Invalid credentials", 401
    return """
<html>
<head><title>Login</title></head>
<body>
<h2>Login</h2>
<form method='post'>
Username: <input name='username'><br>
</form>
<p>Access restricted. Please login.</p>
</body>
</html>
"""


# Update api_stats to include geoIPs
@app.route("/api/stats")
def api_stats():
    try:
        with EVENTS_FILE.open("r") as f:
            events = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read events file: {e}")
        events = []

    # Enrich with datetime for sorting and 24h filtering
    for e in events:
        try:
            e["_dt"] = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        except Exception as e:
            print(f"[WARNING] Failed to parse timestamp: {e}")
            e["_dt"] = datetime.utcnow()

    total_events = len(events)
    last_24h = datetime.utcnow() - timedelta(hours=24)
    last24h_count = sum(1 for e in events if e["_dt"] >= last_24h)

    ip_counts = {}
    for e in events:
        ip = e.get("ip")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(
        ({"ip": ip, "count": count} for ip, count in ip_counts.items()),
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    port_counts = {}
    for e in events:
        port = e.get("port")
        if port:
            port_counts[port] = port_counts.get(port, 0) + 1
    top_ports = sorted(
        ({"port": port, "count": count} for port, count in port_counts.items()),
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    recent_events = sorted(events, key=lambda e: e["_dt"], reverse=True)[:50]
    for e in recent_events:
        e.pop("_dt", None)

    # Add geoIPs
    geo_ips = []
    for entry in top_ips:
        ip = entry["ip"]
        try:
            geo = lookup_geo(ip)
            if geo and geo.get("lat") is not None and geo.get("lon") is not None:
                geo_ips.append(
                    {
                        "ip": ip,
                        "count": entry["count"],
                        "country": geo.get("country"),
                        "lat": geo.get("lat"),
                        "lon": geo.get("lon"),
                    }
                )
        except Exception as e:
            print(f"[WARNING] Geo lookup failed for IP {ip}: {e}")

    return jsonify(
        {
            "totalEvents": total_events,
            "last24h": last24h_count,
            "topIPs": top_ips,
            "topPorts": top_ports,
            "recentEvents": recent_events,
            "geoIPs": geo_ips,
        }
    )


# ---------- Entrypoint ----------

# Ensure the app listens on 0.0.0.0
if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    if not EVENTS_FILE.exists():
        with EVENTS_FILE.open('w') as f:
            json.dump([], f)
    load_geo_cache()
    start_trap_listeners()
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
