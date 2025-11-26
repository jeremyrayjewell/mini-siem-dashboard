import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import ipaddress
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

from traps import (
    EVENTS_FILE,
    EVENTS_LOCK,
    MAX_EVENTS,
    append_event,
    start_trap_listeners,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

app = Flask(__name__)
CORS(app)


# ---------- Event loading helpers ----------

def _load_events():
    if not EVENTS_FILE.exists():
        return []
    try:
        with EVENTS_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _parse_timestamp(ts: str):
    if not ts:
        return None
    try:
        # Handle ...Z or offset formats
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _is_public_ip(ip: str) -> bool:
    """
    Return True if the IP is globally routable.
    Works for both IPv4 and IPv6.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def _lookup_geo(ip: str):
    """
    Geo-lookup using ipwho.is which supports IPv4 and IPv6.
    Returns None on any failure.
    """
    try:
        resp = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=3,
            params={"output": "json"},
        )
        data = resp.json()
        if not data.get("success", True):
            return None

        lat = data.get("latitude")
        lon = data.get("longitude")
        if lat is None or lon is None:
            return None

        return {
            "ip": ip,
            "lat": float(lat),
            "lng": float(lon),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
        }
    except Exception:
        return None


def _build_geo_points(events):
    """
    Build a list of geoPoints for the dashboard map from recent events.
    Each item: { ip, lat, lng, count, city, region, country }
    """
    ip_counts = Counter()
    for e in events:
        raw_ip = e.get("raw_ip") or str(e.get("ip") or "").split()[0]
        if not raw_ip or not _is_public_ip(raw_ip):
            continue
        ip_counts[raw_ip] += 1

    geo_points = []
    for ip, count in ip_counts.items():
        info = _lookup_geo(ip)
        if not info:
            continue
        info["count"] = count
        geo_points.append(info)

    return geo_points


# ---------- HTTP honeypot logging ----------

def _get_client_ip(req):
    """
    Prefer X-Forwarded-For, then Fly-Client-IP, then remote_addr.
    Returns (raw_ip, label_ip) where label_ip may include ' (internal)'.
    """
    xff = (req.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    fly_ip = req.headers.get("Fly-Client-IP")
    remote = req.remote_addr

    ip = xff or fly_ip or remote or "unknown"

    label = ip
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            label = f"{ip} (internal)"
    except ValueError:
        # not a plain IP string; leave as-is
        pass

    return ip, label


def log_http_request(req):
    """
    Append a single HTTP honeypot event (e.g. /admin) to events.json.
    This uses the same schema as TCP connection events.
    """
    raw_ip, label_ip = _get_client_ip(req)

    # Dest & src ports (if available)
    try:
        dest_port = int(req.environ.get("SERVER_PORT") or 8080)
    except Exception:
        dest_port = 8080

    try:
        src_port = int(req.environ.get("REMOTE_PORT") or 0)
    except Exception:
        src_port = None

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_type": "request",
        "protocol": "HTTP",
        "port": dest_port,
        "ip": label_ip,
        "raw_ip": raw_ip,
        "src_port": src_port,
        "banner_sent": False,
        "user_agent": req.headers.get("User-Agent"),
        "method": req.method,
        "path": req.path,
        "message": f"HTTP {req.method} {req.path} from {label_ip}",
    }
    append_event(event)


# ---------- API routes ----------

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """
    Aggregate stats for the dashboard:
      - totalEvents
      - last24Hours
      - eventsOverTime
      - topIPs
      - topPorts
      - eventsByProtocol
      - recentEvents
      - geoPoints
    """
    with EVENTS_LOCK:
        events = _load_events()

    total_events = len(events)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)

    # Filter for last 24h and also parse timestamps
    parsed_events = []
    last24h_count = 0
    for e in events:
        ts = _parse_timestamp(e.get("timestamp"))
        if ts is None:
            continue
        parsed_events.append((ts, e))
        if ts >= cutoff:
            last24h_count += 1

    # Recent events: newest first, limited to 100
    parsed_events.sort(key=lambda pair: pair[0], reverse=True)
    recent_events = [e for _, e in parsed_events[:100]]

    # Events over time (by date)
    by_date = defaultdict(int)
    for ts, _e in parsed_events:
        by_date[ts.date().isoformat()] += 1
    events_over_time = [
        {"date": d, "count": by_date[d]} for d in sorted(by_date.keys())
    ]

    # Top IPs (by label)
    ip_counter = Counter()
    for _ts, e in parsed_events:
        ip_counter[e.get("ip", "unknown")] += 1
    top_ips = [
        {"ip": ip, "count": count}
        for ip, count in ip_counter.most_common(10)
    ]

    # Top ports
    port_counter = Counter()
    for _ts, e in parsed_events:
        port = e.get("port")
        if port is None:
            continue
        port_counter[str(port)] += 1
    top_ports = [
        {"port": port, "count": count}
        for port, count in port_counter.most_common(10)
    ]

    # Events by protocol
    proto_counter = Counter()
    for _ts, e in parsed_events:
        proto_counter[e.get("protocol", "UNKNOWN")] += 1
    events_by_protocol = [
        {"protocol": proto, "count": count}
        for proto, count in proto_counter.most_common()
    ]

    # Geo points for map (IPv4 + IPv6)
    geo_points = _build_geo_points([e for _ts, e in parsed_events])

    return jsonify(
        {
            "totalEvents": total_events,
            "last24Hours": last24h_count,
            "eventsOverTime": events_over_time,
            "topIPs": top_ips,
            "topPorts": top_ports,
            "eventsByProtocol": events_by_protocol,
            "recentEvents": recent_events,
            "geoPoints": geo_points,
            "maxEvents": MAX_EVENTS,
        }
    )


@app.route("/admin", methods=["GET", "POST", "HEAD", "OPTIONS"])
def admin_honeypot():
    """
    Fake /admin endpoint: always returns 404 but logs the request
    as a honeypot event.
    """
    log_http_request(request)
    # Deliberately mimic a generic 404 page (like Werkzeug's)
    return (
        "<!doctype html><html lang=en><title>404 Not Found</title>"
        "<h1>Not Found</h1>"
        "<p>The requested URL was not found on the server. "
        "If you entered the URL manually please check your spelling and try again.</p>",
        404,
        {"Content-Type": "text/html; charset=utf-8"},
    )


@app.route("/")
def health_root():
    return jsonify({"status": "ok", "message": "Mini SIEM backend is running."})


# ---------- Entrypoint ----------

# Ensure data dir and file exist
DATA_DIR.mkdir(exist_ok=True)
if not EVENTS_FILE.exists():
    with EVENTS_FILE.open("w", encoding="utf-8") as f:
        json.dump([], f)

# Start TCP honeypot listeners once when the module is imported / app starts
start_trap_listeners()

if __name__ == "__main__":
    # Local dev runner
    app.run(host="0.0.0.0", port=8080, debug=False)
