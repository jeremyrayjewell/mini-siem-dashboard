import json
from flask import Flask, jsonify, send_from_directory, redirect
from datetime import datetime, timedelta
from pathlib import Path
from backend.traps import start_trap_listeners, EVENTS_FILE, EVENTS_LOCK

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

app = Flask(__name__)

@app.route('/')
def index():
    # Serve index.html from repo root
    return send_from_directory(str(BASE_DIR.parent), 'index.html')

@app.route('/api/stats')
def api_stats():
    with EVENTS_LOCK:
        try:
            with EVENTS_FILE.open('r') as f:
                events = json.load(f)
        except Exception:
            events = []
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    parsed_events = []
    for e in events:
        try:
            e_dt = datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            continue
        e['_dt'] = e_dt
        parsed_events.append(e)
    total_events = len(parsed_events)
    last24h_count = sum(1 for e in parsed_events if e['_dt'] >= last_24h)
    ip_counts = {}
    for e in parsed_events:
        ip = e.get('ip')
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted([
        {'ip': ip, 'count': count} for ip, count in ip_counts.items()
    ], key=lambda x: x['count'], reverse=True)[:5]
    port_counts = {}
    for e in parsed_events:
        port = e.get('port')
        if port:
            port_counts[port] = port_counts.get(port, 0) + 1
    top_ports = sorted([
        {'port': port, 'count': count} for port, count in port_counts.items()
    ], key=lambda x: x['count'], reverse=True)[:5]
    recent_events = sorted(parsed_events, key=lambda e: e['_dt'], reverse=True)[:50]
    for e in recent_events:
        e.pop('_dt', None)
    return jsonify({
        'totalEvents': total_events,
        'last24h': last24h_count,
        'topIPs': top_ips,
        'topPorts': top_ports,
        'recentEvents': recent_events
    })

if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    if not EVENTS_FILE.exists():
        with EVENTS_FILE.open('w') as f:
            json.dump([], f)
    start_trap_listeners()
    app.run(host="0.0.0.0", port=5000, debug=True)
