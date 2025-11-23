from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os
import atexit
from threading import Lock
from traps import tcp_events, tcp_events_lock, load_tcp_events, start_tcp_listeners as _traps_start_tcp_listeners

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

@app.before_request
def before_request_handler():
    if request.path in ['/api/stats', '/favicon.ico']:
        return
    
    forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)
    client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr
    
    attack = {
        'timestamp': datetime.utcnow().isoformat(),
        'ip': client_ip,
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', ''),
        'headers': dict(request.headers)
    }
    with attacks_lock:
        attacks.append(attack)
        if len(attacks) > MAX_LOGS:
            attacks.pop(0)
    
    if len(attacks) % 10 == 0:
        save_attacks()

@app.route('/api/stats')
def get_stats():
    load_tcp_events()
    
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    
    all_events = list(attacks)
    
    with tcp_events_lock:
        for event in tcp_events:
            all_events.append({
                'timestamp': event['timestamp'],
                'ip': event.get('ip', 'unknown'),
                'method': event.get('protocol', 'TCP'),
                'path': f":{event.get('port', 0)} {event.get('protocol', 'unknown')}",
                'user_agent': event.get('message', ''),
                'headers': {}
            })
    
    recent_attacks = [a for a in all_events if datetime.fromisoformat(a['timestamp']) > last_24h]
    
    ip_data = {}
    for attack in all_events:
        ip = attack['ip']
        if ip not in ip_data:
            ip_data[ip] = {'count': 0, 'last_seen': attack['timestamp']}
        ip_data[ip]['count'] += 1
        if attack['timestamp'] > ip_data[ip]['last_seen']:
            ip_data[ip]['last_seen'] = attack['timestamp']
    
    top_ips = [
        {'ip': ip, 'count': data['count'], 'last_seen': data['last_seen']} 
        for ip, data in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
    ]
    
    path_counts = {}
    for attack in all_events:
        path = attack['path']
        path_counts[path] = path_counts.get(path, 0) + 1
    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    stats = {
        'totalAttacks': len(all_events),
        'last24h': len(recent_attacks),
        'topIPs': top_ips,
        'topPaths': [{'path': path, 'count': count} for path, count in top_paths],
        'recentAttacks': list(reversed(all_events[-50:]))
    }
    
    return jsonify(stats)

@app.route('/')
def index():
    return "Server Running"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)