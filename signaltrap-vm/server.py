from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os
import atexit
from threading import Lock

app = Flask(__name__)
CORS(app, origins=["https://mini-siem-dashboard.netlify.app"])

# Configuration
MAX_LOGS = 10000
LOG_RETENTION_DAYS = 7
ATTACKS_FILE = '/data/attacks.json'

# Store attack logs in memory with thread-safe access
attacks = []
attacks_lock = Lock()

# Load existing attacks from file on startup
def load_attacks():
    global attacks
    if os.path.exists(ATTACKS_FILE):
        try:
            with open(ATTACKS_FILE, 'r') as f:
                loaded = json.load(f)
                # Filter out attacks older than retention period
                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
                attacks = [a for a in loaded if a['timestamp'] > cutoff]
                print(f"Loaded {len(attacks)} attacks from disk")
        except Exception as e:
            print(f"Error loading attacks: {e}")
            attacks = []
    else:
        # Create /data directory if it doesn't exist
        os.makedirs(os.path.dirname(ATTACKS_FILE), exist_ok=True)
        attacks = []

# Save attacks to file
def save_attacks():
    try:
        with attacks_lock:
            with open(ATTACKS_FILE, 'w') as f:
                json.dump(attacks, f)
        print(f"Saved {len(attacks)} attacks to disk")
    except Exception as e:
        print(f"Error saving attacks: {e}")

# Save on shutdown
atexit.register(save_attacks)

# Load attacks on startup
load_attacks()

# Middleware to log all requests
@app.before_request
def log_request():
    # Skip logging requests to /api/stats (dashboard polling) and favicon
    if request.path in ['/api/stats', '/favicon.ico']:
        return
    
    # Get real client IP (first IP in X-Forwarded-For chain)
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
    
    # Save to disk every 10 attacks
    if len(attacks) % 10 == 0:
        save_attacks()

# API endpoint for dashboard
@app.route('/api/stats')
def get_stats():
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    
    # Combine HTTP attacks with honeypot events
    all_events = list(attacks)  # HTTP events
    
    # Load honeypot events if they exist
    honeypot_file = '/data/honeypot_events.json'
    if os.path.exists(honeypot_file):
        try:
            with open(honeypot_file, 'r') as f:
                honeypot_events = json.load(f)
                # Convert honeypot events to attack format
                for event in honeypot_events:
                    all_events.append({
                        'timestamp': event['timestamp'],
                        'ip': event.get('ip', 'unknown'),
                        'method': event.get('protocol', 'TCP'),
                        'path': f":{event.get('port', 0)} {event.get('protocol', 'unknown')}",
                        'user_agent': event.get('message', ''),
                        'headers': {}
                    })
        except Exception as e:
            print(f"Error loading honeypot events: {e}")
    
    recent_attacks = [a for a in all_events if datetime.fromisoformat(a['timestamp']) > last_24h]
    
    # Get top IPs with last seen timestamp
    ip_data = {}
    for attack in all_events:
        ip = attack['ip']
        if ip not in ip_data:
            ip_data[ip] = {'count': 0, 'last_seen': attack['timestamp']}
        ip_data[ip]['count'] += 1
        # Update last seen if this attack is more recent
        if attack['timestamp'] > ip_data[ip]['last_seen']:
            ip_data[ip]['last_seen'] = attack['timestamp']
    
    top_ips = [
        {'ip': ip, 'count': data['count'], 'last_seen': data['last_seen']} 
        for ip, data in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
    ]
    
    # Get top paths/protocols
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

# Admin endpoint to clear logs
@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    global attacks
    with attacks_lock:
        attacks.clear()
    save_attacks()
    return jsonify({'status': 'cleared', 'message': 'All logs cleared successfully'})

# Fake WordPress admin
@app.route('/wp-admin')
def wp_admin():
    return render_template_string('''
        <html>
        <head><title>WordPress Admin</title></head>
        <body>
            <h1>WordPress Login</h1>
            <form action="/wp-login.php" method="post">
                <input type="text" name="log" placeholder="Username">
                <input type="password" name="pwd" placeholder="Password">
                <button type="submit">Log In</button>
            </form>
        </body>
        </html>
    ''')

@app.route('/wp-login.php', methods=['POST'])
def wp_login():
    print(f"WordPress login attempt: {request.form}")
    return "ERROR: Invalid username or password."

# Fake phpMyAdmin
@app.route('/phpmyadmin')
@app.route('/pma')
def phpmyadmin():
    return render_template_string('''
        <html>
        <head><title>phpMyAdmin 4.8.5</title></head>
        <body>
            <h1>phpMyAdmin</h1>
            <form action="/phpmyadmin/index.php" method="post">
                <input type="text" name="pma_username" placeholder="Username">
                <input type="password" name="pma_password" placeholder="Password">
                <button type="submit">Go</button>
            </form>
        </body>
        </html>
    ''')

# Fake admin panel
@app.route('/admin')
def admin():
    return render_template_string('''
        <html>
        <head><title>Admin Panel</title></head>
        <body>
            <h1>Administration</h1>
            <form action="/admin/login" method="post">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    ''')

@app.route('/admin/login', methods=['POST'])
def admin_login():
    print(f"Admin login attempt: {request.form}")
    return "Access Denied"

# Common exploit paths
exploit_paths = [
    '/.env',
    '/config.php',
    '/wp-config.php',
    '/.git/config',
    '/backup.sql',
    '/database.sql',
    '/shell.php',
    '/c99.php',
    '/uploads/shell.php',
    '/.aws/credentials',
    '/config.json'
]

for path in exploit_paths:
    app.add_url_rule(path, f'exploit_{path}', lambda: ('Not Found', 404))

# Home page
@app.route('/')
def index():
    return render_template_string('''
        <html>
        <head><title>Server Status</title></head>
        <body>
            <h1>Server Running</h1>
            <p>Status: OK</p>
            <p>Last checked: {{ timestamp }}</p>
        </body>
        </html>
    ''', timestamp=datetime.utcnow().isoformat())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
