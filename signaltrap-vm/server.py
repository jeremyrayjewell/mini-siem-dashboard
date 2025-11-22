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
    attack = {
        'timestamp': datetime.utcnow().isoformat(),
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
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
    
    recent_attacks = [a for a in attacks if datetime.fromisoformat(a['timestamp']) > last_24h]
    
    # Get top IPs
    ip_counts = {}
    for attack in attacks:
        ip = attack['ip']
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Get top paths
    path_counts = {}
    for attack in attacks:
        path = attack['path']
        path_counts[path] = path_counts.get(path, 0) + 1
    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    stats = {
        'totalAttacks': len(attacks),
        'last24h': len(recent_attacks),
        'topIPs': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'topPaths': [{'path': path, 'count': count} for path, count in top_paths],
        'recentAttacks': list(reversed(attacks[-50:]))
    }
    
    return jsonify(stats)

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
