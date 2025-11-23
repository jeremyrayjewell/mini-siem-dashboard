from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os
import atexit
from threading import Lock
import socket
import threading
from collections import defaultdict
import time

app = Flask(__name__)
CORS(app, origins=["https://mini-siem-dashboard.netlify.app"])

# Flag to track if listeners have been started
_listeners_started = False
_listeners_lock = Lock()

# Configuration
MAX_LOGS = 10000
LOG_RETENTION_DAYS = 7
ATTACKS_FILE = '/data/attacks.json'
TCP_EVENTS_FILE = '/data/tcp_events.json'

# Rate limiting for TCP listeners
RATE_LIMIT_WINDOW = 300  # 5 minutes
MAX_CONNECTIONS_PER_IP = 3  # Only 3 connections per 5 minutes
CONNECTION_TIMEOUT = 2  # Seconds
MAX_DATA_SIZE = 512  # Bytes

# Store attack logs in memory with thread-safe access
attacks = []
attacks_lock = Lock()

# TCP events
tcp_events = []
tcp_events_lock = Lock()

# Rate limiting
connection_counts = defaultdict(list)
rate_limit_lock = Lock()

def is_rate_limited(ip):
    """Check if an IP is rate limited"""
    with rate_limit_lock:
        now = time.time()
        connection_counts[ip] = [t for t in connection_counts[ip] if now - t < RATE_LIMIT_WINDOW]
        
        if len(connection_counts[ip]) >= MAX_CONNECTIONS_PER_IP:
            return True
        
        connection_counts[ip].append(now)
        return False

# Load existing attacks from file on startup
def load_attacks():
    global attacks
    if os.path.exists(ATTACKS_FILE):
        try:
            with open(ATTACKS_FILE, 'r') as f:
                loaded = json.load(f)
                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
                attacks = [a for a in loaded if a['timestamp'] > cutoff]
                print(f"Loaded {len(attacks)} HTTP events from disk")
        except Exception as e:
            print(f"Error loading attacks: {e}")
            attacks = []
    else:
        os.makedirs(os.path.dirname(ATTACKS_FILE), exist_ok=True)
        attacks = []

def load_tcp_events():
    global tcp_events
    if os.path.exists(TCP_EVENTS_FILE):
        try:
            with open(TCP_EVENTS_FILE, 'r') as f:
                loaded = json.load(f)
                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
                tcp_events = [e for e in loaded if e['timestamp'] > cutoff]
                print(f"Loaded {len(tcp_events)} TCP events from disk")
        except Exception as e:
            print(f"Error loading TCP events: {e}")
            tcp_events = []
    else:
        os.makedirs(os.path.dirname(TCP_EVENTS_FILE), exist_ok=True)
        tcp_events = []

# Save attacks to file
def save_attacks():
    try:
        with attacks_lock:
            with open(ATTACKS_FILE, 'w') as f:
                json.dump(attacks, f)
        print(f"Saved {len(attacks)} HTTP events to disk")
    except Exception as e:
        print(f"Error saving attacks: {e}")

def save_tcp_events():
    try:
        with tcp_events_lock:
            with open(TCP_EVENTS_FILE, 'w') as f:
                json.dump(tcp_events, f)
        print(f"Saved {len(tcp_events)} TCP events to disk")
    except Exception as e:
        print(f"Error saving TCP events: {e}")

# Save on shutdown
atexit.register(save_attacks)
atexit.register(save_tcp_events)

# Load data on startup
load_attacks()
load_tcp_events()

# Middleware to ensure TCP listeners start and log requests
@app.before_request
def before_request_handler():
    # Start TCP listeners on first request
    global _listeners_started
    print(f"[FLASK DEBUG] before_request called for {request.path}")
    with _listeners_lock:
        if not _listeners_started:
            print("[FLASK] Starting TCP listeners on first request...")
            start_tcp_listeners()
            _listeners_started = True
            print("[FLASK] TCP listeners started!")
        else:
            print("[FLASK DEBUG] Listeners already started, skipping")
    
    # Log requests (skip /api/stats and /favicon.ico)
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
    
    # Combine HTTP attacks with TCP events
    all_events = list(attacks)  # HTTP events
    
    # Convert TCP events to attack format
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

# TCP Listener Classes
class TrapService:
    def __init__(self, port, protocol, banner=None):
        self.port = port
        self.protocol = protocol
        self.banner = banner
        self.running = True
        
    def log_event(self, event_data):
        """Log an event"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'protocol': self.protocol,
            'port': self.port,
            **event_data
        }
        
        with tcp_events_lock:
            tcp_events.append(event)
            if len(tcp_events) > MAX_LOGS:
                tcp_events.pop(0)
            if len(tcp_events) % 10 == 0:
                save_tcp_events()
        
        print(f"[{self.protocol}:{self.port}] {event_data}")
    
    def handle_client(self, client_socket, addr):
        """Override in subclasses"""
        pass
    
    def start(self):
        """Start the trap service"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            server.settimeout(1.0)
            
            print(f"[*] {self.protocol} listener on port {self.port}")
            
            while self.running:
                try:
                    client, addr = server.accept()
                    client.settimeout(CONNECTION_TIMEOUT)
                    
                    if is_rate_limited(addr[0]):
                        print(f"[!] Rate limited: {addr[0]}")
                        client.close()
                        continue
                    
                    self.log_event({
                        'ip': addr[0],
                        'event_type': 'connection',
                        'message': f'Connection from {addr[0]}:{addr[1]}'
                    })
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Error accepting connection in {self.protocol}: {e}")
                    continue
            
            server.close()
        except Exception as e:
            print(f"[!] FATAL: Could not start {self.protocol} listener on port {self.port}: {e}")
            import traceback
            traceback.print_exc()

class SSHTrap(TrapService):
    def __init__(self):
        super().__init__(2222, 'SSH', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')
    
    def handle_client(self, client, addr):
        try:
            client.send(f'{self.banner}\r\n'.encode())
            data = client.recv(MAX_DATA_SIZE)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'data': data.decode('utf-8', errors='ignore')[:100]
                })
            client.send(b'Permission denied\r\n')
        except:
            pass
        finally:
            client.close()

class FTPTrap(TrapService):
    def __init__(self):
        super().__init__(2121, 'FTP', '220 FTP Server ready')
    
    def handle_client(self, client, addr):
        try:
            client.send(f'{self.banner}\r\n'.encode())
            username = None
            attempts = 0
            while attempts < 2:
                data = client.recv(MAX_DATA_SIZE)
                if not data:
                    break
                command = data.decode('utf-8', errors='ignore').strip()
                attempts += 1
                
                if command.upper().startswith('USER'):
                    username = command.split(' ', 1)[1] if ' ' in command else 'unknown'
                    self.log_event({
                        'ip': addr[0],
                        'event_type': 'username',
                        'username': username[:50]
                    })
                    client.send(b'331 Password required\r\n')
                elif command.upper().startswith('PASS'):
                    password = command.split(' ', 1)[1] if ' ' in command else 'unknown'
                    self.log_event({
                        'ip': addr[0],
                        'event_type': 'password',
                        'username': username or 'unknown',
                        'password': password[:50]
                    })
                    client.send(b'530 Login incorrect\r\n')
                    break
                else:
                    client.send(b'500 Unknown command\r\n')
                    break
        except:
            pass
        finally:
            client.close()

class TelnetTrap(TrapService):
    def __init__(self):
        super().__init__(2323, 'Telnet', 'Ubuntu 20.04 LTS')
    
    def handle_client(self, client, addr):
        try:
            client.send(f'{self.banner}\r\nlogin: '.encode())
            username = client.recv(MAX_DATA_SIZE).decode('utf-8', errors='ignore').strip()
            if username:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'username',
                    'username': username[:50]
                })
                client.send(b'Password: ')
                password = client.recv(MAX_DATA_SIZE).decode('utf-8', errors='ignore').strip()
                if password:
                    self.log_event({
                        'ip': addr[0],
                        'event_type': 'password',
                        'username': username[:50],
                        'password': password[:50]
                    })
            client.send(b'\r\nLogin incorrect\r\n')
        except:
            pass
        finally:
            client.close()

class MySQLTrap(TrapService):
    def __init__(self):
        super().__init__(3306, 'MySQL')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(MAX_DATA_SIZE)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'message': 'MySQL authentication attempt'
                })
        except:
            pass
        finally:
            client.close()

class PostgreSQLTrap(TrapService):
    def __init__(self):
        super().__init__(5432, 'PostgreSQL')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(MAX_DATA_SIZE)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'message': 'PostgreSQL authentication attempt'
                })
        except:
            pass
        finally:
            client.close()

class RedisTrap(TrapService):
    def __init__(self):
        super().__init__(6379, 'Redis')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(MAX_DATA_SIZE)
            if data:
                command = data.decode('utf-8', errors='ignore')
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'command',
                    'command': command[:100]
                })
        except:
            pass
        finally:
            client.close()

class MongoDBTrap(TrapService):
    def __init__(self):
        super().__init__(27017, 'MongoDB')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(MAX_DATA_SIZE)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'message': 'MongoDB authentication attempt'
                })
        except:
            pass
        finally:
            client.close()

class RDPTrap(TrapService):
    def __init__(self):
        super().__init__(3389, 'RDP')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(MAX_DATA_SIZE)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'connection_attempt',
                    'message': 'RDP connection attempt'
                })
        except:
            pass
        finally:
            client.close()

def start_tcp_listeners():
    """Start all TCP listener services in background threads"""
    services = [
        SSHTrap(),
        FTPTrap(),
        TelnetTrap(),
        MySQLTrap(),
        PostgreSQLTrap(),
        RedisTrap(),
        MongoDBTrap(),
        RDPTrap()
    ]
    
    for service in services:
        thread = threading.Thread(target=service.start)
        thread.daemon = True
        thread.start()
        print(f"Started {service.protocol} listener on port {service.port}")

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
    # Start Flask app
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
