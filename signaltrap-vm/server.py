from flask import Flask, request, jsonify, render_template_stringfrom flask import Flask, request, jsonify, render_template_string

from flask_cors import CORSfrom flask_cors import CORS

from datetime import datetime, timedeltafrom datetime import datetime, timedelta

import jsonimport json

import osimport os

import atexitimport atexit

from threading import Lockfrom threading import Lock

import sysimport socket

from traps import tcp_events, tcp_events_lock, load_tcp_events, start_tcp_listenersimport threading

from collections import defaultdict

app = Flask(__name__)import time

CORS(app, origins=["https://mini-siem-dashboard.netlify.app"])import fcntl  # For file locking across processes

import sys

# Configuration

MAX_LOGS = 10000app = Flask(__name__)

LOG_RETENTION_DAYS = 7CORS(app, origins=["https://mini-siem-dashboard.netlify.app"])

ATTACKS_FILE = '/data/attacks.json'

# Flag to track if listeners have been started

# Store attack logs in memory with thread-safe access_listeners_started = False

attacks = []_listeners_lock = Lock()

attacks_lock = Lock()

# Configuration

# Load existing attacks from file on startupMAX_LOGS = 10000

def load_attacks():LOG_RETENTION_DAYS = 7

    global attacksATTACKS_FILE = '/data/attacks.json'

    if os.path.exists(ATTACKS_FILE):TCP_EVENTS_FILE = '/data/tcp_events.json'

        try:

            with open(ATTACKS_FILE, 'r') as f:# Rate limiting for TCP listeners

                loaded = json.load(f)RATE_LIMIT_WINDOW = 300  # 5 minutes

                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()MAX_CONNECTIONS_PER_IP = 3  # Only 3 connections per 5 minutes

                attacks = [a for a in loaded if a['timestamp'] > cutoff]CONNECTION_TIMEOUT = 2  # Seconds

                print(f"Loaded {len(attacks)} HTTP events from disk")MAX_DATA_SIZE = 512  # Bytes

        except Exception as e:

            print(f"Error loading attacks: {e}")# Store attack logs in memory with thread-safe access

            attacks = []attacks = []

    else:attacks_lock = Lock()

        os.makedirs(os.path.dirname(ATTACKS_FILE), exist_ok=True)

        attacks = []# TCP events

tcp_events = []

# Save attacks to filetcp_events_lock = Lock()

def save_attacks():

    try:# Rate limiting

        with attacks_lock:connection_counts = defaultdict(list)

            with open(ATTACKS_FILE, 'w') as f:rate_limit_lock = Lock()

                json.dump(attacks, f)

        print(f"Saved {len(attacks)} HTTP events to disk")def is_rate_limited(ip):

    except Exception as e:    """Check if an IP is rate limited"""

        print(f"Error saving attacks: {e}")    with rate_limit_lock:

        now = time.time()

# Save on shutdown        connection_counts[ip] = [t for t in connection_counts[ip] if now - t < RATE_LIMIT_WINDOW]

atexit.register(save_attacks)        

        if len(connection_counts[ip]) >= MAX_CONNECTIONS_PER_IP:

# Load data on startup            return True

load_attacks()        

        connection_counts[ip].append(now)

# Middleware to log requests        return False

@app.before_request

def before_request_handler():# Load existing attacks from file on startup

    print(f"[FLASK DEBUG] before_request called for {request.path}")def load_attacks():

        global attacks

    # Log requests (skip /api/stats and /favicon.ico)    if os.path.exists(ATTACKS_FILE):

    if request.path in ['/api/stats', '/favicon.ico']:        try:

        return            with open(ATTACKS_FILE, 'r') as f:

                    loaded = json.load(f)

    # Get real client IP (first IP in X-Forwarded-For chain)                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()

    forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)                attacks = [a for a in loaded if a['timestamp'] > cutoff]

    client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr                print(f"Loaded {len(attacks)} HTTP events from disk")

            except Exception as e:

    attack = {            print(f"Error loading attacks: {e}")

        'timestamp': datetime.utcnow().isoformat(),            attacks = []

        'ip': client_ip,    else:

        'method': request.method,        os.makedirs(os.path.dirname(ATTACKS_FILE), exist_ok=True)

        'path': request.path,        attacks = []

        'user_agent': request.headers.get('User-Agent', ''),

        'headers': dict(request.headers)def load_tcp_events():

    }    global tcp_events

    with attacks_lock:    if os.path.exists(TCP_EVENTS_FILE):

        attacks.append(attack)        try:

        if len(attacks) > MAX_LOGS:            lock_file = TCP_EVENTS_FILE + '.lock'

            attacks.pop(0)            with open(lock_file, 'w') as lockf:

                    fcntl.flock(lockf.fileno(), fcntl.LOCK_SH)  # Shared lock for reading

    # Save to disk every 10 attacks                try:

    if len(attacks) % 10 == 0:                    with open(TCP_EVENTS_FILE, 'r') as f:

        save_attacks()                        loaded = json.load(f)

                        cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()

# API endpoint for dashboard                        tcp_events = [e for e in loaded if e['timestamp'] > cutoff]

@app.route('/api/stats')                        print(f"Loaded {len(tcp_events)} TCP events from disk")

def get_stats():                finally:

    # Reload TCP events from disk since they're written by separate process                    fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

    load_tcp_events()        except Exception as e:

                print(f"Error loading TCP events: {e}")

    now = datetime.utcnow()            tcp_events = []

    last_24h = now - timedelta(hours=24)    else:

            os.makedirs(os.path.dirname(TCP_EVENTS_FILE), exist_ok=True)

    # Combine HTTP attacks with TCP events        tcp_events = []

    all_events = list(attacks)  # HTTP events

    # Save attacks to file

    # Convert TCP events to attack formatdef save_attacks():

    with tcp_events_lock:    try:

        for event in tcp_events:        with attacks_lock:

            all_events.append({            with open(ATTACKS_FILE, 'w') as f:

                'timestamp': event['timestamp'],                json.dump(attacks, f)

                'ip': event.get('ip', 'unknown'),        print(f"Saved {len(attacks)} HTTP events to disk")

                'method': event.get('protocol', 'TCP'),    except Exception as e:

                'path': f":{event.get('port', 0)} {event.get('protocol', 'unknown')}",        print(f"Error saving attacks: {e}")

                'user_agent': event.get('message', ''),

                'headers': {}def save_tcp_events():

            })    try:

            print("[DEBUG] Starting save_tcp_events...", file=sys.stderr)

    recent_attacks = [a for a in all_events if datetime.fromisoformat(a['timestamp']) > last_24h]        # Use file locking for cross-process safety

            lock_file = TCP_EVENTS_FILE + '.lock'

    # Get top IPs with last seen timestamp        os.makedirs(os.path.dirname(TCP_EVENTS_FILE), exist_ok=True)

    ip_data = {}        

    for attack in all_events:        with open(lock_file, 'w') as lockf:

        ip = attack['ip']            print("[DEBUG] Acquiring lock...", file=sys.stderr)

        if ip not in ip_data:            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)  # Exclusive lock

            ip_data[ip] = {'count': 0, 'last_seen': attack['timestamp']}            print("[DEBUG] Lock acquired.", file=sys.stderr)

        ip_data[ip]['count'] += 1            

        # Update last seen if this attack is more recent            try:

        if attack['timestamp'] > ip_data[ip]['last_seen']:                # Read existing events from file

            ip_data[ip]['last_seen'] = attack['timestamp']                existing = []

                    if os.path.exists(TCP_EVENTS_FILE):

    top_ips = [                    try:

        {'ip': ip, 'count': data['count'], 'last_seen': data['last_seen']}                         with open(TCP_EVENTS_FILE, 'r') as f:

        for ip, data in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True)[:10]                            existing = json.load(f)

    ]                    except:

                            existing = []

    # Get top paths/protocols                

    path_counts = {}                # Merge: add our events that aren't already in file

    for attack in all_events:                existing_keys = {(e['timestamp'], e['ip'], e['port']) for e in existing}

        path = attack['path']                new_count = 0

        path_counts[path] = path_counts.get(path, 0) + 1                with tcp_events_lock:  # Thread lock for our own list

    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]                    for event in tcp_events:

                            key = (event['timestamp'], event['ip'], event['port'])

    stats = {                        if key not in existing_keys:

        'totalAttacks': len(all_events),                            existing.append(event)

        'last24h': len(recent_attacks),                            existing_keys.add(key)

        'topIPs': top_ips,                            new_count += 1

        'topPaths': [{'path': path, 'count': count} for path, count in top_paths],                

        'recentAttacks': list(reversed(all_events[-50:]))                # Apply retention filter

    }                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()

                    existing = [e for e in existing if e['timestamp'] > cutoff]

    return jsonify(stats)                

                # Write back

# Admin endpoint to clear logs                with open(TCP_EVENTS_FILE, 'w') as f:

@app.route('/api/clear-logs', methods=['POST'])                    json.dump(existing, f)

def clear_logs():                

    global attacks                print(f"Saved {len(existing)} TCP events to disk (+{new_count} new)", file=sys.stderr)

    with attacks_lock:            finally:

        attacks.clear()                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)  # Release lock

    save_attacks()                print("[DEBUG] Lock released.", file=sys.stderr)

    return jsonify({'status': 'cleared', 'message': 'All logs cleared successfully'})                

    except Exception as e:

# Fake WordPress admin        print(f"Error saving TCP events: {e}", file=sys.stderr)

@app.route('/wp-admin')        import traceback

def wp_admin():        traceback.print_exc()

    return render_template_string('''

        <html># Save on shutdown

        <head><title>WordPress Admin</title></head>atexit.register(save_attacks)

        <body>atexit.register(save_tcp_events)

            <h1>WordPress Login</h1>

            <form action="/wp-login.php" method="post"># Load data on startup

                <input type="text" name="log" placeholder="Username">load_attacks()

                <input type="password" name="pwd" placeholder="Password">load_tcp_events()

                <button type="submit">Log In</button>

            </form># Middleware to log requests

        </body>@app.before_request

        </html>def before_request_handler():

    ''')    print(f"[FLASK DEBUG] before_request called for {request.path}")

    

@app.route('/wp-login.php', methods=['POST'])    # Log requests (skip /api/stats and /favicon.ico)

def wp_login():    if request.path in ['/api/stats', '/favicon.ico']:

    print(f"WordPress login attempt: {request.form}")        return

    return "ERROR: Invalid username or password."    

    # Get real client IP (first IP in X-Forwarded-For chain)

# Fake phpMyAdmin    forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)

@app.route('/phpmyadmin')    client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr

@app.route('/pma')    

def phpmyadmin():    attack = {

    return render_template_string('''        'timestamp': datetime.utcnow().isoformat(),

        <html>        'ip': client_ip,

        <head><title>phpMyAdmin 4.8.5</title></head>        'method': request.method,

        <body>        'path': request.path,

            <h1>phpMyAdmin</h1>        'user_agent': request.headers.get('User-Agent', ''),

            <form action="/phpmyadmin/index.php" method="post">        'headers': dict(request.headers)

                <input type="text" name="pma_username" placeholder="Username">    }

                <input type="password" name="pma_password" placeholder="Password">    with attacks_lock:

                <button type="submit">Go</button>        attacks.append(attack)

            </form>        if len(attacks) > MAX_LOGS:

        </body>            attacks.pop(0)

        </html>    

    ''')    # Save to disk every 10 attacks

    if len(attacks) % 10 == 0:

# Fake admin panel        save_attacks()

@app.route('/admin')

def admin():# API endpoint for dashboard

    return render_template_string('''@app.route('/api/stats')

        <html>def get_stats():

        <head><title>Admin Panel</title></head>    # Reload TCP events from disk since they're written by separate process

        <body>    load_tcp_events()

            <h1>Administration</h1>    

            <form action="/admin/login" method="post">    now = datetime.utcnow()

                <input type="text" name="username" placeholder="Username">    last_24h = now - timedelta(hours=24)

                <input type="password" name="password" placeholder="Password">    

                <button type="submit">Login</button>    # Combine HTTP attacks with TCP events

            </form>    all_events = list(attacks)  # HTTP events

        </body>    

        </html>    # Convert TCP events to attack format

    ''')    with tcp_events_lock:

        for event in tcp_events:

@app.route('/admin/login', methods=['POST'])            all_events.append({

def admin_login():                'timestamp': event['timestamp'],

    print(f"Admin login attempt: {request.form}")                'ip': event.get('ip', 'unknown'),

    return "Access Denied"                'method': event.get('protocol', 'TCP'),

                'path': f":{event.get('port', 0)} {event.get('protocol', 'unknown')}",

# Common exploit paths                'user_agent': event.get('message', ''),

exploit_paths = [                'headers': {}

    '/.env',            })

    '/config.php',    

    '/wp-config.php',    recent_attacks = [a for a in all_events if datetime.fromisoformat(a['timestamp']) > last_24h]

    '/.git/config',    

    '/backup.sql',    # Get top IPs with last seen timestamp

    '/database.sql',    ip_data = {}

    '/shell.php',    for attack in all_events:

    '/c99.php',        ip = attack['ip']

    '/uploads/shell.php',        if ip not in ip_data:

    '/.aws/credentials',            ip_data[ip] = {'count': 0, 'last_seen': attack['timestamp']}

    '/config.json'        ip_data[ip]['count'] += 1

]        # Update last seen if this attack is more recent

        if attack['timestamp'] > ip_data[ip]['last_seen']:

for path in exploit_paths:            ip_data[ip]['last_seen'] = attack['timestamp']

    app.add_url_rule(path, f'exploit_{path}', lambda: ('Not Found', 404))    

    top_ips = [

# Home page        {'ip': ip, 'count': data['count'], 'last_seen': data['last_seen']} 

@app.route('/')        for ip, data in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True)[:10]

def index():    ]

    return render_template_string('''    

        <html>    # Get top paths/protocols

        <head><title>Server Status</title></head>    path_counts = {}

        <body>    for attack in all_events:

            <h1>Server Running</h1>        path = attack['path']

            <p>Status: OK</p>        path_counts[path] = path_counts.get(path, 0) + 1

            <p>Last checked: {{ timestamp }}</p>    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        </body>    

        </html>    stats = {

    ''', timestamp=datetime.utcnow().isoformat())        'totalAttacks': len(all_events),

        'last24h': len(recent_attacks),

if __name__ == '__main__':        'topIPs': top_ips,

    # Start Flask app (only for local development)        'topPaths': [{'path': path, 'count': count} for path, count in top_paths],

    start_tcp_listeners()        'recentAttacks': list(reversed(all_events[-50:]))

    port = int(os.environ.get('PORT', 8080))    }

    app.run(host='0.0.0.0', port=port)    
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
        """Log an event and save to disk immediately"""
        try:
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'protocol': self.protocol,
                'port': self.port,
                **event_data
            }
            
            print(f"[DEBUG] Logging event: {event}", file=sys.stderr)
            
            with tcp_events_lock:
                tcp_events.append(event)
                if len(tcp_events) > MAX_LOGS:
                    tcp_events.pop(0)
                # Save immediately on every event so separate processes can see it
                save_tcp_events()
            
            print(f"[{self.protocol}:{self.port}] {event_data}")
        except Exception as e:
            print(f"[ERROR] Failed to log event: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
    
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
                    
                    # Handle connection in a separate thread immediately
                    # This prevents logging/locking from blocking the accept loop or the banner
                    client_thread = threading.Thread(
                        target=self._handle_connection_wrapper,
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

    def _handle_connection_wrapper(self, client, addr):
        """Wrapper to handle logging and rate limiting inside the client thread"""
        try:
            # Log connection
            self.log_event({
                'ip': addr[0],
                'event_type': 'connection',
                'message': f'Connection from {addr[0]}:{addr[1]}'
            })
            
            if is_rate_limited(addr[0]):
                print(f"[!] Rate limited: {addr[0]}")
                client.close()
                return
            
            self.handle_client(client, addr)
        except Exception as e:
            print(f"[!] Error in connection wrapper for {addr}: {e}")
            try:
                client.close()
            except:
                pass

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
    # Start Flask app (only for local development)
    start_tcp_listeners()
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
