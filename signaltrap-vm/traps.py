import socket
import threading
import sys
import os
import json
import time
import fcntl
import traceback
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock

# Configuration
MAX_LOGS = 10000
LOG_RETENTION_DAYS = 7
TCP_EVENTS_FILE = '/data/tcp_events.json'
RATE_LIMIT_WINDOW = 300  # 5 minutes
MAX_CONNECTIONS_PER_IP = 3  # Only 3 connections per 5 minutes
CONNECTION_TIMEOUT = 2  # Seconds
MAX_DATA_SIZE = 512  # Bytes

# TCP events storage
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

def load_tcp_events():
    global tcp_events
    if os.path.exists(TCP_EVENTS_FILE):
        try:
            lock_file = TCP_EVENTS_FILE + '.lock'
            with open(lock_file, 'w') as lockf:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
                try:
                    with open(TCP_EVENTS_FILE, 'r') as f:
                        loaded = json.load(f)
                        cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
                        tcp_events = [e for e in loaded if e['timestamp'] > cutoff]
                        print(f"Loaded {len(tcp_events)} TCP events from disk")
                finally:
                    fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            print(f"Error loading TCP events: {e}")
            tcp_events = []
    else:
        os.makedirs(os.path.dirname(TCP_EVENTS_FILE), exist_ok=True)
        tcp_events = []

def save_tcp_events():
    try:
        # Use file locking for cross-process safety
        lock_file = TCP_EVENTS_FILE + '.lock'
        os.makedirs(os.path.dirname(TCP_EVENTS_FILE), exist_ok=True)
        
        with open(lock_file, 'w') as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)  # Exclusive lock
            
            try:
                # Read existing events from file
                existing = []
                if os.path.exists(TCP_EVENTS_FILE):
                    try:
                        with open(TCP_EVENTS_FILE, 'r') as f:
                            existing = json.load(f)
                    except:
                        existing = []
                
                # Merge: add our events that aren't already in file
                existing_keys = {(e['timestamp'], e['ip'], e['port']) for e in existing}
                new_count = 0
                with tcp_events_lock:  # Thread lock for our own list
                    for event in tcp_events:
                        key = (event['timestamp'], event['ip'], event['port'])
                        if key not in existing_keys:
                            existing.append(event)
                            existing_keys.add(key)
                            new_count += 1
                
                # Apply retention filter
                cutoff = (datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()
                existing = [e for e in existing if e['timestamp'] > cutoff]
                
                # Write back
                with open(TCP_EVENTS_FILE, 'w') as f:
                    json.dump(existing, f)
                
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)  # Release lock
                
    except Exception as e:
        print(f"Error saving TCP events: {e}", file=sys.stderr)
        traceback.print_exc()

# TCP Listener Classes
class TrapService:
    def __init__(self, port, protocol, banner=None):
        self.port = port
        self.protocol = protocol
        self.banner = banner
        self.running = True
        
    def log_event(self, event_data):
        """Log an event to memory (saved to disk by background thread)"""
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
            
            print(f"[{self.protocol}:{self.port}] {event_data}")
        except Exception as e:
            print(f"[ERROR] Failed to log event: {e}", file=sys.stderr)
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

def background_saver():
    """Background thread to save events to disk periodically"""
    while True:
        try:
            time.sleep(5)
            save_tcp_events()
        except Exception as e:
            print(f"[ERROR] Background saver failed: {e}", file=sys.stderr)
            traceback.print_exc()

def start_tcp_listeners():
    """Start all TCP listener services in background threads"""
    # Load existing events on first start
    load_tcp_events()
    
    # Start background saver
    saver_thread = threading.Thread(target=background_saver)
    saver_thread.daemon = True
    saver_thread.start()
    print("[LISTENERS] Started background event saver thread")

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
