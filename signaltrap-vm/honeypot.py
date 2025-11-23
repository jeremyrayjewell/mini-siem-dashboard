"""
Multi-protocol honeypot that simulates multiple services
Logs all connection attempts and authentication tries
"""
import socket
import threading
import json
import os
from datetime import datetime, timedelta
from threading import Lock
from collections import defaultdict
import time

# Configuration
LOG_FILE = '/data/honeypot_events.json'
MAX_EVENTS = 10000
RATE_LIMIT_WINDOW = 60  # seconds
MAX_CONNECTIONS_PER_IP = 5  # per window

events = []
events_lock = Lock()

# Rate limiting
connection_counts = defaultdict(list)
rate_limit_lock = Lock()

def is_rate_limited(ip):
    """Check if an IP is rate limited"""
    with rate_limit_lock:
        now = time.time()
        # Clean old entries
        connection_counts[ip] = [t for t in connection_counts[ip] if now - t < RATE_LIMIT_WINDOW]
        
        # Check limit
        if len(connection_counts[ip]) >= MAX_CONNECTIONS_PER_IP:
            return True
        
        # Record this connection
        connection_counts[ip].append(now)
        return False

class HoneypotService:
    def __init__(self, port, protocol, banner=None):
        self.port = port
        self.protocol = protocol
        self.banner = banner
        self.running = True
        
    def log_event(self, event_data):
        """Log an event to the centralized log"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'protocol': self.protocol,
            'port': self.port,
            **event_data
        }
        
        with events_lock:
            events.append(event)
            # Limit total events
            if len(events) > MAX_EVENTS:
                events.pop(0)
            # Save every 10 events
            if len(events) % 10 == 0:
                save_events()
        
        print(f"[{self.protocol}:{self.port}] {event_data}")
    
    def handle_client(self, client_socket, addr):
        """Override in subclasses"""
        pass
    
    def start(self):
        """Start the honeypot service"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(5)
        server.settimeout(1.0)  # Allow checking self.running
        
        print(f"[*] {self.protocol} honeypot listening on port {self.port}")
        
        while self.running:
            try:
                client, addr = server.accept()
                
                # Rate limiting check
                if is_rate_limited(addr[0]):
                    print(f"[!] Rate limited: {addr[0]}")
                    client.close()
                    continue
                
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'connection',
                    'message': f'Connection from {addr[0]}:{addr[1]}'
                })
                
                # Handle in separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Error in {self.protocol}: {e}")
                break
        
        server.close()

class SSHHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(22, 'SSH', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')
    
    def handle_client(self, client, addr):
        try:
            # Send SSH banner
            client.send(f'{self.banner}\r\n'.encode())
            
            # Wait for authentication attempt
            data = client.recv(1024)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'data': data.decode('utf-8', errors='ignore')[:200]
                })
            
            # Reject authentication
            client.send(b'Permission denied\r\n')
        except Exception as e:
            pass
        finally:
            client.close()

class FTPHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(21, 'FTP', '220 FTP Server ready')
    
    def handle_client(self, client, addr):
        try:
            client.send(f'{self.banner}\r\n'.encode())
            
            username = None
            while True:
                data = client.recv(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                
                if command.upper().startswith('USER'):
                    username = command.split(' ', 1)[1] if ' ' in command else 'unknown'
                    self.log_event({
                        'ip': addr[0],
                        'event_type': 'username',
                        'username': username
                    })
                    client.send(b'331 Password required\r\n')
                    
                elif command.upper().startswith('PASS'):
                    password = command.split(' ', 1)[1] if ' ' in command else 'unknown'
                    self.log_event({
                        'ip': addr[0],
                        'event_type': 'password',
                        'username': username or 'unknown',
                        'password': password
                    })
                    client.send(b'530 Login incorrect\r\n')
                    break
                else:
                    client.send(b'500 Unknown command\r\n')
        except Exception as e:
            pass
        finally:
            client.close()

class TelnetHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(23, 'Telnet', 'Ubuntu 20.04 LTS')
    
    def handle_client(self, client, addr):
        try:
            client.send(f'{self.banner}\r\nlogin: '.encode())
            
            username = client.recv(1024).decode('utf-8', errors='ignore').strip()
            if username:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'username',
                    'username': username
                })
                
                client.send(b'Password: ')
                password = client.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if password:
                    self.log_event({
                        'ip': addr[0],
                        'event_type': 'password',
                        'username': username,
                        'password': password
                    })
                
            client.send(b'\r\nLogin incorrect\r\n')
        except Exception as e:
            pass
        finally:
            client.close()

class MySQLHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(3306, 'MySQL')
    
    def handle_client(self, client, addr):
        try:
            # Send MySQL handshake
            handshake = b'\x0a5.7.0\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            client.send(handshake)
            
            data = client.recv(1024)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'message': 'MySQL authentication attempt'
                })
        except Exception as e:
            pass
        finally:
            client.close()

class PostgreSQLHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(5432, 'PostgreSQL')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(1024)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'message': 'PostgreSQL authentication attempt'
                })
                # Send auth error
                client.send(b'E\x00\x00\x00\x00FATAL: password authentication failed')
        except Exception as e:
            pass
        finally:
            client.close()

class RedisHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(6379, 'Redis')
    
    def handle_client(self, client, addr):
        try:
            while True:
                data = client.recv(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore')
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'command',
                    'command': command[:200]
                })
                
                # Send error response
                client.send(b'-NOAUTH Authentication required\r\n')
                break
        except Exception as e:
            pass
        finally:
            client.close()

class MongoDBHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(27017, 'MongoDB')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(1024)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'auth_attempt',
                    'message': 'MongoDB authentication attempt'
                })
        except Exception as e:
            pass
        finally:
            client.close()

class RDPHoneypot(HoneypotService):
    def __init__(self):
        super().__init__(3389, 'RDP')
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(1024)
            if data:
                self.log_event({
                    'ip': addr[0],
                    'event_type': 'connection_attempt',
                    'message': 'RDP connection attempt'
                })
        except Exception as e:
            pass
        finally:
            client.close()

def save_events():
    """Save events to disk"""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'w') as f:
            json.dump(events, f)
        print(f"Saved {len(events)} events to disk")
    except Exception as e:
        print(f"Error saving events: {e}")

def load_events():
    """Load events from disk"""
    global events
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                events = json.load(f)
            print(f"Loaded {len(events)} events from disk")
        except Exception as e:
            print(f"Error loading events: {e}")

if __name__ == '__main__':
    # Load existing events
    load_events()
    
    # Start all honeypot services
    services = [
        SSHHoneypot(),
        FTPHoneypot(),
        TelnetHoneypot(),
        MySQLHoneypot(),
        PostgreSQLHoneypot(),
        RedisHoneypot(),
        MongoDBHoneypot(),
        RDPHoneypot()
    ]
    
    threads = []
    for service in services:
        t = threading.Thread(target=service.start)
        t.daemon = True
        t.start()
        threads.append(t)
    
    print("\n[*] All honeypot services started!")
    print("[*] Press Ctrl+C to exit\n")
    
    try:
        # Keep main thread alive and save periodically
        import time
        while True:
            time.sleep(60)
            save_events()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        for service in services:
            service.running = False
        save_events()
        print("[*] Goodbye!")
