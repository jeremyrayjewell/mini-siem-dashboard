"""Gunicorn configuration file"""

# Don't preload the app
preload_app = False

def when_ready(server):
    """Called just after the server is started"""
    print("[GUNICORN HOOK] when_ready called - server is starting")
    import server as app_server
    print("[GUNICORN HOOK] Starting TCP listeners...")
    app_server.start_tcp_listeners()
    print("[GUNICORN HOOK] TCP listeners started!")

def post_worker_init(worker):
    """Hook that runs after worker process is initialized"""
    print(f"[GUNICORN HOOK] post_worker_init called for worker PID {worker.pid}")
