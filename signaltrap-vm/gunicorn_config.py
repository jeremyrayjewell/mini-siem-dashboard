"""Gunicorn configuration file"""

# Don't preload the app
preload_app = False

def post_worker_init(worker):
    """Hook that runs after worker process is initialized"""
    print(f"[GUNICORN HOOK] post_worker_init called for worker PID {worker.pid}")
    import server
    print("[GUNICORN HOOK] About to start TCP listeners...")
    server.start_tcp_listeners()
    print("[GUNICORN HOOK] TCP listeners started successfully")
