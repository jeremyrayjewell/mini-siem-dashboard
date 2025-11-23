"""Gunicorn configuration file"""

def post_worker_init(worker):
    """Hook that runs after worker process is initialized"""
    print(f"[GUNICORN HOOK] post_worker_init called for worker {worker.pid}")
    # Import here to ensure it runs in worker process
    from server import start_tcp_listeners
    print("[GUNICORN HOOK] About to start TCP listeners...")
    start_tcp_listeners()
    print("[GUNICORN HOOK] TCP listeners started successfully")
