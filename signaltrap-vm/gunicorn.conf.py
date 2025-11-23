"""Gunicorn configuration with post-fork hook to start TCP listeners"""

def post_fork(server, worker):
    """Called just after a worker has been forked"""
    # Import here to avoid issues with module loading order
    from server import start_tcp_listeners
    
    print(f"[GUNICORN] post_fork called for worker {worker.pid}")
    print("[GUNICORN] Starting TCP listeners in worker process...")
    try:
        start_tcp_listeners()
        print("[GUNICORN] TCP listeners started in worker!")
    except Exception as e:
        print(f"[GUNICORN ERROR] Failed to start TCP listeners: {e}")
        import traceback
        traceback.print_exc()
