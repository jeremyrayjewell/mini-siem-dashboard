"""Gunicorn configuration with on_starting hook"""

def on_starting(server):
    """Called just before the master process is initialized"""
    from server import start_tcp_listeners
    import threading
    
    print("[GUNICORN] on_starting: Starting TCP listeners in master process...")
    
    # Start listeners in a daemon thread that keeps the process alive
    def keep_alive():
        start_tcp_listeners()
        print("[GUNICORN] TCP listeners started, keeping thread alive...")
        import time
        while True:
            time.sleep(3600)
    
    listener_thread = threading.Thread(target=keep_alive, daemon=False)
    listener_thread.start()
    print("[GUNICORN] Listener thread started!")
