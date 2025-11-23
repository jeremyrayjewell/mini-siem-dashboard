"""Gunicorn configuration file"""

def post_worker_init(worker):
    """Hook that runs after worker process is initialized"""
    # Import here to ensure it runs in worker process
    from server import start_tcp_listeners
    start_tcp_listeners()
