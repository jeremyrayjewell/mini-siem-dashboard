#!/bin/bash

# Start TCP listeners in background using Python directly
python3 -c "from server import start_tcp_listeners; start_tcp_listeners()" &

# Give listeners time to bind
sleep 2

# Start gunicorn in foreground
exec gunicorn --config gunicorn.conf.py --bind 0.0.0.0:8080 --workers 1 server:app
