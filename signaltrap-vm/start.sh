#!/bin/bash

# Start TCP listeners in separate background process with unbuffered output
python3 -u -c "
from server import start_tcp_listeners
import time
import signal
import sys

# Handle signals gracefully
def signal_handler(sig, frame):
    print('[TCP LISTENERS] Shutting down...')
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

print('[TCP LISTENERS] Starting all TCP listeners...')
start_tcp_listeners()
print('[TCP LISTENERS] All listeners started, keeping process alive...')

# Keep process alive
while True:
    time.sleep(60)
" &

LISTENER_PID=$!
echo "[START.SH] TCP listeners started in background (PID: $LISTENER_PID)"

# Give listeners time to bind
sleep 3

# Start gunicorn in foreground
exec gunicorn --config gunicorn.conf.py --bind 0.0.0.0:8080 --workers 1 server:app
