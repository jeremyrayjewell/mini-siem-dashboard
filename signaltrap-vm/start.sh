#!/bin/bash

# Start TCP listeners in separate background process with unbuffered output
# Use nohup to prevent signals from parent shell
nohup python3 -u -c "
from server import start_tcp_listeners
import time
import signal
import sys

# Ignore common termination signals - we only want explicit shutdown
signal.signal(signal.SIGTERM, signal.SIG_IGN)
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGHUP, signal.SIG_IGN)

print('[TCP LISTENERS] Starting all TCP listeners...')
start_tcp_listeners()
print('[TCP LISTENERS] All listeners started, keeping process alive...')

# Keep process alive
while True:
    time.sleep(60)
" > /tmp/tcp_listeners.log 2>&1 &

LISTENER_PID=$!
echo "[START.SH] TCP listeners started in background (PID: $LISTENER_PID)"

# Give listeners time to bind
sleep 3

# Start gunicorn in foreground
exec gunicorn --config gunicorn.conf.py --bind 0.0.0.0:8080 --workers 1 server:app
