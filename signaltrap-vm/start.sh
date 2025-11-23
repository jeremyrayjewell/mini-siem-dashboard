#!/bin/bash

# Start TCP listeners as a simple background Python script
python3 listeners.py &

LISTENER_PID=$!
echo "[START.SH] TCP listeners started in background (PID: $LISTENER_PID)"

# Give listeners time to bind
sleep 3

# Start gunicorn in foreground
exec gunicorn --config gunicorn.conf.py --bind 0.0.0.0:8080 --workers 1 server:app
