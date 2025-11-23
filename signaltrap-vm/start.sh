#!/bin/bash

# Start TCP listeners as a simple background Python script
python3 listeners.py &

LISTENER_PID=$!
echo "[START.SH] TCP listeners started in background (PID: $LISTENER_PID)"

# Give listeners time to bind
sleep 3

# Start gunicorn in foreground
# Prefer gunicorn_config.py (with hooks) if present, otherwise fall back to gunicorn.conf.py
if [ -f ./gunicorn_config.py ]; then
	echo "[START.SH] Using gunicorn_config.py"
	exec gunicorn --config gunicorn_config.py --bind 0.0.0.0:8080 --workers 1 server:app
else
	echo "[START.SH] Using gunicorn.conf.py"
	exec gunicorn --config gunicorn.conf.py --bind 0.0.0.0:8080 --workers 1 server:app
fi
