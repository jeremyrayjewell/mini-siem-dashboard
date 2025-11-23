#!/bin/bash

# Start TCP listeners in background - keep process alive with infinite loop
python3 -c "
from server import start_tcp_listeners
import time
start_tcp_listeners()
print('[START.SH] TCP listeners running, keeping process alive...')
while True:
    time.sleep(3600)
" &

# Give listeners time to bind
sleep 3

# Start gunicorn in foreground
exec gunicorn --config gunicorn.conf.py --bind 0.0.0.0:8080 --workers 1 server:app
