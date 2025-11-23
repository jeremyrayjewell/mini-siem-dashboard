#!/usr/bin/env python3
"""Standalone TCP listeners process - runs independently from Flask"""

import sys
import time
import traceback

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print('[LISTENERS] Importing server module...')
try:
    from server import start_tcp_listeners
except Exception as e:
    print('[LISTENERS] FATAL: Could not import server:', e)
    traceback.print_exc()
    while True:
        time.sleep(3600)

print('[LISTENERS] Starting all TCP listeners...')
try:
    start_tcp_listeners()
    print('[LISTENERS] All listeners started successfully')
except Exception as e:
    print('[LISTENERS] FATAL: Could not start listeners:', e)
    traceback.print_exc()
    while True:
        time.sleep(3600)

print('[LISTENERS] Process running, will accept connections indefinitely...')
while True:
    try:
        time.sleep(3600)
    except Exception as e:
        print('[LISTENERS] ERROR in keepalive loop:', e)
        traceback.print_exc()
