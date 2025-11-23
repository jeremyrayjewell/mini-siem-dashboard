#!/usr/bin/env python3
"""Standalone TCP listeners process - runs independently from Flask"""
import sys
import time

# Unbuffered output
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print('[LISTENERS] Importing server module...')
from server import start_tcp_listeners

print('[LISTENERS] Starting all TCP listeners...')
start_tcp_listeners()
print('[LISTENERS] All listeners started successfully')

# Keep alive forever
print('[LISTENERS] Process running, will accept connections indefinitely...')
while True:
    time.sleep(3600)  # Sleep for 1 hour at a time
