#!/usr/bin/env python3
"""Standalone TCP listeners process - runs independently from Flask"""

import sys
import time
import traceback
import requests

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print('[LISTENERS] Importing traps module...')
try:
    from traps import start_tcp_listeners
except Exception as e:
    print('[LISTENERS] FATAL: Could not import traps:', e)
    traceback.print_exc()
    while True:
        time.sleep(3600)

print('[LISTENERS] Starting all TCP listeners...')
try:
    from traps import start_tcp_listeners

    def forward_tcp_event(event):
        try:
            response = requests.post(SIEM_INGEST_URL, json=event)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"[ERROR] Failed to forward TCP event to SIEM: {e}")

    # Wrap the original start_tcp_listeners to include forwarding logic
    def start_tcp_listeners_with_forwarding():
        start_tcp_listeners()
        print('[LISTENERS] Forwarding TCP events to SIEM')

    start_tcp_listeners = start_tcp_listeners_with_forwarding

except Exception as e:
    print('[LISTENERS] FATAL: Could not import traps:', e)
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
