#!/bin/bash

# Start the multi-protocol honeypot in the background
python honeypot.py &
HONEYPOT_PID=$!

# Start the Flask web server (HTTP honeypot + API)
gunicorn --bind 0.0.0.0:8080 --workers 1 server:app &
FLASK_PID=$!

# Wait for both processes
echo "Started honeypot services (PID: $HONEYPOT_PID) and Flask server (PID: $FLASK_PID)"

# Handle shutdown gracefully
trap "kill $HONEYPOT_PID $FLASK_PID; exit" SIGTERM SIGINT

wait
