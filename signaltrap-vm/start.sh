#!/bin/bash

# Start gunicorn - it will start TCP listeners via on_starting hook
exec gunicorn --config gunicorn.conf.py --bind 0.0.0.0:8080 --workers 1 server:app
