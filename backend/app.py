import json
from flask import Flask, jsonify, send_from_directory, request
from datetime import datetime, timedelta
from pathlib import Path
from backend.traps import start_trap_listeners, EVENTS_FILE, EVENTS_LOCK, MAX_EVENTS


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PUBLIC_DIR = BASE_DIR.parent / "public"

app = Flask(__name__)
@app.route("/admin/reset-events", methods=["POST"])
def reset_events():
	with EVENTS_LOCK:
		DATA_DIR.mkdir(exist_ok=True)
		with EVENTS_FILE.open("w") as f:
			json.dump([], f)
	return jsonify({"status": "ok", "message": "events reset"})

def log_http_request(req):
	"""
	Append a single HTTP request event to EVENTS_FILE.
	Event fields:
	  - timestamp: ISO8601 UTC string, same format as traps.py
	  - ip: client IP (req.remote_addr)
	  - port: server port
	  - protocol: "HTTP"
	  - event_type: "request"
	  - method: req.method
	  - path: req.path
	  - src_port: client source port (from req.environ["REMOTE_PORT"])
	  - user_agent: User-Agent header
	  - message: f"HTTP {req.method} {req.path} from {ip}"
	Uses EVENTS_LOCK and respects MAX_EVENTS, just like traps.py.
	"""
	ip = req.remote_addr or "unknown"
	# Try to determine the server port
	try:
		host_header = req.host  # e.g., "localhost:5000"
		if ":" in host_header:
			port = int(host_header.rsplit(":", 1)[1])
		else:
			port = int(req.environ.get("SERVER_PORT", 0))
	except Exception:
		port = 0
	# Try to get client source port
	try:
		src_port = int(req.environ.get("REMOTE_PORT", 0))
	except Exception:
		src_port = 0
	user_agent = req.headers.get("User-Agent", "")
	event = {
		"timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
		"ip": ip,
		"port": port,
		"protocol": "HTTP",
		"event_type": "request",
		"method": req.method,
		"path": req.path,
		"src_port": src_port,
		"user_agent": user_agent,
		"message": f"HTTP {req.method} {req.path} from {ip}",
	}
	with EVENTS_LOCK:
		try:
			if not EVENTS_FILE.exists():
				events = []
			else:
				with EVENTS_FILE.open("r") as f:
					events = json.load(f)
		except Exception:
			events = []
		events.append(event)
		if len(events) > MAX_EVENTS:
			events = events[-MAX_EVENTS:]
		with EVENTS_FILE.open("w") as f:
			json.dump(events, f)

@app.before_request
def before_request_logging():
	# Do NOT log:
	# - "/"           (dashboard HTML)
	# - "/api/stats"  (dashboard polling)
	# - "/favicon.ico" (browser noise)
	if request.path in ("/", "/api/stats", "/favicon.ico"):
		return
	log_http_request(request)

@app.route("/")
def index():
	return send_from_directory(str(PUBLIC_DIR), "index.html")

@app.route('/api/stats')
def api_stats():
	with EVENTS_LOCK:
		try:
			with EVENTS_FILE.open('r') as f:
				events = json.load(f)
		except Exception:
			events = []
	now = datetime.utcnow()
	last_24h = now - timedelta(hours=24)
	parsed_events = []
	for e in events:
		try:
			e_dt = datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
		except Exception:
			continue
		e['_dt'] = e_dt
		parsed_events.append(e)
	total_events = len(parsed_events)
	last24h_count = sum(1 for e in parsed_events if e['_dt'] >= last_24h)
	ip_counts = {}
	for e in parsed_events:
		ip = e.get('ip')
		if ip:
			ip_counts[ip] = ip_counts.get(ip, 0) + 1
	top_ips = sorted([
		{'ip': ip, 'count': count} for ip, count in ip_counts.items()
	], key=lambda x: x['count'], reverse=True)[:5]
	port_counts = {}
	for e in parsed_events:
		port = e.get('port')
		if port:
			port_counts[port] = port_counts.get(port, 0) + 1
	top_ports = sorted([
		{'port': port, 'count': count} for port, count in port_counts.items()
	], key=lambda x: x['count'], reverse=True)[:5]
	recent_events = sorted(parsed_events, key=lambda e: e['_dt'], reverse=True)[:50]
	for e in recent_events:
		e.pop('_dt', None)
	return jsonify({
		'totalEvents': total_events,
		'last24h': last24h_count,
		'topIPs': top_ips,
		'topPorts': top_ports,
		'recentEvents': recent_events
	})

if __name__ == "__main__":
	DATA_DIR.mkdir(exist_ok=True)
	if not EVENTS_FILE.exists():
		with EVENTS_FILE.open('w') as f:
			json.dump([], f)
	start_trap_listeners()
	app.run(host="0.0.0.0", port=5000, debug=True)
