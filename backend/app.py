import ipaddress
import requests
_geo_cache = {}

def load_geo_cache():
	global _geo_cache
	if GEO_CACHE_FILE.exists():
		try:
			with GEO_CACHE_FILE.open("r") as f:
				_geo_cache = json.load(f)
		except Exception:
			_geo_cache = {}
	else:
		_geo_cache = {}

def save_geo_cache():
	try:
		with GEO_CACHE_FILE.open("w") as f:
			json.dump(_geo_cache, f)
	except Exception:
		pass

def is_public_ip(ip: str) -> bool:
	try:
		addr = ipaddress.ip_address(ip)
		return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
	except ValueError:
		return False

def lookup_geo(ip: str):
	if not is_public_ip(ip):
		return None
	if ip in _geo_cache:
		return _geo_cache[ip]
	try:
		resp = requests.get(f"https://ipwho.is/{ip}", timeout=3)
		data = resp.json()
		if not data.get("success", False):
			return None
		geo = {
			"ip": ip,
			"country": data.get("country"),
			"lat": data.get("latitude"),
			"lon": data.get("longitude")
		}
		_geo_cache[ip] = geo
		save_geo_cache()
		return geo
	except Exception:
		return None
import json
from flask import Flask, jsonify, send_from_directory, request
from datetime import datetime, timedelta
from pathlib import Path
from backend.traps import start_trap_listeners, EVENTS_FILE, EVENTS_LOCK, MAX_EVENTS
from backend.geo import get_geo


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
	# Use X-Forwarded-For if present, else remote_addr
	ip = req.headers.get("X-Forwarded-For", req.remote_addr)
	if ip and "," in ip:
		ip = ip.split(",")[0].strip()
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
	geo_ips = []
	for entry in top_ips:
		ip = entry["ip"]
		geo = lookup_geo(ip)
		if geo and geo.get("lat") is not None and geo.get("lon") is not None:
			geo_ips.append({
				"ip": ip,
				"count": entry["count"],
				"country": geo.get("country"),
				"lat": geo.get("lat"),
				"lon": geo.get("lon"),
			})
	port_counts = {}
	for e in parsed_events:
		port = e.get('port')
		if port:
			port_counts[port] = port_counts.get(port, 0) + 1
	top_ports = sorted([
		{'port': port, 'count': count} for port, count in port_counts.items()
	], key=lambda x: x['count'], reverse=True)[:5]
	recent_events = sorted(parsed_events, key=lambda e: e['_dt'], reverse=True)[:50]
	# Enrich with geo data and prefer IPv4 for display
	for e in recent_events:
		e.pop('_dt', None)
		ip = e.get('ip', '')
		ipv4 = None
		ipv6 = None
		try:
			addr = ipaddress.ip_address(ip)
			if addr.version == 4:
				ipv4 = ip
			else:
				ipv6 = ip
		except Exception:
			pass
		# Try to extract IPv4 from xff if not present
		if not ipv4 and 'xff' in e:
			xff = e['xff']
			for part in xff.split(','):
				part = part.strip()
				try:
					addr = ipaddress.ip_address(part)
					if addr.version == 4:
						ipv4 = part
						break
					elif addr.version == 6 and not ipv6:
						ipv6 = part
				except Exception:
					continue
		e['ip_display'] = ipv4 if ipv4 else ip
		e['ip_v6'] = ipv6 if ipv6 else (ip if ':' in ip else '')
		geo = get_geo(ip)
		if geo:
			e['country'] = geo.get('country')
			e['latitude'] = geo.get('latitude')
			e['longitude'] = geo.get('longitude')
	return jsonify({
		'totalEvents': total_events,
		'last24h': last24h_count,
		'topIPs': top_ips,
		'topPorts': top_ports,
		'recentEvents': recent_events,
		'geoIPs': geo_ips
	})

if __name__ == "__main__":
	DATA_DIR.mkdir(exist_ok=True)
	GEO_CACHE_FILE = DATA_DIR / "geo_cache.json"
	if not EVENTS_FILE.exists():
		with EVENTS_FILE.open('w') as f:
			json.dump([], f)
	load_geo_cache()
	start_trap_listeners()
	app.run(host="0.0.0.0", port=5000, debug=True)
