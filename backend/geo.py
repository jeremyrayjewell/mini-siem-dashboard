import requests
import json
from pathlib import Path
from threading import Lock

data_file = Path(__file__).resolve().parent / 'data' / 'geo_cache.json'
cache_lock = Lock()
API_URL = 'https://ip-api.com/json/{ip}?fields=status,country,lat,lon'

# Load or create cache
if not data_file.exists():
    data_file.parent.mkdir(exist_ok=True)
    with data_file.open('w') as f:
        json.dump({}, f)

def get_geo(ip):
    with cache_lock:
        with data_file.open('r') as f:
            cache = json.load(f)
        if ip in cache:
            return cache[ip]
    try:
        resp = requests.get(API_URL.format(ip=ip), timeout=3)
        data = resp.json()
        if data.get('status') == 'success':
            geo = {
                'country': data.get('country'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon')
            }
            with cache_lock:
                cache[ip] = geo
                with data_file.open('w') as f:
                    json.dump(cache, f)
            return geo
    except Exception:
        pass
    return None
