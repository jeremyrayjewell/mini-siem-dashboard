from flask import Flask, request, jsonify
from collections import deque, Counter
from datetime import datetime, timedelta

app = Flask(__name__)

# In-memory storage for events
MAX_EVENTS = 10000
events = deque(maxlen=MAX_EVENTS)

@app.route('/ingest', methods=['POST'])
def ingest_event():
    """Receive and store an event from the honeypot."""
    event = request.get_json()
    if not event or 'timestamp' not in event or 'src_ip' not in event:
        return jsonify({'error': 'Invalid event format'}), 400

    events.append(event)
    return jsonify({'status': 'success'}), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Aggregate and return stats in the required JSON shape."""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    # Filter events within the last 24 hours
    recent_events = [e for e in events if datetime.fromisoformat(e['timestamp']) > last_24h]

    # Aggregate stats
    total_attacks = len(events)
    last_24h_count = len(recent_events)

    # Top IPs
    ip_counter = Counter(e['src_ip'] for e in events)
    top_ips = [
        {
            'ip': ip,
            'count': count,
            'last_seen': max(e['timestamp'] for e in events if e['src_ip'] == ip)
        }
        for ip, count in ip_counter.most_common(10)
    ]

    # Top paths
    path_counter = Counter(e['path'] for e in events if 'path' in e)
    top_paths = [
        {'path': path, 'count': count}
        for path, count in path_counter.most_common(10)
    ]

    # Recent attacks
    recent_attacks = list(reversed(recent_events[-50:]))

    stats = {
        'totalAttacks': total_attacks,
        'last24h': last_24h_count,
        'topIPs': top_ips,
        'topPaths': top_paths,
        'recentAttacks': recent_attacks
    }

    return jsonify(stats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)