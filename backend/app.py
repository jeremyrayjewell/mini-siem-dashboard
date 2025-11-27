// === CONFIG: point frontend to Fly backend ===
const API_BASE = 'https://backend-weathered-voice-4887.fly.dev';

// Chart.js chart objects
let eventsOverTimeChart, topIPsChart, protocolChart;
let geoMap, geoMarkers = [];

// Simple in-memory cache for IP geolocation (not used now, kept for future)
const ipGeoCache = {};

async function fetchGeo(ip) {
    // No longer used. All geo lookups are done in the backend.
    return null;
}

// ---------- Geo / map helpers ----------

async function buildGeoMarkers() {
    // Use geoPoints/geoIPs from backend for map markers
    const markers = [];
    if (window.latestGeoIPs && Array.isArray(window.latestGeoIPs)) {
        window.latestGeoIPs.forEach(entry => {
            const ip = entry.ip;
            // Be tolerant of different backend key names
            const lat =
                entry.lat ??
                entry.latitude ??
                null;
            const lng =
                entry.lng ??
                entry.lon ??
                entry.longitude ??
                null;
            const country = entry.country;
            const count = entry.count;

            if (lat != null && lng != null) {
                const popup = `<strong>IP:</strong> ${ip}<br>` +
                    (country
                        ? `<strong>Country:</strong> ${country}<br>`
                        : "<span style='color:#e11d48'>Unknown location</span><br>") +
                    `<strong>Events:</strong> ${count}`;
                markers.push({ lat, lng, popup });
            }
        });
    }
    return markers;
}

// ---------- Aggregation helpers ----------

function groupEventsByMinute(events) {
    // Group events by minute (UTC)
    const buckets = {};
    events.forEach(ev => {
        if (!ev.timestamp) return;
        const d = new Date(ev.timestamp);
        if (Number.isNaN(d.getTime())) return;
        const key =
            d.getUTCFullYear() + '-' +
            String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
            String(d.getUTCDate()).padStart(2, '0') + ' ' +
            String(d.getUTCHours()).padStart(2, '0') + ':' +
            String(d.getUTCMinutes()).padStart(2, '0');
        buckets[key] = (buckets[key] || 0) + 1;
    });
    const labels = Object.keys(buckets).sort();
    const data = labels.map(l => buckets[l]);
    return { labels, data };
}

function groupEventsByProtocol(events) {
    const counts = {};
    events.forEach(ev => {
        const proto = ev.protocol || "Unknown";
        counts[proto] = (counts[proto] || 0) + 1;
    });
    const labels = Object.keys(counts);
    const data = labels.map(l => counts[l]);
    return { labels, data };
}

// ---------- Chart updaters ----------

function updateEventsOverTimeChart(events) {
    const { labels, data } = groupEventsByMinute(events);
    const canvas = document.getElementById('eventsOverTimeChart');
    if (!canvas) return;

    if (!eventsOverTimeChart) {
        const ctx = canvas.getContext('2d');
        eventsOverTimeChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Events',
                    data,
                    borderColor: '#22d3ee',
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { title: { display: true, text: 'Time (UTC)' } },
                    y: { title: { display: true, text: 'Events' }, beginAtZero: true, ticks: { precision: 0 } }
                }
            }
        });
    } else {
        eventsOverTimeChart.data.labels = labels;
        eventsOverTimeChart.data.datasets[0].data = data;
        eventsOverTimeChart.update();
    }

    if (labels.length === 0) {
        canvas.parentElement.innerHTML =
            '<div style="padding:2em;text-align:center;color:#888;">No data yet</div>';
    }
}

function updateTopIPsChart(topIPs) {
    const canvas = document.getElementById('topIPsChart');
    if (!canvas) return;

    const labels = topIPs.map(ip => ip.ip || '');
    const data = topIPs.map(ip => ip.count || 0);

    if (!topIPsChart) {
        const ctx = canvas.getContext('2d');
        topIPsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Events',
                    data,
                    backgroundColor: '#22d3ee'
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 } },
                    y: { ticks: { autoSkip: false } }
                }
            }
        });
    } else {
        topIPsChart.data.labels = labels;
        topIPsChart.data.datasets[0].data = data;
        topIPsChart.update();
    }

    if (labels.length === 0) {
        canvas.parentElement.innerHTML =
            '<div style="padding:2em;text-align:center;color:#888;">No IP data yet</div>';
    }
}

function updateProtocolChart(events) {
    const canvas = document.getElementById('protocolChart');
    if (!canvas) return;

    const { labels, data } = groupEventsByProtocol(events);

    if (!protocolChart) {
        const ctx = canvas.getContext('2d');
        protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    label: 'Events',
                    data,
                    backgroundColor: [
                        '#2563eb', '#22d3ee', '#f59e42', '#f43f5e',
                        '#10b981', '#a78bfa', '#fbbf24', '#eab308'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { position: 'bottom' } }
            }
        });
    } else {
        protocolChart.data.labels = labels;
        protocolChart.data.datasets[0].data = data;
        protocolChart.update();
    }

    if (labels.length === 0) {
        canvas.parentElement.innerHTML =
            '<div style="padding:2em;text-align:center;color:#888;">No protocol data yet</div>';
    }
}

// ---------- Map updater ----------

async function updateGeoMap() {
    const mapEl = document.getElementById('geoMap');
    if (!mapEl) return;

    if (!geoMap) {
        geoMap = L.map('geoMap').setView([0, 0], 1);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 18,
            attribution: '© OpenStreetMap'
        }).addTo(geoMap);
    }

    // Remove old markers
    geoMarkers.forEach(m => geoMap.removeLayer(m));
    geoMarkers = [];

    const markers = await buildGeoMarkers();
    if (markers.length > 0) {
        markers.forEach(m => {
            const marker = L.marker([m.lat, m.lng]).addTo(geoMap);
            marker.bindPopup(m.popup);
            geoMarkers.push(marker);
        });
    }
}

// ---------- Main stats fetch ----------

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        if (!response.ok) {
            console.error('Stats request failed:', response.status, response.statusText);
            return;
        }

        const data = await response.json();

        // High-level counters
        const totalEl = document.getElementById('totalEvents');
        const last24El = document.getElementById('last24h');
        if (totalEl) totalEl.textContent = data.totalEvents ?? '0';
        if (last24El) last24El.textContent = data.last24Hours ?? '0';

        // Top IPs table
        const topIPsBody = document.querySelector('#topIPs tbody');
        if (topIPsBody) {
            let ipRows = '';
            (data.topIPs ?? []).forEach(ip => {
                ipRows += `<tr><td>${ip.ip ?? ''}</td><td>${ip.count ?? ''}</td></tr>`;
            });
            topIPsBody.innerHTML = ipRows;
        }

        // Top ports table
        const topPortsBody = document.querySelector('#topPorts tbody');
        if (topPortsBody) {
            let portRows = '';
            (data.topPorts ?? []).forEach(port => {
                portRows += `<tr><td>${port.port ?? ''}</td><td>${port.count ?? ''}</td></tr>`;
            });
            topPortsBody.innerHTML = portRows;
        }

        // Recent events table
        const recentBody = document.querySelector('#recentEvents tbody');
        if (recentBody) {
            let eventRows = '';
            (data.recentEvents ?? []).forEach(ev => {
                // Tag private/internal/external IPs
                let ipClass = 'ip-external';
                let ipLabel = '';
                const ip = ev.ip_display ?? ev.ip ?? '';

                if (/^127\./.test(ip)) {
                    ipClass = 'ip-internal';
                    ipLabel = ' <span style="color:#64748b;font-size:0.9em">(internal)</span>';
                } else if (/^192\.168\./.test(ip) || /^10\./.test(ip) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) {
                    ipClass = 'ip-internal';
                    ipLabel = ' <span style="color:#64748b;font-size:0.9em">(LAN)</span>';
                } else if (/\(internal\)$/.test(ip) || /fly\.internal$/.test(ip)) {
                    ipClass = 'ip-internal';
                    ipLabel = ' <span style="color:#64748b;font-size:0.9em">(Fly internal)</span>';
                }

                // Synthesize message
                let msg = '';
                if (ev.protocol === 'HTTP') {
                    msg = `HTTP ${ev.method || ''} ${ev.path || ''} from ${ip}`;
                } else {
                    msg = `Connection from ${ip}${ev.src_port ? ':' + ev.src_port : ''} via ${ev.protocol}`;
                }

                eventRows += `<tr>
                    <td>${ev.timestamp ?? ''}</td>
                    <td class="${ipClass}">${ip}${ipLabel}</td>
                    <td>${ev.port ?? ''}</td>
                    <td>${ev.src_port ?? ''}</td>
                    <td>${ev.protocol ?? ''}</td>
                    <td>${ev.event_type ?? ''}</td>
                    <td>${msg}</td>
                    <td>${ev.user_agent ?? ''}</td>
                    <td>${typeof ev.banner_sent === 'boolean' ? String(ev.banner_sent) : ''}</td>
                </tr>`;
            });
            recentBody.innerHTML = eventRows;
        }

        // Geo-IP points from backend:
        // support both "geoPoints" (current) and "geoIPs" (older)
        window.latestGeoIPs = data.geoPoints || data.geoIPs || [];

        // Update visualizations
        updateEventsOverTimeChart(data.recentEvents ?? []);
        updateTopIPsChart(data.topIPs ?? []);
        updateProtocolChart(data.recentEvents ?? []);
        await updateGeoMap();
    } catch (err) {
        console.error('Error fetching stats:', err);
    }
}

// Initial fetch and polling
fetchStats();
setInterval(fetchStats, 5000);
