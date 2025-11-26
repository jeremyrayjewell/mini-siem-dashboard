// Chart.js chart objects
let eventsOverTimeChart, topIPsChart, protocolChart;
let geoMap, geoMarkers = [];

// Simple in-memory cache for IP geolocation
const ipGeoCache = {};

async function fetchGeo(ip) {
    // No longer used. All geo lookups are done in the backend.
    return null;
}

async function buildGeoMarkers(events) {
    // Use geoIPs from backend for map markers
    const markers = [];
    if (window.latestGeoIPs && Array.isArray(window.latestGeoIPs)) {
        window.latestGeoIPs.forEach(entry => {
            const ip = entry.ip;
            const lat = entry.lat;
            const lon = entry.lon;
            const country = entry.country;
            const count = entry.count;
            if (lat != null && lon != null) {
                const popup = `<strong>IP:</strong> ${ip}<br>` +
                    (country ? `<strong>Country:</strong> ${country}<br>` : "<span style='color:#e11d48'>Unknown location</span><br>") +
                    `<strong>Events:</strong> ${count}`;
                markers.push({
                    lat,
                    lng: lon,
                    popup
                });
            }
        });
    }
    return markers;
}

function groupEventsByMinute(events) {
    // Group events by minute (UTC)
    const buckets = {};
    events.forEach(ev => {
        if (!ev.timestamp) return;
        const d = new Date(ev.timestamp);
        const key = d.getUTCFullYear() + '-' + (d.getUTCMonth()+1).toString().padStart(2,'0') + '-' + d.getUTCDate().toString().padStart(2,'0') + ' ' + d.getUTCHours().toString().padStart(2,'0') + ':' + d.getUTCMinutes().toString().padStart(2,'0');
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


function updateEventsOverTimeChart(events) {
    const { labels, data } = groupEventsByMinute(events);
    if (!eventsOverTimeChart) {
        const ctx = document.getElementById('eventsOverTimeChart').getContext('2d');
        eventsOverTimeChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Events',
                    data,
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37,99,235,0.1)',
                    fill: true,
                    tension: 0.2
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { x: { title: { display: true, text: 'Time (UTC)' } }, y: { title: { display: true, text: 'Events' }, beginAtZero: true } }
            }
        });
    } else {
        eventsOverTimeChart.data.labels = labels;
        eventsOverTimeChart.data.datasets[0].data = data;
        eventsOverTimeChart.update();
    }
    if (labels.length === 0) {
        document.getElementById('eventsOverTimeChart').parentElement.innerHTML = '<div style="padding:2em;text-align:center;color:#888;">No data yet</div>';
    }
}

function updateTopIPsChart(topIPs) {
    const labels = topIPs.slice(0,10).map(ip => ip.ip);
    const data = topIPs.slice(0,10).map(ip => ip.count);
    if (!topIPsChart) {
        const ctx = document.getElementById('topIPsChart').getContext('2d');
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
                scales: { x: { title: { display: true, text: 'Events' }, beginAtZero: true }, y: { title: { display: true, text: 'IP' } } }
            }
        });
    } else {
        topIPsChart.data.labels = labels;
        topIPsChart.data.datasets[0].data = data;
        topIPsChart.update();
    }
    if (labels.length === 0) {
        document.getElementById('topIPsChart').parentElement.innerHTML = '<div style="padding:2em;text-align:center;color:#888;">No data yet</div>';
    }
}

function updateProtocolChart(events) {
    const { labels, data } = groupEventsByProtocol(events);
    if (!protocolChart) {
        const ctx = document.getElementById('protocolChart').getContext('2d');
        protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    label: 'Events',
                    data,
                    backgroundColor: ['#2563eb','#22d3ee','#f59e42','#f43f5e','#10b981','#a78bfa','#fbbf24','#eab308']
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
        document.getElementById('protocolChart').parentElement.innerHTML = '<div style="padding:2em;text-align:center;color:#888;">No data yet</div>';
    }
}

async function updateGeoMap(events) {
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
    const markers = await buildGeoMarkers(events);
    // Always show the map, even if there are no markers
    if (markers.length > 0) {
        markers.forEach(m => {
            const marker = L.marker([m.lat, m.lng]).addTo(geoMap);
            marker.bindPopup(m.popup);
            geoMarkers.push(marker);
        });
    }
}

async function fetchStats() {
    try {
        // Always use Fly.io API for stats
        const apiUrl = 'https://backend-weathered-voice-4887.fly.dev/api/stats';
        const response = await fetch(apiUrl);
        if (!response.ok) return;
        const data = await response.json();
        document.getElementById('totalEvents').textContent = data.totalEvents ?? '0';
        document.getElementById('last24h').textContent = data.last24h ?? '0';
        // Top IPs Table
        let ipRows = '';
        (data.topIPs ?? []).forEach(ip => {
            ipRows += `<tr><td>${ip.ip ?? ''}</td><td>${ip.count ?? ''}</td></tr>`;
        });
        document.querySelector('#topIPs tbody').innerHTML = ipRows;
        // Top Ports Table
        let portRows = '';
        (data.topPorts ?? []).forEach(port => {
            portRows += `<tr><td>${port.port ?? ''}</td><td>${port.count ?? ''}</td></tr>`;
        });
        document.querySelector('#topPorts tbody').innerHTML = portRows;
        // Recent Events Table
        let eventRows = '';
        (data.recentEvents ?? []).forEach(ev => {
            // Tag private/internal/external IPs
            let ipClass = 'ip-external', ipLabel = '';
            const ip = ev.ip_display ?? ev.ip ?? '';
            if (/^127\./.test(ip)) { ipClass = 'ip-internal'; ipLabel = ' <span style="color:#64748b;font-size:0.9em">(internal)</span>'; }
            else if (/^192\.168\./.test(ip)) { ipClass = 'ip-internal'; ipLabel = ' <span style="color:#64748b;font-size:0.9em">(LAN)</span>'; }
            else if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) { ipClass = 'ip-internal'; ipLabel = ' <span style="color:#64748b;font-size:0.9em">(Fly internal)</span>'; }

            // Synthesize message
            let msg = '';
            if (ev.protocol === "HTTP") {
                msg = `HTTP ${ev.method || ""} ${ev.path || ""} from ${ip}`;
            } else {
                msg = `Connection from ${ip}${ev.src_port ? ":" + ev.src_port : ""} via ${ev.protocol}`;
            }

            eventRows += `<tr>
                <td>${ev.timestamp ?? ''}</td>
                <td class="${ipClass}">${ip}${ipLabel}</td>
                <td>${ev.port ?? ''}</td>
                <td>${ev.src_port ?? ''}</td>
                <td><span class="event-badge">${ev.protocol ?? ''}</span></td>
                <td><span class="event-badge">${ev.event_type ?? ''}</span></td>
                <td>${msg}</td>
                <td>${ev.user_agent ?? ''}</td>
                <td>${typeof ev.banner_sent === 'boolean' ? String(ev.banner_sent) : ''}</td>
            </tr>`;
        });
        document.querySelector('#recentEvents tbody').innerHTML = eventRows;

        // Save geoIPs for map rendering
        window.latestGeoIPs = data.geoIPs || [];

        // Update analytics visuals
        updateEventsOverTimeChart(data.recentEvents ?? []);
        updateTopIPsChart(data.topIPs ?? []);
        updateProtocolChart(data.recentEvents ?? []);
        await updateGeoMap(data.recentEvents ?? []);
    } catch (err) {
        // Silent fail for now
    }
}
fetchStats();
setInterval(fetchStats, 5000);