# Mini SIEM Dashboard

A simple honeypot and mini-SIEM written in Python (Flask) with a modern JavaScript dashboard. It logs connection events from fake TCP services and displays analytics in a responsive web UI. It is designed for home-lab and research use, and can be exposed to the internet as a small, focused honeypot — but it is **not** a full-featured enterprise SIEM.

## Features

- Honeypot listeners for SSH, FTP, RDP, MySQL, Redis, MongoDB (high ports)
- Logs connection events to `data/events.json` (max 10,000 events)
- Enriched event schema:
  - `timestamp`, `ip`, `port`, `protocol`, `event_type`, `src_port`, `banner_sent`, `user_agent`, `message`
- Flask backend exposes `/api/stats` for dashboard polling
- Dashboard UI with:
  - 2×2 grid of analytics:
    - Geo-IP map (Leaflet)
    - Events Over Time (Chart.js)
    - Top IPs (Chart.js)
    - Events by Protocol (Chart.js)
  - Recent Events table
  - Top IPs and Top Ports tables
  - Responsive, compact layout
- Client-side IP geolocation (`ip-api.com`) for map markers

## Requirements

- Python 3.8+
- Flask (and Python standard library beyond that)
- Windows (tested); should work on Linux/Mac with minor tweaks
- Internet access for:
  - Client-side IP geolocation (ip-api.com)
  - Map tiles (OpenStreetMap via Leaflet)

## Setup

1. **Clone the repository:**

    git clone https://github.com/jeremyrayjewell/mini-siem-dashboard.git
    cd mini-siem-dashboard

2. **Create and activate a virtual environment (optional but recommended):**

   Windows (PowerShell):

    python -m venv venv
    .\venv\Scripts\Activate.ps1

   Linux / Mac:

    python3 -m venv venv
    source venv/bin/activate

3. **Install dependencies:**

   If you have a `requirements.txt`:

    pip install -r requirements.txt

   Or install Flask directly:

    pip install flask

4. **Run the app:**

    python -m backend.app

   The dashboard will be available at:  
   http://localhost:5000

## Quick Test

Once the app is running:

- Open this URL in your browser:
  - http://localhost:5000/wp-login.php
- Or use `curl`:

    curl http://localhost:5000/wp-login.php

Then refresh the dashboard in your browser. You should see:

- New events in the **Recent Events** table
- Updates in the **Top IPs**, **Top Ports**, and chart panels

## Usage

- The dashboard auto-refreshes every 5 seconds.
- Events are logged from both:
  - Honeypot TCP listeners (SSH/FTP/RDP/MySQL/Redis/MongoDB on high ports)
  - HTTP requests (excluding dashboard polling)
- The Geo-IP map shows markers for **public IPs only**:
  - Local/private IPs (e.g., `127.0.0.1`, `192.168.x.x`) are not geolocated.
- To reset all events, send a POST request:

    curl -X POST http://localhost:5000/admin/reset-events

### Internet-facing use

This project is suitable for deployment as a small internet-facing honeypot in a home-lab or research environment. If you expose it publicly:

- Run it in an **isolated** environment (separate from production systems and sensitive data).
- Treat all incoming traffic as potentially hostile.
- Do not reuse any secrets, credentials, or keys from other environments.

## Architecture

- **Honeypot traps**
  - Python socket listeners on high ports for SSH, FTP, RDP, MySQL, Redis, and MongoDB.
  - Each connection generates a JSON event appended to `data/events.json` (up to 10,000 events).

- **Flask backend**
  - Serves the static dashboard (HTML/CSS/JS).
  - Exposes `/api/stats` which returns:
    - Aggregated counts (total events, last 24 hours, top IPs, top ports)
    - Recent events with enriched fields (IP, protocol, port, banner_sent, etc.).

- **Frontend dashboard**
  - Single-page UI using:
    - Chart.js for:
      - Events Over Time (line chart)
      - Top IPs (bar chart)
      - Events by Protocol (donut/pie chart)
    - Leaflet + OpenStreetMap for:
      - Geo-IP map of source IPs (markers sized or grouped by event count)
  - Periodically polls `/api/stats` to update tables and charts.

## Troubleshooting

- **Map shows "no geo data available yet"**
  - Ensure you have events from **public IPs**.
  - Local/private IPs are intentionally skipped for geolocation.
  - Confirm that the browser has internet access (needed for ip-api.com and map tiles).

- **Ports fail to bind**
  - Check that:
    - The ports are not already in use.
    - You have permission to bind to those ports on your OS.
  - You can change the port numbers in `backend/traps.py`.

- **No events are appearing**
  - Verify the app is running and `data/events.json` is being updated.
  - Make test requests (see **Quick Test** section).
  - Check the terminal output for any Python exceptions.

- **Client-side geolocation not working**
  - Verify internet connectivity from the browser.
  - Ensure that calls to `ip-api.com` are not blocked by a firewall or browser extensions.

## License

MIT

---

## Author: **Jeremy Ray Jewell**

[GitHub](https://github.com/jeremyrayjewell)  
[LinkedIn](https://www.linkedin.com/in/jeremyrayjewell)  