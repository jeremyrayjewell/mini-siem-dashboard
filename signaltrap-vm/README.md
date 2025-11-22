# SignalTrap

A network monitoring server for tracking traffic patterns.

## Features

- **Persistent logs** - Attack logs saved to `/data/attacks.json`, survive restarts
- **Auto-rotation** - Logs older than 7 days automatically deleted
- **24/7 operation** - Runs continuously on Fly.io free tier

## Deployment

Deploy to Fly.io:

```bash
fly launch --name signaltrap --region iad
fly deploy
```

## Monitoring Usage

To avoid exceeding Fly.io free tier (160GB/month bandwidth):

```bash
# Check current usage
fly dashboard

# View metrics
fly status -a signaltrap

# Stop machine if needed
fly machine stop -a signaltrap

# Restart machine
fly machine start -a signaltrap
```

Set up billing alerts at: https://fly.io/dashboard/personal/billing

## Configuration

Edit in `server.py`:
- `LOG_RETENTION_DAYS = 7` - How long to keep logs
- `MAX_LOGS = 10000` - Maximum number of logs in memory

## Local Testing

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python server.py
```
