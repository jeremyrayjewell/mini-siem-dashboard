# SignalTrap

A network monitoring server for tracking traffic patterns.

## Deployment

Deploy to Fly.io:

```bash
fly launch --name signaltrap --region iad
fly deploy
```

## Local Testing

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python server.py
```
