FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY listeners.py .
COPY gunicorn.conf.py .
COPY start.sh .
RUN chmod +x start.sh

# Expose all ports
EXPOSE 8080 2222 2121 2323 3306 5432 6379 27017 3389

# Run startup script
CMD ["./start.sh"]
