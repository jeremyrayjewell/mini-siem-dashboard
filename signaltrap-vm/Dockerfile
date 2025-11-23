FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY honeypot.py .
COPY start.sh .

# Make start script executable
RUN chmod +x start.sh

# Expose all ports
EXPOSE 8080 22 21 23 3306 5432 6379 27017 3389

# Run the startup script
CMD ["./start.sh"]
