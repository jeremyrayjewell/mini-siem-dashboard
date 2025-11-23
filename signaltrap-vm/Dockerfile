FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .

# Expose all ports
EXPOSE 8080 2222 2121 2323 3306 5432 6379 27017 3389

# Run gunicorn without config file
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "server:app"]
