# Use official Python image
FROM python:3.11-slim

WORKDIR /app

# Copy source code
COPY . /app

# Install dependencies (if you have requirements.txt, otherwise skip)
RUN pip install --no-cache-dir flask flask-cors requests

# Expose port (adjust if your app uses a different port)
EXPOSE 8080 21 22 5021 5022 3389 53389 3306 53306 6379 56379 27017 57017

# Run the app
CMD ["python", "app.py"]
