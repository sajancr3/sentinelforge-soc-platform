FROM python:3.10-slim

LABEL maintainer="Sajan Raju"
LABEL description="SentinelForge SOC Platform"

WORKDIR /app

# Install iptables (needed by live_monitor for auto-block)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (DB and secrets excluded via .dockerignore)
COPY . .

# Ensure data and samples directories exist
RUN mkdir -p samples data

# Default command (overridden per service in docker-compose.yml)
CMD ["python3", "dashboard.py"]
