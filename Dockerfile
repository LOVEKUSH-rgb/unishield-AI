# UniShield AI — Dockerfile
# Phase 19: containerisation
# This is a stub. Full containerisation implemented in Phase 19.

FROM python:3.12-slim

LABEL maintainer="UniShield AI Team"
LABEL description="UniShield AI — Passive Network Threat Intelligence"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create a non-root user and change ownership
RUN groupadd -r unishield && useradd -r -g unishield unishield && \
    chown -R unishield:unishield /app

# Ensure entrypoint is executable
RUN chmod +x /app/scripts/entrypoint.sh

USER unishield

EXPOSE 8000

# Default: start API
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
