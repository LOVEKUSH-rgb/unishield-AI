#!/bin/bash
# scripts/deploy.sh
# UniShield AI Production Deployment Script

set -e

echo "=========================================="
echo " UniShield AI - Deployment "
echo "=========================================="

if [ ! -f ".env" ]; then
    echo "ERROR: .env file missing. Please copy .env.example to .env and configure secrets."
    exit 1
fi

source .env

if [ -z "$JWT_SECRET_KEY" ]; then
    echo "ERROR: JWT_SECRET_KEY is missing in .env."
    exit 1
fi

if [ "$ENVIRONMENT" != "production" ]; then
    echo "WARNING: ENVIRONMENT is set to '$ENVIRONMENT'. This script is intended for 'production'."
    echo "Press Enter to continue, or Ctrl+C to abort."
    read -r
fi

echo "Building Docker images..."
docker compose -f docker-compose.prod.yml build

echo "Starting deployment..."
docker compose -f docker-compose.prod.yml up -d

echo "Waiting for services to become healthy..."
# We wait for API which depends on Postgres/Redis health
for i in {1..30}; do
    if curl -s http://localhost:8000/health | grep -q '"status":"healthy"'; then
        echo "API is healthy!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: API did not become healthy in time."
        docker compose -f docker-compose.prod.yml logs
        exit 1
    fi
    sleep 2
done

echo "Checking Dashboard..."
if curl -s http://localhost:8501/_stcore/health | grep -q "ok"; then
    echo "Dashboard is healthy!"
else
    echo "WARNING: Dashboard did not return healthy status immediately. Please check."
fi

echo "Deployment completed successfully!"
echo "API running at http://localhost:8000"
echo "Dashboard running at http://localhost:8501"
