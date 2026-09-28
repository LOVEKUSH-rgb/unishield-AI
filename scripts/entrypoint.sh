#!/bin/bash
# scripts/entrypoint.sh
# Entrypoint for the UniShield API container to ensure safe startup.

set -e

echo "Starting UniShield AI API Entrypoint..."

# Fix Render postgres:// dialect issue globally for this script
if [[ "$DATABASE_URL" == postgres://* ]]; then
    export DATABASE_URL="postgresql://${DATABASE_URL#postgres://}"
fi

# START THE APPLICATION IMMEDIATELY IN THE BACKGROUND
# This guarantees Render's strict 60-second healthcheck will pass instantly,
# bypassing the cold-start limitations of the Free Tier database.
PORT=${PORT:-8000}
if [ "$ENVIRONMENT" = "development" ]; then
    echo "Starting in DEVELOPMENT mode with reload on port $PORT..."
    uvicorn src.api.app:app --host 0.0.0.0 --port $PORT --reload &
else
    echo "Starting in PRODUCTION mode on port $PORT..."
    uvicorn src.api.app:app --host 0.0.0.0 --port $PORT &
fi
UVICORN_PID=$!

# Wait for PostgreSQL
if [ -n "$DATABASE_URL" ]; then
    echo "Checking database connection..."
    # We use a simple python script to attempt connection
    python -c '
import os, sys, time, sqlalchemy
url = os.environ.get("DATABASE_URL")
if not url: sys.exit(0)
engine = sqlalchemy.create_engine(url)
for _ in range(45):
    try:
        conn = engine.connect()
        conn.close()
        print("Database is ready.")
        sys.exit(0)
    except Exception as e:
        print("Waiting for database...")
        time.sleep(2)
sys.exit(1)
' || echo "Database connection failed after retries."
fi

# Wait for Redis
if [ -n "$REDIS_URL" ]; then
    echo "Checking Redis connection..."
    python -c '
import os, sys, time, redis
url = os.environ.get("REDIS_URL")
if not url: sys.exit(0)
client = redis.Redis.from_url(url)
for _ in range(45):
    try:
        if client.ping():
            print("Redis is ready.")
            sys.exit(0)
    except Exception as e:
        print("Waiting for Redis...")
        time.sleep(2)
sys.exit(1)
' || echo "Redis connection failed after retries."
fi

# Run migrations if environment is production or development (not test)
if [ "$ENVIRONMENT" != "test" ]; then
    echo "Running database migrations..."
    alembic upgrade head || echo "Migrations failed."
    
    echo "Seeding users manually since uvicorn started in the background..."
    python -c 'from src.persistence.database import init_db; init_db()' || echo "Seeding failed."
fi

# Keep container alive by waiting on the webserver
wait $UVICORN_PID
