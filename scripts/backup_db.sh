#!/bin/bash
# scripts/backup_db.sh
# Creates a logical pg_dump from the running UniShield PostgreSQL container.

set -e

BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/unishield_db_${TIMESTAMP}.sql"

mkdir -p "$BACKUP_DIR"

if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found."
    exit 1
fi
source .env

# We extract the container name dynamically in case compose prefixes it differently
DB_CONTAINER=$(docker compose -f docker-compose.prod.yml ps -q postgres 2>/dev/null || docker compose ps -q postgres 2>/dev/null)

if [ -z "$DB_CONTAINER" ]; then
    echo "ERROR: PostgreSQL container is not running."
    exit 1
fi

echo "Starting database backup..."
docker exec -t "$DB_CONTAINER" pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB:-unishield}" > "$BACKUP_FILE"

echo "Backup successful: $BACKUP_FILE"
