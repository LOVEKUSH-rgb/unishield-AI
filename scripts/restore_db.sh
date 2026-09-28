#!/bin/bash
# scripts/restore_db.sh
# Restores a logical pg_dump into the running UniShield PostgreSQL container.

set -e

if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found."
    exit 1
fi
source .env

if [ -z "$1" ]; then
    echo "Usage: ./restore_db.sh <path_to_backup.sql>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file '$BACKUP_FILE' not found."
    exit 1
fi

# We extract the container name dynamically in case compose prefixes it differently
DB_CONTAINER=$(docker compose -f docker-compose.prod.yml ps -q postgres 2>/dev/null || docker compose ps -q postgres 2>/dev/null)

if [ -z "$DB_CONTAINER" ]; then
    echo "ERROR: PostgreSQL container is not running."
    exit 1
fi

echo "Starting database restore from $BACKUP_FILE..."
# Drop schema and recreate it to ensure a clean restore
docker exec -i "$DB_CONTAINER" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB:-unishield}" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
docker exec -i "$DB_CONTAINER" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB:-unishield}" < "$BACKUP_FILE"

echo "Restore successful!"
