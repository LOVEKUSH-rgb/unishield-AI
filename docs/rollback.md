# UniShield AI Rollback Strategy

## 1. Overview
This document describes the rollback strategy if a deployment to production fails or introduces critical bugs.

## 2. Docker Image Rollback
If the application image is flawed (e.g. bad dependency, broken endpoint) but no database migration occurred:
1. Revert the Git commit locally to the previous stable release.
2. Re-run `bash scripts/deploy.sh` to rebuild the image and redeploy.
3. Verify via `/health`.

## 3. Database Migration Rollback (CAUTION)
**WARNING:** DO NOT implement automatic database rollback in deployment scripts. Alembic down-revisions can drop columns and delete data permanently. 
Prefer forward-compatible database changes (e.g. adding nullable columns instead of renaming/deleting).

If a migration must be reverted:
1. Ensure you have a logical backup (`bash scripts/backup_db.sh`) from *before* the bad migration.
2. Manually execute Alembic downgrade inside the API container:
   ```bash
   docker exec -it unishield-api alembic downgrade -1
   ```
3. If the database schema is irrecoverably corrupted:
   - Bring down the stack: `docker compose -f docker-compose.prod.yml down -v`
   - Bring up the stack with a fresh volume.
   - Restore from the backup (see `docs/deployment.md`).

## 4. Redis Considerations
Redis contains ephemeral state (flow session tables). 
If a rollback requires clearing Redis:
```bash
docker exec -it unishield-redis redis-cli -a <PASSWORD> flushall
```
This is safe. Active sessions will be re-established on next packet/log, but partial session state might be lost.

## 5. Configuration Rollback
If `.env` settings were bad (e.g. typo in JWT secret causing mass logouts):
1. Correct the `.env` file.
2. Restart the API: `docker compose -f docker-compose.prod.yml restart unishield-api`
