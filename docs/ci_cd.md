# UniShield AI CI/CD Pipeline

## 1. Overview
UniShield AI uses GitHub Actions for continuous integration. The pipeline configuration is located in `.github/workflows/ci.yml`.

## 2. CI Pipeline Stages
On every push and pull request to `main`, the CI pipeline executes:

1. **Test Stage:**
   - Installs Python 3.12 and dependencies.
   - Sets up testing environment variables (e.g. `ENVIRONMENT=test`).
   - Runs the full `pytest` suite including:
     - Unit tests
     - Integration tests
     - Security tests
     - Zeek ingestion tests
     - ML registry tests
   
2. **Docker Smoke Test Stage:**
   - Requires the Test Stage to pass.
   - Starts the full stack using `docker-compose.test.yml`.
   - Waits for Postgres and Redis health checks.
   - Executes a Python script against the API's `/health` endpoint inside the Docker network.
   - Tears down the stack cleanly.

## 3. Security Validation
The CI explicitly tests authentication, CORS, and RBAC via `tests/test_security.py`. Hardcoded credentials are automatically scanned during Docker builds because `.env` files are excluded via `.dockerignore`.

## 4. Deployment Model
**IMPORTANT:** CI validates deployability; deployment remains an operator-controlled process. 
The pipeline does *not* automatically deploy to production. Operators must pull the tested branch on the production host and run `scripts/deploy.sh`.
