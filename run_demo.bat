@echo off
echo ============================================================
echo UniShield AI SOC - Golden Demo
echo ============================================================

REM Set PYTHONPATH
set PYTHONPATH=%CD%

echo [1/4] Running Database Migrations...
alembic upgrade head

echo [2/4] Starting Backend API (Uvicorn)...
start "UniShield API" cmd /c "python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000"

echo Waiting for API to start...
timeout /t 5 /nobreak > nul

echo [3/4] Starting Streamlit Dashboard...
start "UniShield Dashboard" cmd /c "python -m streamlit run dashboard/app.py --server.port 8501"

echo Waiting for Dashboard to start...
timeout /t 5 /nobreak > nul

echo [4/4] Triggering Traffic Replay...
python -u scripts/trigger_demo.py

echo.
echo ============================================================
echo Demo started! 
echo Dashboard: http://localhost:8501
echo API: http://localhost:8000
echo ============================================================
pause
