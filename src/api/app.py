"""
UniShield AI -- FastAPI Backend (Phase 23)
==========================================
Exposes the Replay Manager and Incident State to the Dashboard with Authentication.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import uvicorn
from typing import List, Dict, Any, Optional
from datetime import timedelta
from pathlib import Path
import os

from sqlalchemy.orm import Session
from src.persistence.database import SessionLocal, get_db, init_db
from src.persistence.repositories import IncidentRepository, AlertRepository
from src.persistence.redis_client import get_redis
from src.api.replay_manager import manager
from src.utils.config import settings

# Auth imports
from src.api.auth import (
    verify_password, create_access_token, get_current_user,
    require_viewer, require_analyst, require_admin
)
from src.persistence.models import User

app = FastAPI(title="UniShield AI SOC API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import time
from src.utils.prometheus_metrics import HTTP_REQUESTS_TOTAL, HTTP_REQUEST_ERRORS_TOTAL, HTTP_REQUEST_LATENCY_SECONDS

class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method = request.method
        # Avoid high cardinality by grouping paths or using route templates if possible.
        # For simplicity and given the fixed API surface, we use request.url.path
        # But we strip out UUIDs or IDs.
        path = request.url.path
        
        # Simple path generalization for alerts/incidents
        if path.startswith("/alerts/") and len(path.split("/")) > 2:
            path = "/alerts/{id}"
        elif path.startswith("/incidents/") and len(path.split("/")) > 2:
            path = "/incidents/{id}"
            
        start_time = time.time()
        
        try:
            response = await call_next(request)
            status_code = response.status_code
            HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=path, status_code=status_code).inc()
            if status_code >= 500:
                HTTP_REQUEST_ERRORS_TOTAL.labels(method=method, endpoint=path).inc()
        except Exception as e:
            HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=path, status_code=500).inc()
            HTTP_REQUEST_ERRORS_TOTAL.labels(method=method, endpoint=path).inc()
            raise e
        finally:
            latency = time.time() - start_time
            HTTP_REQUEST_LATENCY_SECONDS.labels(method=method, endpoint=path).observe(latency)
            
        return response

app.add_middleware(PrometheusMiddleware)


@app.on_event("startup")
def startup_event():
    # Initialize DB and seed users if necessary
    init_db()
    # Attempt to ping redis and pg, but don't crash if they aren't up yet
    try:
        redis = get_redis()
        redis.ping()
    except Exception:
        pass

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.active:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    access_token_expires = timedelta(minutes=settings.jwt_access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

from fastapi.responses import Response

@app.get("/health/live")
def health_live():
    # Unprotected liveness endpoint
    return {"status": "healthy", "api": "healthy"}

@app.get("/seed_debug")
def seed_debug():
    try:
        from src.persistence.database import SessionLocal
        from src.persistence.models import User
        from src.api.auth import get_password_hash
        db = SessionLocal()
        users_added = []
        for role, username in [("admin", "admin"), ("analyst", "analyst"), ("viewer", "viewer")]:
            existing = db.query(User).filter(User.username == username).first()
            if not existing:
                user = User(username=username, password_hash=get_password_hash("changeme"), role=role)
                db.add(user)
                users_added.append(username)
        db.commit()
        
        # Verify
        count = db.query(User).count()
        return {"status": "success", "users_added": users_added, "total_users": count}
    except Exception as e:
        import traceback
        return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}

@app.get("/health/ready")
def health_ready(db: Session = Depends(get_db)):
    status_dict = {"status": "healthy", "postgres": "healthy", "redis": "healthy", "models": "healthy"}
    
    # Check DB
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
    except Exception:
        status_dict["postgres"] = "unhealthy"
        status_dict["status"] = "degraded"
        
    # Check Redis
    try:
        redis = get_redis()
        redis.ping()
    except Exception:
        status_dict["redis"] = "unhealthy"
        status_dict["status"] = "degraded"
        
    # Check Models
    try:
        from src.models.registry import registry
        for m, stats in registry.get_all_models_status().items():
            if stats.get("status") == "INVALID":
                status_dict["models"] = "degraded"
                status_dict["status"] = "degraded"
                break
    except Exception:
        pass
        
    status_code = 200 if status_dict["status"] == "healthy" else 503
    return Response(content=__import__('json').dumps(status_dict), status_code=status_code, media_type="application/json")

@app.get("/health")
def health_check():
    # Legacy fallback
    return health_live()

@app.get("/metrics")
def get_metrics():
    # Prometheus exposition
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/statistics", dependencies=[Depends(require_viewer)])
def get_statistics():
    # Legacy metrics payload
    return manager.state_mgr.get_state()

@app.get("/threats", dependencies=[Depends(require_viewer)])
def get_threats():
    return manager.state_mgr.get_threats()

@app.get("/incidents", dependencies=[Depends(require_viewer)])
def get_incidents(
    source_ip: Optional[str] = None, 
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    if not db:
        return []
    repo = IncidentRepository(db)
    incs = repo.get_active(source_ip=source_ip)
    incs.sort(key=lambda x: x.risk_score, reverse=True)
    return [i.to_dict() for i in incs[offset:offset+limit]]

@app.get("/incidents/{incident_id}", dependencies=[Depends(require_viewer)])
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    repo = IncidentRepository(db)
    inc = repo.get_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc.to_dict()

@app.get("/alerts", dependencies=[Depends(require_viewer)])
def get_alerts(
    limit: int = 50, 
    offset: int = 0,
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    threat_class: Optional[str] = None,
    db: Session = Depends(get_db)
):
    if not db:
        return []
    repo = AlertRepository(db)
    alerts = repo.get_recent(limit=limit, offset=offset, source_ip=source_ip, severity=severity, threat_class=threat_class)
    return [a.to_dict() for a in alerts]

@app.get("/analytics/detectors", dependencies=[Depends(require_viewer)])
def get_detector_analytics(db: Session = Depends(get_db)):
    if not db:
        return []
    repo = AlertRepository(db)
    return repo.get_detector_stats()

@app.get("/models", dependencies=[Depends(require_viewer)])
def get_models():
    try:
        from src.models.registry import registry
        return registry.get_all_models_status()
    except Exception as e:
        return {"error": str(e)}

# --- REPLAY CONTROLS ---

class ReplayLoadRequest(BaseModel):
    pcap_path: str = "data/samples/demo_scenario.pcap"

class ZeekLoadRequest(BaseModel):
    zeek_dir: str = "data/samples/zeek_logs"

class ReplaySpeedRequest(BaseModel):
    speed: float

def validate_safe_path(target_path: str, base_dir: str = "data") -> Path:
    base_path = Path(base_dir).resolve()
    requested_path = Path(target_path).resolve()
    if not str(requested_path).startswith(str(base_path)):
        raise HTTPException(status_code=403, detail="Path Traversal Attempt Detected")
    if not requested_path.exists():
        raise HTTPException(status_code=404, detail="File or directory not found")
    return requested_path

@app.post("/replay/load", dependencies=[Depends(require_admin)])
def load_replay(req: ReplayLoadRequest):
    safe_path = validate_safe_path(req.pcap_path)
    manager.load_pcap(str(safe_path))
    return {"status": "loaded", "pcap": str(safe_path)}

@app.post("/ingest/zeek", dependencies=[Depends(require_admin)])
def load_zeek(req: ZeekLoadRequest):
    safe_path = validate_safe_path(req.zeek_dir)
    manager.load_zeek(str(safe_path))
    return {"status": "loaded", "zeek_dir": str(safe_path)}

@app.post("/replay/play", dependencies=[Depends(require_admin)])
def play_replay():
    manager.play()
    return {"status": "playing"}

@app.post("/replay/pause", dependencies=[Depends(require_admin)])
def pause_replay():
    manager.pause()
    return {"status": "paused"}

@app.post("/replay/stop", dependencies=[Depends(require_admin)])
def stop_replay():
    manager.stop()
    return {"status": "stopped"}
    
@app.post("/replay/reset", dependencies=[Depends(require_admin)])
def reset_replay():
    manager.reset()
    return {"status": "reset"}

@app.post("/replay/speed", dependencies=[Depends(require_admin)])
def set_replay_speed(req: ReplaySpeedRequest):
    manager.set_speed(req.speed)
    return {"status": "speed_updated", "speed": req.speed}

@app.get("/evaluation/status", dependencies=[Depends(require_viewer)])
def get_evaluation_status():
    status_file = Path("reports/phase32/phase31_vs_phase32.json")
    if not status_file.exists():
        return {"status": "Not Evaluated", "message": "Benchmark has not been run."}
    
    try:
        import json
        with open(status_file, "r") as f:
            data = json.load(f)
        
        # Determine overall coverage
        detectors_evaluated = len(data)
        
        return {
            "status": "Evaluated",
            "detectors_covered": detectors_evaluated,
            "last_benchmark": os.path.getmtime(status_file),
            "results": data
        }
    except Exception as e:
        return {"status": "Error", "message": str(e)}



if __name__ == "__main__":
    uvicorn.run("src.api.app:app", host="0.0.0.0", port=8000, reload=True)
