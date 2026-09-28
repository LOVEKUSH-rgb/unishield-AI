import pytest
from fastapi.testclient import TestClient
from src.api.app import app
from src.api.auth import get_current_user, create_access_token
from src.persistence.models import User
import os

client = TestClient(app)

def test_health_check_unauthenticated():
    res = client.get("/health")
    assert res.status_code == 200

def test_protected_endpoint_without_token():
    # Remove the global override for this specific test
    app.dependency_overrides.pop(get_current_user, None)
    res = client.get("/alerts")
    assert res.status_code == 401
    
    # Restore the override
    def override_get_current_user():
        return User(username="test_admin", role="admin", active=True)
    app.dependency_overrides[get_current_user] = override_get_current_user

def test_rbac_viewer_cannot_play_replay():
    app.dependency_overrides.pop(get_current_user, None)
    def override_viewer():
        return User(username="viewer", role="viewer", active=True)
    app.dependency_overrides[get_current_user] = override_viewer
    
    res = client.post("/replay/play")
    assert res.status_code == 403 # Forbidden
    
    # Restore the override
    def override_get_current_user():
        return User(username="test_admin", role="admin", active=True)
    app.dependency_overrides[get_current_user] = override_get_current_user

def test_path_traversal_protection():
    app.dependency_overrides.pop(get_current_user, None)
    def override_admin():
        return User(username="admin", role="admin", active=True)
    app.dependency_overrides[get_current_user] = override_admin
    
    res = client.post("/replay/load", json={"pcap_path": "../../../../etc/passwd"})
    assert res.status_code == 403 # Path traversal detected
    
    # Restore the override
    def override_get_current_user():
        return User(username="test_admin", role="admin", active=True)
    app.dependency_overrides[get_current_user] = override_get_current_user
