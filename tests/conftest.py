"""
UniShield AI — pytest configuration and shared fixtures.

Fixtures defined here are available to all tests without import.
"""

import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path so that `src.*` imports work
# regardless of where pytest is invoked from.
PROJECT_ROOT = Path(__file__).parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the absolute path to the project root directory."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def config_dir(project_root: Path) -> Path:
    """Return the path to the config/ directory."""
    return project_root / "config"


@pytest.fixture(scope="session")
def data_dir(project_root: Path) -> Path:
    """Return the path to the data/ directory."""
    return project_root / "data"

# Mock Authentication for all tests
from src.api.app import app
from src.api.auth import get_current_user
from src.persistence.models import User

def override_get_current_user():
    return User(username="test_admin", role="admin", active=True)

app.dependency_overrides[get_current_user] = override_get_current_user
