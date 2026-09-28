"""
UniShield AI — Config Loader
============================
Loads and merges config.yaml + thresholds.yaml.
Provides typed access to all configuration values,
and securely loads environment variables via pydantic-settings.
"""

from pathlib import Path
from typing import Any, Dict, Optional, List, Literal
import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

_CONFIG_PATH = Path(__file__).parents[2] / "config" / "config.yaml"
_THRESHOLDS_PATH = Path(__file__).parents[2] / "config" / "thresholds.yaml"
_RISK_PATH = Path(__file__).parents[2] / "config" / "risk.yaml"

from typing import Any, Dict, Optional, List, Literal

class Settings(BaseSettings):
    # Core Application Settings
    environment: Literal["development", "test", "production"] = Field(default="development", env="ENVIRONMENT")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # Database Settings
    postgres_user: Optional[str] = Field(default=None, env="POSTGRES_USER")
    postgres_password: Optional[str] = Field(default=None, env="POSTGRES_PASSWORD")
    postgres_db: Optional[str] = Field(default=None, env="POSTGRES_DB")
    postgres_host: Optional[str] = Field(default="localhost", env="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, env="POSTGRES_PORT")
    database_url: str = Field(default="sqlite:///./data/unishield.db", env="DATABASE_URL")
    
    # Redis Settings
    redis_host: Optional[str] = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    
    # Security Settings (JWT & Auth)
    jwt_secret_key: str = Field(..., env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(default=60, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    cors_allowed_origins: str = Field(default="http://localhost:8501", env="CORS_ALLOWED_ORIGINS")

    # ML Lifecycle Settings
    model_artifact_store: Literal["local"] = Field(default="local", env="MODEL_ARTIFACT_STORE")
    model_registry_path: str = Field(default="models/trained", env="MODEL_REGISTRY_PATH")
    model_sync_enabled: bool = Field(default=False, env="MODEL_SYNC_ENABLED")
    model_require_integrity: bool = Field(default=True, env="MODEL_REQUIRE_INTEGRITY")

    # Observability Settings
    prometheus_enabled: bool = Field(default=True, env="PROMETHEUS_ENABLED")
    prometheus_scrape_interval: str = Field(default="15s", env="PROMETHEUS_SCRAPE_INTERVAL")
    grafana_enabled: bool = Field(default=True, env="GRAFANA_ENABLED")
    observability_alerting_enabled: bool = Field(default=True, env="OBSERVABILITY_ALERTING_ENABLED")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

# Global settings instance
try:
    settings = Settings()
except Exception as e:
    import sys
    print(f"CRITICAL: Failed to load environment settings. Ensure all required secrets are provided. Error: {e}", file=sys.stderr)
    if "pytest" not in sys.modules:
        sys.exit(1)
    else:
        # Provide a dummy fallback for testing only
        settings = Settings(jwt_secret_key="test-secret")

_config_cache: Dict[str, Any] = {}
_thresholds_cache: Dict[str, Any] = {}
_risk_cache: Dict[str, Any] = {}


def get_config() -> Dict[str, Any]:
    global _config_cache
    if not _config_cache:
        with _CONFIG_PATH.open("r") as fh:
            _config_cache = yaml.safe_load(fh) or {}
    return _config_cache


def get_thresholds() -> Dict[str, Any]:
    global _thresholds_cache
    if not _thresholds_cache:
        with _THRESHOLDS_PATH.open("r") as fh:
            _thresholds_cache = yaml.safe_load(fh) or {}
    return _thresholds_cache

def get_risk_config() -> Dict[str, Any]:
    global _risk_cache
    if not _risk_cache:
        with _RISK_PATH.open("r") as fh:
            _risk_cache = yaml.safe_load(fh) or {}
    return _risk_cache


def reload_config() -> None:
    global _config_cache, _thresholds_cache, _risk_cache
    _config_cache = {}
    _thresholds_cache = {}
    _risk_cache = {}
