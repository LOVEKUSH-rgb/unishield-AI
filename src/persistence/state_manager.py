"""
UniShield AI -- State Manager
=============================
Provides high-level state management for metrics and configurations using Redis.
"""
import json
from typing import Dict, Any

from src.persistence.redis_client import get_redis
from src.utils.logging import get_logger

logger = get_logger(__name__)

class StateManager:
    def __init__(self):
        self.redis = get_redis()
        self._state_key = "unishield:replay:state"
        self._threats_key = "unishield:replay:threats"
        
        # Default state
        self._default_state = {
            "status": "STOPPED",
            "progress": 0.0,
            "speed": 1.0,
            "packets_processed": 0,
            "flows_processed": 0,
            "alerts_generated": 0,
            "incidents_generated": 0,
            "current_pcap": "data/samples/demo_six_threats.pcap",
            "mbps": 0.0,
            "flows_per_second": 0.0,
            "bytes_processed": 0,
            "latency_p50": 0.0,
            "latency_p95": 0.0,
            "latency_p99": 0.0,
            "detection_latency_ms": 0.0,
            
            # ML Lifecycle Metrics
            "model_load_success": 0,
            "model_load_failure": 0,
            "model_integrity_failure": 0,
            "model_sync_success": 0,
            "model_sync_failure": 0,
            "model_fallback_active": 0,
            "model_load_latency_ms": 0.0
        }
        
        self._default_threats = {
            "DDoS": 0,
            "C2_Beacon": 0,
            "DNS_DGA": 0,
            "DNS_Tunnel": 0,
            "Reconnaissance": 0,
            "EncryptedAnomaly": 0,
            "Exfiltration": 0
        }
        
        # Initialize if not exists
        if not self.redis.exists(self._state_key):
            self.set_state(self._default_state)
        if not self.redis.exists(self._threats_key):
            self.set_threats(self._default_threats)
            
    def get_state(self) -> Dict[str, Any]:
        import time
        from src.utils.prometheus_metrics import REDIS_OPERATIONS_TOTAL, REDIS_ERRORS_TOTAL, REDIS_LATENCY_SECONDS
        t0 = time.time()
        try:
            data = self.redis.get(self._state_key)
            REDIS_OPERATIONS_TOTAL.labels(operation="get_state").inc()
            REDIS_LATENCY_SECONDS.labels(operation="get_state").observe(time.time() - t0)
            if data:
                try:
                    return json.loads(data)
                except Exception:
                    pass
            return self._default_state.copy()
        except Exception as e:
            REDIS_ERRORS_TOTAL.labels(operation="get_state").inc()
            logger.warning(f"Redis get_state failed: {e}")
            return self._default_state.copy()
        
    def set_state(self, state: Dict[str, Any]):
        import time
        from src.utils.prometheus_metrics import REDIS_OPERATIONS_TOTAL, REDIS_ERRORS_TOTAL, REDIS_LATENCY_SECONDS
        t0 = time.time()
        try:
            self.redis.set(self._state_key, json.dumps(state))
            REDIS_OPERATIONS_TOTAL.labels(operation="set_state").inc()
            REDIS_LATENCY_SECONDS.labels(operation="set_state").observe(time.time() - t0)
        except Exception as e:
            REDIS_ERRORS_TOTAL.labels(operation="set_state").inc()
            logger.warning(f"Redis set_state failed: {e}")
        
    def get_threats(self) -> Dict[str, int]:
        import time
        from src.utils.prometheus_metrics import REDIS_OPERATIONS_TOTAL, REDIS_ERRORS_TOTAL, REDIS_LATENCY_SECONDS
        t0 = time.time()
        try:
            data = self.redis.get(self._threats_key)
            REDIS_OPERATIONS_TOTAL.labels(operation="get_threats").inc()
            REDIS_LATENCY_SECONDS.labels(operation="get_threats").observe(time.time() - t0)
            if data:
                try:
                    return json.loads(data)
                except Exception:
                    pass
            return self._default_threats.copy()
        except Exception as e:
            REDIS_ERRORS_TOTAL.labels(operation="get_threats").inc()
            logger.warning(f"Redis get_threats failed: {e}")
            return self._default_threats.copy()
        
    def set_threats(self, threats: Dict[str, int]):
        import time
        from src.utils.prometheus_metrics import REDIS_OPERATIONS_TOTAL, REDIS_ERRORS_TOTAL, REDIS_LATENCY_SECONDS
        t0 = time.time()
        try:
            self.redis.set(self._threats_key, json.dumps(threats))
            REDIS_OPERATIONS_TOTAL.labels(operation="set_threats").inc()
            REDIS_LATENCY_SECONDS.labels(operation="set_threats").observe(time.time() - t0)
        except Exception as e:
            REDIS_ERRORS_TOTAL.labels(operation="set_threats").inc()
            logger.warning(f"Redis set_threats failed: {e}")
        
    def reset(self):
        self.set_state(self._default_state)
        self.set_threats(self._default_threats)
        
    def increment_metric(self, metric: str, amount: int = 1):
        state = self.get_state()
        if metric in state and isinstance(state[metric], int):
            state[metric] += amount
            self.set_state(state)
            
    def set_metric(self, metric: str, value: Any):
        state = self.get_state()
        state[metric] = value
        self.set_state(state)
