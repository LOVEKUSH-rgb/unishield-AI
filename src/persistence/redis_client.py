"""
UniShield AI -- Redis Client
============================
Manages connections to the Redis ephemeral store.
"""

import redis
from src.utils.logging import get_logger
from src.utils.config import settings

logger = get_logger(__name__)

REDIS_URL = settings.redis_url

_redis_client = None

def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
        
    try:
        client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=1)
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as e:
        logger.warning(f"Could not connect to Redis at {REDIS_URL}, falling back to FakeRedis. Error: {e}")
        import fakeredis
        client = fakeredis.FakeStrictRedis(decode_responses=True)
        _redis_client = client
        return _redis_client
