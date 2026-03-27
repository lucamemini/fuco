# ============================================================================
# cache_manager.py - Unified Cache Manager
# ============================================================================

"""
Unified manager for cache handling.
"""
import logging
from datetime import timedelta
from typing import Optional, Any

import config
import config_ai
from cache_backend import CacheBackend, MemoryCacheBackend, RedisCacheBackend

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Cache manager with configurable Memory/Redis backend support.
    """
    
    def __init__(self, redis_url: str = None):
        """
        Initialize the proper backend based on configuration.
        
        Args:
            redis_url: Redis URL built by fuco.py (only if CACHE_TYPE='redis')
        """
        self.backend: CacheBackend = self._initialize_backend(redis_url)
        self.ttl = timedelta(minutes=config.CACHE_TTL_MINUTES)
        self.ttl_seconds = config.CACHE_TTL_MINUTES * 60
        self.ai_ttl_seconds = config_ai.AI_CACHE_TTL_MINUTES * 60
        
        logger.info(
            f"CacheManager initialized: "
            f"backend={config.CACHE_TYPE}, ttl={config.CACHE_TTL_MINUTES}m"
        )
    
    def _initialize_backend(self, redis_url: str = None) -> CacheBackend:
        """Initialize the backend based on config.CACHE_TYPE."""
        
        if config.CACHE_TYPE == 'redis':
            if not redis_url:
                logger.error("CACHE_TYPE='redis' but redis_url not provided. Falling back to Memory.")
                return MemoryCacheBackend()
            
            try:
                backend = RedisCacheBackend(
                    redis_url,
                    config.REDIS_SOCKET_TIMEOUT,
                    config.REDIS_SOCKET_CONNECT_TIMEOUT
                )
                logger.info("Redis backend enabled successfully")
                return backend
                
            except ImportError as e:
                logger.error(
                    f"Redis not available: {e}. "
                    f"Falling back to MemoryCache. "
                    f"Install with: pip install redis"
                )
                return MemoryCacheBackend()
                
            except Exception as e:
                logger.error(
                    f"Redis connection error: {e}. "
                    f"Falling back to MemoryCache"
                )
                return MemoryCacheBackend()
        
        else:  # memory
            logger.info("Memory backend enabled")
            return MemoryCacheBackend()
    
    def _make_key(self, key_type: str, identifier: str) -> str:
        """
        Create a cache key with namespace.
        
        Args:
            key_type: Data type (e.g., 'report', 'analyzer')
            identifier: Unique ID
        
        Returns:
            Formatted key (e.g., 'fuco:report:job123')
        """
        return f"fuco:{key_type}:{identifier}"
    
    def get_report(self, job_id: str) -> Optional[Any]:
        """Retrieve a report from cache."""
        key = self._make_key('report', job_id)
        return self.backend.get(key)
    
    def set_report(self, job_id: str, report: Any) -> bool:
        """Store a report in cache."""
        key = self._make_key('report', job_id)
        return self.backend.set(key, report, self.ttl_seconds)
    
    def delete_report(self, job_id: str) -> bool:
        """Remove a report from cache."""
        key = self._make_key('report', job_id)
        return self.backend.delete(key)

    def get_ai_assessment(self, cache_key: str) -> Optional[Any]:
        """Retrieve an AI assessment payload from cache."""
        key = self._make_key('ai_assessment', cache_key)
        return self.backend.get(key)

    def set_ai_assessment(self, cache_key: str, payload: Any) -> bool:
        """Store an AI assessment payload in cache."""
        key = self._make_key('ai_assessment', cache_key)
        return self.backend.set(key, payload, self.ai_ttl_seconds)
    
    def clear_all(self) -> bool:
        """Clear all cache entries."""
        return self.backend.clear()
    
    def get_stats(self) -> dict:
        """Return cache statistics."""
        stats = self.backend.get_stats()
        stats['ttl_minutes'] = config.CACHE_TTL_MINUTES
        stats['cache_type'] = config.CACHE_TYPE
        return stats
    
    def ping(self) -> bool:
        """Check whether the backend is available."""
        return self.backend.ping()
    
    def cleanup_expired(self):
        """
        Clean up expired entries (MemoryCache only).
        Redis handles TTL automatically.
        """
        if isinstance(self.backend, MemoryCacheBackend):
            return self.backend.cleanup_expired()
        return 0
