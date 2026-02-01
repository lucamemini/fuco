# ============================================================================
# cache_backend.py - Abstract Cache Backend
# ============================================================================

"""
Configurable cache system with Memory and Redis support.
"""
import logging
import pickle
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional, Any, Dict

logger = logging.getLogger(__name__)


class CacheBackend(ABC):
    """Abstract interface for cache backends."""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Retrieve a value from cache."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Store a value in cache with TTL."""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Remove a value from cache."""
        pass
    
    @abstractmethod
    def clear(self) -> bool:
        """Clear all cache entries."""
        pass
    
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        pass
    
    @abstractmethod
    def ping(self) -> bool:
        """Check backend connectivity."""
        pass


class MemoryCacheBackend(CacheBackend):
    """In-memory cache backend (Python dictionary)."""
    
    def __init__(self):
        self._cache: Dict[str, tuple] = {}  # key -> (timestamp, value)
        logger.info("MemoryCacheBackend initialized")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve a value from the in-memory cache."""
        if key not in self._cache:
            return None
        
        cached_time, value = self._cache[key]
        logger.debug(f"Cache hit (memory): {key}")
        return value
    
    def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Store a value in the in-memory cache."""
        try:
            self._cache[key] = (datetime.now(), value)
            logger.debug(f"Cache set (memory): {key}, TTL: {ttl_seconds}s")
            return True
        except Exception as e:
            logger.error(f"Memory cache set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Remove a value from cache."""
        try:
            if key in self._cache:
                del self._cache[key]
                logger.debug(f"Cache delete (memory): {key}")
                return True
            return False
        except Exception as e:
            logger.error(f"Memory cache delete error: {e}")
            return False
    
    def clear(self) -> bool:
        """Clear all cache entries."""
        try:
            count = len(self._cache)
            self._cache.clear()
            logger.info(f"Cache cleared (memory): {count} items removed")
            return True
        except Exception as e:
            logger.error(f"Memory cache clear error: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """In-memory cache statistics."""
        total = len(self._cache)
        
        stats = {
            'backend': 'memory',
            'total_items': total,
            'by_prefix': {},
            'oldest_entry': None,
            'newest_entry': None,
            'estimated_size_bytes': 0
        }
        
        if total > 0:
            timestamps = []
            for key, (cached_time, value) in self._cache.items():
                # Group by prefix (e.g., "report:", "analyzer:")
                prefix = key.split(':', 1)[0] if ':' in key else 'other'
                stats['by_prefix'][prefix] = stats['by_prefix'].get(prefix, 0) + 1
                timestamps.append(cached_time)
                
                # Estimate size (approximate)
                try:
                    stats['estimated_size_bytes'] += len(pickle.dumps(value))
                except:
                    pass
            
            stats['oldest_entry'] = min(timestamps).isoformat()
            stats['newest_entry'] = max(timestamps).isoformat()
        
        return stats
    
    def ping(self) -> bool:
        """Memory cache is always available."""
        return True
    
    def cleanup_expired(self, ttl: timedelta):
        """Remove expired entries (periodic call)."""
        now = datetime.now()
        expired_keys = []
        
        for key, (cached_time, _) in self._cache.items():
            if now - cached_time > ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned {len(expired_keys)} expired cache entries (memory)")
        
        return len(expired_keys)


class RedisCacheBackend(CacheBackend):
    """Redis cache backend."""
    
    def __init__(self, redis_url: str, socket_timeout: int, socket_connect_timeout: int):
        """
        Initialize the Redis connection.
        
        Args:
            redis_url: Redis connection URL
            socket_timeout: Operation timeout (seconds)
            socket_connect_timeout: Connection timeout (seconds)
        """
        try:
            import redis
        except ImportError:
            raise ImportError(
                "Redis is not installed. Install with: pip install redis\n"
                "Or change CACHE_TYPE='memory' in config.py"
            )
        
        try:
            # Connection with timeout
            self.client = redis.from_url(
                redis_url,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_connect_timeout,
                decode_responses=False  # We use pickle (bytes)
            )
            
            # Connection test
            self.client.ping()
            
            logger.info(f"RedisCacheBackend initialized ({redis_url})")
            
        except redis.ConnectionError as e:
            logger.error(f"Unable to connect to Redis: {e}")
            raise
        except Exception as e:
            logger.error(f"Redis initialization error: {e}")
            raise
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve a value from Redis."""
        try:
            cached = self.client.get(key)
            if cached is None:
                return None
            
            value = pickle.loads(cached)
            logger.debug(f"Cache hit (redis): {key}")
            return value
            
        except Exception as e:
            logger.error(f"Redis cache get error [{key}]: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Store a value in Redis with TTL."""
        try:
            serialized = pickle.dumps(value)
            self.client.setex(key, ttl_seconds, serialized)
            logger.debug(f"Cache set (redis): {key}, TTL: {ttl_seconds}s")
            return True
            
        except Exception as e:
            logger.error(f"Redis cache set error [{key}]: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Remove a value from Redis."""
        try:
            deleted = self.client.delete(key)
            logger.debug(f"Cache delete (redis): {key}, deleted: {deleted}")
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Redis cache delete error [{key}]: {e}")
            return False
    
    def clear(self) -> bool:
        """Clear all FUCO keys in Redis."""
        try:
            # Use a pattern for safety (FUCO keys only)
            pattern = "fuco:*"
            keys = self.client.keys(pattern)
            
            if keys:
                deleted = self.client.delete(*keys)
                logger.info(f"Cache cleared (redis): {deleted} items removed")
                return True
            else:
                logger.info("Cache clear (redis): no items to remove")
                return True
                
        except Exception as e:
            logger.error(f"Redis cache clear error: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Redis cache statistics."""
        try:
            info = self.client.info('memory')
            keys = self.client.keys("fuco:*")
            
            stats = {
                'backend': 'redis',
                'total_items': len(keys),
                'by_prefix': {},
                'memory_usage': info.get('used_memory_human', 'N/A'),
                'peak_memory': info.get('used_memory_peak_human', 'N/A'),
            }
            
            # Group by prefix
            for key in keys[:100]:  # Campiona solo 100 per performance
                try:
                    key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                    # e.g., "fuco:report:123" -> prefix = "report"
                    parts = key_str.split(':', 2)
                    prefix = parts[1] if len(parts) > 1 else 'other'
                    stats['by_prefix'][prefix] = stats['by_prefix'].get(prefix, 0) + 1
                except:
                    pass
            
            return stats
            
        except Exception as e:
            logger.error(f"Redis cache stats error: {e}")
            return {
                'backend': 'redis',
                'error': str(e)
            }
    
    def ping(self) -> bool:
        """Check Redis connectivity."""
        try:
            self.client.ping()
            return True
        except:
            return False
