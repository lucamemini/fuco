# ============================================================================
# cache_backend.py - Backend Cache Astratto
# ============================================================================

"""
Sistema di cache configurabile con supporto Memory e Redis
"""
import logging
import pickle
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional, Any, Dict

logger = logging.getLogger(__name__)


class CacheBackend(ABC):
    """Interfaccia astratta per backend di cache"""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Recupera valore dalla cache"""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Salva valore in cache con TTL"""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Rimuove valore dalla cache"""
        pass
    
    @abstractmethod
    def clear(self) -> bool:
        """Pulisce tutta la cache"""
        pass
    
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Ritorna statistiche sulla cache"""
        pass
    
    @abstractmethod
    def ping(self) -> bool:
        """Verifica connessione al backend"""
        pass


class MemoryCacheBackend(CacheBackend):
    """Backend cache in-memory (dizionario Python)"""
    
    def __init__(self):
        self._cache: Dict[str, tuple] = {}  # key -> (timestamp, value)
        logger.info("Inizializzato MemoryCacheBackend")
    
    def get(self, key: str) -> Optional[Any]:
        """Recupera valore dalla cache in-memory"""
        if key not in self._cache:
            return None
        
        cached_time, value = self._cache[key]
        logger.debug(f"Cache hit (memory): {key}")
        return value
    
    def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Salva in cache in-memory"""
        try:
            self._cache[key] = (datetime.now(), value)
            logger.debug(f"Cache set (memory): {key}, TTL: {ttl_seconds}s")
            return True
        except Exception as e:
            logger.error(f"Errore set cache memory: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Rimuove dalla cache"""
        try:
            if key in self._cache:
                del self._cache[key]
                logger.debug(f"Cache delete (memory): {key}")
                return True
            return False
        except Exception as e:
            logger.error(f"Errore delete cache memory: {e}")
            return False
    
    def clear(self) -> bool:
        """Pulisce tutta la cache"""
        try:
            count = len(self._cache)
            self._cache.clear()
            logger.info(f"Cache cleared (memory): {count} items removed")
            return True
        except Exception as e:
            logger.error(f"Errore clear cache memory: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiche cache in-memory"""
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
                # Raggruppa per prefix (es: "report:", "analyzer:")
                prefix = key.split(':', 1)[0] if ':' in key else 'other'
                stats['by_prefix'][prefix] = stats['by_prefix'].get(prefix, 0) + 1
                timestamps.append(cached_time)
                
                # Stima dimensione (approssimativa)
                try:
                    stats['estimated_size_bytes'] += len(pickle.dumps(value))
                except:
                    pass
            
            stats['oldest_entry'] = min(timestamps).isoformat()
            stats['newest_entry'] = max(timestamps).isoformat()
        
        return stats
    
    def ping(self) -> bool:
        """Memory cache è sempre disponibile"""
        return True
    
    def cleanup_expired(self, ttl: timedelta):
        """Rimuove entry scadute (chiamata periodica)"""
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
    """Backend cache Redis"""
    
    def __init__(self, redis_url: str, socket_timeout: int, socket_connect_timeout: int):
        """
        Inizializza connessione Redis
        
        Args:
            redis_url: URL connessione Redis
            socket_timeout: Timeout operazioni (secondi)
            socket_connect_timeout: Timeout connessione (secondi)
        """
        try:
            import redis
        except ImportError:
            raise ImportError(
                "Redis non installato. Installa con: pip install redis\n"
                "Oppure cambia CACHE_TYPE='memory' in config.py"
            )
        
        try:
            # Connessione con timeout
            self.client = redis.from_url(
                redis_url,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_connect_timeout,
                decode_responses=False  # Usiamo pickle quindi bytes
            )
            
            # Test connessione
            self.client.ping()
            
            logger.info(f"Inizializzato RedisCacheBackend ({redis_url})")
            
        except redis.ConnectionError as e:
            logger.error(f"Impossibile connettersi a Redis: {e}")
            raise
        except Exception as e:
            logger.error(f"Errore inizializzazione Redis: {e}")
            raise
    
    def get(self, key: str) -> Optional[Any]:
        """Recupera valore da Redis"""
        try:
            cached = self.client.get(key)
            if cached is None:
                return None
            
            value = pickle.loads(cached)
            logger.debug(f"Cache hit (redis): {key}")
            return value
            
        except Exception as e:
            logger.error(f"Errore get cache redis [{key}]: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Salva in Redis con TTL"""
        try:
            serialized = pickle.dumps(value)
            self.client.setex(key, ttl_seconds, serialized)
            logger.debug(f"Cache set (redis): {key}, TTL: {ttl_seconds}s")
            return True
            
        except Exception as e:
            logger.error(f"Errore set cache redis [{key}]: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Rimuove da Redis"""
        try:
            deleted = self.client.delete(key)
            logger.debug(f"Cache delete (redis): {key}, deleted: {deleted}")
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Errore delete cache redis [{key}]: {e}")
            return False
    
    def clear(self) -> bool:
        """Pulisce tutte le chiavi FUCO in Redis"""
        try:
            # Usa pattern per sicurezza (solo chiavi FUCO)
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
            logger.error(f"Errore clear cache redis: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiche Redis"""
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
            
            # Raggruppa per prefix
            for key in keys[:100]:  # Campiona solo 100 per performance
                try:
                    key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                    # es: "fuco:report:123" -> prefix = "report"
                    parts = key_str.split(':', 2)
                    prefix = parts[1] if len(parts) > 1 else 'other'
                    stats['by_prefix'][prefix] = stats['by_prefix'].get(prefix, 0) + 1
                except:
                    pass
            
            return stats
            
        except Exception as e:
            logger.error(f"Errore stats cache redis: {e}")
            return {
                'backend': 'redis',
                'error': str(e)
            }
    
    def ping(self) -> bool:
        """Verifica connessione Redis"""
        try:
            self.client.ping()
            return True
        except:
            return False
