# ============================================================================
# cache_manager.py - Manager Cache Unificato
# ============================================================================

"""
Manager unificato per la gestione della cache
"""
import logging
from datetime import timedelta
from typing import Optional, Any

import config
from cache_backend import CacheBackend, MemoryCacheBackend, RedisCacheBackend

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manager per la cache con supporto configurabile Memory/Redis
    """
    
    def __init__(self, redis_url: str = None):
        """
        Inizializza il backend corretto in base alla configurazione
        
        Args:
            redis_url: URL Redis costruito da fuco.py (solo se CACHE_TYPE='redis')
        """
        self.backend: CacheBackend = self._initialize_backend(redis_url)
        self.ttl = timedelta(minutes=config.CACHE_TTL_MINUTES)
        self.ttl_seconds = config.CACHE_TTL_MINUTES * 60
        
        logger.info(
            f"CacheManager inizializzato: "
            f"backend={config.CACHE_TYPE}, ttl={config.CACHE_TTL_MINUTES}m"
        )
    
    def _initialize_backend(self, redis_url: str = None) -> CacheBackend:
        """Inizializza il backend in base a config.CACHE_TYPE"""
        
        if config.CACHE_TYPE == 'redis':
            if not redis_url:
                logger.error("CACHE_TYPE='redis' ma redis_url non fornito. Fallback a Memory.")
                return MemoryCacheBackend()
            
            try:
                backend = RedisCacheBackend(
                    redis_url,
                    config.REDIS_SOCKET_TIMEOUT,
                    config.REDIS_SOCKET_CONNECT_TIMEOUT
                )
                logger.info("Backend Redis attivato con successo")
                return backend
                
            except ImportError as e:
                logger.error(
                    f"Redis non disponibile: {e}. "
                    f"Fallback a MemoryCache. "
                    f"Installa con: pip install redis"
                )
                return MemoryCacheBackend()
                
            except Exception as e:
                logger.error(
                    f"Errore connessione Redis: {e}. "
                    f"Fallback a MemoryCache"
                )
                return MemoryCacheBackend()
        
        else:  # memory
            logger.info("Backend Memory attivato")
            return MemoryCacheBackend()
    
    def _make_key(self, key_type: str, identifier: str) -> str:
        """
        Crea chiave cache con namespace
        
        Args:
            key_type: Tipo di dato (es: 'report', 'analyzer')
            identifier: ID univoco
        
        Returns:
            Chiave formattata (es: 'fuco:report:job123')
        """
        return f"fuco:{key_type}:{identifier}"
    
    def get_report(self, job_id: str) -> Optional[Any]:
        """Recupera report dalla cache"""
        key = self._make_key('report', job_id)
        return self.backend.get(key)
    
    def set_report(self, job_id: str, report: Any) -> bool:
        """Salva report in cache"""
        key = self._make_key('report', job_id)
        return self.backend.set(key, report, self.ttl_seconds)
    
    def delete_report(self, job_id: str) -> bool:
        """Rimuove report dalla cache"""
        key = self._make_key('report', job_id)
        return self.backend.delete(key)
    
    def clear_all(self) -> bool:
        """Pulisce tutta la cache"""
        return self.backend.clear()
    
    def get_stats(self) -> dict:
        """Ritorna statistiche sulla cache"""
        stats = self.backend.get_stats()
        stats['ttl_minutes'] = config.CACHE_TTL_MINUTES
        stats['cache_type'] = config.CACHE_TYPE
        return stats
    
    def ping(self) -> bool:
        """Verifica che il backend sia disponibile"""
        return self.backend.ping()
    
    def cleanup_expired(self):
        """
        Pulisce entry scadute (solo per MemoryCache)
        Per Redis il TTL è automatico
        """
        if isinstance(self.backend, MemoryCacheBackend):
            return self.backend.cleanup_expired(self.ttl)
        return 0
