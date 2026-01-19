# Cache Configuration

## Overview

FUCO implementa un sistema di cache configurabile per ottimizzare le performance e ridurre il carico sull'API di Cortex. La cache memorizza i report delle analisi completate, evitando richieste duplicate per lo stesso observable.

## Backend Disponibili

### 1. Memory Cache (Default)

Cache in-memory basata su dizionario Python.

**Caratteristiche:**
- ✅ Nessuna dipendenza esterna
- ✅ Setup immediato, zero configurazione
- ✅ Ideale per sviluppo e testing
- ✅ Cleanup automatico delle entry scadute
- ❌ Dati volatili (si perdono al restart)
- ❌ Non condivisa tra istanze multiple
- ❌ Limitata dalla RAM del processo

**Configurazione:**
```python
# config.py
CACHE_TYPE = 'memory'
CACHE_TTL_MINUTES = 30
```

### 2. Redis Cache (Recommended for Production)

Cache persistente con Redis server.

**Caratteristiche:**
- ✅ Persistente tra restart dell'applicazione
- ✅ Condivisibile tra istanze multiple (clustering)
- ✅ TTL automatico gestito da Redis
- ✅ Performance superiori
- ✅ Monitoring e statistiche avanzate
- ❌ Richiede Redis server esterno

**Configurazione:**

```python
# config.py
CACHE_TYPE = 'redis'
CACHE_TTL_MINUTES = 30

# Opzione 1: Configurazione per componenti
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # None se no password

# Opzione 2: URL completo (ha precedenza)
REDIS_URL = 'redis://localhost:6379/0'
# Con password: 'redis://:mypassword@localhost:6379/0'

# Timeout connessione
REDIS_SOCKET_TIMEOUT = 5
REDIS_SOCKET_CONNECT_TIMEOUT = 5
```

## Setup e Installazione

### Memory Cache

Già attivo di default, nessuna configurazione necessaria.

### Redis Cache

#### 1. Installa Redis

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

**macOS:**
```bash
brew install redis
brew services start redis
```

**Docker:**
```bash
docker run -d --name fuco-redis \
  -p 6379:6379 \
  redis:7-alpine
```

**Windows:**
```powershell
# Usa Docker o WSL2
wsl --install
# Poi installa Redis in WSL
```

#### 2. Installa Python Redis Client

```bash
pip install redis
```

#### 3. Configura FUCO

Modifica `config.py`:

```python
CACHE_TYPE = 'redis'
REDIS_HOST = 'localhost'  # O IP del tuo server Redis
REDIS_PORT = 6379
REDIS_DB = 0
```

#### 4. Verifica Connessione

```bash
# Test Redis
redis-cli ping
# Dovrebbe rispondere: PONG

# Avvia FUCO
python fuco.py

# Verifica nei log:
# INFO - Inizializzato RedisCacheBackend (redis://localhost:6379/0)
# INFO - CacheManager inizializzato: backend=redis, ttl=30m
```

## Fallback Automatico

Se FUCO è configurato per Redis ma:
- Redis non è installato (`pip install redis` non eseguito)
- Redis server non è raggiungibile
- Errore di connessione/autenticazione

**FUCO automaticamente:**
1. Logga l'errore
2. Fa fallback a Memory Cache
3. Continua a funzionare normalmente

**Log di esempio:**
```
ERROR - Errore connessione Redis: Connection refused. Fallback a MemoryCache
INFO - Backend Memory attivato
```

## Funzionalità Cache

### Time-To-Live (TTL)

I report rimangono in cache per il tempo configurato:

```python
# config.py
CACHE_TTL_MINUTES = 30  # 30 minuti (default)
```

**Note:**
- Solo report con status **finale** vengono cachati (`Success`, `Failure`, `Deleted`)
- Report `InProgress` o `Waiting` NON vengono cachati
- Per Redis, il TTL è gestito automaticamente dal server
- Per Memory, cleanup automatico ogni 10 minuti

### Namespace Chiavi

Tutte le chiavi cache usano il namespace `fuco:` per evitare conflitti:

```
fuco:report:job_abc123
fuco:report:job_xyz789
```

### API di Gestione

#### 1. Statistiche Cache

```bash
# GET /api/cache/stats
curl http://localhost:5000/api/cache/stats

# Response
{
  "backend": "redis",
  "total_items": 156,
  "by_prefix": {
    "report": 156
  },
  "memory_usage": "2.5M",
  "peak_memory": "3.1M",
  "ttl_minutes": 30,
  "cache_type": "redis"
}
```

**Restrizioni:** Solo IP autorizzati (vedi `ALLOWED_IPS` in `config.py`)

#### 2. Pulizia Cache

```bash
# Pulisci tutta la cache
curl -X POST http://localhost:5000/api/cache/clear

# Pulisci singolo report
curl -X POST http://localhost:5000/api/cache/clear \
  -H "Content-Type: application/json" \
  -d '{"job_id": "abc123"}'
```

**Restrizioni:** Solo IP autorizzati

#### 3. Health Check

```bash
# GET /health
curl http://localhost:5000/health

# Response
{
  "status": "healthy",
  "timestamp": "2026-01-18T10:30:00",
  "version": "FUCO 1.0",
  "components": {
    "cache": {
      "status": "ok",
      "type": "redis"
    },
    "cortex": {
      "status": "ok"
    }
  }
}
```

## Monitoring Redis

### Redis CLI

```bash
# Connetti a Redis
redis-cli

# Visualizza tutte le chiavi FUCO
127.0.0.1:6379> KEYS fuco:*

# Conta chiavi
127.0.0.1:6379> DBSIZE

# Info memoria
127.0.0.1:6379> INFO memory

# Monitora operazioni in tempo reale
127.0.0.1:6379> MONITOR
```

### Redis Insight (GUI)

Scarica da: https://redis.io/insight/

- Visualizzazione grafica dei dati
- Monitoring performance
- Query builder

## Configurazioni Avanzate

### Redis con Password

```python
# config.py
REDIS_PASSWORD = 'your-secure-password'

# Oppure via URL
REDIS_URL = 'redis://:your-secure-password@localhost:6379/0'
```

### Redis Remoto

```python
# config.py
REDIS_HOST = 'redis.example.com'
REDIS_PORT = 6379
REDIS_PASSWORD = 'your-password'

# Con SSL/TLS
REDIS_URL = 'rediss://:password@redis.example.com:6380/0'
```

### Redis Sentinel (High Availability)

```python
# Richiede configurazione custom del RedisCacheBackend
# Vedi documentazione redis-py per Sentinel
```

### Multiple Databases

```python
# Database separati per ambienti
REDIS_DB = 0  # Production
REDIS_DB = 1  # Staging
REDIS_DB = 2  # Development
```

## Performance Tuning

### Memory Cache

```python
# Aumenta frequenza cleanup
# fuco.py - scheduler interval
@scheduler.task('interval', id='cleanup_cache', minutes=5)  # da 10 a 5
```

### Redis Cache

```python
# Riduci timeout per failover veloce
REDIS_SOCKET_TIMEOUT = 2
REDIS_SOCKET_CONNECT_TIMEOUT = 2

# Aumenta TTL per ridurre load Cortex
CACHE_TTL_MINUTES = 60  # 1 ora invece di 30 minuti
```

### Redis Configuration File

Ottimizza `/etc/redis/redis.conf`:

```conf
# Limita memoria massima
maxmemory 256mb

# Policy di eviction (rimuovi chiavi meno usate)
maxmemory-policy allkeys-lru

# Salvataggio su disco (persistenza)
save 900 1
save 300 10
save 60 10000

# AOF per durabilità
appendonly yes
appendfsync everysec
```

## Troubleshooting

### "Redis non installato"

```bash
# Installa client Python
pip install redis

# Verifica installazione
python -c "import redis; print(redis.__version__)"
```

### "Connection refused"

```bash
# Verifica che Redis sia in esecuzione
sudo systemctl status redis-server

# Testa connessione
redis-cli ping

# Controlla bind address in /etc/redis/redis.conf
# bind 127.0.0.1 ::1

# Controlla porta
netstat -tlnp | grep 6379
```

### "Authentication required"

```bash
# Redis richiede password ma config.py non l'ha impostata
# Opzione 1: Aggiungi password in config.py
REDIS_PASSWORD = 'your-password'

# Opzione 2: Disabilita auth in redis.conf
# requirepass ""
```

### "Memory usage troppo alta"

```bash
# Verifica uso memoria
redis-cli INFO memory

# Pulisci cache manualmente
redis-cli FLUSHDB

# Riduci TTL in config.py
CACHE_TTL_MINUTES = 15
```

### "Cache sempre vuota dopo restart"

**Memory Cache:** Comportamento normale, cache volatile.

**Redis Cache:**
```bash
# Verifica salvataggio Redis
redis-cli CONFIG GET save

# Abilita persistenza in redis.conf
save 900 1
```

## Best Practices

### Sviluppo
- ✅ Usa Memory Cache
- ✅ TTL breve (10-15 minuti)
- ✅ Cleanup automatico attivo

### Test/Staging
- ✅ Usa Redis se disponibile, altrimenti Memory
- ✅ TTL medio (30 minuti)
- ✅ Monitora statistiche cache

### Produzione
- ✅ Sempre Redis Cache
- ✅ TTL lungo (60+ minuti)
- ✅ Redis persistente (AOF + RDB)
- ✅ Monitoring attivo
- ✅ Backup Redis periodici
- ✅ Clustering multi-istanza FUCO + Redis

### Sicurezza
- 🔒 Redis con password (`requirepass` in redis.conf)
- 🔒 Bind solo IP necessari (`bind 127.0.0.1`)
- 🔒 Firewall per porta 6379
- 🔒 API cache protette da IP whitelist
- 🔒 Backup crittografati

## Esempi di Utilizzo

### Scenario 1: Laptop Development

```python
# config.py
CACHE_TYPE = 'memory'
CACHE_TTL_MINUTES = 10
```

**Vantaggi:** Zero setup, funziona ovunque.

### Scenario 2: Server Singolo Production

```bash
# Install Redis
sudo apt-get install redis-server

# config.py
CACHE_TYPE = 'redis'
REDIS_HOST = 'localhost'
CACHE_TTL_MINUTES = 60
```

**Vantaggi:** Persistenza, performance.

### Scenario 3: Cluster Load-Balanced

```bash
# Separate Redis server
# redis-server.example.com

# FUCO Instance 1 - config.py
CACHE_TYPE = 'redis'
REDIS_HOST = 'redis-server.example.com'
REDIS_PASSWORD = 'secure-password'

# FUCO Instance 2 - same config
# Entrambe condividono la stessa cache Redis
```

**Vantaggi:** Cache condivisa, scalabilità orizzontale.

### Scenario 4: Docker Compose

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    networks:
      - fuco_net

  fuco:
    build: .
    environment:
      # Redis hostname è nome service
      REDIS_HOST: redis
    depends_on:
      - redis
    networks:
      - fuco_net

volumes:
  redis_data:

networks:
  fuco_net:
```

```python
# config.py in container
CACHE_TYPE = 'redis'
REDIS_HOST = 'redis'  # Nome del service Docker
```

## Migration Guide

### Da Memory a Redis

1. Installa Redis server
2. Installa `pip install redis`
3. Modifica `config.py`:
   ```python
   CACHE_TYPE = 'redis'
   ```
4. Restart FUCO
5. Verifica log: `INFO - Backend Redis attivato`

**Note:** La cache Memory viene persa, Redis parte vuota.

### Da Redis a Memory

1. Modifica `config.py`:
   ```python
   CACHE_TYPE = 'memory'
   ```
2. Restart FUCO
3. (Opzionale) Disinstalla Redis se non usato

**Note:** Dati Redis rimangono intatti ma inutilizzati.

## FAQ

**Q: Posso usare Redis di un altro progetto?**  
A: Sì, usa un database diverso (`REDIS_DB = 5`) per evitare conflitti.

**Q: Come pulisco SOLO la cache di FUCO senza toccare altri dati Redis?**  
A: `redis-cli --scan --pattern "fuco:*" | xargs redis-cli DEL`

**Q: La cache funziona anche per gli analyzer jobs non completati?**  
A: No, solo job con status finale (`Success`, `Failure`, `Deleted`) vengono cachati.

**Q: Come faccio backup della cache Redis?**  
A: `redis-cli SAVE` oppure copia file `/var/lib/redis/dump.rdb`

**Q: Posso usare Redis Cloud/AWS ElastiCache?**  
A: Sì, configura `REDIS_URL` con l'endpoint remoto.

**Q: Memory Cache usa troppa RAM, come limito?**  
A: Non c'è limite hard. Riduci `CACHE_TTL_MINUTES` o passa a Redis con `maxmemory`.

---

## Next Steps

- **Performance**: Vedi [Performance Optimization](#)
- **Monitoring**: Vedi [Monitoring Guide](#)
- **Deployment**: Vedi [Production Deployment](#)