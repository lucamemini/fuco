# FUCO - Search Engine for Cortex

FUCO (Fast Universal Cortex Observer) is a modern web interface for [TheHive Project's Cortex](https://github.com/TheHive-Project/Cortex), providing an intuitive search engine for security observables analysis.

![FUCO Main Interface](https://github.com/lucamemini/fuco/blob/master/img/fuco_main.jpg?raw=true)

## 📋 Table of Contents

- [What is FUCO?](#what-is-fuco)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Basic Configuration](#basic-configuration)
  - [Cache Configuration](#cache-configuration)
  - [Advanced Configuration](#advanced-configuration)
- [Running FUCO](#running-fuco)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Screenshots](#screenshots)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## What is FUCO?

FUCO acts as a front-end layer for Cortex, transforming the complexity of threat intelligence analysis into a simple, Google-like search experience. It allows security analysts to:

- **Search and analyze observables** (IPs, domains, URLs, hashes, emails) through a unified interface
- **Leverage multiple analyzers** simultaneously for comprehensive threat assessment
- **View historical analysis** with intelligent caching to reduce API calls
- **Export reports** in various formats for documentation and sharing
- **Process batch queries** for efficient bulk analysis

The application streamlines the workflow of security operations teams by providing instant access to enriched threat intelligence from dozens of sources through Cortex's analyzer ecosystem.

## 🚀 Key Features

### 🔍 Unified Search Interface
- Clean, intuitive search bar supporting multiple observable types
- Automatic data type detection (IP, domain, URL, hash, email)
- Multi-analyzer selection with bulk operations
- Recent searches quick access

### ⚡ Performance Optimized
- Asynchronous job submission for instant page loading
- Intelligent caching system (Memory or Redis) to minimize redundant API calls
- Concurrent polling for faster results aggregation
- Progressive rendering of analysis results

### 📊 Rich Reporting
- Taxonomy-based quick summaries (short templates)
- Detailed analyzer-specific reports (long templates)
- Historical analysis view for any observable
- PDF export capability (Linux/macOS only)

### 🛡️ Responder Actions
- Execute Cortex responders directly from reports
- Session-based authentication (login once, API key stored server-side)
- Bulk responder actions on multiple observables
- Support for TheHive case artifact payload mapping

### 🔌 RESTful API
- `/api/short` - Fast taxonomy-only results
- `/api/analysis` - Complete analysis reports
- `/api/getAnalyzer` - Retrieve available analyzers
- `/api/responder/*` - Responder listing, execution, bulk, and status
- Support for programmatic integrations

## 📦 Prerequisites

### Required Software

#### 1. Cortex Instance (v3.x or higher)
- A running Cortex server from [TheHive Project](https://github.com/TheHive-Project/Cortex)
- Configured analyzers for your use case
- API key with appropriate permissions

#### 2. Python Environment
- Python 3.8 or higher
- pip package manager
- virtualenv (recommended)

#### 3. System Dependencies
- **Linux/macOS**: All features supported including PDF export
- **Windows**: Core features supported, PDF export disabled

### Optional but Recommended

- **Redis server** for production cache (recommended)
- **Reverse proxy** (nginx/Apache) for production deployment
- **SSL/TLS certificates** for secure communication
- **Systemd service** file for automatic startup (Linux)

## 🔧 Installation

### Quick Start (5 minutes)

```bash
# Clone the repository
git clone https://github.com/lucamemini/fuco
cd fuco

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure Cortex connection
cp cortexconfig.py.template cortexconfig.py
# Edit cortexconfig.py with your Cortex credentials

# Run FUCO
python fuco.py
```

Access at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

### Detailed Installation Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/lucamemini/fuco
cd fuco
```

#### 2. Create Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

For Redis cache support (optional):
```bash
pip install redis
```

#### 4. Verify Cortex Connection

Test the connection before configuring:

```bash
python3 -c "from utils import cortex_api; print(cortex_api.analyzers.find_all({}, range='0-5'))"
```

If successful, you should see a list of available analyzers.

## ⚙️ Configuration

### Basic Configuration

#### 1. Cortex Connection

Copy the template and configure your Cortex credentials:

```bash
cp cortexconfig.py.template cortexconfig.py
```

Edit `cortexconfig.py`:

```python
cortex = {
    "host": "https://your-cortex-server.example.com",
    "apikey": "your-cortex-api-key-here"
}
```

**Important**: Ensure your Cortex API key has the following permissions:
- Read analyzers
- Submit jobs
- Read job results

#### 2. Application Settings

Edit `config.py` to customize FUCO behavior:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `DEFAULT_PAP` | 1 (GREEN) | Default PAP level for job submission |
| `DEFAULT_TLP` | 1 (GREEN) | Default TLP level for job submission |
| `SECRET_KEY` | `None` | Session secret. Set a strong value in production |
| `CACHE_TYPE` | `'memory'` | Cache backend: `'memory'` or `'redis'` |
| `CACHE_TTL_MINUTES` | 30 | Cache lifetime for reports (minutes) |
| `REDIS_URL` | `None` | Redis URL (overrides host/port if set) |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` | `localhost` / `6379` / `0` | Redis connection parameters |
| `REDIS_PASSWORD` | `None` | Redis password (if enabled) |
| `API_SHORT_MAX_ATTEMPTS` | 15 | Polling attempts for short API |
| `API_SHORT_INITIAL_DELAY` | 5 | Initial delay between polls (seconds) |
| `JOB_RECENT_LIMIT` | 10 | Number of recent searches to display |
| `ALLOWED_IPS` | `['127.0.0.1','::1']` | Whitelist for cache admin endpoints |

#### Rate limiting (Flask-Limiter)

Rate limits are configurable in `config.py`. Set a value like `"60/minute"`, or disable by using `None` or `""` (empty string). Suggested ranges are included as inline comments.

Key parameters:
- `RATE_LIMIT_EXPORT_PDF`
- `RATE_LIMIT_SUBMIT_JOB`
- `RATE_LIMIT_API_SHORT`
- `RATE_LIMIT_API_ANALYSIS`
- `RATE_LIMIT_GET_ANALYSIS`
- `RATE_LIMIT_GET_SHORT`
- `RATE_LIMIT_RESPONDER_LIST`
- `RATE_LIMIT_RESPONDER_EXECUTE`
- `RATE_LIMIT_RESPONDER_BULK`
- `RATE_LIMIT_RESPONDER_STATUS`
- `RATE_LIMIT_RESPONDER_POLL`
- `RATE_LIMIT_RESPONDER_HISTORY`
- `RATE_LIMIT_RESPONDER_VALIDATE`
- `RATE_LIMIT_RESPONDER_FOR_OBSERVABLE`

### Responder & Authentication

FUCO supports responder actions with session-based authentication. Users login once via the UI; the API key is stored in the server-side session.

**Routes:**
- `/api/auth/login`, `/api/auth/logout`, `/api/auth/status`
- `/api/responder/list`, `/api/responder/execute`, `/api/responder/bulk`

**Responder settings:**
See [config_responder.py](config_responder.py) for defaults such as TLP/PAP and bulk limits.

### Notifications (Email)

FUCO can send an email notification whenever a responder action is requested.

**Configuration (config.py):**
```python
NOTIFY_ENABLED = True
NOTIFY_METHOD = 'auto'  # auto|sendmail|smtp
NOTIFY_SENDMAIL_PATH = '/usr/sbin/sendmail'

NOTIFY_SMTP_HOST = 'mail.example.com'
NOTIFY_SMTP_PORT = 587
NOTIFY_AUTH_USER = 'user@example.com'
NOTIFY_AUTH_PASS = 'secret'
NOTIFY_USE_TLS = True
NOTIFY_USE_SSL = False
NOTIFY_ALLOW_SELF_SIGNED = False

NOTIFY_FROM = 'fuco@example.com'
NOTIFY_TO = 'soc@example.com;secops@example.com'
```

**Notes:**
- On Linux, `auto` tries local sendmail first, otherwise falls back to SMTP.
- `NOTIFY_ALLOW_SELF_SIGNED=True` disables TLS certificate validation.

**TLP/PAP Levels Reference:**
```python
# WHITE: 0, GREEN: 1, AMBER: 2, RED: 3
```

### Cache Configuration

FUCO implements a configurable caching system to optimize performance and reduce load on the Cortex API. The cache stores completed analysis reports, avoiding duplicate requests for the same observable.

#### Memory Cache (Default)

In-memory cache based on Python dictionary. **No external dependencies required.**

**Characteristics:**
- ✅ Zero setup, works immediately
- ✅ Ideal for development and testing
- ✅ Automatic cleanup of expired entries
- ❌ Volatile data (lost on restart)
- ❌ Not shared between multiple instances
- ❌ Limited by process RAM

**Configuration:**
```python
# config.py
CACHE_TYPE = 'memory'
CACHE_TTL_MINUTES = 30
```

#### Redis Cache (Recommended for Production)

Persistent cache with Redis server.

**Characteristics:**
- ✅ Persistent across application restarts
- ✅ Shareable between multiple instances (clustering)
- ✅ Automatic TTL management by Redis
- ✅ Superior performance
- ✅ Advanced monitoring and statistics
- ❌ Requires external Redis server

**Setup Redis Cache:**

**Step 1: Install Redis Server**

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

macOS:
```bash
brew install redis
brew services start redis
```

Docker:
```bash
docker run -d --name fuco-redis \
  -p 6379:6379 \
  redis:7-alpine
```

**Step 2: Install Python Redis Client**
```bash
pip install redis
```

**Step 3: Configure FUCO**

Edit `config.py`:

```python
# Enable Redis cache
CACHE_TYPE = 'redis'
CACHE_TTL_MINUTES = 30

# Option 1: Configure by components
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # None if no password

# Option 2: Full URL (takes precedence)
REDIS_URL = 'redis://localhost:6379/0'
# With password: 'redis://:mypassword@localhost:6379/0'

# Connection timeouts (seconds)
REDIS_SOCKET_TIMEOUT = 5
REDIS_SOCKET_CONNECT_TIMEOUT = 5
```

**Step 4: Verify Connection**

```bash
# Test Redis
redis-cli ping
# Should respond: PONG

# Start FUCO
python fuco.py

# Check logs:
# INFO - Initialized RedisCacheBackend (redis://localhost:6379/0)
# INFO - CacheManager initialized: backend=redis, ttl=30m
```

#### Automatic Fallback

If FUCO is configured for Redis but:
- Redis is not installed (`pip install redis` not executed)
- Redis server is unreachable
- Connection/authentication error occurs

**FUCO will automatically:**
1. Log the error
2. Fall back to Memory Cache
3. Continue operating normally

**Example log:**
```
ERROR - Redis connection error: Connection refused. Fallback to MemoryCache
INFO - Memory backend activated
```

#### Cache Features

**Time-To-Live (TTL):**
- Reports remain cached for the configured time
- Only reports with **final status** are cached (`Success`, `Failure`, `Deleted`)
- `InProgress` or `Waiting` reports are NOT cached
- Redis: TTL automatically managed by server
- Memory: Automatic cleanup every 10 minutes

**Key Namespace:**
All cache keys use the `fuco:` namespace to avoid conflicts:
```
fuco:report:job_abc123
fuco:report:job_xyz789
```

#### Cache Management API

**1. Cache Statistics** (IP-restricted)
```bash
curl http://localhost:5000/api/cache/stats

# Response
{
  "backend": "redis",
  "total_items": 156,
  "by_prefix": {
    "report": 156
  },
  "memory_usage": "2.5M",
  "ttl_minutes": 30,
  "cache_type": "redis"
}
```

**2. Clear Cache** (IP-restricted)
```bash
# Clear all cache
curl -X POST http://localhost:5000/api/cache/clear

# Clear specific report
curl -X POST http://localhost:5000/api/cache/clear \
  -H "Content-Type: application/json" \
  -d '{"job_id": "abc123"}'
```

**3. Health Check**
```bash
curl http://localhost:5000/health

# Response
{
  "status": "healthy",
  "timestamp": "2026-01-18T10:30:00",
  "version": "FUCO 1.0",
  "components": {
    "cache": {"status": "ok", "type": "redis"},
    "cortex": {"status": "ok"}
  }
}
```

#### Redis Monitoring

**Using Redis CLI:**
```bash
redis-cli

# View all FUCO keys
127.0.0.1:6379> KEYS fuco:*

# Count keys
127.0.0.1:6379> DBSIZE

# Memory info
127.0.0.1:6379> INFO memory

# Monitor operations in real-time
127.0.0.1:6379> MONITOR
```

**Using Redis Insight (GUI):**
Download from: https://redis.io/insight/

#### Advanced Redis Configuration

**With Password:**
```python
# config.py
REDIS_PASSWORD = 'your-secure-password'
# Or via URL
REDIS_URL = 'redis://:your-secure-password@localhost:6379/0'
```

**Remote Redis:**
```python
REDIS_HOST = 'redis.example.com'
REDIS_PORT = 6379
REDIS_PASSWORD = 'your-password'

# With SSL/TLS
REDIS_URL = 'rediss://:password@redis.example.com:6380/0'
```

**Multiple Databases:**
```python
REDIS_DB = 0  # Production
REDIS_DB = 1  # Staging
REDIS_DB = 2  # Development
```

#### Cache Best Practices

**Development:**
- ✅ Use Memory Cache
- ✅ Short TTL (10-15 minutes)
- ✅ Automatic cleanup enabled

**Production:**
- ✅ Always use Redis Cache
- ✅ Long TTL (60+ minutes)
- ✅ Redis persistence enabled (AOF + RDB)
- ✅ Active monitoring
- ✅ Regular Redis backups
- ✅ Multi-instance FUCO + Redis clustering

**Security:**
- 🔒 Redis with password authentication
- 🔒 Bind only to necessary IPs
- 🔒 Firewall protection for port 6379
- 🔒 Cache APIs protected by IP whitelist
- 🔒 Encrypted backups

### Advanced Configuration

#### IP Whitelist for Cache API

Edit `config.py` to restrict access to cache management endpoints:

```python
ALLOWED_IPS = [
    '127.0.0.1',      # Localhost IPv4
    '::1',            # Localhost IPv6
    '192.168.1.100',  # Admin workstation
    # Add your trusted IPs here
]
```

#### Logging Configuration

```python
# config.py
import logging

LOG_LEVEL = logging.INFO  # Change to DEBUG for detailed logs
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
```

## 🏃 Running FUCO

### Development Mode

```bash
./run.sh
```

Or manually:

```bash
source venv/bin/activate
python fuco.py
```

### Production Deployment

#### Using Gunicorn

```bash
# Install gunicorn
pip install gunicorn

# Run with 4 workers (adjust based on CPU cores)
gunicorn --workers 4 \
         --bind 0.0.0.0:8000 \
         --timeout 120 \
         --access-logfile /var/log/fuco/access.log \
         --error-logfile /var/log/fuco/error.log \
         fuco:app
```

#### Nginx Reverse Proxy

Create `/etc/nginx/sites-available/fuco`:

```nginx
server {
    listen 80;
    server_name fuco.yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300;
    }
    
    location /static {
        alias /path/to/fuco/web/static;
        expires 30d;
    }
}
```

Enable and reload:
```bash
sudo ln -s /etc/nginx/sites-available/fuco /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### Systemd Service (Linux)

Create `/etc/systemd/system/fuco.service`:

```ini
[Unit]
Description=FUCO - Cortex Search Engine
After=network.target redis.service

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/fuco
Environment="PATH=/opt/fuco/venv/bin"
ExecStart=/opt/fuco/venv/bin/gunicorn --workers 4 --bind 0.0.0.0:8000 fuco:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fuco
sudo systemctl start fuco
sudo systemctl status fuco
```

#### Docker Compose

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    networks:
      - fuco_net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  fuco:
    build: .
    ports:
      - "8000:8000"
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      - redis
    networks:
      - fuco_net
    volumes:
      - ./logs:/app/logs

volumes:
  redis_data:

networks:
  fuco_net:
```

## 💡 Usage Examples

### Web Interface

1. Navigate to the home page
2. Select observable type (or leave for auto-detection)
3. Enter the observable (e.g., `8.8.8.8`, `example.com`)
4. Select desired analyzers
5. Click search

### API Usage

#### Quick Taxonomy Check

```bash
curl -X POST http://localhost:5000/api/short \
  -H "Content-Type: application/json" \
  -d '{
    "Data": "8.8.8.8",
    "DataType": "ip",
    "analyzer_list": ["Shodan_Host", "AbuseIPDB"]
  }'
```

**Response:**

```json
[
  {
    "input": "8.8.8.8",
    "analyzer": "Shodan_Host",
    "status": "Success",
    "taxonomies": [
      {
        "level": "info",
        "namespace": "Shodan",
        "predicate": "Host",
        "value": "Found"
      }
    ]
  }
]
```

#### Full Analysis

```bash
curl -X POST http://localhost:5000/api/analysis \
  -H "Content-Type: application/json" \
  -d '{
    "Data": "malicious-domain.com",
    "DataType": "domain",
    "analyzer_list": ["VirusTotal_GetReport", "GoogleSafeBrowsing"]
  }'
```

#### Batch IP Analysis

FUCO supports comma-separated IP addresses:

```bash
curl -X POST http://localhost:5000/api/short \
  -H "Content-Type: application/json" \
  -d '{
    "Data": "1.1.1.1, 8.8.8.8, 9.9.9.9",
    "DataType": "ip",
    "analyzer_list": ["Shodan_Host", "MaxMind_GeoIP"]
  }'
```

#### Get Available Analyzers

```bash
curl http://localhost:5000/api/getAnalyzer
```

## 📚 API Reference

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface home page |
| `/analysis` | POST | Submit analysis via web form |
| `/api/short` | POST | Quick taxonomy-only API |
| `/api/analysis` | POST | Full analysis API |
| `/api/getAnalyzer` | GET | List available analyzers |
| `/api/submit_job` | POST | Submit single job (AJAX) |
| `/api/poll_job/<job_id>` | GET | Poll job status |
| `/api/cache/stats` | GET | Cache statistics (IP-restricted) |
| `/api/cache/clear` | POST | Clear cache (IP-restricted) |
| `/health` | GET | Health check endpoint |
| `/getShort?JobId=<id>` | GET | Get taxonomy HTML for job |
| `/getAnalysis?JobId=<id>` | GET | Get full report HTML for job |
| `/allReports?observable=<val>&datatype=<type>` | GET | View all reports for observable |

### Request/Response Examples

#### POST /api/short

**Request:**
```json
{
  "Data": "example.com",
  "DataType": "domain",
  "analyzer_list": ["VirusTotal_GetReport"]
}
```

**Response:**
```json
[
  {
    "input": "example.com",
    "analyzer": "VirusTotal_GetReport",
    "status": "Success",
    "taxonomies": [
      {
        "level": "safe",
        "namespace": "VT",
        "predicate": "Score",
        "value": "0/90"
      }
    ]
  }
]
```

## 📸 Screenshots

### Search Interface
![FUCO Search](https://github.com/lucamemini/fuco/blob/master/img/fuco_search.jpg?raw=true)

### Results View
![FUCO Results](https://github.com/lucamemini/fuco/blob/master/img/fuco_result.jpg?raw=true)

## 🔧 Troubleshooting

### Common Issues

#### Connection to Cortex fails

**Symptoms:** API errors, "Connection refused"

**Solutions:**
```bash
# Verify Cortex is running
curl -k https://your-cortex-server/api/status

# Check API key permissions in Cortex UI
# Ensure firewall allows connections to Cortex port

# Test from FUCO server
telnet your-cortex-server 9001
```

#### No analyzers showing

**Symptoms:** Empty analyzer list

**Solutions:**
- Verify analyzers are enabled in Cortex UI
- Check analyzer configuration in Cortex
- Review FUCO logs
- Test API key permissions

#### Jobs timing out

**Symptoms:** "Timeout" status, incomplete results

**Solutions:**
```python
# Increase timeout in config.py
API_SHORT_MAX_ATTEMPTS = 30  # from 15
API_SHORT_INITIAL_DELAY = 10  # from 5
```

#### Redis connection issues

**Symptoms:** "Connection refused", "Authentication required"

**Solutions:**
```bash
# Verify Redis is running
sudo systemctl status redis-server

# Test connection
redis-cli ping

# Check password configuration
# config.py should match /etc/redis/redis.conf
```

#### Cache issues

**Symptoms:** Stale data, outdated results

**Solutions:**
```bash
# Clear cache via API
curl -X POST http://localhost:5000/api/cache/clear

# Or via Redis CLI
redis-cli FLUSHDB

# Reduce TTL in config.py
CACHE_TTL_MINUTES = 15
```

#### PDF export not working

**Symptoms:** Error when exporting to PDF

**Solutions:**
```bash
# Install WeasyPrint dependencies (Ubuntu/Debian)
sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

# Reinstall WeasyPrint
pip install --upgrade weasyprint
```

### Enable Debug Logging

```python
# In config.py
import logging
LOG_LEVEL = logging.DEBUG
```

Check logs:
```bash
# Development
python fuco.py 2>&1 | tee fuco.log

# Production (systemd)
journalctl -u fuco -f
```

## 🗂️ Architecture

FUCO follows a modern Flask architecture:

```
┌─────────────────┐
│   Web Browser   │
│  (JavaScript)   │
└────────┬────────┘
         │ HTTP/AJAX
         │
┌────────▼────────┐
│  Flask App      │
│  (fuco.py)      │
├─────────────────┤
│  Routes Layer   │  ← REST API & Web UI
│  (routes.py)    │     - HTML rendering
│                 │     - JSON API
│                 │     - Request validation
├─────────────────┤
│  Business Logic │
│  (utils.py)     │  ← - Analyzer management
│                 │     - Job polling
│                 │     - Template rendering
├─────────────────┤
│  Cache Layer    │
│ (cache_manager) │  ← - Memory/Redis backend
│                 │     - TTL management
└────────┬────────┘
         │ cortex4py
         │
┌────────▼────────┐
│  Cortex API     │
│  (TheHive)      │  ← - Analyzer execution
│                 │     - Job management
│                 │     - Result storage
└─────────────────┘
```

### Component Responsibilities

- **fuco.py**: Application entry point, Flask initialization, configuration validation
- **routes.py**: HTTP routing, request handling, response formatting
- **utils.py**: Core business logic, Cortex API interaction, template rendering
- **cache_manager.py**: Unified cache management (Memory/Redis)
- **cache_backend.py**: Abstract cache backends implementation
- **config.py**: Configuration parameters and constants
- **cortexconfig.py**: Cortex connection credentials (not in git)
- **templates/**: Jinja2 templates for HTML rendering
  - `short/`: Taxonomy summary templates
  - `long/`: Detailed report templates

### Customizing Templates

FUCO supports analyzer-specific templates:

#### Short Templates (Taxonomy Summaries)

Create `web/templates/short/AnalyzerName.short.html`:

```html
{% for taxonomy in taxonomies %}
<span class="badge {{ taxonomy.css }}">
    {{ taxonomy.namespace }}:{{ taxonomy.predicate }}="{{ taxonomy.value }}"
</span>
{% endfor %}
```

#### Long Templates (Detailed Reports)

Create `web/templates/long/AnalyzerName.long.html`:

```html
<div class="analyzer-report">
    <h3>{{ artifact.analyzerName }}</h3>
    <pre>{{ artifact.report | tojson(indent=2) }}</pre>
</div>
```

If no specific template exists, FUCO uses `generic.short.html` or `generic.long.html` automatically.

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Follow existing code style** (PEP 8 for Python)
4. **Add tests** if applicable
5. **Commit your changes** (`git commit -m 'Add amazing feature'`)
6. **Push to the branch** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

### Development Guidelines

- Use meaningful commit messages
- Update documentation for new features
- Ensure backward compatibility
- Test with multiple Cortex versions
- Add logging for debugging

## 📄 License

This project is open source. Please check the repository for license details.

## 👏 Credits

**Author**: [Luca Memini](mailto:luca@memini.it)

**Built with**:
- [TheHive Project - Cortex](https://github.com/TheHive-Project/Cortex)
- [cortex4py](https://github.com/TheHive-Project/Cortex4py) Python library
- [Flask](https://flask.palletsprojects.com/)
- [Bootstrap](https://getbootstrap.com/)
- [Redis](https://redis.io/) (optional)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/lucamemini/fuco/issues)
- **Email**: luca@memini.it
- **Documentation**: [Cortex Documentation](https://docs.thehive-project.org/cortex/)

---

**Note**: FUCO is a community project and is not officially affiliated with TheHive Project.

⭐ If you find FUCO useful, please consider starring the repository!