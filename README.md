# FUCO - Search Engine for Cortex

FUCO (Fast Universal Cortex Observer) is a modern web interface for [TheHive Project's Cortex](https://github.com/TheHive-Project/Cortex), providing an intuitive search engine for security observables analysis.

![FUCO Main Interface](https://github.com/lucamemini/fuco/blob/master/img/fuco_main.jpg?raw=true)

## 📋 Table of Contents

- [What is FUCO?](#what-is-fuco)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
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
- Intelligent caching system to minimize redundant API calls
- Concurrent polling for faster results aggregation
- Progressive rendering of analysis results

### 📊 Rich Reporting
- Taxonomy-based quick summaries (short templates)
- Detailed analyzer-specific reports (long templates)
- Historical analysis view for any observable
- PDF export capability (Linux only)

### 🔌 RESTful API
- `/api/short` - Fast taxonomy-only results
- `/api/analysis` - Complete analysis reports
- `/api/getAnalyzer` - Retrieve available analyzers
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

- Reverse proxy (nginx/Apache) for production deployment
- SSL/TLS certificates for secure communication
- Systemd service file for automatic startup (Linux)

## 🔧 Installation

### Quick Start (4 minutes)

```bash
# Clone the repository
git clone https://github.com/lucamemini/fuco
cd fuco

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure Cortex connection
cp fucoconfig.py.template fucoconfig.py
# Edit fucoconfig.py with your credentials

# Run FUCO
./run.sh
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

#### 4. Verify Cortex Connection

Test the connection before configuring:

```bash
python3 -c "from utils import cortex_api; print(cortex_api.analyzers.find_all({}, range='0-5'))"
```

If successful, you should see a list of available analyzers.

## ⚙️ Configuration

### Basic Configuration

1. **Copy the template configuration:**

```bash
cp fucoconfig.py.template fucoconfig.py
```

2. **Edit `fucoconfig.py` with your Cortex details:**

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

### Advanced Configuration

Edit `config.py` to customize behavior:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `DEFAULT_PAP` | 2 (AMBER) | Default PAP level for job submission |
| `DEFAULT_TLP` | 2 (AMBER) | Default TLP level for job submission |
| `API_SHORT_MAX_ATTEMPTS` | 15 | Polling attempts for short API |
| `API_SHORT_INITIAL_DELAY` | 5 | Initial delay between polls (seconds) |
| `CACHE_TTL_MINUTES` | 30 | Cache lifetime for reports |
| `JOB_RECENT_LIMIT` | 10 | Number of recent searches to display |

### TLP/PAP Levels Reference

```python
# WHITE: 0
# GREEN: 1
# AMBER: 2
# RED: 3
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

For production use, deploy with a WSGI server like Gunicorn:

```bash
# Install gunicorn
pip install gunicorn

# Run with appropriate workers (adjust based on CPU cores)
gunicorn --workers 4 \
         --bind 0.0.0.0:8000 \
         --timeout 120 \
         --access-logfile /var/log/fuco/access.log \
         --error-logfile /var/log/fuco/error.log \
         fuco:app
```

#### Nginx Reverse Proxy Configuration

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

#### Systemd Service (Linux)

Create `/etc/systemd/system/fuco.service`:

```ini
[Unit]
Description=FUCO - Cortex Search Engine
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/fuco
Environment="PATH=/opt/fuco/venv/bin"
ExecStart=/opt/fuco/venv/bin/gunicorn --workers 4 --bind 0.0.0.0:8000 fuco:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable fuco
sudo systemctl start fuco
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
| `/getShort?JobId=<id>` | GET | Get taxonomy HTML for job |
| `/getAnalisys?JobId=<id>` | GET | Get full report HTML for job |
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

## 🔍 Troubleshooting

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
- Review FUCO logs: `tail -f /var/log/fuco/error.log`
- Test API key permissions

#### Jobs timing out

**Symptoms:** "Timeout" status, incomplete results

**Solutions:**
```python
# Increase timeout in config.py
API_SHORT_MAX_ATTEMPTS = 30  # from 15
API_SHORT_INITIAL_DELAY = 10  # from 5
```

- Check Cortex analyzer performance
- Review Cortex worker logs
- Verify network latency

#### PDF export not working

**Symptoms:** Error when exporting to PDF

**Solutions:**
```bash
# Ensure running on Linux/macOS (Windows not supported)

# Install WeasyPrint dependencies (Ubuntu/Debian)
sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

# Install WeasyPrint dependencies (CentOS/RHEL)
sudo yum install pango gdk-pixbuf2 libffi-devel

# Reinstall WeasyPrint
pip install --upgrade weasyprint
```

#### Cache issues

**Symptoms:** Stale data, outdated results

**Solutions:**
```bash
# Clear cache via API
curl -X POST http://localhost:5000/api/cache/clear

# Reduce cache TTL in config.py
CACHE_TTL_MINUTES = 10  # from 30
```

### Debugging

Enable detailed logging:

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

## 🏗️ Architecture

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
│                 │     - Caching
│                 │     - Template rendering
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

- **fuco.py**: Application entry point, Flask initialization
- **routes.py**: HTTP routing, request handling, response formatting
- **utils.py**: Core business logic, Cortex API interaction, caching
- **config.py**: Configuration parameters and constants
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
    {{ taxonomy.namespace }}:{{ taxonomy.predicate }} = {{ taxonomy.value }}
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

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/lucamemini/fuco/issues)
- **Email**: luca@memini.it
- **Documentation**: [Cortex Documentation](https://docs.thehive-project.org/cortex/)

---

**Note**: FUCO is a community project and is not officially affiliated with TheHive Project.

⭐ If you find FUCO useful, please consider starring the repository!
