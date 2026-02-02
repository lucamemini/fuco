"""
Utility functions and business logic for FUCO.
"""
import time
import logging
import json
import re
import ipaddress
import os

from typing import Optional

from jinja2 import Environment, FileSystemLoader

import cortexconfig as cfg
from cortex4py.api import Api
from cortex4py.query import And, Eq
import config

import bleach

# cache
#from cache_manager import cache_manager
from flask import current_app

# Logging configuration
logger = logging.getLogger(__name__)

# Cortex API
cortex_api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

# ============ HTML Sanitization ============

_ALLOWED_TAGS = [
    'a', 'abbr', 'b', 'blockquote', 'br', 'code', 'div', 'dl', 'dt', 'dd',
    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'kbd',
    'li', 'ol', 'p', 'pre', 'small', 'span', 'strong', 'sub', 'sup',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'ul'
]

_ALLOWED_ATTRS = {
    '*': ['class', 'id', 'title', 'aria-*', 'role', 'data-bs-toggle', 'data-bs-target', 'data-toggle', 'data-target'],
    'a': ['href', 'target', 'rel', 'name', 'data-bs-toggle', 'data-bs-target', 'data-toggle', 'data-target'],
    'img': ['src', 'alt', 'title', 'loading'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
}

_ALLOWED_STYLES = [
    'color', 'background-color', 'font-weight', 'font-style', 'text-decoration',
    'text-align', 'white-space', 'width', 'height', 'max-width', 'max-height',
    'border', 'border-color', 'border-width', 'border-style', 'margin', 'padding'
]

# --- bleach feature detection ---
try:
    from bleach.css_sanitizer import CSSSanitizer

    _CSS_SANITIZER = CSSSanitizer(
        allowed_css_properties=_ALLOWED_STYLES
    )
    _USE_CSS_SANITIZER = True

except ImportError:
    from bleach.sanitizer import Cleaner

    _CLEANER = Cleaner(
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        styles=_ALLOWED_STYLES,
        strip=True,
    )
    _USE_CSS_SANITIZER = False


def sanitize_html(html: str) -> str:
    """Sanitize HTML output to mitigate XSS risks."""
    if html is None:
        return ''
    if not isinstance(html, str):
        html = str(html)

    if _USE_CSS_SANITIZER:
        return bleach.clean(
            html,
            tags=_ALLOWED_TAGS,
            attributes=_ALLOWED_ATTRS,
            strip=True,
            css_sanitizer=_CSS_SANITIZER,
        )
    else:
        return _CLEANER.clean(html)

class InputValidator:
    """Input validation and sanitization."""

    EXTRA_TYPES = {
        'certificate_hash',
        'filename',
        'uri_path',
        'user-agent',
        'mail_subject',
        'registry',
        'regexp',
        'file',
        'fqdn'
    }

    @staticmethod
    def allowed_types():
        return set(config.ANALYZER_TYPES) | InputValidator.EXTRA_TYPES

    @staticmethod
    def sanitize_observable(data: str, max_length: int = 500) -> str:
        if data is None:
            raise ValueError("Observable missing")
        if not isinstance(data, str):
            data = str(data)
        data = data.replace('\x00', '')
        data = ' '.join(data.split())
        data = data.strip()
        if not data:
            raise ValueError("Observable is empty")
        return data[:max_length]

    @staticmethod
    def validate_datatype(datatype: str, allow_thehive: bool = False) -> str:
        if datatype is None:
            raise ValueError("Datatype missing")
        if not isinstance(datatype, str):
            datatype = str(datatype)
        dtype = datatype.strip().lower()
        if allow_thehive and dtype.startswith('thehive:'):
            return dtype
        if dtype not in InputValidator.allowed_types():
            raise ValueError(f"Invalid datatype: {dtype}")
        return dtype

    @staticmethod
    def validate_observable_by_type(datatype: str, data: str) -> None:
        if datatype == 'ip':
            try:
                ipaddress.ip_address(data)
                return
            except Exception:
                raise ValueError("Invalid IP address")
        if datatype in ('domain', 'fqdn'):
            if not re.match(config.DOMAIN_REGEX, data):
                raise ValueError("Invalid domain")
            return
        if datatype == 'url':
            if not re.match(config.URL_REGEX, data):
                raise ValueError("Invalid URL")
            return
        if datatype in ('hash', 'certificate_hash'):
            if not (re.match(config.MD5_REGEX, data) or re.match(config.SHA256_REGEX, data)):
                raise ValueError("Invalid hash")
            return
        if datatype == 'mail':
            if not re.match(config.EMAIL_REGEX, data):
                raise ValueError("Invalid email")
            return
        # For other types, accept non-empty strings
        return

def get_cached_report(job_id):
    """
    Retrieve a report from cache or Cortex.
    Uses the CacheManager configured in fuco.py.
    """
    from flask import current_app
    cache_manager = current_app.cache_manager
    
    # 1. Check cache
    report = cache_manager.get_report(job_id)
    if report:
        logger.debug(f"Report {job_id} retrieved from cache")
        return report
    
    # 2. Not in cache, fetch from Cortex
    logger.info(f"Report {job_id} not in cache, fetching from Cortex")
    
    try:
        report = cortex_api_call(cortex_api.jobs.get_report, job_id)
        
        # 3. Save to cache ONLY if status is final
        final_statuses = ("Success", "Failure", "Deleted")
        
        if hasattr(report, 'status') and report.status in final_statuses:
            cache_manager.set_report(job_id, report)
            logger.info(f"Report {job_id} saved to cache (status: {report.status})")
        else:
            current_status = getattr(report, 'status', 'Unknown')
            logger.debug(
                f"Report {job_id} NOT cached "
                f"(non-final status: {current_status})"
            )
        
        return report
        
    except Exception as e:
        logger.error(f"Error retrieving report {job_id}: {str(e)}")
        raise


def clear_report_cache(job_id=None):
    """
    Clear the report cache.
    
    Args:
        job_id: If provided, remove only that report.
                Otherwise clear the entire cache.
    """
    from flask import current_app
    cache_manager = current_app.cache_manager
    
    if job_id:
        success = cache_manager.delete_report(job_id)
        if success:
            logger.info(f"Report {job_id} removed from cache")
        return success
    else:
        success = cache_manager.clear_all()
        if success:
            logger.info("Cache fully cleared")
        return success


def get_cache_stats():
    """Return cache statistics."""
    from flask import current_app
    cache_manager = current_app.cache_manager
    return cache_manager.get_stats()


# Wrapper for API calls with retry
def cortex_api_call(func, *args, **kwargs):
    """
    Wrapper for Cortex API calls with retry and timeout.
    Handles transient network errors with exponential backoff.
    """
    max_retries = 3
    timeout = kwargs.pop('timeout', 30)  # 30-second timeout
    
    for attempt in range(max_retries):
        try:
            # Execute the API call
            result = func(*args, **kwargs)
            return result
            
        except ConnectionError as e:
            logger.warning(f"ConnectionError attempt {attempt+1}/{max_retries}: {str(e)}")
            if attempt == max_retries - 1:
                raise Exception(f"Unable to connect to Cortex after {max_retries} attempts")
            time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
            
        except TimeoutError as e:
            logger.warning(f"Timeout attempt {attempt+1}/{max_retries}")
            if attempt == max_retries - 1:
                raise Exception(f"Timeout after {max_retries} attempts")
            time.sleep(2 ** attempt)
            
        except Exception as e:
            logger.error(f"Cortex API error: {str(e)}")
            # If it's a 4xx (client error), do not retry
            if hasattr(e, 'response') and e.response and 400 <= e.response.status_code < 500:
                raise
            # Otherwise retry
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)

def get_analyzer_by_type(analyzer_type: str):
    """Get analyzers for a specific data type."""
    try:
        #analyzers = cortex_api.analyzers.get_by_type(analyzer_type)
        analyzers = cortex_api_call(cortex_api.analyzers.get_by_type, analyzer_type)
        
        logger.info(f"Retrieved {len(analyzers) if analyzers else 0} analyzers for type: {analyzer_type}")
        return analyzers
    except Exception as e:
        logger.error(f"Error retrieving analyzers for type {analyzer_type}: {str(e)}")
        return []


def get_recent_searches():
    """Retrieve the 10 most recent searches for each data type."""
    try:
        query = And(Eq('status', 'Success'))
        #jobs = cortex_api.jobs.find_all(query, range=config.JOB_SEARCH_RANGE, sort='-createdAt')
        jobs = cortex_api_call(
            cortex_api.jobs.find_all,
            query,
            range=config.JOB_SEARCH_RANGE,
            sort='-createdAt'
        )

        recent = {}
        
        for job in jobs:
            dt = job.dataType
            # Exclude TheHive datatypes (responder actions)
            if hasattr(job, 'dataType') and str(job.dataType).lower().startswith('thehive:'):
                continue
            
            if dt not in recent:
                recent[dt] = {}
            data = job.data
            if isinstance(data, dict):
                data = json.dumps(data, sort_keys=True)
            elif not isinstance(data, str):
                data = str(data)
            if data not in recent[dt]:
                if len(recent[dt]) < config.JOB_RECENT_LIMIT:
                    recent[dt][data] = []
            if data in recent[dt]:
                recent[dt][data].append(job.id)
        
        logger.info(f"Recent searches retrieved: {sum(len(items) for items in recent.values())} items")
        return recent
    except Exception as e:
        logger.error(f"Error retrieving recent searches: {str(e)}")
        return {}

def run_analysis(analyzer: str, datatype: str, data: str, tlp: int = None, pap: int = None) -> dict:
    """
    Run an analysis through a specific analyzer.
    
    Args:
        analyzer: Analyzer name
        datatype: Data type (ip, domain, url, hash, etc.)
        data: Data to analyze
        tlp: Traffic Light Protocol level (0-3). If None, uses config.DEFAULT_TLP
        pap: Permissible Actions Protocol level (0-3). If None, uses config.DEFAULT_PAP
    
    Returns:
        dict: JSON result of the submitted job
    
    TLP/PAP Levels:
        0 = WHITE
        1 = GREEN
        2 = AMBER (default)
        3 = RED
    """
    # Use defaults if not provided
    if tlp is None:
        tlp = config.DEFAULT_TLP
    if pap is None:
        pap = config.DEFAULT_PAP
    
    # Validation
    if not (0 <= tlp <= 3):
        logger.warning(f"Invalid TLP {tlp}, using default {config.DEFAULT_TLP}")
        tlp = config.DEFAULT_TLP
    if not (0 <= pap <= 3):
        logger.warning(f"Invalid PAP {pap}, using default {config.DEFAULT_PAP}")
        pap = config.DEFAULT_PAP
    
    try:
        job = cortex_api_call(
            cortex_api.analyzers.run_by_name,
            analyzer,
            {
                'data': data,
                'dataType': datatype,
                'pap': pap,
                'tlp': tlp
            }, 
            force=1
        )
        
        logger.info(f"Job started: {analyzer} for {datatype} '{data}' (ID: {job.id}) - TLP:{tlp} PAP:{pap}")
        return job.json()
        
    except Exception as e:
        logger.error(f"Error starting analysis: {str(e)}")
        raise



def poll_job(job_id: str, max_attempts: int = None, initial_delay: int = None):
    """
    Poll a job until completion.
    
    Args:
        job_id: Job ID to monitor
        max_attempts: Max attempts (default: config.DEFAULT_MAX_ATTEMPTS)
        initial_delay: Initial delay in seconds (default: config.DEFAULT_INITIAL_DELAY)
    
    Returns:
        Report if completed, None on timeout
    """
    if max_attempts is None:
        max_attempts = config.DEFAULT_MAX_ATTEMPTS
    if initial_delay is None:
        initial_delay = config.DEFAULT_INITIAL_DELAY
    
    try:
        for attempt in range(max_attempts):
            time.sleep(initial_delay + attempt)
            #report = cortex_api.jobs.get_report(job_id)
            report = get_cached_report(job_id)
            if report.status in ("Success", "Failure"):
                logger.info(f"Job {job_id} completed with status: {report.status}")
                return report
        
        logger.warning(f"Job {job_id} not completed after {max_attempts} attempts")
        return None
    except Exception as e:
        logger.error(f"Error while polling job {job_id}: {str(e)}")
        return None


def extract_taxonomies(report) -> list:
    """Extract taxonomies from the report, with a default fallback."""
    try:
        taxonomies = report.report['summary']['taxonomies']
        logger.debug(f"Extracted {len(taxonomies)} taxonomies from report")
        return taxonomies
    except (KeyError, TypeError) as e:
        logger.debug(f"Taxonomies not found in report, using default: {str(e)}")
        return [{
            "level": "undef",
            "namespace": report.analyzerName,
            "predicate": "Summary",
            "value": "NoData"
        }]


def render_short_template(taxonomies: list, analyzer_name: str, app_root_path: str) -> str:
    """
    Render the short template for taxonomies.

        Template contract:
            - ALWAYS receives a list: taxonomies
            - each element has: level, namespace, predicate, value, css

    Args:
        taxonomies: list of taxonomies
        analyzer_name: analyzer name for a specific template
        app_root_path: Flask app root path

    Returns:
        Rendered HTML
    """
    try:
        # Path template (OS-agnostic)
        template_dir = os.path.join(app_root_path, config.TEMPLATE_FOLDER)
        short_template_dir = os.path.join(template_dir, "short")

        logger.debug(f"Short template dir: {short_template_dir}")

        # Consistent and safe Jinja2 environment
        env = Environment(
            loader=FileSystemLoader(short_template_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Normalize taxonomies + CSS
        normalized_taxonomies = []
        for taxonomy in taxonomies:
            level = taxonomy.get("level", "").lower()

            css_class = "bg-secondary"
            if level == "info":
                css_class = "bg-info text-dark"
            elif level == "safe":
                css_class = "bg-success"
            elif level == "suspicious":
                css_class = "bg-warning text-dark"
            elif level == "malicious":
                css_class = "bg-danger"

            t = taxonomy.copy()
            t["css"] = css_class
            normalized_taxonomies.append(t)

        # If there are no taxonomies, exit cleanly
        if not normalized_taxonomies:
            logger.debug("No taxonomy to render")
            return ""

        # Analyzer-specific template
        specific_template_name = f"{analyzer_name}.short.html"
        specific_template_path = os.path.join(short_template_dir, specific_template_name)

        if os.path.exists(specific_template_path):
            logger.info(f"Using analyzer-specific short template: {specific_template_name}")
            template = env.get_template(specific_template_name)
        else:
            logger.info("Specific template not found, using generic.short.html")
            template = env.get_template("generic.short.html")

        # Single render (no manual concatenation)
        html = template.render(taxonomies=normalized_taxonomies)
        html = sanitize_html(html)

        logger.debug("Short template rendering completed")
        return html

    except FileNotFoundError as e:
        logger.error(f"Template not found: {e}")
        return "<p>Error loading taxonomies (template not found).</p>"

    except Exception as e:
        logger.exception("Error rendering short template")
        return "<p>Error loading taxonomies.</p>"

def resolve_long_template(report, app_root_path: str) -> Optional[str]:
    """
    Resolve the correct LONG template for the analyzer.

    Does NOT render HTML.
    Returns only the LONG template name to use.

    Args:
        report: report/analyzer result object
        app_root_path: Flask app root path

    Returns:
        LONG template name or None
    """
    try:
        template_dir = os.path.join(
            app_root_path,
            config.TEMPLATE_FOLDER,
            "long"
        )

        analyzer_name = getattr(report, "analyzerName", None)
        if not analyzer_name:
            logger.warning("report.analyzerName missing")
            return None

        template_name = f"{analyzer_name}.long.html"
        template_path = os.path.join(template_dir, template_name)

        if os.path.isfile(template_path):
            logger.info(f"LONG template found: {template_name}")
            return f"long/{template_name}"
            # return template_name

        logger.info(f"Specific LONG template not found: {template_name}")
        return None

    except Exception as e:
        logger.exception("Error resolving LONG template")
        return None


def detect_data_type(data: str) -> str:
    """
    Automatically detect the data type based on regex patterns.
    
    Args:
        data: Data to analyze
    
    Returns:
        Detected data type or None if not recognized
    """
    if re.match(config.IPV4_REGEX, data):
        try:
            ip_obj = ipaddress.ip_address(data)
            if not ip_obj.is_private:
                return "ip"
        except ValueError:
            pass
    elif re.match(config.DOMAIN_REGEX, data):
        return "domain"
    elif re.match(config.URL_REGEX, data):
        return "url"
    elif re.match(config.SHA256_REGEX, data):
        return "sha256"
    elif re.match(config.MD5_REGEX, data):
        return "md5"
    elif re.match(config.EMAIL_REGEX, data):
        return "email"
    
    logger.warning(f"Unable to detect data type for: {data}")
    return None


def validate_ip_address(ip: str) -> bool:
    """Validate whether an IP address is public and valid."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False


def parse_multiple_ips(raw_data: str) -> list:
    """Extract and validate multiple IPs from a comma-separated string."""
    ips = []
    try:
        candidates = [ip.strip() for ip in raw_data.split(',')]
        for ip in candidates:
            if validate_ip_address(ip):
                ips.append(ip)
        logger.info(f"Extracted {len(ips)} valid public IPs from input")
        return ips
    except Exception as e:
        logger.error(f"Error parsing IPs: {str(e)}")
        return []
