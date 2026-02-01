"""
Funzioni utility e business logic per FUCO
"""
import time
import logging
import json
import re
import ipaddress
import os

from typing import Optional

from jinja2 import Environment, FileSystemLoader
import bleach
from bleach.css_sanitizer import CSSSanitizer

import cortexconfig as cfg
from cortex4py.api import Api
from cortex4py.query import And, Eq
import config

# cache
#from cache_manager import cache_manager
from flask import current_app

# Configurazione logging
logger = logging.getLogger(__name__)

# API Cortex
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

_CSS_SANITIZER = CSSSanitizer(allowed_css_properties=[
    'color', 'background-color', 'font-weight', 'font-style', 'text-decoration',
    'text-align', 'white-space', 'width', 'height', 'max-width', 'max-height',
    'border', 'border-color', 'border-width', 'border-style', 'margin', 'padding'
])


def sanitize_html(html: str) -> str:
    """Sanitize HTML output to mitigate XSS risks."""
    if html is None:
        return ''
    if not isinstance(html, str):
        html = str(html)
    return bleach.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        strip=True,
        css_sanitizer=_CSS_SANITIZER
    )


class InputValidator:
    """Validazione e sanitizzazione input."""

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
            raise ValueError("Observable mancante")
        if not isinstance(data, str):
            data = str(data)
        data = data.replace('\x00', '')
        data = ' '.join(data.split())
        data = data.strip()
        if not data:
            raise ValueError("Observable vuoto")
        return data[:max_length]

    @staticmethod
    def validate_datatype(datatype: str, allow_thehive: bool = False) -> str:
        if datatype is None:
            raise ValueError("Datatype mancante")
        if not isinstance(datatype, str):
            datatype = str(datatype)
        dtype = datatype.strip().lower()
        if allow_thehive and dtype.startswith('thehive:'):
            return dtype
        if dtype not in InputValidator.allowed_types():
            raise ValueError(f"Datatype non valido: {dtype}")
        return dtype

    @staticmethod
    def validate_observable_by_type(datatype: str, data: str) -> None:
        if datatype == 'ip':
            try:
                ipaddress.ip_address(data)
                return
            except Exception:
                raise ValueError("IP non valido")
        if datatype in ('domain', 'fqdn'):
            if not re.match(config.DOMAIN_REGEX, data):
                raise ValueError("Domain non valido")
            return
        if datatype == 'url':
            if not re.match(config.URL_REGEX, data):
                raise ValueError("URL non valido")
            return
        if datatype in ('hash', 'certificate_hash'):
            if not (re.match(config.MD5_REGEX, data) or re.match(config.SHA256_REGEX, data)):
                raise ValueError("Hash non valido")
            return
        if datatype == 'mail':
            if not re.match(config.EMAIL_REGEX, data):
                raise ValueError("Email non valida")
            return
        # Per gli altri tipi accetta stringhe non vuote
        return

def get_cached_report(job_id):
    """
    Recupera report dalla cache o da Cortex.
    Usa il CacheManager configurato in fuco.py
    """
    from flask import current_app
    cache_manager = current_app.cache_manager
    
    # 1. Controlla cache
    report = cache_manager.get_report(job_id)
    if report:
        logger.debug(f"Report {job_id} recuperato da cache")
        return report
    
    # 2. Non in cache, recupera da Cortex
    logger.info(f"Report {job_id} non in cache, recupero da Cortex")
    
    try:
        report = cortex_api_call(cortex_api.jobs.get_report, job_id)
        
        # 3. Salva in cache SOLO se status finale
        final_statuses = ("Success", "Failure", "Deleted")
        
        if hasattr(report, 'status') and report.status in final_statuses:
            cache_manager.set_report(job_id, report)
            logger.info(f"Report {job_id} salvato in cache (status: {report.status})")
        else:
            current_status = getattr(report, 'status', 'Unknown')
            logger.debug(
                f"Report {job_id} NON salvato in cache "
                f"(status non finale: {current_status})"
            )
        
        return report
        
    except Exception as e:
        logger.error(f"Errore recupero report {job_id}: {str(e)}")
        raise


def clear_report_cache(job_id=None):
    """
    Pulisce la cache dei report.
    
    Args:
        job_id: Se specificato, rimuove solo quel report. 
                Altrimenti pulisce tutta la cache.
    """
    from flask import current_app
    cache_manager = current_app.cache_manager
    
    if job_id:
        success = cache_manager.delete_report(job_id)
        if success:
            logger.info(f"Report {job_id} rimosso dalla cache")
        return success
    else:
        success = cache_manager.clear_all()
        if success:
            logger.info("Cache completa svuotata")
        return success


def get_cache_stats():
    """Ritorna statistiche sulla cache."""
    from flask import current_app
    cache_manager = current_app.cache_manager
    return cache_manager.get_stats()


# Wrapper per chiamate API con retry
def cortex_api_call(func, *args, **kwargs):
    """
    Wrapper per chiamate API Cortex con retry e timeout.
    Gestisce errori di rete temporanei con exponential backoff.
    """
    max_retries = 3
    timeout = kwargs.pop('timeout', 30)  # Timeout di 30 secondi
    
    for attempt in range(max_retries):
        try:
            # Esegui la chiamata API
            result = func(*args, **kwargs)
            return result
            
        except ConnectionError as e:
            logger.warning(f"ConnectionError tentativo {attempt+1}/{max_retries}: {str(e)}")
            if attempt == max_retries - 1:
                raise Exception(f"Impossibile connettersi a Cortex dopo {max_retries} tentativi")
            time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
            
        except TimeoutError as e:
            logger.warning(f"Timeout tentativo {attempt+1}/{max_retries}")
            if attempt == max_retries - 1:
                raise Exception(f"Timeout dopo {max_retries} tentativi")
            time.sleep(2 ** attempt)
            
        except Exception as e:
            logger.error(f"Errore API Cortex: {str(e)}")
            # Se è un errore 4xx (client error), non ritentare
            if hasattr(e, 'response') and e.response and 400 <= e.response.status_code < 500:
                raise
            # Altrimenti ritenta
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)

def get_analyzer_by_type(analyzer_type: str):
    """Ottiene gli analyzer per un tipo di dato specifico."""
    try:
        #analyzers = cortex_api.analyzers.get_by_type(analyzer_type)
        analyzers = cortex_api_call(cortex_api.analyzers.get_by_type, analyzer_type)
        
        logger.info(f"Ottenuti {len(analyzers) if analyzers else 0} analyzer per tipo: {analyzer_type}")
        return analyzers
    except Exception as e:
        logger.error(f"Errore nel recupero degli analyzer per tipo {analyzer_type}: {str(e)}")
        return []


def get_recent_searches():
    """Recupera le 10 ricerche recenti per ogni tipo di dato."""
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
            # Escludi datatype TheHive (azioni responder)
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
        
        logger.info(f"Recuperate ricerche recenti: {sum(len(items) for items in recent.values())} elementi")
        return recent
    except Exception as e:
        logger.error(f"Errore nel recupero delle ricerche recenti: {str(e)}")
        return {}

def run_analysis(analyzer: str, datatype: str, data: str, tlp: int = None, pap: int = None) -> dict:
    """
    Esegue un'analisi tramite un analyzer specifico.
    
    Args:
        analyzer: Nome dell'analyzer
        datatype: Tipo di dato (ip, domain, url, hash, etc.)
        data: Dato da analizzare
        tlp: Traffic Light Protocol level (0-3). Se None, usa config.DEFAULT_TLP
        pap: Permissible Actions Protocol level (0-3). Se None, usa config.DEFAULT_PAP
    
    Returns:
        dict: Risultato JSON del job sottomesso
    
    TLP/PAP Levels:
        0 = WHITE
        1 = GREEN
        2 = AMBER (default)
        3 = RED
    """
    # Usa i valori di default se non specificati
    if tlp is None:
        tlp = config.DEFAULT_TLP
    if pap is None:
        pap = config.DEFAULT_PAP
    
    # Validazione
    if not (0 <= tlp <= 3):
        logger.warning(f"TLP invalido {tlp}, uso default {config.DEFAULT_TLP}")
        tlp = config.DEFAULT_TLP
    if not (0 <= pap <= 3):
        logger.warning(f"PAP invalido {pap}, uso default {config.DEFAULT_PAP}")
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
        
        logger.info(f"Job avviato: {analyzer} per {datatype} '{data}' (ID: {job.id}) - TLP:{tlp} PAP:{pap}")
        return job.json()
        
    except Exception as e:
        logger.error(f"Errore durante l'avvio dell'analisi: {str(e)}")
        raise



def poll_job(job_id: str, max_attempts: int = None, initial_delay: int = None):
    """
    Esegue il polling di un job fino a completamento.
    
    Args:
        job_id: ID del job da monitorare
        max_attempts: Numero massimo di tentativi (default: config.DEFAULT_MAX_ATTEMPTS)
        initial_delay: Delay iniziale in secondi (default: config.DEFAULT_INITIAL_DELAY)
    
    Returns:
        Report se completato, None se timeout
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
                logger.info(f"Job {job_id} completato con status: {report.status}")
                return report
        
        logger.warning(f"Job {job_id} non completato dopo {max_attempts} tentativi")
        return None
    except Exception as e:
        logger.error(f"Errore durante il polling del job {job_id}: {str(e)}")
        return None


def extract_taxonomies(report) -> list:
    """Estrae le taxonomies dal report, con fallback a valore di default."""
    try:
        taxonomies = report.report['summary']['taxonomies']
        logger.debug(f"Estratte {len(taxonomies)} taxonomies dal report")
        return taxonomies
    except (KeyError, TypeError) as e:
        logger.debug(f"Taxonomies non trovate nel report, usando default: {str(e)}")
        return [{
            "level": "undef",
            "namespace": report.analyzerName,
            "predicate": "Summary",
            "value": "NoData"
        }]


def render_short_template(taxonomies: list, analyzer_name: str, app_root_path: str) -> str:
    """
    Renderizza il template short per le taxonomies.

    Contratto template:
      - riceve SEMPRE una lista: taxonomies
      - ogni elemento ha: level, namespace, predicate, value, css

    Args:
        taxonomies: lista di taxonomies
        analyzer_name: nome analyzer per template specifico
        app_root_path: root path applicazione Flask

    Returns:
        HTML renderizzato
    """
    try:
        # Path template (OS-agnostic)
        template_dir = os.path.join(app_root_path, config.TEMPLATE_FOLDER)
        short_template_dir = os.path.join(template_dir, "short")

        logger.debug(f"Short template dir: {short_template_dir}")

        # Ambiente Jinja2 coerente e sicuro
        env = Environment(
            loader=FileSystemLoader(short_template_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Normalizza taxonomies + CSS
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

        # Se non ci sono taxonomies, esci pulito
        if not normalized_taxonomies:
            logger.debug("Nessuna taxonomy da renderizzare")
            return ""

        # Template specifico analyzer
        specific_template_name = f"{analyzer_name}.short.html"
        specific_template_path = os.path.join(short_template_dir, specific_template_name)

        if os.path.exists(specific_template_path):
            logger.info(f"Usando template short specifico: {specific_template_name}")
            template = env.get_template(specific_template_name)
        else:
            logger.info("Template specifico non trovato, uso generic.short.html")
            template = env.get_template("generic.short.html")

        # Render UNICO (niente concatenazioni manuali)
        html = template.render(taxonomies=normalized_taxonomies)
        html = sanitize_html(html)

        logger.debug("Rendering short template completato")
        return html

    except FileNotFoundError as e:
        logger.error(f"Template non trovato: {e}")
        return "<p>Errore nel caricamento delle taxonomies (template non trovato).</p>"

    except Exception as e:
        logger.exception("Errore nel rendering short template")
        return "<p>Errore nel caricamento delle taxonomies.</p>"

def resolve_long_template(report, app_root_path: str) -> Optional[str]:
    """
    Risolve il template LONG corretto per l'analyzer.

    NON renderizza HTML.
    Ritorna solo il nome del template LONG da usare.

    Args:
        report: oggetto report/analyzer result
        app_root_path: root path dell'app Flask

    Returns:
        Nome del template LONG o None
    """
    try:
        template_dir = os.path.join(
            app_root_path,
            config.TEMPLATE_FOLDER,
            "long"
        )

        analyzer_name = getattr(report, "analyzerName", None)
        if not analyzer_name:
            logger.warning("report.analyzerName mancante")
            return None

        template_name = f"{analyzer_name}.long.html"
        template_path = os.path.join(template_dir, template_name)

        if os.path.isfile(template_path):
            logger.info(f"Template LONG trovato: {template_name}")
            return f"long/{template_name}"
            # return template_name

        logger.info(f"Template LONG specifico non trovato: {template_name}")
        return None

    except Exception as e:
        logger.exception("Errore nella risoluzione del template LONG")
        return None


def detect_data_type(data: str) -> str:
    """
    Rileva automaticamente il tipo di dato basandosi su pattern regex.
    
    Args:
        data: Dato da analizzare
    
    Returns:
        Tipo di dato rilevato o None se non riconosciuto
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
    
    logger.warning(f"Impossibile rilevare il tipo di dato per: {data}")
    return None


def validate_ip_address(ip: str) -> bool:
    """Valida se un indirizzo IP è pubblico e valido."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False


def parse_multiple_ips(raw_data: str) -> list:
    """Estrae e valida indirizzi IP multipli da una stringa separata da virgole."""
    ips = []
    try:
        candidates = [ip.strip() for ip in raw_data.split(',')]
        for ip in candidates:
            if validate_ip_address(ip):
                ips.append(ip)
        logger.info(f"Estratti {len(ips)} IP pubblici validi da input")
        return ips
    except Exception as e:
        logger.error(f"Errore nel parsing degli IP: {str(e)}")
        return []
