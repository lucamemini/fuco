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

# cache
from functools import lru_cache
from datetime import datetime, timedelta

import fucoconfig as cfg
from cortex4py.api import Api
from cortex4py.query import And, Eq
import config

# Configurazione logging
logger = logging.getLogger(__name__)

# API Cortex
cortex_api = Api(cfg.cortex["host"], cfg.cortex["apikey"])


# Cache per report (semplice, in-memory)
_report_cache = {}
_cache_ttl = timedelta(minutes=config.CACHE_TTL_MINUTES)

def get_cached_report(job_id):
    """Recupera report dalla cache o da Cortex"""
    if job_id in _report_cache:
        cached_time, report = _report_cache[job_id]
        if datetime.now() - cached_time < _cache_ttl:
            logger.info(f"Report {job_id} recuperato da cache")
            return report
    
    # Altrimenti recupera da Cortex
    report = cortex_api.jobs.get_report(job_id)
    _report_cache[job_id] = (datetime.now(), report)
    return report

def get_analyzer_by_type(analyzer_type: str):
    """Ottiene gli analyzer per un tipo di dato specifico."""
    try:
        analyzers = cortex_api.analyzers.get_by_type(analyzer_type)
        logger.info(f"Ottenuti {len(analyzers) if analyzers else 0} analyzer per tipo: {analyzer_type}")
        return analyzers
    except Exception as e:
        logger.error(f"Errore nel recupero degli analyzer per tipo {analyzer_type}: {str(e)}")
        return []


def get_recent_searches():
    """Recupera i 10 ricerche recenti per ogni tipo di dato."""
    try:
        query = And(Eq('status', 'Success'))
        jobs = cortex_api.jobs.find_all(query, range=config.JOB_SEARCH_RANGE, sort='-createdAt')
        recent = {}
        
        for job in jobs:
            dt = job.dataType
            if dt not in recent:
                recent[dt] = {}
            data = job.data
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


def run_analysis(analyzer: str, datatype: str, data: str) -> dict:
    """Esegue un'analisi tramite un analyzer specifico."""
    try:
        job = cortex_api.analyzers.run_by_name(analyzer, {
            'data': data,
            'dataType': datatype,
            'pap': config.DEFAULT_PAP,
            'tlp': config.DEFAULT_TLP
        }, force=1)
        logger.info(f"Job avviato: {analyzer} per {datatype} '{data}' (ID: {job.id})")
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
