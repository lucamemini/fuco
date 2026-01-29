"""
Routes Flask per l'applicazione FUCO
"""
from io import BytesIO
import json
import logging
import sys
from typing import List, Optional
from urllib.parse import quote
from functools import wraps

from flask import render_template, request, jsonify, Blueprint, current_app, abort
from pydantic import BaseModel, Field, validator

from concurrent.futures import ThreadPoolExecutor, as_completed

import utils
import config

from datetime import datetime
from flask import jsonify, current_app

# printing 
try:
    if not sys.platform.startswith("win"):
        from weasyprint import HTML
    else:
        HTML = None
except Exception:
    HTML = None

# Configurazione logging
logger = logging.getLogger(__name__)

# Blueprint per le route
routes_bp = Blueprint('routes', __name__)

# ============ IP Filtering Decorator ============

def ip_whitelist_required(allowed_ips=None):
    """
    Decorator per limitare l'accesso a specifici IP.
    
    Args:
        allowed_ips: Lista di IP consentiti. Se None, usa config.ALLOWED_IPS
    
    Usage:
        @ip_whitelist_required(['127.0.0.1', '192.168.1.100'])
        def my_route():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Usa gli IP dal parametro o dal config
            whitelist = allowed_ips or getattr(config, 'ALLOWED_IPS', ['127.0.0.1', '::1'])
            
            # Ottieni l'IP del client
            if request.headers.get('X-Forwarded-For'):
                # Se dietro reverse proxy (nginx, apache)
                client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            elif request.headers.get('X-Real-IP'):
                # Header alternativo per reverse proxy
                client_ip = request.headers.get('X-Real-IP')
            else:
                # Connessione diretta
                client_ip = request.remote_addr
            
            logger.debug(f"IP client rilevato: {client_ip}")
            
            # Verifica se l'IP è nella whitelist
            if client_ip not in whitelist:
                logger.warning(f"Accesso negato per IP non autorizzato: {client_ip}")
                return jsonify({
                    'error': 'Access denied',
                    'message': 'Your IP address is not authorized to access this resource'
                }), 403
            
            logger.debug(f"IP {client_ip} autorizzato")
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# ============ Modelli Pydantic per validazione ============

class ShortRequest(BaseModel):
    """Modello di validazione per /api/short"""
    Data: str = Field(..., min_length=1, max_length=255)
    DataType: Optional[str] = None
    analyzer_list: List[str] = Field(..., min_items=1)
    
    @validator('analyzer_list')
    def validate_analyzers(cls, v):
        if not all(isinstance(x, str) and len(x) > 0 for x in v):
            raise ValueError('analyzer_list deve contenere stringhe non vuote')
        return v


class AnalysisRequest(BaseModel):
    """Modello di validazione per /api/analysis"""
    Data: str = Field(..., min_length=1, max_length=255)
    DataType: Optional[str] = None
    analyzer_list: List[str] = Field(..., min_items=1)


# ============ Funzioni helper ============

def error_response(message: str, code: int = 500):
    """Helper per generare risposte di errore JSON."""
    logger.error(f"Errore ({code}): {message}")
    return jsonify({"error": message}), code

# ============ Route HTML ============


@routes_bp.route('/export/pdf', methods=['POST'])
def export_pdf():
    """
    Esporta i risultati in PDF.
    Riceve via POST i dati delle analisi e genera un PDF.
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Nessun dato fornito", 400)
        
        observable = data.get('observable')
        datatype = data.get('datatype')
        jobs = data.get('jobs', [])
        
        if not observable or not jobs:
            return error_response("Parametri mancanti", 400)
        
        logger.info(f"Generazione PDF per {observable} con {len(jobs)} job")
        
        # Recupera i report completi per ogni job
        reports_data = []
        for job in jobs:
            job_id = job.get('id')
            try:
                # Usa la cache se disponibile
                report = get_cached_report(job_id)
                
                if report and report.status == "Success":
                    reports_data.append({
                        'id': job_id,
                        'analyzer': job.get('analyzer'),
                        'report': report,
                        'html': render_report_html(report, current_app.root_path)
                    })
            except Exception as e:
                logger.error(f"Errore recupero report {job_id}: {str(e)}")
                continue
        
        # Renderizza il template PDF
        html_content = render_template('pdf_export.html',
                                     observable=observable,
                                     datatype=datatype,
                                     reports=reports_data,
                                     timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Converti HTML in PDF
        pdf_buffer = BytesIO()
        if HTML is None:
            raise RuntimeError("PDF rendering disabled on this platform")
        
        HTML(string=html_content, base_url=request.url_root).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        
        # Crea response
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=fuco_report_{observable}.pdf'
        
        logger.info(f"PDF generato con successo per {observable}")
        return response
        
    except Exception as e:
        logger.error(f"Errore generazione PDF: {str(e)}", exc_info=True)
        return error_response(f"Errore nella generazione del PDF: {str(e)}", 500)


def render_report_html(report, app_root_path):
    """
    Renderizza il report in HTML per il PDF.
    Usa lo stesso sistema dei template LONG.
    """
    try:
        template_name = utils.resolve_long_template(report, app_root_path)
        generic_template = "long/generic.long.html"
        
        if not template_name:
            template_name = generic_template
        
        try:
            return render_template(template_name, artifact=report)
        except Exception:
            return render_template(generic_template, artifact=report)
            
    except Exception as e:
        logger.error(f"Errore rendering report HTML: {str(e)}")
        return f"<div class='alert alert-danger'>Errore nel rendering: {str(e)}</div>"


@routes_bp.route('/')
def home():
    """Homepage con form di ricerca e ricerche recenti."""
    try:
        # DEBUG
        q_param = request.args.get('q')
        type_param = request.args.get('t')

        # Se non è stringa, è un problema del frontend
        if not isinstance(type_param, str):
#           logger.error("TYPE NON È STRINGA!")
           q_param = ''
           type_param = '_default'
           
        if q_param and type_param:
            return render_template('index.html', q=q_param, t=type_param)
        else:
            result = utils.get_analyzer_by_type("_default")
            recent = utils.get_recent_searches()
            return render_template('index.html', t=result, recent=recent)
    except Exception as e:
        logger.error(f"Errore in home(): {str(e)}")
        return error_response(str(e))

@routes_bp.route("/favicon.ico")
def favicon():
    return "", 204

@routes_bp.route('/getAnalyzer', methods=['GET'])
def get_analyzer():
    """Restituisce gli analyzer per un tipo di dato."""
    try:
        analyzer_type = str(request.args.get('type', 'domain'))
        result = utils.get_analyzer_by_type(analyzer_type)
        return render_template('analyzer.html', data=result)
    except Exception as e:
        logger.error(f"Errore in get_analyzer(): {str(e)}")
        return error_response(str(e))


@routes_bp.route("/analysis", methods=["POST"])
def analysis():
    """
    Renderizza IMMEDIATAMENTE la pagina report.
    I job vengono sottomessi via AJAX dal browser con TLP/PAP custom.
    """
    try:
        data = request.form.get('tosearch')
        if not data:
            return error_response("Parametro 'tosearch' mancante", 400)
        
        datatype = request.form.get('DataType')
        if not datatype:
            return error_response("Parametro 'DataType' mancante", 400)
        
        analyzer_list = request.form.getlist('analyzer')
        if not analyzer_list:
            return error_response("Nessun analyzer selezionato", 400)
        
        # NUOVO: Recupera TLP/PAP dal form
        try:
            tlp = int(request.form.get('tlp', config.DEFAULT_TLP))
            pap = int(request.form.get('pap', config.DEFAULT_PAP))
        except (ValueError, TypeError):
            tlp = config.DEFAULT_TLP
            pap = config.DEFAULT_PAP
        
        # Validazione TLP/PAP (0-3)
        if not (0 <= tlp <= 3):
            logger.warning(f"TLP invalido ricevuto: {tlp}, uso default {config.DEFAULT_TLP}")
            tlp = config.DEFAULT_TLP
        if not (0 <= pap <= 3):
            logger.warning(f"PAP invalido ricevuto: {pap}, uso default {config.DEFAULT_PAP}")
            pap = config.DEFAULT_PAP
        
        logger.info(f"Richiesta analisi per '{data}' ({datatype}) con {len(analyzer_list)} analyzer - TLP:{tlp} PAP:{pap}")
        
        # Prepara i dati per il template (SENZA sottomettere job)
        result = {
            'fuco': {
                'question': data,
                'datatype': datatype,
                'tlp': tlp,
                'pap': pap
            },
            'analyzers': sorted(analyzer_list, key=str.lower)
        }
        
        # Renderizza IMMEDIATAMENTE
        logger.info("Rendering immediato della pagina report")
        return render_template('report_async.html', data=result)
        
    except Exception as e:
        logger.error(f"Errore in analysis(): {str(e)}", exc_info=True)
        return error_response(str(e))

@routes_bp.route('/api/submit_job', methods=['POST'])
def api_submit_job():
    """
    API per sottomettere UN SINGOLO job a Cortex.
    Chiamata via AJAX dal browser.
    NUOVO: Supporta TLP/PAP custom per job.
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return error_response("Nessun dato JSON fornito", 400)
        
        analyzer = request_data.get('analyzer')
        datatype = request_data.get('datatype')
        data = request_data.get('data')
        
        # NUOVO: Recupera TLP/PAP (opzionali, usa default se mancanti)
        try:
            tlp = int(request_data.get('tlp', config.DEFAULT_TLP))
            pap = int(request_data.get('pap', config.DEFAULT_PAP))
        except (ValueError, TypeError):
            tlp = config.DEFAULT_TLP
            pap = config.DEFAULT_PAP
        
        # Validazione
        if not all([analyzer, datatype, data]):
            return error_response("Parametri mancanti (analyzer, datatype, data)", 400)
        
        if not (0 <= tlp <= 3):
            tlp = config.DEFAULT_TLP
        if not (0 <= pap <= 3):
            pap = config.DEFAULT_PAP
        
        logger.info(f"Sottomissione job: {analyzer} per {data} - TLP:{tlp} PAP:{pap}")
        
        # Sottometti il job a Cortex CON TLP/PAP custom
        job_result = utils.run_analysis(analyzer, datatype, data, tlp=tlp, pap=pap)
        
        return jsonify({
            'status': 'success',
            'job_id': job_result['id'],
            'analyzer': analyzer,
            'tlp': tlp,
            'pap': pap
        })
        
    except Exception as e:
        logger.error(f"Errore in api_submit_job(): {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@routes_bp.route('/api/poll_job/<job_id>', methods=['GET'])
def api_poll_job(job_id):
    """
    API per il polling di un singolo job.
    Restituisce lo stato corrente del job.
    """
    try:
        # Polling con max_attempts=1 (controlla solo lo stato attuale)
        report = utils.poll_job(job_id, max_attempts=1, initial_delay=0)
        
        if not report:
            return jsonify({
                'status': 'pending',
                'job_id': job_id
            })
        
        if report.status == "Success":
            return jsonify({
                'status': 'success',
                'job_id': job_id,
                'analyzer_name': report.analyzerName
            })
        elif report.status == "InProgress" or report.status == "Waiting":
            return jsonify({
                'status': 'pending',
                'job_id': job_id
            })
        else:
            # Failure, Timeout, ecc.
            return jsonify({
                'status': 'failed',
                'job_id': job_id,
                'report_status': report.status
            })
            
    except Exception as e:
        logger.error(f"Errore polling job {job_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'job_id': job_id,
            'error': str(e)
        }), 500

# ============ Route API ============

@routes_bp.route('/api/short', methods=['POST'])
def api_short():
    """
    API per analisi brevi con supporto a IP multipli.
    Restituisce solo le taxonomies per ogni analyzer.
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return error_response("Nessun dato JSON fornito", 400)
        
        # Validazione con Pydantic
        try:
            short_req = ShortRequest(**request_data)
        except ValueError as e:
            return error_response(f"Dati non validi: {str(e)}", 400)
        
        raw_data = short_req.Data
        datatype = short_req.DataType
        analyzer_list = short_req.analyzer_list
        
        # Determinazione del tipo di dato se non specificato
        input_items = []
        if not datatype:
            # Caso IP multipli
            if ',' in raw_data:
                ips = utils.parse_multiple_ips(raw_data)
                if not ips:
                    return error_response("Nessun IP pubblico valido trovato", 400)
                input_items = [(ip, "ip") for ip in ips]
            else:
                detected_type = utils.detect_data_type(raw_data)
                if not detected_type:
                    return error_response("Impossibile determinare automaticamente il tipo di dato", 400)
                input_items = [(raw_data, detected_type)]
        else:
            # DataType esplicitamente specificato
            if datatype.lower() == "ip" and ',' in raw_data:
                ips = utils.parse_multiple_ips(raw_data)
                if not ips:
                    return error_response("Nessun IP pubblico valido trovato", 400)
                input_items = [(ip, "ip") for ip in ips]
            else:
                input_items = [(raw_data, datatype.lower())]
        
        # Esecuzione delle analisi
        job_results = []
        for data, dtype in input_items:
            for analyzer in analyzer_list:
                try:
                    job_result = utils.run_analysis(analyzer, dtype, data)
                    job_results.append((data, analyzer, job_result))
                except Exception as e:
                    logger.error(f"Errore nell'avvio dell'analisi: {str(e)}")
                    return error_response(str(e), 500)
        
        # Polling dei job
        final_results = []
        for data, analyzer, job in job_results:
            job_id = job['id']
            report = utils.poll_job(job_id, config.API_SHORT_MAX_ATTEMPTS, config.API_SHORT_INITIAL_DELAY)
            
            result_entry = {
                "input": data,
                "analyzer": analyzer,
                "status": report.status if report else "Timeout",
            }
            
            if report and report.status == "Success":
                result_entry["taxonomies"] = utils.extract_taxonomies(report)
            else:
                result_entry["taxonomies"] = [{
                    "level": "undef",
                    "namespace": analyzer,
                    "predicate": "Summary",
                    "value": "Error" if report else "Timeout"
                }]
            
            final_results.append(result_entry)
        
        return jsonify(final_results)
    
    except Exception as e:
        logger.error(f"Errore in api_short(): {str(e)}")
        return error_response(str(e), 500)


@routes_bp.route('/api/analysis', methods=['POST'])
def api_analysis():
    """
    API per analisi complete che restituisce il report completo.
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return error_response("Nessun dato JSON fornito", 400)
        
        # Validazione con Pydantic
        try:
            analysis_req = AnalysisRequest(**request_data)
        except ValueError as e:
            return error_response(f"Dati non validi: {str(e)}", 400)
        
        data = analysis_req.Data
        datatype = analysis_req.DataType
        analyzer_list = analysis_req.analyzer_list
        
        # Determinazione del tipo di dato se non specificato
        if not datatype:
            datatype = utils.detect_data_type(data)
            if not datatype:
                return error_response("Impossibile determinare automaticamente il tipo di dato", 400)
        
        # Esecuzione delle analisi
        job_results = []
        for analyzer in analyzer_list:
            try:
                job_result = utils.run_analysis(analyzer, datatype, data)
                job_results.append(job_result)
            except Exception as e:
                logger.error(f"Errore nell'avvio dell'analisi: {str(e)}")
                return error_response(str(e), 500)
        
        # Polling dei job
        final_results = []
        for job in job_results:
            job_id = job['id']
            report = utils.poll_job(job_id, config.API_SHORT_MAX_ATTEMPTS, config.API_SHORT_INITIAL_DELAY)
            
            if report and report.status == "Success":
                final_results.append(report.json())
            else:
                final_results.append({
                    "id": job_id,
                    "status": report.status if report else "Timeout",
                    "error": "Analisi non completata"
                })
        
        response = {
            "question": data,
            "datatype": datatype,
            "results": final_results
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Errore in api_analysis(): {str(e)}")
        return error_response(str(e), 500)


@routes_bp.route('/api/getAnalyzer', methods=['GET'])
def api_get_analyzer():
    """API per ottenere la lista di tutti gli analyzer disponibili."""
    try:
        all_analyzers = []
        all_data_types = set()
        
        # Raccoglie analyzer per ogni tipo
        for analyzer_type in config.ANALYZER_TYPES:
            try:
                analyzers = utils.get_analyzer_by_type(analyzer_type)
                if analyzers:
                    for analyzer in analyzers:
                        if not any(a.get('name') == analyzer.name for a in all_analyzers):
                            analyzer_data = {
                                "id": analyzer.id if hasattr(analyzer, 'id') else "N/A",
                                "name": analyzer.name if hasattr(analyzer, 'name') else "N/A",
                                "version": analyzer.version if hasattr(analyzer, 'version') else "N/A",
                                "description": analyzer.description if hasattr(analyzer, 'description') else "N/A",
                                "dataTypeList": analyzer.dataTypeList if hasattr(analyzer, 'dataTypeList') else [],
                                "type": analyzer_type
                            }
                            all_analyzers.append(analyzer_data)
                            
                            if hasattr(analyzer, 'dataTypeList'):
                                for data_type in analyzer.dataTypeList:
                                    all_data_types.add(data_type)
            except Exception as e:
                logger.warning(f"Errore nel recupero degli analyzer per tipo {analyzer_type}: {str(e)}")
                continue
        
        response = {
            "analyzers": all_analyzers,
            "supportedDataTypes": list(all_data_types)
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Errore in api_get_analyzer(): {str(e)}")
        return error_response(str(e), 500)


# ============ Route di supporto ============

@routes_bp.route('/getAnalisys', methods=['GET'])
def get_analysis():
    analysis_id = request.args.get('JobId')
    if not analysis_id:
        abort(400, "Missing analysis id")

    report = utils.get_cached_report(analysis_id)

    template_name = utils.resolve_long_template(report, current_app.root_path)
    generic_template = "long/generic.long.html"

    if not template_name:
        logger.warning("Template specifico non trovato, uso generico")
        template_name = generic_template

    try:
        return render_template(template_name, artifact=report)

    except Exception as e:
        logger.error(
            "Errore rendering template %s, fallback su generico",
            template_name,
            exc_info=True
        )

        try:
            return render_template(generic_template, artifact=report)
        except Exception:
            logger.critical(
                "Errore anche nel template generico",
                exc_info=True
            )
            abort(500, "Template rendering failed")

@routes_bp.route('/getShort', methods=['GET'])
def get_short():
    """Restituisce il template short per le taxonomies di un job."""
    try:
        job_id = str(request.args.get('JobId'))
        if not job_id:
            return error_response("Parametro 'JobId' mancante", 400)
        
        report = utils.poll_job(job_id, config.GET_SHORT_MAX_ATTEMPTS, config.GET_SHORT_INITIAL_DELAY)
        if not report:
            return error_response("Job non completato o timeout", 408)
        
        taxonomies = utils.extract_taxonomies(report)
        html = utils.render_short_template(taxonomies, report.analyzerName, current_app.root_path)
        return html
    
    except Exception as e:
        logger.error(f"Errore in get_short(): {str(e)}")
        return error_response(str(e), 500)

@routes_bp.route('/allReports', methods=['GET'])
def all_reports():
    """
    Visualizza tutti i report già esistenti per un osservabile specifico.
    Recupera dalla cache di Cortex SENZA risubmittare le analisi.
    """
    try:
        observable = request.args.get('observable')
        datatype = request.args.get('datatype')
        
        if not observable:
            return error_response("Parametro 'observable' mancante", 400)
        if not datatype:
            return error_response("Parametro 'datatype' mancante", 400)
        
        logger.info(f"Ricerca report esistenti per: {observable} (tipo: {datatype})")
        
        from utils import cortex_api
        
        try:
            logger.info("Recupero job recenti da Cortex")
            all_jobs = list(cortex_api.jobs.find_all(
                {},
                range=config.LAST_ANALYSIS_RANGE, 
                sort='-createdAt'
            ))
            logger.info(f"Recuperati {len(all_jobs)} job totali")
            
            # Filtro manuale per observable e datatype
            jobs = []
            for job in all_jobs:
                if (hasattr(job, 'data') and job.data == observable and 
                    hasattr(job, 'dataType') and job.dataType == datatype and
                    hasattr(job, 'status') and job.status == 'Success'):
                    jobs.append(job)
            
            logger.info(f"Trovati {len(jobs)} job Success per {observable} ({datatype})")
            
        except Exception as e:
            logger.error(f"Errore nella query Cortex: {str(e)}", exc_info=True)
            jobs = []
        
        if not jobs:
            logger.info(f"Nessun report trovato per {observable}")
            return render_template('no_reports.html', 
                                 observable=observable, 
                                 datatype=datatype)
        
        # Prepara la struttura dati per il template
        result = {
            'fuco': {
                'question': observable,
                'datatype': datatype
            },
            'jobs': []
        }
        
        # Raccoglie i job con le loro informazioni
        for job in jobs:
            job_info = {
                'id': job.id,
                'analyzer': job.workerName if hasattr(job, 'workerName') else 'Unknown',
                'status': job.status,
                'createdAt': job.createdAt if hasattr(job, 'createdAt') else None,
                'startDate': job.startDate if hasattr(job, 'startDate') else None,
                'endDate': job.endDate if hasattr(job, 'endDate') else None,
                'createdBy': job.createdBy if hasattr(job, 'createdBy') else None,
            }
            result['jobs'].append(job_info)
        
        result['jobs'] = sorted(result['jobs'], key=lambda x: x.get('analyzer', '').lower())
        logger.info(f"Rendering {len(result['jobs'])} report per {observable}")
        return render_template('all_reports.html', data=result)
    
    except Exception as e:
        logger.error(f"Errore in all_reports(): {str(e)}", exc_info=True)
        return error_response(str(e), 500)


# ============ API Cache (PROTETTE DA IP WHITELIST) ============

@routes_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint per monitoring/load balancer.
    Verifica stato cache e connessione Cortex.
    """
    health = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': 'FUCO 1.0',
        'components': {}
    }
    
    # Check cache backend
    try:
        cache_manager = current_app.cache_manager
        if cache_manager.ping():
            health['components']['cache'] = {
                'status': 'ok',
                'type': config.CACHE_TYPE
            }
        else:
            health['components']['cache'] = {
                'status': 'down',
                'type': config.CACHE_TYPE
            }
            health['status'] = 'degraded'
    except Exception as e:
        health['components']['cache'] = {
            'status': 'error',
            'error': str(e)
        }
        health['status'] = 'degraded'
    
    # Check Cortex (opzionale, commentabile se troppo lento)
    try:
        from utils import cortex_api
        cortex_api.analyzers.find_all({}, range='0-1')
        health['components']['cortex'] = {'status': 'ok'}
    except Exception as e:
        health['components']['cortex'] = {
            'status': 'error',
            'error': str(e)
        }
        health['status'] = 'degraded'
    
    status_code = 200 if health['status'] == 'healthy' else 503
    return jsonify(health), status_code


@routes_bp.route('/api/cache/stats', methods=['GET'])
@ip_whitelist_required()  # Usa la configurazione di default da config.py
def cache_stats():
    """
    Endpoint di debug per vedere lo stato della cache.
    PROTETTO: Solo IP nella whitelist possono accedere.
    """
    try:
        stats = utils.get_cache_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Errore nel recupero stats cache: {str(e)}")
        return error_response(str(e), 500)


@routes_bp.route('/api/cache/clear', methods=['POST'])
@ip_whitelist_required()  # Usa la configurazione di default da config.py
def clear_cache():
    """
    Endpoint per svuotare la cache manualmente.
    PROTETTO: Solo IP nella whitelist possono accedere.
    """
    try:
        data = request.get_json()
        job_id = data.get('job_id') if data else None
        
        utils.clear_report_cache(job_id)
        
        return jsonify({
            'success': True,
            'message': f'Cache cleared for job {job_id}' if job_id else 'All cache cleared'
        })
    except Exception as e:
        logger.error(f"Errore nella pulizia cache: {str(e)}")
        return error_response(str(e), 500)

# @app.route('/bulk-responder')
@routes_bp.route('/bulk-responder', methods=['GET'])
def bulk_responder_page():
    return render_template('bulk_responder.html')