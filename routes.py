"""
Routes Flask per l'applicazione FUCO
"""
import json
import logging
from typing import List, Optional
from urllib.parse import quote

from flask import render_template, request, jsonify, Blueprint, current_app, abort
from pydantic import BaseModel, Field, validator

import utils
import config


# Configurazione logging
logger = logging.getLogger(__name__)

# Blueprint per le route
routes_bp = Blueprint('routes', __name__)


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

def fang(s):
    """Custom filter: upper-case a string"""
    try:
        return s.upper()
    except Exception:
        return s


def urlencode_filter(s):
    """Custom filter: URL encode a string"""
    return quote(str(s))


def error_response(message: str, code: int = 500):
    """Helper per generare risposte di errore JSON."""
    logger.error(f"Errore ({code}): {message}")
    return jsonify({"error": message}), code


# ============ Route HTML ============

@routes_bp.route('/')
def home():
    """Homepage con form di ricerca e ricerche recenti."""
    try:
        q_param = request.args.get('q')
        type_param = request.args.get('t')
        if q_param and type_param:
            return render_template('index.html', q=q_param, t=type_param)
        else:
            result = utils.get_analyzer_by_type("domain")
            recent = utils.get_recent_searches()
            return render_template('index.html', t=result, recent=recent)
    except Exception as e:
        logger.error(f"Errore in home(): {str(e)}")
        return error_response(str(e))


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


@routes_bp.route('/analysis', methods=['POST'])
def analysis():
    """Route tradizionale per form submissions (non API)."""
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
        
        result = {}
        result['analysis'] = []
        result['fuco'] = {}
        result['fuco']['question'] = data
        result['fuco']['datatype'] = datatype
        
        # Esecuzione delle analisi e polling dei job
        job_results = []
        for analyzer in analyzer_list:
            try:
                job_result = utils.run_analysis(analyzer, datatype, data)
                job_results.append(job_result)
            except Exception as e:
                logger.error(f"Errore nell'esecuzione dell'analisi: {str(e)}")
                result['analysis'].append({"error": str(e)})
        
        # Polling dei job fino a completamento
        for job in job_results:
            job_id = job['id']
            
            # Polling dello stato del job
            report = utils.poll_job(job_id, config.API_SHORT_MAX_ATTEMPTS, config.API_SHORT_INITIAL_DELAY)
            
            if report and report.status == "Success":
                result['analysis'].append(report.json())
            else:
                status = report.status if report else "Timeout"
                logger.warning(f"Job {job_id} completato con status: {status}")
                result['analysis'].append({
                    "id": job_id,
                    "status": status,
                    "error": "Analisi non completata con successo"
                })
        
        return render_template('report.html', data=result)
    except Exception as e:
        logger.error(f"Errore in analysis(): {str(e)}")
        return error_response(str(e))


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

@routes_bp.route('/lastAnalisys', methods=['GET'])
def last_analysis():
    """Restituisce le ultime analisi organizzate per osservabile."""
    try:
        from cortex4py.query import And, Eq
        from utils import cortex_api
        
        query = And(Eq('status', 'Success'))
        jobs = cortex_api.jobs.find_all(query, range=config.LAST_ANALYSIS_RANGE, sort='-createdAt')
        organized_data = {}
        
        for item in jobs:
            data_value = item.data
            if data_value not in organized_data:
                organized_data[data_value] = []
            
            report = utils.poll_job(item.id, max_attempts=1)
            if report:
                t = utils.extract_taxonomies(report)
                organized_data[data_value].extend(t)
        
        return jsonify(organized_data)
    except Exception as e:
        logger.error(f"Errore in last_analysis(): {str(e)}")
        return error_response(str(e), 500)


@routes_bp.route('/getAnalisys', methods=['GET'])
def get_analysis():
    analysis_id = request.args.get('JobId')
    if not analysis_id:
        abort(400, "Missing analysis id")

    report = utils.cortex_api.jobs.get_report(analysis_id)

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
    """Visualizza tutti i report per un osservabile specifico."""
    try:
        observable = request.args.get('observable')
        datatype = request.args.get('datatype')
        
        if not observable:
            return error_response("Parametro 'observable' mancante", 400)
        if not datatype:
            return error_response("Parametro 'datatype' mancante", 400)
        
        logger.info(f"Ricerca di tutti i report per: {observable} (tipo: {datatype})")
        
        # Interroga Cortex per trovare tutti i job associati a questo osservabile
        from cortex4py.query import And, Eq
        from utils import cortex_api
        
        # Cerca job con questo osservabile - cortex usa 'data' per l'osservabile
        # Prova con query semplice (solo data)
        try:
            query = Eq('data', observable)
            logger.debug(f"Query Cortex: {query}")
            jobs = list(cortex_api.jobs.find_all(query, range=config.LAST_ANALYSIS_RANGE, sort='-createdAt'))
            logger.info(f"Trovati {len(jobs)} job per {observable}")
        except Exception as e:
            logger.error(f"Errore nella query Cortex: {str(e)}")
            logger.warning(f"Ritento senza filtro dataType")
            # Se la query fallisce, usa solo 'data'
            jobs = []
        
        result = {}
        result['analysis'] = []
        result['fuco'] = {}
        result['fuco']['question'] = observable
        result['fuco']['datatype'] = datatype
        
        # Per ogni job trovato, recupera il report
        for job in jobs:
            try:
                # Verifica che il job abbia il datatype corretto
                if hasattr(job, 'dataType') and job.dataType != datatype:
                    logger.debug(f"Job {job.id} ha datatype {job.dataType}, cerco {datatype} - SKIP")
                    continue
                
                report = utils.poll_job(job.id, max_attempts=1)
                if report and report.status == "Success":
                    result['analysis'].append(report.json())
                else:
                    status = report.status if report else "Timeout"
                    logger.warning(f"Job {job.id} completato con status: {status}")
                    result['analysis'].append({
                        "id": job.id,
                        "status": status,
                        "error": "Analisi non completata con successo"
                    })
            except Exception as e:
                logger.error(f"Errore nel recupero del report {job.id}: {str(e)}")
                continue
        
        if not result['analysis']:
            logger.info(f"Nessun report trovato per {observable}")
        
        return render_template('report.html', data=result)
    
    except Exception as e:
        logger.error(f"Errore in all_reports(): {str(e)}")
        return error_response(str(e), 500)


