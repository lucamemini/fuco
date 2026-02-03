"""
Flask routes for the FUCO application.
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
import config_responder as responder_cfg
from security import login_required_json, optional_limit

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

# Logging configuration
logger = logging.getLogger(__name__)

# Blueprint for routes
routes_bp = Blueprint('routes', __name__)

# ============ IP Filtering Decorator ============

def ip_whitelist_required(allowed_ips=None):
    """
    Decorator to restrict access to specific IPs.
    
    Args:
        allowed_ips: List of allowed IPs. If None, uses config.ALLOWED_IPS
    
    Usage:
        @ip_whitelist_required(['127.0.0.1', '192.168.1.100'])
        def my_route():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use IPs from parameter or config
            whitelist = allowed_ips or getattr(config, 'ALLOWED_IPS', ['127.0.0.1', '::1'])
            
            # Get client IP
            if request.headers.get('X-Forwarded-For'):
                # Behind reverse proxy (nginx, apache)
                client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            elif request.headers.get('X-Real-IP'):
                # Alternate header for reverse proxy
                client_ip = request.headers.get('X-Real-IP')
            else:
                # Direct connection
                client_ip = request.remote_addr
            
            logger.debug(f"Detected client IP: {client_ip}")
            
            # Check if IP is in the whitelist
            if client_ip not in whitelist:
                logger.warning(f"Access denied for unauthorized IP: {client_ip}")
                return jsonify({
                    'error': 'Access denied',
                    'message': 'Your IP address is not authorized to access this resource'
                }), 403
            
            logger.debug(f"IP {client_ip} authorized")
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# ============ Pydantic validation models ============

class ShortRequest(BaseModel):
    """Validation model for /api/short"""
    Data: str = Field(..., min_length=1, max_length=255)
    DataType: Optional[str] = None
    analyzer_list: List[str] = Field(..., min_items=1)
    
    @validator('analyzer_list')
    def validate_analyzers(cls, v):
        if not all(isinstance(x, str) and len(x) > 0 for x in v):
            raise ValueError('analyzer_list must contain non-empty strings')
        return v


class AnalysisRequest(BaseModel):
    """Validation model for /api/analysis"""
    Data: str = Field(..., min_length=1, max_length=255)
    DataType: Optional[str] = None
    analyzer_list: List[str] = Field(..., min_items=1)


# ============ Helper functions ============

def error_response(message: str, code: int = 500):
    """Helper to generate JSON error responses."""
    logger.error(f"Error ({code}): {message}")
    return jsonify({"error": message}), code

# ============ HTML routes ============


@routes_bp.route('/export/pdf', methods=['POST'])
@login_required_json
@optional_limit(config.RATE_LIMIT_EXPORT_PDF)
def export_pdf():
    """
    Export results to PDF.
    Receives analysis data via POST and generates a PDF.
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("No data provided", 400)
        
        observable = data.get('observable')
        datatype = data.get('datatype')
        jobs = data.get('jobs', [])
        
        if not observable or not jobs:
            return error_response("Missing parameters", 400)
        
        logger.info(f"Generating PDF for {observable} with {len(jobs)} jobs")
        
        # Fetch full reports for each job
        reports_data = []
        for job in jobs:
            job_id = job.get('id')
            try:
                # Use cache if available
                report = get_cached_report(job_id)
                
                if report and report.status == "Success":
                    reports_data.append({
                        'id': job_id,
                        'analyzer': job.get('analyzer'),
                        'report': report,
                        'html': render_report_html(report, current_app.root_path)
                    })
            except Exception as e:
                logger.error(f"Error retrieving report {job_id}: {str(e)}")
                continue
        
        # Render the PDF template
        html_content = render_template('pdf_export.html',
                                     observable=observable,
                                     datatype=datatype,
                                     reports=reports_data,
                                     timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Convert HTML to PDF
        pdf_buffer = BytesIO()
        if HTML is None:
            raise RuntimeError("PDF rendering disabled on this platform")
        
        HTML(string=html_content, base_url=request.url_root).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        
        # Create response
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=fuco_report_{observable}.pdf'
        
        logger.info(f"PDF generated successfully for {observable}")
        return response
        
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}", exc_info=True)
        return error_response(f"Error generating the PDF: {str(e)}", 500)


def render_report_html(report, app_root_path):
    """
    Render a report to HTML for PDF export.
    Uses the same LONG template system.
    """
    try:
        generic_template = "long/generic.long.html"
        template_name = generic_template

        if report and getattr(report, "status", None) == "Success":
            template_name = utils.resolve_long_template(report, app_root_path)
            if not template_name:
                template_name = generic_template
        
        try:
            rendered = render_template(template_name, artifact=report)
            return utils.sanitize_html(rendered)
        except Exception:
            rendered = render_template(generic_template, artifact=report)
            return utils.sanitize_html(rendered)
            
    except Exception as e:
        logger.error(f"Error rendering report HTML: {str(e)}")
        return f"<div class='alert alert-danger'>Rendering error: {str(e)}</div>"


@routes_bp.route('/')
def home():
    """Homepage with search form and recent searches."""
    try:
        # DEBUG
        q_param = request.args.get('q')
        type_param = request.args.get('t')

        # If it's not a string, it's a frontend issue
        if not isinstance(type_param, str):
    #           logger.error("TYPE IS NOT A STRING!")
           q_param = ''
           type_param = '_default'
           
        if q_param and type_param:
            return render_template('index.html', q=q_param, t=type_param, cortex_host=_get_cortex_host())
        else:
            result = utils.get_analyzer_by_type("_default")
            recent = utils.get_recent_searches()
            return render_template('index.html', t=result, recent=recent, cortex_host=_get_cortex_host())
    except Exception as e:
        logger.error(f"Error in home(): {str(e)}")
        return error_response(str(e))

@routes_bp.route("/favicon.ico")
def favicon():
    return "", 204

@routes_bp.route('/getAnalyzer', methods=['GET'])
def get_analyzer():
    """Return analyzers for a specific data type."""
    try:
        analyzer_type = str(request.args.get('type', 'domain'))
        analyzer_type = utils.InputValidator.validate_datatype(analyzer_type)
        result = utils.get_analyzer_by_type(analyzer_type)
        return render_template('analyzer.html', data=result)
    except Exception as e:
        logger.error(f"Error in get_analyzer(): {str(e)}")
        return error_response(str(e))


@routes_bp.route("/analysis", methods=["POST"])
def analysis():
    """
    Render the report page immediately.
    Jobs are submitted via AJAX from the browser with custom TLP/PAP.
    """
    try:
        data = request.form.get('observable')
        if not data:
            return error_response("Missing 'observable' parameter", 400)
        data = utils.InputValidator.sanitize_observable(data)

        datatype = request.form.get('datatype')
        if not datatype or str(datatype).strip().lower() == '_disabled':
            datatype = utils.detect_data_type(data)
            if not datatype:
                return error_response("Unable to automatically determine the data type", 400)
        else:
            datatype = utils.InputValidator.validate_datatype(datatype)
            utils.InputValidator.validate_observable_by_type(datatype, data)
        
        analyzer_list = request.form.getlist('analyzer')
        if not analyzer_list:
            return error_response("No analyzer selected", 400)
        
        # NEW: Read TLP/PAP from the form
        try:
            tlp = int(request.form.get('tlp', config.DEFAULT_TLP))
            pap = int(request.form.get('pap', config.DEFAULT_PAP))
        except (ValueError, TypeError):
            tlp = config.DEFAULT_TLP
            pap = config.DEFAULT_PAP
        
        # Validate TLP/PAP (0-3)
        if not (0 <= tlp <= 3):
            logger.warning(f"Invalid TLP received: {tlp}, using default {config.DEFAULT_TLP}")
            tlp = config.DEFAULT_TLP
        if not (0 <= pap <= 3):
            logger.warning(f"Invalid PAP received: {pap}, using default {config.DEFAULT_PAP}")
            pap = config.DEFAULT_PAP
        
        logger.info(f"Analysis request for '{data}' ({datatype}) with {len(analyzer_list)} analyzers - TLP:{tlp} PAP:{pap}")
        
        # Prepare data for the template (WITHOUT submitting jobs)
        result = {
            'fuco': {
                'question': data,
                'datatype': datatype,
                'tlp': tlp,
                'pap': pap
            },
            'analyzers': sorted(analyzer_list, key=str.lower)
        }
        
        # Render immediately
        logger.info("Immediate report page render")
        return render_template('report_async.html', data=result, cortex_host=_get_cortex_host())
        
    except Exception as e:
        logger.error(f"Error in analysis(): {str(e)}", exc_info=True)
        return error_response(str(e))

@routes_bp.route('/api/submit_job', methods=['POST'])
@optional_limit(config.RATE_LIMIT_SUBMIT_JOB)
def api_submit_job():
    """
    API to submit a SINGLE job to Cortex.
    Called via AJAX from the browser.
    NEW: Supports custom TLP/PAP per job.
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return error_response("No JSON data provided", 400)
        
        analyzer = request_data.get('analyzer')
        datatype = request_data.get('datatype')
        data = request_data.get('data')
        
        # NEW: Retrieve TLP/PAP (optional, defaults if missing)
        try:
            tlp = int(request_data.get('tlp', config.DEFAULT_TLP))
            pap = int(request_data.get('pap', config.DEFAULT_PAP))
        except (ValueError, TypeError):
            tlp = config.DEFAULT_TLP
            pap = config.DEFAULT_PAP
        
        # Validation
        if not all([analyzer, datatype, data]):
            return error_response("Missing parameters (analyzer, datatype, data)", 400)
        data = utils.InputValidator.sanitize_observable(data)
        datatype = utils.InputValidator.validate_datatype(datatype)
        utils.InputValidator.validate_observable_by_type(datatype, data)
        
        if not (0 <= tlp <= 3):
            tlp = config.DEFAULT_TLP
        if not (0 <= pap <= 3):
            pap = config.DEFAULT_PAP
        
        logger.info(f"Submitting job: {analyzer} for {data} - TLP:{tlp} PAP:{pap}")
        
        # Submit the job to Cortex WITH custom TLP/PAP
        job_result = utils.run_analysis(analyzer, datatype, data, tlp=tlp, pap=pap)
        
        return jsonify({
            'status': 'success',
            'job_id': job_result['id'],
            'analyzer': analyzer,
            'tlp': tlp,
            'pap': pap
        })
        
    except Exception as e:
        logger.error(f"Error in api_submit_job(): {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@routes_bp.route('/api/poll_job/<job_id>', methods=['GET'])
def api_poll_job(job_id):
    """
    API for polling a single job.
    Returns the current job status.
    """
    try:
        # Polling with max_attempts=1 (check current status only)
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
            # Failure, Timeout, etc.
            return jsonify({
                'status': 'failed',
                'job_id': job_id,
                'report_status': report.status
            })
            
    except Exception as e:
        logger.error(f"Error polling job {job_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'job_id': job_id,
            'error': str(e)
        }), 500

# ============ Route API ============

@routes_bp.route('/api/short', methods=['POST'])
@optional_limit(config.RATE_LIMIT_API_SHORT)
def api_short():
    """
    API for short analyses with multi-IP support.
    Returns only taxonomies per analyzer.
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return error_response("No JSON data provided", 400)
        
        # Validation with Pydantic
        try:
            short_req = ShortRequest(**request_data)
        except ValueError as e:
            return error_response(f"Invalid data: {str(e)}", 400)
        
        raw_data = utils.InputValidator.sanitize_observable(short_req.Data)
        datatype = short_req.DataType
        analyzer_list = short_req.analyzer_list
        
        # Determine data type if not specified
        input_items = []
        if not datatype:
            # Multiple IPs case
            if ',' in raw_data:
                ips = utils.parse_multiple_ips(raw_data)
                if not ips:
                    return error_response("No valid public IPs found", 400)
                input_items = [(ip, "ip") for ip in ips]
            else:
                detected_type = utils.detect_data_type(raw_data)
                if not detected_type:
                    return error_response("Unable to automatically determine the data type", 400)
                input_items = [(raw_data, detected_type)]
        else:
            # Explicit DataType
            datatype = utils.InputValidator.validate_datatype(datatype)
            if datatype.lower() == "ip" and ',' in raw_data:
                ips = utils.parse_multiple_ips(raw_data)
                if not ips:
                    return error_response("No valid public IPs found", 400)
                input_items = [(ip, "ip") for ip in ips]
            else:
                utils.InputValidator.validate_observable_by_type(datatype.lower(), raw_data)
                input_items = [(raw_data, datatype.lower())]
        
        # Run analyses
        job_results = []
        for data, dtype in input_items:
            for analyzer in analyzer_list:
                try:
                    job_result = utils.run_analysis(analyzer, dtype, data)
                    job_results.append((data, analyzer, job_result))
                except Exception as e:
                    logger.error(f"Error starting analysis: {str(e)}")
                    return error_response(str(e), 500)
        
        # Poll jobs
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
        logger.error(f"Error in api_short(): {str(e)}")
        return error_response(str(e), 500)


@routes_bp.route('/api/analysis', methods=['POST'])
@optional_limit(config.RATE_LIMIT_API_ANALYSIS)
def api_analysis():
    """
    API for full analyses that returns the complete report.
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return error_response("No JSON data provided", 400)
        
        # Validation with Pydantic
        try:
            analysis_req = AnalysisRequest(**request_data)
        except ValueError as e:
            return error_response(f"Invalid data: {str(e)}", 400)
        
        data = utils.InputValidator.sanitize_observable(analysis_req.Data)
        datatype = analysis_req.DataType
        analyzer_list = analysis_req.analyzer_list
        
        # Determine data type if not specified
        if not datatype:
            datatype = utils.detect_data_type(data)
            if not datatype:
                return error_response("Unable to automatically determine the data type", 400)
        else:
            datatype = utils.InputValidator.validate_datatype(datatype)
            utils.InputValidator.validate_observable_by_type(datatype, data)
        
        # Run analyses
        job_results = []
        for analyzer in analyzer_list:
            try:
                job_result = utils.run_analysis(analyzer, datatype, data)
                job_results.append(job_result)
            except Exception as e:
                logger.error(f"Error starting analysis: {str(e)}")
                return error_response(str(e), 500)
        
        # Poll jobs
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
                    "error": "Analysis not completed"
                })
        
        response = {
            "question": data,
            "datatype": datatype,
            "results": final_results
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error in api_analysis(): {str(e)}")
        return error_response(str(e), 500)


@routes_bp.route('/api/getAnalyzer', methods=['GET'])
def api_get_analyzer():
    """API to retrieve the list of all available analyzers."""
    try:
        all_analyzers = []
        all_data_types = set()
        
        # Collect analyzers per type
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
                logger.warning(f"Error retrieving analyzers for type {analyzer_type}: {str(e)}")
                continue
        
        response = {
            "analyzers": all_analyzers,
            "supportedDataTypes": list(all_data_types)
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error in api_get_analyzer(): {str(e)}")
        return error_response(str(e), 500)


# ============ Support routes ============

@routes_bp.route('/getAnalisys', methods=['GET'])
@routes_bp.route('/getAnalysis', methods=['GET'])
@optional_limit(config.RATE_LIMIT_GET_ANALYSIS)
def get_analysis():
    analysis_id = request.args.get('JobId')
    if not analysis_id:
        abort(400, "Missing analysis id")

    report = utils.get_cached_report(analysis_id)

    generic_template = "long/generic.long.html"
    template_name = generic_template

    if report and getattr(report, "status", None) == "Success":
        template_name = utils.resolve_long_template(report, current_app.root_path)
        if not template_name:
            logger.warning("Specific template not found, using generic")
            template_name = generic_template
    else:
        logger.info("Report status not successful, using generic template")

    try:
        rendered = render_template(template_name, artifact=report)
        return utils.sanitize_html(rendered)

    except Exception as e:
        logger.error(
            "Error rendering template %s, falling back to generic",
            template_name,
            exc_info=True
        )

        try:
            rendered = render_template(generic_template, artifact=report)
            return utils.sanitize_html(rendered)
        except Exception:
            logger.critical(
                "Error rendering the generic template as well",
                exc_info=True
            )
            abort(500, "Template rendering failed")

@routes_bp.route('/getShort', methods=['GET'])
@optional_limit(config.RATE_LIMIT_GET_SHORT)
def get_short():
    """Return the short template for a job's taxonomies."""
    try:
        job_id = str(request.args.get('JobId'))
        if not job_id:
            return error_response("Missing 'JobId' parameter", 400)
        
        report = utils.poll_job(job_id, config.GET_SHORT_MAX_ATTEMPTS, config.GET_SHORT_INITIAL_DELAY)
        if not report:
            return error_response("Job not completed or timed out", 408)
        
        taxonomies = utils.extract_taxonomies(report)
        html = utils.render_short_template(taxonomies, report.analyzerName, current_app.root_path)
        return html
    
    except Exception as e:
        logger.error(f"Error in get_short(): {str(e)}")
        return error_response(str(e), 500)

@routes_bp.route('/allReports', methods=['GET','POST'])
def all_reports():
    """
    Show all existing reports for a specific observable.
    Retrieve from the Cortex cache WITHOUT re-submitting analyses.
    """
    try:
        default_datatype = "_default"
        datatype = default_datatype
        if request.method == 'GET':
            observable = request.args.get('observable')
            datatype = request.args.get('datatype') or default_datatype

        elif request.method == 'POST':
            data = request.form
            observable = data.get('observable')
            datatype = data.get('datatype') or default_datatype
        
        if not observable:
            return error_response(f"Missing 'observable' parameter  {observable}", 400)
        observable = utils.InputValidator.sanitize_observable(observable)
        if datatype and str(datatype).strip().lower() == '_disabled':
            datatype = default_datatype
        if datatype and datatype != default_datatype:
            datatype = utils.InputValidator.validate_datatype(datatype)
        
        logger.info(f"Searching existing reports for: {observable} (type: {datatype})")
        
        from utils import cortex_api
        
        try:
            logger.info("Fetching recent jobs from Cortex")
            all_jobs = list(cortex_api.jobs.find_all(
                {},
                range=config.LAST_ANALYSIS_RANGE, 
                sort='-createdAt'
            ))
            logger.info(f"Fetched {len(all_jobs)} total jobs")
            
            # Filtro manuale per observable e datatype
            jobs = []
            for job in all_jobs:
                # Exclude TheHive datatypes (responder actions)
                if hasattr(job, 'dataType') and str(job.dataType).lower().startswith('thehive:'):
                    continue
                
                matches_datatype = (datatype == default_datatype) or (
                    hasattr(job, 'dataType') and job.dataType == datatype
                )

                if (hasattr(job, 'data') and job.data == observable and
                    matches_datatype and
                    hasattr(job, 'status') and job.status == 'Success'):
                    jobs.append(job)
            
            logger.info(f"Found {len(jobs)} Success jobs for {observable} ({datatype})")
            
        except Exception as e:
            logger.error(f"Error in Cortex query: {str(e)}", exc_info=True)
            jobs = []
        
        if not jobs:
            logger.info(f"No reports found for {observable}")
            return render_template('no_reports.html', 
                                 observable=observable, 
                                 datatype=datatype,
                                 cortex_host=_get_cortex_host())
        
        # Resolve datatype if default
        resolved_datatype = datatype
        if datatype == default_datatype:
            for job in jobs:
                if hasattr(job, 'dataType') and job.dataType:
                    resolved_datatype = job.dataType
                    break
            if resolved_datatype == default_datatype:
                try:
                    resolved_datatype = utils.detect_data_type(observable)
                except Exception:
                    resolved_datatype = datatype

        # Prepare data structure for the template
        result = {
            'fuco': {
                'question': observable,
                'datatype': resolved_datatype
            },
            'jobs': []
        }
        
        # Collect jobs with their details
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
        logger.info(f"Rendering {len(result['jobs'])} reports for {observable}")
        return render_template('all_reports.html', data=result, cortex_host=_get_cortex_host())
    
    except Exception as e:
        logger.error(f"Error in all_reports(): {str(e)}", exc_info=True)
        return error_response(str(e), 500)


# ============ Cache API (PROTECTED BY IP WHITELIST) ============

@routes_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring/load balancers.
    Checks cache status and Cortex connectivity.
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
    
    # Check Cortex (optional, comment out if too slow)
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
@ip_whitelist_required()  # Uses default config from config.py
def cache_stats():
    """
    Debug endpoint to view cache status.
    PROTECTED: Only IPs in the whitelist can access.
    """
    try:
        stats = utils.get_cache_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error retrieving cache stats: {str(e)}")
        return error_response(str(e), 500)


@routes_bp.route('/api/cache/clear', methods=['POST'])
@ip_whitelist_required()  # Uses default config from config.py
def clear_cache():
    """
    Endpoint to clear the cache manually.
    PROTECTED: Only IPs in the whitelist can access.
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
        logger.error(f"Error clearing cache: {str(e)}")
        return error_response(str(e), 500)

# @app.route('/bulk-responder')
@routes_bp.route('/bulk-responder', methods=['GET'])
def bulk_responder_page():
    return render_template(
        'bulk_responder.html',
        max_bulk_observables=responder_cfg.MAX_BULK_OBSERVABLES,
        cortex_host=_get_cortex_host()
    )


def _get_cortex_host() -> str:
    try:
        import cortexconfig as cortex_cfg
        host = cortex_cfg.cortex.get('host') if hasattr(cortex_cfg, 'cortex') else None
        return host.rstrip('/') if host else ''
    except Exception:
        return ''