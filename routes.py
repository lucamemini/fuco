"""
Flask routes for the FUCO application.
"""
from io import BytesIO
import json
import logging
import sys
import time
from typing import List, Optional
from urllib.parse import quote
from functools import wraps

from flask import render_template, request, jsonify, Blueprint, current_app, abort
from markupsafe import escape
from pydantic import BaseModel, Field, validator

from concurrent.futures import ThreadPoolExecutor, as_completed

import utils
import config
import config_ai
import ai_manager
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


def _render_generic_fallback(report):
    """
    Render a safe fallback HTML block.
    - Success: show JSON
    - Failure/None: show error message
    """
    artifact = _report_to_template_payload(report)

    try:
        rendered = render_template("long/generic.long.html", artifact=artifact)
        return utils.sanitize_html(rendered)
    except Exception:
        pass

    status = artifact.get("status") if artifact else None
    if status == "Success":
        payload = artifact.get("report")
        if payload is None:
            payload = artifact
        try:
            json_text = json.dumps(payload, indent=2, default=str)
        except Exception:
            json_text = json.dumps({"error": "Unable to serialize report"}, indent=2)

        return (
            "<div class='card'>"
            "<div class='card-header'>Report JSON</div>"
            "<div class='card-body'><pre><code>"
            f"{escape(json_text)}"
            "</code></pre></div></div>"
        )

    error_message = artifact.get("errorMessage") if artifact else None
    report_body = artifact.get("report") if artifact else None
    if not error_message and isinstance(report_body, dict):
        error_message = report_body.get("errorMessage")

    if not error_message:
        error_message = "Unknown error occurred"

    return (
        "<div class='alert alert-danger'>"
        "<strong>Error</strong><br>"
        f"{escape(str(error_message))}"
        "</div>"
    )

# ============ IP Filtering Decorator ============

def ip_whitelist_required(allowed_ips=None):
    """
    Decorator to restrict access to specific IPs.
    
    Args:
        allowed_ips: List of allowed IPs. If None, uses config.ALLOWED_IPS
    
    Usage:
        @ip_whitelist_required(['192.168.1.100', '10.0.0.5'])
        def my_route():
            ...
    
    Note:
        If behind nginx/apache, this correctly detects the real client IP
        from X-Forwarded-For or X-Real-IP headers.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from security import _get_client_ip
            
            # Use IPs from parameter or config
            whitelist = allowed_ips or getattr(config, 'ALLOWED_IPS', ['127.0.0.1', '::1'])
            
            # Get client IP (handles proxy headers correctly)
            client_ip = _get_client_ip()
            
            logger.debug(
                f"IP whitelist check: {client_ip} vs {whitelist} | "
                f"Path: {request.path}"
            )
            
            # Check if IP is in the whitelist
            if client_ip not in whitelist:
                logger.warning(
                    f"IP whitelist: Access denied for {client_ip} | "
                    f"Path: {request.path} | Allowed: {whitelist}"
                )
                return jsonify({
                    'error': 'Access denied',
                    'message': 'Your IP address is not authorized to access this resource'
                }), 403
            
            logger.debug(f"IP whitelist: {client_ip} authorized for {request.path}")
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


class AiAnalyzeRequest(BaseModel):
    """Validation model for /api/ai/analyze"""
    observable: str = Field(..., min_length=1, max_length=500)
    datatype: str = Field(..., min_length=1, max_length=100)
    jobs: List[str] = Field(..., min_items=1)
    force_refresh: Optional[bool] = False
    tlp: Optional[int] = None
    pap: Optional[int] = None


# ============ Helper functions ============

def error_response(message: str, code: int = 500):
    """Helper to generate JSON error responses."""
    logger.error(f"Error ({code}): {message}")
    return jsonify({"error": message}), code


def _report_to_template_payload(report) -> dict:
    """Normalize a Cortex report object into a dict for Jinja templates."""
    if report is None:
        return {}

    if isinstance(report, dict):
        return report

    report_json = {}
    report_json_method = getattr(report, 'json', None)
    if callable(report_json_method):
        try:
            report_json = report_json_method()
        except Exception:
            report_json = {}

    if isinstance(report_json, dict) and report_json:
        return report_json

    report_body = getattr(report, 'report', None)
    if not isinstance(report_body, dict):
        report_body = {}

    return {
        'id': getattr(report, 'id', None),
        'status': getattr(report, 'status', None),
        'analyzerName': getattr(report, 'analyzerName', None),
        'data': getattr(report, 'data', None),
        'errorMessage': getattr(report, 'errorMessage', None),
        'report': report_body,
    }


def _report_to_ai_payload(report, job_id: str) -> dict:
    """Build a compact AI short-report with premium-source context and summary evidence."""
    _LEVEL_RANK = {'malicious': 4, 'suspicious': 3, 'info': 2, 'safe': 1, 'undef': 0}

    status_raw = getattr(report, 'status', None)
    analyzer_name = getattr(report, 'analyzerName', None)
    analyzer_lc = str(analyzer_name or '').lower()
    is_ok = status_raw == 'Success'

    premium_analyzers = [str(x).lower() for x in (getattr(config_ai, 'AI_PREMIUM_ANALYZERS', []) or [])]
    is_premium = any(token and token in analyzer_lc for token in premium_analyzers)

    report_json = {}
    report_json_method = getattr(report, 'json', None)
    if callable(report_json_method):
        try:
            report_json = report_json_method()
        except Exception:
            report_json = {}

    taxonomies = []
    try:
        taxonomies = utils.extract_taxonomies(report)
    except Exception:
        taxonomies = []

    # Derive top risk level from highest-ranked taxonomy level
    top_level = None
    top_rank = -1
    suspicious_hits = 0
    for t in taxonomies:
        lvl = (t.get('level') or '').lower()
        r = _LEVEL_RANK.get(lvl, -1)
        if r > top_rank:
            top_rank = r
            top_level = lvl if lvl and lvl != 'undef' else None
        if lvl in ('suspicious', 'malicious'):
            suspicious_hits += 1

    # Compact tag strings: "predicate:value", capped in count and length
    max_tags = int(getattr(config_ai, 'AI_MAX_TAGS_PER_REPORT', 5) or 5)
    max_tag_len = int(getattr(config_ai, 'AI_MAX_TAG_VALUE_LEN', 80) or 80)
    tags = []
    for t in taxonomies[:max_tags]:
        pred = str(t.get('predicate') or '').strip()
        val = str(t.get('value') or '').strip()
        tag = f"{pred}:{val}" if pred else val
        tag = tag[:max_tag_len]
        if tag:
            tags.append(tag)

    # Add a few summary-derived evidence lines for richer context without raw JSON dump.
    max_evidence = int(getattr(config_ai, 'AI_MAX_EVIDENCE_PER_REPORT', 3) or 3)
    max_evidence_len = int(getattr(config_ai, 'AI_MAX_EVIDENCE_VALUE_LEN', 120) or 120)
    evidence = []
    summary_obj = report_json.get('summary') if isinstance(report_json, dict) else None
    if isinstance(summary_obj, dict):
        for k, v in summary_obj.items():
            if len(evidence) >= max_evidence:
                break
            if isinstance(v, (str, int, float, bool)):
                line = f"{k}:{v}"[:max_evidence_len]
                if line:
                    evidence.append(line)
    elif isinstance(summary_obj, list):
        for item in summary_obj:
            if len(evidence) >= max_evidence:
                break
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, (str, int, float, bool)):
                        line = f"{k}:{v}"[:max_evidence_len]
                        if line:
                            evidence.append(line)
                            break
            elif isinstance(item, (str, int, float, bool)):
                evidence.append(str(item)[:max_evidence_len])

    def _compact_full_report(full_obj):
        max_full_report_bytes = int(getattr(config_ai, 'AI_MAX_FULL_REPORT_BYTES_PER_REPORT', 60000) or 60000)
        try:
            raw = json.dumps(full_obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if len(raw) <= max_full_report_bytes:
                return full_obj
        except Exception:
            return None

        if isinstance(full_obj, dict):
            compact = {'_truncated': True}
            for key in ('summary', 'taxonomies', 'level', 'score', 'report'):
                if key in full_obj:
                    compact[key] = full_obj.get(key)

            try:
                raw_compact = json.dumps(compact, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
                if len(raw_compact) <= max_full_report_bytes:
                    return compact
            except Exception:
                pass

            # Last-resort compact skeleton to preserve useful hints without overflow.
            return {
                '_truncated': True,
                'summary': full_obj.get('summary') if isinstance(full_obj.get('summary'), (dict, list, str, int, float, bool)) else None,
                'keys': list(full_obj.keys())[:40],
            }

        # Non-dict payload: keep a bounded textual excerpt.
        text = str(full_obj)
        return {
            '_truncated': True,
            'excerpt': text[: min(len(text), 4000)],
        }

    entry = {
        "analyzer": analyzer_name,
        "status": "ok" if is_ok else "error",
        "importance": "high" if is_premium else "normal",
        "risk_level": top_level,
        "suspicious_hits": suspicious_hits,
        "tags": tags,
        "evidence": evidence[:max_evidence],
    }
    if is_premium and report_json:
        entry["full_report"] = _compact_full_report(report_json)
    if not is_ok:
        err = getattr(report, 'errorMessage', None)
        if err:
            entry["error"] = str(err)[:200]
    return entry

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
            return _render_generic_fallback(report)
            
    except Exception as e:
        logger.error(f"Error rendering report HTML: {str(e)}")
        return _render_generic_fallback(report)


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
            return render_template(
                'index.html',
                q=q_param,
                t=type_param,
                cortex_host=_get_cortex_host(),
                ai_enabled=bool(getattr(config_ai, 'AI_ENABLED', False)),
            )
        else:
            result = utils.get_analyzer_by_type("_default")
            recent = utils.get_recent_searches()
            return render_template(
                'index.html',
                t=result,
                recent=recent,
                cortex_host=_get_cortex_host(),
                ai_enabled=bool(getattr(config_ai, 'AI_ENABLED', False)),
            )
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


@routes_bp.route('/api/ai/analyze', methods=['POST'])
@optional_limit(getattr(config, 'RATE_LIMIT_API_AI_ANALYSIS', None))
def api_ai_analyze():
    """AI assessment endpoint (cache-aware)."""
    if not config_ai.AI_ENABLED:
        return error_response("AI feature disabled", 503)

    if not ai_manager.is_enabled():
        return error_response("AI not configured (missing provider/key)", 503)

    try:
        endpoint_started = time.time()
        request_data = request.get_json()
        if not request_data:
            return error_response("No JSON data provided", 400)

        try:
            ai_req = AiAnalyzeRequest(**request_data)
        except ValueError as e:
            return error_response(f"Invalid data: {str(e)}", 400)

        observable = utils.InputValidator.sanitize_observable(ai_req.observable)
        datatype = utils.InputValidator.validate_datatype(ai_req.datatype)

        # TLP enforcement: block if request TLP exceeds AI_MAX_TLP
        _TLP_NAMES = {0: 'WHITE', 1: 'GREEN', 2: 'AMBER', 3: 'RED'}
        _max_tlp = getattr(config_ai, 'AI_MAX_TLP', None)
        if _max_tlp is not None:
            _req_tlp = ai_req.tlp if ai_req.tlp is not None else config.DEFAULT_TLP
            if not (0 <= _req_tlp <= 3):
                _req_tlp = config.DEFAULT_TLP
            if _req_tlp > _max_tlp:
                logger.warning(
                    "AI assessment blocked: TLP:%s exceeds AI_MAX_TLP:%s (observable=%s)",
                    _TLP_NAMES.get(_req_tlp, _req_tlp),
                    _TLP_NAMES.get(_max_tlp, _max_tlp),
                    observable,
                )
                return jsonify({
                    "error": "tlp_blocked",
                    "message": (
                        f"AI Assessment non consentito: il TLP dell'analisi è "
                        f"TLP:{_TLP_NAMES.get(_req_tlp, _req_tlp)}, "
                        f"ma la configurazione permette solo fino a "
                        f"TLP:{_TLP_NAMES.get(_max_tlp, _max_tlp)}."
                    ),
                    "request_tlp": _req_tlp,
                    "max_tlp": _max_tlp,
                }), 403

        # PAP enforcement: block if request PAP exceeds AI_MAX_PAP
        _max_pap = getattr(config_ai, 'AI_MAX_PAP', None)
        if _max_pap is not None:
            _req_pap = ai_req.pap if ai_req.pap is not None else config.DEFAULT_PAP
            if not (0 <= _req_pap <= 3):
                _req_pap = config.DEFAULT_PAP
            if _req_pap > _max_pap:
                logger.warning(
                    "AI assessment blocked: PAP:%s exceeds AI_MAX_PAP:%s (observable=%s)",
                    _TLP_NAMES.get(_req_pap, _req_pap),
                    _TLP_NAMES.get(_max_pap, _max_pap),
                    observable,
                )
                return jsonify({
                    "error": "pap_blocked",
                    "message": (
                        f"AI Assessment non consentito: il PAP dell'analisi è "
                        f"PAP:{_TLP_NAMES.get(_req_pap, _req_pap)}, "
                        f"ma la configurazione permette solo fino a "
                        f"PAP:{_TLP_NAMES.get(_max_pap, _max_pap)}."
                    ),
                    "request_pap": _req_pap,
                    "max_pap": _max_pap,
                }), 403

        jobs = [str(job_id).strip() for job_id in ai_req.jobs if str(job_id).strip()]
        if not jobs:
            return error_response("No valid job ids provided", 400)

        max_jobs = int(getattr(config_ai, 'AI_MAX_JOBS', 100))
        if len(jobs) > max_jobs:
            return error_response(f"Too many jobs (max {max_jobs})", 400)

        reports_payload = []
        final_statuses = ("Success", "Failure", "Deleted")
        reports_collection_started = time.time()

        for job_id in jobs:
            report = utils.get_cached_report(job_id)
            if not report:
                continue

            status = getattr(report, 'status', None)
            if getattr(config_ai, 'AI_REQUIRE_FINAL_RESULTS', True) and status not in final_statuses:
                return error_response(f"Job {job_id} not completed yet", 409)

            reports_payload.append(_report_to_ai_payload(report, job_id))

        reports_collection_ms = int((time.time() - reports_collection_started) * 1000)

        if not reports_payload:
            return error_response("No reports available for AI analysis", 404)

        bundle_build_started = time.time()
        bundle = ai_manager.build_bundle(observable, datatype, reports_payload)
        bundle_build_ms = int((time.time() - bundle_build_started) * 1000)

        ai_step_started = time.time()
        result = ai_manager.get_or_generate_assessment(
            current_app.cache_manager,
            bundle,
            force_refresh=bool(ai_req.force_refresh),
        )
        ai_step_ms = int((time.time() - ai_step_started) * 1000)

        logger.info(
            "AI_ANALYZE_TIMING jobs=%s reports=%s source=%s reports_collection_ms=%s bundle_build_ms=%s ai_step_ms=%s total_ms=%s",
            len(jobs),
            len(reports_payload),
            result.get('source', 'unknown'),
            reports_collection_ms,
            bundle_build_ms,
            ai_step_ms,
            int((time.time() - endpoint_started) * 1000),
        )

        return jsonify(result)

    except ValueError as e:
        return error_response(str(e), 400)
    except ai_manager.AIProviderError as e:
        status_code = int(getattr(e, 'status_code', 502) or 502)
        retry_after = getattr(e, 'retry_after_seconds', None)
        message = str(e)

        body = {"error": message}
        if retry_after is not None:
            body["retry_after_seconds"] = retry_after

        response = jsonify(body)
        if retry_after is not None:
            response.headers['Retry-After'] = str(retry_after)

        logger.warning("AI provider error (%s): %s", status_code, message)
        return response, status_code
    except Exception as e:
        logger.error(f"Error in api_ai_analyze(): {str(e)}", exc_info=True)
        return error_response(str(e), 500)


@routes_bp.route('/api/ai/cache-assessment', methods=['POST'])
@optional_limit(getattr(config, 'RATE_LIMIT_API_AI_ANALYSIS', None))
def api_ai_cache_assessment():
    """Return cached AI assessment only (does not call AI provider)."""
    if not config_ai.AI_ENABLED:
        return error_response("AI feature disabled", 503)

    try:
        request_data = request.get_json()
        if not request_data:
            return error_response("No JSON data provided", 400)

        try:
            ai_req = AiAnalyzeRequest(**request_data)
        except ValueError as e:
            return error_response(f"Invalid data: {str(e)}", 400)

        observable = utils.InputValidator.sanitize_observable(ai_req.observable)
        datatype = utils.InputValidator.validate_datatype(ai_req.datatype)

        # TLP enforcement: block if request TLP exceeds AI_MAX_TLP
        _TLP_NAMES = {0: 'WHITE', 1: 'GREEN', 2: 'AMBER', 3: 'RED'}
        _max_tlp = getattr(config_ai, 'AI_MAX_TLP', None)
        if _max_tlp is not None:
            _req_tlp = ai_req.tlp if ai_req.tlp is not None else config.DEFAULT_TLP
            if not (0 <= _req_tlp <= 3):
                _req_tlp = config.DEFAULT_TLP
            if _req_tlp > _max_tlp:
                logger.warning(
                    "AI cache-assessment blocked: TLP:%s exceeds AI_MAX_TLP:%s (observable=%s)",
                    _TLP_NAMES.get(_req_tlp, _req_tlp),
                    _TLP_NAMES.get(_max_tlp, _max_tlp),
                    observable,
                )
                return jsonify({
                    "error": "tlp_blocked",
                    "message": (
                        f"AI Assessment non consentito: il TLP dell'analisi \u00e8 "
                        f"TLP:{_TLP_NAMES.get(_req_tlp, _req_tlp)}, "
                        f"ma la configurazione permette solo fino a "
                        f"TLP:{_TLP_NAMES.get(_max_tlp, _max_tlp)}."
                    ),
                    "request_tlp": _req_tlp,
                    "max_tlp": _max_tlp,
                }), 403

        # PAP enforcement: block if request PAP exceeds AI_MAX_PAP
        _max_pap = getattr(config_ai, 'AI_MAX_PAP', None)
        if _max_pap is not None:
            _req_pap = ai_req.pap if ai_req.pap is not None else config.DEFAULT_PAP
            if not (0 <= _req_pap <= 3):
                _req_pap = config.DEFAULT_PAP
            if _req_pap > _max_pap:
                logger.warning(
                    "AI cache-assessment blocked: PAP:%s exceeds AI_MAX_PAP:%s (observable=%s)",
                    _TLP_NAMES.get(_req_pap, _req_pap),
                    _TLP_NAMES.get(_max_pap, _max_pap),
                    observable,
                )
                return jsonify({
                    "error": "pap_blocked",
                    "message": (
                        f"AI Assessment non consentito: il PAP dell'analisi è "
                        f"PAP:{_TLP_NAMES.get(_req_pap, _req_pap)}, "
                        f"ma la configurazione permette solo fino a "
                        f"PAP:{_TLP_NAMES.get(_max_pap, _max_pap)}."
                    ),
                    "request_pap": _req_pap,
                    "max_pap": _max_pap,
                }), 403

        jobs = [str(job_id).strip() for job_id in ai_req.jobs if str(job_id).strip()]
        if not jobs:
            return error_response("No valid job ids provided", 400)

        max_jobs = int(getattr(config_ai, 'AI_MAX_JOBS', 100))
        if len(jobs) > max_jobs:
            return error_response(f"Too many jobs (max {max_jobs})", 400)

        reports_payload = []
        final_statuses = ("Success", "Failure", "Deleted")

        for job_id in jobs:
            report = utils.get_cached_report(job_id)
            if not report:
                continue

            status = getattr(report, 'status', None)
            if getattr(config_ai, 'AI_REQUIRE_FINAL_RESULTS', True) and status not in final_statuses:
                return error_response(f"Job {job_id} not completed yet", 409)

            reports_payload.append(_report_to_ai_payload(report, job_id))

        if not reports_payload:
            return error_response("No reports available for AI analysis", 404)

        bundle = ai_manager.build_bundle(observable, datatype, reports_payload)
        cache_key = ai_manager.make_cache_key(bundle)
        cached = current_app.cache_manager.get_ai_assessment(cache_key)

        if not cached:
            latest_index_key = ai_manager.make_latest_index_key(observable, datatype)
            latest_ptr = current_app.cache_manager.get_ai_assessment(latest_index_key)
            latest_cache_key = (latest_ptr or {}).get('cache_key') if isinstance(latest_ptr, dict) else None
            if latest_cache_key:
                cached = current_app.cache_manager.get_ai_assessment(latest_cache_key)

        if not cached:
            return error_response("No AI assessment in cache.", 404)

        response = dict(cached)
        response['source'] = 'cache'
        return jsonify(response)

    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Error in api_ai_cache_assessment(): {str(e)}", exc_info=True)
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

    artifact = _report_to_template_payload(report)

    try:
        rendered = render_template(template_name, artifact=artifact)
        return utils.sanitize_html(rendered)

    except Exception:
        logger.error(
            "Error rendering template %s, falling back to generic",
            template_name,
            exc_info=True
        )
        return _render_generic_fallback(report)

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

        # Calcola il TLP massimo (worst-case) tra tutti i job trovati
        max_tlp = config.DEFAULT_TLP
        for job in jobs:
            job_tlp = getattr(job, 'tlp', None)
            if job_tlp is not None:
                try:
                    job_tlp = int(job_tlp)
                    if 0 <= job_tlp <= 3 and job_tlp > max_tlp:
                        max_tlp = job_tlp
                except (ValueError, TypeError):
                    pass

        # Calcola il PAP massimo (worst-case) tra tutti i job trovati
        max_pap = config.DEFAULT_PAP
        for job in jobs:
            job_pap = getattr(job, 'pap', None)
            if job_pap is not None:
                try:
                    job_pap = int(job_pap)
                    if 0 <= job_pap <= 3 and job_pap > max_pap:
                        max_pap = job_pap
                except (ValueError, TypeError):
                    pass

        # Prepare data structure for the template
        result = {
            'fuco': {
                'question': observable,
                'datatype': resolved_datatype,
                'tlp': max_tlp,
                'pap': max_pap
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


# ============ DEBUG ENDPOINT (rimuovere in produzione!) ============

@routes_bp.route('/debug/ip-info', methods=['GET', 'POST'])
def debug_ip_info():
    """
    Endpoint di debug per verificare quale IP viene rilevato.
    ATTENZIONE: Rimuovere o proteggere in produzione!
    """
    from security import _get_client_ip
    
    client_ip = _get_client_ip()
    csrf_whitelist = current_app.config.get('CSRF_WHITELIST', [])
    
    info = {
        'detected_client_ip': client_ip,
        'is_whitelisted': client_ip in csrf_whitelist,
        'csrf_whitelist': csrf_whitelist,
        'raw_data': {
            'remote_addr': request.remote_addr,
            'x_forwarded_for': request.headers.get('X-Forwarded-For'),
            'x_real_ip': request.headers.get('X-Real-IP'),
        },
        'request_info': {
            'method': request.method,
            'path': request.path,
            'referrer': request.referrer,
            'user_agent': request.headers.get('User-Agent')
        },
        'all_headers': dict(request.headers)
    }
    
    return jsonify(info)