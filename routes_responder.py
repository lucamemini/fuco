# ============================================================================
# routes_responder.py - Route API per Responder
# ============================================================================

"""
Flask routes for Responder management with Basic Auth authentication.
"""
import logging
from typing import List, Optional
from flask import request, jsonify, current_app
from pydantic import BaseModel, Field

import config_responder as responder_cfg
import config
from notify_manager import notify_responder_action
import utils
from security import login_required_json, optional_limit

logger = logging.getLogger(__name__)


# ============ Pydantic validation models ============

class ResponderExecuteRequest(BaseModel):
    """Model for single responder execution"""
    observable: str = Field(..., min_length=1, max_length=500)
    dataType: str = Field(..., min_length=1)
    responderId: str = Field(..., min_length=1)
    tlp: int = Field(default=responder_cfg.RESPONDER_DEFAULT_TLP, ge=0, le=3)
    pap: int = Field(default=responder_cfg.RESPONDER_DEFAULT_PAP, ge=0, le=3)
    message: str = Field(default=None, max_length=500)


class ObservableItem(BaseModel):
    """Single observable for bulk"""
    data: str = Field(..., min_length=1)
    dataType: str = Field(..., min_length=1)


class ResponderBulkRequest(BaseModel):
    """Model for bulk responder execution"""
    observables: List[ObservableItem] = Field(..., min_items=1, max_items=responder_cfg.MAX_BULK_OBSERVABLES)
    responderIds: List[str] = Field(..., min_items=1, max_items=responder_cfg.MAX_BULK_RESPONDERS)
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    tlp: int = Field(default=responder_cfg.RESPONDER_DEFAULT_TLP, ge=0, le=3)
    pap: int = Field(default=responder_cfg.RESPONDER_DEFAULT_PAP, ge=0, le=3)
    message: Optional[str] = Field(default=None, max_length=500)


class JobStatusRequest(BaseModel):
    """Model for job status query"""
    jobId: str = Field(..., min_length=1)
    username: str = Field(default=None)
    password: str = Field(default=None)


# ============ Helper Functions ============

def error_response(message: str, code: int = 500):
    """Helper to generate JSON error responses."""
    logger.error(f"Error ({code}): {message}")
    return jsonify({"error": message}), code


# ============ Route API Responder ============

def register_responder_routes(app):
    """
    Register responder routes in the Flask app.
    
    Call from fuco.py after app initialization.
    """
    if app.config.get('RESPONDER_ROUTES_REGISTERED'):
        logger.info("Responder routes already registered, skipping")
        return
    app.config['RESPONDER_ROUTES_REGISTERED'] = True
    
    @app.route('/api/responder/list', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_LIST)
    def list_responders():
        """
        List available responders, optionally filtered by type.
        
        Query params:
            - dataType (optional): filter by data type
            - username (optional): for Basic Auth
            - password (optional): for Basic Auth
        """
        try:
            data_type = request.args.get('dataType')
            username = request.args.get('username')
            password = request.args.get('password')
            responder_manager = current_app.responder_manager
            if responder_manager is None:
                return error_response("Responder manager non disponibile", 503)

            api_key = None
            auth_manager = getattr(current_app, 'auth_manager', None)
            if auth_manager and auth_manager.is_authenticated():
                api_key = auth_manager.get_api_key()
            elif not (username and password):
                return error_response("Authentication required", 401)

            responders = responder_manager.list_responders(
                data_type=data_type,
                username=username,
                password=password,
                api_key=api_key
            )
            
            return jsonify({
                'success': True,
                'count': len(responders),
                'responders': responders
            })
            
        except Exception as e:
            logger.error(f"Error in list_responders: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/execute', methods=['POST'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_EXECUTE)
    def execute_responder():
        """
        Execute a responder on an observable.
        Uses the API key from the session (after login).
        
        Body JSON:
        {
            "observable": "1.2.3.4",
            "dataType": "ip",
            "tlp": 2,
            "pap": 2,
            "message": "Optional note"
        }
        
        Note: username/password not needed anymore, uses authenticated session
        """
        try:
            # Authentication check
            auth_manager = current_app.auth_manager
            if not auth_manager.is_authenticated():
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'message': 'Please login first'
                }), 401
            
            # Retrieve API key from session
            api_key = auth_manager.get_api_key()
            username = auth_manager.get_username()
            
            # Input validation
            data = request.get_json()
            if not data:
                return error_response("Missing JSON body", 400)
            
            # Input validation
            req = ResponderExecuteRequest(**data)
            req.observable = utils.InputValidator.sanitize_observable(req.observable)
            req.dataType = utils.InputValidator.validate_datatype(req.dataType, allow_thehive=True)
            
            # Execute responder with API key
            responder_manager = current_app.responder_manager
            action = responder_manager.run_responder(
                observable=req.observable,
                data_type=req.dataType,
                responder_id=req.responderId,
                api_key=api_key,  # Use API key from the session
                tlp=req.tlp,
                pap=req.pap,
                message=req.message
            )
            
            # Refresh session

            # Notification (only on success)
            try:
                final_result = responder_manager.poll_responder_job(
                    job_id=action.job_id,
                    api_key=api_key,
                    max_attempts=responder_cfg.RESPONDER_MAX_POLL_ATTEMPTS,
                    delay=responder_cfg.RESPONDER_POLL_DELAY
                )
                if final_result.get('status') == 'Success':
                    notify_responder_action(action, username)
            except Exception as e:
                logger.warning(f"Responder notification skipped: {str(e)}")
            
            logger.info(f"Responder executed by {username}: {req.responderId} on {req.observable}")
            
            return jsonify({
                'success': True,
                'job_id': action.job_id,
                'observable': action.observable,
                'responder_name': action.responder_name,
                'status': action.status,
                'created_at': action.created_at.isoformat(),
                'executed_by': username
            }), 201
            
        except ValueError as e:
            return error_response(f"Validation failed: {str(e)}", 400)
        except Exception as e:
            logger.error(f"Error in execute_responder: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/bulk', methods=['POST'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_BULK)
    def execute_bulk_responders():
        """
        Execute multiple responders on multiple observables.
        
        Body JSON:
        {
            "observables": [
                {"data": "1.2.3.4", "dataType": "ip"},
            ],
            "responderIds": ["Responder1", "Responder2"],
            "username": "cortex_user",
            "password": "cortex_pass",
            "tlp": 2,
            "pap": 2
        }
        """
        try:
            # Input validation
            data = request.get_json()
            if not data:
                return error_response("Missing JSON body", 400)
            
            req = ResponderBulkRequest(**data)
            for obs in req.observables:
                obs.data = utils.InputValidator.sanitize_observable(obs.data)
                obs.dataType = utils.InputValidator.validate_datatype(obs.dataType, allow_thehive=True)

            responder_manager = current_app.responder_manager
            if responder_manager is None:
                return error_response("Responder manager non disponibile", 503)

            api_key = None
            auth_manager = getattr(current_app, 'auth_manager', None)
            if auth_manager and auth_manager.is_authenticated():
                api_key = auth_manager.get_api_key()
            elif not (req.username and req.password):
                return error_response("Authentication required", 401)
            
            # Convert observables to dict
            observables = [obs.dict() for obs in req.observables]
            
            # Execute bulk
            actions = responder_manager.run_responder_bulk(
                observables=observables,
                responder_ids=req.responderIds,
                username=req.username,
                password=req.password,
                api_key=api_key,
                tlp=req.tlp,
                pap=req.pap,
                message=req.message
            )
            
            # Notify for each action
            auth_manager = getattr(current_app, 'auth_manager', None)
            if auth_manager and auth_manager.is_authenticated():
                executed_by = auth_manager.get_username()
            else:
                executed_by = req.username or 'unknown'

            for action in actions:
                if not action.job_id or action.status == "Invalid data type":
                    continue
                try:
                    final_result = responder_manager.poll_responder_job(
                        job_id=action.job_id,
                        api_key=api_key,
                        max_attempts=responder_cfg.RESPONDER_MAX_POLL_ATTEMPTS,
                        delay=responder_cfg.RESPONDER_POLL_DELAY
                    )
                    if final_result.get('status') == 'Success':
                        notify_responder_action(action, executed_by)
                except Exception as e:
                    logger.warning(f"Bulk responder notification skipped: {str(e)}")

            # Build response
            results = []
            for action in actions:
                results.append({
                    'job_id': action.job_id,
                    'observable': action.observable,
                    'data_type': action.data_type,
                    'responder_name': action.responder_name,
                    'status': action.status
                })
            
            return jsonify({
                'success': True,
                'total_executed': len(results),
                'total_requested': len(observables) * len(req.responderIds),
                'results': results
            }), 201
            
        except ValueError as e:
            return error_response(f"Validation failed: {str(e)}", 400)
        except Exception as e:
            logger.error(f"Error in execute_bulk: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/status/<job_id>', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_STATUS)
    def get_responder_status(job_id):
        """
        Retrieve the status of a responder job.
        
        Optional query params:
            - username: for Basic Auth
            - password: for Basic Auth
        """
        try:
            username = request.args.get('username')
            password = request.args.get('password')
            responder_manager = current_app.responder_manager
            if responder_manager is None:
                return error_response("Responder manager non disponibile", 503)

            api_key = None
            auth_manager = getattr(current_app, 'auth_manager', None)
            if auth_manager and auth_manager.is_authenticated():
                api_key = auth_manager.get_api_key()
            elif not (username and password):
                return error_response("Authentication required", 401)

            status = responder_manager.get_responder_job_status(
                job_id=job_id,
                username=username,
                password=password,
                api_key=api_key
            )
            
            return jsonify({
                'success': True,
                'job': status
            })
            
        except Exception as e:
            logger.error(f"Error in get_status: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/poll/<job_id>', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_POLL)
    def poll_responder_job(job_id):
        """
        Poll a responder job until completion.
        May take up to 60 seconds.
        
        Optional query params:
            - username: for Basic Auth
            - password: for Basic Auth
            - maxAttempts: max attempts (default: 30)
            - delay: seconds between attempts (default: 2)
        """
        try:
            username = request.args.get('username')
            password = request.args.get('password')
            max_attempts = int(request.args.get('maxAttempts', responder_cfg.RESPONDER_MAX_POLL_ATTEMPTS))
            delay = int(request.args.get('delay', responder_cfg.RESPONDER_POLL_DELAY))

            responder_manager = current_app.responder_manager
            if responder_manager is None:
                return error_response("Responder manager non disponibile", 503)

            api_key = None
            auth_manager = getattr(current_app, 'auth_manager', None)
            if auth_manager and auth_manager.is_authenticated():
                api_key = auth_manager.get_api_key()
            elif not (username and password):
                return error_response("Authentication required", 401)

            result = responder_manager.poll_responder_job(
                job_id=job_id,
                username=username,
                password=password,
                api_key=api_key,
                max_attempts=max_attempts,
                delay=delay
            )
            
            return jsonify({
                'success': result['status'] != 'Timeout',
                'job': result
            })
            
        except Exception as e:
            logger.error(f"Error in poll_job: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/history', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_HISTORY)
    def get_responder_history():
        """
        Retrieve the history of responder actions.
        
        Query params:
            - limit (optional): max actions (default: 100)
        """
        try:
            limit = int(request.args.get('limit', 100))
            
            responder_manager = current_app.responder_manager
            history = responder_manager.get_action_history(limit=limit)
            
            return jsonify({
                'success': True,
                'count': len(history),
                'history': history
            })
            
        except Exception as e:
            logger.error(f"Error in get_history: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/validate', methods=['POST'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_VALIDATE)
    def validate_credentials():
        """
        Validate Cortex Basic Auth credentials.
        
        Body JSON:
        {
            "username": "cortex_user",
            "password": "cortex_pass"
        }
        """
        try:
            data = request.get_json()
            if not data or 'username' not in data or 'password' not in data:
                return error_response("Username and password required", 400)
            
            responder_manager = current_app.responder_manager
            is_valid = responder_manager.validate_credentials(
                username=data['username'],
                password=data['password']
            )
            
            if is_valid:
                return jsonify({
                    'success': True,
                    'valid': True,
                    'message': 'Valid credentials'
                })
            else:
                return jsonify({
                    'success': False,
                    'valid': False,
                    'message': 'Invalid credentials'
                }), 401
            
        except Exception as e:
            logger.error(f"Error in validate: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/for-observable', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_FOR_OBSERVABLE)
    def get_responders_for_observable():
        """
        Retrieve responders compatible with an observable type.
        
        Query params:
            - dataType: data type (ip, domain, etc.)
            - username (optional): for Basic Auth
            - password (optional): for Basic Auth
        """
        try:
            data_type = request.args.get('dataType')
            if not data_type:
                return error_response("Parameter 'dataType' required", 400)
            
            username = request.args.get('username')
            password = request.args.get('password')
            responder_manager = current_app.responder_manager
            if responder_manager is None:
                return error_response("Responder manager non disponibile", 503)

            api_key = None
            auth_manager = getattr(current_app, 'auth_manager', None)
            if auth_manager and auth_manager.is_authenticated():
                api_key = auth_manager.get_api_key()
            elif not (username and password):
                return error_response("Authentication required", 401)

            responders = responder_manager.get_responders_for_observable(
                data_type=data_type,
                username=username,
                password=password,
                api_key=api_key
            )
            
            return jsonify({
                'success': True,
                'dataType': data_type,
                'count': len(responders),
                'responders': responders
            })
            
        except Exception as e:
            logger.error(f"Error in get_responders_for_observable: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    logger.info("Responder routes registered successfully")
