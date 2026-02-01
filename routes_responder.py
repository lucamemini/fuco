# ============================================================================
# routes_responder.py - Route API per Responder
# ============================================================================

"""
Route Flask per gestione Responder con autenticazione Basic Auth
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


# ============ Modelli Pydantic per validazione ============

class ResponderExecuteRequest(BaseModel):
    """Modello per esecuzione singola responder"""
    observable: str = Field(..., min_length=1, max_length=500)
    dataType: str = Field(..., min_length=1)
    responderId: str = Field(..., min_length=1)
    tlp: int = Field(default=responder_cfg.RESPONDER_DEFAULT_TLP, ge=0, le=3)
    pap: int = Field(default=responder_cfg.RESPONDER_DEFAULT_PAP, ge=0, le=3)
    message: str = Field(default=None, max_length=500)


class ObservableItem(BaseModel):
    """Singolo osservabile per bulk"""
    data: str = Field(..., min_length=1)
    dataType: str = Field(..., min_length=1)


class ResponderBulkRequest(BaseModel):
    """Modello per esecuzione bulk responder"""
    observables: List[ObservableItem] = Field(..., min_items=1, max_items=responder_cfg.MAX_BULK_OBSERVABLES)
    responderIds: List[str] = Field(..., min_items=1, max_items=responder_cfg.MAX_BULK_RESPONDERS)
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    tlp: int = Field(default=responder_cfg.RESPONDER_DEFAULT_TLP, ge=0, le=3)
    pap: int = Field(default=responder_cfg.RESPONDER_DEFAULT_PAP, ge=0, le=3)
    message: Optional[str] = Field(default=None, max_length=500)


class JobStatusRequest(BaseModel):
    """Modello per query status job"""
    jobId: str = Field(..., min_length=1)
    username: str = Field(default=None)
    password: str = Field(default=None)


# ============ Helper Functions ============

def error_response(message: str, code: int = 500):
    """Helper per generare risposte di errore JSON."""
    logger.error(f"Errore ({code}): {message}")
    return jsonify({"error": message}), code


# ============ Route API Responder ============

def register_responder_routes(app):
    """
    Registra le route responder nell'app Flask.
    
    Chiamare da fuco.py dopo l'inizializzazione dell'app.
    """
    if app.config.get('RESPONDER_ROUTES_REGISTERED'):
        logger.info("Route responder già registrate, skip")
        return
    app.config['RESPONDER_ROUTES_REGISTERED'] = True
    
    @app.route('/api/responder/list', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_LIST)
    def list_responders():
        """
        Lista responder disponibili, opzionalmente filtrati per tipo.
        
        Query params:
            - dataType (optional): filtra per tipo di dato
            - username (optional): per Basic Auth
            - password (optional): per Basic Auth
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
            logger.error(f"Errore list_responders: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/execute', methods=['POST'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_EXECUTE)
    def execute_responder():
        """
        Esegue un responder su un osservabile.
        Usa API Key dalla sessione (dopo login).
        
        Body JSON:
        {
            "observable": "1.2.3.4",
            "dataType": "ip",
            "tlp": 2,
            "pap": 2,
            "message": "Optional note"
        }
        
        Nota: Non serve più username/password, usa sessione autenticata
        """
        try:
            # Check autenticazione
            auth_manager = current_app.auth_manager
            if not auth_manager.is_authenticated():
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'message': 'Please login first'
                }), 401
            
            # Recupera API Key dalla sessione
            api_key = auth_manager.get_api_key()
            username = auth_manager.get_username()
            
            # Validazione input
            data = request.get_json()
            if not data:
                return error_response("Body JSON mancante", 400)
            
            # Validazione input
            req = ResponderExecuteRequest(**data)
            req.observable = utils.InputValidator.sanitize_observable(req.observable)
            req.dataType = utils.InputValidator.validate_datatype(req.dataType, allow_thehive=True)
            
            # Esegui responder con API Key
            responder_manager = current_app.responder_manager
            action = responder_manager.run_responder(
                observable=req.observable,
                data_type=req.dataType,
                responder_id=req.responderId,
                api_key=api_key,  # Usa API Key dalla sessione
                tlp=req.tlp,
                pap=req.pap,
                message=req.message
            )
            
            # Refresh sessione

            # Notifica
            notify_responder_action(action, username)
            
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
            return error_response(f"Validazione fallita: {str(e)}", 400)
        except Exception as e:
            logger.error(f"Errore execute_responder: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/bulk', methods=['POST'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_BULK)
    def execute_bulk_responders():
        """
        Esegue responder multipli su osservabili multipli.
        
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
            # Validazione input
            data = request.get_json()
            if not data:
                return error_response("Body JSON mancante", 400)
            
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
            
            # Converti observables in dict
            observables = [obs.dict() for obs in req.observables]
            
            # Esegui bulk
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
            
            # Notifica per ogni azione
            auth_manager = getattr(current_app, 'auth_manager', None)
            if auth_manager and auth_manager.is_authenticated():
                executed_by = auth_manager.get_username()
            else:
                executed_by = req.username or 'unknown'

            for action in actions:
                notify_responder_action(action, executed_by)

            # Prepara response
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
            return error_response(f"Validazione fallita: {str(e)}", 400)
        except Exception as e:
            logger.error(f"Errore execute_bulk: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/status/<job_id>', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_STATUS)
    def get_responder_status(job_id):
        """
        Recupera lo status di un job responder.
        
        Query params opzionali:
            - username: per Basic Auth
            - password: per Basic Auth
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
            logger.error(f"Errore get_status: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/poll/<job_id>', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_POLL)
    def poll_responder_job(job_id):
        """
        Polling di un job responder fino a completamento.
        Può richiedere fino a 60 secondi.
        
        Query params opzionali:
            - username: per Basic Auth
            - password: per Basic Auth
            - maxAttempts: numero massimo tentativi (default: 30)
            - delay: secondi tra tentativi (default: 2)
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
            logger.error(f"Errore poll_job: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/history', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_HISTORY)
    def get_responder_history():
        """
        Recupera lo storico delle azioni responder eseguite.
        
        Query params:
            - limit (optional): numero max azioni (default: 100)
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
            logger.error(f"Errore get_history: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/validate', methods=['POST'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_VALIDATE)
    def validate_credentials():
        """
        Valida credenziali Cortex Basic Auth.
        
        Body JSON:
        {
            "username": "cortex_user",
            "password": "cortex_pass"
        }
        """
        try:
            data = request.get_json()
            if not data or 'username' not in data or 'password' not in data:
                return error_response("Username e password richiesti", 400)
            
            responder_manager = current_app.responder_manager
            is_valid = responder_manager.validate_credentials(
                username=data['username'],
                password=data['password']
            )
            
            if is_valid:
                return jsonify({
                    'success': True,
                    'valid': True,
                    'message': 'Credenziali valide'
                })
            else:
                return jsonify({
                    'success': False,
                    'valid': False,
                    'message': 'Credenziali non valide'
                }), 401
            
        except Exception as e:
            logger.error(f"Errore validate: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    
    @app.route('/api/responder/for-observable', methods=['GET'])
    @login_required_json
    @optional_limit(config.RATE_LIMIT_RESPONDER_FOR_OBSERVABLE)
    def get_responders_for_observable():
        """
        Recupera responder compatibili con un tipo di osservabile.
        
        Query params:
            - dataType: tipo di dato (ip, domain, etc.)
            - username (optional): per Basic Auth
            - password (optional): per Basic Auth
        """
        try:
            data_type = request.args.get('dataType')
            if not data_type:
                return error_response("Parameter 'dataType' richiesto", 400)
            
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
            logger.error(f"Errore get_responders_for_observable: {str(e)}", exc_info=True)
            return error_response(str(e), 500)
    
    logger.info("Route responder registrate con successo")
