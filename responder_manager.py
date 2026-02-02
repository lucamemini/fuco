# ============================================================================
# responder_manager.py - Manager for Cortex Responders
# ============================================================================

"""
Responder management system with Basic Auth support.
"""
import logging
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from cortex4py.api import Api
from requests.auth import HTTPBasicAuth

import config_responder as responder_cfg

logger = logging.getLogger(__name__)


@dataclass
class ResponderAction:
    """Represents an executed responder action."""
    job_id: str
    observable: str
    data_type: str
    responder_name: str
    status: str
    created_at: datetime
    payload_data_type: str
    payload_data: Any
    completed_at: Optional[datetime] = None
    report: Optional[Dict] = None
    error: Optional[str] = None


class ResponderManager:
    """
    Manager for executing and monitoring Cortex Responders.
    Supports Basic Auth for protected actions.
    """
    
    def __init__(self, cortex_host: str, cortex_api_key: str = None):
        """
        Initialize the responder manager.
        
        Args:
            cortex_host: Cortex server URL
            cortex_api_key: API Key (if not using Basic Auth for responders)
        """
        self.cortex_host = cortex_host
        self.api = Api(cortex_host, cortex_api_key) if cortex_api_key else None
        self._action_history: List[ResponderAction] = []
        self._responder_cache: Dict[str, Dict[str, Any]] = {}
        self._responder_type_constraints: Dict[str, List[str]] = self._build_type_constraints()
        
        logger.info(f"ResponderManager initialized for {cortex_host}")

    def _build_type_constraints(self) -> Dict[str, List[str]]:
        constraints: Dict[str, set] = {}

        explicit = getattr(responder_cfg, 'RESPONDER_TYPE_CONSTRAINTS', {}) or {}
        for responder_key, types in explicit.items():
            if not types:
                continue
            normalized = {str(t).lower() for t in types}
            if normalized:
                constraints.setdefault(responder_key, set()).update(normalized)

        if getattr(responder_cfg, 'RESPONDER_ENFORCE_PRESET_TYPES', False):
            presets = getattr(responder_cfg, 'RESPONDER_PRESETS', {}) or {}
            for data_type, responders in presets.items():
                if not responders:
                    continue
                dtype = str(data_type).lower()
                for responder_key in responders:
                    constraints.setdefault(responder_key, set()).add(dtype)

        return {k: sorted(list(v)) for k, v in constraints.items()}

    def _is_allowed_by_config(self, responder_id: str, responder_name: str, data_type: str) -> bool:
        dtype = str(data_type).lower()
        allowed = None

        if responder_id in self._responder_type_constraints:
            allowed = self._responder_type_constraints[responder_id]
        elif responder_name in self._responder_type_constraints:
            allowed = self._responder_type_constraints[responder_name]

        if not allowed:
            return True
        return dtype in {t.lower() for t in allowed}
    
    def get_authenticated_api(self, username: str = None, password: str = None, api_key: str = None) -> Api:
        """
        Create an authenticated Cortex API instance.
        
        Supports two methods:
        1. API Key (preferred) - If provided, use it
        2. Basic Auth (fallback) - If no API Key, use username/password
        
        Args:
            username: Cortex username (optional if api_key provided)
            password: Cortex password (optional if api_key provided)
            api_key: Cortex API Key (preferred)
        
        Returns:
            Api: Authenticated Cortex API instance
        """
        if api_key:
            # Preferred method: API Key
            api = Api(self.cortex_host, api_key)
            logger.debug("Cortex API authenticated with API Key")
            return api
        
        elif username and password:
            # Fallback: Basic Auth (only to obtain API Key)
            api = Api(self.cortex_host)
            api.session.auth = HTTPBasicAuth(username, password)
            logger.debug(f"Cortex API authenticated with Basic Auth for user: {username}")
            return api
        
        else:
            raise ValueError("Must provide api_key OR username+password")
    
    def list_responders(self, data_type: str = None, 
                       username: str = None, password: str = None, api_key: str = None) -> List[Dict]:
        """
        List available responders.
        
        Args:
            data_type: Filter by data type (ip, domain, etc.)
            username: Username for Basic Auth (optional)
            password: Password for Basic Auth (optional)
            api_key: API Key (preferred)
        
        Returns:
            List of available responders
        """
        try:
            # Use authenticated API
            if api_key:
                api = self.get_authenticated_api(api_key=api_key)
            elif username and password:
                api = self.get_authenticated_api(username=username, password=password)
            elif self.api:
                api = self.api
            else:
                raise ValueError("No authentication provided")
            
            # Retrieve responders
            if data_type:
                responders = api.responders.get_by_type(data_type)
            else:
                responders = api.responders.find_all({}, range='all')
            
            # Convert to dict for serialization
            result = []
            for resp in responders:
                resp_data = {
                    'id': resp.id,
                    'name': resp.name,
                    'version': getattr(resp, 'version', 'N/A'),
                    'dataTypeList': getattr(resp, 'dataTypeList', []),
                    'description': getattr(resp, 'description', ''),
                    'maxTlp': getattr(resp, 'maxTlp', 2),
                    'maxPap': getattr(resp, 'maxPap', 2)
                }
                result.append(resp_data)
                self._responder_cache[resp.id] = resp_data
            
            logger.info(f"Retrieved {len(result)} responders" + 
                       (f" for type {data_type}" if data_type else ""))
            for resp in result:
                logger.info(
                    "Responder: %s (%s) | dataTypeList=%s",
                    resp.get('name'),
                    resp.get('id'),
                    resp.get('dataTypeList')
                )
            return result
            
        except Exception as e:
            logger.error(f"Error retrieving responders: {str(e)}")
            raise
    
    def run_responder(self, 
                     observable: str,
                     data_type: str,
                     responder_id: str,
                     username: str = None,
                     password: str = None,
                     api_key: str = None,
                     tlp: int = responder_cfg.RESPONDER_DEFAULT_TLP,
                     pap: int = responder_cfg.RESPONDER_DEFAULT_PAP,
                     message: str = None) -> ResponderAction:
        """
        Execute a responder on an observable.
        
        Args:
            observable: Data to process
            data_type: Data type (ip, domain, etc.)
            responder_id: Responder ID to execute
            username: Cortex username (Basic Auth, optional if api_key)
            password: Cortex password (Basic Auth, optional if api_key)
            api_key: Cortex API Key (preferred)
            tlp: Traffic Light Protocol (0-3)
            pap: Permissible Actions Protocol (0-3)
            message: Optional message/notes
        
        Returns:
            ResponderAction: Object with execution info
        """
        try:
            # Create authenticated API
            if api_key:
                api = self.get_authenticated_api(api_key=api_key)
            elif username and password:
                api = self.get_authenticated_api(username=username, password=password)
            else:
                raise ValueError("Must provide api_key OR username+password")

            responder_name = self._get_responder_name(responder_id, api) or responder_id
            if not self._is_allowed_by_config(responder_id, responder_name, data_type):
                raise ValueError(
                    f"Responder '{responder_name}' is not allowed for data type '{data_type}' by configuration"
                )
            
            # Determine effective payload datatype
            payload_data_type = data_type
            payload_data = observable
            supported_types = self._get_responder_supported_types(responder_id, api)
            if supported_types and data_type not in supported_types:
                if 'thehive:case_artifact' in supported_types and not data_type.startswith('thehive:'):
                    payload_data_type = 'thehive:case_artifact'
                    payload_data = {
                        'dataType': data_type,
                        'data': observable
                    }
                    logger.info(
                        "Mapping datatype '%s' -> '%s' for responder %s",
                        data_type,
                        payload_data_type,
                        responder_id
                    )

            # Normalize message
            if message is not None:
                message = message.strip()
                if message == '':
                    message = None
                elif not message.lower().startswith('[fuco]:'):
                    message = f"[fuco]: {message}"

            if not message:
                message = responder_cfg.RESPONDER_DEFAULT_MESSAGE

            # Build payload
            payload = {
                'data': payload_data,
                'dataType': payload_data_type,
                'tlp': tlp,
                'pap': pap
            }

            # Add message to both top-level and case_artifact
            payload['message'] = message
            if payload_data_type == 'thehive:case_artifact' and isinstance(payload_data, dict):
                payload_data['message'] = message
            
            # Execute responder
            logger.info(f"Executing responder {responder_id} on {data_type}:{observable}")
            job = api.responders.run_by_id(responder_id, payload)
            
            # Build action object
            action = ResponderAction(
                job_id=job.id,
                observable=observable,
                data_type=data_type,
                responder_name=responder_name or (job.responderId if hasattr(job, 'responderId') else responder_id),
                status=job.status,
                created_at=datetime.now(),
                payload_data_type=payload_data_type,
                payload_data=payload_data
            )
            
            # Add to history
            self._action_history.append(action)
            
            logger.info(f"Responder job started: {job.id}")
            return action
            
        except Exception as e:
            logger.error(f"Error executing responder: {str(e)}")
            raise
    
    def run_responder_bulk(self,
                          observables: List[Dict[str, str]],
                          responder_ids: List[str],
                          username: str = None,
                          password: str = None,
                          api_key: str = None,
                          tlp: int = responder_cfg.RESPONDER_DEFAULT_TLP,
                          pap: int = responder_cfg.RESPONDER_DEFAULT_PAP,
                          message: str = None) -> List[ResponderAction]:
        """
        Execute multiple responders on multiple observables.
        
        Args:
            observables: List of dicts {data, dataType}
            responder_ids: List of responder IDs to execute
            username: Cortex username (optional if api_key)
            password: Cortex password (optional if api_key)
            api_key: Cortex API Key (preferred)
            tlp: Traffic Light Protocol
            pap: Permissible Actions Protocol
        
        Returns:
            List of executed ResponderAction
        """
        actions = []
        
        # Note: Cortex responder API accepts one observable per request.
        # "Bulk" here is a loop of single calls (one per observable x responder).
        logger.info(f"Bulk execution: {len(observables)} observables x {len(responder_ids)} responders")
        
        for obs in observables:
            for resp_id in responder_ids:
                try:
                    action = self.run_responder(
                        observable=obs['data'],
                        data_type=obs['dataType'],
                        responder_id=resp_id,
                        username=username,
                        password=password,
                        api_key=api_key,
                        tlp=tlp,
                        pap=pap,
                        message=message
                    )
                    actions.append(action)
                    
                    # Small delay to avoid overload
                    time.sleep(0.5)
                    
                except Exception as e:
                    logger.error(f"Bulk execution error for {obs['data']}: {str(e)}")
                    if isinstance(e, ValueError) and "not allowed for data type" in str(e):
                        actions.append(
                            ResponderAction(
                                job_id="",
                                observable=obs['data'],
                                data_type=obs['dataType'],
                                responder_name=resp_id,
                                status="Invalid data type",
                                created_at=datetime.now(),
                                payload_data_type=obs['dataType'],
                                payload_data=obs,
                                error=str(e)
                            )
                        )
                    # Continue with the next ones
                    continue
        
        logger.info(f"Bulk execution completed: {len(actions)}/{len(observables)*len(responder_ids)} success")
        return actions
    
    def get_responder_job_status(self, job_id: str,
                                 username: str = None,
                                 password: str = None,
                                 api_key: str = None) -> Dict[str, Any]:
        """
        Retrieve the status of a responder job.
        
        Args:
            job_id: Job ID
            username: Username for Basic Auth
            password: Password for Basic Auth
        
        Returns:
            Dict with job status and report
        """
        try:
            # Use authenticated API
            if api_key:
                api = self.get_authenticated_api(api_key=api_key)
            elif username and password:
                api = self.get_authenticated_api(username, password)
            elif self.api:
                api = self.api
            else:
                raise ValueError("No authentication provided")
            
            # Retrieve job
            job = api.jobs.get_by_id(job_id)
            
            result = {
                'id': job.id,
                'status': job.status,
                'responderId': getattr(job, 'responderId', 'N/A'),
                'responderName': getattr(job, 'responderName', 'N/A'),
                'createdAt': getattr(job, 'createdAt', None),
                'startDate': getattr(job, 'startDate', None),
                'endDate': getattr(job, 'endDate', None)
            }
            
            # If completed, add report
            if job.status in ('Success', 'Failure'):
                try:
                    report = api.jobs.get_report(job_id)
                    result['report'] = report.report if hasattr(report, 'report') else {}
                    
                    # Update action history
                    for action in self._action_history:
                        if action.job_id == job_id:
                            action.status = job.status
                            action.completed_at = datetime.now()
                            action.report = result['report']
                            break
                            
                except Exception as e:
                    logger.warning(f"Unable to retrieve report for job {job_id}: {str(e)}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error retrieving job status {job_id}: {str(e)}")
            raise
    
    def poll_responder_job(self, job_id: str,
                          username: str = None,
                          password: str = None,
                          api_key: str = None,
                          max_attempts: int = 30,
                          delay: int = 2) -> Dict[str, Any]:
        """
        Poll a responder job until completion.
        
        Args:
            job_id: Job ID
            username: Username for Basic Auth
            password: Password for Basic Auth
            max_attempts: Maximum attempts
            delay: Seconds between attempts
        
        Returns:
            Dict with final status and report
        """
        for attempt in range(max_attempts):
            try:
                status = self.get_responder_job_status(job_id, username, password, api_key)
                
                if status['status'] in ('Success', 'Failure'):
                    logger.info(f"Job {job_id} completed: {status['status']}")
                    return status
                
                logger.debug(f"Job {job_id} in progress... ({attempt+1}/{max_attempts})")
                time.sleep(delay)
                
            except Exception as e:
                logger.error(f"Error polling job {job_id}: {str(e)}")
                raise
        
        logger.warning(f"Job {job_id} timed out after {max_attempts} attempts")
        return {
            'id': job_id,
            'status': 'Timeout',
            'error': f'Job not completed after {max_attempts * delay} seconds'
        }
    
    def get_action_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve the history of executed responder actions.
        
        Args:
            limit: Max number of actions to return
        
        Returns:
            List of actions as dicts
        """
        history = []
        for action in self._action_history[-limit:]:
            history.append({
                'job_id': action.job_id,
                'observable': action.observable,
                'data_type': action.data_type,
                'responder_name': action.responder_name,
                'status': action.status,
                'created_at': action.created_at.isoformat(),
                'completed_at': action.completed_at.isoformat() if action.completed_at else None,
                'has_report': action.report is not None,
                'error': action.error
            })
        
        return history
    
    def validate_credentials(self, username: str, password: str) -> bool:
        """
        Validate Cortex credentials by attempting an API call.
        
        Args:
            username: Username
            password: Password
        
        Returns:
            True if credentials are valid, otherwise False
        """
        try:
            api = self.get_authenticated_api(username, password)
            # Attempt a lightweight call to validate
            api.responders.find_all({}, range='0-1')
            logger.info(f"Valid credentials for user: {username}")
            return True
            
        except Exception as e:
            logger.warning(f"Invalid credentials for {username}: {str(e)}")
            return False
    
    def get_responders_for_observable(self, data_type: str,
                                     username: str = None,
                                     password: str = None,
                                     api_key: str = None) -> List[Dict]:
        """
        Retrieve responders compatible with an observable type.
        
        Args:
            data_type: Data type
            username: Username for Basic Auth
            password: Password for Basic Auth
        
        Returns:
            List of compatible responders
        """
        try:
            all_responders = self.list_responders(username=username, password=password, api_key=api_key)
            
            # Filter by dataType
            compatible = []
            for resp in all_responders:
                data_types = resp.get('dataTypeList', [])
                if data_type in data_types or not data_types:  # Empty list = supports all
                    compatible.append(resp)
                elif 'thehive:case_artifact' in data_types and not data_type.startswith('thehive:'):
                    resp_with_hint = dict(resp)
                    resp_with_hint['payloadDataType'] = 'thehive:case_artifact'
                    compatible.append(resp_with_hint)
            
            logger.info(f"Found {len(compatible)} responders for type {data_type}")
            return compatible
            
        except Exception as e:
            logger.error(f"Error retrieving responders for {data_type}: {str(e)}")
            raise

    def _get_responder_supported_types(self, responder_id: str, api: Api) -> List[str]:
        """Retrieve responder-supported data types, using cache when possible."""
        cached = self._responder_cache.get(responder_id)
        if cached is not None:
            return cached.get('dataTypeList', [])

        try:
            responders = api.responders.find_all({}, range='all')
            for resp in responders:
                resp_data = {
                    'id': resp.id,
                    'name': resp.name,
                    'version': getattr(resp, 'version', 'N/A'),
                    'dataTypeList': getattr(resp, 'dataTypeList', []),
                    'description': getattr(resp, 'description', ''),
                    'maxTlp': getattr(resp, 'maxTlp', 2),
                    'maxPap': getattr(resp, 'maxPap', 2)
                }
                self._responder_cache[resp.id] = resp_data

            cached = self._responder_cache.get(responder_id)
            return cached.get('dataTypeList', []) if cached else []
        except Exception as e:
            logger.warning(f"Unable to retrieve dataTypeList for responder {responder_id}: {str(e)}")
            return []

    def _get_responder_name(self, responder_id: str, api: Api) -> Optional[str]:
        cached = self._responder_cache.get(responder_id)
        if cached is not None:
            return cached.get('name')
        _ = self._get_responder_supported_types(responder_id, api)
        cached = self._responder_cache.get(responder_id)
        return cached.get('name') if cached else None
