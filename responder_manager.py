# ============================================================================
# responder_manager.py - Manager per Cortex Responders
# ============================================================================

"""
Sistema di gestione responder con supporto autenticazione Basic Auth
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
    """Rappresenta un'azione responder eseguita"""
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
    Manager per l'esecuzione e il monitoraggio dei Responder Cortex.
    Supporta autenticazione Basic Auth per azioni protette.
    """
    
    def __init__(self, cortex_host: str, cortex_api_key: str = None):
        """
        Inizializza il manager responder.
        
        Args:
            cortex_host: URL del server Cortex
            cortex_api_key: API Key (se non usa Basic Auth per responder)
        """
        self.cortex_host = cortex_host
        self.api = Api(cortex_host, cortex_api_key) if cortex_api_key else None
        self._action_history: List[ResponderAction] = []
        self._responder_cache: Dict[str, Dict[str, Any]] = {}
        
        logger.info(f"ResponderManager inizializzato per {cortex_host}")
    
    def get_authenticated_api(self, username: str = None, password: str = None, api_key: str = None) -> Api:
        """
        Crea un'istanza API Cortex con autenticazione.
        
        Supporta due metodi:
        1. API Key (preferito) - Se fornita, usa quella
        2. Basic Auth (fallback) - Se no API Key, usa username/password
        
        Args:
            username: Username Cortex (opzionale se api_key fornita)
            password: Password Cortex (opzionale se api_key fornita)
            api_key: API Key Cortex (metodo preferito)
        
        Returns:
            Api: Istanza autenticata dell'API Cortex
        """
        if api_key:
            # Metodo preferito: usa API Key
            api = Api(self.cortex_host, api_key)
            logger.debug("API Cortex autenticata con API Key")
            return api
        
        elif username and password:
            # Fallback: Basic Auth (solo per ottenere API Key)
            api = Api(self.cortex_host)
            api.session.auth = HTTPBasicAuth(username, password)
            logger.debug(f"API Cortex autenticata con Basic Auth per utente: {username}")
            return api
        
        else:
            raise ValueError("Deve fornire api_key OPPURE username+password")
    
    def list_responders(self, data_type: str = None, 
                       username: str = None, password: str = None, api_key: str = None) -> List[Dict]:
        """
        Elenca i responder disponibili.
        
        Args:
            data_type: Filtra per tipo di dato (ip, domain, etc.)
            username: Username per Basic Auth (opzionale)
            password: Password per Basic Auth (opzionale)
            api_key: API Key (metodo preferito)
        
        Returns:
            Lista di responder disponibili
        """
        try:
            # Usa API autenticata
            if api_key:
                api = self.get_authenticated_api(api_key=api_key)
            elif username and password:
                api = self.get_authenticated_api(username=username, password=password)
            elif self.api:
                api = self.api
            else:
                raise ValueError("Nessuna autenticazione fornita")
            
            # Recupera responder
            if data_type:
                responders = api.responders.get_by_type(data_type)
            else:
                responders = api.responders.find_all({}, range='all')
            
            # Converti in dict per serializzazione
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
            
            logger.info(f"Recuperati {len(result)} responder" + 
                       (f" per tipo {data_type}" if data_type else ""))
            for resp in result:
                logger.info(
                    "Responder: %s (%s) | dataTypeList=%s",
                    resp.get('name'),
                    resp.get('id'),
                    resp.get('dataTypeList')
                )
            return result
            
        except Exception as e:
            logger.error(f"Errore nel recupero responder: {str(e)}")
            raise
    
    def run_responder(self, 
                     observable: str,
                     data_type: str,
                     responder_id: str,
                     username: str = None,
                     password: str = None,
                     api_key: str = None,
                     tlp: int = 2,
                     pap: int = 2,
                     message: str = None) -> ResponderAction:
        """
        Esegue un responder su un osservabile.
        
        Args:
            observable: Dato da processare
            data_type: Tipo di dato (ip, domain, etc.)
            responder_id: ID del responder da eseguire
            username: Username Cortex (per Basic Auth, opzionale se api_key)
            password: Password Cortex (per Basic Auth, opzionale se api_key)
            api_key: API Key Cortex (metodo preferito)
            tlp: Traffic Light Protocol (0-3)
            pap: Permissible Actions Protocol (0-3)
            message: Messaggio/note opzionale
        
        Returns:
            ResponderAction: Oggetto con info sull'azione eseguita
        """
        try:
            # Crea API autenticata
            if api_key:
                api = self.get_authenticated_api(api_key=api_key)
            elif username and password:
                api = self.get_authenticated_api(username=username, password=password)
            else:
                raise ValueError("Deve fornire api_key OPPURE username+password")
            
            # Determina datatype effettivo del payload
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

            # Normalizza message
            if message is not None:
                message = message.strip()
                if message == '':
                    message = None

            if not message:
                message = responder_cfg.RESPONDER_DEFAULT_MESSAGE

            # Prepara payload
            payload = {
                'data': payload_data,
                'dataType': payload_data_type,
                'tlp': tlp,
                'pap': pap
            }

            # Inserisci message sia top-level che nel case_artifact
            payload['message'] = message
            if payload_data_type == 'thehive:case_artifact' and isinstance(payload_data, dict):
                payload_data['message'] = message
            
            # Esegui responder
            logger.info(f"Esecuzione responder {responder_id} su {data_type}:{observable}")
            job = api.responders.run_by_id(responder_id, payload)
            
            # Crea oggetto action
            action = ResponderAction(
                job_id=job.id,
                observable=observable,
                data_type=data_type,
                responder_name=self._get_responder_name(responder_id, api) or (job.responderId if hasattr(job, 'responderId') else responder_id),
                status=job.status,
                created_at=datetime.now(),
                payload_data_type=payload_data_type,
                payload_data=payload_data
            )
            
            # Aggiungi allo storico
            self._action_history.append(action)
            
            logger.info(f"Responder job avviato: {job.id}")
            return action
            
        except Exception as e:
            logger.error(f"Errore esecuzione responder: {str(e)}")
            raise
    
    def run_responder_bulk(self,
                          observables: List[Dict[str, str]],
                          responder_ids: List[str],
                          username: str = None,
                          password: str = None,
                          api_key: str = None,
                          tlp: int = 2,
                          pap: int = 2,
                          message: str = None) -> List[ResponderAction]:
        """
        Esegue responder multipli su osservabili multipli.
        
        Args:
            observables: Lista di dict {data, dataType}
            responder_ids: Lista di responder ID da eseguire
            username: Username Cortex (opzionale se api_key)
            password: Password Cortex (opzionale se api_key)
            api_key: API Key Cortex (metodo preferito)
            tlp: Traffic Light Protocol
            pap: Permissible Actions Protocol
        
        Returns:
            Lista di ResponderAction eseguite
        """
        actions = []
        
        # Nota: l'API Cortex dei responder accetta un solo observable per richiesta.
        # Il "bulk" qui è quindi un loop di chiamate singole (una per observable x responder).
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
                    
                    # Piccolo delay per evitare overload
                    time.sleep(0.5)
                    
                except Exception as e:
                    logger.error(f"Errore bulk execution per {obs['data']}: {str(e)}")
                    # Continua con i successivi
                    continue
        
        logger.info(f"Bulk execution completata: {len(actions)}/{len(observables)*len(responder_ids)} successo")
        return actions
    
    def get_responder_job_status(self, job_id: str,
                                 username: str = None,
                                 password: str = None,
                                 api_key: str = None) -> Dict[str, Any]:
        """
        Recupera lo stato di un job responder.
        
        Args:
            job_id: ID del job
            username: Username per Basic Auth
            password: Password per Basic Auth
        
        Returns:
            Dict con status e report del job
        """
        try:
            # Usa API autenticata
            if api_key:
                api = self.get_authenticated_api(api_key=api_key)
            elif username and password:
                api = self.get_authenticated_api(username, password)
            elif self.api:
                api = self.api
            else:
                raise ValueError("Nessuna autenticazione fornita")
            
            # Recupera job
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
            
            # Se completato, aggiungi report
            if job.status in ('Success', 'Failure'):
                try:
                    report = api.jobs.get_report(job_id)
                    result['report'] = report.report if hasattr(report, 'report') else {}
                    
                    # Aggiorna action history
                    for action in self._action_history:
                        if action.job_id == job_id:
                            action.status = job.status
                            action.completed_at = datetime.now()
                            action.report = result['report']
                            break
                            
                except Exception as e:
                    logger.warning(f"Impossibile recuperare report per job {job_id}: {str(e)}")
            
            return result
            
        except Exception as e:
            logger.error(f"Errore recupero status job {job_id}: {str(e)}")
            raise
    
    def poll_responder_job(self, job_id: str,
                          username: str = None,
                          password: str = None,
                          api_key: str = None,
                          max_attempts: int = 30,
                          delay: int = 2) -> Dict[str, Any]:
        """
        Polling di un job responder fino a completamento.
        
        Args:
            job_id: ID del job
            username: Username per Basic Auth
            password: Password per Basic Auth
            max_attempts: Numero massimo di tentativi
            delay: Secondi tra i tentativi
        
        Returns:
            Dict con status finale e report
        """
        for attempt in range(max_attempts):
            try:
                status = self.get_responder_job_status(job_id, username, password, api_key)
                
                if status['status'] in ('Success', 'Failure'):
                    logger.info(f"Job {job_id} completato: {status['status']}")
                    return status
                
                logger.debug(f"Job {job_id} in corso... ({attempt+1}/{max_attempts})")
                time.sleep(delay)
                
            except Exception as e:
                logger.error(f"Errore polling job {job_id}: {str(e)}")
                raise
        
        logger.warning(f"Job {job_id} timeout dopo {max_attempts} tentativi")
        return {
            'id': job_id,
            'status': 'Timeout',
            'error': f'Job non completato dopo {max_attempts * delay} secondi'
        }
    
    def get_action_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Recupera lo storico delle azioni responder eseguite.
        
        Args:
            limit: Numero massimo di azioni da ritornare
        
        Returns:
            Lista di azioni in formato dict
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
        Valida le credenziali Cortex tentando una chiamata API.
        
        Args:
            username: Username
            password: Password
        
        Returns:
            True se credenziali valide, False altrimenti
        """
        try:
            api = self.get_authenticated_api(username, password)
            # Tenta una chiamata leggera per validare
            api.responders.find_all({}, range='0-1')
            logger.info(f"Credenziali valide per utente: {username}")
            return True
            
        except Exception as e:
            logger.warning(f"Credenziali non valide per {username}: {str(e)}")
            return False
    
    def get_responders_for_observable(self, data_type: str,
                                     username: str = None,
                                     password: str = None,
                                     api_key: str = None) -> List[Dict]:
        """
        Recupera i responder compatibili con un tipo di osservabile.
        
        Args:
            data_type: Tipo di dato
            username: Username per Basic Auth
            password: Password per Basic Auth
        
        Returns:
            Lista di responder compatibili
        """
        try:
            all_responders = self.list_responders(username=username, password=password, api_key=api_key)
            
            # Filtra per dataType
            compatible = []
            for resp in all_responders:
                data_types = resp.get('dataTypeList', [])
                if data_type in data_types or not data_types:  # Empty list = supports all
                    compatible.append(resp)
                elif 'thehive:case_artifact' in data_types and not data_type.startswith('thehive:'):
                    resp_with_hint = dict(resp)
                    resp_with_hint['payloadDataType'] = 'thehive:case_artifact'
                    compatible.append(resp_with_hint)
            
            logger.info(f"Trovati {len(compatible)} responder per tipo {data_type}")
            return compatible
            
        except Exception as e:
            logger.error(f"Errore recupero responder per {data_type}: {str(e)}")
            raise

    def _get_responder_supported_types(self, responder_id: str, api: Api) -> List[str]:
        """Recupera i dataType supportati da un responder, usando cache se possibile."""
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
            logger.warning(f"Impossibile recuperare dataTypeList per responder {responder_id}: {str(e)}")
            return []

    def _get_responder_name(self, responder_id: str, api: Api) -> Optional[str]:
        cached = self._responder_cache.get(responder_id)
        if cached is not None:
            return cached.get('name')
        _ = self._get_responder_supported_types(responder_id, api)
        cached = self._responder_cache.get(responder_id)
        return cached.get('name') if cached else None
