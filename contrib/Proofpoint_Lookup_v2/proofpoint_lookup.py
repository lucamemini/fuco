#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import json
import requests
import hashlib
from requests.auth import HTTPBasicAuth

class ProofpointForensicsAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Proofpoint service is missing')
        self.url = self.get_param('config.url', None, 'Proofpoint URL is missing')
        if self.url is None:
            self.url = 'https://tap-api-v2.proofpoint.com'
        self.apikey = self.get_param('config.apikey', None, 'Proofpoint apikey is missing')
        self.secret = self.get_param('config.secret', None, 'Proofpoint secret is missing')
        self.verify = self.get_param('config.verifyssl', True)
        self.include_campaign_forensics = self.get_param('config.includeCampaignForensics', False)
        # Nuovo parametro per auto-enrichment con Threats API
        self.auto_enrich = self.get_param('config.autoEnrich', True)
        
        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
    def summary(self, raw):
        taxonomies = []
        namespace = "Proofpoint"
        
        # Se abbiamo enrichment data, usa quello per il summary
        if 'threat_summary' in raw and raw['threat_summary']:
            threat = raw['threat_summary']
            
            # Taxonomy: Category
            category = threat.get('category', 'unknown')
            level = "info"
            if category == "malware":
                level = "malicious"
            elif category == "phish":
                level = "malicious"
            elif category == "impostor":
                level = "suspicious"
            elif category == "spam":
                level = "suspicious"
                
            taxonomies.append(
                self.build_taxonomy(level, namespace, "Category", category.title())
            )
            
            # Taxonomy: Severity
            severity = threat.get('severity', 0)
            sev_level = "info"
            if severity >= 700:
                sev_level = "malicious"
            elif severity >= 400:
                sev_level = "suspicious"
            elif severity >= 100:
                sev_level = "safe"
                
            taxonomies.append(
                self.build_taxonomy(sev_level, namespace, "Severity", str(severity))
            )
            
            # Taxonomy: Status
            status = threat.get('status', 'unknown')
            status_level = "malicious" if status == "active" else "safe"
            taxonomies.append(
                self.build_taxonomy(status_level, namespace, "Status", status.title())
            )
            
        # Altrimenti usa i dati forensics
        elif 'reports' in raw and len(raw['reports']) > 0:
            level = "info"
            value = "Unknown"
            malicious_count = 0
            
            for report in raw['reports']:
                if 'forensics' in report and len(report['forensics']) > 0:
                    for forensic in report['forensics']:
                        if forensic.get('malicious', False):
                            malicious_count += 1
            
            if malicious_count > 0:
                level = "malicious"
                value = f"{malicious_count} malicious evidence(s)"
            else:
                level = "info"
                value = "No malicious evidence"
                
            taxonomies.append(
                self.build_taxonomy(level, namespace, "Forensics", value)
            )
        
        # Default se nessun dato
        if not taxonomies:
            if 'known' in raw and not raw['known']:
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Status", "Unknown")
                )
        
        return {"taxonomies": taxonomies}
    
    def enrich_with_threats_api(self, threat_id, auth, headers):
        """
        Chiama il Threats API per ottenere informazioni aggiuntive sulla minaccia
        """
        try:
            # Rimuovi /v2 se presente e costruisci URL corretto
            base_url = self.url.strip('/').rstrip('/v2')
            url = f"{base_url}/v2/threat/summary/{threat_id}"
            
            response = requests.get(
                url,
                headers=headers,
                verify=self.verify,
                auth=auth,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # Threat non trovato in Threats API (può succedere)
                return None
            else:
                # Altri errori, ma non blocchiamo - continuiamo senza enrichment
                return None
                
        except Exception as e:
            # In caso di errore, logga ma continua senza enrichment
            return None
        
    def run(self):
        Analyzer.run(self)
        
        try:
            user_agent = {'User-Agent': 'Cortex Analyzer'}
            sha256 = None
            report = {}
            
            if self.service == 'query':
                # Calcola hash dall'input
                if self.data_type == 'file':
                    filepath = self.get_param('file', None, 'File is missing')
                    with open(filepath, "rb") as f:
                        try:
                            # Python 3.11+
                            digest = hashlib.file_digest(f, "sha256")
                        except AttributeError:
                            # Python < 3.11
                            sha256_hash = hashlib.sha256()
                            for chunk in iter(lambda: f.read(4096), b""):
                                sha256_hash.update(chunk)
                            digest = sha256_hash
                    sha256 = digest.hexdigest()
                    
                elif self.data_type == 'hash':
                    hash_value = self.get_data()
                    if len(hash_value) == 64:  # SHA256
                        sha256 = hash_value
                    else:
                        self.error('Hash must be SHA256 (64 characters)')
                        return
                        
                elif self.data_type == 'url':
                    url_data = self.get_data()
                    sha256 = hashlib.sha256(url_data.encode()).hexdigest()
                    report['original_url'] = url_data
                    
                else:
                    # Per altri tipi, calcola hash
                    sha256 = hashlib.sha256(self.get_data().encode()).hexdigest()
            else:
                self.error('Unknown service. Use "query"')
                return
            
            if sha256 is None:
                self.error('No hash defined')
                return
            
            # Autenticazione
            auth = HTTPBasicAuth(self.apikey, self.secret)
            
            # STEP 1: Query Forensics API
            params = {'threatId': sha256}
            if self.include_campaign_forensics:
                params['includeCampaignForensics'] = 'true'
            
            response = requests.get(
                self.url.strip('/') + '/v2/forensics',
                params=params,
                headers=user_agent,
                verify=self.verify,
                auth=auth,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                report['known'] = True
                report['sha256'] = sha256
                
                if 'reports' in data:
                    report['reports'] = data['reports']
                if 'generated' in data:
                    report['generated'] = data['generated']
                
                # STEP 2: Auto-enrichment con Threats API (se abilitato)
                if self.auto_enrich and 'reports' in data and len(data['reports']) > 0:
                    # Prendi il threat ID dal primo report
                    threat_id = data['reports'][0].get('id')
                    
                    if threat_id:
                        threat_summary = self.enrich_with_threats_api(
                            threat_id, 
                            auth, 
                            user_agent
                        )
                        
                        if threat_summary:
                            # Aggiungi i dati enrichment al report
                            report['threat_summary'] = threat_summary
                            report['enriched'] = True
                        else:
                            report['enriched'] = False
                
                self.report(report)
                
            elif response.status_code == 400:
                self.error('Bad request sent to Proofpoint API')
                
            elif response.status_code == 401:
                self.error('Unauthorized access. Verify your API key and secret values')
                
            elif response.status_code == 404:
                report = {
                    'known': False,
                    'sha256': sha256,
                    'message': 'Threat ID not found in Proofpoint Forensics'
                }
                self.report(report)
                
            elif response.status_code == 429:
                self.error('Rate limit exceeded. Maximum 50 calls per 24 hours per threatId')
                
            elif response.status_code == 500:
                self.error('Internal server error from Proofpoint API')
                
            else:
                self.error(f'Unknown error. HTTP status code: {response.status_code}')
                
        except requests.exceptions.Timeout:
            self.error('Request timeout. Proofpoint API did not respond in time')
            
        except requests.exceptions.RequestException as e:
            self.error(f'Request error: {str(e)}')
            
        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    ProofpointForensicsAnalyzer().run()