#!/usr/bin/env python3
# encoding: utf-8

import csv
import hashlib
import json
import os
import time

import requests
from cortexutils.analyzer import Analyzer


class CertGraveyardLookupAnalyzer(Analyzer):
    PARAM_TO_COLUMNS = {
        'sha256': ['Hash'],
        'email': ['Email'],
        'thumbprint': ['Thumbprint'],
        'tbs_md5': ['TBS MD5'],
        'tbs_sha1': ['TBS SHA1'],
        'tbs_sha256': ['TBS SHA256'],
        'tbs_sha384': ['TBS SHA384'],
        'signer': ['Signer'],
        'issuer-short': ['Issuer Short'],
        'issuer': ['Issuer'],
        'serial': ['Serial'],
        'rdn-serial': ['RDN Serial Number']
    }

    def __init__(self):
        Analyzer.__init__(self)
        self.mode = self.get_param('config.mode', 'online')
        self.api_key = self.get_param('config.api_key', None)
        self.query_url = self.get_param(
            'config.query_url',
            'https://certgraveyard.org/api/query_database'
        )
        self.download_url = self.get_param(
            'config.download_url',
            'https://certgraveyard.org/api/download_csv'
        )
        self.cache_max_hours = int(self.get_param('config.cache_max_hours', 24))
        self.local_db_path = self.get_param(
            'config.local_db_path',
            'cert_graveyard_database.csv'
        )
        self.other_search_parameter = self.get_param(
            'config.other_search_parameter',
            'signer'
        )
        self.verify = self.get_param('config.verifyssl', True)

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        if not os.path.isabs(self.local_db_path):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.local_db_path = os.path.join(base_dir, self.local_db_path)

    def summary(self, raw):
        taxonomies = []
        namespace = 'CertGraveyard'
        count = raw.get('count', 0)

        if count > 0:
            taxonomies.append(
                self.build_taxonomy('malicious', namespace, 'Match', f'{count} record(s)')
            )
            malware_names = []
            for record in raw.get('records', []):
                malware = (record.get('malware') or '').strip()
                if malware and malware not in malware_names:
                    malware_names.append(malware)
            if malware_names:
                value = malware_names[0] if len(malware_names) == 1 else f'{len(malware_names)} malware name(s)'
                taxonomies.append(
                    self.build_taxonomy('malicious', namespace, 'Malware', value)
                )
        else:
            taxonomies.append(
                self.build_taxonomy('safe', namespace, 'Match', 'No match')
            )

        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)

        try:
            term, parameters = self.resolve_query()
            if term is None or not parameters:
                return

            query = {
                'parameters': parameters,
                'term': term,
                'data_type': self.data_type
            }

            if self.is_local_mode():
                records, cache_info = self.query_local(term, parameters)
                report = {
                    'query': query,
                    'source': 'local',
                    'count': len(records),
                    'records': records,
                    'cache': cache_info
                }
            else:
                records = self.query_api(parameters[0], term)
                report = {
                    'query': query,
                    'source': 'api',
                    'count': len(records),
                    'records': records
                }

            self.report(report)

        except requests.exceptions.Timeout:
            self.error('Request timeout. The Cert Graveyard API did not respond in time')
        except requests.exceptions.RequestException as exc:
            self.error(f'Request error: {str(exc)}')
        except Exception as exc:
            self.unexpectedError(exc)

    def is_local_mode(self):
        return self.mode.lower() in ('local', 'download', 'offline')

    def resolve_query(self):
        if self.data_type == 'file':
            filepath = self.get_param('file', None, 'File is missing')
            with open(filepath, 'rb') as file_handle:
                try:
                    digest = hashlib.file_digest(file_handle, 'sha256')
                except AttributeError:
                    sha256_hash = hashlib.sha256()
                    for chunk in iter(lambda: file_handle.read(4096), b''):
                        sha256_hash.update(chunk)
                    digest = sha256_hash
            return digest.hexdigest(), ['sha256']

        if self.data_type == 'hash':
            hash_value = self.get_data()
            if len(hash_value) != 64:
                self.error('Hash must be SHA256 (64 characters)')
                return None, []
            return hash_value, ['sha256']

        if self.data_type == 'mail':
            term = (self.get_data() or '').strip()
            if not term:
                self.error('Email value is missing')
                return None, []
            return term, ['email']

        if self.data_type == 'certificate_hash':
            term = (self.get_data() or '').strip()
            if len(term) not in (32, 40, 64, 96):
                self.error('Certificate hash must be MD5 (32), SHA1 (40), SHA256 (64), or SHA384 (96)')
                return None, []

            if self.is_local_mode():
                return term, ['tbs_md5', 'tbs_sha1', 'tbs_sha256', 'tbs_sha384', 'thumbprint']

            if len(term) == 40:
                return term, ['thumbprint']

            self.error('Online mode supports only thumbprint (SHA1). Use local mode for TBS hashes')
            return None, []

        if self.data_type == 'other':
            term = (self.get_data() or '').strip()
            if not term:
                self.error('Other value is missing')
                return None, []

            if self.is_local_mode():
                return term, ['signer', 'issuer-short', 'issuer', 'serial', 'rdn-serial']

            allowed = ('signer', 'issuer-short', 'issuer', 'serial')
            if self.other_search_parameter not in allowed:
                self.error('Invalid other_search_parameter. Use signer, issuer-short, issuer, or serial')
                return None, []
            return term, [self.other_search_parameter]

        self.error('Unsupported data type. Use hash, file, mail, certificate_hash, or other')
        return None, []

    def query_api(self, parameter, term):
        if not self.api_key:
            self.error('API key is missing. Configure config.api_key or use local mode')
            return []

        headers = {
            'X-API-KEY': self.api_key,
            'Content-Type': 'application/json'
        }
        payload = {
            'search_parameter': parameter,
            'search_term': term
        }

        response = requests.post(
            self.query_url,
            headers=headers,
            data=json.dumps(payload),
            verify=self.verify,
            timeout=30
        )

        if response.status_code != 200:
            self.error(f'API returned HTTP {response.status_code}')
            return []

        try:
            data = response.json()
        except ValueError:
            self.error('Unexpected response format from API')
            return []

        return self.normalize_results(data)

    def query_local(self, term, parameters):
        path, cache_info = self.ensure_local_db()
        records = []
        term_value = (term or '').strip()
        if not term_value:
            return records, cache_info
        term_lower = term_value.lower()

        if not path or not os.path.exists(path):
            return records, cache_info

        with open(path, 'r', newline='', encoding='utf-8') as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if self.row_matches(row, term_lower, parameters):
                    records.append(self.normalize_record(row))

        return records, cache_info

    def row_matches(self, row, term_lower, parameters):
        for parameter in parameters:
            columns = self.PARAM_TO_COLUMNS.get(parameter, [])
            for column in columns:
                value = (row.get(column) or '').strip()
                if value and value.lower() == term_lower:
                    return True
        return False

    def ensure_local_db(self):
        refreshed = False
        stale = False
        os.makedirs(os.path.dirname(self.local_db_path), exist_ok=True)

        if os.path.exists(self.local_db_path):
            age_hours = (time.time() - os.path.getmtime(self.local_db_path)) / 3600
        else:
            age_hours = None

        if (age_hours is None) or (age_hours > self.cache_max_hours):
            response = requests.get(
                self.download_url,
                verify=self.verify,
                timeout=60
            )
            if response.status_code != 200:
                if os.path.exists(self.local_db_path):
                    age_hours = (time.time() - os.path.getmtime(self.local_db_path)) / 3600
                    stale = age_hours > self.cache_max_hours
                else:
                    self.error(f'Failed to download CSV (HTTP {response.status_code})')
                    return None, {
                        'path': self.local_db_path,
                        'age_hours': None,
                        'refreshed': False,
                        'stale': False
                    }
                return self.local_db_path, {
                    'path': self.local_db_path,
                    'age_hours': round(age_hours, 2) if age_hours is not None else None,
                    'refreshed': False,
                    'stale': stale
                }

            with open(self.local_db_path, 'wb') as handle:
                handle.write(response.content)

            refreshed = True
            age_hours = 0.0

        return self.local_db_path, {
            'path': self.local_db_path,
            'age_hours': round(age_hours, 2) if age_hours is not None else None,
            'refreshed': refreshed,
            'stale': age_hours is not None and age_hours > self.cache_max_hours
        }

    def normalize_results(self, data):
        if isinstance(data, list):
            return [self.normalize_record(item) for item in data if isinstance(item, dict)]

        if isinstance(data, dict):
            for key in ['results', 'data', 'result']:
                if key in data and isinstance(data[key], list):
                    return [self.normalize_record(item) for item in data[key] if isinstance(item, dict)]
            if 'error' in data:
                self.error(data.get('error', 'API error'))
                return []
            return [self.normalize_record(data)]

        return []

    def normalize_record(self, record):
        def get_value(*keys):
            for key in keys:
                if key in record and record[key] is not None:
                    return str(record[key]).strip()
            return ''

        return {
            'hash': get_value('Hash', 'hash'),
            'malware': get_value('Malware', 'malware'),
            'malware_type': get_value('Malware Type', 'malware_type'),
            'malware_notes': get_value('Malware Notes', 'malware_notes'),
            'signer': get_value('Signer', 'signer'),
            'issuer_short': get_value('Issuer Short', 'issuer_short'),
            'issuer': get_value('Issuer', 'issuer'),
            'serial': get_value('Serial', 'serial'),
            'thumbprint': get_value('Thumbprint', 'thumbprint'),
            'valid_from': get_value('Valid From', 'valid_from'),
            'valid_to': get_value('Valid To', 'valid_to'),
            'country': get_value('Country', 'country'),
            'state': get_value('State', 'state'),
            'locality': get_value('Locality', 'locality'),
            'email': get_value('Email', 'email'),
            'rdn_serial_number': get_value('RDN Serial Number', 'rdn_serial_number'),
            'tbs_md5': get_value('TBS MD5', 'tbs_md5'),
            'tbs_sha1': get_value('TBS SHA1', 'tbs_sha1'),
            'tbs_sha256': get_value('TBS SHA256', 'tbs_sha256'),
            'tbs_sha384': get_value('TBS SHA384', 'tbs_sha384')
        }


if __name__ == '__main__':
    CertGraveyardLookupAnalyzer().run()
