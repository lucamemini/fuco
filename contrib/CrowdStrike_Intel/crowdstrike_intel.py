#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
import json
import re
import time

import requests
from cortexutils.analyzer import Analyzer


class CrowdStrikeIntelAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.client_id = self.get_param('config.client_id', None, 'CrowdStrike Client ID is missing')
        self.client_secret = self.get_param('config.client_secret', None, 'CrowdStrike Client Secret is missing')
        self.base_url = self.get_param('config.base_url', 'https://api.eu-2.crowdstrike.com')
        self.verify = self.get_param('config.verifyssl', True)

        self.access_token = None
        self.token_expires_at = 0

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_access_token(self):
        """Get or refresh OAuth2 access token from CrowdStrike."""
        if self.access_token and time.time() < (self.token_expires_at - 60):
            return self.access_token

        token_url = f"{self.base_url}/oauth2/token"
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        try:
            response = requests.post(
                token_url,
                data=payload,
                headers=headers,
                verify=self.verify,
                timeout=30
            )

            if not (200 <= response.status_code < 300):
                self.error(f'OAuth2 token request failed (HTTP {response.status_code}): {response.text}')

            data = response.json()
            access_token = data.get('access_token')
            expires_in = data.get('expires_in', 3600)

            if not access_token:
                self.error('Access token missing from OAuth2 response')

            self.access_token = access_token
            self.token_expires_at = time.time() + int(expires_in)
            return access_token

        except Exception as exc:
            self.error(f'Failed to obtain access token: {str(exc)}')

    def _get_headers(self):
        token = self._get_access_token()
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def _get_input_data(self):
        """Return observable data from Cortex input, with local-test fallbacks."""
        try:
            value = self.get_data()
        except Exception:
            value = None

        if value is None:
            value = self.get_param('data.data', None)
        if value is None:
            value = self.get_param('data', None)

        if value is None:
            self.error('Observable data is missing')

        value = str(value).strip()
        if not value:
            self.error('Observable data is missing')

        return value

    def _detect_hash_type(self, hash_value):
        hash_value = hash_value.strip().lower()
        length = len(hash_value)

        if length == 32:
            return 'md5'
        if length == 40:
            return 'sha1'
        if length == 64:
            return 'sha256'
        return None

    def _detect_ioc_type(self, value):
        """Infer data type when payload does not expose dataType."""
        candidate = str(value).strip()
        if not candidate:
            return None

        if self._detect_hash_type(candidate):
            return 'hash'

        try:
            ipaddress.ip_address(candidate)
            return 'ip'
        except ValueError:
            pass

        if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', candidate):
            return 'url'

        if re.match(r'^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$', candidate):
            return 'fqdn'

        return None

    def _get_input_data_type(self, data_value=None):
        """Resolve datatype from payload, else infer from data."""
        data_type = getattr(self, 'data_type', None)

        if not data_type:
            for key in ('data.dataType', 'data.datatype', 'dataType', 'datatype'):
                data_type = self.get_param(key, None)
                if data_type:
                    break

        if data_type:
            return str(data_type).strip().lower()

        if data_value is None:
            data_value = self._get_input_data()

        inferred_type = self._detect_ioc_type(data_value)
        if inferred_type:
            return inferred_type

        return 'other'

    def _build_indicator_params(self, ioc_type, ioc_value):
        """Build API query params for indicator search based on input type."""
        escaped_value = ioc_value.replace('"', '\\"')
        params = {'limit': 10}

        if ioc_type == 'hash':
            hash_type = self._detect_hash_type(ioc_value)
            if not hash_type:
                return None
            params['filter'] = f"type:'hash_{hash_type}'+indicator:'{escaped_value}'"
            return params

        if ioc_type == 'ip':
            params['filter'] = f"type:'ip_address'+indicator:'{escaped_value}'"
            return params

        if ioc_type in ('domain', 'fqdn', 'url'):
            params['filter'] = f"type:'domain'+indicator:'{escaped_value}'"
            return params

        if ioc_type == 'mail':
            params['filter'] = f"indicator:'{escaped_value}'"
            return params

        if ioc_type in ('other', 'filename', 'uri_path', 'user-agent', 'mail_subject', 'regexp'):
            params['q'] = ioc_value
            return params

        params['q'] = ioc_value
        return params

    def _to_summary_value(self, item, preferred_keys):
        """Convert API fields that may be dict/list/string to a summary string."""
        if item is None:
            return None

        if isinstance(item, str):
            value = item.strip()
            return value or None

        if isinstance(item, dict):
            for key in preferred_keys:
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()
            return json.dumps(item, sort_keys=True)

        if isinstance(item, (list, tuple, set)):
            values = []
            for sub_item in item:
                sub_value = self._to_summary_value(sub_item, preferred_keys)
                if sub_value:
                    values.append(sub_value)
            return ', '.join(values) if values else None

        return str(item)

    def _search_indicators(self, ioc_type, ioc_value):
        query_params = self._build_indicator_params(ioc_type, ioc_value)
        if not query_params:
            return {'error': f'Unsupported IoC type or invalid hash format: {ioc_type}'}

        headers = self._get_headers()
        url = f"{self.base_url}/intel/combined/indicators/v1"

        try:
            response = requests.get(
                url,
                params=query_params,
                headers=headers,
                verify=self.verify,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                return {'resources': []}

            self.error(f'Indicator search failed (HTTP {response.status_code}): {response.text}')

        except Exception as exc:
            self.error(f'Exception during indicator search: {str(exc)}')

    def run(self):
        Analyzer.run(self)

        ioc_value = self._get_input_data()
        ioc_type = self._get_input_data_type(ioc_value)

        result = self._search_indicators(ioc_type, ioc_value)
        if result is None:
            self.error('Indicator search returned no data from API')
            return

        if 'error' in result:
            self.error(result['error'])
            return

        indicators = result.get('resources', [])
        report = {
            'ioc': ioc_value,
            'ioc_type': ioc_type,
            'found': len(indicators) > 0,
            'indicators': indicators,
            'indicator_count': len(indicators)
        }

        all_actors = set()
        all_labels = set()
        max_confidence = 'unverified'

        for indicator in indicators:
            confidence = indicator.get('malicious_confidence', 'unverified')
            if confidence == 'high':
                max_confidence = 'high'
            elif confidence == 'medium' and max_confidence != 'high':
                max_confidence = 'medium'
            elif confidence == 'low' and max_confidence not in ('high', 'medium'):
                max_confidence = 'low'

            for actor in indicator.get('actors', []):
                actor_value = self._to_summary_value(actor, ['name', 'slug', 'short_name', 'value', 'label'])
                if actor_value:
                    all_actors.add(actor_value)

            for label in indicator.get('labels', []):
                label_value = self._to_summary_value(label, ['name', 'label', 'value', 'slug'])
                if label_value:
                    all_labels.add(label_value)

        report['summary_actors'] = list(all_actors)
        report['summary_labels'] = list(all_labels)
        report['max_confidence'] = max_confidence

        self.report(report)

    def summary(self, raw):
        taxonomies = []
        namespace = 'CrowdStrike'

        if not raw.get('found'):
            taxonomies.append(self.build_taxonomy('info', namespace, 'Status', 'Not Found'))
            return {'taxonomies': taxonomies}

        max_confidence = raw.get('max_confidence', 'unverified')
        confidence_level_map = {
            'high': 'malicious',
            'medium': 'suspicious',
            'low': 'suspicious',
            'unverified': 'info'
        }

        level = confidence_level_map.get(max_confidence, 'info')
        taxonomies.append(self.build_taxonomy(level, namespace, 'Confidence', max_confidence.title()))

        actors = raw.get('summary_actors', [])
        if actors:
            actor_str = ', '.join(actors[:3])
            actor_level = 'malicious' if max_confidence == 'high' else 'suspicious'
            taxonomies.append(self.build_taxonomy(actor_level, namespace, 'Actors', actor_str))

        labels = raw.get('summary_labels', [])
        if labels:
            label_str = ', '.join(labels[:3])
            taxonomies.append(self.build_taxonomy('suspicious', namespace, 'Labels', label_str))

        count = raw.get('indicator_count', 0)
        count_level = 'malicious' if count > 0 and max_confidence == 'high' else 'info'
        taxonomies.append(self.build_taxonomy(count_level, namespace, 'Indicators', str(count)))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    CrowdStrikeIntelAnalyzer().run()
