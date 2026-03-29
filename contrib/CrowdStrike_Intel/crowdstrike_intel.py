#!/usr/bin/env python3
# encoding: utf-8

import time
import hashlib
import json
import re
from urllib.parse import quote

import requests
from cortexutils.analyzer import Analyzer


class CrowdStrikeIntelAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.client_id = self.get_param('config.client_id', None, 'CrowdStrike Client ID is missing')
        self.client_secret = self.get_param('config.client_secret', None, 'CrowdStrike Client Secret is missing')
        self.base_url = self.get_param('config.base_url', 'https://api.eu-2.crowdstrike.com')
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.verify = self.get_param('config.verifyssl', True)

        self.access_token = None
        self.token_expires_at = 0

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_access_token(self):
        """Get or refresh OAuth2 access token from CrowdStrike."""
        # Return cached token if still valid (with 60s buffer)
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

            if response.status_code != 200:
                self.error(f'OAuth2 token request failed (HTTP {response.status_code}): {response.text}')

            data = response.json()
            access_token = data.get('access_token')
            expires_in = data.get('expires_in', 3600)

            if not access_token:
                self.error('Access token missing from OAuth2 response')

            self.access_token = access_token
            self.token_expires_at = time.time() + int(expires_in)
            return access_token

        except Exception as e:
            self.error(f'Failed to obtain access token: {str(e)}')

    def _get_headers(self):
        """Build authorization headers with bearer token."""
        token = self._get_access_token()
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def _detect_hash_type(self, hash_value):
        """Detect hash type based on length."""
        hash_value = hash_value.strip().lower()
        length = len(hash_value)

        if length == 32:
            return 'md5'
        elif length == 40:
            return 'sha1'
        elif length == 64:
            return 'sha256'
        else:
            return None

    def _build_indicator_filter(self, ioc_type, ioc_value):
        """Build FQL filter for indicator search based on IoC type."""
        # Escape quotes in value for FQL
        escaped_value = ioc_value.replace('"', '\\"')

        if ioc_type == 'hash':
            hash_type = self._detect_hash_type(ioc_value)
            if not hash_type:
                return None
            return f'type:\'hash_{hash_type}\'+indicator:\'{escaped_value}\''

        elif ioc_type == 'ip':
            return f'type:\'ip_address\'+indicator:\'{escaped_value}\''

        elif ioc_type in ['domain', 'fqdn', 'url']:
            return f'type:\'domain\'+indicator:\'{escaped_value}\''

        return None

    def _search_indicators(self, ioc_type, ioc_value):
        """Search CrowdStrike Intel for indicators."""
        fql_filter = self._build_indicator_filter(ioc_type, ioc_value)

        if not fql_filter:
            return {'error': f'Unsupported IoC type or invalid hash format: {ioc_type}'}

        headers = self._get_headers()
        url = f"{self.base_url}/intelligence/combined/indicators/v1"

        params = {
            'filter': fql_filter,
            'limit': 10
        }

        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                verify=self.verify,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'resources': []}
            else:
                self.error(f'Indicator search failed (HTTP {response.status_code}): {response.text}')

        except Exception as e:
            self.error(f'Exception during indicator search: {str(e)}')

    def _search_actors(self, freetext_query):
        """Search CrowdStrike Intel for threat actors."""
        headers = self._get_headers()
        url = f"{self.base_url}/intelligence/combined/actors/v1"

        params = {
            'q': freetext_query,
            'limit': 5
        }

        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                verify=self.verify,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'resources': []}
            else:
                self.error(f'Actor search failed (HTTP {response.status_code}): {response.text}')

        except Exception as e:
            self.error(f'Exception during actor search: {str(e)}')

    def run(self):
        """Main analyzer execution."""
        Analyzer.run(self)

        if self.service == 'intel_indicator':
            self._run_intel_indicator()
        elif self.service == 'intel_actor':
            self._run_intel_actor()
        else:
            self.error(f'Unknown service: {self.service}. Use "intel_indicator" or "intel_actor"')

    def _run_intel_indicator(self):
        """Process indicator lookup."""
        ioc_type = self.data_type
        ioc_value = self.get_data()

        result = self._search_indicators(ioc_type, ioc_value)

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

        # Extract unique actors and labels for summary
        all_actors = set()
        all_labels = set()
        max_confidence = 'unverified'

        for indicator in indicators:
            # Track confidence level
            confidence = indicator.get('malicious_confidence', 'unverified')
            if confidence == 'high':
                max_confidence = 'high'
            elif confidence == 'medium' and max_confidence != 'high':
                max_confidence = 'medium'
            elif confidence == 'low' and max_confidence not in ['high', 'medium']:
                max_confidence = 'low'

            # Collect actors
            for actor in indicator.get('actors', []):
                all_actors.add(actor)

            # Collect labels
            for label in indicator.get('labels', []):
                all_labels.add(label)

        report['summary_actors'] = list(all_actors)
        report['summary_labels'] = list(all_labels)
        report['max_confidence'] = max_confidence

        self.report(report)

    def _run_intel_actor(self):
        """Process actor lookup."""
        query = self.get_data()

        result = self._search_actors(query)

        actors = result.get('resources', [])

        report = {
            'query': query,
            'found': len(actors) > 0,
            'actors': actors,
            'actor_count': len(actors)
        }

        self.report(report)

    def summary(self, raw):
        """Build taxonomy summary from raw report."""
        taxonomies = []
        namespace = "CrowdStrike"

        if self.service == 'intel_indicator':
            return self._summary_indicator(raw, taxonomies, namespace)
        elif self.service == 'intel_actor':
            return self._summary_actor(raw, taxonomies, namespace)

        return {"taxonomies": taxonomies}

    def _summary_indicator(self, raw, taxonomies, namespace):
        """Summarize indicator results."""
        if not raw.get('found'):
            taxonomies.append(self.build_taxonomy("info", namespace, "Status", "Not Found"))
            return {"taxonomies": taxonomies}

        max_confidence = raw.get('max_confidence', 'unverified')
        confidence_level_map = {
            'high': 'malicious',
            'medium': 'suspicious',
            'low': 'suspicious',
            'unverified': 'info'
        }

        level = confidence_level_map.get(max_confidence, 'info')
        taxonomies.append(self.build_taxonomy(level, namespace, "Confidence", max_confidence.title()))

        # Add actor info if available
        actors = raw.get('summary_actors', [])
        if actors:
            actor_str = ', '.join(actors[:3])  # limit to 3 for readability
            actor_level = 'malicious' if max_confidence == 'high' else 'suspicious'
            taxonomies.append(self.build_taxonomy(actor_level, namespace, "Actors", actor_str))

        # Add label info if available
        labels = raw.get('summary_labels', [])
        if labels:
            label_str = ', '.join(labels[:3])
            taxonomies.append(self.build_taxonomy('suspicious', namespace, "Labels", label_str))

        # Add count
        count = raw.get('indicator_count', 0)
        count_level = 'malicious' if count > 0 and max_confidence == 'high' else 'info'
        taxonomies.append(self.build_taxonomy(count_level, namespace, "Indicators", str(count)))

        return {"taxonomies": taxonomies}

    def _summary_actor(self, raw, taxonomies, namespace):
        """Summarize actor results."""
        if not raw.get('found'):
            taxonomies.append(self.build_taxonomy("info", namespace, "Status", "No Actors Found"))
            return {"taxonomies": taxonomies}

        count = raw.get('actor_count', 0)
        taxonomies.append(self.build_taxonomy("info", namespace, "Actors Found", str(count)))

        # Add first actor name if available
        actors = raw.get('actors', [])
        if actors and len(actors) > 0:
            first_actor = actors[0]
            actor_name = first_actor.get('name', 'Unknown')
            taxonomies.append(self.build_taxonomy("suspicious", namespace, "Actor", actor_name))

        return {"taxonomies": taxonomies}
