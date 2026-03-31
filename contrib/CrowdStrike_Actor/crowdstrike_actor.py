#!/usr/bin/env python3
# encoding: utf-8

import time
import requests
from cortexutils.analyzer import Analyzer


class CrowdStrikeActorAnalyzer(Analyzer):

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
        """Return actor query string from Cortex input."""
        try:
            value = self.get_data()
        except Exception:
            value = None

        if value is None:
            value = self.get_param('data.data', None)
        if value is None:
            value = self.get_param('data', None)

        if value is None:
            self.error('Actor query is missing')

        value = str(value).strip()
        if not value:
            self.error('Actor query is missing')

        return value

    def _search_actors(self, query):
        """Search CrowdStrike Intel for threat actors."""
        headers = self._get_headers()
        url = f"{self.base_url}/intel/combined/actors/v1"
        params = {
            'q': query,
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
            if response.status_code == 404:
                return {'resources': []}

            self.error(f'Actor search failed (HTTP {response.status_code}): {response.text}')

        except Exception as exc:
            self.error(f'Exception during actor search: {str(exc)}')

    def run(self):
        Analyzer.run(self)

        query = self._get_input_data()
        result = self._search_actors(query)
        if result is None:
            self.error('Actor search returned no data from API')
            return

        actors = result.get('resources', [])
        report = {
            'query': query,
            'found': len(actors) > 0,
            'actors': actors,
            'actor_count': len(actors)
        }

        self.report(report)

    def summary(self, raw):
        taxonomies = []
        namespace = 'CrowdStrike'

        if not raw.get('found'):
            taxonomies.append(self.build_taxonomy('info', namespace, 'Status', 'No Actors Found'))
            return {'taxonomies': taxonomies}

        count = raw.get('actor_count', 0)
        taxonomies.append(self.build_taxonomy('info', namespace, 'Actors Found', str(count)))

        actors = raw.get('actors', [])
        if actors:
            first_actor = actors[0]
            actor_name = first_actor.get('name', 'Unknown')
            taxonomies.append(self.build_taxonomy('suspicious', namespace, 'Actor', actor_name))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    CrowdStrikeActorAnalyzer().run()
