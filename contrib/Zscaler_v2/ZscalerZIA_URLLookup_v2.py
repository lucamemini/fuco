#!/usr/bin/env python3
# encoding: utf-8

import time
from urllib.parse import urlparse

import requests
from cortexutils.analyzer import Analyzer


class ZscalerZIA_URLLookupV2(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.zia_vanity_domain = self.get_param('config.zia_vanity_domain', None, 'ZIA Vanity Domain is required for OneAPI authentication')
        self.zia_client_id = self.get_param('config.zia_client_id', None, 'ZIA Client ID is required for OneAPI authentication')
        self.zia_client_secret = self.get_param('config.zia_client_secret', None, 'ZIA Client Secret is required for OneAPI authentication')
        self.oneapi_audience = self.get_param('config.oneapi_audience', 'https://api.zscaler.com')
        self.api_base_url = self.get_param('config.api_base_url', 'https://api.zsapi.net')

        self.malicious_categories = self.get_param('config.malicious_categories', [])
        self.suspicious_categories = self.get_param('config.suspicious_categories', [])
        self.verify = self.get_param('config.verifyssl', True)
        self.access_token = None
        self.token_expires_at = 0

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_access_token(self):
        if self.access_token and time.time() < (self.token_expires_at - 60):
            return self.access_token

        token_url = f"https://{self.zia_vanity_domain}.zslogin.net/oauth2/v1/token"
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.zia_client_id,
            'client_secret': self.zia_client_secret,
            'audience': self.oneapi_audience
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = requests.post(
            token_url,
            data=payload,
            headers=headers,
            verify=self.verify,
            timeout=30
        )

        if response.status_code != 200:
            self.error(f'OneAPI token request failed (HTTP {response.status_code})')

        try:
            data = response.json()
        except ValueError:
            self.error('Unexpected token response format from ZIdentity')

        access_token = data.get('access_token')
        expires_in = data.get('expires_in', 0)
        if not access_token:
            self.error('Access token missing from ZIdentity response')

        self.access_token = access_token
        self.token_expires_at = time.time() + int(expires_in)
        return access_token

    def _url_lookup_oneapi(self, normalized_url):
        base_url = (self.api_base_url or 'https://api.zsapi.net').rstrip('/')
        url = f"{base_url}/zia/api/v1/urlLookup"
        payload = [normalized_url]

        for attempt in range(3):
            access_token = self._get_access_token()
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            response = requests.post(
                url,
                headers=headers,
                json=payload,
                verify=self.verify,
                timeout=30
            )

            if response.status_code == 403:
                try:
                    data = response.json()
                except ValueError:
                    data = {}
                if response.headers.get('x-zscaler-mode') == 'read-only' or data.get('code') == 'STATE_READONLY':
                    if attempt < 2:
                        time.sleep(2 ** attempt)
                        continue
                self.error('ZIA is in read-only mode. Try again later.')

            if response.status_code != 200:
                self.error(f'ZIA urlLookup failed (HTTP {response.status_code})')

            try:
                data = response.json()
            except ValueError:
                self.error('Unexpected response format from ZIA urlLookup')

            if not isinstance(data, list) or not data:
                self.error('No results returned from ZIA urlLookup')

            return data[0]

    def _normalize_url(self, data, data_type):
        if data_type == 'url':
            url_data = urlparse(data)
            normalized = url_data.netloc + url_data.path
            if url_data.params:
                normalized += ';' + url_data.params
            if url_data.query:
                normalized += '?' + url_data.query
            return normalized
        return data

    def _classify_url(self, url_data):
        url = url_data.get('url', 'Unknown')
        url_classifications = url_data.get('urlClassifications', [])
        security_classifications = url_data.get('urlClassificationsWithSecurityAlert', [])
        db_categorized_urls = url_data.get('dbCategorizedUrls', [])
        custom_categories = url_data.get('customCategories', [])

        level = 'safe'
        matched_categories = []

        if security_classifications:
            level = 'suspicious'
            matched_categories = security_classifications

            if set(security_classifications).intersection(set(self.malicious_categories)):
                level = 'malicious'
                matched_categories = list(set(security_classifications).intersection(set(self.malicious_categories)))

        if url_classifications:
            if set(url_classifications).intersection(set(self.malicious_categories)):
                level = 'malicious'
                matched_categories = list(set(url_classifications).intersection(set(self.malicious_categories)))
            elif set(url_classifications).intersection(set(self.suspicious_categories)):
                if level != 'malicious':
                    level = 'suspicious'
                    matched_categories = list(set(url_classifications).intersection(set(self.suspicious_categories)))
            elif not security_classifications:
                level = 'safe'
                matched_categories = url_classifications

        return {
            'url': url,
            'level': level,
            'matched_categories': matched_categories,
            'all_classifications': url_classifications,
            'security_alerts': security_classifications,
            'custom_categories': custom_categories,
            'db_categorized_urls': db_categorized_urls,
            'metrics': {
                'total_categories': len(url_classifications),
                'security_alert_count': len(security_classifications),
                'has_custom_categories': len(custom_categories) > 0,
                'is_known_to_zscaler': len(db_categorized_urls) > 0 or len(url_classifications) > 0,
                'has_security_alerts': len(security_classifications) > 0
            }
        }

    def summary(self, raw):
        taxonomies = []

        classification = raw.get('classification', {})
        level = classification.get('level', 'info')
        matched_categories = classification.get('matched_categories', [])

        if matched_categories:
            value = ', '.join(matched_categories[:3])
            if len(matched_categories) > 3:
                value += f' (+{len(matched_categories) - 3} more)'
        else:
            value = 'No match'

        taxonomies.append(self.build_taxonomy(level, 'Zscaler', 'Category', value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)

        if self.data_type not in ['domain', 'fqdn', 'url', 'ip']:
            self.error(f'Invalid data type: {self.data_type}. Expected: domain, fqdn, url, or ip')

        data = self.get_param('data', None, 'No observable data available')
        try:
            normalized_url = self._normalize_url(data, self.data_type)
            url_data = self._url_lookup_oneapi(normalized_url)
            classification = self._classify_url(url_data)

            report = {
                'classification': classification,
                'categorization': {
                    'url_classifications': url_data.get('urlClassifications', []),
                    'security_alerts': url_data.get('urlClassificationsWithSecurityAlert', []),
                    'custom_categories': url_data.get('customCategories', []),
                    'db_categorized_urls': url_data.get('dbCategorizedUrls', [])
                },
                'assessment': {
                    'risk_level': classification['level'],
                    'is_malicious': classification['level'] == 'malicious',
                    'is_suspicious': classification['level'] in ['suspicious', 'malicious'],
                    'has_security_alerts': len(url_data.get('urlClassificationsWithSecurityAlert', [])) > 0,
                    'category_count': len(url_data.get('urlClassifications', [])),
                    'matched_threat_categories': classification['matched_categories']
                },
                'query': {
                    'original': data,
                    'normalized': normalized_url,
                    'type': self.data_type
                },
                'raw_response': url_data
            }

            self.report(report)

        except Exception as e:
            self.error(f'Unexpected error during URL lookup: {str(e)}')


if __name__ == '__main__':
    ZscalerZIA_URLLookupV2().run()