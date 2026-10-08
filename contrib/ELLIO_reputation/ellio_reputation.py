#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
from urllib.parse import quote

import requests
from cortexutils.analyzer import Analyzer


class ELLIOReputationAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.api_key = self.get_param('config.api_key', None, 'ELLIO API key is missing')
        self.base_url = self.get_param('config.base_url', 'https://api.ellio.tech').rstrip('/')
        self.verify = self.get_param('config.verifyssl', True)
        self.enable_cti = self.get_param('config.enable_cti', True)
        self.enable_rdns = self.get_param('config.enable_rdns', True)
        self.enable_cbs = self.get_param('config.enable_cbs', True)

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_headers(self):
        return {'accept': 'application/json', 'X-API-Key': str(self.api_key)}

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

        value = str(value).strip() if value is not None else ''
        if not value:
            self.error('Observable data is missing')

        return value

    def _validate_ip(self, value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            self.error(f'Invalid IP address: {value}')

    @staticmethod
    def _error_detail(response):
        try:
            body = response.json()
            return body.get('detail') or body.get('message') or body.get('title') or response.text
        except Exception:
            return response.text

    def _request(self, path, params=None):
        """Return (data, error). A 404 yields (None, None); other failures yield an error string."""
        url = f'{self.base_url}{path}'
        try:
            response = requests.get(
                url,
                params=params,
                headers=self._get_headers(),
                verify=self.verify,
                timeout=30
            )
        except Exception as exc:
            return None, f'Request failed: {str(exc)}'

        status = response.status_code
        if status == 200:
            try:
                return response.json(), None
            except ValueError:
                return None, 'Invalid JSON in response'
        if status == 404:
            return None, None

        detail = self._error_detail(response)
        if status == 401:
            return None, f'Authentication failed (HTTP 401): {detail}'
        if status == 403:
            return None, f'Forbidden, missing permission or active plan (HTTP 403): {detail}'
        if status == 429:
            return None, f'Rate limit exceeded (HTTP 429): {detail}'
        return None, f'HTTP {status}: {detail}'

    def run(self):
        Analyzer.run(self)

        ip = self._validate_ip(self._get_input_data())
        quoted_ip = quote(ip, safe='')

        report = {'ioc': ip, 'errors': {}}

        if self.enable_cti:
            cti, err = self._request(f'/v1/cti/lookup/{quoted_ip}')
            report['cti'] = cti
            if err:
                report['errors']['cti'] = err

        if self.enable_rdns:
            rdns, err = self._request(f'/v1/rdns/ip/{quoted_ip}')
            report['rdns'] = rdns
            if err:
                report['errors']['rdns'] = err

        if self.enable_cbs:
            cbs, err = self._request('/v1/cbs/lookup', params={'ip': ip})
            report['cbs'] = cbs
            if err:
                report['errors']['cbs'] = err

        queried = [name for name in ('cti', 'rdns', 'cbs') if name in report]
        if not queried:
            self.error('All ELLIO services are disabled in configuration')

        # Fail only when every queried service failed; partial results are still reported.
        if all(name in report['errors'] for name in queried):
            self.error('; '.join(f'{k}: {v}' for k, v in report['errors'].items()))

        self.report(report)

    def summary(self, raw):
        taxonomies = []
        namespace = 'ELLIO'

        cti = raw.get('cti')
        if 'cti' in raw and 'cti' not in raw.get('errors', {}):
            if cti and cti.get('seen'):
                classification = str(cti.get('classification') or 'seen')
                lowered = classification.lower()
                if 'malicious' in lowered:
                    level = 'malicious'
                elif 'benign' in lowered:
                    level = 'safe'
                else:
                    level = 'suspicious'
                taxonomies.append(self.build_taxonomy(level, namespace, 'CTI', classification))

                if cti.get('actor'):
                    taxonomies.append(self.build_taxonomy('suspicious', namespace, 'Actor', str(cti['actor'])))

                tags = cti.get('tags') or []
                if tags:
                    taxonomies.append(
                        self.build_taxonomy('info', namespace, 'Tags', ', '.join(tags[:3]))
                    )
            else:
                taxonomies.append(self.build_taxonomy('info', namespace, 'CTI', 'Not Seen'))

        cbs = raw.get('cbs')
        if cbs and cbs.get('found'):
            names = cbs.get('providers') or cbs.get('labels') or []
            if names:
                taxonomies.append(self.build_taxonomy('info', namespace, 'CBS', ', '.join(names[:3])))

        rdns = raw.get('rdns')
        if rdns and rdns.get('ptr'):
            taxonomies.append(self.build_taxonomy('info', namespace, 'PTR', str(len(rdns['ptr']))))

        if not taxonomies:
            taxonomies.append(self.build_taxonomy('info', namespace, 'Reputation', 'No Data'))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    ELLIOReputationAnalyzer().run()
