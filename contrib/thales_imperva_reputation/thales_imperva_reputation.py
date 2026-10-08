#!/usr/bin/env python3
# encoding: utf-8

import ipaddress

import requests
from cortexutils.analyzer import Analyzer


class ThalesImpervaReputationAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.api_id = self.get_param('config.api_id', None, 'Imperva API ID is missing')
        self.api_key = self.get_param('config.api_key', None, 'Imperva API Key is missing')
        self.base_url = self.get_param(
            'config.base_url', 'https://api.imperva.com/ip-reputation'
        ).rstrip('/')
        self.verify = self.get_param('config.verifyssl', True)

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_headers(self):
        return {
            'accept': 'application/json',
            'x-API-Id': str(self.api_id),
            'x-API-Key': str(self.api_key),
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

        value = str(value).strip() if value is not None else ''
        if not value:
            self.error('Observable data is missing')

        return value

    def _validate_ipv4(self, value):
        try:
            return ipaddress.IPv4Address(value)
        except ValueError:
            self.error(f'Only IPv4 addresses are supported: {value}')

    def _get_reputation(self, ip):
        url = f'{self.base_url}/v1/reputation'

        try:
            response = requests.get(
                url,
                params={'ip': ip},
                headers=self._get_headers(),
                verify=self.verify,
                timeout=30
            )
        except Exception as exc:
            self.error(f'Exception during reputation lookup: {str(exc)}')

        if response.status_code == 200:
            return response.json()
        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            self.error(f'Imperva authentication failed (HTTP {response.status_code}): {response.text}')
        if response.status_code == 429:
            self.error('Imperva rate limit exceeded (10 requests per minute)')

        self.error(f'Reputation lookup failed (HTTP {response.status_code}): {response.text}')

    @staticmethod
    def _split_list(value):
        if not value or not isinstance(value, str):
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    @staticmethod
    def _parse_percentages(value):
        """Parse strings like 'Travel: 41%,Business: 20%' into [{'name', 'percentage'}]."""
        result = []
        if not value or not isinstance(value, str):
            return result
        for item in value.split(','):
            name, sep, pct = item.rpartition(':')
            if not sep:
                continue
            name, pct = name.strip(), pct.strip()
            if name and pct:
                result.append({'name': name, 'percentage': pct})
        return result

    def run(self):
        Analyzer.run(self)

        ip = str(self._validate_ipv4(self._get_input_data()))
        data = self._get_reputation(ip)

        if not data:
            self.report({'ioc': ip, 'found': False})
            return

        risk = data.get('risk_score') or {}
        report = {
            'ioc': ip,
            'found': True,
            'origin': data.get('origin') or {},
            'asn': data.get('ASN') or {},
            'risk_score': risk.get('risk_score'),
            'risk_score_number': risk.get('risk_score_number'),
            'risk_description': risk.get('risk_description'),
            'known_to_use': self._split_list(data.get('known_to_use')),
            'known_for': self._split_list(data.get('known_for')),
            'requests': data.get('requests'),
            'violations': self._parse_percentages(data.get('violations')),
            'client_application': self._parse_percentages(data.get('client_application')),
            'client_application_details': data.get('client_application_details'),
            'violations_over_time': data.get('violations_over_time'),
            'attacks_by_industries': self._parse_percentages(data.get('attacks_by_industries')),
            'raw': data,
        }

        self.report(report)

    def summary(self, raw):
        taxonomies = []
        namespace = 'Imperva'

        if not raw.get('found'):
            taxonomies.append(self.build_taxonomy('info', namespace, 'Reputation', 'Not Found'))
            return {'taxonomies': taxonomies}

        risk = str(raw.get('risk_score') or 'unknown').upper()
        level_map = {
            'CRITICAL': 'malicious',
            'HIGH': 'malicious',
            'MEDIUM': 'suspicious',
            'LOW': 'safe',
        }
        level = level_map.get(risk, 'info')
        score = raw.get('risk_score_number')
        value = f'{risk} ({score})' if score not in (None, '') else risk
        taxonomies.append(self.build_taxonomy(level, namespace, 'Risk', value))

        known_to_use = raw.get('known_to_use') or []
        if known_to_use:
            taxonomies.append(
                self.build_taxonomy('suspicious', namespace, 'KnownToUse', ', '.join(known_to_use[:3]))
            )

        known_for = raw.get('known_for') or []
        if known_for:
            taxonomies.append(
                self.build_taxonomy('suspicious', namespace, 'KnownFor', ', '.join(known_for[:3]))
            )

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    ThalesImpervaReputationAnalyzer().run()
