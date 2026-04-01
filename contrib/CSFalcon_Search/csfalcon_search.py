#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
import json
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from cortexutils.analyzer import Analyzer


class CSFalconSearchAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.client_id = self.get_param('config.client_id', None, 'CrowdStrike Client ID is missing')
        self.client_secret = self.get_param('config.client_secret', None, 'CrowdStrike Client Secret is missing')
        self.base_url = self.get_param('config.base_url', 'https://api.eu-1.crowdstrike.com')
        self.verify = self.get_param('config.verifyssl', True)
        self.lookback_days = self._safe_int(self.get_param('config.lookback_days', 7), 7)
        self.max_results = max(1, min(100, self._safe_int(self.get_param('config.max_results', 20), 20)))
        self.include_hidden_alerts = bool(self.get_param('config.include_hidden_alerts', False))

        self.access_token = None
        self.token_expires_at = 0

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    @staticmethod
    def _safe_int(value, default):
        try:
            return int(value)
        except Exception:
            return default

    @staticmethod
    def _parse_ts(value):
        if not value:
            return None
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)

        text = str(value).strip()
        if not text:
            return None

        for candidate in (text, text.replace('Z', '+00:00')):
            try:
                parsed = datetime.fromisoformat(candidate)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except Exception:
                continue
        return None

    @staticmethod
    def _iso_utc_days_ago(days):
        dt = datetime.now(timezone.utc) - timedelta(days=max(0, int(days)))
        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

    @staticmethod
    def _deep_get(obj, path, default=None):
        cur = obj
        for key in path:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(key)
            if cur is None:
                return default
        return cur

    def _get_access_token(self):
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

    def _request_json(self, method, endpoint, params=None, body=None, timeout=30):
        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers()

        try:
            if method.upper() == 'GET':
                response = requests.get(url, params=params, headers=headers, verify=self.verify, timeout=timeout)
            else:
                response = requests.post(url, params=params, json=body, headers=headers, verify=self.verify, timeout=timeout)

            if 200 <= response.status_code < 300:
                return response.json()
            if response.status_code == 404:
                return {'resources': []}

            self.error(f'CrowdStrike API request failed (HTTP {response.status_code}) for {endpoint}: {response.text}')
        except Exception as exc:
            self.error(f'CrowdStrike API exception for {endpoint}: {str(exc)}')

    def _get_input_data(self):
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
        value = str(hash_value).strip().lower()
        if len(value) == 32:
            return 'md5'
        if len(value) == 40:
            return 'sha1'
        if len(value) == 64:
            return 'sha256'
        return None

    def _detect_ioc_type(self, value):
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

        if '@' in candidate and re.match(r'^[^@]+@[^@]+\.[^@]+$', candidate):
            return 'mail'

        if re.match(r'^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$', candidate):
            return 'fqdn'

        return 'other'

    def _get_input_data_type(self, data_value=None):
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

        return self._detect_ioc_type(data_value) or 'other'

    def _normalize_indicator(self, ioc_type, ioc_value):
        raw = str(ioc_value).strip()

        if ioc_type == 'hash':
            hash_type = self._detect_hash_type(raw)
            if hash_type in ('md5', 'sha256'):
                return hash_type, raw.lower(), None
            return None, raw, 'Direct telemetry lookup supports MD5 and SHA256 only; SHA1 will be alerts-only.'

        if ioc_type == 'ip':
            ip_obj = ipaddress.ip_address(raw)
            return ('ipv6' if ip_obj.version == 6 else 'ipv4'), raw, None

        if ioc_type in ('domain', 'fqdn'):
            return 'domain', raw.lower(), None

        if ioc_type == 'url':
            parsed = urlparse(raw)
            hostname = (parsed.hostname or '').strip().lower()
            if hostname:
                return 'domain', hostname, 'URL normalized to hostname for device/process telemetry lookup.'
            return None, raw, 'Unable to extract hostname from URL for direct telemetry lookup.'

        return None, raw, f'Direct device/process telemetry lookup is not supported for datatype: {ioc_type}. Alerts correlation will still run.'

    @staticmethod
    def _extract_resources(payload):
        if isinstance(payload, dict):
            resources = payload.get('resources')
            if isinstance(resources, list):
                return resources
            if resources is None:
                return []
            return [resources]
        if isinstance(payload, list):
            return payload
        return []

    @staticmethod
    def _extract_total_count(payload, fallback=0):
        if isinstance(payload, dict):
            for key in ('device_count', 'count', 'total', 'total_count'):
                value = payload.get(key)
                if isinstance(value, int):
                    return value

            resources = payload.get('resources')
            if isinstance(resources, dict):
                for key in ('device_count', 'count', 'total', 'total_count'):
                    value = resources.get(key)
                    if isinstance(value, int):
                        return value

            meta = payload.get('meta') or {}
            pagination = meta.get('pagination') or {}
            for key in ('total', 'count'):
                value = pagination.get(key)
                if isinstance(value, int):
                    return value

        return int(fallback or 0)

    def _get_device_details(self, device_ids):
        if not device_ids:
            return []

        payload = self._request_json('POST', '/devices/entities/devices/v2', body={'ids': device_ids[:100]})
        details = []
        for item in self._extract_resources(payload):
            if not isinstance(item, dict):
                continue
            details.append({
                'device_id': item.get('device_id') or item.get('aid') or item.get('id'),
                'hostname': item.get('hostname') or item.get('device_name'),
                'platform_name': item.get('platform_name'),
                'status': item.get('status'),
                'local_ip': item.get('local_ip'),
                'external_ip': item.get('external_ip'),
                'first_seen': item.get('first_seen'),
                'last_seen': item.get('last_seen') or item.get('modified_timestamp'),
                'os_version': item.get('os_version'),
                'machine_domain': item.get('machine_domain'),
            })
        return details

    def _get_process_details(self, process_ids):
        if not process_ids:
            return []

        params = {'ids': ','.join(process_ids[:100])}
        payload = self._request_json('GET', '/processes/entities/processes/v1', params=params)
        details = []
        for item in self._extract_resources(payload):
            if not isinstance(item, dict):
                continue
            details.append({
                'id': item.get('id') or item.get('process_id'),
                'device_id': item.get('device_id'),
                'filename': item.get('filename') or item.get('name'),
                'command_line': item.get('cmdline') or item.get('command_line'),
                'sha256': item.get('sha256'),
                'user_name': item.get('user_name') or item.get('user'),
                'timestamp': item.get('timestamp') or item.get('created_timestamp'),
            })
        return details

    def _search_telemetry(self, query_type, query_value):
        result = {
            'supported': bool(query_type),
            'query_type': query_type,
            'query_value': query_value,
            'device_count_total': 0,
            'device_count_recent': 0,
            'devices': [],
            'processes': [],
            'found_recent': False,
            'notes': []
        }

        if not query_type:
            result['notes'].append('No direct device/process telemetry API available for this datatype.')
            return result

        count_payload = self._request_json(
            'GET',
            '/iocs/aggregates/indicators/device-count/v1',
            params={'type': query_type, 'value': query_value}
        )
        result['device_count_total'] = self._extract_total_count(count_payload, 0)

        devices_payload = self._request_json(
            'GET',
            '/iocs/queries/indicators/devices/v1',
            params={'type': query_type, 'value': query_value, 'limit': self.max_results, 'offset': 0}
        )
        raw_devices = self._extract_resources(devices_payload)

        device_ids = []
        for item in raw_devices:
            if isinstance(item, str):
                device_ids.append(item)
            elif isinstance(item, dict):
                device_id = item.get('device_id') or item.get('aid') or item.get('id')
                if device_id:
                    device_ids.append(device_id)

        device_ids = list(dict.fromkeys(device_ids))
        detailed_devices = self._get_device_details(device_ids)

        if self.lookback_days > 0:
            since_dt = datetime.now(timezone.utc) - timedelta(days=self.lookback_days)
            recent_devices = []
            for item in detailed_devices:
                observed = self._parse_ts(item.get('last_seen') or item.get('first_seen'))
                if observed and observed >= since_dt:
                    recent_devices.append(item)
            result['devices'] = recent_devices
        else:
            result['devices'] = detailed_devices

        result['device_count_recent'] = len(result['devices']) if result['devices'] else min(len(device_ids), result['device_count_total'])
        result['found_recent'] = result['device_count_recent'] > 0

        processes_payload = self._request_json(
            'GET',
            '/iocs/queries/indicators/processes/v1',
            params={'type': query_type, 'value': query_value, 'limit': self.max_results, 'offset': 0}
        )
        raw_processes = self._extract_resources(processes_payload)
        process_ids = []
        process_fallback = []

        for item in raw_processes:
            if isinstance(item, str):
                process_ids.append(item)
            elif isinstance(item, dict):
                process_id = item.get('id') or item.get('process_id')
                if process_id:
                    process_ids.append(process_id)
                else:
                    process_fallback.append(item)

        detailed_processes = self._get_process_details(list(dict.fromkeys(process_ids)))
        result['processes'] = detailed_processes if detailed_processes else process_fallback[:self.max_results]
        return result

    def _search_recent_alerts(self, raw_value, normalized_value=None):
        search_terms = []
        for candidate in (raw_value, normalized_value):
            value = str(candidate or '').strip()
            if value and value not in search_terms:
                search_terms.append(value)

        since_iso = self._iso_utc_days_ago(self.lookback_days)
        alerts = []
        notes = []

        for term in search_terms:
            params = {
                'q': term,
                'filter': f"created_timestamp:>='{since_iso}'",
                'sort': 'created_timestamp|desc',
                'limit': self.max_results,
                'include_hidden': str(self.include_hidden_alerts).lower()
            }
            query_payload = self._request_json('GET', '/alerts/queries/alerts/v2', params=params)
            alert_ids = [x for x in self._extract_resources(query_payload) if isinstance(x, str)]
            if not alert_ids:
                continue

            details_payload = self._request_json(
                'POST',
                '/alerts/entities/alerts/v2',
                params={'include_hidden': str(self.include_hidden_alerts).lower()},
                body={'composite_ids': alert_ids[:1000]}
            )

            for item in self._extract_resources(details_payload):
                if not isinstance(item, dict):
                    continue
                alerts.append({
                    'id': item.get('composite_id') or item.get('id'),
                    'name': item.get('name') or item.get('scenario') or item.get('type'),
                    'status': item.get('status'),
                    'severity': item.get('severity'),
                    'created_timestamp': item.get('created_timestamp') or item.get('timestamp'),
                    'updated_timestamp': item.get('updated_timestamp'),
                    'hostname': self._deep_get(item, ['device', 'hostname']) or item.get('hostname'),
                    'product': item.get('product'),
                    'type': item.get('type'),
                })

            if alerts:
                notes.append(f"Recent alerts correlated using q='{term}' and created_timestamp>={since_iso}.")
                break

        dedup = []
        seen = set()
        for item in alerts:
            key = item.get('id') or json.dumps(item, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            dedup.append(item)

        return {
            'found': len(dedup) > 0,
            'count': len(dedup),
            'alerts': dedup[:self.max_results],
            'notes': notes,
        }

    def run(self):
        Analyzer.run(self)

        raw_value = self._get_input_data()
        ioc_type = self._get_input_data_type(raw_value)
        query_type, normalized_value, normalization_note = self._normalize_indicator(ioc_type, raw_value)

        telemetry = self._search_telemetry(query_type, normalized_value)
        alerts = self._search_recent_alerts(raw_value, normalized_value if normalized_value != raw_value else None)

        notes = []
        if normalization_note:
            notes.append(normalization_note)
        notes.extend(telemetry.get('notes', []))
        notes.extend(alerts.get('notes', []))

        found = bool(telemetry.get('found_recent') or alerts.get('found'))
        report = {
            'observable': raw_value,
            'input_type': ioc_type,
            'normalized_value': normalized_value,
            'telemetry_query_type': query_type,
            'lookback_days': self.lookback_days,
            'lookback_since': self._iso_utc_days_ago(self.lookback_days),
            'found': found,
            'telemetry_found': bool(telemetry.get('device_count_total', 0) > 0),
            'telemetry_found_recent': bool(telemetry.get('found_recent')),
            'device_count_total': telemetry.get('device_count_total', 0),
            'device_count_recent': telemetry.get('device_count_recent', 0),
            'devices': telemetry.get('devices', []),
            'processes': telemetry.get('processes', []),
            'alert_found': alerts.get('found', False),
            'alert_count': alerts.get('count', 0),
            'alerts': alerts.get('alerts', []),
            'notes': notes,
        }
        self.report(report)

    def summary(self, raw):
        taxonomies = []
        namespace = 'CrowdStrike'

        if raw.get('found'):
            level = 'suspicious' if raw.get('alert_count', 0) or raw.get('device_count_recent', 0) else 'info'
            taxonomies.append(self.build_taxonomy(level, namespace, 'Found', 'Yes'))
        else:
            taxonomies.append(self.build_taxonomy('safe', namespace, 'Found', 'No'))

        taxonomies.append(self.build_taxonomy('info', namespace, 'Lookback', f"{raw.get('lookback_days', 0)}d"))

        device_recent = int(raw.get('device_count_recent', 0) or 0)
        if device_recent:
            taxonomies.append(self.build_taxonomy('suspicious', namespace, 'Recent Devices', str(device_recent)))
        else:
            total_devices = int(raw.get('device_count_total', 0) or 0)
            if total_devices:
                taxonomies.append(self.build_taxonomy('info', namespace, 'Historical Devices', str(total_devices)))

        alert_count = int(raw.get('alert_count', 0) or 0)
        if alert_count:
            taxonomies.append(self.build_taxonomy('malicious', namespace, 'Recent Alerts', str(alert_count)))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    CSFalconSearchAnalyzer().run()
