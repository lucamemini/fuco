#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import json
import re

class Minemeld(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.minemeld_url = self.get_param('config.minemeld_url', None, 'URL missing!')
        self.minemeld_user = self.get_param('config.minemeld_user', None, 'Username missing!')
        self.minemeld_password = self.get_param('config.minemeld_password', None, 'Password missing!')
        self.minemeld_indicator_list = self.get_param('config.minemeld_indicator_list', None, "List missing!")
        self.minemeld_share_level = self.get_param('config.minemeld_share_level', None, "Share level missing!")
        self.minemeld_confidence = self.get_param('config.minemeld_confidence', None, "Confidence level missing!")
        self.minemeld_ttl = self.get_param('config.minemeld_ttl', None, "TTL missing!")
        self.minemeld_timeout = self.get_param('config.minemeld_timeout', 15, "Timeout missing!")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
        self.observable_description = self.get_param('data.message', None, "Message is empty")
        self.observable = self.get_param('data.data', None, "Data is empty")
        
        # Regex patterns
        self.pattern_ipv4 = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
        self.pattern_ipv6 = re.compile(r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$')
        self.pattern_url = re.compile(r'^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&#+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.pattern_domain = re.compile(r'^([A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.)+[A-Za-z]{2,63}$')
        self.pattern_md5 = re.compile(r'^[0-9a-fA-F]{32}$')
        self.pattern_sha1 = re.compile(r'^[a-fA-F0-9]{40}$')
        self.pattern_sha256 = re.compile(r'^[a-fA-F0-9]{64}$')
    
    def detect_indicator_type(self):
        """Detect the correct indicator type based on regex patterns"""
        indicator_type = None
        verified = True
        
        # Check IP addresses
        if self.observable_type == "ip":
            if self.pattern_ipv4.match(self.observable):
                #indicator_type = "IPv4"
                indicator_type = "data_ip"
            elif self.pattern_ipv6.match(self.observable):
                indicator_type = "data_ipv6"
                verified = False
            else:
                indicator_type = "data_ip"
                verified = False
        
        # Check URL
        elif self.observable_type == "url":
            if self.pattern_url.match(self.observable):
                indicator_type = "data_url"
            else:
                indicator_type = "data_url"
                verified = False
        
        # Check domain/fqdn
        elif self.observable_type in ["domain", "fqdn"]:
            if self.pattern_domain.match(self.observable):
                indicator_type = "data_domain"
            else:
                indicator_type = f"data_{self.observable_type}"
                verified = False
        
        # Check hashes
        elif self.observable_type == "hash":
            if self.pattern_md5.match(self.observable):
                indicator_type = "data_md5"
            elif self.pattern_sha1.match(self.observable):
                indicator_type = "data_sha1"
            elif self.pattern_sha256.match(self.observable):
                indicator_type = "data_sha256"
            else:
                indicator_type = "data_hash"
                verified = False
        
        # For other types that are not verifiable
        else:
            indicator_type = f"data_{self.observable_type}"
            verified = False
        
        return indicator_type, verified
    
    def run(self):
        Responder.run(self)
        auth = (self.minemeld_user, self.minemeld_password)
        headers = {
            "Content-Type": "application/json"
        }
        
        # Detect indicator type
        indicator_type, verified = self.detect_indicator_type()
        
        # Build comment
        if not self.observable_description:
            comment = "Indicator submitted from TheHive"
        else:
            comment = self.observable_description
        
        # Add verification status to comment
        if not verified:
            comment = f"{comment} - [data type unverified]"
        
        # Normalize TTL
        ttl_value = None
        if self.minemeld_ttl is not None:
            try:
                ttl_value = int(self.minemeld_ttl)
            except (TypeError, ValueError):
                ttl_value = None

        # Build payload
        payload = {
            "indicator": self.observable,
            "type": indicator_type,
            "comment": comment,
            "share_level": self.minemeld_share_level,
            "confidence": self.minemeld_confidence,
            "ttl": ttl_value
        }

        # Send request
        try:
            r = requests.post(
                f"{self.minemeld_url}/config/data/{self.minemeld_indicator_list}_indicators/append?h={self.minemeld_indicator_list}&t=localdb",
                data=json.dumps(payload),
                headers=headers,
                auth=auth,
                verify=False,
                timeout=self.minemeld_timeout
            )
            r.raise_for_status()
            self.report({'message': f"Indicator {self.observable} (type: {indicator_type}) submitted to MineMeld."})
        except Exception as e:
            self.error({'message': f"Error submitting indicator: {str(e)}"})
    
    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='Minemeld:Indicator Added')]

if __name__ == '__main__':
    Minemeld().run()