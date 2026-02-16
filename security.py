"""
security.py - Utilities for auth, CSRF, and rate limiting
"""
import logging
from functools import wraps
from typing import Callable

from flask import current_app, jsonify
from flask_wtf import CSRFProtect
from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

def _get_client_ip() -> str:
    """
    Get the real client IP address, considering proxy headers.
    Priority: X-Forwarded-For > X-Real-IP > remote_addr
    """
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    x_real_ip = request.headers.get('X-Real-IP')
    remote_addr = request.remote_addr or ''
    
    if x_forwarded_for:
        # X-Forwarded-For può contenere più IP: "client, proxy1, proxy2"
        # Prendiamo il primo (client originale)
        client_ip = x_forwarded_for.split(',')[0].strip()
        logger.debug(f"IP from X-Forwarded-For: {client_ip} (full: {x_forwarded_for})")
        return client_ip
    
    if x_real_ip:
        logger.debug(f"IP from X-Real-IP: {x_real_ip}")
        return x_real_ip
    
    logger.debug(f"IP from remote_addr: {remote_addr}")
    return remote_addr


class CSRFProtectWithAllowlist(CSRFProtect):
    def _protect(self):
        allowlist = current_app.config.get('CSRF_WHITELIST', [])
        if isinstance(allowlist, str):
            allowlist = [ip.strip() for ip in allowlist.replace(',', ';').split(';') if ip.strip()]
        
        client_ip = _get_client_ip()
        
        if allowlist:
            if client_ip in allowlist:
                logger.debug(f"CSRF check bypassed for whitelisted IP: {client_ip}")
                return
            else:
                logger.debug(
                    f"CSRF check enforced: IP {client_ip} not in whitelist {allowlist}"
                )
        
        # Enforce CSRF protection
        return super()._protect()


csrf = CSRFProtectWithAllowlist()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


def optional_limit(limit_value):
    """
    Apply a rate limit only if a value is provided.
    Use None/""/0 to disable the limit.
    """
    if not limit_value:
        def decorator(f):
            return f
        return decorator
    return limiter.limit(limit_value)


def login_required_json(f: Callable):
    """
    Require authenticated session for API endpoints.
    Returns JSON 401 on missing authentication.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_manager = getattr(current_app, 'auth_manager', None)
        if not auth_manager or not auth_manager.is_authenticated():
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'message': 'Please login first'
            }), 401
        return f(*args, **kwargs)
    return wrapper
