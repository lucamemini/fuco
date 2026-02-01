"""
security.py - Utilities for auth, CSRF, and rate limiting
"""
from functools import wraps
from typing import Callable

from flask import current_app, jsonify
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

csrf = CSRFProtect()
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
