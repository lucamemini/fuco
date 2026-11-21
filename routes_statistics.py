"""Authenticated read-only APIs for FUCO statistics."""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request

from security import login_required_json


logger = logging.getLogger(__name__)
statistics_bp = Blueprint("statistics", __name__)
ALLOWED_PERIODS = frozenset((7, 30, 90))


def _period_days():
    raw_days = request.args.get("days", "30")
    try:
        days = int(raw_days)
    except (TypeError, ValueError):
        return None
    return days if days in ALLOWED_PERIODS else None


def _admin_usernames():
    configured = current_app.config.get("STATS_ADMIN_USERS", [])
    if isinstance(configured, str):
        configured = configured.replace(";", ",").split(",")
    if not isinstance(configured, (list, tuple, set)):
        return set()
    return {
        str(username).strip().casefold()
        for username in configured
        if str(username).strip()
    }


def _current_username():
    auth_manager = getattr(current_app, "auth_manager", None)
    return auth_manager.get_username() if auth_manager else None


def _is_admin(username):
    return bool(username) and username.casefold() in _admin_usernames()


def _period_bounds(days):
    end_at = datetime.now(timezone.utc)
    return end_at - timedelta(days=days), end_at


def _statistics_manager():
    manager = getattr(current_app, "statistics_manager", None)
    if manager is None:
        return None
    return manager


def _database_unavailable():
    logger.exception("Unable to read FUCO statistics")
    return jsonify({
        "success": False,
        "error": "Statistics database unavailable",
    }), 503


@statistics_bp.route("/api/statistics/aggregate", methods=["GET"])
@login_required_json
def api_statistics_aggregate():
    """Return global aggregates and the current user's individual aggregates."""
    days = _period_days()
    if days is None:
        return jsonify({
            "success": False,
            "error": "days must be one of 7, 30, or 90",
        }), 400

    current_username = _current_username()
    if not current_username:
        return jsonify({
            "success": False,
            "error": "Authenticated username unavailable",
        }), 401

    is_admin = _is_admin(current_username)
    requested_username = request.args.get("username")
    if requested_username and not is_admin:
        return jsonify({
            "success": False,
            "error": "Administrator access required",
        }), 403

    target_username = requested_username.strip() if requested_username else current_username
    if not target_username:
        return jsonify({
            "success": False,
            "error": "username must not be empty",
        }), 400

    manager = _statistics_manager()
    if manager is None:
        return jsonify({
            "success": False,
            "error": "Statistics are disabled or unavailable",
        }), 503

    start_at, end_at = _period_bounds(days)
    try:
        aggregate = manager.aggregate_events(start_at=start_at, end_at=end_at)
        individual = manager.aggregate_events(
            start_at=start_at,
            end_at=end_at,
            username=target_username,
        )
        global_dashboard = manager.dashboard_data(
            start_at=start_at, end_at=end_at
        )
        individual_dashboard = manager.dashboard_data(
            start_at=start_at,
            end_at=end_at,
            username=target_username,
        )
    except sqlite3.Error:
        return _database_unavailable()

    return jsonify({
        "success": True,
        "days": days,
        "is_admin": is_admin,
        "individual_username": target_username,
        "aggregate": aggregate,
        "individual": individual,
        "dashboard": global_dashboard,
        "individual_dashboard": individual_dashboard,
    })


@statistics_bp.route("/api/statistics/users", methods=["GET"])
@login_required_json
def api_statistics_users():
    """Return usernames with events in the selected period to administrators."""
    current_username = _current_username()
    if not current_username:
        return jsonify({
            "success": False,
            "error": "Authenticated username unavailable",
        }), 401
    if not _is_admin(current_username):
        return jsonify({
            "success": False,
            "error": "Administrator access required",
        }), 403

    days = _period_days()
    if days is None:
        return jsonify({
            "success": False,
            "error": "days must be one of 7, 30, or 90",
        }), 400

    manager = _statistics_manager()
    if manager is None:
        return jsonify({
            "success": False,
            "error": "Statistics are disabled or unavailable",
        }), 503

    start_at, end_at = _period_bounds(days)
    try:
        usernames = manager.list_usernames(start_at=start_at, end_at=end_at)
    except sqlite3.Error:
        return _database_unavailable()

    return jsonify({
        "success": True,
        "days": days,
        "users": usernames,
    })
