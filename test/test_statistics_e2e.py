import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask, session

import ai_manager
from routes import routes_bp
from routes_statistics import statistics_bp
from statistics_manager import StatisticsManager


class SessionAuthManager:
    def is_authenticated(self):
        return bool(session.get("cortex_authenticated"))

    def get_username(self):
        return session.get("cortex_username") if self.is_authenticated() else None


class AssessmentCache:
    def __init__(self):
        self.assessments = {}

    def get_ai_assessment(self, key):
        return self.assessments.get(key)

    def set_ai_assessment(self, key, value):
        self.assessments[key] = value


class CompletedReport:
    status = "Success"
    analyzerName = "TestAnalyzer"
    errorMessage = None
    report = {
        "summary": {
            "taxonomies": [
                {"level": "safe", "predicate": "verdict", "value": "safe"}
            ],
            "evidence": "REPORT_SECRET_MARKER",
        }
    }

    def json(self):
        return self.report


class StatisticsEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = str(Path(self.temp_dir.name) / "stats.sqlite3")
        self.statistics = StatisticsManager(db_path)
        self.statistics.initialize()

        self.app = Flask(__name__)
        self.app.secret_key = "test"
        self.app.config["TESTING"] = True
        self.app.config["STATS_ADMIN_USERS"] = ["root"]
        self.app.statistics_manager = self.statistics
        self.app.cache_manager = AssessmentCache()
        self.app.auth_manager = SessionAuthManager()
        self.app.register_blueprint(routes_bp)
        self.app.register_blueprint(statistics_bp)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def login_as(self, username):
        with self.client.session_transaction() as user_session:
            user_session["cortex_authenticated"] = True
            user_session["cortex_username"] = username
            user_session["cortex_api_key"] = "API_KEY_SECRET_MARKER"

    def test_fresh_cache_personal_admin_visibility_and_database_minimization(self):
        self.login_as("analyst")
        provider = mock.Mock(
            return_value=(
                {"summary": "assessment"},
                {
                    "model": "test-model",
                    "latency_ms": 25,
                    "token_usage": {
                        "input_tokens": 11,
                        "output_tokens": 7,
                        "total_tokens": 18,
                    },
                },
            )
        )
        request_body = {
            "observable": "secret123.test",
            "datatype": "domain",
            "jobs": ["cortex-job-1"],
            "provider": "test",
        }

        with mock.patch.object(ai_manager, "is_enabled", return_value=True), \
                mock.patch.object(
                    ai_manager, "resolve_provider", return_value="test"
                ), \
                mock.patch.dict(ai_manager._PROVIDER_CALLS, {"test": provider}), \
                mock.patch(
                    "routes.utils.get_cached_report",
                    return_value=(CompletedReport(), "cortex"),
                ):
            fresh_response = self.client.post(
                "/api/ai/analyze", json=request_body
            )
            cache_response = self.client.post(
                "/api/ai/analyze", json=request_body
            )

        self.assertEqual(fresh_response.status_code, 200)
        self.assertEqual(fresh_response.get_json()["source"], "fresh")
        self.assertEqual(cache_response.status_code, 200)
        self.assertEqual(cache_response.get_json()["source"], "cache")
        provider.assert_called_once()

        self.statistics.record_event(
            "analyzer",
            job_id="bob-job",
            username="bob",
            analyzer_name="PrivateAnalyzer",
            status="Success",
        )
        standard_response = self.client.get("/api/statistics/aggregate?days=30")
        self.assertEqual(standard_response.status_code, 200)
        standard_data = standard_response.get_json()
        self.assertEqual(standard_data["individual_username"], "analyst")
        self.assertEqual(standard_data["individual_dashboard"]["ai"]["assessments"], 2)
        self.assertEqual(standard_data["individual_dashboard"]["analyzer"]["jobs"], 0)
        self.assertEqual(
            self.client.get(
                "/api/statistics/aggregate?username=bob"
            ).status_code,
            403,
        )

        self.login_as("root")
        admin_users = self.client.get("/api/statistics/users?days=30")
        self.assertEqual(admin_users.status_code, 200)
        self.assertEqual(admin_users.get_json()["users"], ["analyst", "bob"])
        admin_detail = self.client.get(
            "/api/statistics/aggregate?days=30&username=bob"
        )
        self.assertEqual(admin_detail.status_code, 200)
        self.assertEqual(
            admin_detail.get_json()["individual_dashboard"]["analyzer"]["jobs"], 1
        )

        connection = sqlite3.connect(self.statistics.db_path)
        try:
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(statistics_events)"
                )
            }
            stored_rows = connection.execute(
                "SELECT * FROM statistics_events"
            ).fetchall()
        finally:
            connection.close()

        forbidden_columns = {
            "observable", "report", "prompt", "response", "api_key", "parameters"
        }
        self.assertTrue(forbidden_columns.isdisjoint(columns))
        stored_data = repr(stored_rows)
        for marker in (
            "secret123.test",
            "REPORT_SECRET_MARKER",
            "API_KEY_SECRET_MARKER",
        ):
            self.assertNotIn(marker, stored_data)
        self.assertEqual(
            self.statistics.aggregate_events(event_type="ai")[0]["event_count"], 2
        )


if __name__ == "__main__":
    unittest.main()
