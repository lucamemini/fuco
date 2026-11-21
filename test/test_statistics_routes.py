import tempfile
import unittest
from pathlib import Path

from flask import Flask

from routes import routes_bp
from routes_statistics import statistics_bp
from statistics_manager import StatisticsManager


class FakeAuthManager:
    def __init__(self, username=None, authenticated=False):
        self.username = username
        self.authenticated = authenticated

    def is_authenticated(self):
        return self.authenticated

    def get_username(self):
        return self.username


class StatisticsRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = str(Path(self.temp_dir.name) / "stats.sqlite3")
        self.manager = StatisticsManager(db_path)
        self.manager.initialize()
        self.manager.record_event(
            "ai", username="alice", status="Success", source="fresh"
        )
        self.manager.record_event(
            "responder", job_id="bob-job", username="bob", status="Failure"
        )

        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["STATS_ADMIN_USERS"] = ["root"]
        self.app.statistics_manager = self.manager
        self.app.auth_manager = FakeAuthManager()
        self.app.register_blueprint(statistics_bp)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def authenticate_as(self, username):
        self.app.auth_manager = FakeAuthManager(username, authenticated=True)

    def test_anonymous_users_cannot_access_either_endpoint(self):
        self.assertEqual(
            self.client.get("/api/statistics/aggregate").status_code, 401
        )
        self.assertEqual(self.client.get("/api/statistics/users").status_code, 401)

    def test_standard_user_gets_aggregate_and_only_own_individual_data(self):
        self.authenticate_as("alice")

        response = self.client.get("/api/statistics/aggregate?days=30")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["individual_username"], "alice")
        self.assertFalse(body["is_admin"])
        self.assertEqual(len(body["aggregate"]), 2)
        self.assertEqual(body["dashboard"]["ai"]["assessments"], 1)
        self.assertEqual(body["dashboard"]["responder"]["jobs"], 1)
        self.assertEqual(body["individual_dashboard"]["ai"]["assessments"], 1)
        self.assertEqual(body["individual_dashboard"]["responder"]["jobs"], 0)
        self.assertEqual(
            [(row["event_type"], row["event_count"]) for row in body["individual"]],
            [("ai", 1)],
        )

        self.assertEqual(
            self.client.get(
                "/api/statistics/aggregate?username=bob"
            ).status_code,
            403,
        )
        self.assertEqual(self.client.get("/api/statistics/users").status_code, 403)

    def test_administrator_can_list_users_and_read_another_users_data(self):
        self.authenticate_as("root")

        users_response = self.client.get("/api/statistics/users?days=30")
        self.assertEqual(users_response.status_code, 200)
        self.assertEqual(users_response.get_json()["users"], ["alice", "bob"])

        detail_response = self.client.get(
            "/api/statistics/aggregate?days=30&username=bob"
        )
        self.assertEqual(detail_response.status_code, 200)
        body = detail_response.get_json()
        self.assertTrue(body["is_admin"])
        self.assertEqual(body["individual_username"], "bob")
        self.assertEqual(
            [(row["event_type"], row["event_count"]) for row in body["individual"]],
            [("responder", 1)],
        )

    def test_period_validation_and_unavailable_database(self):
        self.authenticate_as("alice")
        self.assertEqual(
            self.client.get("/api/statistics/aggregate?days=14").status_code, 400
        )
        self.authenticate_as("root")
        self.assertEqual(
            self.client.get("/api/statistics/users?days=14").status_code, 400
        )

        self.app.statistics_manager = None
        self.assertEqual(
            self.client.get("/api/statistics/aggregate").status_code, 503
        )

    def test_dashboard_page_renders_required_controls_and_disclaimers(self):
        template_folder = str(
            Path(__file__).resolve().parent.parent / "web" / "templates"
        )
        page_app = Flask(__name__, template_folder=template_folder)
        page_app.jinja_env.globals["csrf_token"] = lambda: "test-token"
        page_app.register_blueprint(routes_bp)

        response = page_app.test_client().get("/statistics")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('id="statisticsDays"', page)
        self.assertIn('id="globalDashboard"', page)
        self.assertIn('id="individualDashboard"', page)
        self.assertIn("funzionamento tecnico", page)
        self.assertIn("/js/statistics.js", page)


if __name__ == "__main__":
    unittest.main()
