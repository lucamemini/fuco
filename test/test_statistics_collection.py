import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask, session

import ai_manager
import utils
from responder_manager import ResponderManager
from statistics_manager import StatisticsManager, duration_milliseconds


class FakeCache:
    def __init__(self):
        self.assessments = {}
        self.reports = {}

    def get_ai_assessment(self, key):
        return self.assessments.get(key)

    def set_ai_assessment(self, key, value):
        self.assessments[key] = value

    def get_report(self, job_id):
        return self.reports.get(job_id)

    def set_report(self, job_id, report):
        self.reports[job_id] = report


class StatisticsCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = str(Path(self.temp_dir.name) / "stats.sqlite3")
        self.statistics = StatisticsManager(db_path)
        self.statistics.initialize()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _events(self, event_type):
        connection = sqlite3.connect(self.statistics.db_path)
        connection.row_factory = sqlite3.Row
        try:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM statistics_events WHERE event_type = ?",
                    (event_type,),
                )
            ]
        finally:
            connection.close()

    def _ai(self, cache, provider, force_refresh=False):
        patches = (
            mock.patch.object(ai_manager, "resolve_provider", return_value="test"),
            mock.patch.object(ai_manager, "make_cache_key", return_value="cache-key"),
            mock.patch.object(
                ai_manager, "make_latest_index_key", return_value="latest-key"
            ),
            mock.patch.dict(ai_manager._PROVIDER_CALLS, {"test": provider}),
        )
        with patches[0], patches[1], patches[2], patches[3]:
            return ai_manager.get_or_generate_assessment(
                cache,
                {"observable": "not-persisted", "datatype": "domain", "reports": []},
                force_refresh=force_refresh,
                provider="test",
                statistics_manager=self.statistics,
                username="analyst",
                indicators_count=1,
                reports_count=2,
                ai_input_count=3,
            )

    def test_duration_conversion_accepts_cortex_epoch_milliseconds_and_bad_values(self):
        self.assertEqual(
            duration_milliseconds(1760000000000, 1760000001500), 1500
        )
        self.assertIsNone(duration_milliseconds("invalid", 1760000001500))
        self.assertIsNone(
            duration_milliseconds(10 ** 1000, 1760000001500)
        )

    def test_fresh_and_forced_refresh_record_counts_latency_and_tokens(self):
        provider = mock.Mock(
            return_value=(
                {"summary": "assessment"},
                {
                    "model": "test-model",
                    "latency_ms": 42,
                    "token_usage": {
                        "input_tokens": 10,
                        "output_tokens": 5,
                        "total_tokens": 15,
                    },
                },
            )
        )
        self._ai(FakeCache(), provider)
        self._ai(FakeCache(), provider, force_refresh=True)

        events = self._events("ai")
        self.assertEqual([event["source"] for event in events], ["fresh", "refresh"])
        self.assertTrue(all(event["status"] == "Success" for event in events))
        self.assertTrue(all(event["provider_latency_ms"] == 42 for event in events))
        self.assertTrue(all(event["input_tokens"] == 10 for event in events))
        self.assertTrue(all(event["indicators_count"] == 1 for event in events))
        self.assertTrue(all(event["reports_count"] == 2 for event in events))
        self.assertTrue(all(event["ai_input_count"] == 3 for event in events))

        dashboard = self.statistics.dashboard_data(username="analyst")
        self.assertEqual(dashboard["ai"]["assessments"], 2)
        self.assertEqual(dashboard["ai"]["provider_call_count"], 2)
        self.assertEqual(dashboard["ai"]["cache_hit_count"], 0)
        self.assertEqual(dashboard["ai"]["latency_median_ms"], 42)
        self.assertEqual(dashboard["ai"]["latency_p95_ms"], 42)
        self.assertEqual(dashboard["ai"]["tokens"]["total_tokens"], 30)
        self.assertEqual(dashboard["ai"]["indicators_count"], 2)
        self.assertEqual(dashboard["ai"]["reports_count"], 4)
        self.assertEqual(dashboard["ai"]["ai_input_count"], 6)

    def test_cache_hit_and_provider_failure_record_distinct_events(self):
        cache = FakeCache()
        cache.assessments["cache-key"] = {
            "ok": True,
            "created_at": "2026-01-01T00:00:00Z",
            "token_usage": {"input_tokens": 200},
        }
        provider = mock.Mock()
        self._ai(cache, provider)
        provider.assert_not_called()

        failing_provider = mock.Mock(side_effect=RuntimeError("provider failed"))
        with self.assertRaisesRegex(RuntimeError, "provider failed"):
            self._ai(FakeCache(), failing_provider)

        events = self._events("ai")
        self.assertEqual(
            [(event["source"], event["status"]) for event in events],
            [("cache", "Success"), ("fresh", "Failure")],
        )
        self.assertIsNone(events[0]["input_tokens"])
        self.assertIsNone(events[0]["provider_latency_ms"])

    def test_missing_provider_token_usage_stays_unavailable_and_stats_failure_is_safe(self):
        provider = mock.Mock(
            return_value=(
                {"summary": "assessment"},
                {"model": "test-model", "latency_ms": 12},
            )
        )
        with mock.patch.object(
            self.statistics, "record_event", side_effect=RuntimeError("db down")
        ):
            result = self._ai(FakeCache(), provider)
        self.assertEqual(result["source"], "fresh")

        provider.return_value = (
            {"summary": "assessment"},
            {"model": "test-model", "latency_ms": 12},
        )
        self._ai(FakeCache(), provider)
        event = self._events("ai")[0]
        self.assertIsNone(event["input_tokens"])
        self.assertIsNone(event["output_tokens"])
        self.assertIsNone(event["total_tokens"])

    def test_analyzer_submit_and_cached_final_report_update_one_event(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.cache_manager = FakeCache()
        app.statistics_manager = self.statistics
        job = mock.Mock(id="analyzer-job", json=lambda: {"id": "analyzer-job"})
        report = mock.Mock(
            status="Success",
            startDate=1760000000000,
            endDate=1760000001500,
        )
        app.cache_manager.reports["analyzer-job"] = report

        with app.test_request_context("/"):
            session["cortex_username"] = "analyst"
            with mock.patch("utils.cortex_api_call", return_value=job):
                utils.run_analysis("ExampleAnalyzer", "domain", "sensitive.example")
            utils.get_cached_report("analyzer-job")
        self.statistics.record_event(
            "analyzer",
            job_id="abandoned-job",
            username="analyst",
            analyzer_name="ExampleAnalyzer",
            data_type="domain",
            status="Submitted",
        )

        events = self._events("analyzer")
        completed = next(event for event in events if event["job_id"] == "analyzer-job")
        self.assertEqual(len(events), 2)
        self.assertEqual(completed["status"], "Success")
        self.assertEqual(completed["username"], "analyst")
        self.assertEqual(completed["duration_ms"], 1500)
        self.assertNotIn("sensitive.example", str(completed))

        dashboard = self.statistics.dashboard_data(username="analyst")["analyzer"]
        self.assertEqual(dashboard["jobs"], 2)
        self.assertEqual(dashboard["unobserved_count"], 1)
        self.assertEqual(dashboard["observed_count"], 1)
        self.assertEqual(dashboard["success_rate"], 100)
        self.assertEqual(dashboard["duration_median_ms"], 1500)
        self.assertEqual(dashboard["most_used"][0]["data_type"], "domain")

    def test_analyzer_poll_timeout_is_recorded(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.cache_manager = FakeCache()
        app.statistics_manager = self.statistics
        self.statistics.record_event(
            "analyzer", job_id="timeout-job", status="Submitted"
        )

        with app.test_request_context("/"), mock.patch(
            "utils.get_cached_report", return_value=mock.Mock(status="InProgress")
        ), mock.patch("utils.time.sleep"):
            self.assertIsNone(utils.poll_job("timeout-job", max_attempts=2))

        self.assertEqual(self._events("analyzer")[0]["status"], "Timeout")

    def test_responder_bulk_submission_and_final_status_update_one_event(self):
        manager = ResponderManager("http://cortex.invalid", "test-key")
        api = mock.Mock()
        api.responders.run_by_id.return_value = mock.Mock(
            id="responder-job", status="Waiting", responderId="ExampleResponder"
        )
        api.jobs.get_by_id.return_value = mock.Mock(
            id="responder-job",
            status="Success",
            responderId="responder-id",
            responderName="ExampleResponder",
            createdAt=None,
            startDate=1760000000000,
            endDate=1760000002500,
        )
        api.jobs.get_report.return_value = mock.Mock(report={})
        manager.get_authenticated_api = mock.Mock(return_value=api)
        manager._get_responder_name = mock.Mock(return_value="ExampleResponder")
        manager._is_allowed_by_config = mock.Mock(return_value=True)
        manager._get_responder_supported_types = mock.Mock(return_value=["ip"])

        app = Flask(__name__)
        app.secret_key = "test"
        app.statistics_manager = self.statistics
        with app.test_request_context("/"):
            action = manager.run_responder(
                observable="not-persisted",
                data_type="ip",
                responder_id="responder-id",
                api_key="test-key",
                statistics_username="analyst",
                mode="bulk",
            )
            manager.get_responder_job_status(action.job_id, api_key="test-key")

        events = self._events("responder")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "Success")
        self.assertEqual(events[0]["mode"], "bulk")
        self.assertEqual(events[0]["username"], "analyst")
        self.assertEqual(events[0]["duration_ms"], 2500)
        self.assertNotIn("not-persisted", str(events[0]))
        dashboard = self.statistics.dashboard_data(username="analyst")["responder"]
        self.assertEqual(dashboard["indicators_processed"], 1)
        self.assertEqual(dashboard["most_used"][0]["name"], "ExampleResponder")
        self.assertEqual(dashboard["success_rate"], 100)

    def test_responder_invalid_type_and_poll_timeout_are_distinct(self):
        manager = ResponderManager("http://cortex.invalid", "test-key")
        manager.get_authenticated_api = mock.Mock(return_value=mock.Mock())
        manager._get_responder_name = mock.Mock(return_value="ExampleResponder")
        manager._is_allowed_by_config = mock.Mock(return_value=False)
        app = Flask(__name__)
        app.secret_key = "test"
        app.statistics_manager = self.statistics

        with app.test_request_context("/"):
            with self.assertRaisesRegex(ValueError, "not allowed for data type"):
                manager.run_responder(
                    observable="not-persisted",
                    data_type="invalid",
                    responder_id="responder-id",
                    api_key="test-key",
                    statistics_username="analyst",
                )
            self.statistics.record_event(
                "responder", job_id="responder-timeout", status="Submitted"
            )
            with mock.patch.object(
                manager,
                "get_responder_job_status",
                return_value={"status": "InProgress"},
            ), mock.patch("responder_manager.time.sleep"):
                result = manager.poll_responder_job(
                    "responder-timeout", api_key="test-key", max_attempts=1
                )

        self.assertEqual(result["status"], "Timeout")
        events = self._events("responder")
        self.assertEqual(
            {event["status"] for event in events},
            {"Invalid data type", "Timeout"},
        )


if __name__ == "__main__":
    unittest.main()
