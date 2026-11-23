"""Tests for the SQLite statistics storage layer.

Run with:
  python -m unittest discover -s test -p test_statistics_manager.py
"""

import logging
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import config
from statistics_manager import StatisticsManager


class StatisticsManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "stats.sqlite3")
        self.manager = StatisticsManager(self.db_path, retention_days=90)
        self.manager.initialize()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initialization_is_idempotent_and_creates_required_indexes(self):
        self.manager.initialize()
        connection = sqlite3.connect(self.db_path)
        try:
            indexes = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(statistics_events)")
            }
        finally:
            connection.close()

        self.assertTrue(
            {
                "idx_statistics_events_created_at",
                "idx_statistics_events_username",
                "idx_statistics_events_event_type",
                "idx_statistics_events_analyzer_name",
                "idx_statistics_events_responder_name",
            }.issubset(indexes)
        )
        self.assertIn("event_type", columns)
        self.assertIn("job_id", columns)
        self.assertNotIn("observable", columns)
        self.assertNotIn("report", columns)

    def test_job_events_are_unique_and_can_be_updated(self):
        event_id = self.manager.record_event(
            "analyzer",
            job_id="job-1",
            username="analyst",
            analyzer_name="Example",
            data_type="domain",
            status="Submitted",
        )
        duplicate_id = self.manager.record_event(
            "analyzer",
            job_id="job-1",
            username="analyst",
            analyzer_name="Example",
            status="Submitted",
        )

        self.assertEqual(event_id, duplicate_id)
        self.assertTrue(
            self.manager.update_event(
                "analyzer", "job-1", status="Success", duration_ms=125.5
            )
        )
        self.assertFalse(self.manager.update_event("analyzer", "missing", status="Failure"))
        aggregate = self.manager.aggregate_events(event_type="analyzer")
        self.assertEqual(aggregate[0]["event_count"], 1)
        self.assertEqual(aggregate[0]["success_count"], 1)
        self.assertEqual(aggregate[0]["average_duration_ms"], 125.5)

    def test_event_insertion_works_without_upsert_syntax(self):
        class LegacyConnection(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if "ON CONFLICT" in sql.upper():
                    raise sqlite3.OperationalError('near "ON": syntax error')
                return super().execute(sql, parameters)

        connect = sqlite3.connect

        def legacy_connect(*args, **kwargs):
            return connect(*args, factory=LegacyConnection, **kwargs)

        with mock.patch("statistics_manager.sqlite3.connect", side_effect=legacy_connect):
            job_id = self.manager.record_event("analyzer", job_id="job-1")
            self.assertEqual(self.manager.record_event("analyzer", job_id="job-1"), job_id)
            self.assertNotEqual(
                self.manager.record_event("responder", job_id="job-1"), job_id
            )
            first_ai = self.manager.record_event("ai")
            self.assertNotEqual(self.manager.record_event("ai"), first_ai)

    def test_concurrent_duplicate_job_insertions_return_same_id(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            ids = list(executor.map(
                lambda _: self.manager.record_event("analyzer", job_id="shared-job"),
                range(16),
            ))

        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(
            self.manager.aggregate_events(event_type="analyzer")[0]["event_count"], 1
        )

    def test_insertion_does_not_hide_other_constraint_errors(self):
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                "CREATE TRIGGER reject_event BEFORE INSERT ON statistics_events "
                "WHEN NEW.status = 'rejected' BEGIN "
                "SELECT RAISE(ABORT, 'rejected'); END"
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertLogs("statistics_manager", level=logging.ERROR):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "rejected"):
                self.manager.record_event("analyzer", job_id="job-1", status="rejected")

    def test_ai_events_persist_and_aggregate_without_job_ids(self):
        self.manager.record_event(
            "ai",
            username="analyst",
            status="Success",
            source="fresh",
            provider_latency_ms=50,
            input_tokens=12,
            output_tokens=8,
            total_tokens=20,
        )
        aggregate = StatisticsManager(self.db_path).aggregate_events(
            username="analyst"
        )

        self.assertEqual(aggregate[0]["event_type"], "ai")
        self.assertEqual(aggregate[0]["input_tokens"], 12)
        self.assertEqual(aggregate[0]["output_tokens"], 8)
        self.assertEqual(aggregate[0]["total_tokens"], 20)

    def test_cleanup_removes_only_events_older_than_retention(self):
        for username in ("old", "outside", "boundary", "inside"):
            self.manager.record_event("ai", username=username)
        now = datetime(2026, 11, 11, tzinfo=timezone.utc)
        cutoff = "2026-08-13T00:00:00.000000+00:00"
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                "UPDATE statistics_events SET created_at = ? WHERE username = ?",
                ("2026-08-12T23:00:00.000000+00:00", "old"),
            )
            connection.execute(
                "UPDATE statistics_events SET created_at = ? WHERE username = ?",
                ("2026-08-12T23:59:59.999999+00:00", "outside"),
            )
            connection.execute(
                "UPDATE statistics_events SET created_at = ? WHERE username = ?",
                (cutoff, "boundary"),
            )
            connection.execute(
                "UPDATE statistics_events SET created_at = ? WHERE username = ?",
                ("2026-08-13T00:00:00.000001+00:00", "inside"),
            )
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(self.manager.cleanup(now=now), 2)
        self.assertEqual(self.manager.cleanup(now=now), 0)
        remaining = self.manager.list_usernames()
        self.assertEqual(remaining, ["boundary", "inside"])

    def test_concurrent_cleanup_is_idempotent(self):
        event_count = 30
        for index in range(event_count):
            self.manager.record_event("ai", username="old-{}".format(index))

        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                "UPDATE statistics_events SET created_at = ?",
                ("2026-01-01T00:00:00.000000+00:00",),
            )
            connection.commit()
        finally:
            connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            removed = list(executor.map(lambda _: self.manager.cleanup(), range(2)))

        self.assertEqual(sum(removed), event_count)
        self.assertEqual(self.manager.aggregate_events(), [])

    def test_configured_alternate_database_path_survives_reinitialization(self):
        alternate_path = str(Path(self.temp_dir.name) / "alternate.sqlite3")
        with mock.patch.object(config, "STATS_DB_PATH", alternate_path):
            manager = StatisticsManager()
            manager.initialize()
            manager.record_event("ai", username="persisted")

        reopened = StatisticsManager(alternate_path)
        self.assertEqual(
            reopened.aggregate_events(username="persisted")[0]["event_count"], 1
        )

    def test_rejects_fields_that_could_store_observables(self):
        with self.assertRaisesRegex(ValueError, "Unsupported statistics field"):
            self.manager.record_event("ai", observable="example.org")

    def test_database_errors_are_logged_and_propagated(self):
        missing_path = str(Path(self.temp_dir.name) / "missing" / "stats.sqlite3")
        manager = StatisticsManager(missing_path)
        with self.assertLogs("statistics_manager", level=logging.ERROR):
            with self.assertRaises(sqlite3.OperationalError):
                manager.initialize()


if __name__ == "__main__":
    unittest.main()
