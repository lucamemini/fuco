import unittest
from unittest import mock

import utils


class BulkAnalysisTests(unittest.TestCase):
    def test_bulk_runs_ids_and_skips_incompatible_pairs(self):
        observables = [
            {"data": "192.0.2.1", "dataType": "ip"},
            {"data": "192.0.2.2", "dataType": "ip"},
            {"data": "example.com", "dataType": "domain"},
        ]
        analyzer_map = {"domain-id": ["domain"], "both-id": ["ip", "domain"]}
        job = mock.Mock(id="job-1", json=lambda: {"id": "job-1", "status": "Waiting"})

        with mock.patch.object(utils.cortex_api.analyzers, "run_by_id", return_value=job) as by_id, \
             mock.patch.object(utils.cortex_api.analyzers, "run_by_name") as by_name, \
             mock.patch.object(utils, "record_event_safely"), \
             mock.patch.object(utils.time, "sleep"):
            jobs, errors = utils.run_analysis_bulk(
                observables, ["domain-id", "both-id"], tlp=1, pap=2,
                delay=0, analyzer_map=analyzer_map,
            )

        self.assertEqual(len(jobs), 4)
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(error["analyzerId"] == "domain-id" for error in errors))
        self.assertTrue(all("does not support dataType 'ip'" in error["reason"] for error in errors))
        self.assertEqual(by_id.call_args_list, [
            mock.call("both-id", {"data": "192.0.2.1", "dataType": "ip", "tlp": 1, "pap": 2}, force=1),
            mock.call("both-id", {"data": "192.0.2.2", "dataType": "ip", "tlp": 1, "pap": 2}, force=1),
            mock.call("domain-id", {"data": "example.com", "dataType": "domain", "tlp": 1, "pap": 2}, force=1),
            mock.call("both-id", {"data": "example.com", "dataType": "domain", "tlp": 1, "pap": 2}, force=1),
        ])
        by_name.assert_not_called()

    def test_bulk_reports_failed_id_and_continues(self):
        job = mock.Mock(id="job-1", json=lambda: {"id": "job-1"})

        def run_by_id(analyzer_id, payload, **kwargs):
            if analyzer_id == "missing-id":
                raise ValueError("Analyzer unavailable")
            return job

        with mock.patch.object(utils.cortex_api.analyzers, "run_by_id", side_effect=run_by_id), \
             mock.patch.object(utils, "record_event_safely"), \
             mock.patch.object(utils.time, "sleep"):
            jobs, errors = utils.run_analysis_bulk(
                [{"data": "example.com", "dataType": "domain"}],
                ["missing-id", "working-id"], delay=0,
            )

        self.assertEqual([job["analyzerId"] for job in jobs], ["working-id"])
        self.assertEqual(errors, [{
            "observable": "example.com",
            "analyzerId": "missing-id",
            "reason": "Analyzer unavailable",
        }])

    def test_single_analysis_still_runs_by_name(self):
        job = mock.Mock(id="job-1", json=lambda: {"id": "job-1"})
        with mock.patch.object(utils.cortex_api.analyzers, "run_by_name", return_value=job) as by_name, \
             mock.patch.object(utils.cortex_api.analyzers, "run_by_id") as by_id, \
             mock.patch.object(utils, "record_event_safely"):
            result = utils.run_analysis("ExampleAnalyzer", "domain", "example.com", tlp=1, pap=2)

        self.assertEqual(result["id"], "job-1")
        by_name.assert_called_once_with(
            "ExampleAnalyzer",
            {"data": "example.com", "dataType": "domain", "tlp": 1, "pap": 2},
            force=1,
        )
        by_id.assert_not_called()


if __name__ == "__main__":
    unittest.main()
