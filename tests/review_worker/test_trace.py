"""Execution diagnostics preserve uncertainty and do not become verdict authority."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from review_trace import ReviewTrace, summarize, markdown


class Trace(unittest.TestCase):
    def test_trace_exposes_disappearing_relationship_and_native_failure_without_relabeling(self):
        with tempfile.TemporaryDirectory() as name:
            run = Path(name)
            (run / "jobs").mkdir()
            (run / "jobs/job.json").write_text(json.dumps({"binding":{"review_ids":["id"]}, "status":"drafted",
                "calls":2, "queries":1, "progress":[], "draft":{"results":[{"review_id":"id","decision":"not_issue","summary":"Claim dismissed.","checks":[]}]}}))
            (run / "worker.json").write_text(json.dumps({"status":"incomplete", "reason":"NativeFailure"}))
            trace = ReviewTrace(run / "review-trace.jsonl")
            trace.emit("job_started", job_id="job", review_ids=["id"])
            trace.emit("progress_changed", job_id="job", round=1, dropped_open_edges=["Read acceptance branch"])
            trace.emit("native_failed", job_id="job", operation="investigate/review-bundle-finalize")
            result = summarize(run, "id")
            self.assertEqual(result["mechanical_assessment"], "not_admitted_or_still_running")
            self.assertEqual(result["semantic_quality"], "not_established_by_execution_trace")
            self.assertEqual(result["attention_counts"]["open_relationship_disappeared"], 1)
            self.assertEqual(result["jobs"][0]["decisions"][0]["decision"], "not_issue")
            self.assertIn("Read acceptance branch", json.dumps(result))
            self.assertIn("native_failed", markdown(result))
            with self.assertRaisesRegex(ValueError, "not present"):
                summarize(run, "other-id")

    def test_legacy_empty_lookup_and_torn_trace_are_explicit_not_a_pass(self):
        with tempfile.TemporaryDirectory() as name:
            run = Path(name)
            (run / "jobs").mkdir()
            (run / "jobs/job.json").write_text(json.dumps({"binding":{"review_ids":["id"]},"status":"incomplete"}))
            lookup = {"round":0,"query":{"tool":"symbol","review_id":"id","arguments":{"name":"helper"}},"result":{"results":[]}}
            (run / "research.jsonl").write_text(json.dumps(lookup)+"\n")
            result = summarize(run)
            self.assertEqual(result["trace_history"], "legacy_reconstruction")
            self.assertEqual(result["unfinished_jobs"], ["job"])
            self.assertEqual(result["attention_counts"]["empty_or_failed_navigation"], 1)
            (run / "review-trace.jsonl").write_text('{"event":')
            self.assertTrue(summarize(run)["incomplete_trace_rows"])


if __name__ == "__main__":
    unittest.main()
