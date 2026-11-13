"""Allocation preserves large native queues and shares bounded execution fairly."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import review_budget as budget
import review_scheduler as scheduler


class Scheduler(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "budget.json"

    def jobs(self, lane, count):
        return [{"id": lane + str(i), "lane": lane,
                 "review_ids": ["candidate" + str(i)] if lane == "native" else []}
                for i in range(count)]

    def execute(self, job):
        try:
            lease = budget.reserve(self.path, "source_review", lane=job["lane"])
        except budget.BudgetExhausted as error:
            return scheduler.deferred(job, str(error))
        budget.finish(self.path, lease, {"usage": {"input_tokens": 100}})
        return {"assignment_id": job["id"], "status": "complete", "calls": 1}

    def run_jobs(self, native, ai, **limits):
        budget.initialize(self.path, native_percent=limits.pop("native_percent", 80), **limits)
        return list(scheduler.run({"native": self.jobs("native", native), "ai": self.jobs("ai", ai)},
                                 self.execute, workers=3, budget_path=self.path))

    def test_large_native_queue_retains_every_id_and_eighty_twenty_calls(self):
        results = self.run_jobs(500, 100)
        self.assertEqual(len(results), 600)
        self.assertEqual(len({job["id"] for job, _ in results}), 600)
        state = budget.snapshot(self.path)
        self.assertEqual(state["reserved_calls"], 40)
        self.assertEqual(state["lanes"]["native"]["reserved_calls"], 32)
        self.assertEqual(state["lanes"]["ai"]["reserved_calls"], 8)
        remaining = [row for _, row in results if row["status"] == "deferred"]
        self.assertEqual(len(remaining), 560)
        self.assertTrue(all(row["calls"] == 0 for row in remaining))
        self.assertEqual(sum(len(row["review_ids"]) for row in remaining), 468)

    def test_few_native_candidates_transfer_unused_calls_to_discovery(self):
        results = self.run_jobs(2, 100)
        state = budget.snapshot(self.path)
        self.assertEqual(state["lanes"]["native"]["reserved_calls"], 2)
        self.assertEqual(state["lanes"]["ai"]["reserved_calls"], 38)
        self.assertEqual(sum(row["status"] == "complete" for _, row in results), 40)

    def test_empty_native_queue_uses_discovery_without_all_source_fallback(self):
        results = self.run_jobs(0, 4)
        self.assertEqual(len(results), 4)
        self.assertTrue(all(row["status"] == "complete" for _, row in results))
        state = budget.snapshot(self.path)
        self.assertEqual(state["reserved_calls"], 4)
        self.assertEqual(state["lanes"]["ai"]["allocation"], 40)
        self.assertTrue(state["lanes"]["ai"]["complete"])

    def test_scan_only_and_ai_only_do_not_transfer_into_disabled_queue(self):
        for native_percent, enabled in ((100, "native"), (0, "ai")):
            with self.subTest(native_percent=native_percent):
                self.path = self.path.with_name(str(native_percent) + ".json")
                results = self.run_jobs(2, 2, native_percent=native_percent)
                state = budget.snapshot(self.path)
                self.assertEqual(state["reserved_calls"], 2)
                self.assertTrue(all(lease["lane"] == enabled for lease in state["leases"].values()))
                self.assertEqual(sum(row["status"] == "deferred" for _, row in results), 2)

    def test_custom_fraction_and_limits_are_read_from_ledger(self):
        self.run_jobs(20, 20, max_calls=9, native_percent=100 / 3,
                      input_limit=9000, reservation_per_call=1000, admission_seconds=30)
        state = budget.snapshot(self.path)
        self.assertEqual(state["reserved_calls"], 9)
        self.assertEqual(state["lanes"]["native"]["reserved_calls"], 3)
        self.assertEqual(state["lanes"]["ai"]["reserved_calls"], 6)
        self.assertEqual(state["observed_input_tokens"], 900)

    def test_unknown_usage_stops_new_dispatch_and_keeps_remaining_membership(self):
        budget.initialize(self.path, native_percent=80)
        def execute(job):
            lease = budget.reserve(self.path, "source_review", lane=job["lane"])
            budget.finish(self.path, lease, None)
            return {"status": "incomplete", "assignment_id": job["id"], "calls": 1}
        results = list(scheduler.run({"native": self.jobs("native", 5), "ai": self.jobs("ai", 2)},
                                     execute, workers=1, budget_path=self.path))
        self.assertEqual(len(results), 7)
        self.assertEqual(sum(row["status"] == "deferred" for _, row in results), 6)
        self.assertEqual(budget.snapshot(self.path)["reserved_calls"], 1)

    def test_partial_investigation_is_not_retried_after_unused_share_transfers(self):
        budget.initialize(self.path, max_calls=10, native_percent=80)
        native = self.jobs("native", 1)
        ai = self.jobs("ai", 1)
        calls = {"native": 0, "ai": 0}
        def execute(job):
            calls[job["lane"]] += 1
            turns = 10 if job["lane"] == "native" else 1
            result = None
            for _ in range(turns):
                result = self.execute(job)
                if result["status"] != "complete":
                    return {**result, "status": "incomplete"}
            return result
        results = list(scheduler.run({"native": native, "ai": ai}, execute,
                                    workers=1, budget_path=self.path))
        self.assertEqual(calls, {"native": 1, "ai": 1})
        self.assertEqual([row["status"] for _, row in results], ["incomplete", "complete"])
        self.assertEqual(budget.snapshot(self.path)["reserved_calls"], 9)

    def test_deadline_defers_both_queues_without_calling_reviewer(self):
        budget.initialize(self.path, native_percent=80, admission_seconds=1)
        with patch.object(budget.time, "time", return_value=budget.snapshot(self.path)["deadline_epoch"] + 1):
            results = list(scheduler.run({"native": self.jobs("native", 5), "ai": self.jobs("ai", 2)},
                                        self.execute, workers=3, budget_path=self.path))
        self.assertEqual(len(results), 7)
        self.assertTrue(all(row["status"] == "deferred" for _, row in results))
        self.assertEqual(budget.snapshot(self.path)["reserved_calls"], 0)

    def test_invalid_configuration_is_rejected_before_budget_file_exists(self):
        for options in ({"native_percent": -1}, {"native_percent": 101},
                        {"native_percent": float("nan")}, {"native_percent": True},
                        {"max_calls": 0}, {"input_limit": -1}, {"reservation_per_call": 0},
                        {"max_call_input_tokens": 0}, {"max_call_input_tokens": True},
                        {"admission_seconds": 0}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                budget.initialize(self.path, **options)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
