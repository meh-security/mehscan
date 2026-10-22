"""Routing is evidence-driven; shared reservations survive stage/retry changes."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import unittest

from test_worker import worker

flow = worker.orchestration


def policy(calls=4, run_calls=6):
    limits = {"model_calls":calls, "queries":6, "bytes":100, "timeout_seconds":60}
    return {"case_limits":limits, "run_limits":{**limits, "model_calls":run_calls},
            "audit_percent":0, "audit_seed":"fixed"}


class Orchestration(unittest.TestCase):
    def test_profiles_share_case_and_run_reservations_and_recovery_keeps_spend(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.json"
            budget = flow.SharedReviewBudget(path, policy(calls=2, run_calls=3), worker.write)
            budget.begin_case("one")
            budget.reserve("one", "model_calls", 1)  # routine
            budget.end_case("one")
            budget.begin_case("one")
            budget.reserve("one", "model_calls", 1)  # expert
            with self.assertRaises(flow.BudgetExhausted):
                budget.reserve("one", "model_calls", 1)
            budget.end_case("one")
            budget.close()
            recovered = flow.SharedReviewBudget(Path(directory) / "retry.json", policy(2, 3), worker.write, path)
            recovered.begin_case("two")
            recovered.reserve("two", "model_calls", 1)
            with self.assertRaises(flow.BudgetExhausted):
                recovered.reserve("two", "model_calls", 1)
            self.assertEqual(recovered.state["totals"]["model_calls"], 3)
            recovered.end_case("two")
            recovered.close()

    def test_concurrent_reservations_never_oversubscribe_and_received_bytes_are_not_free(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = flow.SharedReviewBudget(Path(directory) / "budget.json", policy(20, 5), worker.write)
            for identity in ("a", "b"):
                budget.begin_case(identity)
            def reserve(index):
                try:
                    budget.reserve("ab"[index % 2], "model_calls", 1)
                    return True
                except flow.BudgetExhausted:
                    return False
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(sum(pool.map(reserve, range(20))), 5)
            with self.assertRaises(flow.BudgetExhausted):
                budget.reserve("a", "bytes", 101)
            self.assertEqual(budget.state["totals"]["bytes"], 101)
            self.assertLess(budget.remaining("a", "bytes"), 0)
            for identity in ("a", "b"):
                budget.end_case(identity)
            budget.close()

    def test_external_questions_stay_pending_but_reasoning_and_risky_closures_route(self):
        result = {"review_id":"id", "decision":"needs_review"}
        for reason in ("external_required", "human_required", "budget_exhausted"):
            self.assertFalse(flow.needs_secondary([result], [{"review_id":"id", "reason":reason}], policy()))
        self.assertTrue(flow.needs_secondary([result], [], policy()))
        self.assertTrue(flow.needs_secondary([{**result, "decision":"issue"}], [], policy()))
        self.assertTrue(flow.needs_secondary([{**result, "decision":"not_issue"}],
            [{"review_id":"id", "reason":"risky_dismissal"}], policy()))
        sampled = {**policy(), "audit_percent":100}
        self.assertTrue(flow.needs_secondary([{**result, "decision":"not_issue"}], [], sampled))
        with self.assertRaises(ValueError):
            flow.validate_routing([{"review_id":"other", "reason":"risky_dismissal"}], ["id"])

    def test_conflicts_preserve_pending_while_matching_results_retain_expert_evidence(self):
        first = {"schema_version":"1.3", "results":[{"review_id":"id", "decision":"issue",
            "confidence":"medium", "summary":"first", "checks":[],
            "investigation":{"journal_summary":{}, "blockers":[], "decisive_artifacts":["original"]}}]}
        other = copy.deepcopy(first)
        other["results"][0]["summary"] = "expert"
        result = flow.reconcile(first, other, "routine")["results"][0]
        self.assertEqual(result["summary"], "expert")
        other["results"][0]["decision"] = "not_issue"
        result = flow.reconcile(first, other, "routine")["results"][0]
        self.assertEqual(result["decision"], "needs_review")
        self.assertTrue(result["checks"])
        self.assertIsNone(result["investigation"]["journal_summary"])
        self.assertEqual(first["results"][0]["decision"], "issue")
