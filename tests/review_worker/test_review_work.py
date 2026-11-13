"""Bound obligations, risk-first selection, explicit unresolved work and cost fencing."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_budget as budget
import review_source
import review_work as work
import test_review_domains as domain_fixtures


class WorkPlan(unittest.TestCase):
    def setUp(self):
        fixture = domain_fixtures.DomainPlan()
        fixture.setUp()
        self.plan, self.ids = fixture.plan, fixture.ids
        first = fixture.case("lower", "first", "first.py", 3)
        first.update(priority=dict(impact="medium", exposure="authenticated", evidence="strong", basis="A constrained update."),
            actor="Account member", conditions="Supported application operation.",
            checks=[dict(id="binding", question="Does the actor own the selected record?")],
            review_roles=dict(verify=["failure"], cover=[], context=["fact"]),
            estimate=dict(calls=[1, 3], input_tokens=[1000, 5000], output_tokens=[100, 500]))
        second = copy.deepcopy(first)
        second.update(id="higher", review_roles=dict(verify=[], cover=["marker"], context=[]))
        second["priority"]["impact"] = "critical"
        self.manifest = dict(schema_version=work.VERSION, source_plan_id="native-plan", source_fingerprint="source",
                             items=[first, second], coverage_limits=["Dynamic plugin binding is not inventoried."])

    def validate(self, **kwargs):
        return work.validate(self.manifest, self.plan, self.ids,
                             validate_selection=review_source.validate_selection, **kwargs)

    def result(self, item, status="satisfied"):
        check = dict(check_id="binding", status=status, summary="The bound source establishes this relationship.",
            evidence=[dict(path="first.py", start_line=2, end_line=2)],
            next_deciding_fact=None if status in ("satisfied", "violated") else "Inspect the effective provider binding.")
        return dict(case_id=item, status="complete", calls=1, draft=dict(work_checks=[check], results=[], proposals=[]))

    def test_priority_does_not_follow_origin_or_input_order(self):
        value = self.validate()
        self.assertEqual([row["id"] for row in value["cases"]], ["higher", "lower"])
        self.assertEqual(len({row["assignment_id"] for row in value["cases"]}), 1)
        self.assertEqual(set(value["lead_accounting"]), set(self.ids))
        self.assertEqual(value["lead_accounting"]["unknown"]["role"], "unclassified")

    def test_target_only_selects_requested_work_without_clearing_other_leads(self):
        value = self.validate(goal="coverage", targets=["lower"])
        self.assertEqual([row["id"] for row in value["cases"]], ["lower"])
        report = work.ledger(value, [self.result("lower")])
        self.assertTrue(report["target_complete"])
        self.assertEqual(report["summary"]["remaining_by_potential_impact"], {"critical": 1})
        self.assertEqual(report["items"][0]["status"], "outside_target")
        self.assertIn("unknown", report["summary"]["unclassified_native_ids"])
        self.assertEqual(report["summary"]["closed"], 1)
        self.assertEqual(report["summary"]["remaining"], 1)
        self.assertEqual(report["summary"]["checks_closed"], 1)
        self.assertIn("1 completed / 2 declared; 1 remaining", work.markdown(report))

    def test_completed_packet_with_unresolved_property_does_not_complete_target(self):
        value = self.validate(goal="coverage", targets=["lower"])
        report = work.ledger(value, [self.result("lower", "unresolved")])
        self.assertFalse(report["target_complete"])
        self.assertEqual(report["items"][1]["status"], "investigated_unresolved")
        self.assertEqual(report["items"][1]["next_deciding_facts"], ["Inspect the effective provider binding."])

    def test_native_pending_decision_also_prevents_false_closure(self):
        result = self.result("lower")
        result["draft"]["results"] = [dict(review_id="failure", decision="needs_review")]
        report = work.ledger(self.validate(goal="coverage", targets=["lower"]), [result])
        self.assertFalse(report["target_complete"])

    def test_blocked_target_is_retained_without_funding_a_job(self):
        self.manifest["items"][0].update(readiness="blocked", blocked_reason="Deployment provider is unavailable.")
        value = self.validate(goal="coverage", targets=["lower"])
        self.assertEqual(value["cases"], [])
        report = work.ledger(value)
        self.assertFalse(report["target_complete"])
        self.assertEqual(report["items"][1]["status"], "blocked")

    def test_invalid_work_never_becomes_a_case(self):
        original = copy.deepcopy(self.manifest)
        for change in (lambda d:d.update(source_fingerprint="other"),
                       lambda d:d["items"][1].update(id="lower"),
                       lambda d:d["items"][1]["review_roles"].update(verify=["failure"]),
                       lambda d:d["items"][0]["priority"].update(impact="imaginary"),
                       lambda d:d["items"][0].update(checks=[]),
                       lambda d:d["items"][0].update(estimate={"calls":[3,1]})):
            self.manifest = copy.deepcopy(original)
            change(self.manifest)
            with self.assertRaises(ValueError):
                self.validate()
        self.manifest = original
        with self.assertRaises(ValueError):
            self.validate(goal="coverage", targets=["foreign"])

    def test_closed_answers_require_exact_check_membership_and_evidence(self):
        required = self.manifest["items"][0]["checks"]
        row = self.result("lower")["draft"]["work_checks"][0]
        work.check_results(required, [row])
        for rows in ([], [row, row], [{**row, "evidence": []}], [{**row, "check_id": "foreign"}],
                     [{**row, "status": "unresolved", "next_deciding_fact": None}]):
            with self.assertRaises(ValueError):
                work.check_results(required, rows)

    def test_estimates_and_unknowns_remain_explicit(self):
        self.manifest["items"][1].pop("estimate")
        report = work.ledger(self.validate())
        self.assertEqual(report["remaining_estimate"]["calls"]["unknown_items"], ["higher"])
        self.assertIn("importance is unknown", work.markdown(report))
        self.assertEqual(report["summary"]["closed"], 0)

    def test_deciding_signal_evidence_is_metadata_until_item_dispatch(self):
        self.manifest["items"][0]["signal"]["evidence"].append(dict(path="second.py", start_line=1, end_line=2))
        result = self.validate()
        lower = next(row for row in result["cases"] if row["id"] == "lower")
        self.assertEqual(lower["shared_facts"], [dict(path="second.py", start_line=1, end_line=2, source_sha256="second-hash")])
        self.assertNotIn("quote", json.dumps(result))
        self.assertNotIn("check()\\nwrite()", json.dumps(result))

    def test_missing_effort_does_not_rank_as_the_cheapest_equal_impact(self):
        self.manifest["items"][1]["priority"]["impact"] = "medium"
        self.manifest["items"][1].pop("estimate")
        self.assertEqual([row["id"] for row in self.validate()["cases"]], ["lower", "higher"])

    def test_zero_native_candidates_does_not_hide_unmapped_source(self):
        for item in self.manifest["items"]:
            item["review_roles"] = {}
        result = work.validate(self.manifest, self.plan, [], validate_selection=review_source.validate_selection)
        report = work.ledger(result)
        self.assertEqual(report["summary"]["unclassified_native_ids"], [])
        self.assertEqual(report["source_scope"]["windows_without_named_owner"][0]["path"], "second.py")

    def test_exhausted_effort_estimate_does_not_claim_free_remaining_work(self):
        result = self.result("lower", "unresolved")
        result["calls"] = 4
        report = work.ledger(self.validate(goal="coverage", targets=["lower"]), [result])
        self.assertIn("lower", report["target_remaining_estimate"]["calls"]["unknown_items"])

    def test_incomplete_information_counters_do_not_look_like_complete_usage(self):
        report = work.ledger(self.validate(), [self.result("lower")], metrics=[
            dict(work_item_id="lower", usage={"input_tokens":100})])
        lower = next(row for row in report["items"] if row["id"] == "lower")
        self.assertEqual(lower["status"], "closed")
        self.assertFalse(lower["usage_complete"])


class CostBudget(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "budget.json"
        self.rates = dict(input_per_million=1, cached_input_per_million=.1, output_per_million=5)

    def test_shared_inflight_cost_headroom_and_actual_settlement(self):
        budget.initialize(self.path, cost=budget.cost_policy("0.7", self.rates))
        one = budget.reserve(self.path, "source_review")
        two = budget.reserve(self.path, "source_review")
        with self.assertRaises(budget.BudgetExhausted):
            budget.reserve(self.path, "source_review")
        budget.finish(self.path, one, {"usage":dict(input_tokens=100000, cached_input_tokens=80000, output_tokens=1000)})
        self.assertEqual(budget.snapshot(self.path)["cost"]["observed_micros"], 33000)
        self.assertIsNone(budget.capacity(self.path))
        budget.finish(self.path, two, {"usage":dict(input_tokens=1000, cached_input_tokens=0, output_tokens=100)})

    def test_unknown_cost_counter_fences_while_preserving_known_input(self):
        budget.initialize(self.path, cost=budget.cost_policy("5", self.rates))
        lease = budget.reserve(self.path, "source_review")
        self.assertTrue(budget.finish(self.path, lease, {"usage":{"input_tokens":100}}))
        state = budget.snapshot(self.path)
        self.assertEqual(state["observed_input_tokens"], 100)
        self.assertFalse(state["cost"]["complete"])
        self.assertTrue(state["fenced"])

    def test_cost_overrun_fences_future_calls_but_receipts_drain(self):
        budget.initialize(self.path, cost=budget.cost_policy("0.7", self.rates))
        leases = [budget.reserve(self.path, "source_review") for _ in range(2)]
        for lease in leases:
            budget.finish(self.path, lease, {"usage":dict(input_tokens=200000, cached_input_tokens=0, output_tokens=40000)})
        state = budget.snapshot(self.path)
        self.assertEqual(state["cost"]["observed_micros"], 800000)
        self.assertTrue(all(row["status"] == "settled" for row in state["leases"].values()))
        self.assertTrue(state["fenced"])

    def test_invalid_price_policy_cannot_start_a_ledger(self):
        for amount in ("nan", "-1", "0", True):
            with self.assertRaises(ValueError):
                budget.cost_policy(amount, self.rates)
        with self.assertRaises(ValueError):
            budget.cost_policy("5", {**self.rates, "input_per_million": "Infinity"})

    def test_reporting_rates_without_monetary_cap_do_not_limit_spending(self):
        budget.initialize(self.path, cost=budget.cost_policy(None, self.rates))
        lease = budget.reserve(self.path, "source_review")
        budget.finish(self.path, lease, {"usage":dict(input_tokens=200000, cached_input_tokens=0, output_tokens=100000)})
        state = budget.snapshot(self.path)
        self.assertIsNone(state["cost"]["limit_micros"])
        self.assertEqual(state["cost"]["observed_micros"], 700000)
        self.assertFalse(state["fenced"])
        self.assertIsNone(budget.capacity(self.path))

    def test_missing_cost_only_counters_remain_informational_without_a_cap(self):
        budget.initialize(self.path, cost=budget.cost_policy(None, self.rates))
        lease = budget.reserve(self.path, "source_review")
        budget.finish(self.path, lease, {"usage":{"input_tokens":100}})
        state = budget.snapshot(self.path)
        self.assertFalse(state["cost"]["complete"])
        self.assertFalse(state["fenced"])
        self.assertIsNone(budget.capacity(self.path))

    def test_reporting_only_cost_is_rendered_below_item_progress(self):
        fixture = WorkPlan()
        fixture.setUp()
        registry = fixture.validate()
        report = work.ledger(registry, budget={"cost":budget.cost_policy(None, self.rates)})
        rendered = work.markdown(report)
        self.assertIn("tracking only, no monetary cap", rendered)
        self.assertLess(rendered.index("Items:"), rendered.index("Managed estimated spend:"))


if __name__ == "__main__":
    unittest.main()
