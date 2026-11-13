"""Interrupted source attempts conserve source bindings, receipts and allowance."""
import json
from pathlib import Path
import tempfile
import unittest

import test_worker
import review_budget as budget
import review_source_recovery as recovery

worker = test_worker.worker


class SourceRecovery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.parent = self.base / "attempt"
        self.old = self.parent / "source-review"
        self.new = self.base / "recovered/source-review"
        for stage in (self.old, self.new):
            stage.mkdir(parents=True)
            worker.write(stage / "plan.json", {"source":"pinned"})
            worker.write(stage / "work-plan.json", {"items":["case"]})
        self.budget = self.old / "budget.json"
        budget.initialize(self.budget, max_calls=3)
        self.binding = {"source":"pinned", "provider":"bound"}
        recovery.seal(self.old, self.binding, self.budget, self.parent, worker)
        self.job = self.old / "jobs/job"
        self.job.mkdir(parents=True)

    def turn(self):
        lease = budget.reserve(self.budget, "source_review")
        worker.write(self.job / "0-input.json", {"conversation_id":"original", "research":{"round":0}})
        recovery.save(self.job / "recovery.json", "packet", "inflight",
            {"lease":lease, "turn":0, "provider":None}, self.budget, worker)
        return lease

    def test_known_turn_settles_once_and_unattributed_dispatch_fences(self):
        first = self.turn()
        row = {"conversation_id":"original", "round":0, "provider":None,
               "usage":{"input_tokens":123, "cached_input_tokens":0, "output_tokens":10}}
        (self.job / "provider-metrics-original.jsonl").write_text(json.dumps(row) + "\n")
        unknown = budget.reserve(self.budget, "source_review")
        recovery.restore(self.parent, self.new, self.binding, self.root, worker)
        recovery.settle_interrupted(self.new, self.budget, worker)
        recovery.settle_interrupted(self.new, self.budget, worker)
        state = budget.snapshot(self.budget)
        self.assertEqual(state["leases"][first]["status"], "settled")
        self.assertEqual(state["leases"][unknown]["status"], "unknown")
        self.assertEqual(state["observed_input_tokens"], 123)
        self.assertEqual(state["reserved_calls"], 2)
        self.assertTrue(state["fenced"])
        self.assertEqual(recovery.receipts(self.new, worker), [row])

    def test_paid_work_cannot_be_erased_by_resetting_original_counters(self):
        self.turn()
        state = budget.snapshot(self.budget)
        state["reserved_calls"] = 0
        worker.write(self.budget, state)
        with self.assertRaisesRegex(ValueError, "reset prior usage"):
            recovery.restore(self.parent, self.new, self.binding, self.root, worker)

    def test_changed_provider_plan_or_allowance_rejected_before_copy(self):
        for change in ("provider", "plan", "allowance"):
            with self.subTest(change=change):
                binding = dict(self.binding)
                original = self.budget.read_bytes()
                if change == "provider":
                    binding["provider"] = "different"
                elif change == "plan":
                    worker.write(self.new / "plan.json", {"source":"changed"})
                else:
                    value = budget.snapshot(self.budget)
                    value["max_calls"] += 1
                    worker.write(self.budget, value)
                with self.assertRaises(ValueError):
                    recovery.restore(self.parent, self.new, binding, self.root, worker)
                self.assertFalse((self.new / "jobs").exists())
                worker.write(self.new / "plan.json", {"source":"pinned"})
                self.budget.write_bytes(original)

    def test_recovery_lineage_keeps_ancestor_budget_instead_of_a_fresh_copy(self):
        self.turn()
        first = recovery.restore(self.parent, self.new, self.binding, self.root, worker)
        recovery.seal(self.new, self.binding, Path(first["budget_path"]), Path(first["lineage_output"]), worker)
        recovery.claim_successor(self.parent, self.new, worker)
        next_stage = self.base / "again/source-review"
        next_stage.mkdir(parents=True)
        for name in ("plan.json", "work-plan.json"):
            (next_stage / name).write_bytes((self.old / name).read_bytes())
        second = recovery.restore(self.new.parent, next_stage, self.binding, self.root, worker)
        self.assertEqual(second["budget_path"], str(self.budget))
        self.assertEqual(second["lineage_output"], str(self.parent))
        self.assertFalse((next_stage / "budget.json").exists())
        with self.assertRaisesRegex(ValueError, "already continued"):
            recovery.restore(self.parent, next_stage, self.binding, self.root, worker)


if __name__ == "__main__":
    unittest.main()
