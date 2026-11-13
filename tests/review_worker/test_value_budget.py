"""Bounded source selection and shared provider admission regressions."""

from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import review_budget as budget
import review_source as source
import review_worker as worker


class Selection(unittest.TestCase):
    def setUp(self):
        self.plan = {"plan_id": "plan", "source_fingerprint": "source", "assignments": [
            {"id": "one", "review_ids": ["inside", "outside"], "windows": [
                {"path": "app.py", "start_line": 1, "end_line": 3, "source_sha256": "hash", "text": "read()\nwrite()\nother()"}]}]}
        self.selection = {"source_plan_id": "plan", "source_fingerprint": "source", "assignment_ids": ["one"],
            "assignments": [{"assignment_id": "one", "owner_path": "app.py", "start_line": 1, "end_line": 2,
                "question": "Can a caller choose the write target?", "protected_effect": "write", "area": "authorization",
                "reason": "The read result supplies the write target.", "next_deciding_fact": "The target authority check.",
                "signal": {"kind": "source_relationship", "evidence": [{"path": "app.py", "start_line": 1, "end_line": 2}]}}]}

    def test_scope_binds_plan_source_membership_owner_and_evidence(self):
        selected, focus = source.validate_selection(self.selection, self.plan)
        self.assertEqual(selected, ["one"])
        self.assertEqual(focus["one"]["signal"]["evidence"][0]["quote"], "read()\nwrite()")
        entries = [{"review_id": "inside", "path": "app.py", "line": 2},
                   {"review_id": "outside", "path": "app.py", "line": 3}]
        self.assertEqual(source.scoped_native_ids(["outside", "inside"], entries, focus), ["inside"])
        options = source.selection_options(self.plan)
        self.assertNotIn("text", options["assignments"][0]["windows"][0])
        self.assertNotIn("read()", json.dumps(options))

    def test_invalid_selection_never_reaches_a_provider(self):
        for mutate in (
            lambda v: v.update(source_plan_id="stale"),
            lambda v: v.update(source_fingerprint="stale"),
            lambda v: v.update(assignment_ids=["unknown"]),
            lambda v: v.update(assignment_ids=["one"] * 7),
            lambda v: v["assignments"][0].update(start_line=0),
            lambda v: v["assignments"][0].update(end_line=4),
            lambda v: v["assignments"][0].update(next_deciding_fact=""),
            lambda v: v["assignments"][0]["signal"].update(kind="pathname"),
            lambda v: v["assignments"][0]["signal"]["evidence"][0].update(end_line=4),
        ):
            value = copy.deepcopy(self.selection)
            mutate(value)
            with self.subTest(value=value), patch.object(worker, "execute") as execute:
                with self.assertRaises(ValueError):
                    source.validate_selection(value, self.plan)
                execute.assert_not_called()


class Budget(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "budget.json"
        budget.initialize(self.path)

    def state(self):
        return json.loads(self.path.read_text())

    def finish(self, lease, tokens=100):
        return budget.finish(self.path, lease, {"usage": {"input_tokens": tokens}})

    def test_concurrent_calls_cannot_exceed_forty(self):
        def call(_):
            try:
                lease = budget.reserve(self.path, "source_review")
            except budget.BudgetExhausted:
                return False
            self.finish(lease)
            return True
        with ThreadPoolExecutor(max_workers=10) as pool:
            admitted = list(pool.map(call, range(80)))
        self.assertEqual(sum(admitted), 40)
        self.assertEqual(self.state()["reserved_calls"], 40)
        self.assertEqual(self.state()["observed_input_tokens"], 4000)

    def test_inflight_headroom_deadline_and_drain(self):
        leases = [budget.reserve(self.path, "source_review") for _ in range(15)]
        with self.assertRaises(budget.BudgetExhausted):
            budget.reserve(self.path, "native_bundle")
        with patch.object(budget.time, "time", return_value=self.state()["deadline_epoch"] + 1):
            self.finish(leases[0])
            with self.assertRaises(budget.BudgetExhausted):
                budget.reserve(self.path, "native_bundle")
        self.assertEqual(self.state()["leases"][leases[0]]["status"], "settled")

    def test_observed_input_ceiling_blocks_native_handoff(self):
        for _ in range(15):
            self.finish(budget.reserve(self.path, "source_review"), 100000)
        self.assertEqual(self.state()["observed_input_tokens"], 1500000)
        with self.assertRaises(budget.BudgetExhausted):
            budget.reserve(self.path, "native_bundle")

    def test_unknown_and_oversized_usage_fence_new_calls_without_reset(self):
        lease = budget.reserve(self.path, "source_review")
        self.assertFalse(budget.finish(self.path, lease, None))
        with self.assertRaises(budget.BudgetExhausted):
            budget.reserve(self.path, "native_bundle")
        with self.assertRaises(ValueError):
            budget.initialize(self.path)
        other = self.path.with_name("oversized.json")
        budget.initialize(other)
        budget.finish(other, budget.reserve(other, "source_review"), {"usage": {"input_tokens": 250001}})
        with self.assertRaises(budget.BudgetExhausted):
            budget.reserve(other, "native_bundle")

    def test_per_call_fence_is_separate_from_inflight_reservation(self):
        for tokens in (100001, 250000):
            self.finish(budget.reserve(self.path, "source_review"), tokens)
            self.assertFalse(self.state()["fenced"])
        state = self.state()
        self.assertEqual(state["reservation_per_call"], 100000)
        self.assertEqual(state["max_call_input_tokens"], 250000)
        self.assertIsNone(budget.capacity(self.path))

    def test_legacy_ledger_keeps_its_original_call_fence(self):
        state = self.state()
        del state["max_call_input_tokens"]
        self.path.write_text(json.dumps(state), encoding="utf8")
        self.finish(budget.reserve(self.path, "source_review"), 100001)
        self.assertTrue(self.state()["fenced"])

    def test_native_handoff_uses_source_ledger_and_no_provider_retry(self):
        frame = {"kind": "native_bundle", "conversation_id": "conversation", "research": {"round": 0}}
        with patch.object(worker, "execute", side_effect=RuntimeError("provider failed")) as execute, \
                patch.object(worker, "observed_turn", return_value=None):
            with self.assertRaisesRegex(ValueError, "usage is unknown"):
                worker.execute_provider([], self.path.parent, {}, 10, frame, None, self.path)
            with self.assertRaises(budget.BudgetExhausted):
                worker.execute_provider([], self.path.parent, {}, 10, frame, None, self.path)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.state()["reserved_calls"], 1)

    def test_unknown_usage_preserves_timeout_cause_without_reopening_budget(self):
        frame = {"kind": "source_review", "conversation_id": "conversation", "research": {"round": 0}}
        failure = TimeoutError("review command timed out")
        with patch.object(worker, "execute", side_effect=failure) as execute, \
                patch.object(worker, "observed_turn", return_value=None):
            with self.assertRaisesRegex(ValueError, "original failure: TimeoutError: review command timed out") as caught:
                worker.execute_provider([], self.path.parent, {}, 10, frame, None, self.path)
            self.assertIs(caught.exception.__cause__, failure)
            with self.assertRaises(budget.BudgetExhausted):
                worker.execute_provider([], self.path.parent, {}, 10, frame, None, self.path)
        self.assertEqual(execute.call_count, 1)
        self.assertTrue(self.state()["fenced"])

    def test_lock_selects_windows_and_posix_primitives(self):
        handle = Mock()
        handle.fileno.return_value = 7
        windows = types.SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=Mock())
        posix = types.SimpleNamespace(LOCK_EX=1, LOCK_NB=4, LOCK_UN=8, flock=Mock())
        with patch.dict(sys.modules, {"msvcrt": windows, "fcntl": posix}):
            with patch.object(budget.os, "name", "nt"):
                budget._lock(handle, True)
                budget._lock(handle, False)
            with patch.object(budget.os, "name", "posix"):
                budget._lock(handle, True)
                budget._lock(handle, False)
        windows.locking.assert_any_call(7, windows.LK_NBLCK, 1)
        windows.locking.assert_any_call(7, windows.LK_UNLCK, 1)
        posix.flock.assert_any_call(7, posix.LOCK_EX | posix.LOCK_NB)
        posix.flock.assert_any_call(7, posix.LOCK_UN)


if __name__ == "__main__":
    unittest.main()
