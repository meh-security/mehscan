"""Concurrency/recovery boundaries; no inference or token estimates."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_worker import worker


class QueueBoundaries(unittest.TestCase):
    def test_same_inflight_query_runs_once_and_failure_is_not_a_negative_fact(self):
        broker = worker.EvidenceBroker()
        entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
        calls = []

        def load():
            calls.append(True)
            entered.set()
            self.assertTrue(release.wait(5))
            return {"result_id": "original", "origin_review_id": "first"}

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(broker.get, "key", load, 5)
            self.assertTrue(entered.wait(5))
            original_wait = broker.pending["key"].result
            def wait_for_original(*args, **kwargs):
                waiting.set()
                return original_wait(*args, **kwargs)
            broker.pending["key"].result = wait_for_original
            second = pool.submit(broker.get, "key", load, 5)
            self.assertTrue(waiting.wait(5))
            release.set()
            values = [first.result(), second.result()]
        self.assertEqual(len(calls), 1)
        self.assertEqual(sorted(reused for _, reused in values), [False, True])
        self.assertEqual(values[0][0], values[1][0])

        def fail():
            raise TimeoutError("unavailable")
        with self.assertRaises(TimeoutError):
            broker.get("failed", fail, 5)
        fact, reused = broker.get("failed", lambda: {"actual": "source"}, 5)
        self.assertFalse(reused)
        self.assertEqual(fact, {"actual": "source"})

    def test_crash_conserves_active_time_calls_and_queries_and_rejects_other_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            job = worker.JobCheckpoint(base / "job.json", {"package": "one"})
            job.save(calls=2, queries=4, bytes=120, model_inflight=True, active_since=100)
            with patch.object(worker.time, "time", return_value=125):
                recovered = worker.JobCheckpoint(base / "recovered.json", {"package": "one"}, job.path)
            self.assertEqual(recovered.state["calls"], 2)
            self.assertEqual(recovered.state["queries"], 4)
            self.assertEqual(recovered.state["bytes"], 120)
            self.assertGreaterEqual(recovered.prior_elapsed, 25)
            self.assertEqual(recovered.state["unknown_provider_calls"], 1)
            with self.assertRaisesRegex(ValueError, "binding"):
                worker.JobCheckpoint(base / "wrong.json", {"package": "two"}, job.path)
            recovered.complete({"results": []})
            state = json.loads(recovered.path.read_text())
            state["draft"]["results"].append("altered")
            recovered.path.write_text(json.dumps(state))
            with self.assertRaisesRegex(ValueError, "draft changed"):
                worker.JobCheckpoint(base / "altered.json", {"package": "one"}, recovered.path)

    def test_second_controller_cannot_consume_the_same_stream_and_lock_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controller.lock"
            with worker.controller_lock(path):
                with self.assertRaisesRegex(RuntimeError, "another review controller"):
                    with worker.controller_lock(path):
                        self.fail("double controller acquired")
            with worker.controller_lock(path):
                pass

    def test_recovery_keeps_unconsolidated_usage_without_double_counting_observed_turns(self):
        with tempfile.TemporaryDirectory() as directory:
            previous, current = Path(directory) / "previous", Path(directory) / "current"
            previous.mkdir()
            current.mkdir()
            row = {"conversation_id": "original", "round": 0, "usage": {"input_tokens": 7}}
            (previous / "provider-metrics-original.jsonl").write_text(json.dumps(row) + '\n')
            worker.consolidate_metrics(current, previous)
            self.assertEqual(json.loads((current / "provider-metrics.jsonl").read_text()), row)
            # The old aggregate may already contain that same durable turn.
            (previous / "provider-metrics.jsonl").write_text(json.dumps(row) + '\n')
            worker.consolidate_metrics(current, previous)
            self.assertEqual(len((current / "provider-metrics.jsonl").read_text().splitlines()), 1)
            altered = {**row, "usage": {"input_tokens": 9}}
            (previous / "provider-metrics-original.jsonl").write_text(json.dumps(altered) + '\n')
            with self.assertRaisesRegex(ValueError, "conflicting provider counters"):
                worker.consolidate_metrics(current, previous)
