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
    def test_native_replay_binds_the_run_and_secondary_assessment_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, run, stages = base / "source", base / "run", base / "assessments"
            for path in (root, run, stages):
                path.mkdir()
            (run / "response.json").write_text('{"decision":"issue"}')
            stage = stages / "expert.json"
            stage.write_text('{"decision":"issue","source":"original"}')
            work, execution = base / "work.json", base / "execution.json"
            work.write_text('{}')
            execution.write_text('{}')
            calls = []
            def native(argv):
                calls.append(argv)
                return {"sequence":1, "replayed":bool(len(calls) > 1), "currently_owned":True}
            writes = worker.NativeWrites(base / "writes", root, native, [])
            writes.apply("admission", [{"operation":"record", "operation_key":"worker-record:one", "options":{
                "--run":str(run), "--work-package":str(work), "--reviewer":"fixture", "--review-execution":str(execution)}}])
            stage.write_text('{"decision":"issue","source":"altered"}')
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                writes.apply("admission")
            self.assertEqual(len(calls), 1)
            stage.write_text('{"decision":"issue","source":"original"}')
            (run / "new-response.json").write_text('{}')
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                writes.apply("admission")
            self.assertEqual(len(calls), 1)

    def test_native_writes_replay_lost_receipts_and_reject_changed_inputs_or_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "source"
            root.mkdir()
            question = base / "question.json"
            question.write_text('{"question":"Check the delegated policy"}')
            committed, calls = {}, []
            def native(arguments):
                key = arguments[arguments.index("--operation-key") + 1]
                calls.append(key)
                replayed = key in committed
                committed.setdefault(key, len(committed) + 1)
                if len(calls) == 1:
                    raise TimeoutError("response lost after native commit")
                return {"sequence":committed[key], "replayed":replayed, "currently_owned":True}
            writes = worker.NativeWrites(base / "first", root, native, ["--owner", "private-owner"])
            entries = [{"operation":"pending", "operation_key":"worker-question:one",
                        "options":{"--input":str(question)}}]
            with self.assertRaises(TimeoutError):
                writes.apply("admission", entries)
            resumed = worker.NativeWrites(base / "second", root, native, ["--owner", "private-owner"], base / "first")
            self.assertEqual(resumed.apply("admission"), [{"sequence":1, "replayed":True}])
            self.assertEqual(calls, ["worker-question:one"] * 2)
            self.assertNotIn("private-owner", (base / "second/admission.json").read_text())
            question.write_text('{"question":"An altered question"}')
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                resumed.apply("admission")
            self.assertEqual(len(calls), 2)
            question.write_text('{"question":"Check the delegated policy"}')
            resumed.native = lambda argv: {"sequence":1, "replayed":True, "currently_owned":False}
            with self.assertRaisesRegex(ValueError, "no longer owned"):
                resumed.apply("admission")

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
