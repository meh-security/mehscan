"""Active Action ownership and real native worker, without network/model calls."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import test_advisory as fixtures

adapter = fixtures.adapter


class ReviewHandoff(fixtures.NativeFixture):
    def setUp(self):
        super().setUp()
        self.command = self.workspace / "trusted/reviewer-argv.json"
        self.reviewer = self.workspace / "trusted/reviewer.py"
        self.reviewer.write_text('''import json,sys
from pathlib import Path
task=json.load(sys.stdin)
work=json.loads(Path(task["work_package"]).read_text())["payload"]
if task["kind"]=="change_pass":
    print(json.dumps({"change_pass":[{"path":"app.js","status":"reviewed",
        "summary":"Inspected the changed operation and its previous source.","questions":[],
        "native_review_ids":work["review_ids"],"evidence":[
            {"side":"base","path":"app.js","start_line":1,"end_line":1},
            {"side":"current","path":"app.js","start_line":1,"end_line":1}]}]}))
else:
    print(json.dumps({"results":[{"review_id":i,"decision":"issue","confidence":"medium",
        "summary":"Synthetic operation issue for handoff acceptance.",
        "reason":"The current code passes request.query.code into eval.",
        "evidence":[{"path":"app.js","start_line":1,"end_line":1}],"checks":[],"blockers":[]}
        for i in task["review_ids"]]}))
''', encoding="utf-8")
        self.command.write_text(json.dumps([sys.executable, str(self.reviewer)]))

    def ready(self, policy="value", execute=None):
        os.environ["MEHSCAN_REVIEW_MODE"] = policy
        directory, plan = self.prepare()
        record = adapter.finish(directory / "plan.json", self.delivery.get, execute or self.execute)
        self.assertEqual(record["status"], "review_ready", record)
        return directory, plan, record

    def view(self, directory, plan, operation="status"):
        _, common, key = adapter.review_lane(plan, directory)
        return adapter.state_json(plan, self.execute, operation, [*common, "--repository-key", key])

    def consume(self, record, execute=None):
        return adapter.review(record["review_handoff"], self.command, "deterministic/medium",
                              self.delivery.get, execute or self.execute)

    def test_native_default_and_invalid_or_persistent_review_configuration(self):
        directory, plan = self.prepare()
        record = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(record["status"], "native_only")
        self.assertNotIn("review", plan)
        for mode in ("full", "VALUE"):
            os.environ["MEHSCAN_REVIEW_MODE"] = mode
            with self.assertRaises(ValueError):
                self.prepare()
        os.environ["MEHSCAN_REVIEW_MODE"] = "value"
        self.enable_state()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_profiles_keep_active_ownership_private_and_bind_distinct_work(self):
        snapshots = []
        for policy, queries in (("value", 8), ("comprehensive", 12)):
            directory, plan, record = self.ready(policy)
            state = self.view(directory, plan)
            self.assertEqual(state["attempt_status"], "running")
            work = json.loads((directory / "work.json").read_text())
            self.assertEqual(work["payload"]["policy"], policy)
            self.assertEqual(work["payload"]["runtime"]["limits"]["queries"], queries)
            self.assertTrue((directory / "bundles/manifest.json").is_file())
            control = Path(plan["review_control"])
            self.assertFalse(control.is_relative_to(directory))
            owner = json.loads((control / "claim.json").read_text())["result"]["owner"]
            for path in directory.rglob("*"):
                if path.is_file():
                    self.assertNotIn(owner.encode(), path.read_bytes(), str(path))
                    self.assertNotIn(self.env["GH_TOKEN"].encode(), path.read_bytes(), str(path))
            snapshots.append(record["snapshot_id"])
        self.assertNotEqual(*snapshots)

    def test_real_worker_finishes_native_admission_without_workflow_secrets_or_replay(self):
        directory, plan, record = self.ready("comprehensive")
        calls = []
        def execute(argv, **kwargs):
            if str(argv[1]).endswith("review_worker.py"):
                calls.append(kwargs["env"])
            return self.execute(argv, **kwargs)
        with patch.dict(os.environ, {"GITHUB_TOKEN":"secret", "OPENAI_API_KEY":"secret", "WORKFLOW_SECRET":"secret", "PYTHONPATH":"source"}):
            result = self.consume(record, execute)
        self.assertEqual(result["status"], "reviewed", result)
        self.assertEqual(result["review_execution"], "admitted")
        self.assertTrue(result["completion"]["issue_review_ids"])
        history = self.view(directory, plan, "history")
        self.assertEqual(history["attempt_status"], "finished")
        self.assertTrue(history["decisions"])
        self.assertTrue((directory / "review/findings.json").exists())
        self.assertEqual(len(calls), 1)
        self.assertFalse(any(key in calls[0] for key in ("GH_TOKEN","GITHUB_TOKEN","OPENAI_API_KEY","WORKFLOW_SECRET","PYTHONPATH")))
        with self.assertRaises(ValueError):
            self.consume(record, execute)
        self.assertEqual(len(calls), 1)

    def test_pending_native_answer_does_not_become_security_clearance(self):
        self.reviewer.write_text(self.reviewer.read_text().replace('"decision":"issue"', '"decision":"needs_review"')
            .replace('"checks":[]', '"checks":["Requires additional deployment proof."]'))
        directory, plan, record = self.ready()
        result = self.consume(record)
        self.assertEqual(result["status"], "reviewed", result)
        self.assertEqual(result["completion"]["security_resolution"], "not_established")
        self.assertTrue(result["completion"]["pending_review_ids"])
        self.assertEqual(self.view(directory, plan)["attempt_status"], "finished")

    def test_zero_native_queue_still_runs_the_changed_effect_pass(self):
        (self.checkout / "app.js").write_text("const current = true;\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "safe source-only change")
        self.head = self.git("rev-parse", "HEAD")
        self.delivery.pr["head"]["sha"] = self.head
        directory, plan, record = self.ready()
        self.assertEqual(json.loads((directory / "work.json").read_text())["payload"]["review_ids"], [])
        self.assertFalse((directory / "bundles").exists())
        result = self.consume(record)
        self.assertEqual(result["status"], "reviewed", result)
        state = self.view(directory, plan)
        self.assertEqual(state["attempt_status"], "finished")
        self.assertEqual(state["completion"]["security_resolution"], "not_established")
        self.assertEqual(json.loads((directory / "review/worker.json").read_text())["status"], "admitted")

    def test_endpoint_drift_before_consumer_prevents_any_worker_launch(self):
        directory, plan, record = self.ready()
        self.delivery.base = fixtures.B
        def execute(argv, **kwargs):
            self.assertFalse(str(argv[1]).endswith("review_worker.py"))
            return self.execute(argv, **kwargs)
        result = self.consume(record, execute)
        self.assertEqual(result["status"], "stale", result)
        self.assertEqual(self.view(directory, plan)["attempt_status"], "incomplete")
        self.assertFalse((directory / "review").exists())

    def test_endpoint_drift_after_worker_retains_historical_decisions_only(self):
        directory, plan, record = self.ready()
        def execute(argv, **kwargs):
            value = self.execute(argv, **kwargs)
            if str(argv[1]).endswith("review_worker.py"):
                self.delivery.base = fixtures.B
            return value
        result = self.consume(record, execute)
        self.assertEqual(result["status"], "stale", result)
        self.assertEqual(result["review_execution"], "admitted")
        self.assertEqual(result["contract"]["endpoints"]["base_commit"], self.base)
        history = self.view(directory, plan, "history")
        self.assertTrue(history["decisions"])
        self.assertEqual(history["attempt_status"], "incomplete")

    def test_drift_or_cancellation_after_claim_closes_without_exporting_handoff(self):
        for kind in ("stale", "cancelled"):
            os.environ["MEHSCAN_REVIEW_MODE"] = "value"
            self.delivery.base = self.base
            directory, plan = self.prepare()
            cancelled = False
            def execute(argv, **kwargs):
                nonlocal cancelled
                value = self.execute(argv, **kwargs)
                if argv[1:3] == ["state", "claim"]:
                    if kind == "stale": self.delivery.base = fixtures.B
                    else: cancelled = True
                return value
            result = adapter.finish(directory / "plan.json", self.delivery.get, execute, lambda: cancelled)
            self.assertEqual(result["status"], kind, result)
            self.assertNotIn("review_handoff", result)
            self.assertEqual(self.view(directory, plan)["attempt_status"], "incomplete" if kind == "stale" else "cancelled")

    def test_failed_consumer_closes_incomplete_and_tool_drift_prevents_launch(self):
        for kind in ("failure", "controller_drift"):
            directory, plan, record = self.ready()
            def execute(argv, **kwargs):
                if str(argv[1]).endswith("review_worker.py"):
                    self.assertEqual(kind, "failure")
                    raise RuntimeError("synthetic worker failure")
                return self.execute(argv, **kwargs)
            original = adapter.file_digest
            def changed(path):
                return "changed" if kind == "controller_drift" and Path(path).name == "review_worker.py" else original(path)
            with patch.object(adapter, "file_digest", side_effect=changed):
                result = self.consume(record, execute)
            self.assertEqual(result["status"], "incomplete", result)
            self.assertEqual(self.view(directory, plan)["attempt_status"], "incomplete")
            self.assertNotIn("review_handoff", result)

    def test_concurrent_consumers_launch_once_and_do_not_end_each_others_work(self):
        directory, plan, record = self.ready()
        calls = []
        def execute(argv, **kwargs):
            if str(argv[1]).endswith("review_worker.py"):
                calls.append(argv)
            return self.execute(argv, **kwargs)
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks = [pool.submit(self.consume, record, execute) for _ in range(2)]
            results = []
            for task in tasks:
                try:
                    results.append(task.result(timeout=180)["status"])
                except (ValueError, TimeoutError):
                    results.append("rejected_duplicate")
        self.assertEqual(sorted(results), ["rejected_duplicate", "reviewed"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.view(directory, plan)["attempt_status"], "finished")

    def test_changed_work_package_never_launches_a_worker(self):
        directory, plan, record = self.ready()
        work = json.loads((directory / "work.json").read_text())
        work["payload"]["runtime"]["limits"]["queries"] = 7
        (directory / "work.json").write_text(json.dumps(work))
        def execute(argv, **kwargs):
            self.assertFalse(str(argv[1]).endswith("review_worker.py"))
            return self.execute(argv, **kwargs)
        result = self.consume(record, execute)
        self.assertEqual(result["status"], "incomplete", result)
        self.assertEqual(self.view(directory, plan)["attempt_status"], "incomplete")

    def test_late_consumer_cannot_close_a_new_generation(self):
        directory, plan, record = self.ready()
        superseded = False
        def execute(argv, **kwargs):
            nonlocal superseded
            if argv[1:3] == ["state", "end"] and not superseded:
                superseded = True
                _, common, _ = adapter.review_lane(plan, directory)
                adapter.state_json(plan, self.execute, "claim", [*common, "--inventory", str(directory / "inventory"),
                    "--source-root", str(self.checkout), "--attempt-id", "trusted-retry", "--expected-generation", "1",
                    "--retry", "true", "--operation-key", "trusted-retry"])
            if str(argv[1]).endswith("review_worker.py"):
                raise RuntimeError("synthetic worker failure before supersession")
            return self.execute(argv, **kwargs)
        result = self.consume(record, execute)
        self.assertEqual(result["status"], "incomplete", result)
        state = self.view(directory, plan)
        self.assertEqual(state["generation"], 2)
        self.assertEqual(state["attempt_id"], "trusted-retry")
        self.assertEqual(state["attempt_status"], "running")

    def test_release_delta_handoff_keeps_direct_endpoints_through_worker(self):
        os.environ.update(GITHUB_EVENT_NAME="workflow_dispatch", MEHSCAN_BASE="old", MEHSCAN_TARGET="new")
        self.delivery.tags = {"old": self.base, "new": self.head}
        directory, plan, record = self.ready("comprehensive")
        comparison = json.loads((directory / "work.json").read_text())["payload"]["impact_scope"]["comparison"]
        self.assertFalse(comparison.get("merge_base_commit"))
        result = self.consume(record)
        self.assertEqual(result["status"], "reviewed", result)
        self.assertEqual(result["contract"]["endpoints"]["kind"], "release_delta")
        self.assertEqual(self.view(directory, plan)["attempt_status"], "finished")

    def test_provider_descriptor_is_bound_and_cannot_run_a_generic_unprotected_consumer(self):
        descriptor = self.workspace / "trusted/provider.json"
        provider = {"schema_version":"1","provider":"codex-cli",
            "executable_version":"0.162.0-alpha.17.2",
            "model":"gpt-6-luna","reasoning_effort":"medium"}
        descriptor.write_text(json.dumps(provider))
        os.environ["MEHSCAN_PROVIDER_CONTRACT"] = str(descriptor)
        directory, plan, record = self.ready()
        self.assertEqual(plan["review"]["runtime"]["provider"], provider)
        self.assertEqual(json.loads((directory / "work.json").read_text())["payload"]["runtime"]["provider"], provider)
        result = self.consume(record)
        self.assertEqual(result["status"], "incomplete", result)
        self.assertEqual(self.view(directory, plan)["attempt_status"], "incomplete")
        self.assertFalse(self.view(directory, plan, "history")["decisions"])
