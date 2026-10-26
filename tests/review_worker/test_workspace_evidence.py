"""Source sharing/provenance controls, not evidence of model review savings."""
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from review_workspace import Workspace
from review_workspace_evidence import VERSION, dependency, prepare


class DecidingEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-deciding-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "source"
        self.root.mkdir()
        (self.root / "helper.ts").write_text("export function bind(req) { req.body.UserId = req.user.id; }\n", encoding="utf-8")
        self.manifest({"dependencies":{"finale-rest":"^1.2.2"}})
        self.binding = {"snapshot_id":"snapshot", "plan_id":"plan", "runtime_id":"runtime"}
        self.workspace = Workspace.create(self.directory / "state.sqlite", self.root, self.binding,
            [{"review_id":name, "property":"owner check", "path":"helper.ts", "line":1, "bundle_id":"b"}
             for name in ("a", "b")], {"model_calls":2, "queries":0, "source_bytes":4096})

    def manifest(self, value):
        (self.root / "package.json").write_text(json.dumps(value), encoding="utf-8")

    def request(self, work="initial", question="Does body.UserId constrain the path-selected update?"):
        return {"version":VERSION, "targets":[{"work_id":work, "question":question,
            "windows":[{"path":"helper.ts", "start_line":1, "end_line":1,
                        "file_sha256":hashlib.sha256((self.root / "helper.ts").read_bytes()).hexdigest()}],
            "packages":["finale-rest"]}]}

    def split(self):
        self.workspace.apply("split", self.workspace.snapshot()["revision"],
            {"kind":"split", "work_id":"initial", "new_work_id":"other", "review_ids":["b"], "strategy":"separate caller"})

    def test_shared_source_is_delivered_before_session_once_stored_per_caller(self):
        self.split()
        request = self.request()
        request["targets"] += self.request("other", "Does this different caller constrain its update?")["targets"]
        prepare(self.workspace, request, "prepare")
        state = self.workspace.snapshot()
        self.assertEqual(len(state["evidence"]), 1)
        self.assertEqual(len(state["dependency_observations"]), 1)
        self.assertEqual(state["used"]["source_bytes"], len(next(iter(state["evidence"].values()))["text"].encode()))
        for work in ("initial", "other"):
            view = self.workspace.view(work)
            self.assertEqual(len(view["deciding_evidence"]), 1)
            self.assertEqual(len(view["evidence"]), 1)
            self.assertEqual(view["applicability"], {})
            self.assertEqual(view["propositions"], {})
        self.assertEqual(state["sessions"], {})
        self.assertEqual(state["calls"], {})
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))

    def test_declared_range_missing_files_and_installed_version_are_distinct(self):
        observed = dependency(self.root, "finale-rest")
        self.assertEqual(observed["declarations"], {"dependencies":"^1.2.2"})
        self.assertIsNone(observed["root_installed_manifest_version"])
        self.assertEqual([f["status"] for f in observed["files"]], ["present"] + ["missing"] * 5)
        (self.root / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
        package = self.root / "node_modules/finale-rest"
        package.mkdir(parents=True)
        (package / "package.json").write_text('{"version":"1.2.9"}', encoding="utf-8")
        observed = dependency(self.root, "finale-rest")
        self.assertEqual(observed["root_installed_manifest_version"], "1.2.9")
        self.assertIn("No workspace, nested", observed["limits"])
        self.assertNotIn("resolved_version", observed)

    def test_replay_and_changed_request(self):
        request = self.request()
        first = prepare(self.workspace, request, "prep")
        second = prepare(self.workspace, request, "prep")
        self.assertEqual(first["revision"], second["revision"])
        self.assertTrue(second["replayed"])
        request["targets"][0]["question"] = "different"
        with self.assertRaisesRegex(ValueError, "retry changed"):
            prepare(self.workspace, request, "prep")

    def test_missing_metadata_becoming_present_invalidates_view_and_replay(self):
        request = self.request()
        prepare(self.workspace, request, "prep")
        (self.root / "yarn.lock").write_text("new resolution", encoding="utf-8")
        for operation in (lambda: self.workspace.view("initial"), lambda: prepare(self.workspace, request, "prep")):
            with self.assertRaisesRegex(ValueError, "observation is stale"):
                operation()

    def test_manifest_edits_and_source_edits_invalidate(self):
        prepare(self.workspace, self.request(), "prep")
        self.manifest({"dependencies":{"finale-rest":"2.0.0"}})
        with self.assertRaisesRegex(ValueError, "observation is stale"):
            self.workspace.view("initial")
        self.manifest({"dependencies":{"finale-rest":"^1.2.2"}})
        (self.root / "helper.ts").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.workspace.view("initial")

    def test_late_failure_rolls_back_all_source_and_receipts(self):
        before = self.workspace.snapshot()
        request = self.request()
        request["targets"] += self.request(question="second question")["targets"]
        request["targets"][-1]["windows"][0]["file_sha256"] = "wrong"
        with self.assertRaisesRegex(ValueError, "stale"):
            prepare(self.workspace, request, "prep")
        self.assertEqual(self.workspace.snapshot(), before)
        self.assertIsNone(self.workspace.operation("prep"))

    def test_split_retains_receipts_and_focus_cannot_hide_support(self):
        prepare(self.workspace, self.request(), "prep")
        self.split()
        self.workspace.apply("focus", self.workspace.snapshot()["revision"],
            {"kind":"focus", "work_id":"other", "evidence_ids":[], "proposition_ids":[]})
        self.assertEqual(len(self.workspace.view("other")["evidence"]), 1)
        self.assertEqual(len(self.workspace.view("other")["deciding_evidence"]), 1)

    def test_model_updates_cannot_invoke_preparation(self):
        before = self.workspace.snapshot()
        with self.assertRaisesRegex(ValueError, "privileged"):
            self.workspace.apply("model", before["revision"], {"kind":"review_updates", "updates":[
                {"kind":"prepare_evidence", "targets":self.request()["targets"]}]})
        self.assertEqual(self.workspace.snapshot(), before)

    def test_package_path_validation_scoped_package_and_malformed_manifest(self):
        self.assertEqual(dependency(self.root, "@scope/package")["package"], "@scope/package")
        for name in ("../escape", "a/b", "/abs", "x\\y", "X", "a" * 215):
            with self.subTest(name=name), self.assertRaises(ValueError):
                dependency(self.root, name)
        self.manifest({"dependencies":[]})
        with self.assertRaises(ValueError):
            dependency(self.root, "finale-rest")

    def test_dependency_only_request_does_not_invent_effect_source(self):
        request = self.request()
        request["targets"][0]["windows"] = []
        prepare(self.workspace, request, "prep")
        view = self.workspace.view("initial")
        self.assertEqual(view["evidence"], {})
        self.assertEqual(view["questions"], {})
        self.assertEqual(self.workspace.snapshot()["used"], {"model_calls":0,"queries":0,"source_bytes":0})

    def test_added_evidence_requires_a_new_session(self):
        session = self.workspace.apply("session", 0, {"kind":"session", "work_id":"initial",
            "parent_session":None, "max_bytes":32768})["result"]["session_id"]
        prepare(self.workspace, self.request(), "prep")
        with self.assertRaisesRegex(ValueError, "context changed"):
            self.workspace.check_session(session)

    def test_source_budget_overflow_rolls_back_preparation(self):
        request = self.request()
        # A distinct 400-line window exceeds this workspace's capture allowance.
        (self.root / "large.ts").write_text("x" * 5000 + "\n", encoding="utf-8")
        request["targets"][0]["windows"].append({"path":"large.ts", "start_line":1, "end_line":1,
            "file_sha256":hashlib.sha256((self.root / "large.ts").read_bytes()).hexdigest()})
        before = self.workspace.snapshot()
        with self.assertRaises(ValueError):
            prepare(self.workspace, request, "prep")
        self.assertEqual(self.workspace.snapshot(), before)


class NativeEvidencePreparationTests(unittest.TestCase):
    def test_cli_native_guard_and_fresh_process_receipt_replay(self):
        import test_workspace_bridge as fixtures
        fixture = fixtures.NativeBridgeTests(methodName="test_rejected_completed_reply_still_records_usage")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        bridge = fixture.create()
        request = {"version":VERSION, "targets":[{"work_id":"initial",
            "question":"Which local dependency metadata is actually available?",
            "windows":[{"path":"app.js", "start_line":1, "end_line":1,
                        "file_sha256":hashlib.sha256((fixture.root / "app.js").read_bytes()).hexdigest()}],
            "packages":["finale-rest"]}]}
        path = fixture.base / "evidence-request.json"
        path.write_text(json.dumps(request), encoding="utf-8")
        command = [sys.executable, str(Path(__file__).resolve().parents[2] / "scripts/review_workspace_bridge.py"),
            "prepare-evidence", "--evidence-request", str(path), "--operation-key", "shared-evidence"]
        for key, value in vars(fixture.args).items():
            command += ["--" + key.replace("_", "-"), str(value)]
        for replay in (False, True):
            completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["replayed"], replay)
        recovered = fixtures.NativeWorkspace(fixture.args)
        view = recovered.workspace.view("initial")
        self.assertEqual(len(view["deciding_evidence"]), 1)
        self.assertEqual(recovered.workspace.snapshot()["calls"], {})
        self.assertEqual(recovered.workspace.snapshot()["sessions"], {})


if __name__ == "__main__":
    unittest.main()
