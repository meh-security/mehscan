"""Lifecycle delivery uses fake read-only GitHub; native smoke uses real Git/CLI."""
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("mehscan_advisory", ROOT / "scripts/github_action.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
A, B, H = "a" * 40, "b" * 40, "c" * 40


def pr(base=A, head=H, draft=False, state="open", fork=False):
    return {"number": 24, "state": state, "draft": draft, "merged": False,
            "base": {"repo": {"id": 123, "full_name": "owner/project"}, "ref": "main", "sha": base},
            "head": {"repo": {"id": 777 if fork else 123, "full_name": "fork/project" if fork else "owner/project"}, "ref": "topic", "sha": head}}


class Delivery:
    def __init__(self, current=None):
        self.pr = current or pr()
        self.base = self.pr["base"]["sha"]
        self.tags = {"old": A, "new": H}
        self.calls = []

    def get(self, endpoint):
        self.calls.append(endpoint)
        if endpoint.endswith("/pulls/24"):
            return copy.deepcopy(self.pr)
        if "/git/ref/heads/" in endpoint:
            return {"object": {"sha": self.base}}
        if endpoint == "/repos/owner/project":
            return {"id": 123, "full_name": "owner/project"}
        if "/commits/" in endpoint:
            return {"sha": self.tags[endpoint.rsplit("/", 1)[1]]}
        raise AssertionError(endpoint)


class FixtureBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-action-test-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        self.checkout = self.workspace / "mehscan-source"
        self.checkout.mkdir()
        self.scanner = self.workspace / "trusted" / "mehscan"
        self.scanner.parent.mkdir()
        self.scanner.write_bytes(b"synthetic trusted scanner")
        self.event = self.workspace / "event.json"
        self.event.write_text(json.dumps({"number": 24, "action": "synchronize", "pull_request": pr(head=B)}))
        self.env = {"GITHUB_WORKSPACE": str(self.workspace), "RUNNER_TEMP": str(self.workspace),
                    "GITHUB_EVENT_PATH": str(self.event), "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_REPOSITORY": "owner/project", "GITHUB_REPOSITORY_ID": "123",
                    "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SERVER_URL": "https://github.com",
                    "MEHSCAN_SCANNER_PATH": str(self.scanner), "MEHSCAN_SOURCE_PATH": "mehscan-source", "MEHSCAN_SCAN_ROOT": ".",
                    "MEHSCAN_PR": "", "MEHSCAN_BASE": "", "MEHSCAN_TARGET": "", "GH_TOKEN": "synthetic-read-token",
                    "MEHSCAN_STATE_STORE": "", "MEHSCAN_STATE_RETRY": "false",
                    "MEHSCAN_REVIEW_MODE": "native", "MEHSCAN_SKILL_ROOT": "", "MEHSCAN_PROVIDER_CONTRACT": "",
                    "MEHSCAN_PROVIDER_CONFIG": "", "MEHSCAN_ALLOW_FORK_REVIEW": "false",
                    "GITHUB_OUTPUT": str(self.workspace / "outputs"), "GITHUB_STEP_SUMMARY": str(self.workspace / "summary")}
        self.patch = patch.dict(os.environ, self.env)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.delivery = Delivery()

    def prepare(self):
        directory = adapter.prepare(self.delivery.get)
        return directory, json.loads((directory / "plan.json").read_text())

    def fake_scan(self, plan, directory, execute):
        endpoints = plan["endpoints"]
        comparison = {"base_commit": endpoints["base_commit"], "target_commit": endpoints["target_commit"], "working_tree": False}
        inputs = {"input_fingerprint": "fixture-input", "changed_snapshot": "fixture-source"}
        overview = {"review_count": 0, "coverage": {"scanned": 0}, "impact_scope": {"comparison": comparison}}
        return comparison, inputs, overview

    def finish(self, directory, **kwargs):
        with patch.object(adapter, "scan", side_effect=self.fake_scan):
            return adapter.finish(directory / "plan.json", self.delivery.get, **kwargs)

class Lifecycle(FixtureBase):
    def test_authoritative_head_base_branch_tip_and_fork_namespace(self):
        self.delivery.pr = pr(fork=True)
        self.delivery.base = B
        _, plan = self.prepare()
        self.assertEqual(plan["endpoints"]["target_commit"], H)  # event head B is merely a locator
        self.assertEqual(plan["endpoints"]["base_commit"], B)  # PR object's cached base A is insufficient
        self.assertEqual(plan["endpoints"]["base_repository"]["id"], 123)
        self.assertEqual(plan["endpoints"]["source_repository"]["id"], 777)

    def test_duplicate_delivery_same_snapshot_separate_attempt_artifacts(self):
        first, _ = self.prepare()
        os.environ["GITHUB_RUN_ATTEMPT"] = "2"
        second, _ = self.prepare()
        a, b = self.finish(first), self.finish(second)
        self.assertNotEqual(first, second)
        self.assertEqual(a["snapshot_id"], b["snapshot_id"])
        self.assertNotEqual(a["run_attempt"], b["run_attempt"])
        self.assertEqual(a["policy"]["alert_disposition"], "not_established")

    def test_head_force_push_and_base_only_push_reject_old_attempt_before_scan(self):
        for changed in ("head", "base", "base_ref", "closed", "draft", "fork"):
            with self.subTest(changed=changed):
                self.delivery = Delivery()
                directory, _ = self.prepare()
                if changed == "head": self.delivery.pr["head"]["sha"] = B
                elif changed == "base": self.delivery.base = B
                elif changed == "base_ref": self.delivery.pr["base"]["ref"] = "release"
                elif changed == "closed": self.delivery.pr["state"] = "closed"
                elif changed == "draft": self.delivery.pr["draft"] = True
                else: self.delivery.pr["head"]["repo"]["id"] = 999
                with patch.object(adapter, "scan") as scan:
                    result = adapter.finish(directory / "plan.json", self.delivery.get)
                    scan.assert_not_called()
                self.assertEqual(result["status"], "stale")

    def test_base_moves_during_scan_preserves_historical_contract(self):
        directory, plan = self.prepare()
        def moving_scan(*args):
            output = self.fake_scan(*args)
            self.delivery.base = B
            return output
        with patch.object(adapter, "scan", side_effect=moving_scan):
            result = adapter.finish(directory / "plan.json", self.delivery.get)
        self.assertEqual(result["status"], "stale")
        self.assertEqual(result["contract"]["endpoints"]["base_commit"], plan["endpoints"]["base_commit"])
        self.assertEqual(result["contract"]["endpoints"]["base_commit"], A)

    def test_close_deleted_fork_and_metadata_only_edits_are_skipped(self):
        self.delivery.pr["state"] = "closed"
        self.delivery.pr["head"]["repo"] = None
        directory, plan = self.prepare()
        self.assertFalse(plan["should_scan"])
        self.assertEqual(self.finish(directory)["status"], "skipped")
        self.delivery = Delivery()
        self.event.write_text(json.dumps({"number": 24, "action": "edited", "changes": {"title": {"from": "old"}}}))
        directory, plan = self.prepare()
        self.assertEqual(plan["skip_reason"], "metadata_only_edit")
        self.event.write_text(json.dumps({"number": 24, "action": "edited", "changes": {"base": {"ref": {"from": "old"}}}}))
        _, plan = self.prepare()
        self.assertTrue(plan["should_scan"])

    def test_draft_ready_reopen_and_conflict_are_native_only(self):
        for action in ("opened", "converted_to_draft", "ready_for_review", "reopened"):
            self.event.write_text(json.dumps({"number": 24, "action": action}))
            self.delivery.pr["draft"] = action == "converted_to_draft"
            self.delivery.pr["mergeable"] = False
            directory, _ = self.prepare()
            result = self.finish(directory)
            self.assertEqual(result["status"], "native_only")
            self.assertEqual(result["policy"]["ai_review"], "not_run")
            self.assertEqual(result["policy"]["integration_review"], "not_run")

    def test_missing_metadata_history_and_cancellation_stay_incomplete_or_cancelled(self):
        directory, _ = self.prepare()
        with patch.object(adapter, "scan", side_effect=RuntimeError("untrusted ::error:: do not print")):
            result = adapter.finish(directory / "plan.json", self.delivery.get)
        self.assertEqual(result["status"], "incomplete")
        self.assertNotIn("::error::", (directory / "summary.md").read_text())
        self.assertEqual(self.finish(directory, cancelled=lambda: True)["status"], "cancelled")
        directory, _ = self.prepare()
        def cancelled_scan(*args):
            output = self.fake_scan(*args)
            os.environ["TEST_CANCELLED"] = "true"
            return output
        with patch.object(adapter, "scan", side_effect=cancelled_scan):
            result = adapter.finish(directory / "plan.json", self.delivery.get, cancelled=lambda: os.environ.get("TEST_CANCELLED") == "true")
        self.assertEqual(result["status"], "cancelled")

    def test_explicit_release_refs_pin_direct_endpoints_and_detect_tag_movement(self):
        os.environ.update(GITHUB_EVENT_NAME="workflow_dispatch", MEHSCAN_BASE="old", MEHSCAN_TARGET="new")
        directory, plan = self.prepare()
        self.assertEqual(plan["endpoints"]["kind"], "release_delta")
        self.assertEqual(plan["endpoints"]["base_commit"], A)
        self.delivery.tags["old"] = B
        self.assertEqual(self.finish(directory)["status"], "stale")

    def test_unsupported_events_overrides_paths_and_target_binary_fail(self):
        for event in ("issue_comment", "pull_request_target", "merge_group", "push"):
            with self.subTest(event=event), self.assertRaises(ValueError):
                adapter.route(event, {}, "", "", "")
        with self.assertRaises(ValueError): adapter.route("pull_request", {"number":24,"action":"synchronize"}, "25", "", "")
        for field, value in (("MEHSCAN_SOURCE_PATH", "../escape"), ("MEHSCAN_SOURCE_PATH", "."), ("MEHSCAN_SCAN_ROOT", "../escape")):
            with patch.dict(os.environ, {field: value}), self.assertRaises(ValueError): self.prepare()
        target_scanner = self.checkout / "scanner"
        target_scanner.write_bytes(b"untrusted")
        with patch.dict(os.environ, {"MEHSCAN_SCANNER_PATH": str(target_scanner)}), self.assertRaises(ValueError): self.prepare()
        with patch.dict(os.environ, {"GITHUB_WORKSPACE": str(ROOT), "MEHSCAN_SOURCE_PATH": "scripts"}), self.assertRaises(ValueError): self.prepare()
        before = set(self.checkout.iterdir())
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.checkout)}), self.assertRaises(ValueError): self.prepare()
        self.assertEqual(set(self.checkout.iterdir()), before)
        for state_path in (str(self.checkout), str(self.workspace), "relative-state"):
            with patch.dict(os.environ, {"MEHSCAN_STATE_STORE": state_path}), self.assertRaises(ValueError):
                self.prepare()
        with patch.dict(os.environ, {"MEHSCAN_STATE_RETRY": "true"}), self.assertRaises(ValueError):
            self.prepare()

    def test_checkout_and_scanner_drift_and_wrong_comparison_cannot_be_native_complete(self):
        directory, plan = self.prepare()
        with self.assertRaises(ValueError): adapter.scan(plan, directory, lambda *args, **kwargs: B)
        self.scanner.write_bytes(b"changed executable")
        with self.assertRaises(ValueError): adapter.scan(plan, directory, lambda *args, **kwargs: H)

    def test_fetch_and_scanner_environment_do_not_persist_or_leak_credentials(self):
        directory, plan = self.prepare()
        calls = []
        def execute(args, **kwargs):
            calls.append((args, kwargs))
            if args[1:3] == ["rev-parse", "HEAD"]: return H
            if "--help" in args: return "--target --merge-base"
            if "review-inventory" in args: raise RuntimeError("stop after inspecting environment")
            return ""
        with self.assertRaises(RuntimeError): adapter.scan(plan, directory, execute)
        fetch = next(call for call in calls if "fetch" in call[0])
        self.assertNotIn("synthetic-read-token", str(fetch[0]))
        self.assertEqual(fetch[1]["env"]["GIT_CONFIG_COUNT"], "1")
        for args, kwargs in calls:
            if str(plan["scanner"]) == args[0]:
                self.assertNotIn("GH_TOKEN", kwargs["env"])
                self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
        self.assertIn("--merge-base", next(args for args, _ in calls if "review-inventory" in args))


class NativeFixture(FixtureBase):
    def setUp(self):
        super().setUp()
        executable = Path(os.environ.get("MEHSCAN_TEST_SCANNER", ROOT / "target/debug" / ("mehscan.exe" if os.name == "nt" else "mehscan")))
        if not executable.is_file():
            if os.environ.get("MEHSCAN_REQUIRE_NATIVE_TESTS") == "true":
                self.fail("native Action acceptance requires the built CLI")
            self.skipTest("build mehscan-cli before native Action smoke tests")
        os.environ["MEHSCAN_SCANNER_PATH"] = str(executable)
        def git(*args):
            return adapter.run_command(["git", *args], cwd=self.checkout).strip()
        self.git = git
        git("init", "--quiet")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "Action fixture")
        (self.checkout / "app.js").write_text("const old = true;\n")
        git("add", ".")
        git("commit", "--quiet", "-m", "base")
        self.base = git("rev-parse", "HEAD")
        (self.checkout / "app.js").write_text("function handle(request) { eval(request.query.code); }\n")
        git("add", ".")
        git("commit", "--quiet", "-m", "head")
        self.head = git("rev-parse", "HEAD")
        self.delivery = Delivery(pr(base=self.base, head=self.head, fork=True))

    def execute(self, args, **kwargs):
        # Objects already exist locally; transport delivery is stubbed. All CLI
        # source validation, Git comparisons, inventory and hashes are real.
        if "fetch" in args: return ""
        return adapter.run_command(args, **kwargs)

    def enable_state(self):
        self.state_temp = tempfile.TemporaryDirectory(prefix="mehscan-persistent-state-")
        self.addCleanup(self.state_temp.cleanup)
        os.environ["MEHSCAN_STATE_STORE"] = self.state_temp.name

    def state_view(self, plan, operation="status"):
        store, _, key, stream = adapter.state_layout(plan)
        return adapter.state_json(plan, self.execute, operation,
                                  ["--store", str(store), "--stream", stream, "--repository-key", key])


class NativeSmoke(NativeFixture):
    def test_concurrent_persistent_deliveries_have_one_finished_owner(self):
        self.enable_state()
        first, plan = self.prepare()
        os.environ["GITHUB_RUN_ATTEMPT"] = "2"
        second, _ = self.prepare()
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(adapter.finish, directory / "plan.json", self.delivery.get, self.execute)
                       for directory in (first, second)]
            results = [future.result(timeout=60) for future in futures]
        self.assertEqual({result["status"] for result in results}, {"native_only"}, results)
        self.assertEqual({result["coordination"]["state"] for result in results}, {"owned_finished", "coalesced_finished"})
        self.assertEqual({result["coordination"]["generation"] for result in results}, {1})
        history = self.state_view(plan, "history")
        self.assertEqual(len(history["attempts"]), 1)
        self.assertEqual(history["decisions"], {})
        self.assertTrue(all(subject["state"] == "unassessed" for subject in history["subjects"]))
        for result in results:
            self.assertNotIn('"owner"', json.dumps(result))
            self.assertNotIn(self.env["GH_TOKEN"], json.dumps(result))

    def test_drift_after_inventory_cannot_claim_and_drift_after_claim_ends_incomplete(self):
        self.enable_state()
        directory, plan = self.prepare()
        native_scan = adapter.scan
        def drift_before_claim(*args):
            result = native_scan(*args)
            self.delivery.base = B
            return result
        with patch.object(adapter, "scan", side_effect=drift_before_claim):
            result = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(result["status"], "stale", result)
        store, _, _, _ = adapter.state_layout(plan)
        self.assertFalse((store / "transactions.jsonl").exists())
        self.delivery.base = self.base
        directory, plan = self.prepare()
        def drift_after_claim(args, **kwargs):
            result = self.execute(args, **kwargs)
            if args[1:3] == ["state", "claim"]:
                self.delivery.base = B
            return result
        result = adapter.finish(directory / "plan.json", self.delivery.get, drift_after_claim)
        self.assertEqual(result["status"], "stale", result)
        self.assertEqual(self.state_view(plan)["attempt_status"], "incomplete")

    def test_closed_draft_and_explicit_retry_keep_state_execution_only(self):
        self.enable_state()
        directory, plan = self.prepare()
        first = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(first["coordination"]["generation"], 1)
        self.delivery.pr["draft"] = True  # Same native inputs, different full Action contract.
        directory, plan = self.prepare()
        draft = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(draft["coordination"]["generation"], 2, draft)
        bindings = [copy.deepcopy(attempt["binding"]) for attempt in self.state_view(plan, "history")["attempts"]]
        first_key, second_key = (binding.pop("coordination_key") for binding in bindings)
        self.assertNotEqual(first_key, second_key)
        self.assertEqual(bindings[0], bindings[1])
        os.environ["MEHSCAN_STATE_RETRY"] = "true"
        directory, plan = self.prepare()
        retry = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(retry["coordination"]["generation"], 3, retry)
        self.delivery.pr["state"] = "closed"
        directory, _ = self.prepare()
        closed = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(closed["status"], "skipped")
        view = self.state_view(plan)
        self.assertEqual(view["generation"], 3)  # A skipped event is not remediation.
        self.assertEqual(view["alert_disposition"], "not_established")

    def test_cancellation_after_claim_preserves_cancelled_attempt_and_corruption_fails_closed(self):
        self.enable_state()
        directory, plan = self.prepare()
        cancelled = False
        def execute(args, **kwargs):
            nonlocal cancelled
            result = self.execute(args, **kwargs)
            if args[1:3] == ["state", "claim"]:
                cancelled = True
            return result
        result = adapter.finish(directory / "plan.json", self.delivery.get, execute, lambda: cancelled)
        self.assertEqual(result["status"], "cancelled", result)
        self.assertEqual(self.state_view(plan)["attempt_status"], "cancelled")
        store, _, _, _ = adapter.state_layout(plan)
        journal = store / "transactions.jsonl"
        journal.write_bytes(journal.read_bytes()[:-1])
        directory, _ = self.prepare()
        result = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(result["status"], "incomplete", result)
        self.assertEqual(result["coordination"]["state"], "incomplete")

    def test_abandoned_claim_coalesces_without_authority_until_explicit_retry(self):
        self.enable_state()
        directory, plan = self.prepare()
        def lost_receipt(args, **kwargs):
            result = self.execute(args, **kwargs)
            if args[1:3] == ["state", "claim"]:
                raise RuntimeError("worker lost the claim receipt")
            return result
        lost = adapter.finish(directory / "plan.json", self.delivery.get, lost_receipt)
        self.assertEqual(lost["status"], "incomplete", lost)
        self.assertEqual(self.state_view(plan)["attempt_status"], "running")
        directory, _ = self.prepare()
        coalesced = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(coalesced["coordination"]["state"], "coalesced_running", coalesced)
        self.assertEqual(coalesced["coordination"]["generation"], 1)
        os.environ["MEHSCAN_STATE_RETRY"] = "true"
        directory, plan = self.prepare()
        retried = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(retried["coordination"]["state"], "owned_finished", retried)
        self.assertEqual(self.state_view(plan)["generation"], 2)

    def test_new_generation_fences_late_action_end_even_on_identical_head(self):
        self.enable_state()
        directory, plan = self.prepare()
        superseded = False
        def execute(args, **kwargs):
            nonlocal superseded
            if args[1:3] == ["state", "end"] and not superseded:
                superseded = True
                store, _, _, stream = adapter.state_layout(plan)
                adapter.state_json(plan, self.execute, "claim", ["--store", str(store), "--stream", stream,
                    "--inventory", str(directory / "inventory"), "--source-root", str(self.checkout),
                    "--attempt-id", "trusted-manual-retry", "--expected-generation", "1", "--retry", "true",
                    "--operation-key", "trusted-manual-retry"])
            return self.execute(args, **kwargs)
        result = adapter.finish(directory / "plan.json", self.delivery.get, execute)
        self.assertEqual(result["status"], "incomplete", result)
        current = self.state_view(plan)
        self.assertEqual(current["generation"], 2)
        self.assertEqual(current["attempt_id"], "trusted-manual-retry")
        self.assertEqual(current["attempt_status"], "running")

    def test_source_drift_after_claim_is_historical_and_never_native_current(self):
        self.enable_state()
        directory, plan = self.prepare()
        def dirty_after_claim(args, **kwargs):
            result = self.execute(args, **kwargs)
            if args[1:3] == ["state", "claim"]:
                (self.checkout / "after-claim.txt").write_text("source changed after validated claim\n")
            return result
        result = adapter.finish(directory / "plan.json", self.delivery.get, dirty_after_claim)
        self.assertEqual(result["status"], "stale", result)
        self.assertEqual(result["reason"], "source_changed_before_artifact")
        self.assertEqual(result["contract"]["endpoints"]["target_commit"], self.head)

    def test_real_cli_pins_whole_pr_scope_and_native_repository_namespace(self):
        # A later unrelated push must retain the earlier security-bearing file.
        (self.checkout / "notes.txt").write_text("unrelated push\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "unrelated")
        self.delivery.pr["head"]["sha"] = self.git("rev-parse", "HEAD")
        directory, _ = self.prepare()
        result = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(result["status"], "native_only", result)
        self.assertGreater(result["native_inventory"]["review_count"], 0)
        names = {entry["path"] for entry in result["native_inventory"]["impact_scope"]["changed_files"]}
        self.assertEqual(names, {"app.js", "notes.txt"})
        self.assertEqual(result["contract"]["comparison"]["merge_base_commit"], self.base)
        overview = json.loads((directory / "inventory/overview.json").read_text())
        self.assertEqual(overview["native_identity"]["repository"]["repository_key"], "github.com/repositories/123")
        self.assertEqual(overview["native_identity"]["repository"]["source_repository_key"], "github.com/repositories/777")

    def test_real_cli_release_comparison_is_direct_and_dirty_source_is_incomplete(self):
        os.environ.update(GITHUB_EVENT_NAME="workflow_dispatch", MEHSCAN_BASE="old", MEHSCAN_TARGET="new")
        self.delivery.tags = {"old": self.base, "new": self.head}
        directory, _ = self.prepare()
        result = adapter.finish(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(result["status"], "native_only", result)
        self.assertNotIn("merge_base_commit", result["contract"]["comparison"])
        (self.checkout / "extra.txt").write_text("dirty")
        directory, _ = self.prepare()
        self.assertEqual(adapter.finish(directory / "plan.json", self.delivery.get, self.execute)["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
