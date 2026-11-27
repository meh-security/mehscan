"""Configured Action review: deterministic CLI/native Git, no inference or GitHub writes."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch
import test_advisory as fixtures

adapter = fixtures.adapter
ROOT = fixtures.ROOT


class Routing(fixtures.FixtureBase):
    def test_composite_requires_optin_and_exposes_final_review_outputs(self):
        import yaml
        action=yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        self.assertEqual(action["inputs"]["review-mode"]["default"],"native")
        self.assertEqual(action["inputs"]["provider-config"]["default"],"")
        review=next(step for step in action["runs"]["steps"] if step.get("id")=="review")
        self.assertIn("review_ready",review["if"])
        self.assertIn("inputs.provider-config != ''",review["if"])
        self.assertIn(" run-model ",review["run"])
        self.assertIn("steps.review.outputs.status",action["outputs"]["status"]["value"])
        self.assertIn("incomplete",action["outputs"]["status"]["value"])
        self.assertIn("steps.review.outcome == 'skipped'",action["outputs"]["review-handoff"]["value"])

    def test_hosted_delivery_skips_drafts_forks_and_superseded_events(self):
        os.environ.update(GITHUB_EVENT_NAME="pull_request_target", MEHSCAN_REVIEW_MODE="value",
                          MEHSCAN_SHARE_LINK=str(self.workspace / "unused-link.json"), MEHSCAN_PROVIDER_CONFIG="unused")
        for current, reason in ((fixtures.pr(draft=True), "pull_request_not_ready"),
                                (fixtures.pr(fork=True), "pull_request_outside_enrollment"),
                                (fixtures.pr(), "superseded_pull_request_event")):
            self.delivery.pr = current
            # The queued event carries a prior head. No sharing or reviewer work starts.
            if reason == "superseded_pull_request_event":
                client = adapter.sharing_client()
                link = Path(os.environ["MEHSCAN_SHARE_LINK"])
                link.write_text(json.dumps({"repository_id": "123"}))
                with patch.object(client, "send") as send:
                    _, plan = self.prepare()
                    send.assert_not_called()
            else:
                _, plan = self.prepare()
            self.assertFalse(plan["should_scan"])
            self.assertEqual(plan["skip_reason"], reason)

    def test_hosted_value_prioritizes_new_paths_within_scan_root_without_dropping_work(self):
        plan = {"checkout": str(self.checkout), "scan_root": "src", "scanner": str(self.scanner),
                "sharing": {"binding": {"previous_head_sha": fixtures.B, "head_sha": fixtures.H, "path_prefix": "src"}}}
        work = {"payload": {"review_ids": ["old", "new"]}}
        source = {"plan_id": "plan", "source_fingerprint": "source", "assignments": [
            {"id": "older", "review_ids": ["old"], "windows": [{"path": "old.js"}]},
            {"id": "updated", "review_ids": ["new"], "windows": [{"path": "new.js"}]}]}

        def execute(args, **_):
            return {"investigate": json.dumps(source), "merge-base": fixtures.B, "diff": "src/new.js\0"}[args[1]]

        path = adapter.hosted_value_selection(plan, self.workspace / "inventory", work, self.workspace, execute)
        selection = json.loads(path.read_text())
        self.assertEqual(selection["native_assignment_ids"], ["updated", "older"])
        self.assertEqual(selection["assignment_ids"], [])

    def test_fork_event_never_reads_config_or_launches_model(self):
        endpoints = {"kind":"pull_request", "base_repository":{"id":123}, "source_repository":{"id":777}}
        os.environ.update(MEHSCAN_REVIEW_MODE="value",MEHSCAN_PROVIDER_CONFIG="missing-config")
        self.assertEqual(adapter.model_options("value",endpoints),("native",None,"fork_model_review_not_authorized"))
        endpoints["source_repository"]["id"]=123
        self.assertEqual(adapter.model_options("value",endpoints),("value","missing-config",None))

    def test_native_mode_and_nonmanual_fork_optin_are_rejected(self):
        endpoints = {"kind":"pull_request", "base_repository":{"id":123}, "source_repository":{"id":777}}
        os.environ["MEHSCAN_PROVIDER_CONFIG"]="missing-config"
        with self.assertRaises(ValueError): adapter.model_options("native",endpoints)
        os.environ["MEHSCAN_ALLOW_FORK_REVIEW"]="true"
        with self.assertRaises(ValueError): adapter.model_options("value",endpoints)
        os.environ["GITHUB_EVENT_NAME"]="workflow_dispatch"
        self.assertEqual(adapter.model_options("value",endpoints),("value","missing-config",None))

    def test_summary_keeps_missing_completion_unknown_and_effects_separate(self):
        directory = self.workspace / "artifacts"
        directory.mkdir()
        record = {"schema_version":"1", "status":"reviewed", "snapshot_id":"test-snapshot", "reason":"advisory_review_finished",
            "contract":{"endpoints":{"base_commit":fixtures.A,"target_commit":fixtures.H},
                        "scan_root":".", "policy":adapter.POLICY}}
        adapter.save_result(directory,record)
        self.assertIn("issue-count=\n",(self.workspace / "outputs").read_text())
        record["completion"] = {"review_work_complete":False,"security_resolution":"not_established",
            "issue_review_ids":[],"pending_review_ids":[],"pending_changed_effects":[{"path":"app.js","questions":["Inspect issuer."]}],
            "deferred_review_ids":{"native-1":"Value selection"},"missing_or_conflicting_review_ids":["native-2"]}
        record["contract"]["review_runtime"]={"policy":"value"}
        adapter.save_result(directory,record)
        outputs=(self.workspace / "outputs").read_text()
        self.assertIn("pending-effect-count=1",outputs)
        self.assertIn("deferred-count=1",outputs)
        self.assertIn("missing-review-count=1",outputs)
        self.assertIn("review-work-complete=false",outputs)
        completion=json.loads((directory / "completion.json").read_text())
        self.assertEqual(completion["execution_status"],record["status"])
        self.assertIn("Pending changed effects: 1",(directory / "summary.md").read_text())


class BYOK(fixtures.NativeFixture):
    def setUp(self):
        super().setUp()
        self.delivery.pr["head"]["repo"] = dict(self.delivery.pr["base"]["repo"])
        self.auth = self.workspace / "trusted/auth.json"
        self.auth.write_text('{"fixture":"not-a-real-key"}')
        self.cli_script = self.workspace / "trusted/codex-fixture.py"
        self.cli_script.write_text(r'''import json, os, pathlib, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli fixture-1")
elif "--help" in args:
    print("--ignore-user-config --ignore-rules --strict-config --output-schema --json")
elif args == ["features", "list"]:
    print("\n".join(["shell_tool","multi_agent","apps","plugins","hooks","view_image"]))
else:
    assert "--last" not in args
    assert 'permissions.mehscan_review.network.enabled=false' in args
    assert "GH_TOKEN" not in os.environ and "GITHUB_TOKEN" not in os.environ
    prompt = sys.stdin.read()
    auth = json.loads((pathlib.Path(os.environ["CODEX_HOME"]) / "auth.json").read_text())
    schema = json.loads(pathlib.Path(args[args.index("--output-schema")+1]).read_text())
    shape = schema["properties"]["draft"]["anyOf"][0]["properties"]
    if "proposals" in shape:
        packet=json.loads(prompt.split("Requested source assignment and native questions:\n")[1].split("\n")[0])
        windows=json.JSONDecoder().raw_decode(prompt.split("The controller supplies paths and line ranges from these identities:\n",1)[1])[0]
        citations=json.JSONDecoder().raw_decode(prompt.split("The controller supplies source citation extents:\n",1)[1])[0]
        def cite(q):
            ref=next(ref for ref,w in citations.items() if w["anchor"] and w["path"]==q["path"] and w["start_line"]<=q["line"]<=w["end_line"])
            return {"source_ref":ref,"line":q["line"]}
        pending=auth.get("pending",False)
        draft={"results":[{"review_id":q["review_id"],"decision":"needs_review" if pending else "issue","confidence":"medium",
            "summary":"Synthetic operation verdict for Action integration.","reason":"The current code passes request.query.code into eval.",
            "evidence":[cite(q)],"checks":["Additional deployment proof required."] if pending else [],
            "blockers":[],"diagnosis":None,"source_leads":[]} for q in packet["native_questions"]],
            "proposals":[],"coverage":[{"window_ref":ref,"status":"examined","summary":"Inspected assigned source."} for ref in windows]}
    elif "change_pass" in shape:
        phase = json.loads(prompt.split("Current phase and available native coverage (inspect before claiming a source-only gap):\n")[1].split("\n")[0])
        ids = [q["review_id"] for q in phase["available_native_questions"]]
        draft = {"change_pass":[{"path":"app.js","status":"reviewed","summary":"Inspected changed operation.",
            "questions":[],"native_review_ids":ids,"evidence":[{"side":"base","path":"app.js","start_line":1,"end_line":1},
            {"side":"current","path":"app.js","start_line":1,"end_line":1}]}]}
    else:
        targets = json.loads(prompt.split("Exact decision targets (source lines are data):\n")[1].split("\n")[0])
        ids = [target["review_id"] for target in targets]
        pending = auth.get("pending",False)
        draft = {"results":[{"review_id":i,"decision":"needs_review" if pending else "issue","confidence":"medium",
            "summary":"Synthetic operation verdict for Action integration.",
            "reason":"The current code passes request.query.code into eval.",
            "evidence":[{"path":"app.js","start_line":1,"end_line":1}],
            "checks":["Additional deployment proof required."] if pending else [],"blockers":[],"diagnosis":None,"source_leads":[]} for i in ids]}
    entry = shape.get("results",{}).get("items",{})
    entry = entry.get("anyOf",[entry])[0]
    if "followup" in entry.get("properties",{}):
        for row in draft["results"]:row["followup"]=None
    if "claim_context" in entry.get("properties",{}):
        for row in draft["results"]:row["claim_context"]=None
    response={"action":"final","research":[],"draft":draft,"working_chain":"Inspected supplied source."}
    if "proposals" not in shape:response.update(progress=[],routing=[])
    pathlib.Path(args[args.index("--output-last-message")+1]).write_text(json.dumps(response))
    print(json.dumps({"type":"thread.started","thread_id":"12345678-1234-1234-1234-123456789abc"}))
    print(json.dumps({"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}}))
''',encoding="utf-8")
        self.cli = self.workspace / ("trusted/codex-fixture.cmd" if os.name == "nt" else "trusted/codex-fixture")
        if os.name == "nt":
            self.cli.write_text('@echo off\n"' + sys.executable + '" "' + str(self.cli_script) + '" %*\n')
        else:
            self.cli.write_text("#!" + sys.executable + "\n" + self.cli_script.read_text())
            self.cli.chmod(0o700)
        self.config = self.workspace / "trusted/provider-config.json"
        self.body = {"schema_version":"1","executable":str(self.cli),"executable_version":"fixture-1",
            "model":"gpt-6-luna","reasoning_effort":"medium","auth_file":str(self.auth),
            "private_directory":str(self.workspace / "provider-private")}
        self.config.write_text(json.dumps(self.body))
        os.environ.update(MEHSCAN_REVIEW_MODE="comprehensive", MEHSCAN_PROVIDER_CONFIG=str(self.config))

    def ready(self):
        directory, plan = self.prepare()
        record = adapter.finish(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(record["status"],"review_ready",record)
        return directory,plan,record

    def test_hosted_value_review_publishes_retained_result_after_base_moves(self):
        client = adapter.sharing_client()
        with patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
            import review_host as host
        db = self.workspace / "shared.sqlite"

        def sql(query, *args):
            with closing(sqlite3.connect(db)) as connection, connection:
                connection.row_factory = sqlite3.Row
                return [dict(row) for row in connection.execute(query, args).fetchall()]

        def store(enrollment):
            return client.EventStore(sql, enrollment["id"])

        registry = host.Registry(self.workspace / "registry.sqlite")
        enrollment = registry.enroll("123", "team", "org", "review", "MEHSCAN_TURSO_WRITE_TOKEN_TEST", "manager",
                                     storage=store, lookup=lambda *_: ("fixture-database", "https://fixture.turso.io"))
        workflow = "owner/project/.github/workflows/hosted.yml@refs/heads/main"
        claims = {"repository_id": "123", "workflow_ref": workflow, "workflow_sha": self.base, "sha": self.base,
                  "ref": "refs/heads/main", "environment": "Review", "event_name": "pull_request_target",
                  "run_id": "42", "run_attempt": "1", "head_ref": "topic", "base_ref": "main"}
        service = host.Service(registry, lambda _: claims, storage=store,
            reader=lambda _: {"database_id": enrollment["database_id"], "remote": enrollment["remote"], "token": "fixture"},
            pull_request=lambda repo, number: adapter.resolve_pr(self.delivery.get, repo, number, "https://github.com"))
        request = {"repository_id": "123", "audience": "team"}
        token = registry.issue("manager", 1)["token"]
        service.dispatch("/v1/workflow", token, {**request, "submission": {
            "workflow_ref": workflow, "ref": "refs/heads/main", "environment": "Review", "stream": "main",
            "events": ["pull_request_target", "workflow_dispatch"]}})
        link = {**service.dispatch("/v1/link", "fixture-oidc", request), **request, "host": "https://sharing.example"}
        path = self.workspace / "link.json"
        path.write_text(json.dumps(link))
        self.event.write_text(json.dumps({"number": 24, "action": "ready_for_review", "pull_request": self.delivery.pr}))
        os.environ.update(GITHUB_EVENT_NAME="pull_request_target", MEHSCAN_SHARE_LINK=str(path), MEHSCAN_REVIEW_MODE="value")

        def send(_link, operation, body=None):
            return service.dispatch("/v1/" + operation, "fixture-oidc",
                                    request if body is None else {**request, "submission": body})

        def execute(args, **kwargs):
            result = self.execute(args, **kwargs)
            if len(args) > 1 and str(args[1]).endswith("review_worker.py"):
                self.delivery.base = fixtures.B
            return result

        with patch.object(client, "send", side_effect=send), patch.object(client, "sql_database", return_value=sql):
            directory, plan, _ = self.ready()
            plan_path = directory / "plan.json"
            self.assertEqual(plan["sharing"]["binding"]["head_sha"], self.head)
            result = adapter.run_model(plan_path, self.delivery.get, execute)
            self.assertEqual((result["status"], result["review_execution"]), ("stale", "admitted"), result)
            adapter.publish_hosted(plan_path)
            published = json.loads((directory / "run.json").read_text())["publication"]
            self.assertEqual(published["status"], "historical")
            self.assertIn("Shared review: **historical**", (directory / "summary.md").read_text())
            adapter.publish_hosted(plan_path)
            self.assertEqual(len(store(enrollment).list(0)), 1)
            self.delivery.base = self.base
            current = send(link, "pr-current", {"pull_request": 24})
            self.assertEqual((current["status"], current["result"]["id"]), ("current", published["receipt"]["id"]))

    def test_configured_model_runs_native_admission_and_exports_completion(self):
        directory,plan,record = self.ready()
        provider = plan["review"]["runtime"]["provider"]
        self.assertEqual(provider["model"],"gpt-6-luna")
        self.assertFalse(Path(plan["model"]["command"]).is_relative_to(directory))
        result = adapter.run_model(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(result["status"],"reviewed",result)
        self.assertEqual(result["review_execution"],"admitted")
        completion = json.loads((directory / "completion.json").read_text())
        self.assertEqual(completion["snapshot_id"],result["snapshot_id"])
        self.assertEqual(completion["endpoints"]["target_commit"],self.head)
        self.assertTrue(completion["completion"]["issue_review_ids"])
        self.assertNotIn("review_handoff",result)
        self.assertNotIn("not-a-real-key",(directory / "run.json").read_text())
        self.assertIn("issue-count=1",(self.workspace / "outputs").read_text())
        sarif=json.loads((directory / "findings.sarif").read_text())
        self.assertEqual(sarif["version"],"2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]),1)
        self.assertTrue(sarif["runs"][0]["results"][0]["partialFingerprints"])
        self.assertEqual(sarif["runs"][0]["properties"]["mehscanAction"]["endpoints"]["target_commit"],self.head)
        usage=json.loads((directory / "usage.json").read_text())
        self.assertTrue(usage["usage_available"])
        self.assertEqual(usage["reported_token_sums"]["input_tokens"],200)
        self.assertIsNone(usage["cost"])
        manifest=json.loads((directory / "artifacts.json").read_text())
        self.assertTrue({"finding-groups.json","finding-groups.md"} <= {r["path"] for r in manifest["files"]})
        groups=json.loads((directory / "finding-groups.json").read_text())
        self.assertEqual(groups["claim_count"],1)
        import hashlib
        for entry in manifest["files"]:
            self.assertEqual(hashlib.sha256((directory / entry["path"]).read_bytes()).hexdigest(),entry["sha256"])
        with self.assertRaises(ValueError): adapter.run_model(directory / "plan.json",self.delivery.get,self.execute)

    def test_configured_value_stops_at_selection_checkpoint(self):
        os.environ["MEHSCAN_REVIEW_MODE"] = "value"
        directory, plan, record = self.ready()
        result = adapter.run_model(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(result["status"], "selection_required", result)
        self.assertNotIn("completion", result)
        self.assertFalse((directory / "usage.json").exists())
        self.assertFalse((directory / "review/source-review/jobs").exists())
        self.assertTrue(Path(result["source_selection"]).is_file())
        self.assertFalse((Path(plan["review_control"]) / "close.json").exists())

    def test_value_consumes_a_trusted_selection_for_the_same_pinned_source(self):
        os.environ["MEHSCAN_REVIEW_MODE"] = "value"
        directory, _, _ = self.ready()
        result = adapter.run_model(directory / "plan.json", self.delivery.get, self.execute)
        options = json.loads(Path(result["source_selection"]).read_text())
        selected = self.workspace / "trusted" / "selection.json"
        selected.write_text(json.dumps({
            "source_plan_id": options["source_plan_id"],
            "source_fingerprint": options["source_fingerprint"],
            "assignment_ids": [], "assignments": [],
        }))
        os.environ["MEHSCAN_SOURCE_SELECTION"] = str(selected)
        directory, plan, _ = self.ready()
        selected.unlink()  # Handoff uses the private copy from preparation.
        result = adapter.run_model(directory / "plan.json", self.delivery.get, self.execute)
        self.assertEqual(result["status"], "reviewed", result)
        output = (self.workspace / "outputs").read_text().splitlines()
        [receipt] = [Path(line.removeprefix("close-receipt=")) for line in output if line.startswith("close-receipt=")]
        self.assertEqual(receipt.parent, Path(plan["review_control"]))
        self.assertFalse(receipt.is_relative_to(directory))
        close = json.loads(receipt.read_text())
        self.assertEqual(close["result"]["generation"], result["coordination"]["generation"])
        self.assertEqual(close["result"]["status"], "finished")
        self.assertEqual(close["memory"]["reason"], "temporary_mode")
        rendered = json.loads(self.execute([plan["scanner"], "report", "--close-receipt", str(receipt), "--format", "json"]))
        self.assertEqual(rendered, json.loads((directory / "review/findings.json").read_text()))
        self.assertTrue(rendered["decision_records"])

    def test_pending_verdict_keeps_success_separate_from_security_resolution(self):
        self.auth.write_text('{"fixture":"not-a-real-key","pending":true}')
        directory,plan,record = self.ready()
        result = adapter.run_model(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(result["status"],"reviewed",result)
        self.assertTrue(result["completion"]["pending_review_ids"])
        self.assertEqual(result["completion"]["security_resolution"],"not_established")
        self.assertIn("pending-review-count=1",(self.workspace / "outputs").read_text())
        self.assertEqual(json.loads((directory / "findings.sarif").read_text())["runs"][0]["results"],[])
        self.assertTrue(json.loads((directory / "findings.json").read_text())["review_required"])

    def test_missing_auth_and_changed_config_close_owned_attempt_incomplete(self):
        os.environ["MEHSCAN_REQUIRE_COMPLETE_DELTA_COVERAGE"] = "true"
        directory,plan,record = self.ready()
        self.auth.unlink()
        result = adapter.run_model(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(result["status"],"incomplete",result)
        self.assertEqual(result["coordination"]["state"],"owned_incomplete")
        self.assertNotIn("completion",result)
        self.assertFalse((directory / "completion.json").exists())
        coverage = json.loads((directory / "delta-coverage.json").read_text())
        self.assertEqual((coverage["status"], coverage["gate"]), ("incomplete", "blocked"))
        self.assertEqual(coverage["counts"]["unavailable"], 1)
        self.assertNotIn("review_handoff",result)
        self.assertIn("review-work-complete=\n",(self.workspace / "outputs").read_text())

    def test_changed_config_rejects_before_any_worker(self):
        directory,plan,record = self.ready()
        self.config.write_text(json.dumps({**self.body,"model":"different-model"}))
        def execute(argv,**kwargs):
            self.assertFalse(any(str(value).endswith("review_worker.py") for value in argv))
            return self.execute(argv,**kwargs)
        result = adapter.run_model(directory / "plan.json",self.delivery.get,execute)
        self.assertEqual(result["status"],"incomplete",result)
        self.assertEqual(result["coordination"]["state"],"owned_incomplete")

    def test_automatic_fork_prepares_native_only_without_reading_model_config(self):
        self.delivery.pr["head"]["repo"] = {"id":777,"full_name":"fork/project"}
        self.config.unlink()
        directory,plan = self.prepare()
        self.assertNotIn("model",plan)
        self.assertNotIn("review",plan)
        record = adapter.finish(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(record["status"],"native_only",record)
        self.assertEqual(record["reason"],"fork_model_review_not_authorized")

    def test_fork_model_authorization_requires_explicit_manual_dispatch(self):
        self.delivery.pr["head"]["repo"] = {"id":777,"full_name":"fork/project"}
        os.environ["MEHSCAN_ALLOW_FORK_REVIEW"] = "true"
        with self.assertRaises(ValueError): self.prepare()
        os.environ.update(GITHUB_EVENT_NAME="workflow_dispatch",MEHSCAN_PR="24")
        directory,plan,record = self.ready()
        self.assertIn("model",plan)
        self.assertEqual(plan["endpoints"]["source_repository"]["id"],777)

    def test_subdirectory_sarif_locations_are_repository_relative(self):
        sub=self.checkout / "src"
        sub.mkdir()
        (self.checkout / "app.js").rename(sub / "app.js")
        self.git("add",".")
        self.git("commit","--quiet","-m","move source into scan root")
        self.head=self.git("rev-parse","HEAD")
        self.delivery.pr["head"]["sha"]=self.head
        os.environ["MEHSCAN_SCAN_ROOT"]="src"
        # Explicit release base is the previous same-path code, avoiding rename
        # scope ambiguity in this fixture; every actual byte is still CLI-bound.
        self.git("checkout","--quiet",self.base)
        (self.checkout / "src").mkdir()
        (self.checkout / "app.js").rename(self.checkout / "src/app.js")
        self.git("add",".")
        self.git("commit","--quiet","-m","subdirectory base")
        self.base=self.git("rev-parse","HEAD")
        self.git("checkout","--quiet",self.head)
        os.environ.update(GITHUB_EVENT_NAME="workflow_dispatch",MEHSCAN_BASE=self.base,MEHSCAN_TARGET=self.head)
        self.delivery.tags[self.base]=self.base
        self.delivery.tags[self.head]=self.head
        directory,plan,record=self.ready()
        result=adapter.run_model(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(result["status"],"reviewed",result)
        sarif=json.loads((directory / "findings.sarif").read_text())
        primary=sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(primary,"src/app.js")

    def test_export_failure_is_incomplete_without_a_ready_manifest(self):
        directory,plan,record=self.ready()
        def execute(argv,**kwargs):
            if "--format" in argv and argv[argv.index("--format")+1] in ("json-sarif", "sarif"):
                raise RuntimeError("synthetic renderer failure")
            return self.execute(argv,**kwargs)
        result=adapter.run_model(directory / "plan.json",self.delivery.get,execute)
        self.assertEqual(result["status"],"incomplete",result)
        self.assertNotIn("exports",result)
        self.assertFalse((directory / "artifacts.json").exists())

    def test_native_config_and_source_config_are_rejected(self):
        os.environ["MEHSCAN_REVIEW_MODE"]="native"
        with self.assertRaises(ValueError): self.prepare()
        os.environ["MEHSCAN_REVIEW_MODE"]="value"
        path = self.checkout / "config.json"
        path.write_text(json.dumps(self.body))
        os.environ["MEHSCAN_PROVIDER_CONFIG"]=str(path)
        with self.assertRaises(ValueError): self.prepare()


if __name__ == "__main__":
    unittest.main()
