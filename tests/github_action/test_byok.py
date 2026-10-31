"""Configured Action review: deterministic CLI/native Git, no inference or GitHub writes."""
import json
import os
from pathlib import Path
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
            "contract":{"endpoints":{"base_commit":fixtures.A,"target_commit":fixtures.H}}}
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
    if "change_pass" in shape:
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
    pathlib.Path(args[args.index("--output-last-message")+1]).write_text(json.dumps({"action":"final","research":[],
        "draft":draft,"working_chain":"Inspected supplied source.","progress":[],"routing":[]}))
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
        os.environ.update(MEHSCAN_REVIEW_MODE="value", MEHSCAN_PROVIDER_CONFIG=str(self.config))

    def ready(self):
        directory, plan = self.prepare()
        record = adapter.finish(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(record["status"],"review_ready",record)
        return directory,plan,record

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
        import hashlib
        for entry in manifest["files"]:
            self.assertEqual(hashlib.sha256((directory / entry["path"]).read_bytes()).hexdigest(),entry["sha256"])
        with self.assertRaises(ValueError): adapter.run_model(directory / "plan.json",self.delivery.get,self.execute)

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
        directory,plan,record = self.ready()
        self.auth.unlink()
        result = adapter.run_model(directory / "plan.json",self.delivery.get,self.execute)
        self.assertEqual(result["status"],"incomplete",result)
        self.assertEqual(result["coordination"]["state"],"owned_incomplete")
        self.assertNotIn("completion",result)
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
            if "--format" in argv and argv[argv.index("--format")+1]=="sarif":
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
