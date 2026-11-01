"""Real native/controller acceptance; reviewer output is deterministic, not AI truth."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("mehscan_review_worker", ROOT / "scripts/review_worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class ArtifactCopy(unittest.TestCase):
    def test_late_usage_survives_multiple_recovery_attempts_and_keeps_deadline(self):
        with tempfile.TemporaryDirectory(prefix='mehscan-recovery-') as name:
            root=Path(name)
            first=root/'first/jobs/job.json';second=root/'second/jobs/job.json';third=root/'third/jobs/job.json'
            for path in (first,second,third):path.parent.mkdir(parents=True)
            binding={'runtime':'fixture'};turn={'conversation_id':'a'*64,'round':0}
            with patch.object(worker.time,'time',return_value=1000):
                job=worker.JobCheckpoint(first,binding,timeout=100)
                job.save(calls=1,queries=2,bytes=10,model_inflight=True,active_turn=turn)
                job.fail(TimeoutError('fixture interruption'))
            with patch.object(worker.time,'time',return_value=1010):
                pending=worker.JobCheckpoint(second,binding,first,timeout=100)
                self.assertEqual(pending.state['unknown_provider_calls'],1)
                self.assertEqual(pending.state['deadline_epoch'],1100)
            receipt={**turn,'provider':None,'elapsed_ms':4,'usage':{'input_tokens':50,'cached_input_tokens':10,'output_tokens':3}}
            (first.parent.parent/('provider-metrics-'+turn['conversation_id']+'.jsonl')).write_text(json.dumps(receipt)+'\n')
            with patch.object(worker.time,'time',return_value=1120):
                recovered=worker.JobCheckpoint(third,binding,second,timeout=100)
                self.assertLessEqual(recovered.deadline,worker.time.monotonic())
            self.assertEqual(recovered.state['unknown_provider_calls'],0)
            self.assertEqual([recovered.state[k] for k in ('calls','queries','bytes')],[1,2,10])
            self.assertEqual(worker.consolidate_metrics(third.parent.parent,second.parent.parent),[receipt])
            self.assertEqual(worker.consolidate_metrics(third.parent.parent,second.parent.parent),[receipt])

    def test_refinalization_clears_native_journal_counts_without_mutating_approved_siblings(self):
        response = {"results":[{"decision":"issue","investigation":{"journal_summary":{"queries":1},"decisive_artifacts":["source"]}},
            {"decision":"needs_review","checks":["Read the control."],"investigation":{"journal_summary":None}}]}
        draft = worker.finalization_draft(response)
        self.assertEqual(response["results"][0]["investigation"]["journal_summary"],{"queries":1})
        self.assertEqual([r["investigation"]["journal_summary"] for r in draft["results"]],[None,None])
        self.assertEqual(draft["results"][0]["investigation"]["decisive_artifacts"],["source"])

    def test_artifact_copy_preserves_bytes_without_requiring_metadata(self):
        with tempfile.TemporaryDirectory(prefix="mehscan-artifact-") as name:
            root = Path(name)
            source = root / "requests"
            source.mkdir()
            data = b'{"source_bound":"actual bytes"}\n'
            (source / "request.json").write_bytes(data)
            with patch("shutil.copystat", side_effect=PermissionError("metadata unsupported")):
                worker.copy_review_files(source, root / "copied")
            self.assertEqual((root / "copied/request.json").read_bytes(), data)
            run = root / "run"
            run.mkdir()
            (run / "manifest.json").write_bytes(data)
            (run / "input-binding.json").write_bytes(data)
            shutil.copytree(source, run / "requests")
            shutil.copytree(source, run / "responses")
            with patch("shutil.copystat", side_effect=PermissionError("metadata unsupported")):
                worker.copy_bundle_run(run, root / "copied-run")
            for relative in ("manifest.json", "input-binding.json", "requests/request.json", "responses/request.json"):
                self.assertEqual((root / "copied-run" / relative).read_bytes(), data)
            (source / "unexpected-directory").mkdir()
            with self.assertRaises(ValueError):
                worker.copy_review_files(source, root / "rejected")


class LookupFailures(unittest.TestCase):
    def test_missing_symbol_prefix_is_navigation_feedback_not_absence_proof(self):
        for tool in ("symbol", "definition", "references"):
            query = {"tool":tool,"arguments":{"path_prefix":"src/missing"}}
            missing = worker.CommandFailure(2,'error: cannot access query directory "src/missing": missing (os error 2)')
            result = worker.missing_source_result(query,missing)
            self.assertEqual(result["error"]["code"],"scope_not_found")
            self.assertIn("not evidence",result["error"]["message"])
            for diagnostic in ('error: cannot access query directory "src/missing": denied (os error 5)',
                               missing.stderr + '\nadditional error'):
                self.assertIsNone(worker.missing_source_result(query,worker.CommandFailure(2,diagnostic)))

    def test_symbol_and_definition_keep_the_requested_directory_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "src/policy").mkdir(parents=True)
            (root / "src/policy/guard.ts").write_text("export function guard() {}")
            for tool in ("symbol", "definition"):
                original = {"tool":tool, "review_id":"id", "arguments":{"name":"guard", "path":"src/policy"}}
                compiled = worker.research_arguments(original,root,["id"],root / "journals")
                self.assertNotIn("--path",compiled)
                self.assertEqual(compiled[compiled.index("--path-prefix")+1],"src/policy")
                self.assertEqual(original["arguments"]["path"],"src/policy")
                self.assertEqual(compiled.filter_normalization["original_arguments"],original["arguments"])
                canonical = {**original,"arguments":{"name":"guard","path_prefix":"src/policy"}}
                self.assertEqual(compiled,worker.research_arguments(canonical,root,["id"],root / "journals"))
                for arguments in ({"name":"guard","path":"src/policy/guard.ts","path_prefix":"src/policy"},
                                  {"name":"guard","path_prefix":"src/policy/guard.ts"}):
                    with self.assertRaises(worker.ResearchFilterError):
                        worker.research_arguments({**original,"arguments":arguments},root,["id"],root / "journals")
                with self.assertRaisesRegex(ValueError,"authorized source"):
                    worker.research_arguments({**original,"arguments":{"name":"guard","path_prefix":"../outside"}},
                                              root,["id"],root / "journals")
                missing = worker.research_arguments({**original,"arguments":{"name":"guard","path":"missing"}},
                                                    root,["id"],root / "journals")
                self.assertIsNone(missing.filter_normalization)
                self.assertIn("--path",missing)
            self.assertEqual(worker.research_cost([
                {"tool":"symbol"},{"tool":"definition"}]),3)
            self.assertFalse((root / "journals").exists())

    def test_batch_feedback_collects_window_directory_limit_and_total_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "module").mkdir()
            queries = [
                {"tool":"source","review_id":"id","arguments":{"path":"app.js","start_line":1,"end_line":500}},
                {"tool":"outline","review_id":"id","arguments":{"path":"module"}},
                {"tool":"references","review_id":"id","arguments":{"symbol":"guard","limit":101}}]
            original = json.dumps(queries)
            with self.assertRaises(worker.ResearchBatchError) as caught:
                worker.research_batch_arguments(queries,root,["id"],root / "journals",query_units_remaining=2)
            error = caught.exception
            self.assertEqual(error.error_count,4)
            self.assertEqual([e["query_index"] for e in error.errors],[0,1,2,None])
            self.assertIn("400 lines",str(error))
            self.assertEqual(error.errors[1]["lookup_feedback"]["code"],"file_filter_is_directory")
            self.assertFalse(error.errors[1]["lookup_feedback"]["native_query_executed"])
            self.assertIn("query units",error.errors[-1]["reason"])
            self.assertEqual(json.dumps(queries),original)
            self.assertFalse((root / "journals").exists())
            # A later authorization/path violation is not downgraded into repair.
            queries.append({"tool":"source","review_id":"id","arguments":{"path":"../secret","start_line":1,"end_line":1}})
            with self.assertRaisesRegex(ValueError,"authorized source") as fatal:
                worker.research_batch_arguments(queries,root,["id"],root / "journals")
            self.assertNotIsInstance(fatal.exception,worker.ResearchBatchError)

    def test_batch_feedback_is_bounded_and_valid_queries_keep_order_and_cost(self):
        query = {"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":401}}
        with self.assertRaises(worker.ResearchBatchError) as caught:
            worker.research_batch_arguments([query]*40,ROOT,[],ROOT)
        self.assertEqual(caught.exception.error_count,40)
        self.assertEqual(len(caught.exception.errors),32)
        valid = [{**query,"arguments":{**query["arguments"],"end_line":1}},
                 {"tool":"definition","review_id":None,"arguments":{"name":"guard"}}]
        commands = worker.research_batch_arguments(valid,ROOT,[],ROOT,query_units_remaining=3)
        self.assertEqual(commands,[worker.research_arguments(q,ROOT,[],ROOT) for q in valid])
        self.assertEqual(worker.research_cost(valid),3)

    def test_cwe_feedback_is_exact_and_does_not_repair_other_native_failures(self):
        message="error: invalid reviewer work: diagnosis CWEs must be at most five distinct CWE-N identifiers"
        self.assertIn("distinct CWE-N",worker.finalization_feedback(worker.CommandFailure(2,message),["id"]))
        for code,text in ((1,message),(2,message+"\nsource changed"),(2,"error: source changed"),
                          (2,"error: invalid reviewer work: diagnosis severity is invalid")):
            self.assertIsNone(worker.finalization_feedback(worker.CommandFailure(code,text),["id"]))

    def test_guidance_is_an_allowlisted_skill_read_not_a_source_command(self):
        import review_context as context
        guide = {"tool":"guidance", "review_id":"id", "arguments":{"name":"mass-assignment"}}
        self.assertEqual(worker.research_arguments(guide, ROOT, ["id"], ROOT), [])
        self.assertEqual(worker.research_cost([guide]), 1)
        result = context.load_guidance(ROOT / "skills/mehscan-security", "mass-assignment")
        self.assertEqual(result["authority"], "trusted_skill_guidance_not_application_evidence")
        self.assertIn("sensitive fields", result["text"])
        html = context.load_guidance(ROOT / "skills/mehscan-security", "html-output")
        self.assertIn("URLSearchParams", html["text"])
        self.assertNotIn("finalize and report", html["text"])
        self.assertNotIn("mehscan investigate source", html["text"])
        guide["arguments"]["name"] = "../../AGENTS.md"
        with self.assertRaisesRegex(ValueError, "unknown review guidance"):
            worker.research_arguments(guide, ROOT, ["id"], ROOT)

    def test_definition_body_is_only_read_for_an_unambiguous_bounded_native_range(self):
        item = {"location":{"path":"helper.go","start":{"line":5},"end":{"line":15}}}
        read_ranges = []
        def source(values):
            read_ranges.append(values)
            return {"operation":"get_source", "truncated":False, "results":{"text":"actual implementation"}}
        result = worker.definition_result({"results":[item],"truncated":False}, source)
        self.assertTrue(result["source_complete"])
        self.assertEqual(read_ranges, [{"path":"helper.go","start_line":5,"end_line":15}])
        for discovery, limit in [({"results":[item],"truncated":True},"symbol_lookup_incomplete"),
                ({"results":[item, {"location":{**item["location"],"path":"other.go"}}]},"ambiguous_declaration"),
                ({"results":[]},"declaration_not_found"),
                ({"results":[{"location":{**item["location"],"end":{"line":125}}}]},"declaration_exceeds_120_lines")]:
            self.assertEqual(worker.definition_result(discovery, source)["limit"], limit)
        self.assertEqual(len(read_ranges), 2)
        self.assertEqual(read_ranges[-1],{"path":"helper.go","start_line":5,"end_line":124})
        partial = worker.definition_result({"results":[{"location":{**item["location"],"end":{"line":200}}}]},source)
        self.assertFalse(partial["source_complete"])
        self.assertIsNotNone(partial["source"])
        self.assertEqual(worker.research_cost([{"tool":"definition"},{"tool":"source"}]), 3)

    def test_only_exact_current_source_not_found_is_recoverable(self):
        query = {"tool": "source", "arguments": {"path": "missing.ts"}}
        message = 'error: text file "missing.ts" was not found under the scan root\n'
        result = worker.missing_source_result(query, worker.CommandFailure(2, message))
        self.assertEqual(result["error"]["code"], "not_found")
        self.assertEqual(result["results"], [])
        for code, diagnostic in [(1, message), (2, 'permission denied'), (2, message + 'other failure'),
                                 (2, message.replace('missing.ts', 'another.ts'))]:
            with self.subTest(code=code, diagnostic=diagnostic):
                self.assertIsNone(worker.missing_source_result(query, worker.CommandFailure(code, diagnostic)))
        self.assertIsNone(worker.missing_source_result({**query, "tool": "base_source"}, worker.CommandFailure(2, message)))
        outside = {"tool":"source", "arguments":{"path":"app.ts","start_line":1201,"end_line":1300}}
        result = worker.missing_source_result(outside,worker.CommandFailure(2,"error: start line 1201 is outside app.ts (872 lines)"))
        self.assertEqual(result["error"]["line_count"],872)
        self.assertEqual(result["error"]["code"],"range_outside_file")
        self.assertIsNone(worker.missing_source_result(outside,worker.CommandFailure(2,
            "error: start line 1201 is outside app.ts (872 lines)\npermission denied")))

    def test_missing_navigation_scope_is_a_bounded_non_source_receipt(self):
        query={"tool":"references","arguments":{"symbol":"guard","path_prefix":"api/routes"}}
        message='error: cannot access query directory "api/routes": No such file or directory (os error 2)'
        result=worker.missing_source_result(query,worker.CommandFailure(2,message))
        self.assertEqual(result["operation"],"reference_lookup_error")
        self.assertEqual(result["error"]["code"],"scope_not_found")
        for diagnostic in (message.replace("api/routes","outside"),message.replace("error 2","error 5"),message+'\nother failure'):
            self.assertIsNone(worker.missing_source_result(query,worker.CommandFailure(2,diagnostic)))

    def test_missing_file_navigation_recovers_only_the_exact_native_diagnostic(self):
        message = 'error: scannable text file "api/controllers/index.ts" was not found under the scan root\n'
        for tool, operation in [("references","reference_lookup_error"), ("symbol","symbol_lookup_error"),
                                ("definition","symbol_lookup_error"), ("outline","outline_lookup_error")]:
            query = {"tool":tool, "arguments":{"path":"api/controllers/index.ts"}}
            with self.subTest(tool=tool):
                result = worker.missing_source_result(query, worker.CommandFailure(2, message))
                self.assertEqual(result["operation"], operation)
                self.assertEqual(result["error"]["code"], "not_found")
                self.assertEqual(result["results"], [])
                for code, diagnostic in [(1,message), (2,message.replace("index.ts","other.ts")),
                                         (2,message+'permission denied'), (2,'error: parser produced ERROR'),
                                         (2,'error: permission denied')]:
                    self.assertIsNone(worker.missing_source_result(query,worker.CommandFailure(code,diagnostic)))
        for tool in ("source", "base_source"):
            self.assertIsNone(worker.missing_source_result({"tool":tool,"arguments":{"path":"api/controllers/index.ts"}},
                                                          worker.CommandFailure(2,message)))


class Worker(unittest.TestCase):
    def test_on_demand_guides_flow_through_worker_without_becoming_source_proof(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' print(json.dumps({"research":[{"tool":"guidance","review_id":task["review_ids"][0],'
            '"purpose":"Load the relevant interpreter review contract","arguments":{"name":name}} '
            'for name in ["process-code","structured-query"]],"working_chain":"Check exact interpretation",'
            '"progress":[{"edge":"Deciding interpreter relationship","status":"open","cause":None,"artifacts":[]}]}))\n'
            'else:\n'
            ' facts=json.loads(Path(task["shared_facts"]).read_text())["facts"]\n'
            ' guides=[f for f in facts if f["result"].get("operation")=="review_guidance"]\n'
            ' assert {f["result"]["name"] for f in guides}=={"process-code","structured-query"}\n'
            ' assert not ({f["result_id"] for f in guides} & set(task["research"]["artifact_handles"].values()))\n'
            ' draft=json.loads(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n'
            ' print(json.dumps({"draft":draft,"working_chain":"Selected source evaluated.","progress":[]}))\n')
        result = self.invoke(extra=["--phase","native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        from review_trace import summarize
        trace = summarize(self.base / "worker", self.ids[0])
        self.assertEqual(trace["mechanical_assessment"], "admitted")
        self.assertEqual(trace["attention_counts"]["open_relationship_disappeared"], 1)
        checkpoint = next((self.base / "worker/jobs").glob("*.json"))
        self.assertIn("progress", json.loads(checkpoint.read_text()))
        queries = [r for r in trace["jobs"][0]["queries"] if r["query"]["tool"] == "guidance"]
        self.assertEqual(len(queries), 2)
        self.assertEqual(len({r["result_id"] for r in queries}), 2)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-worker-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.scanner = Path(os.environ.get("MEHSCAN_TEST_SCANNER", ROOT / "target/debug" / ("mehscan.exe" if os.name == "nt" else "mehscan")))
        if not self.scanner.is_file():
            self.fail("worker tests require a built native CLI")
        self.git("init", "--quiet")
        self.git("config", "user.name", "Worker fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / "app.js").write_text("const harmless = true;\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "base")
        self.old = self.git("rev-parse", "HEAD")
        (self.root / "app.js").write_text("function handle(request) { eval(request.query.code); }\n")
        for path, source in getattr(self, "extra_source_files", {}).items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        self.inventory = self.base / "inventory"
        self.store = self.base / "state"
        self.run = self.base / "run"
        self.native("investigate", "review-inventory", str(self.root), "--changed-from", self.old, "--diff-mode", "files",
                    "--repository-key", "evaluation:worker", "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--attempt-id", "first", "--expected-generation", "0", "--operation-key", "claim")
        self.claim = self.base / "private-claim.json"
        self.claim.write_text(json.dumps(claim))
        self.owner = claim["result"]["owner"]
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--generation", "1", "--owner", self.owner]
        draft = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"), "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive")
        self.ids = draft["selected_review_ids"]
        self.assertTrue(self.ids)
        plan = self.base / "plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--operation-key", "plan")
        self.native("investigate", "review-bundles", str(self.root), "--inventory", str(self.inventory), "--review-ids", ",".join(self.ids),
            "--output", str(self.run))
        self.package = self.base / "work.json"
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        self.reviewer = self.base / "reviewer.py"
        self.reviewer.write_text('''import json,sys
from pathlib import Path
task=json.load(sys.stdin)
package=json.loads(Path(task["work_package"]).read_text())["payload"]
if task["kind"]=="change_pass":
    print(json.dumps({"change_pass":[{"path":"app.js","status":"reviewed","summary":"Inspected the changed operation and its previous source.",
        "questions":[],"native_review_ids":package["review_ids"],"evidence":[{"side":"base","path":"app.js","start_line":1,"end_line":1},
        {"side":"current","path":"app.js","start_line":1,"end_line":1}]}]}))
else:
    print(json.dumps({"results":[{"review_id":review_id,"decision":"issue","confidence":"medium",
        "summary":"Synthetic operation issue for controller acceptance.","reason":"The current code passes request.query.code into eval.",
        "evidence":[{"path":"app.js","start_line":1,"end_line":1}],"checks":[],"blockers":[]} for review_id in task["review_ids"]]}))
''')
        self.command = self.base / "reviewer-command.json"
        self.command.write_text(json.dumps([sys.executable, str(self.reviewer)]))

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def native(self, *args):
        if args[:2] in (("state", "work"), ("state", "plan"), ("state", "record")) and "--skill-root" not in args:
            args = (*args, "--skill-root", str(ROOT / "skills/mehscan-security"))
        result = subprocess.run([str(self.scanner), *args], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def invoke(self, name="worker", extra=()):
        return subprocess.run([sys.executable, str(ROOT / "scripts/review_worker.py"), "--scanner", str(self.scanner),
            "--source-root", str(self.root), "--inventory", str(self.inventory), "--store", str(self.store), "--stream", "local-review",
            "--claim", str(self.claim), "--work-package", str(self.package), "--reviewer-command", str(self.command),
            "--reviewer-label", "deterministic/medium", "--run", str(self.run), "--output", str(self.base / name), *extra],
            capture_output=True, text=True, encoding="utf-8", timeout=60)

    def configure_tiered(self, run_calls=2, quality=False, research_rounds=0, audit_percent=100, final_qa=True):
        from argparse import Namespace
        primary = {"schema_version":"1", "provider":"codex-cli", "executable_version":"fixture-1",
                   "model":"gpt-6-luna", "reasoning_effort":"medium"}
        expert = {**primary, "model":"gpt-6-sol"}
        provider = self.base / "provider.json"
        provider.write_text(json.dumps(primary))
        limits = {"model_calls":run_calls if quality else 2, "queries":6 if research_rounds else 0, "bytes":262144, "timeout_seconds":300}
        policy = {"expert":expert, "case_limits":limits, "run_limits":{**limits, "model_calls":run_calls},
                  "max_reviews_per_job":5, "audit_percent":audit_percent, "audit_seed":"controller-test"}
        if quality:
            policy["quality"] = {"adjudicate_disagreements":True, "final_qa":final_qa}
        policy_path = self.base / "orchestration.json"
        policy_path.write_text(json.dumps(policy))
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(ROOT / "skills/mehscan-security"),
            "--provider-contract", str(provider), "--review-orchestration", str(policy_path), "--research-rounds", str(research_rounds))
        plan = self.base / "tiered-plan.json"
        plan.write_text(json.dumps(draft))
        parent = json.loads(self.package.read_text())["payload"]["plan_id"]
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", parent,
            "--provider-contract", str(provider), "--operation-key", "tiered-plan-" + str(run_calls))
        self.package.write_text(json.dumps(self.native("state", "work", *self.common, "--provider-contract", str(provider))))
        adapter = ROOT / "skills/mehscan-security/scripts/codex_reviewer.py"
        for profile, descriptor in (("routine", primary), ("expert", expert)):
            config = self.base / (profile + "-config.json")
            config.write_text(json.dumps({**{key:value for key,value in descriptor.items() if key != "provider"},
                "executable":sys.executable, "auth_file":str(self.base / "unused-auth.json"),
                "private_directory":str(self.base / (profile + "-private"))}))
            (self.base / (profile + "-command.json")).write_text(json.dumps([sys.executable, str(adapter), "--config", str(config)]))
        return Namespace(scanner=str(self.scanner), source_root=str(self.root), inventory=str(self.inventory),
            store=str(self.store), stream="local-review", claim=str(self.claim), work_package=str(self.package),
            reviewer_command=str(self.base / "routine-command.json"), reviewer_label="tiered-test", run=str(self.run),
            output=str(self.base / ("tiered-" + str(run_calls))), provider_contract=str(provider), artifact_root=None,
            phase="native", supersede=False, timeout=None, skill_root=str(ROOT / "skills/mehscan-security"),
            research_rounds=None, research_queries=None, research_bytes=None, workers=2, query_workers=2,
            expert_command=str(self.base / "expert-command.json"), expert_workers=1, expert_review_ids=None, resume_from=None)

    def tiered_provider(self, calls, conflict=False, reject_unverified=False):
        original = worker.execute
        def execute(command, cwd, env, timeout, payload=None):
            if len(command) == 4 and command[1].endswith("codex_reviewer.py"):
                task = json.loads(payload)
                packet = json.loads(Path(task["evidence_packet"]).read_text())
                calls.append((task["profile"], task["review_role"]))
                self.assertEqual(packet["job_binding"]["profile"], task["profile"])
                self.assertEqual(packet["job_binding"]["provider"]["model"],
                    "gpt-6-sol" if task["profile"] == "expert" else "gpt-6-luna")
                if task["review_role"] == "verification":
                    self.assertEqual(packet["work"]["parent_decisions"], {})
                    self.assertEqual(packet["work"]["change_pass"], [])
                    self.assertEqual(task["research"]["results"], [])
                    self.assertNotIn("draft", packet)
                decision = "not_issue" if conflict and task["profile"] == "expert" else "issue"
                return {"draft":{"results":[{"review_id":identity, "decision":decision, "confidence":"medium",
                    "summary":"Deterministic source assessment.", "reason":"The source evaluates the request operand.",
                    "checks":[], "blockers":[], "evidence":[{"path":"app.js", "start_line":1,"end_line":1}]}
                    for identity in task["review_ids"]]}, "progress":[], "working_chain":"", "routing":[]}
            if reject_unverified and command[1:3] == ["state", "record"]:
                path = Path(command[command.index("--review-execution") + 1])
                saved = path.read_bytes()
                receipt = json.loads(saved)
                receipt["cases"][0]["assessments"] = receipt["cases"][0]["assessments"][:1]
                path.write_text(json.dumps(receipt))
                try:
                    with self.assertRaises(worker.CommandFailure) as rejected:
                        original(command, cwd, env, timeout, payload)
                    self.assertIn("two independent", rejected.exception.stderr)
                finally:
                    path.write_bytes(saved)
                receipt = json.loads(saved)
                stage = path.parent / "assessments" / (receipt["cases"][0]["assessments"][0]["job_id"] + ".json")
                stage_bytes = stage.read_bytes()
                forged = json.loads(stage_bytes)
                forged["results"][0]["investigation"]["decisive_artifacts"][0]["excerpt"] = "invented source"
                stage.write_text(json.dumps(forged))
                receipt["cases"][0]["assessments"][0]["response_sha256"] = worker.digest_file(stage)
                path.write_text(json.dumps(receipt))
                try:
                    with self.assertRaises(worker.CommandFailure):
                        original(command, cwd, env, timeout, payload)
                finally:
                    path.write_bytes(saved)
                    stage.write_bytes(stage_bytes)
            return original(command, cwd, env, timeout, payload)
        return execute

    def quality_provider(self, calls, reopen=False, interrupt_qa=False):
        base = self.tiered_provider(calls, conflict=True)
        original, qa_turns, interrupted = worker.execute, [], []
        qa_id = worker.context.digest(["native_bundle", self.ids, "expert", "final_qa"])
        def execute(command, cwd, env, timeout, payload=None):
            if len(command) == 4 and command[1].endswith("codex_reviewer.py"):
                task = json.loads(payload)
                role = task["review_role"]
                if role in ("investigator", "verification"):
                    return base(command, cwd, env, timeout, payload)
                calls.append((task["profile"], role))
                packet = json.loads(Path(task["evidence_packet"]).read_text())
                self.assertIn(role, [s for row in packet["contract"]["sources"] for s in row["sections"]])
                if role == "final_qa" and interrupt_qa and not qa_turns:
                    qa_turns.append(True)
                    return {"research":[{"tool":"references", "review_id":task["review_ids"][0],
                        "arguments":{"symbol":"eval", "limit":10}}]}
                response = {"draft":{"results":[{"review_id":identity,
                    "decision":"needs_review" if role == "final_qa" and reopen else "issue", "confidence":"medium",
                    "summary":"Exact source question remains." if reopen and role == "final_qa" else "The request operand reaches evaluation.",
                    "reason":"The handler directly evaluates the request operand without a rejection branch.",
                    "checks":["Confirm whether this handler is reachable from the exposed application."] if reopen and role == "final_qa" else [],
                    "blockers":[], "evidence":[{"path":"app.js", "start_line":1,"end_line":1}]}
                    for identity in task["review_ids"]]}, "progress":[], "working_chain":"", "routing":[]}
                if role == "adjudication":
                    self.assertEqual(len(packet["stage_context"]["assessments"]), 2)
                    response["resolutions"] = [{"review_id":identity,
                        "disputed_claim":"Does a control reject the request operand before evaluation?",
                        "reason":"The complete handler evaluates request.query.code without a control branch."}
                        for identity in task["adjudicate_ids"]]
                else:
                    self.assertEqual(packet["stage_context"]["baseline"]["results"][0]["decision"], "issue")
                    self.assertIn("related_reviews", packet["stage_context"])
                return response
            result = original(command, cwd, env, timeout, payload)
            if interrupt_qa and command[1:3] == ["investigate", "review-bundle-finalize"] and not interrupted:
                target = Path(command[command.index("--output") + 1])
                if target.name == qa_id + ".json":
                    interrupted.append(True)
                    raise TimeoutError("QA draft completed, finalization response lost")
            return result
        return execute

    def test_stage_exhaustion_reuses_source_and_expert_resolution_is_terminal(self):
        args = self.configure_tiered(run_calls=6, quality=True, research_rounds=1)
        original, calls = worker.execute, []
        def provider(command, cwd, env, timeout, payload=None):
            if len(command) != 4 or not command[1].endswith("codex_reviewer.py"):
                return original(command, cwd, env, timeout, payload)
            task = json.loads(payload)
            role = task["review_role"]
            calls.append((task["profile"], role))
            if role == "investigator" and task["research"]["round"] == 0:
                return {"research":[{"tool":"definition", "review_id":self.ids[0],
                    "purpose":"Read the actual handler before deciding its input boundary.",
                    "arguments":{"name":"handle","path":"app.js","limit":10}}]}
            first = role == "investigator"
            facts = json.loads(Path(task["shared_facts"]).read_text())["facts"]
            self.assertTrue(facts[0]["result"]["source_complete"])
            self.assertIn("eval(request.query.code)", json.dumps(facts))
            if role == "verification":
                self.assertEqual(task["research"]["results"], [])
                self.assertNotIn("purpose", facts[0]["query"])
                packet = json.loads(Path(task["evidence_packet"]).read_text())
                self.assertNotIn("stage_context", packet)
                self.assertEqual(packet["work"]["parent_decisions"], {})
            response = {"draft":{"results":[{"review_id":identity,
                "decision":"needs_review" if first else "issue", "confidence":"medium",
                "summary":"The local source question remains." if first else "The request operand is evaluated.",
                "reason":"The handler evaluates request.query.code without a guard.",
                "checks":["Assess the request operand after the local stage limit."] if first else [],
                "blockers":[], "evidence":[{"path":"app.js","start_line":1,"end_line":1}]}
                for identity in self.ids]},"progress":[],"working_chain":"",
                "routing":[{"review_id":identity,"reason":"budget_exhausted"} for identity in self.ids] if first else []}
            if role == "adjudication":
                response["resolutions"] = [{"review_id":identity,
                    "disputed_claim":"Is the request operand passed to evaluation without a control?",
                    "reason":"The handler directly evaluates request.query.code without a guard."} for identity in self.ids]
            return response
        with patch.object(worker, "execute", side_effect=provider):
            result = worker.run(args)
        self.assertEqual(result["status"], "admitted", result)
        self.assertEqual(calls, [("routine","investigator"),("routine","investigator"),
            ("expert","verification"),("expert","final_qa")])
        directory = Path(args.output)
        budget = json.loads((directory / "budget.json").read_text())
        self.assertEqual(budget["totals"]["model_calls"], 4)
        self.assertEqual(budget["totals"]["queries"], 2)
        execution = json.loads((directory / "review-execution.json").read_text())
        self.assertTrue(all("blocker" not in c for c in execution["cases"]))
        investigator = next(json.loads(p.read_text()) for p in (directory / "jobs").glob("*.json")
                            if json.loads(p.read_text())["binding"]["role"] == "investigator")
        self.assertEqual(investigator["reported_routing"][0]["reason"], "budget_exhausted")
        self.assertEqual(investigator["routing"][0]["reason"], "stage_budget_exhausted")

    def test_shared_dependency_research_resumes_callers_and_restart_keeps_knowledge_and_spend(self):
        (self.root / "app.js").write_text(
            "function first(request) { eval(request.query.one); }\n"
            "function second(request) { eval(request.query.two); }\n")
        (self.root / "policy.js").write_text("export function allow(subject) { return subject.admin === true; }\n")
        self.inventory, self.store, self.run = [self.base / name for name in ("shared-inventory", "shared-state", "shared-run")]
        self.native("investigate", "review-inventory", str(self.root), "--repository-key", "evaluation:worker", "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--attempt-id", "shared", "--expected-generation", "0", "--operation-key", "claim")
        self.claim.write_text(json.dumps(claim))
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--generation", "1", "--owner", claim["result"]["owner"]]
        plan = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(ROOT / "skills/mehscan-security"))
        self.ids = plan["selected_review_ids"]
        self.assertEqual(len(self.ids),2)
        path = self.base / "shared-plan.json"
        path.write_text(json.dumps(plan))
        self.native("state", "plan", *self.common, "--input", str(path), "--operation-key", "plan")
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        self.native("investigate", "review-bundles", str(self.root), "--inventory", str(self.inventory),
            "--review-ids", ",".join(self.ids), "--max-reviews", "1", "--output", str(self.run))
        args = self.configure_tiered(run_calls=12, quality=True, research_rounds=1, audit_percent=0, final_qa=False)
        args.source_collector_profile = "routine"
        original, calls, interrupted = worker.execute, [], []
        first_caller, caller_lock, research_started = [], threading.Lock(), threading.Event()
        def provider(command, cwd, env, timeout, payload=None):
            if len(command) != 4 or not command[1].endswith("codex_reviewer.py"):
                return original(command,cwd,env,timeout,payload)
            task = json.loads(payload)
            packet = json.loads(Path(task["evidence_packet"]).read_text())
            role, resumed = task["review_role"], task.get("assessment_cycle") == "dependency_resume"
            provider_id=(packet['work']['runtime']['orchestration']['expert'] if task['profile']=='expert'
                         else packet['work']['runtime']['provider'])
            with Path(task['provider_metrics']).open('a',encoding='utf-8') as receipt:
                receipt.write(json.dumps({'conversation_id':task['conversation_id'],'round':task['research']['round'],
                    'provider':provider_id,'elapsed_ms':1,
                    'usage':{'input_tokens':100,'cached_input_tokens':0,'output_tokens':10}})+'\n')
            calls.append((role,resumed,task["review_ids"][0]))
            if role == "collection":
                research_started.set()
                self.assertEqual(packet["native_questions"],[])
                self.assertNotIn("sweep",packet)
                self.assertFalse(task["dependency_allowed"])
                source_id = packet["stage_context"]["dependency"]["artifacts"][0]
                handle = next(k for k,v in task["research"]["artifact_handles"].items() if v == source_id)
                self.assertEqual(task["profile"],"routine")
                return {"collection":{"summary":"Retrieved allow implementation source.",
                    "remaining":"Does not establish route exposure or invocation by these callers.",
                    "status":"collected","artifacts":[handle]}}
            if role == "investigator" and not resumed:
                self.assertTrue(task["dependency_allowed"])
                if task["research"]["round"] == 0:
                    with caller_lock:
                        if not first_caller:
                            first_caller.append(task["review_ids"][0])
                    if task["review_ids"][0] != first_caller[0]:
                        self.assertTrue(research_started.wait(60), "shared research never started")
                    return {"research":[{"tool":"source","review_id":task["review_ids"][0],
                        "arguments":{"path":"policy.js","start_line":1,"end_line":1}}]}
                fact = next(f for f in json.loads(Path(task["shared_facts"]).read_text())["facts"]
                            if f["query"]["tool"] == "source")
                handle = next(k for k,v in task["research"]["artifact_handles"].items() if v == fact["result_id"])
                joined = task["review_ids"][0] != first_caller[0]
                catalog = task["research"]["dependency_catalog"]
                if joined:
                    self.assertEqual(len(catalog),1)
                return {"dependency":{"question":"Can this second caller use the same implementation evidence?" if joined else "What does allow establish for its caller?",
                    "scope":"Caller " + task["review_ids"][0] + "; applicability remains unproven.","artifacts":[handle],
                    "reuse_id":catalog[0]["dependency_id"] if joined else None}}
            if resumed:
                self.assertEqual(task["research"]["queries_remaining"],0)
                self.assertEqual(task["research"]["rounds_remaining"],0)
                note = packet["stage_context"]["resolved_dependency"]
                self.assertIn("route exposure",note["remaining"])
                self.assertNotIn("summary",note)  # Collector prose cannot anchor the verdict.
                self.assertIn(task["review_ids"][0],note["consumer_request"]["scope"])
                self.assertEqual(task["research"]["evidence_agenda"]["caller_request"], note["consumer_request"])
                if not interrupted:
                    interrupted.append(True)
                    raise TimeoutError("interrupted resumed provider call")
            else:
                self.assertEqual(role,"verification")
                self.assertNotIn("stage_context",packet)  # Interpretation never enters blind verification.
            return {"draft":{"results":[{"review_id":q["review_id"],"decision":"issue","confidence":"medium",
                "summary":"Request data reaches evaluation in this handler.","reason":"The complete handler evaluates a request query operand without a guard.",
                "checks":[],"blockers":[],"evidence":[{"path":q["path"],"start_line":q["line"],"end_line":q["line"]}]}
                for q in packet["native_questions"]]},"progress":[],"working_chain":"","routing":[]}
        with patch.object(worker,"execute",side_effect=provider):
            result = worker.run(args)
        self.assertNotEqual(result["status"],"admitted")
        first = Path(args.output)
        book = json.loads((first / "research-knowledge.json").read_text())
        self.assertEqual(len(book["dependencies"]),1,result)
        self.assertEqual(len(next(iter(book["dependencies"].values()))["consumers"]),2)
        self.assertEqual(sum(role == "collection" for role,_,_ in calls),1)
        prior_calls = len(calls)
        args.resume_from, args.output = str(first), str(self.base / "shared-recovered")
        with patch.object(worker,"execute",side_effect=provider):
            result = worker.run(args)
        self.assertEqual(result["status"],"admitted",result)
        self.assertEqual(sum(role == "collection" for role,_,_ in calls),1)
        self.assertEqual(len(calls)-prior_calls,2)  # Only interrupted caller and its independent verification.
        budget = json.loads((Path(args.output) / "budget.json").read_text())
        self.assertEqual(budget["totals"]["model_calls"],len(calls))
        self.assertEqual(len(json.loads((Path(args.output) / "review-execution.json").read_text())["cases"]),2)

    def test_native_citation_feedback_repairs_once_without_an_expert_or_budget_reset(self):
        args = self.configure_tiered(run_calls=3,quality=True,research_rounds=2,audit_percent=0,final_qa=False)
        original, calls = worker.execute, []
        def provider(command,cwd,env,timeout,payload=None):
            if len(command) != 4 or not command[1].endswith("codex_reviewer.py"):
                return original(command,cwd,env,timeout,payload)
            task = json.loads(payload)
            calls.append(task["profile"])
            if len(calls) == 1:
                return {"research":[{"tool":"source","review_id":task["review_ids"][0],
                    "arguments":{"path":"app.js","start_line":1,"end_line":1}}]}
            if len(calls) == 3:
                self.assertIn("1 to 400",task["research"]["feedback"]["reason"])
                self.assertEqual(task["research"]["queries_remaining"],0)
            return {"draft":{"results":[{"review_id":identity,"decision":"needs_review","confidence":"medium",
                "summary":"The handler evaluates the query operand; exposure is unresolved.",
                "reason":"The local source does not establish deployment exposure.",
                "evidence":[{"path":"app.js","start_line":1,"end_line":401 if len(calls) == 2 else 1}],
                "checks":["Establish the deployed entrypoint for this handler."],"blockers":[]}
                for identity in task["review_ids"]]},"working_chain":"","progress":[],
                "routing":[{"review_id":identity,"reason":"external_required"} for identity in task["review_ids"]]}
        with patch.object(worker,"execute",side_effect=provider):
            result = worker.run(args)
        self.assertEqual(result["status"],"admitted",result)
        self.assertEqual(calls,["routine","routine","routine"])
        self.assertEqual(json.loads((Path(args.output) / "budget.json").read_text())["totals"]["model_calls"],3)

    def run_cwe_repair_case(self, *, interrupt=False, repeat_invalid=False):
        from argparse import Namespace
        plan=self.native("state","plan-template","--inventory",str(self.inventory),"--source-root",str(self.root),
            "--policy","comprehensive","--skill-root",str(ROOT/"skills/mehscan-security"),
            "--research-rounds","1","--research-queries","4","--research-bytes","262144","--timeout","60")
        plan_path=self.base/"cwe-plan.json";plan_path.write_text(json.dumps(plan))
        parent=json.loads(self.package.read_text())["payload"]["plan_id"]
        self.native("state","plan",*self.common,"--input",str(plan_path),"--expected-plan-id",parent,"--operation-key","cwe-plan")
        self.package.write_text(json.dumps(self.native("state","work",*self.common)))
        args=Namespace(scanner=str(self.scanner),source_root=str(self.root),inventory=str(self.inventory),
            store=str(self.store),stream="local-review",claim=str(self.claim),work_package=str(self.package),
            reviewer_command=str(self.command),reviewer_label="cwe-repair-test",run=str(self.run),
            output=str(self.base/"cwe-first"),provider_contract=None,artifact_root=None,phase="native",supersede=False,
            timeout=60,skill_root=str(ROOT/"skills/mehscan-security"),research_rounds=1,research_queries=4,
            research_bytes=262144,workers=1,query_workers=1,expert_command=None,expert_workers=1,
            expert_review_ids=None,resume_from=None,source_collector_profile=None)
        original, calls, interrupted = worker.execute, [], []
        def provider(command,cwd,env,timeout,payload=None):
            if command == [sys.executable,str(self.reviewer)]:
                task=json.loads(payload);calls.append(task)
                if len(calls)>1:
                    self.assertEqual(task["research"]["queries_remaining"],0)
                    self.assertEqual(task["research"]["rounds_remaining"],0)
                    self.assertIn("distinct CWE-N",task["research"]["feedback"]["reason"])
                    self.assertEqual(task["research"]["feedback"]["rejected_draft"]["results"][0]["diagnosis"]["cwes"],
                                     ["CWE- mass-assignment","CWE-94"])
                cwes=["CWE- mass-assignment","CWE-94"] if len(calls)==1 or repeat_invalid else ["CWE-94"]
                return {"draft":{"results":[{"review_id":rid,"decision":"issue","confidence":"medium",
                    "summary":"Request data reaches eval.","reason":"The supplied handler evaluates request.query.code.",
                    "checks":[],"blockers":[],"evidence":[{"path":"app.js","start_line":1,"end_line":1}],
                    "diagnosis":{"title":"Request data is evaluated","cwes":cwes,"severity":"high",
                                 "impact":"A caller can supply evaluated code.","remediation":"Remove evaluation of caller-supplied code."}}
                    for rid in task["review_ids"]]},"working_chain":"","progress":[],"routing":[]}
            if interrupt and not interrupted and command[1:3]==["investigate","review-bundle-finalize"]:
                interrupted.append(True)
                raise worker.CommandFailure(1,"injected interruption after saving the candidate")
            return original(command,cwd,env,timeout,payload)
        with patch.object(worker,"execute",side_effect=provider):result=worker.run(args)
        if interrupt:
            self.assertEqual(result["status"],"incomplete",result)
            self.assertEqual(len(calls),1)
            previous=Path(args.output)
            self.assertTrue(any("candidate_draft"in json.loads(p.read_text())for p in(previous/"jobs").glob("*.json")))
            args.resume_from,args.output=str(previous),str(self.base/"cwe-recovered")
            with patch.object(worker,"execute",side_effect=provider):result=worker.run(args)
        self.assertEqual(len(calls),2,result)
        self.assertEqual(sum(json.loads(p.read_text())["calls"]for p in(Path(args.output)/"jobs").glob("*.json")),2)
        return result,args

    def test_native_cwe_format_repairs_once_with_original_budget_and_real_validator(self):
        result,args=self.run_cwe_repair_case()
        self.assertEqual(result["status"],"admitted",result)
        jobs=[json.loads(p.read_text())for p in(Path(args.output)/"jobs").glob("*.json")]
        self.assertEqual(jobs[0]["draft"]["results"][0]["diagnosis"]["cwes"],["CWE-94"])

    def test_recovered_invalid_candidate_uses_only_its_remaining_repair_turn(self):
        result,_=self.run_cwe_repair_case(interrupt=True)
        self.assertEqual(result["status"],"admitted",result)

    def test_second_invalid_cwe_reply_stops_without_extra_calls_or_admission(self):
        result,_=self.run_cwe_repair_case(repeat_invalid=True)
        self.assertEqual(result["status"],"incomplete",result)

    def run_revalidation_case(self, reopening=False, interrupt=False):
        args = self.configure_tiered(run_calls=10, quality=True, research_rounds=1)
        original, calls, interrupted = worker.execute, [], []
        def provider(command, cwd, env, timeout, payload=None):
            if len(command) == 4 and command[1].endswith("codex_reviewer.py"):
                task = json.loads(payload)
                role, fresh = task["review_role"], task.get("assessment_cycle") == "revalidation"
                calls.append((task["profile"],role,fresh))
                if fresh:
                    self.assertEqual(task["research"]["rounds_remaining"], 0)
                    if role == "verification":
                        packet = json.loads(Path(task["evidence_packet"]).read_text())
                        self.assertNotIn("stage_context", packet)
                        self.assertEqual(packet["work"]["parent_decisions"], {})
                        facts = json.loads(Path(task["shared_facts"]).read_text())["facts"]
                        self.assertTrue(facts)
                        self.assertTrue(all("purpose" not in f["query"] for f in facts))
                if not fresh and (role == "adjudication" or reopening and role == "final_qa") and task["research"]["round"] == 0:
                    return {"research":[{"tool":"definition","review_id":self.ids[0],"purpose":"Read decisive implementation.",
                        "arguments":{"name":"handle","path":"app.js","limit":10}}]}
                decision = "issue" if fresh or role == "adjudication" or reopening and role != "final_qa" else "needs_review"
                draft = {"draft":{"results":[{"review_id":identity,"decision":decision,"confidence":"medium",
                    "summary":"The reaching request operand is evaluated." if fresh else "A source question remains.",
                    "reason":"The handler evaluates request.query.code.","checks":["Check the precise reaching condition."] if decision == "needs_review" else [],
                    "blockers":[],"evidence":[{"path":"app.js","start_line":1,"end_line":1}]} for identity in self.ids]},
                    "progress":[],"working_chain":"","routing":[{"review_id":identity,
                        "reason":"reasoning_gap" if reopening else "conflicting_evidence"}
                        for identity in self.ids] if decision == "needs_review" else []}
                if role == "adjudication":
                    draft["resolutions"] = [{"review_id":identity,"disputed_claim":"Does the request operand reach eval?",
                        "reason":"The handler evaluates request.query.code."} for identity in task["adjudicate_ids"]]
                if reopening and role == "final_qa" and not fresh:
                    # Same issue label, corrected claim: this must not quietly
                    # preserve the overbroad baseline prose as an approval.
                    for row in draft["draft"]["results"]:row.update(decision="issue",checks=[])
                    draft["qa_actions"] = [{"review_id":identity,"action":"repair","claim":"Verify the precise reaching condition."} for identity in self.ids]
                return draft
            if command[1:3] == ["state","record"]:
                path = Path(command[command.index("--review-execution")+1]); saved = path.read_bytes()
                for mutation in ("same_profile","missing_qa","wrong_reason"):
                    receipt = json.loads(saved); detail = receipt["cases"][0]["revalidation"]
                    if mutation == "same_profile":detail["assessments"][0]["profile"] = detail["assessments"][1]["profile"]
                    elif mutation == "missing_qa":detail.pop("quality_review")
                    else:detail["reason"] = "new_source_verdict" if reopening else "quality_reopening"
                    path.write_text(json.dumps(receipt))
                    try:
                        with self.assertRaises(worker.CommandFailure):original(command,cwd,env,timeout,payload)
                    finally:path.write_bytes(saved)
            result = original(command,cwd,env,timeout,payload)
            if interrupt and not interrupted and command[1:3] == ["investigate","review-bundle-finalize"]:
                expected = worker.context.digest(["native_bundle",self.ids,"expert","verification","revalidation"])
                if Path(command[command.index("--output")+1]).name == expected+".json":
                    interrupted.append(True)
                    raise TimeoutError("Fresh assessment finalized, response lost")
            return result
        with patch.object(worker,"execute",side_effect=provider):result = worker.run(args)
        if interrupt:
            self.assertEqual(result["status"],"incomplete",result)
            self.assertEqual(len(calls),6,result)
            previous = args.output
            args.resume_from,args.output = previous,str(self.base/"revalidated-resume")
            with patch.object(worker,"execute",side_effect=provider):result = worker.run(args)
        self.assertEqual(result["status"],"admitted",result)
        directory = Path(args.output)
        receipt = json.loads((directory/"review-execution.json").read_text())["cases"][0]
        self.assertEqual(receipt["revalidation"]["reason"], "quality_reopening" if reopening else "new_source_verdict")
        self.assertEqual([a["profile"] for a in receipt["revalidation"]["assessments"]],["routine","expert"])
        self.assertEqual(receipt["revalidation"]["quality_review"]["decision"],"issue")
        self.assertEqual(len(calls),7)
        self.assertEqual(json.loads((directory/"budget.json").read_text())["totals"]["model_calls"],7)
        self.assertEqual(result["completion"]["issue_review_ids"],self.ids)
        if reopening:self.assertEqual(receipt["quality_review"]["decision"],"needs_review")
        else:self.assertNotIn("quality_review",receipt)

    def test_revalidation_recovers_new_source_verdict_once_with_native_guards_and_restart(self):
        self.run_revalidation_case(interrupt=True)

    def test_revalidation_repairs_a_qa_reopening_without_erasing_the_prior_assessment(self):
        self.run_revalidation_case(reopening=True)

    def test_pending_only_quality_skips_qa_without_fabricating_an_approval(self):
        args = self.configure_tiered(run_calls=4, quality=True)
        original, calls = worker.execute, []
        def provider(command,cwd,env,timeout,payload=None):
            if len(command) == 4 and command[1].endswith("codex_reviewer.py"):
                task = json.loads(payload); calls.append(task["review_role"])
                return {"draft":{"results":[{"review_id":identity,"decision":"needs_review","confidence":"low",
                    "summary":"An external policy is unavailable.","reason":"The code does not establish the external authority.",
                    "checks":["Confirm the external authority."],"blockers":[],
                    "evidence":[{"path":"app.js","start_line":1,"end_line":1}]} for identity in self.ids]},
                    "progress":[],"working_chain":"","routing":[{"review_id":identity,"reason":"external_required"} for identity in self.ids]}
            return original(command,cwd,env,timeout,payload)
        with patch.object(worker,"execute",side_effect=provider):result = worker.run(args)
        self.assertEqual(result["status"],"admitted",result)
        self.assertEqual(calls,["investigator"])
        case = json.loads((Path(args.output)/"review-execution.json").read_text())["cases"][0]
        self.assertNotIn("quality_review",case)
        self.assertNotIn("revalidation",case)
        self.assertEqual(case["blocker"],"external_required")

    def test_source_adjudication_and_final_qa_admit_a_resolved_issue_with_native_guards(self):
        args = self.configure_tiered(run_calls=4, quality=True)
        calls = []
        provider = self.quality_provider(calls)
        original = worker.execute
        def guarded(command, cwd, env, timeout, payload=None):
            if command[1:3] == ["state", "record"]:
                path = Path(command[command.index("--review-execution") + 1])
                saved = path.read_bytes()
                for mutation, diagnostic in (("qa", "requires a final QA"), ("resolution", "not bound to its source"), ("role", "provider policy")):
                    receipt = json.loads(saved)
                    case = receipt["cases"][0]
                    if mutation == "qa":
                        case.pop("quality_review")
                    elif mutation == "resolution":
                        case["resolution"]["reason"] = "Invented explanation not present in the assessment."
                    else:
                        case["assessments"][2]["role"] = "verification"
                    path.write_text(json.dumps(receipt))
                    try:
                        with self.assertRaises(worker.CommandFailure) as rejected:
                            original(command, cwd, env, timeout, payload)
                        self.assertIn(diagnostic, rejected.exception.stderr)
                    finally:
                        path.write_bytes(saved)
            return provider(command, cwd, env, timeout, payload)
        with patch.object(worker, "execute", guarded):
            result = worker.run(args)
        self.assertEqual(result["status"], "admitted", result)
        self.assertEqual(calls, [("routine","investigator"), ("expert","verification"), ("expert","adjudication"), ("expert","final_qa")])
        self.assertEqual(result["completion"]["issue_review_ids"], self.ids)
        case = json.loads((Path(args.output) / "review-execution.json").read_text())["cases"][0]
        self.assertEqual([r["decision"] for r in case["assessments"]], ["issue", "not_issue", "issue"])
        self.assertEqual(case["quality_review"]["decision"], "issue")

    def test_final_qa_reopens_exact_ids_and_recovers_research_without_repeating_models(self):
        args = self.configure_tiered(run_calls=6, quality=True, research_rounds=1)
        calls = []
        provider = self.quality_provider(calls, reopen=True, interrupt_qa=True)
        with patch.object(worker, "execute", provider):
            first = worker.run(args)
        self.assertEqual(first["status"], "incomplete", first)
        self.assertEqual(len(calls), 5)
        original = Path(args.output)
        args.resume_from, args.output = str(original), str(self.base / "quality-resumed")
        with patch.object(worker, "execute", provider):
            result = worker.run(args)
        self.assertEqual(result["status"], "admitted", result)
        self.assertEqual(len(calls), 5)
        self.assertEqual(result["completion"]["pending_review_ids"], self.ids)
        summary = json.loads((Path(args.output) / "quality-summary.json").read_text())
        self.assertEqual(summary["reopened_review_ids"], self.ids)
        self.assertEqual(json.loads((Path(args.output) / "budget.json").read_text())["totals"]["model_calls"], 5)
        self.assertEqual((original / "decisions" / next((original / "decisions").iterdir()).name).read_bytes(), next((Path(args.output) / "decisions").iterdir()).read_bytes())

    def test_tiered_blind_reviews_preserve_conflicts_as_native_pending_work(self):
        args = self.configure_tiered()
        calls = []
        with patch.object(worker, "execute", side_effect=self.tiered_provider(calls, conflict=True)):
            record = worker.run(args)
        self.assertEqual(record["status"], "admitted", record)
        self.assertEqual(calls, [("routine", "investigator"), ("expert", "verification")])
        self.assertEqual(record["completion"]["pending_review_ids"], self.ids)
        receipt = json.loads((Path(args.output) / "review-execution.json").read_text())
        self.assertEqual([a["decision"] for a in receipt["cases"][0]["assessments"]], ["issue", "not_issue"])
        self.assertEqual(json.loads((Path(args.output) / "budget.json").read_text())["totals"]["model_calls"], 2)

    def test_tiered_budget_and_native_gate_block_unverified_issues_then_direct_expert_works(self):
        args = self.configure_tiered(run_calls=1)
        args.expert_review_ids = ",".join(self.ids)
        calls = []
        with patch.object(worker, "execute", side_effect=self.tiered_provider(calls)):
            record = worker.run(args)
        self.assertEqual(record["status"], "incomplete", record)
        self.assertEqual(calls, [("expert", "investigator")])
        self.assert_no_decisions()
        args = self.configure_tiered(run_calls=2)
        args.expert_review_ids = ",".join(self.ids)
        calls.clear()
        with patch.object(worker, "execute", side_effect=self.tiered_provider(calls, reject_unverified=True)):
            record = worker.run(args)
        self.assertEqual(record["status"], "admitted", record)
        self.assertEqual(calls, [("expert", "investigator"), ("routine", "verification")])
        self.assertEqual(record["completion"]["issue_review_ids"], self.ids)

    def test_full_repository_work_preserves_null_scope_and_native_admission(self):
        self.inventory = self.base / "full-inventory"
        self.store = self.base / "full-state"
        self.run = self.base / "full-run"
        self.native("investigate", "review-inventory", str(self.root), "--repository-key", "evaluation:worker",
                    "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review",
            "--inventory", str(self.inventory), "--source-root", str(self.root), "--attempt-id", "full",
            "--expected-generation", "0", "--operation-key", "claim")
        self.claim.write_text(json.dumps(claim))
        self.owner = claim["result"]["owner"]
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
                      "--source-root", str(self.root), "--generation", "1", "--owner", self.owner]
        plan = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"),
                          "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive")
        self.assertEqual(plan["change_pass"], [])
        self.ids = plan["selected_review_ids"]
        (self.base / "plan.json").write_text(json.dumps(plan))
        self.native("state", "plan", *self.common, "--input", str(self.base / "plan.json"), "--operation-key", "plan")
        self.native("investigate", "review-bundles", str(self.root), "--inventory", str(self.inventory),
                    "--review-ids", ",".join(self.ids), "--output", str(self.run))
        package = self.native("state", "work", *self.common)
        self.assertIsNone(package["payload"]["impact_scope"])
        self.package.write_text(json.dumps(package))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["status"], "admitted", record)
        self.assertTrue(record["completion"]["review_work_complete"])
        self.assertEqual(record["completion"]["security_resolution"], "not_established")
        self.assertEqual(json.loads((self.base / "worker/prepared-changes.json").read_text())["windows"], [])

    def test_parallel_bundles_share_queries_and_recover_only_unfinished_work(self):
        (self.root / "app.js").write_text("".join(
            "function handle" + str(index) + "(request) { eval(request.query.code); }\n" for index in range(4)))
        self.inventory, self.store, self.run = [self.base / name for name in ("parallel-inventory", "parallel-state", "parallel-run")]
        self.native("investigate", "review-inventory", str(self.root), "--repository-key", "evaluation:worker", "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--attempt-id", "parallel", "--expected-generation", "0", "--operation-key", "claim")
        self.claim.write_text(json.dumps(claim))
        self.owner = claim["result"]["owner"]
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--generation", "1", "--owner", self.owner]
        plan = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(ROOT / "skills/mehscan-security"))
        self.ids = plan["selected_review_ids"]
        self.assertEqual(len(self.ids), 4)
        (self.base / "parallel-plan.json").write_text(json.dumps(plan))
        self.native("state", "plan", *self.common, "--input", str(self.base / "parallel-plan.json"), "--operation-key", "plan")
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        self.native("investigate", "review-bundles", str(self.root), "--inventory", str(self.inventory),
            "--review-ids", ",".join(self.ids), "--max-reviews", "1", "--output", str(self.run))
        self.reviewer.write_text('''import json,sys,time
from pathlib import Path
task=json.load(sys.stdin)
base=Path(__file__).parent
events=base/'events'
events.mkdir(exist_ok=True)
ids=json.loads(Path(task['work_package']).read_text())['payload']['review_ids']
id=task['review_ids'][0]
round=task['research']['round']
event=events/(task['conversation_id']+'-'+str(round)+'.json')
started=time.time()
if not task['research']['results']:
    (events/(id+'.started')).touch()
    deadline=time.monotonic()+15
    while len(list(events.glob('*.started')))<2:
        if time.monotonic()>deadline: raise RuntimeError('review jobs did not overlap')
        time.sleep(0.02)
    result={'research':[{'tool':'references','review_id':id,'arguments':{'symbol':'eval','limit':20}}]}
else:
    assert task['research']['results']
    if id==ids[-1] and not (base/'allow-last').exists():
        event.write_text(json.dumps({'id':id,'start':started,'end':time.time(),'failed':True}))
        sys.exit(2)
    packet=json.loads(Path(task['evidence_packet']).read_text())
    result={'results':[{'review_id':q['review_id'],'decision':'issue','confidence':'medium',
        'summary':'Synthetic controller issue.','reason':'The selected function evaluates request data.',
        'evidence':[{'path':q['path'],'start_line':q['line'],'end_line':q['line']}],'checks':[],'blockers':[]}
        for q in packet['native_questions']]}
event.write_text(json.dumps({'id':id,'start':started,'end':time.time(),'failed':False}))
print(json.dumps(result))
''')
        result = self.invoke("parallel-first", ["--phase", "native", "--workers", "2", "--query-workers", "2"])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        first = self.base / "parallel-first"
        record = json.loads((first / "worker.json").read_text())
        self.assertEqual(sum(job["status"] == "finalized" for job in record["jobs"].values()), 3)
        self.assertEqual(record["research_executions"], 1)
        self.assertEqual(record["research_cache_hits"], 3)
        self.assert_no_decisions()
        self.assertFalse((first / "findings.json").exists())
        facts = json.loads((first / "source-facts.json").read_text())["facts"]
        self.assertEqual(len(facts), 1)
        origin = facts[0]["origin_review_id"]
        self.assertEqual(len(list((first / "journals").glob("*.jsonl"))), 1)
        self.assertEqual((first / "journals" / (origin + ".jsonl")).read_text().count('\n'), 1)
        events = [json.loads(path.read_text()) for path in (self.base / "events").glob("*.json")]
        boundaries = sorted([(event["start"], 1) for event in events] + [(event["end"], -1) for event in events])
        active, peak = 0, 0
        for _, change in boundaries:
            active += change
            peak = max(peak, active)
        self.assertEqual(peak, 2)
        before = {id: sum(event["id"] == id for event in events) for id in self.ids}

        # Repacking identical authorized IDs changes job identities. It must
        # not silently create fresh conversation budgets in a recovery chain.
        original_run = self.run
        self.run = self.base / "regrouped-run"
        self.native("investigate", "review-bundles", str(self.root), "--inventory", str(self.inventory),
            "--review-ids", ",".join(self.ids), "--max-reviews", "2", "--output", str(self.run))
        self.assertEqual(len(json.loads((self.run / "manifest.json").read_text())["bundles"]), 2)
        result = self.invoke("parallel-regrouped", ["--phase", "native", "--resume-from", str(first)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recovery requires", json.loads((self.base / "parallel-regrouped/worker.json").read_text())["detail"])
        self.assertFalse((first / "continued-to.json").exists())
        self.assertEqual(len(list((self.base / "events").glob("*.json"))), len(events))
        self.run = original_run

        # A delayed, exact receipt makes the failed test turn observable. This
        # is recovery of actual counters, not permission to assume a free call.
        failed=next(json.loads(p.read_text()) for p in (first/'jobs').glob('*.json') if json.loads(p.read_text())['status']=='incomplete')
        turn=failed['unobserved_turns'][0]
        (first/('provider-metrics-'+turn['conversation_id']+'.jsonl')).write_text(json.dumps({
            **turn,'provider':None,'usage':{'input_tokens':10,'cached_input_tokens':0,'output_tokens':2},'elapsed_ms':1})+'\n')
        partial=json.loads((first/'partial-results.json').read_text())
        self.assertEqual(len(partial['completed_review_ids']),3)
        self.assertEqual(partial['incomplete_review_ids'],[self.ids[-1]])
        (self.base / "allow-last").touch()
        result = self.invoke("parallel-recovered", ["--phase", "native", "--workers", "2", "--resume-from", str(first)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + (self.base / "parallel-recovered/worker.json").read_text())
        recovered = self.base / "parallel-recovered"
        record = json.loads((recovered / "worker.json").read_text())
        self.assertEqual(sum(job["recovered_draft"] for job in record["jobs"].values()), 3)
        self.assertTrue(record["completion"]["review_work_complete"])
        self.assertEqual(record["unknown_provider_calls"], 0)
        events = [json.loads(path.read_text()) for path in (self.base / "events").glob("*.json")]
        after = {id: sum(event["id"] == id for event in events) for id in self.ids}
        self.assertEqual({id: after[id]-before[id] for id in self.ids}, {id: 1 if id == self.ids[-1] else 0 for id in self.ids})
        self.assertEqual(len(json.loads((recovered / "source-facts.json").read_text())["facts"]), 1)
        self.assertEqual((recovered / "journals" / (origin + ".jsonl")).read_bytes(), (first / "journals" / (origin + ".jsonl")).read_bytes())

        # A newly admitted decision changes the work package. Recovery must not
        # replay old drafts into a new generation/parent set or call providers.
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        result = self.invoke("parallel-stale", ["--phase", "native", "--resume-from", str(first)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recovery requires", json.loads((self.base / "parallel-stale/worker.json").read_text())["detail"])
        self.assertEqual(len(list((self.base / "events").glob("*.json"))), len(events))

    def test_unknown_provider_failure_stops_without_a_fresh_paid_conversation(self):
        original = self.reviewer.read_text()
        self.reviewer.write_text(original.replace('package=json.loads', '''marker=Path(__file__).with_suffix('.failed')
if not marker.exists():
    marker.touch()
    sys.exit(2)
package=json.loads'''))
        result = self.invoke("retry-once", ["--phase", "native"])
        directory = self.base / "retry-once"
        record = json.loads((directory / "worker.json").read_text())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["review_mode"], "single_model")
        self.assertEqual(record["review_capacity"], 3)
        self.assertEqual(record["provider_retries"], 0)
        self.assertEqual(record["unknown_provider_calls"], 1)
        self.assertFalse(record["usage_complete"])
        self.assertEqual(record["status"], "incomplete")
        job = json.loads(next((directory / "jobs").glob('*.json')).read_text())
        self.assertEqual(job["calls"], 1)
        turns = [row for row in record["timings_ms"] if row["operation"] == "reviewer/native_bundle"]
        self.assertEqual([row["succeeded"] for row in turns], [False])
        contexts = [json.loads(path.read_text()) for path in directory.glob('context-*.json')]
        self.assertEqual(len(contexts), 1)
        self.assertTrue(all('tiered_routing' not in packet['contract']['sources'][0]['sections'] for packet in contexts))
        self.assertFalse((directory / "findings.json").exists())
        retry = self.invoke("unknown-recovery",["--phase","native","--resume-from",str(directory)])
        self.assertNotEqual(retry.returncode,0)
        recovered=json.loads((self.base/'unknown-recovery/worker.json').read_text())
        self.assertIn('usage is unknown',recovered['detail'])
        self.assertEqual(sum(json.loads(p.read_text())['calls'] for p in (self.base/'unknown-recovery/jobs').glob('*.json')),1)
        self.assert_no_decisions()

    def test_typed_proof_rejection_uses_one_bound_correction_and_counts_both_turns(self):
        original=self.reviewer.read_text()
        self.reviewer.write_text(original.replace('package=json.loads','''import hashlib
turn=task['research']['round']
row={'conversation_id':task['conversation_id'],'round':turn,'provider':None,
     'usage':{'input_tokens':10,'cached_input_tokens':0,'output_tokens':2},'elapsed_ms':1}
with Path(task['provider_metrics']).open('a',encoding='utf-8') as handle:
    handle.write(json.dumps(row)+'\\n')
Path(__file__).with_suffix('.turn-'+str(turn)+'.json').write_text(json.dumps(task))
if turn==0:
    diagnostic={'schema_version':'1','kind':'local_response_validation',
        'conversation_id':task['conversation_id'],'round':turn,
        'task_sha256':hashlib.sha256(json.dumps(task,sort_keys=True,ensure_ascii=False).encode()).hexdigest(),
        'error_paths':[['progress',0,'artifacts',0]],'repairable_proof_references':True,
        'artifact_handles':list(task['research']['artifact_handles']),
        'source_artifact_handles':task['research']['source_artifact_handles']}
    Path(task['provider_metrics']).with_name('reply-validation-'+task['conversation_id']+'-0.json').write_text(json.dumps(diagnostic))
    sys.exit(2)
assert turn==1 and task['research']['feedback']['kind']=='local_response_validation'
package=json.loads'''))
        result=self.invoke('proof-corrected',['--phase','native'])
        directory=self.base/'proof-corrected'
        record=json.loads((directory/'worker.json').read_text())
        self.assertEqual(result.returncode,0,result.stderr+json.dumps(record))
        self.assertEqual(record['reply_validation_corrections'],1)
        self.assertEqual(record['unknown_provider_calls'],0)
        self.assertEqual(record['provider_usage'][0]['usage']['input_tokens'],20)
        first=json.loads(self.reviewer.with_suffix('.turn-0.json').read_text())
        second=json.loads(self.reviewer.with_suffix('.turn-1.json').read_text())
        self.assertEqual(first['conversation_id'],second['conversation_id'])
        self.assertEqual(second['research']['queries_remaining'],first['research']['queries_remaining'])
        self.assertLessEqual(second['research']['seconds_remaining'],first['research']['seconds_remaining'])
        self.assertEqual(len(list(directory.glob('context-*.json'))),1)

    def test_completed_but_rejected_provider_reply_is_not_automatically_retried(self):
        self.reviewer.write_text('''import json,sys
from pathlib import Path
task=json.load(sys.stdin)
row={'conversation_id':task['conversation_id'],'round':task['research']['round'],
     'provider':None,'profile':'routine','role':'investigator','elapsed_ms':1,
     'usage':{'input_tokens':10,'cached_input_tokens':0,'output_tokens':2}}
with Path(task['provider_metrics']).open('a',encoding='utf-8') as handle:
    handle.write(json.dumps(row)+'\\n')
sys.exit(2)
''')
        result = self.invoke("rejected-provider", ["--phase", "native"])
        directory = self.base / "rejected-provider"
        record = json.loads((directory / "worker.json").read_text())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["provider_retries"], 0)
        self.assertEqual(record["unknown_provider_calls"], 0)
        self.assertTrue(record["usage_complete"])
        self.assertFalse(record["cache_write_usage_complete"])
        self.assertEqual(record["provider_usage"][0]["usage"]["input_tokens"], 10)
        self.assertEqual(len([t for t in record['timings_ms'] if t['operation']=='reviewer/native_bundle']), 1)
        self.assertFalse((directory / "findings.json").exists())

    def test_final_allowed_provider_failure_cannot_buy_a_retry_on_recovery(self):
        plan = self.native("state", "plan-template", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--skill-root", str(ROOT / "skills/mehscan-security"),
            "--policy", "comprehensive", "--research-rounds", "0")
        plan_path = self.base / "zero-research-plan.json"
        plan_path.write_text(json.dumps(plan))
        parent = json.loads(self.package.read_text())["payload"]["plan_id"]
        self.native("state", "plan", *self.common, "--input", str(plan_path),
            "--expected-plan-id", parent, "--operation-key", "zero-research-plan")
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        self.reviewer.write_text('''import sys
from pathlib import Path
with Path(__file__).with_suffix('.calls').open('a') as handle:
    handle.write('call\\n')
sys.exit(2)
''')
        first = self.base / "exhausted-provider"
        result = self.invoke(first.name, ["--phase", "native"])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((first / "worker.json").read_text())
        self.assertEqual(record["provider_retries"], 0)
        self.assertEqual(record["unknown_provider_calls"], 1)
        result = self.invoke("exhausted-recovery", ["--phase", "native", "--resume-from", str(first)])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.reviewer.with_suffix('.calls').read_text(), 'call\n')
        recovered = json.loads((self.base / "exhausted-recovery/worker.json").read_text())
        self.assertTrue('no remaining model turns' in recovered['detail'] or 'usage is unknown' in recovered['detail'])
        self.assertEqual(recovered["unknown_provider_calls"], 1)

    def test_change_pass_native_finalization_and_state_admission_share_one_bound_workflow(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["status"], "admitted", record)
        self.assertTrue(record["completion"]["review_work_complete"])
        self.assertEqual(record["completion"]["security_resolution"], "not_established")
        self.assertEqual(len(record["completion"]["issue_review_ids"]), len(self.ids))
        self.assertNotIn(self.owner, (self.base / "worker/worker.json").read_text())
        self.assertNotIn(self.owner, (self.base / "worker/work.json").read_text())

    def test_native_admission_and_pending_crashes_resume_without_more_model_calls(self):
        args = self.configure_tiered()
        calls = []
        provider = self.tiered_provider(calls, conflict=True)
        crash = ["record"]
        def interrupted(command, *rest, **kwargs):
            result = provider(command, *rest, **kwargs)
            if command[1:3] == ["state", crash[0]]:
                raise TimeoutError("lost native response after commit")
            return result
        first = Path(args.output)
        with patch.object(worker, "execute", interrupted):
            result = worker.run(args)
        self.assertEqual(result["status"], "incomplete", result)
        self.assertEqual(len(calls), 2, result)
        batch = json.loads((first / "native-writes/admission.json").read_text())
        self.assertEqual(batch["receipts"], [])  # The record really committed without a local receipt.
        self.assertGreater(len(batch["entries"]), 1)
        args.resume_from, args.output = str(first), str(self.base / "retry-pending")
        crash[0] = "pending"
        with patch.object(worker, "execute", interrupted):
            result = worker.run(args)
        self.assertEqual(result["status"], "incomplete", result)
        second = Path(args.output)
        admission_sequence = json.loads((second / "native-writes/admission.json").read_text())["receipts"][0]["sequence"]
        args.resume_from, args.output = str(second), str(self.base / "retry-complete")
        crash[0] = "never"
        with patch.object(worker, "execute", interrupted):
            result = worker.run(args)
        self.assertEqual(result["status"], "admitted", result)
        self.assertTrue(result["recovered_admission"])
        self.assertEqual(result["admission_sequence"], admission_sequence)
        self.assertEqual(len(calls), 2)
        self.assertEqual(json.loads((Path(args.output) / "budget.json").read_text())["totals"]["model_calls"], 2)
        self.assertEqual(len(result["completion"]["pending_review_ids"]), len(self.ids))
        receipts = json.loads((Path(args.output) / "native-writes/admission.json").read_text())["receipts"]
        self.assertTrue(all(receipt["replayed"] for receipt in receipts[:2]))
        canonical = self.native("report", "--run", str(Path(args.output) / "run"), "--source-root", str(self.root), "--reviewer", args.reviewer_label)
        self.assertEqual(canonical, json.loads((Path(args.output) / "findings.json").read_text()))
        for path in (Path(args.output) / "native-writes").glob("*.json"):
            self.assertNotIn(self.owner, path.read_text())
        # A source change cannot use a committed batch as an escape from freshness.
        last = args.output
        (self.root / "app.js").write_text("function handle(request) { return 'changed'; }\n")
        args.resume_from, args.output = last, str(self.base / "retry-stale")
        with patch.object(worker, "execute", interrupted):
            stale = worker.run(args)
        self.assertEqual(stale["status"], "incomplete", stale)
        self.assertEqual(len(calls), 2)
        (self.root / "app.js").write_text("function handle(request) { eval(request.query.code); }\n")
        self.native("state", "claim", "--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--attempt-id", "superseding", "--expected-generation", "1", "--retry", "true",
            "--operation-key", "superseding-claim")
        args.output = str(self.base / "retry-superseded")
        with patch.object(worker, "execute", interrupted):
            superseded = worker.run(args)
        self.assertEqual(superseded["status"], "incomplete", superseded)
        self.assertEqual(len(calls), 2)

    def test_change_plan_and_change_question_crashes_resume_before_native_review(self):
        from argparse import Namespace
        args = Namespace(scanner=str(self.scanner), source_root=str(self.root), inventory=str(self.inventory),
            store=str(self.store), stream="local-review", claim=str(self.claim), work_package=str(self.package),
            reviewer_command=str(self.command), reviewer_label="deterministic/medium", run=str(self.run),
            output=str(self.base / "plan-crash"), provider_contract=None, artifact_root=None,
            phase="all", supersede=False, timeout=None, skill_root=str(ROOT / "skills/mehscan-security"),
            research_rounds=None, research_queries=None, research_bytes=None, workers=2, query_workers=2,
            expert_command=None, expert_workers=1, expert_review_ids=None, resume_from=None)
        original, calls, crash = worker.execute, [], ["plan"]
        def interrupted(command, *rest, **kwargs):
            result = original(command, *rest, **kwargs)
            if command[0] == sys.executable and command[1] == str(self.reviewer):
                task = json.loads(kwargs.get("payload") or rest[-1])
                calls.append(task["kind"])
                if task["kind"] == "change_pass":
                    result["change_pass"][0].update(status="needs_review", questions=["Confirm the delegated policy applies here."])
            if command[1:3] == ["state", crash[0]]:
                raise TimeoutError("lost native response after commit")
            return result
        with patch.object(worker, "execute", interrupted):
            first = worker.run(args)
        self.assertEqual(first["status"], "incomplete", first)
        self.assertEqual(calls, ["change_pass"])
        args.resume_from, args.output = args.output, str(self.base / "change-question-crash")
        crash[0] = "pending"
        with patch.object(worker, "execute", interrupted):
            second = worker.run(args)
        self.assertEqual(second["status"], "incomplete", second)
        self.assertEqual(calls, ["change_pass"])
        args.resume_from, args.output = args.output, str(self.base / "change-resumed")
        crash[0] = "never"
        with patch.object(worker, "execute", interrupted):
            final = worker.run(args)
        self.assertEqual(final["status"], "admitted", final)
        self.assertEqual(calls.count("change_pass"), 1)
        self.assertEqual(calls.count("native_bundle"), 1)
        self.assertTrue(json.loads((Path(args.output) / "native-writes/plan.json").read_text())["receipts"][0]["replayed"])
        self.assertTrue(json.loads((Path(args.output) / "native-writes/change-questions.json").read_text())["receipts"][0]["replayed"])

    def test_recovery_cannot_reset_exhausted_turn_budget_or_fork_an_old_attempt(self):
        expected_calls = json.loads(self.package.read_text())["payload"]["runtime"]["limits"]["rounds"] + 1
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            'base=Path(__file__).parent\n'
            'with (base/"model-calls.jsonl").open("a") as log: log.write("call\\n")\n'
            'if (base/"release-budget").exists():\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n'
            'else:\n'
            ' print(json.dumps({"research":[{"tool":"references","review_id":task["review_ids"][0],'
            '"arguments":{"symbol":"eval","limit":20}}]}))\n')
        first = self.base / "budget-first"
        result = self.invoke(first.name, ["--phase", "native", "--workers", "1"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len((self.base / "model-calls.jsonl").read_text().splitlines()), expected_calls)
        (self.base / "release-budget").touch()
        result = self.invoke("budget-retry", ["--phase", "native", "--resume-from", str(first)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "budget-retry/worker.json").read_text())
        self.assertIn("no remaining model turns", record["detail"])
        result = self.invoke("budget-fork", ["--phase", "native", "--resume-from", str(first)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "budget-fork/worker.json").read_text())
        self.assertIn("already continued", record["detail"])
        self.assertEqual(len((self.base / "model-calls.jsonl").read_text().splitlines()), expected_calls)
        self.assert_no_decisions()

    def test_native_csharp_policy_source_reaches_reviewer_and_admits_both_verdicts(self):
        (self.root / "app.js").unlink()
        (self.root / "App.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"/>\n')
        (self.root / "Program.cs").write_text('builder.Services.AddControllers();\nbuilder.Services.AddAuthorization(o => o.FallbackPolicy = null);\napp.MapControllers();\n')
        (self.root / "Base.cs").write_text('using Microsoft.AspNetCore.Mvc;\n[IgnoreAntiforgeryToken]\npublic abstract class DemoBase : ControllerBase {}\n')
        fixture = ROOT / 'tests/fixtures/v11-review-effects/Actions.cs'
        (self.root / "Actions.cs").write_text(fixture.read_text().replace('ActionsController : ControllerBase', 'ActionsController : DemoBase'))
        self.inventory, self.store, self.run = [self.base / name for name in ('policy-inventory', 'policy-state', 'policy-run')]
        self.native('investigate', 'review-inventory', str(self.root), '--repository-key', 'evaluation:worker', '--output', str(self.inventory))
        claim = self.native('state', 'claim', '--store', str(self.store), '--stream', 'local-review', '--inventory', str(self.inventory),
            '--source-root', str(self.root), '--attempt-id', 'policy', '--expected-generation', '0', '--operation-key', 'claim')
        self.claim.write_text(json.dumps(claim))
        self.owner = claim['result']['owner']
        self.common = ['--store', str(self.store), '--stream', 'local-review', '--inventory', str(self.inventory),
            '--source-root', str(self.root), '--generation', '1', '--owner', self.owner]
        plan = self.native('state', 'plan-template', '--inventory', str(self.inventory), '--source-root', str(self.root),
            '--policy', 'comprehensive', '--skill-root', str(ROOT / 'skills/mehscan-security'))
        self.ids = plan['selected_review_ids']
        (self.base / 'plan.json').write_text(json.dumps(plan))
        self.native('state', 'plan', *self.common, '--input', str(self.base / 'plan.json'), '--operation-key', 'plan')
        self.native('investigate', 'review-bundles', str(self.root), '--inventory', str(self.inventory), '--review-ids', ','.join(self.ids), '--output', str(self.run))
        self.package.write_text(json.dumps(self.native('state', 'work', *self.common)))
        self.reviewer.write_text('''import json,sys
from pathlib import Path
task=json.load(sys.stdin)
packet=json.loads(Path(task['evidence_packet']).read_text())
windows=packet['primary']['windows']
assert any(w['path']=='Program.cs' and w['complete_file'] and 'FallbackPolicy' in w['text'] for w in windows)
assert any(w['path']=='Base.cs' and 'IgnoreAntiforgeryToken' in w['text'] for w in windows)
source=Path(task['source_root'],'Actions.cs').read_text().splitlines()
results=[]
for question in packet['native_questions']:
    symbol=question['symbol']
    mutation=symbol=='ResetPassword'
    start=next(n for n,text in enumerate(source) if ' '+symbol+'(' in text)
    line=next(n for n,text in enumerate(source[start:],start+1) if ('password = next;' if mutation else 'return Ok(new { success = true') in text)
    results.append({'review_id':question['review_id'],'decision':'issue' if mutation else 'not_issue','confidence':'high',
        'summary':'Deterministic fixture: actual write.' if mutation else 'Deterministic fixture: simulated operation.',
        'reason':'Fixture source writes the credential.' if mutation else 'Fixture source only returns a success response.',
        'evidence':[{'path':'Actions.cs','start_line':line,'end_line':line}],'checks':[],'blockers':[]})
print(json.dumps({'results':results}))
''')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / 'worker/worker.json').read_text())
        self.assertEqual(record['status'], 'admitted', record)
        self.assertTrue(record['completion']['review_work_complete'])
        decisions = json.loads((self.base / 'worker/findings.json').read_text())['decision_records']
        self.assertEqual({d['response']['decision'] for d in decisions}, {'issue', 'not_issue'})

    def test_invalid_reviewer_output_and_stale_package_do_not_admit_decisions(self):
        self.reviewer.write_text('print("not valid review JSON")\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        state = self.native("state", "history", "--store", str(self.store), "--stream", "local-review", "--repository-key", "evaluation:worker")
        self.assertEqual(state["decisions"], {})
        value = json.loads(self.package.read_text())
        value["payload"]["generation"] = 999
        self.package.write_text(json.dumps(value))
        result = self.invoke("altered-worker")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads((self.base / "altered-worker/worker.json").read_text())["status"], "incomplete")

    def test_timeout_and_cancelled_controller_never_invent_responses(self):
        script = self.base / "slow.py"
        script.write_text("import time; time.sleep(10)\n")
        with self.assertRaises(TimeoutError):
            worker.execute([sys.executable, str(script)], self.base, dict(os.environ), 0.1, "{}")
        worker._cancelled = True
        try:
            with self.assertRaises(InterruptedError):
                worker.execute([sys.executable, str(script)], self.base, dict(os.environ), 1)
        finally:
            worker._cancelled = False

    def test_pending_native_answers_are_registered_without_resolving_security(self):
        text = self.reviewer.read_text()
        text = text.replace('"decision":"issue"', '"decision":"needs_review"')
        text = text.replace('"checks":[]', '"checks":["Confirm the exact request authority."]')
        text = text.replace('"blockers":[]', '"blockers":["Confirm whether the named caller enforces its admin gate."]')
        self.reviewer.write_text(text)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["completion"]["pending_review_ids"], self.ids)
        self.assertTrue(list((self.base / "worker").glob("pending-*.json")))
        current = self.native("state", "work", *self.common)
        self.assertEqual(len(current["payload"]["pending_questions"]), 2 * len(self.ids))
        self.assertEqual(current["payload"]["evidence_updates"], [])

    def test_source_only_changed_effect_is_preserved_without_a_native_queue(self):
        (self.root / "app.js").write_text("function requireAdmin(user) { return true; }\n")
        self.inventory = self.base / "inventory-source-only"
        self.native("investigate", "review-inventory", str(self.root), "--changed-from", self.old, "--diff-mode", "files",
                    "--repository-key", "evaluation:worker", "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--attempt-id", "source-only", "--expected-generation", "1", "--operation-key", "claim-source-only")
        self.claim.write_text(json.dumps(claim))
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--generation", "2", "--owner", claim["result"]["owner"]]
        draft = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"), "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive")
        self.assertEqual(draft["selected_review_ids"], [])
        plan = self.base / "source-only-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--operation-key", "source-only-plan")
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        text = self.reviewer.read_text().replace('"status":"reviewed"', '"status":"needs_review"')
        self.reviewer.write_text(text.replace('"questions":[]', '"questions":["Which unchanged callers rely on the removed admin guard?"]'))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["completion"]["selected_review_count"], 0)
        self.assertEqual(len(record["completion"]["pending_changed_effects"]), 1)
        current = self.native("state", "work", *self.common)
        self.assertEqual(len(current["payload"]["pending_questions"]), 1)

    def research_reviewer(self, query_expression):
        original = self.reviewer.read_text()
        prefix, final = original.split('if task["kind"]=="change_pass":', 1)
        self.reviewer.write_text(prefix + '''if task["research"]["round"] == 0:
    print(json.dumps({"research": ''' + query_expression + '''}))
else:
    assert task["research"]["results"]
    assert "eval" in json.dumps(task["research"]["results"])
    if task["kind"]=="change_pass":''' + '\n'.join('\n    ' + line if line else '' for line in final.splitlines()))

    def assert_no_decisions(self):
        history = self.native("state", "history", "--store", str(self.store), "--stream", "local-review", "--repository-key", "evaluation:worker")
        self.assertEqual(history["decisions"], {})

    def test_model_directed_queries_are_source_bound_and_journaled_only_to_prompting_native_id(self):
        self.research_reviewer('[{"tool":"source", "review_id":task["review_ids"][0] if task["kind"] == "native_bundle" else None, '
                              '"arguments":{"path":"app.js","start_line":1,"end_line":1}}]')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = self.base / "worker"
        audit = [json.loads(line) for line in (directory / "research.jsonl").read_text().splitlines()]
        self.assertEqual([entry["kind"] for entry in audit], ["change_pass", "native_bundle"])
        self.assertIsNone(audit[0]["query"]["review_id"])
        self.assertEqual(audit[1]["query"]["review_id"], self.ids[0])
        self.assertFalse((directory / "journals" / (self.ids[0] + ".jsonl")).exists())
        self.assertEqual([entry["reused"] for entry in audit], [False, True])
        self.assertIsNone(audit[1]["origin_review_id"])
        self.assertNotIn(self.owner, (directory / "research.jsonl").read_text())
        report = json.loads((directory / "findings.json").read_text())
        trace = report["decision_records"][0]["response"]["investigation"]
        self.assertEqual(trace["journal_summary"]["query_count"], 0)

    def source_profile(self):
        import hashlib
        payload=json.loads(self.package.read_text())['payload']
        manifest=json.loads((self.run/'manifest.json').read_text())
        profile={'schema_version':'mehscanSourceProfile/v1',
            **{k:payload[k] for k in ('repository','inventory_input_fingerprint')},
            'targets':[{'review_ids':b['review_ids'],'windows':[{'path':'app.js','start_line':1,'end_line':1,
                'file_sha256':hashlib.sha256((self.root/'app.js').read_bytes()).hexdigest()}]} for b in manifest['bundles']]}
        path=self.base/'explicit-source.json';path.write_text(json.dumps(profile),encoding='utf-8')
        return path

    def test_profile_changed_during_provider_keeps_attempt_but_rejects_admission(self):
        profile=self.source_profile()
        normal=self.base/'normal.py';normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            'p=Path('+repr(str(profile))+')\np.write_text(p.read_text()+" ")\n'
            'print(subprocess.check_output([sys.executable,'+repr(str(normal))+'],input=json.dumps(task),text=True))\n')
        result=self.invoke(extra=['--phase','native','--source-profile',str(profile)])
        self.assertNotEqual(result.returncode,0)
        record=json.loads((self.base/'worker/worker.json').read_text())
        self.assertIn('source profile changed',record['detail'])
        job=json.loads(next((self.base/'worker/jobs').glob('*.json')).read_text())
        self.assertEqual(job['calls'],1)
        self.assert_no_decisions()

    def test_profile_change_cannot_resume_an_old_failed_attempt(self):
        profile=self.source_profile()
        self.reviewer.write_text('raise SystemExit(1)\n')
        first=self.invoke('profile-first',extra=['--phase','native','--source-profile',str(profile)])
        self.assertNotEqual(first.returncode,0)
        profile.write_text(profile.read_text()+' ')
        result=self.invoke('profile-resume',extra=['--phase','native','--source-profile',str(profile),
            '--resume-from',str(self.base/'profile-first')])
        self.assertNotEqual(result.returncode,0)
        record=json.loads((self.base/'profile-resume/worker.json').read_text())
        self.assertIn('reviewer configuration',record['detail'])
        self.assertFalse(list((self.base/'profile-resume').glob('context-*.json')))
        self.assert_no_decisions()

    def test_profile_for_foreign_claim_is_rejected_before_a_provider_attempt(self):
        profile=self.source_profile();value=json.loads(profile.read_text())
        value['targets'][0]['review_ids']=['foreign'];profile.write_text(json.dumps(value))
        result=self.invoke(extra=['--phase','native','--source-profile',str(profile)])
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(list((self.base/'worker/jobs').glob('*.json')))
        self.assert_no_decisions()

    def test_first_native_query_is_executed_and_journaled_without_fabricating_sibling_activity(self):
        self.research_reviewer('[{"tool":"references", "review_id":task["review_ids"][0], '
                              '"arguments":{"symbol":"eval","limit":20}}]')
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((self.base / "worker/findings.json").read_text())
        self.assertEqual(report["decision_records"][0]["response"]["investigation"]["journal_summary"]["query_count"], 1)

    def test_definition_lookup_returns_actual_source_and_reserves_both_query_units(self):
        self.research_reviewer('[{"tool":"definition", "review_id":task["review_ids"][0], '
                              '"arguments":{"name":"handle","path":"app.js","limit":10}}]')
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = self.base / "worker"
        row = json.loads((directory / "research.jsonl").read_text().splitlines()[0])
        self.assertTrue(row["result"]["source_complete"])
        self.assertIn("eval(request.query.code)", json.dumps(row["result"]["source"]))
        self.assertEqual(row["reserved_query_units"], 2)
        self.assertEqual(json.loads((directory / "worker.json").read_text())["research_queries"], 2)
        self.assertTrue((directory / "journals" / (self.ids[0] + ".jsonl")).exists())

    def test_query_batch_uses_one_post_fence_including_cache_hits(self):
        self.research_reviewer('[{"tool":"references","review_id":task["review_ids"][0],'
            '"arguments":{"symbol":"eval","limit":20}},'
            '{"tool":"references","review_id":task["review_ids"][0],'
            '"arguments":{"symbol":"handle","limit":20}},'
            '{"tool":"references","review_id":task["review_ids"][0],'
            '"arguments":{"symbol":"eval","limit":20}}]')
        result = self.invoke(extra=["--phase", "native", "--query-workers", "2"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = self.base / "worker"
        record = json.loads((directory / "worker.json").read_text())
        operations = [item["operation"] for item in record["timings_ms"]]
        turns = [index for index, operation in enumerate(operations) if operation == "reviewer/native_bundle"]
        self.assertEqual(len(turns), 2)
        # One provider post-check and one whole-batch post-check, independent
        # of query count. Both precede the next model's consumption of facts.
        self.assertEqual(operations[turns[0] + 1:turns[1]].count("state/work"), 2)
        self.assertEqual(record["research_executions"], 2)
        self.assertEqual(record["research_cache_hits"], 1)
        self.assertEqual(len(json.loads((directory / "source-facts.json").read_text())["facts"]), 2)
        self.assertEqual(len((directory / "research.jsonl").read_text().splitlines()), 3)

    def test_missing_source_returns_negative_lookup_then_discovers_and_reads_real_source(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text(), encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'round=task["research"]["round"]\nid=task["review_ids"][0]\n'
            'if round == 0:\n'
            ' print(json.dumps({"research":[{"tool":"source","review_id":id,"arguments":'
            '{"path":"missing.js","start_line":1,"end_line":10}}]}))\n'
            'elif round == 1:\n'
            ' result=task["research"]["results"][0]["result"]\n'
            ' assert result["error"]["code"] == "not_found" and result["results"] == []\n'
            ' print(json.dumps({"research":[{"tool":"paths","review_id":id,"arguments":{"name":"app.js"}}]}))\n'
            'elif round == 2:\n'
            ' assert "app.js" in json.dumps(task["research"]["results"])\n'
            ' print(json.dumps({"research":[{"tool":"source","review_id":id,"arguments":'
            '{"path":"app.js","start_line":1,"end_line":1}}]}))\n'
            'else:\n'
            ' assert "eval" in json.dumps(task["research"]["results"])\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n',
            encoding="utf-8")
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = self.base / "worker"
        audit = [json.loads(line) for line in (directory / "research.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([entry["query"]["tool"] for entry in audit], ["source", "paths", "source"])
        self.assertEqual(audit[0]["result"]["error"]["code"], "not_found")
        journal = [json.loads(line) for line in (directory / "journals" / (self.ids[0] + ".jsonl")).read_text(encoding="utf-8").splitlines()]
        self.assertEqual(journal[0]["status"], "error")
        self.assertEqual(journal[1]["status"], "ok")
        record = json.loads((directory / "worker.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "admitted")
        self.assertEqual(record["research_queries"], 3)  # The failed read is not free research.

    def test_progress_uses_short_handles_but_saved_proof_is_full_current_identity(self):
        original = self.reviewer.read_text()
        # Run the existing deterministic adapter as a trusted subprocess, then wrap
        # its final draft; no duplicated native verdict implementation here.
        normal = self.base / "normal.py"
        normal.write_text(original)
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'draft=json.loads(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n'
            'handle=next(iter(task["research"]["artifact_handles"]))\n'
            'print(json.dumps({"draft":draft,"working_chain":"Inspected supplied exact source.","progress":['
            '{"edge":"Exact source evidence","status":"inspected","cause":None,"artifacts":[handle]}]}))\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path in (self.base / "worker").glob("progress-*.json"):
            value = json.loads(path.read_text())
            self.assertTrue(value["edges"][0]["artifacts"][0].startswith("mehscan"))
            self.assertEqual(value["assertion"], "reviewer_hypothesis")

    def test_conditional_protocol_feedback_repairs_once_without_admitting_rejected_draft(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' print(json.dumps({"draft":{"change_pass":[]},"progress":[{"edge":"Available consumer",'
            '"status":"open","cause":None,"artifacts":[]}]}))\n'
            'else:\n'
            ' assert "not admitted" in task["research"]["feedback"]["instruction"]\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["protocol_corrections"], 2)  # One conditional repair per bound conversation.
        feedback = [json.loads(line) for line in (self.base / "worker/review-feedback.jsonl").read_text().splitlines()]
        self.assertEqual(len(feedback), 2)
        self.assertTrue(all(item["round"] == 0 for item in feedback))
        self.assertEqual(record["status"], "admitted")

    def test_invalid_source_window_gets_one_repair_and_never_executes_its_batch(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        for name, repair in (("repeated-window", False), ("repaired-window", True)):
            self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
                'if not ' + repr(repair) + ' or task["research"]["round"] == 0:\n'
                ' print(json.dumps({"research":[{"tool":"source","review_id":task["review_ids"][0],'
                '"arguments":{"path":"app.js","start_line":1,"end_line":1}},'
                '{"tool":"source","review_id":task["review_ids"][0],'
                '"arguments":{"path":"app.js","start_line":1,"end_line":401}}]}))\n'
                'else:\n'
                ' assert "400 lines" in task["research"]["feedback"]["reason"]\n'
                ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
            result = self.invoke(name, extra=["--phase", "native"])
            directory = self.base / name
            record = json.loads((directory / "worker.json").read_text())
            self.assertEqual(record["protocol_corrections"], 1)
            self.assertFalse((directory / "research.jsonl").exists())
            if repair:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(record["status"], "admitted")
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_decisions()

    def test_mixed_query_errors_share_one_charged_repair_without_partial_execution(self):
        (self.root / "module").mkdir()
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text(),encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' id=task["review_ids"][0]\n'
            ' print(json.dumps({"research":[{"tool":"source","review_id":id,"arguments":{"path":"app.js","start_line":1,"end_line":1}},'
            '{"tool":"source","review_id":id,"arguments":{"path":"app.js","start_line":1,"end_line":401}},'
            '{"tool":"outline","review_id":id,"arguments":{"path":"module"}}]}))\n'
            'else:\n'
            ' feedback=task["research"]["feedback"]\n'
            ' assert [e["query_index"] for e in feedback["query_errors"]] == [1,2]\n'
            ' assert feedback["query_errors"][1]["lookup_feedback"]["code"] == "file_filter_is_directory"\n'
            ' assert not task["research"]["results"]\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n',encoding="utf-8")
        result = self.invoke(extra=["--phase","native"])
        self.assertEqual(result.returncode,0,result.stdout + result.stderr)
        directory = self.base / "worker"
        record = json.loads((directory / "worker.json").read_text())
        self.assertEqual(record["protocol_corrections"],1)
        job = json.loads(next((directory / "jobs").glob("*.json")).read_text())
        self.assertEqual((job["calls"],job["queries"]),(2,0))
        self.assertFalse((directory / "research.jsonl").exists())

    def test_oversized_definition_batch_defers_whole_lookups_without_a_repair_call(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' q={"tool":"definition","review_id":task["review_ids"][0],"arguments":{"name":"handle"}}\n'
            ' print(json.dumps({"research":[q]*(task["research"]["queries_remaining"]//2+1)}))\n'
            'else:\n'
            ' feedback=task["research"]["feedback"]\n'
            ' assert feedback["reason"] == "research_query_budget_deferral"\n'
            ' assert len(feedback["deferred_queries"]) == 1\n'
            ' assert feedback["deferred_queries"][0]["executed"] is False\n'
            ' assert len(task["research"]["results"]) == 12\n'
            ' assert task["research"]["queries_remaining"] == 0\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = self.base / "worker"
        record = json.loads((directory / "worker.json").read_text())
        self.assertEqual(record.get("protocol_corrections", 0), 0)
        self.assertEqual(record["research_budget_deferrals"], 1)
        rows = [json.loads(line) for line in (directory / "research.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 12)
        self.assertTrue(all(row["reserved_query_units"] == 2 for row in rows))
        job = json.loads(next((directory / "jobs").glob("*.json")).read_text())
        self.assertEqual(job["calls"], 2)
        self.assertEqual(job["queries"], 24)
        self.assertEqual(record["status"], "admitted")

    def test_conflicting_path_filters_repair_before_any_batch_query_executes(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text(), encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'round=task["research"]["round"]\nid=task["review_ids"][0]\n'
            'if round == 0:\n'
            ' print(json.dumps({"research":[{"tool":"source","review_id":id,'
            '"arguments":{"path":"app.js","start_line":1,"end_line":1}},'
            '{"tool":"references","review_id":id,'
            '"arguments":{"symbol":"eval","path":"app.js","path_prefix":"src"}}]}))\n'
            'elif round == 1:\n'
            ' feedback=task["research"]["feedback"]\n'
            ' assert feedback["lookup_feedback"]["code"] == "conflicting_path_filters"\n'
            ' assert "not both" in feedback["reason"]\n'
            ' assert feedback["lookup_feedback"]["native_query_executed"] is False\n'
            ' assert not task["research"]["results"]\n'
            ' print(json.dumps({"research":[{"tool":"references","review_id":id,'
            '"arguments":{"symbol":"eval","path":"app.js"}}]}))\n'
            'else:\n'
            ' assert len(task["research"]["results"]) == 1\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n',
            encoding="utf-8")
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = self.base / "worker"
        audit = [json.loads(line) for line in (directory / "research.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["query"]["tool"] for row in audit], ["references"])
        self.assertEqual(audit[0]["query"]["arguments"]["path"], "app.js")
        record = json.loads((directory / "worker.json").read_text(encoding="utf-8"))
        self.assertEqual(record["protocol_corrections"], 1)
        self.assertEqual(record["research_queries"], 1)
        self.assertEqual(record["status"], "admitted")

    def test_directory_reference_variants_share_native_result_without_provider_repair(self):
        (self.root / "module").mkdir()
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text(),encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' queries=[{"tool":"references","review_id":task["review_ids"][0],"arguments":dict(symbol="eval",**args)}'
            'for args in ({"path":"module"},{"path_prefix":"module"},{"path":"module","path_prefix":"module/"})]\n'
            ' print(json.dumps({"research":queries}))\n'
            'else:\n'
            ' rows=task["research"]["results"]\n'
            ' assert len(rows)==3 and rows[0]["result"]==rows[1]["result"]==rows[2]["result"]\n'
            ' assert rows[0]["filter_normalization"]["effective_arguments"]["path_prefix"]=="module"\n'
            ' assert "filter_normalization" not in rows[1]\n'
            ' print(subprocess.check_output([sys.executable,'+repr(str(normal))+'],input=json.dumps(task),text=True))\n',encoding="utf-8")
        result = self.invoke(extra=["--phase","native"])
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        directory=self.base/"worker";record=json.loads((directory/"worker.json").read_text())
        rows=[json.loads(s)for s in(directory/"research.jsonl").read_text().splitlines()]
        self.assertEqual([r["query"]["arguments"]for r in rows],
                         [{"symbol":"eval","path":"module"},{"symbol":"eval","path_prefix":"module"},
                          {"symbol":"eval","path":"module","path_prefix":"module/"}])
        self.assertEqual(record["research_queries"],3)
        self.assertEqual(record["research_executions"],1)
        self.assertEqual(record["research_cache_hits"],2)
        self.assertEqual(record.get("protocol_corrections",0),0)
        self.assertEqual(record["status"],"admitted")

    def test_directory_definition_reads_only_its_unique_scoped_source_without_repair(self):
        self.extra_source_files = {"module/helper.js":"export function handle(value) { return value; }\n"}
        self.setUp()  # Bind the helper before inventory/source freshness is frozen.
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text(),encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' print(json.dumps({"research":[{"tool":"definition","review_id":task["review_ids"][0],'
            '"arguments":{"name":"handle","path":"module"}}]}))\n'
            'else:\n'
            ' assert not task["research"].get("feedback")\n'
            ' result=task["research"]["results"][0]["result"]\n'
            ' assert result["source_complete"]\n'
            ' body=result["source"]["results"]\n'
            ' assert body.get("path",body.get("location",{}).get("path")) == "module/helper.js"\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
        result = self.invoke(extra=["--phase","native"])
        self.assertEqual(result.returncode,0,result.stdout + result.stderr)
        directory = self.base / "worker"
        record = json.loads((directory / "worker.json").read_text())
        self.assertEqual(record.get("protocol_corrections",0),0)
        rows = [json.loads(line) for line in (directory / "research.jsonl").read_text().splitlines()]
        self.assertEqual(rows[0]["query"]["arguments"]["path"],"module")
        self.assertEqual(rows[0]["filter_normalization"]["effective_arguments"]["path_prefix"],"module")
        self.assertEqual(rows[0]["reserved_query_units"],2)

    def test_file_only_directory_feedback_is_bounded_and_preserves_batch_atomicity(self):
        (self.root / "module").mkdir()
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text(), encoding="utf-8")
        for name, repair in (("repeated-directory", False), ("corrected-directory", True)):
            self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
                'round=task["research"]["round"]\nid=task["review_ids"][0]\n'
                'if not ' + repr(repair) + ' or round == 0:\n'
                ' print(json.dumps({"research":[{"tool":"source","review_id":id,'
                '"arguments":{"path":"app.js","start_line":1,"end_line":1}},'
                '{"tool":"outline","review_id":id,'
                '"arguments":{"path":"module"}}]}))\n'
                'elif round == 1:\n'
                ' feedback=task["research"]["feedback"]["lookup_feedback"]\n'
                ' assert feedback["code"] == "file_filter_is_directory"\n'
                ' assert feedback["tool"] == "outline"\n'
                ' assert "path_prefix" not in feedback["allowed_arguments"]["optional"]\n'
                ' assert feedback["native_query_executed"] is False\n'
                ' assert "not source evidence" in feedback["authority"]\n'
                ' assert not task["research"]["results"]\n'
                ' print(json.dumps({"research":[{"tool":"definition","review_id":id,'
                '"arguments":{"name":"handle","path":"app.js"}}]}))\n'
                'else:\n'
                ' assert len(task["research"]["results"]) == 1\n'
                ' assert task["research"]["results"][0]["result"]["source_complete"]\n'
                ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n',
                encoding="utf-8")
            result = self.invoke(name, extra=["--phase", "native"])
            directory = self.base / name
            record = json.loads((directory / "worker.json").read_text())
            self.assertEqual(record["protocol_corrections"], 1)
            job = json.loads(next((directory / "jobs").glob("*.json")).read_text())
            self.assertEqual(job["calls"], 3 if repair else 2)
            self.assertEqual(job["queries"], 2 if repair else 0)
            if repair:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                rows = [json.loads(line) for line in (directory / "research.jsonl").read_text().splitlines()]
                self.assertEqual([row["query"]["tool"] for row in rows], ["definition"])
                self.assertEqual(record["status"], "admitted")
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((directory / "research.jsonl").exists())
                self.assert_no_decisions()

    def test_escaping_definition_path_cannot_enter_filter_feedback(self):
        self.research_reviewer('[{"tool":"definition","review_id":task["review_ids"][0],'
                              '"arguments":{"name":"handle","path":"../module"}}]')
        result = self.invoke(extra=["--phase", "native"])
        self.assertNotEqual(result.returncode, 0)
        directory = self.base / "worker"
        record = json.loads((directory / "worker.json").read_text())
        self.assertEqual(record.get("protocol_corrections", 0), 0)
        job = json.loads(next((directory / "jobs").glob("*.json")).read_text())
        self.assertEqual(job["calls"], 1)
        self.assertEqual(job["queries"], 0)
        self.assertFalse((directory / "research.jsonl").exists())
        self.assert_no_decisions()

    def test_reviewed_diagnosis_survives_brief_finalization_and_native_report(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text(), encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'draft=json.loads(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n'
            'for result in draft.get("results",[]):\n'
            ' if result["decision"] == "issue":\n'
            '  result["diagnosis"]={"title":"Request-supplied code is evaluated","cwes":["CWE-95"],'
            '"severity":"high","impact":"The request code executes with the service authority.",'
            '"remediation":"Remove evaluation of request-controlled expressions."}\n'
            'print(json.dumps(draft))\n', encoding="utf-8")
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((self.base / "worker/findings.json").read_text(encoding="utf-8"))
        self.assertTrue(report["findings"])
        finding = report["findings"][0]
        self.assertEqual(finding["title"], "Request-supplied code is evaluated")
        self.assertEqual(finding["cwes"], ["CWE-95"])
        self.assertEqual(finding["severity"], {"level":"high", "source":"reviewer_assessment"})
        self.assertEqual(finding["remediation"]["text"], "Remove evaluation of request-controlled expressions.")
        self.assertTrue(finding["provenance"]["candidate_cwes"])

    def test_evidence_handles_remain_stable_after_new_query_facts(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            'saved=Path("initial-handles.json")\n'
            'if task["kind"] == "change_pass":\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n'
            'elif task["research"]["round"] == 0:\n'
            ' assert any(key.startswith("evidence") for key in task["research"]["artifact_handles"])\n'
            ' saved.write_text(json.dumps(task["research"]["artifact_handles"]))\n'
            ' print(json.dumps({"research":[{"tool":"references","review_id":task["review_ids"][0],'
            '"arguments":{"symbol":"eval","limit":20}}]}))\n'
            'else:\n'
            ' initial=json.loads(saved.read_text())\n'
            ' assert all(task["research"]["artifact_handles"][key] == value for key,value in initial.items())\n'
            ' assert "fact1" in task["research"]["artifact_handles"]\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_progress_rejects_unknown_proof_and_open_final_local_edges(self):
        for index, edge in enumerate((
                {"edge":"Unknown source","status":"inspected","cause":None,"artifacts":["source999"]},
                {"edge":"Named available consumer","status":"open","cause":None,"artifacts":[]})):
            self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\nprint(json.dumps({"draft":{"change_pass":[]},'
                '"working_chain":"Incomplete", "progress":[' + repr(edge) + ']}))\n')
            result = self.invoke("bad-progress-" + str(index))
            self.assertNotEqual(result.returncode, 0)
            self.assert_no_decisions()

    def test_base_source_is_pinned_and_current_source_is_not_labeled_as_old_proof(self):
        self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' print(json.dumps({"research":[{"tool":"base_source","review_id":None,"purpose":"Read exact old primary",'
            '"arguments":{"path":"app.js","start_line":1,"end_line":1}}]}))\n'
            'else:\n'
            ' result=task["research"]["results"][0]["result"]\n'
            ' assert result["results"]["side"] == "base" and "harmless" in result["results"]["text"]\n'
            ' print("invalid final draft")\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        audit = json.loads((self.base / "worker/research.jsonl").read_text().splitlines()[0])
        self.assertEqual(audit["query"]["tool"], "base_source")
        self.assertIn("harmless", audit["result"]["results"]["text"])
        self.assertEqual(list((self.base / "worker/journals").iterdir()), [])
        self.assert_no_decisions()

    def test_discovery_queries_preserve_actual_native_results_and_explicit_limits(self):
        self.research_reviewer('[{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}},'
            '{"tool":"symbol","review_id":None,"arguments":{"name":"handle","path":"app.js","limit":1}},'
            '{"tool":"references","review_id":None,"arguments":{"symbol":"request","path":"app.js","limit":2}},'
            '{"tool":"paths","review_id":None,"arguments":{"name":"app","limit":1}}]')
        result = self.invoke(extra=["--phase", "change-pass"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + (self.base / "worker/worker.json").read_text())
        audit = [json.loads(line) for line in (self.base / "worker/research.jsonl").read_text().splitlines()]
        self.assertEqual([entry["query"]["tool"] for entry in audit], ["source", "symbol", "references", "paths"])
        self.assertTrue(all(entry["result"] is not None for entry in audit))
        self.assertTrue(all(entry["query"]["review_id"] is None for entry in audit))
        self.assertEqual(list((self.base / "worker/journals").iterdir()), [])
        self.assert_no_decisions()

    def test_invalid_batch_paths_and_unrelated_ids_execute_no_queries(self):
        for index, bad in enumerate((
                '{"tool":"source","review_id":None,"arguments":{"path":"../private-claim.json","start_line":1,"end_line":1}}',
                '{"tool":"source","review_id":"other-id","arguments":{"path":"app.js","start_line":1,"end_line":1}}',
                '{"tool":"shell","review_id":None,"arguments":{"name":"anything"}}')):
            self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\nprint(json.dumps({"research":['
                '{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}},' + bad + ']}))\n')
            name = "invalid-" + str(index)
            result = self.invoke(name)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse((self.base / name / "research.jsonl").exists())
            self.assert_no_decisions()

    def test_exhausted_round_and_output_budgets_preserve_incomplete_work_without_inventing_verdicts(self):
        self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\nprint(json.dumps({"research":['
            '{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}}]}))\n')
        for name, extra in (("round-budget", ["--research-rounds", "1"]), ("byte-budget", ["--research-bytes", "1"]),
                            ("query-budget", ["--research-queries", "0"])):
            current = self.native("state", "work", *self.common)
            draft = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"),
                "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive", *extra)
            plan = self.base / (name + "-plan.json")
            plan.write_text(json.dumps(draft))
            self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"], "--operation-key", name + "-plan")
            self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
            result = self.invoke(name)
            self.assertNotEqual(result.returncode, 0)
            record = json.loads((self.base / name / "worker.json").read_text())
            self.assertEqual(record["status"], "incomplete")
            self.assertFalse((self.base / name / "findings.json").exists())
            self.assert_no_decisions()

    def test_source_changed_during_reviewer_is_rejected_before_research_or_admission(self):
        self.reviewer.write_text('import json,sys\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            '(Path(task["source_root"])/"app.js").write_text("const changed = true;\\n")\n'
            'print(json.dumps({"research":[{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}}]}))\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "worker/research.jsonl").exists())
        self.assert_no_decisions()

    def test_plan_and_owner_changes_during_reviewer_fence_research_and_admission(self):
        for mode in ("plan", "owner"):
            with self.subTest(mode=mode):
                current = self.native("state", "work", *self.common)
                self.package.write_text(json.dumps(current))
                if mode == "plan":
                    draft = self.native("state", "plan-template", "--inventory", str(self.inventory),
                        "--source-root", str(self.root), "--policy", "comprehensive",
                        "--skill-root", str(ROOT / "skills/mehscan-security"), "--research-rounds", "2")
                    path = self.base / "new-plan.json"
                    path.write_text(json.dumps(draft))
                    command = [str(self.scanner), "state", "plan", *self.common,
                        "--input", str(path), "--expected-plan-id", current["payload"]["plan_id"],
                        "--skill-root", str(ROOT / "skills/mehscan-security"), "--operation-key", "during-model-plan"]
                else:
                    command = [str(self.scanner), "state", "claim", "--store", str(self.store),
                        "--stream", "local-review", "--inventory", str(self.inventory), "--source-root", str(self.root),
                        "--attempt-id", "new-owner", "--expected-generation", "1", "--retry", "true",
                        "--operation-key", "during-model-owner"]
                marker = self.base / (mode + "-mutation-completed")
                query = {"research":[{"tool":"source", "review_id":None,
                    "arguments":{"path":"app.js", "start_line":1, "end_line":1}}]}
                self.reviewer.write_text("import json,subprocess\nfrom pathlib import Path\n"
                    + "subprocess.run(" + repr(command) + ",check=True,stdout=subprocess.DEVNULL)\n"
                    + "Path(" + repr(str(marker)) + ").write_text('changed')\n"
                    + "print(json.dumps(" + repr(query) + "))\n")
                result = self.invoke(mode + "-drift")
                self.assertTrue(marker.exists(), result.stderr)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.base / (mode + "-drift") / "research.jsonl").exists())
                self.assert_no_decisions()

    def test_source_changed_during_query_is_rejected_before_receipt_or_admission(self):
        from argparse import Namespace
        self.research_reviewer('[{"tool":"references","review_id":task["review_ids"][0],'
                              '"arguments":{"symbol":"eval","limit":20}},'
                              '{"tool":"references","review_id":task["review_ids"][0],'
                              '"arguments":{"symbol":"handle","limit":20}}]')
        original = worker.execute
        queried = []
        def changing_query(command, *args, **kwargs):
            result = original(command, *args, **kwargs)
            if command[1:3] == ["investigate", "references"]:
                queried.append(True)
                (self.root / "app.js").write_text("const changed = true;\n")
            return result
        args = Namespace(scanner=str(self.scanner), source_root=str(self.root), inventory=str(self.inventory),
            store=str(self.store), stream="local-review", claim=str(self.claim), work_package=str(self.package),
            reviewer_command=str(self.command), reviewer_label="deterministic/medium", run=str(self.run),
            output=str(self.base / "query-drift"), provider_contract=None, artifact_root=None,
            phase="native", supersede=False, timeout=None, skill_root=str(ROOT / "skills/mehscan-security"),
            research_rounds=None, research_queries=None, research_bytes=None)
        with patch.object(worker, "execute", side_effect=changing_query):
            record = worker.run(args)
        self.assertTrue(queried)
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(record["step"], "native/state/work")
        self.assertFalse((self.base / "query-drift/research.jsonl").exists())
        facts_path = self.base / "query-drift/source-facts.json"
        self.assertFalse(facts_path.exists() and json.loads(facts_path.read_text())["facts"])
        self.assert_no_decisions()

    def test_native_runtime_matches_python_package_and_rejects_worker_override(self):
        package = json.loads(self.package.read_text())
        runtime = package["payload"]["runtime"]
        self.assertEqual(runtime["skill_bundle_id"], worker.context.skill_bundle_id(ROOT / "skills/mehscan-security"))
        result = self.invoke(extra=["--research-rounds", "1"])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertIn("override differs", record["detail"])
        self.assertFalse(list((self.base / "worker").glob("context-*.json")))
        self.assert_no_decisions()

    def test_legacy_manual_plan_remains_cli_usable_but_cannot_enter_ai_worker(self):
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--policy", "comprehensive")
        self.assertNotIn("runtime", draft)
        plan = self.base / "manual-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan),
            "--expected-plan-id", current["payload"]["plan_id"], "--operation-key", "manual-plan")
        package = self.native("state", "work", *self.common)
        self.assertNotIn("runtime", package["payload"])
        self.package.write_text(json.dumps(package))
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertIn("requires a native runtime-bound plan", record["detail"])
        self.assertFalse(list((self.base / "worker").glob("context-*.json")))
        self.assert_no_decisions()

    def test_changed_trusted_skill_cannot_run_a_bound_review(self):
        skill = self.base / "skill"
        shutil.copytree(ROOT / "skills/mehscan-security", skill)
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--skill-root", str(skill), "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--policy", "comprehensive")
        plan = self.base / "skill-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"], "--operation-key", "skill-plan", "--skill-root", str(skill))
        self.package.write_text(json.dumps(self.native("state", "work", *self.common, "--skill-root", str(skill))))
        with (skill / "references/runtime-review.md").open("a", encoding="utf-8") as stream:
            stream.write("\nChanged trusted policy.\n")
        result = self.invoke(extra=["--skill-root", str(skill)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["step"], "native/state/work")
        self.assertIn("review command failed", record["detail"])
        self.assertFalse(list((self.base / "worker").glob("context-*.json")))
        self.assert_no_decisions()

    def test_directory_filters_normalize_only_unambiguous_reference_scope(self):
        directory = self.root / "module"
        directory.mkdir()
        for arguments in ({"symbol":"eval","path_prefix":"app.js"},
                          {"symbol":"eval","path":"module","path_prefix":"missing"},
                          {"symbol":"eval","path":"missing","path_prefix":"missing"}):
            with self.assertRaises(ValueError):
                worker.research_arguments({"tool":"references","review_id":None,"arguments":arguments}, self.root, [], self.base)
        compiled = worker.research_arguments({"tool":"references","review_id":None,
            "arguments":{"symbol":"eval","path_prefix":"module"}}, self.root, [], self.base)
        self.assertIn("--path-prefix", compiled)
        trailing = worker.research_arguments({"tool":"references","review_id":None,
            "arguments":{"symbol":"eval","path_prefix":"module/"}}, self.root, [], self.base)
        self.assertEqual(trailing,compiled)
        for arguments in ({"symbol":"eval","path":"module"},
                          {"symbol":"eval","path":"module","path_prefix":"module/"}):
            normalized = worker.research_arguments({"tool":"references","review_id":None,"arguments":arguments},self.root,[],self.base)
            self.assertEqual(normalized,compiled)
            self.assertEqual(normalized.filter_normalization["original_arguments"],arguments)
            self.assertEqual(normalized.filter_normalization["effective_arguments"],
                             {"symbol":"eval","path_prefix":"module","limit":20})
        unknown=worker.research_arguments({"tool":"references","review_id":None,
            "arguments":{"symbol":"eval","path":"missing"}},self.root,[],self.base)
        self.assertIn("--path",unknown)
        self.assertIsNone(unknown.filter_normalization)
        for path in ("/module/", "module/../../", "module//nested/"):
            with self.assertRaises(ValueError):
                worker.research_arguments({"tool":"references","review_id":None,
                    "arguments":{"symbol":"eval","path_prefix":path}},self.root,[],self.base)

    def test_research_rejects_symlink_escape_and_boolean_ranges(self):
        for arguments in ({"path":"app.js","start_line":True,"end_line":1},
                          {"path":"C:/outside.js","start_line":1,"end_line":1},
                          {"path":".git/config","start_line":1,"end_line":1}):
            with self.assertRaises(ValueError):
                worker.research_arguments({"tool":"source","review_id":None,"arguments":arguments}, self.root, [], self.base)
        link = self.root / "external.js"
        try:
            link.symlink_to(self.claim)
        except OSError:
            return  # Windows runners without symlink privileges still cover traversal above.
        with self.assertRaises(ValueError):
            worker.research_arguments({"tool":"source","review_id":None,"arguments":{
                "path":"external.js","start_line":1,"end_line":1}}, self.root, [], self.base)

    def test_bound_provider_rejects_unprotected_argv_and_different_actual_model(self):
        provider = {"schema_version":"1","provider":"codex-cli",
            "executable_version":"0.162.0-alpha.17.2",
            "model":"gpt-6-luna","reasoning_effort":"medium"}
        descriptor = self.base / "provider.json"
        descriptor.write_text(json.dumps(provider))
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(ROOT / "skills/mehscan-security"), "--provider-contract", str(descriptor))
        plan = self.base / "provider-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"],
            "--operation-key", "provider-plan", "--provider-contract", str(descriptor))
        self.package.write_text(json.dumps(self.native("state", "work", *self.common, "--provider-contract", str(descriptor))))
        result = self.invoke("unsafe-provider", extra=["--provider-contract", str(descriptor)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "unsafe-provider/worker.json").read_text())
        self.assertIn("requires the bundled BYOK adapter", record["detail"])
        config = self.base / "provider-config.json"
        config.write_text(json.dumps({**provider, "model":"different-model"}))
        self.command.write_text(json.dumps([sys.executable,str(ROOT / "skills/mehscan-security/scripts/codex_reviewer.py"),"--config",str(config)]))
        result = self.invoke("wrong-model", extra=["--provider-contract", str(descriptor)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "wrong-model/worker.json").read_text())
        self.assertIn("actual provider configuration differs", record["detail"])
        self.assertFalse(list((self.base / "wrong-model").glob("context-*.json")))
        self.assert_no_decisions()

    @unittest.skipUnless(os.name == "posix", "CLI fixture uses a POSIX executable")
    def test_bound_byok_adapter_runs_change_pass_and_native_admission(self):
        executable = self.base / "codex-fixture"
        executable.write_text("#!" + sys.executable + "\n" + r'''import json, pathlib, sys
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
    prompt = sys.stdin.read()
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
        draft = {"results":[{"review_id":i,"decision":"issue","confidence":"medium",
            "summary":"Synthetic operation issue for BYOK integration acceptance.",
            "reason":"The current code passes request.query.code into eval.",
            "evidence":[{"path":"app.js","start_line":1,"end_line":1}],"checks":[],"blockers":[],"diagnosis":None,"source_leads":[]} for i in ids]}
    pathlib.Path(args[args.index("--output-last-message")+1]).write_text(json.dumps({"action":"final","research":[],
        "draft":draft,"working_chain":"Inspected supplied source.","progress":[],"routing":[]}))
    print(json.dumps({"type":"thread.started","thread_id":"12345678-1234-1234-1234-123456789abc"}))
    print(json.dumps({"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}}))
''')
        executable.chmod(0o700)
        auth = self.base / "provider-auth.json"
        auth.write_text('{"fixture":"not-a-real-key"}')
        config = {"schema_version":"1","executable":str(executable),"executable_version":"fixture-1",
            "model":"gpt-6-luna","reasoning_effort":"medium","auth_file":str(auth),
            "private_directory":str(self.base / "provider-private")}
        descriptor = self.base / "provider.json"
        provider = {"schema_version":"1","provider":"codex-cli",
            **{key:config[key] for key in ("executable_version","model","reasoning_effort")}}
        descriptor.write_text(json.dumps(provider))
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(ROOT / "skills/mehscan-security"), "--provider-contract", str(descriptor))
        plan = self.base / "provider-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"],
            "--operation-key", "byok-plan", "--provider-contract", str(descriptor))
        self.package.write_text(json.dumps(self.native("state", "work", *self.common, "--provider-contract", str(descriptor))))
        config_path = self.base / "provider-config.json"
        config_path.write_text(json.dumps(config))
        self.command.write_text(json.dumps([sys.executable,str(ROOT / "skills/mehscan-security/scripts/codex_reviewer.py"),"--config",str(config_path)]))
        result = self.invoke("byok-worker", extra=["--provider-contract",str(descriptor)])
        self.assertEqual(result.returncode,0,result.stdout + result.stderr)
        record = json.loads((self.base / "byok-worker/worker.json").read_text())
        self.assertEqual(record["status"],"admitted",record)
        self.assertEqual(len(record["completion"]["issue_review_ids"]),len(self.ids))
        self.assertEqual(record["runtime"]["provider"],provider)
        self.assertTrue((self.base / "byok-worker/provider-metrics.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
