"""Actual native work/finalizer + bundled adapter, deterministic provider only."""
from argparse import Namespace
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

PRODUCT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PRODUCT / "scripts"))
sys.path.insert(0,str(PRODUCT / "skills/mehscan-security/scripts"))
import codex_reviewer
import codex_launcher
from review_workspace_bridge import NativeWorkspace, read
from review_worker import CommandFailure


class NativeBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-workspace-native-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "app.js").write_text("export function first(request) { return eval(request.query.code); }\n"
                                          "export function second(request) { return eval(request.body.code); }\n",encoding="utf-8")
        for path,text in getattr(self,"extra_source",{}).items():
            (self.root / path).parent.mkdir(parents=True,exist_ok=True)
            (self.root / path).write_text(text,encoding="utf-8")
        self.scanner = Path(os.environ.get("MEHSCAN_TEST_SCANNER",PRODUCT / "target/debug" / ("mehscan.exe" if os.name == "nt" else "mehscan")))
        self.skill = PRODUCT / "skills/mehscan-security"
        self.inventory, self.store = self.base / "inventory", self.base / "store"
        self.config = {"schema_version":"1","executable":sys.executable,"executable_version":"fixture-1",
                       "model":"fixture-model","reasoning_effort":"medium","auth_file":str(self.base / "auth.json"),
                       "private_directory":str(self.base / "provider-private")}
        (self.base / "auth.json").write_text('{"fixture":"never-an-api-key"}')
        self.config_path = self.base / "config.json"
        self.config_path.write_text(json.dumps(self.config))
        self.provider_path = self.base / "provider.json"
        self.provider_path.write_text(json.dumps(codex_launcher.provider_contract(self.config)))
        self.native("investigate","review-inventory",str(self.root),"--repository-key","evaluation:workspace-bridge","--output",str(self.inventory))
        claim = self.native("state","claim","--store",str(self.store),"--stream","pilot","--inventory",str(self.inventory),
                            "--source-root",str(self.root),"--attempt-id","first","--expected-generation","0","--operation-key","claim")
        self.claim_path = self.base / "claim.json"
        self.claim_path.write_text(json.dumps(claim))
        self.common = ["--store",str(self.store),"--stream","pilot","--inventory",str(self.inventory),"--source-root",str(self.root),
                       "--generation","1","--owner",claim["result"]["owner"],"--skill-root",str(self.skill),
                       "--provider-contract",str(self.provider_path)]
        plan = self.native("state","plan-template","--inventory",str(self.inventory),"--source-root",str(self.root),
                           "--policy","comprehensive","--skill-root",str(self.skill),"--provider-contract",str(self.provider_path))
        self.plan_path = self.base / "plan.json"
        self.plan_path.write_text(json.dumps(plan))
        self.native("state","plan",*self.common,"--input",str(self.plan_path),"--operation-key","plan")
        self.package = self.native("state","work",*self.common)
        self.package_path = self.base / "work.json"
        self.package_path.write_text(json.dumps(self.package))
        self.args = Namespace(scanner=str(self.scanner),source_root=str(self.root),inventory=str(self.inventory),store=str(self.store),
                              stream="pilot",claim=str(self.claim_path),work_package=str(self.package_path),skill_root=str(self.skill),
                              provider_contract=str(self.provider_path),directory=str(self.base / "workspace"))
        self.limits = {"model_calls":3,"queries":4,"source_bytes":65536}
        self.experiment = {"max_input_tokens":100000,"max_output_tokens":10000,"max_elapsed_seconds":600,"context_max_bytes":32768}

    def native(self,*args):
        result = subprocess.run([str(self.scanner),*args],text=True,encoding="utf-8",capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)

    def create(self):
        self.bridge = NativeWorkspace.create(self.args,self.limits,self.experiment)
        return self.bridge

    def provider(self,calls, *, alter=None, invalid=False):
        config = self.config
        def invoke(task):
            packet = read(task["evidence_packet"])
            class Fake:
                def review(self,prompt,schema,thread_id=None,timeout=600):
                    calls.append({"prompt":prompt,"schema":schema,"thread_id":thread_id,"task":copy.deepcopy(task)})
                    if alter:
                        alter()
                    results = [{"review_id":q["review_id"],"decision":"issue","confidence":"high",
                        "summary":"Request text reaches the selected evaluator.","reason":"The shown call interprets request input.",
                        "evidence":[{"path":q["path"],"start_line":q["line"],"end_line":q["line"]}],
                        "checks":[],"blockers":[],"source_leads":[],
                        "diagnosis":{"title":"Request-controlled evaluation","cwes":["CWE-94"],"severity":"high",
                                     "impact":"Request text is interpreted as program code.","remediation":"Remove evaluation of request text."}}
                        for q in packet["native_questions"]]
                    response = {"action":"final","research":[],"draft":{"results":results},
                                "working_chain":"Exact selected evaluator calls inspected.","progress":[],"routing":[]}
                    if invalid:
                        response["action"] = "research"
                    events = [{"type":"thread.started","thread_id":str(uuid.uuid4())},
                              {"type":"turn.started"},{"type":"turn.completed","usage":{
                                  "input_tokens":100,"cached_input_tokens":0,"output_tokens":20}}]
                    return response,"\n".join(json.dumps(e) for e in events),""
            return codex_reviewer.run(config,task,lambda c,s:Fake())
        return invoke

    def test_native_bootstrap_fresh_context_reuse_and_complete_original_bundle_finalization(self):
        bridge = self.create()
        state = bridge.workspace.snapshot()
        seed = read(bridge.directory / "seed.json")
        self.assertEqual(seed["binding"],state["binding"])
        self.assertEqual({c["review_id"] for c in seed["claims"]},set(state["claims"]))
        self.assertEqual(set(state["claims"]),set(self.package["payload"]["review_ids"]))
        self.assertGreaterEqual(len(state["claims"]),2)
        bundle_id = next(iter(bridge.metadata["bundles"]))
        ids = bridge.metadata["bundles"][bundle_id]["review_ids"]
        self.assertGreaterEqual(len(ids),2)
        shared_evidence = next(iter(state["evidence"]))
        bridge.apply("prop",{"kind":"proposition","proposition_id":"eval-input","statement":"The selected calls evaluate their argument.",
                             "scope":"The shown evaluator calls","conditions":"Arguments reach these calls","exclusions":"No claim about other callers",
                             "evidence":[shared_evidence]})
        bridge.apply("focus",{"kind":"focus","work_id":"initial","evidence_ids":list(state["evidence"]),"proposition_ids":["eval-input"]})
        bridge.apply("split",{"kind":"split","work_id":"initial","new_work_id":"second","review_ids":ids[1:],"strategy":"interpreted-input"})
        calls = []
        first = bridge.prepare("initial",self.config_path,"first-session")["session_id"]
        bridge.review(first,self.config_path,self.provider(calls))
        with self.assertRaisesRegex(ValueError,"incomplete"):
            bridge.finalize(bundle_id)
        bridge = NativeWorkspace(self.args)  # Real process-local reconstruction.
        second = bridge.prepare("second",self.config_path,"second-session")["session_id"]
        bridge.review(second,self.config_path,self.provider(calls))
        self.assertNotEqual(first,second)
        self.assertEqual([c["thread_id"] for c in calls],[None,None])
        self.assertIn("The selected calls evaluate their argument",calls[1]["prompt"])
        self.assertNotIn(ids[0],read(calls[1]["task"]["evidence_packet"])["work"]["review_ids"])
        self.assertEqual(bridge.workspace.usage()["totals"]["input_tokens"],200)
        finalized = bridge.finalize(bundle_id)
        response = read(finalized["response"])
        self.assertEqual({r["review_id"] for r in response["results"]},set(ids))
        self.assertFalse(finalized["native_admission"])
        self.assertTrue(finalized["native_validated"])
        native_status = self.native("state","status","--store",str(self.store),"--stream","pilot",
                                    "--repository-key","evaluation:workspace-bridge")
        self.assertTrue(native_status["subjects"])
        self.assertEqual({s["state"] for s in native_status["subjects"]},{"unassessed"})
        # A displayed proposition is conservatively a dependency even without
        # importing an affirmative applicability claim from another caller.
        bridge.apply("dispute",{"kind":"dispute","proposition_id":"eval-input","reason":"Condition needs revision"})
        self.assertTrue(all(bridge.workspace.snapshot()["claims"][i]["reconsideration"] for i in ids))
        with self.assertRaisesRegex(ValueError,"reconsideration"):
            bridge.finalize(bundle_id)
        exported = (bridge.directory / "native-binding.json").read_text()
        self.assertNotIn(read(self.claim_path)["result"]["owner"],exported)
        self.assertNotIn("never-an-api-key",exported)
        trace = [json.loads(row) for row in (bridge.directory / "bridge-trace.jsonl").read_text().splitlines()]
        self.assertTrue(any(e["event"] == "native" for e in trace))
        self.assertTrue(any(e.get("operation") == "init" and e["completed"] for e in trace))
        self.assertTrue(any(e.get("operation") == "finalize" and e["completed"] for e in trace))
        self.assertNotIn(read(self.claim_path)["result"]["owner"],json.dumps(trace))

    def test_altered_work_and_source_rejected_before_workspace_publication(self):
        altered = copy.deepcopy(self.package)
        altered["payload"]["review_ids"] = altered["payload"]["review_ids"][:1]
        self.package_path.write_text(json.dumps(altered))
        with self.assertRaisesRegex(ValueError,"stale or altered"):
            self.create()
        self.assertFalse(Path(self.args.directory).exists())
        self.package_path.write_text(json.dumps(self.package))
        (self.root / "app.js").write_text("changed source\n")
        with self.assertRaises(CommandFailure):
            self.create()
        self.assertFalse(Path(self.args.directory).exists())

    def test_packet_tampering_and_changed_runtime_provider_execute_no_model(self):
        bridge = self.create()
        session = bridge.prepare("initial",self.config_path,"prepare")["session_id"]
        calls = []
        packet = bridge.directory / "sessions" / session / "context.json"
        packet.write_text("{}")
        with self.assertRaisesRegex(ValueError,"packet changed"):
            bridge.review(session,self.config_path,self.provider(calls))
        self.assertEqual(calls,[])
        self.assertEqual(bridge.workspace.usage()["calls"],0)
        changed = {**self.config,"model":"different-fixture"}
        self.config_path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError,"actual provider"):
            bridge.prepare("initial",self.config_path,"other")
        request = next((bridge.directory / "run/requests").glob("*.json"))
        request.write_text("{}")
        with self.assertRaisesRegex(ValueError,"artifact changed"):
            bridge.check()

    def test_paid_stale_answer_is_rejected_but_actual_usage_survives(self):
        bridge = self.create()
        session = bridge.prepare("initial",self.config_path,"prepare")["session_id"]
        calls = []
        def alter():
            (self.root / "app.js").write_text("changed during paid inference\n")
        with self.assertRaises(CommandFailure):
            bridge.review(session,self.config_path,self.provider(calls,alter=alter))
        self.assertEqual(len(calls),1)
        self.assertEqual(bridge.workspace.usage()["totals"]["input_tokens"],100)
        self.assertTrue(all(c["draft"] is None for c in bridge.workspace.snapshot()["claims"].values()))

    def test_unknown_call_cannot_be_redispatched_or_reset_by_new_session(self):
        bridge = self.create()
        session = bridge.prepare("initial",self.config_path,"prepare")["session_id"]
        def fail(task):
            raise RuntimeError("provider vanished before counters were observed")
        with self.assertRaises(RuntimeError):
            bridge.review(session,self.config_path,fail)
        self.assertEqual(bridge.workspace.usage()["unobserved_calls"],1)
        with self.assertRaisesRegex(ValueError,"already dispatched"):
            bridge.review(session,self.config_path,fail)
        replacement = bridge.prepare("initial",self.config_path,"replacement",session)["session_id"]
        with self.assertRaisesRegex(ValueError,"usage is unknown"):
            bridge.review(replacement,self.config_path,fail)
        self.assertEqual(bridge.workspace.usage()["calls"],1)

    def test_dispatch_callback_uses_deadline_supplied_before_call_reservation(self):
        bridge = self.create()
        session = bridge.prepare("initial",self.config_path,"prepare")["session_id"]
        calls = []
        provider = self.provider(calls)
        def invoke(task):
            self.assertEqual(bridge.workspace.usage()["unobserved_calls"],1)
            with self.assertRaisesRegex(ValueError,"usage is unknown"):
                bridge._remaining_seconds()
            # The controller already checked usage and supplied this deadline.
            # A callback must not run the previous-call guard on its own reservation.
            self.assertGreater(task["research"]["seconds_remaining"],0)
            return provider(task)
        bridge.review(session,self.config_path,invoke)
        self.assertEqual(len(calls),1)
        self.assertEqual(bridge.workspace.usage()["unobserved_calls"],0)

    def test_rejected_completed_reply_still_records_usage(self):
        bridge = self.create()
        session = bridge.prepare("initial",self.config_path,"prepare")["session_id"]
        with self.assertRaises(ValueError):
            bridge.review(session,self.config_path,self.provider([],invalid=True))
        self.assertEqual(bridge.workspace.usage()["totals"]["input_tokens"],100)
        self.assertTrue(all(c["draft"] is None for c in bridge.workspace.snapshot()["claims"].values()))

    def test_preparation_retry_recovers_partial_artifacts_and_replays_without_new_sessions(self):
        bridge = self.create()
        import review_workspace_bridge as module
        original = module.worker.write
        def interrupted(path,value):
            if Path(path).name == "facts.json":
                raise RuntimeError("preparation interrupted")
            return original(path,value)
        with patch.object(module.worker,"write",side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError,"interrupted"):
                bridge.prepare("initial",self.config_path,"prepare-once")
        prepared = bridge.prepare("initial",self.config_path,"prepare-once")
        repeated = bridge.prepare("initial",self.config_path,"prepare-once")
        self.assertEqual(prepared,repeated)
        self.assertEqual(len(bridge.workspace.snapshot()["sessions"]),1)
        self.assertEqual(bridge.workspace.usage()["calls"],0)

    def test_observed_token_ceiling_and_frozen_experiment_survive_new_contexts(self):
        self.experiment["max_input_tokens"] = 100
        bridge = self.create()
        first = bridge.prepare("initial",self.config_path,"first")["session_id"]
        bridge.review(first,self.config_path,self.provider([]))
        claim_id = next(iter(bridge.workspace.snapshot()["claims"]))
        bridge.apply("new-question",{"kind":"question","question_id":"new","review_ids":[claim_id],"question":"Is an additional condition required?"})
        second = bridge.prepare("initial",self.config_path,"second")["session_id"]
        with self.assertRaisesRegex(ValueError,"token ceiling"):
            bridge.review(second,self.config_path,self.provider([]))
        self.assertEqual(bridge.workspace.usage()["calls"],1)
        binding = read(bridge.directory / "native-binding.json")
        binding["experiment"]["max_input_tokens"] = 200
        (bridge.directory / "native-binding.json").write_text(json.dumps(binding))
        with self.assertRaisesRegex(ValueError,"binding differs"):
            NativeWorkspace(self.args)

    def test_usage_recovery_can_account_for_interrupted_call_after_source_became_stale(self):
        bridge = self.create()
        session = bridge.prepare("initial",self.config_path,"prepare")["session_id"]
        def interrupted(task):
            raise RuntimeError("lost response")
        with self.assertRaises(RuntimeError):
            bridge.review(session,self.config_path,interrupted)
        metrics = bridge.directory / "sessions" / session / "provider-metrics.jsonl"
        metrics.write_text(json.dumps({"conversation_id":session,"round":0,"provider":codex_launcher.provider_contract(self.config),
            "usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":20},"elapsed_ms":10}) + "\n")
        (self.root / "app.js").write_text("source no longer matches the old work package\n")
        reopened = NativeWorkspace(self.args)
        self.assertEqual(reopened.recover_usage(session)["totals"]["input_tokens"],100)
        self.assertTrue(all(c["draft"] is None for c in reopened.workspace.snapshot()["claims"].values()))


if __name__ == "__main__":
    unittest.main()
