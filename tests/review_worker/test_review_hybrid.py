"""Real native validation and deterministic providers for routed execution."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

PRODUCT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PRODUCT/"scripts"))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import review_hybrid as hybrid
import review_routing as routing
import review_worker as worker
import review_workspace_pilot as pilot
from review_workspace import identity
from review_workspace_bridge import NativeWorkspace
import test_workspace_bridge as fixtures
import test_workspace_actions as actions
import codex_reviewer


class HybridBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="mehscan-hybrid-budget-")
        self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.now=1000

    def schedule(self):
        manifest={"bundles":[{"bundle_fingerprint":"one","review_ids":["a","b"]},
                             {"bundle_fingerprint":"two","review_ids":["c"]}]}
        plan={"selected_review_ids":["a","b","c"],"claims":[{"review_id":r,"route":"workspace" if r in ("a","c") else "native"} for r in ("a","b","c")],
              "investigations":[{"id":"shared","route":"workspace","review_ids":["a","c"]}],
              "native_packets":[{"original_bundle_id":"one","review_ids":["b"]}]}
        case=dict(rounds=1,queries=4,bytes=100,timeout_seconds=100)
        return hybrid.schedule(plan,manifest,case)

    def ledger(self,compiled=None,model_calls=4):
        return hybrid.Ledger(self.base/"ledger.json",compiled or self.schedule(),
            {"model_calls":model_calls,"queries":8,"source_bytes":200},
            {"max_input_tokens":10000,"max_output_tokens":10000,"max_elapsed_seconds":300},clock=lambda:self.now)

    def call(self,ledger,uid):
        task={"conversation_id":str(uuid.uuid4()),"research":{"round":0},"provider_metrics":str(self.base/"metrics.jsonl")}
        index,offer=ledger.reserve_call(uid,task)
        worker.write_text(task["provider_metrics"],json.dumps({"conversation_id":task["conversation_id"],"round":0,"provider":{"model":"fixture"},
            "usage":{"input_tokens":10,"cached_input_tokens":0,"output_tokens":1},"elapsed_ms":2})+'\n')
        ledger.observe_call(index,task,{"model":"fixture"})
        return offer

    def test_cross_bundle_groups_share_only_the_original_credit(self):
        compiled=self.schedule()
        self.assertEqual(len(compiled["components"]),1)
        self.assertEqual(compiled["components"][0]["limits"]["model_calls"],4)
        self.assertEqual(compiled["components"][0]["limits"]["queries"],8)
        self.assertEqual(compiled["units"][0]["id"],"shared")
        ledger=self.ledger(compiled);first,last=[u["id"] for u in compiled["units"]]
        self.assertEqual(self.call(ledger,first)["model_calls"],2)
        self.assertEqual(self.call(ledger,first)["queries"],0)
        ledger.finish(first,True)
        self.assertEqual(self.call(ledger,last)["model_calls"],2)
        self.assertEqual(self.call(ledger,last)["model_calls"],1)
        with self.assertRaisesRegex(ValueError,"allowance exhausted"):ledger.offer(last)
        self.assertEqual(ledger.usage()["attempted_calls"],4)

    def test_one_final_slot_is_reserved_for_remaining_fragments(self):
        compiled=self.schedule();compiled["components"][0]["limits"]["model_calls"]=3
        ledger=self.ledger(compiled,model_calls=3);first,last=[u["id"] for u in compiled["units"]]
        self.call(ledger,first);self.call(ledger,first);ledger.finish(first,True)
        offer=ledger.offer(last)
        self.assertEqual((offer["model_calls"],offer["queries"]),(1,0))
        self.call(ledger,last)
        self.assertEqual(ledger.usage()["attempted_calls"],3)

    def test_unknown_usage_blocks_both_routes_and_preserves_reservation(self):
        ledger=self.ledger();first,last=[u["id"] for u in ledger.state["schedule"]["units"]]
        task={"conversation_id":"unknown","research":{"round":0},"provider_metrics":str(self.base/"missing.jsonl")}
        index,_=ledger.reserve_call(first,task);ledger.observe_call(index,task,{})
        for uid in (first,last):
            with self.subTest(uid=uid),self.assertRaisesRegex(ValueError,"unknown paid usage"):ledger.offer(uid)
        self.assertEqual(ledger.usage()["unobserved_calls"],1)
        self.assertEqual(worker.read(ledger.path)["units"][first]["model_calls"],1)

    def test_rejected_query_batch_and_received_overspend_stay_charged(self):
        ledger=self.ledger();uid=ledger.state["schedule"]["units"][0]["id"]
        with self.assertRaisesRegex(ValueError,"advertised remainder"):
            ledger.charge_queries(uid,[{"tool":"definition"},{"tool":"source"}],2)
        self.assertEqual(worker.read(ledger.path)["units"][uid]["queries"],3)
        with self.assertRaisesRegex(ValueError,"observation retained"):ledger.observe_bytes(uid,101)
        self.assertEqual(worker.read(ledger.path)["units"][uid]["received_bytes"],101)

    def test_deadline_restart_and_route_coverage_guards(self):
        ledger=self.ledger();uid=ledger.state["schedule"]["units"][0]["id"]
        self.call(ledger,uid);self.now+=301
        with self.assertRaisesRegex(ValueError,"allowance exhausted"):ledger.offer(uid)
        with self.assertRaisesRegex(ValueError,"already exists"):self.ledger()
        with self.assertRaisesRegex(ValueError,"global hybrid allowance"):
            hybrid.Ledger(self.base/"too-small.json",self.schedule(),{"model_calls":1,"queries":8,"source_bytes":200},
                {"max_input_tokens":100,"max_output_tokens":100,"max_elapsed_seconds":300})


class HybridNativeTests(unittest.TestCase):
    def prepare(self,explicit=False):
        f=fixtures.NativeBridgeTests(methodName="test_rejected_completed_reply_still_records_usage")
        f.extra_source={"policy.ts":"export function policy() { return true; }\n"}
        f.setUp();self.addCleanup(f.doCleanups)
        inv=worker.read(f.inventory/"inventory.json");ids=f.package["payload"]["review_ids"]
        run=f.base/"original-bundles"
        f.native("investigate","review-bundles",str(f.root),"--inventory",str(f.inventory),"--review-ids",",".join(ids),"--output",str(run))
        manifest=worker.read(run/"manifest.json")
        selection={"schema_version":routing.SELECTION_VERSION,"binding":routing.input_binding(inv,manifest),"selections":[{
            "review_ids":[ids[0]],"route":"workspace","kind":"relationship","deciding_question":"Does the selected evaluator interpret request input?",
            "reason":"Exercise targeted workspace investigation beside a native fragment in the same original bundle.",
            "caller_checks":{ids[0]:"Inspect this selected input-to-effect relationship independently."},
            "evidence_windows":[{"path":"app.js","start_line":1,"end_line":2,"file_sha256":worker.digest_file(f.root/"app.js")}],
            "limits":["Structural dispatch fixture, not a real application accuracy result."]}]}
        plan=routing.build(f.root,inv,manifest,selections=selection)
        path=f.base/"routing.json";worker.write(path,plan)
        selections=f.base/"selections.json";worker.write(selections,selection)
        design={"batch_mode":True,"hybrid_mode":True,"source_pin":{"local_export":str(f.root),"native_repository_key":"evaluation:workspace-bridge",
            "native_source_fingerprint":inv["identity_catalog"]["source_fingerprint"]},"model":f.config["model"],"reasoning_effort":"medium",
            "selected_review_ids":ids,"per_arm_limits":f.limits,"per_arm_experiment":f.experiment,
            "native_case_limits":{"rounds":2,"queries":4,"bytes":65536,"timeout_seconds":600}}
        if explicit:
            design["source_profile"]={"schema_version":"mehscanSourceProfile/v1",
                **{k:f.package['payload'][k] for k in ('repository','inventory_input_fingerprint')},
                "targets":[{"review_ids":ids,"windows":[{"path":name,"start_line":1,"end_line":last,
                    "file_sha256":worker.digest_file(f.root/name)} for name,last in (("app.js",2),("policy.ts",1))]}]}
        design_path=f.base/"design.json";worker.write(design_path,design)
        args=copy.copy(f.args)
        for key,value in dict(design=str(design_path),output=str(f.base/"hybrid"),private=str(f.base/"hybrid-private"),
                provider_config=str(f.config_path),provider_executable=sys.executable,routing=str(path),routing_inventory=str(f.inventory/"inventory.json"),
                routing_manifest=str(run/"manifest.json"),planner_plan=None,selections=str(selections)).items():setattr(args,key,value)
        with patch.object(pilot.subprocess,"check_output",return_value="codex-cli fixture-1\n"),patch("codex_launcher.Launcher"):
            prepared=hybrid.prepare(args)
        self.assertEqual(prepared["units"],2)
        return f,Path(args.output)

    def provider(self,setup,callback):
        command=worker.read(setup["arms"]["treatment"]["command"])
        config=worker.read(setup["arms"]["treatment"]["config"])
        original=worker.execute
        def execute(argv,cwd,env,timeout,payload=None):
            if argv!=command:return original(argv,cwd,env,timeout,payload)
            task=json.loads(payload);packet=worker.read(task["evidence_packet"])
            answer=callback(task,packet)
            class Fake:
                def review(instance,prompt,schema,thread_id=None,timeout=600):
                    events=[{"type":"thread.started","thread_id":thread_id or str(uuid.uuid4())},
                        {"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":30}}]
                    return answer,'\n'.join(json.dumps(e) for e in events),''
            return codex_reviewer.run(config,task,lambda c,s:Fake())
        return execute

    def final(self,task,packet):
        results=[actions.WorkspaceActionTests.decision(c) for c in packet["native_questions"]]
        if task.get("workspace_protocol"):return {"updates":[],"lookups":[],"decisions":results}
        return {"action":"final","research":[],"draft":{"results":[{**r,"checks":[],"blockers":[]} for r in results]},
                "working_chain":"Selected source inspected.","progress":[],"routing":[]}

    def test_mixed_native_and_workspace_reassemble_original_bundle_without_admission(self):
        f,root=self.prepare();_,_,setup,_=hybrid.load(root);calls=[]
        before=worker.read(setup["arms"]["treatment"]["work_package"])
        def answer(task,packet):
            calls.append((copy.deepcopy(task),packet));reply=self.final(task,packet)
            if task.get("workspace_protocol"):
                reply["updates"]=[{"kind":"proposition","proposition_id":"selected-effect",
                    "statement":"The selected implementation interprets its supplied input.","scope":"Selected evaluator",
                    "conditions":"The inspected caller reaches this implementation.","exclusions":"Other callers and authorization are not established.",
                    "evidence":[actions.WorkspaceActionTests.handle(task,packet,"app.js")]}]
            else:self.assertNotIn("workspace_evidence",packet)
            return reply
        with patch.object(worker,"execute",side_effect=self.provider(setup,answer)):result=hybrid.run(root)
        self.assertEqual(result["status"],"source_validated",result)
        self.assertEqual([bool(t.get("workspace_protocol")) for t,p in calls],[True,False])
        self.assertEqual([len(t["review_ids"]) for t,p in calls],[1,1])
        self.assertEqual(result["usage"]["attempted_calls"],2)
        self.assertEqual(result["usage"]["unobserved_calls"],0)
        self.assertFalse(result["native_admission"])
        package=worker.read(root/"treatment/review-package.json")
        self.assertEqual(len(package["claims"]),2)
        self.assertFalse(package["omitted_review_ids"])
        findings=worker.read(root/"treatment/findings.json")
        self.assertEqual(len(findings["decision_records"]),2)
        native=next((root/"treatment/native").iterdir())
        self.assertEqual(worker.read(native/"worker.json")["status"],"source_validated")
        self.assertNotIn("admission_sequence",worker.read(native/"worker.json"))
        opts=setup["arms"]["treatment"];bridge=NativeWorkspace(fixtures.Namespace(**opts))
        self.assertEqual(bridge.native(["state","work",*bridge.common,"--review-ids",','.join(before['payload']['review_ids'])]),before)
        imported=worker.read(native/"hybrid-import.json")["drafts"][0]["results"][0]
        self.assertEqual(next(c["result"] for c in package["claims"] if c["review_id"]==imported["review_id"]),imported)
        self.assertEqual(next(c["reviewer_notes"] for c in package["claims"] if c["review_id"]==imported["review_id"]),[])
        note=next(iter(package["notes"].values()))
        self.assertEqual(note["conditions"],"The inspected caller reaches this implementation.")
        self.assertEqual(note["exclusions"],"Other callers and authorization are not established.")
        with self.assertRaises((ValueError,FileExistsError)):hybrid.run(root)

    def test_workspace_lookup_and_native_final_share_original_remaining_allowance(self):
        f,root=self.prepare();_,_,setup,_=hybrid.load(root);calls=[]
        def answer(task,packet):
            calls.append(copy.deepcopy(task))
            if len(calls)==1:
                rid=task["review_ids"][0]
                return {"updates":[],"decisions":[],"lookups":[{"question_id":"selected-effect","review_ids":[rid],
                    "question":"What is the selected helper's implementation?","queries":[{"tool":"source","review_id":rid,
                    "purpose":"Inspect the selected helper.","arguments":{"path":"policy.ts","start_line":1,"end_line":1}}]}]}
            response=self.final(task,packet)
            if task.get("workspace_protocol"):
                eid=actions.WorkspaceActionTests.handle(task,packet,"policy.ts")
                response["updates"]=[{"kind":"answer","question_id":"selected-effect","evidence":[eid],"status":"answered","reason":"The selected helper returns true."}]
            return response
        with patch.object(worker,"execute",side_effect=self.provider(setup,answer)):result=hybrid.run(root)
        self.assertEqual(result["status"],"source_validated",result)
        self.assertEqual(len(calls),3)
        self.assertEqual([t["research"]["queries_remaining"] for t in calls],[4,0,0])
        self.assertEqual(result["usage"]["spent"]["queries"],1)
        self.assertGreater(result["usage"]["spent"]["received_bytes"],0)

    def test_modified_schedule_blocks_execution_before_provider(self):
        f,root=self.prepare()
        path=root/"hybrid-schedule.json";data=worker.read(path);data["units"][0]["route"]="native";worker.write(path,data)
        with self.assertRaisesRegex(ValueError,"frozen hybrid input changed"):hybrid.run(root)
        self.assertFalse((root/"treatment/.execution").exists())

    def test_native_continuation_uses_ordinary_research_protocol_and_remaining_component_credit(self):
        f,root=self.prepare();_,_,setup,_=hybrid.load(root);calls=[]
        def answer(task,packet):
            calls.append(copy.deepcopy(task))
            if not task.get("workspace_protocol") and task["research"]["round"]==0:
                return {"action":"research","research":[{"tool":"source","review_id":task["review_ids"][0],
                    "purpose":"Read the selected helper.","arguments":{"path":"policy.ts","start_line":1,"end_line":1}}],
                    "draft":None,"working_chain":"Establish the helper behavior.","progress":[],"routing":[]}
            return self.final(task,packet)
        with patch.object(worker,"execute",side_effect=self.provider(setup,answer)):result=hybrid.run(root)
        self.assertEqual(result["status"],"source_validated",result)
        self.assertEqual([bool(t.get("workspace_protocol")) for t in calls],[True,False,False])
        self.assertEqual([t["research"]["round"] for t in calls],[0,0,1])
        self.assertEqual([t["research"]["queries_remaining"] for t in calls],[4,4,0])
        self.assertEqual(result["usage"]["spent"]["queries"],1)
        self.assertGreater(result["usage"]["spent"]["received_bytes"],0)
        self.assertEqual(result["usage"]["attempted_calls"],3)

    def test_partial_native_usage_stops_assembly_without_discarding_workspace_result(self):
        f,root=self.prepare();_,_,setup,_=hybrid.load(root)
        provider=self.provider(setup,self.final);command=worker.read(setup["arms"]["treatment"]["command"])
        def execute(argv,cwd,env,timeout,payload=None):
            reply=provider(argv,cwd,env,timeout,payload)
            if argv==command:
                task=json.loads(payload)
                if not task.get("workspace_protocol"):
                    path=Path(task["provider_metrics"])
                    rows=[json.loads(s) for s in path.read_text(encoding="utf-8").splitlines()]
                    rows[-1]["usage"].pop("cached_input_tokens")
                    worker.write_text(path,'\n'.join(json.dumps(r) for r in rows)+'\n')
            return reply
        with patch.object(worker,"execute",side_effect=execute):result=hybrid.run(root)
        self.assertEqual(result["status"],"incomplete")
        self.assertEqual(result["usage"]["attempted_calls"],2)
        self.assertEqual(result["usage"]["unobserved_calls"],1)
        self.assertFalse((root/"treatment/report-responses").exists())
        opts=setup["arms"]["treatment"];bridge=NativeWorkspace(fixtures.Namespace(**opts))
        claims=bridge.workspace.snapshot()["claims"]
        self.assertEqual(sum(c["draft"] is not None for c in claims.values()),1)

    def test_validate_only_rejects_change_pass_before_any_work(self):
        with self.assertRaisesRegex(ValueError,"native phase"):
            worker.run_locked(fixtures.Namespace(validate_only=True,phase="all",supersede=False))

    def test_native_fragment_preserves_original_explicit_source_with_exact_subset_scope(self):
        f,root=self.prepare(explicit=True);_,design,setup,compiled=hybrid.load(root)
        native=next(u for u in compiled["units"] if u["route"]=="native")
        inputs=worker.read(root/"hybrid-native-inputs.json")[native["id"]]
        profile=worker.read(inputs["source_profile"])
        self.assertEqual(profile["targets"][0]["review_ids"],native["review_ids"])
        self.assertEqual(profile["targets"][0]["windows"],design["source_profile"]["targets"][0]["windows"])
        packets=[]
        def answer(task,packet):
            packets.append(packet)
            coverage=pilot.source_coverage(f.root,profile["targets"][0]["windows"],packet["primary"]["windows"])
            self.assertTrue(coverage["complete"])
            return self.final(task,packet)
        with patch.object(worker,"execute",side_effect=self.provider(setup,answer)):result=hybrid.run(root)
        self.assertEqual(result["status"],"source_validated",result)
        self.assertEqual(len(packets),2)


if __name__=="__main__":unittest.main()
