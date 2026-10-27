"""Matched native batch membership and complete workspace report; fake inference."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_bridge as fixtures
import test_workspace_actions as action_fixtures
import review_workspace_pilot as pilot
import review_workspace_batch_comparison as batch
import review_worker as worker
import codex_reviewer


class BatchComparisonTests(unittest.TestCase):
    def prepare(self,explicit=False,extra_source=None):
        f=fixtures.NativeBridgeTests(methodName="test_rejected_completed_reply_still_records_usage")
        if extra_source:
            f.extra_source=extra_source
        if explicit:
            f.extra_source={f"profile{i}.ts":f"export const p{i} = true;\n" + ("\n" if i == 0 else "") for i in range(8)}
        f.setUp();self.addCleanup(f.doCleanups)
        inv=fixtures.read(f.inventory/"inventory.json")
        design={"batch_mode":True,"source_pin":{"local_export":str(f.root),"native_repository_key":"evaluation:workspace-bridge",
            "native_source_fingerprint":inv["identity_catalog"]["source_fingerprint"]},"model":f.config["model"],
            "reasoning_effort":f.config["reasoning_effort"],"selected_review_ids":f.package["payload"]["review_ids"],
            "per_arm_limits":f.limits,"per_arm_experiment":f.experiment,
            "native_case_limits":{"rounds":5,"queries":24,"bytes":524288,"timeout_seconds":900}}
        if explicit:
            design["source_profile"]={"schema_version":"mehscanSourceProfile/v1",
                **{k:f.package['payload'][k] for k in ('repository','inventory_input_fingerprint')},
                "targets":[{"review_ids":design['selected_review_ids'],"windows":[{
                    "path":name,"start_line":1,"end_line":2 if name == "profile0.ts" else 1,
                    "file_sha256":hashlib.sha256((f.root/name).read_bytes()).hexdigest()} for name in f.extra_source]}]}
        path=f.base/"design.json";path.write_text(json.dumps(design))
        args=copy.copy(f.args)
        args.design,args.output,args.private=str(path),str(f.base/"batch"),str(f.base/"batch-private")
        args.provider_config,args.provider_executable=str(f.config_path),sys.executable
        with patch.object(pilot.subprocess,"check_output",return_value="codex-cli fixture-1\n"),patch("codex_launcher.Launcher"):
            pilot.prepare(args)
        return f,Path(args.output)

    def test_native_sees_global_query_remainder_after_rejected_batch(self):
        f,root=self.prepare(extra_source={'helpers/policy.ts':'export function policy() { return true; }\n'})
        _,_,setup=pilot.load_run(root);opts=setup['arms']['control']
        config=fixtures.read(opts['config']);command=fixtures.read(opts['command'])
        entries={e['review_id']:e for e in fixtures.read(f.inventory/'inventory.json')['entries']}
        original=worker.execute;calls=[]
        def execute(argv,cwd,env,timeout,payload=None):
            if argv!=command:return original(argv,cwd,env,timeout,payload)
            task=json.loads(payload);calls.append(task)
            rid=task['review_ids'][0]
            if len(calls)==1:
                queries=[{'tool':'definition','review_id':rid,'purpose':'Inspect the policy implementation.',
                          'arguments':{'name':'policy','path':'helpers','limit':1}}]
            elif len(calls)==2:
                queries=[{'tool':'source','review_id':rid,'purpose':'Inspect the selected evaluator.',
                          'arguments':{'path':'app.js','start_line':line,'end_line':line}} for line in (1,2)]
            else:queries=[]
            class Fake:
                def review(instance,prompt,schema,thread_id=None,timeout=600):
                    results=[] if queries else [{**action_fixtures.WorkspaceActionTests.decision(entries[r]),
                                                 'checks':[],'blockers':[]} for r in task['review_ids']]
                    answer={'action':'research' if queries else 'final','research':queries,'draft':None if queries else {'results':results},
                            'working_chain':'Inspect the selected evaluator with the offered remaining allowance.',
                            'progress':[],'routing':[]}
                    events=[{'type':'thread.started','thread_id':thread_id or str(uuid.uuid4())},
                            {'type':'turn.completed','usage':{'input_tokens':100,'cached_input_tokens':0,'output_tokens':30}}]
                    return answer,'\n'.join(json.dumps(e) for e in events),''
            return codex_reviewer.run(config,task,lambda c,s:Fake())
        with patch.object(worker,'execute',side_effect=execute):result=pilot.run_control(root)
        self.assertEqual(result['status'],'admitted',(result,fixtures.read(root/'control/worker/worker.json').get('detail')))
        self.assertEqual([c['research']['queries_remaining'] for c in calls],[4,2,0])
        self.assertEqual(result['usage']['observed_calls'],3)
        self.assertEqual(result['usage']['unobserved_calls'],0)
        self.assertEqual(fixtures.read(root/'control/budget.json')['queries'],4)
        job=fixtures.read(next((root/'control/worker/jobs').glob('*.json')))
        self.assertEqual(job['queries'],2)  # Rejected definition remains charged only in the outer ledger.
        receipts=[json.loads(s) for s in (root/'control/worker/research.jsonl').read_text().splitlines()]
        self.assertEqual([r['query']['tool'] for r in receipts],['source','source'])
        self.assertEqual(fixtures.read(root/'control/worker/worker.json')['protocol_corrections'],1)

    def test_explicit_eight_window_channel_reaches_both_actual_reviewers_and_stays_bound(self):
        f,root=self.prepare(explicit=True)
        _,_,setup=pilot.load_run(root)
        entries={e['review_id']:e for e in fixtures.read(f.inventory/'inventory.json')['entries']}
        command_to_arm={tuple(fixtures.read(opts['command'])):arm for arm,opts in setup['arms'].items()}
        original=worker.execute;packets={}
        def execute(argv,cwd,env,timeout,payload=None):
            arm=command_to_arm.get(tuple(argv))
            if arm is None:return original(argv,cwd,env,timeout,payload)
            task=json.loads(payload);packet=fixtures.read(task['evidence_packet']);packets[arm]=packet
            paths={w['path'] for w in packet['primary']['windows']}
            self.assertTrue(set(f.extra_source)<=paths)
            class Fake:
                def review(instance,prompt,schema,thread_id=None,timeout=600):
                    decisions=[action_fixtures.WorkspaceActionTests.decision(entries[rid]) for rid in task['review_ids']]
                    if not task.get('workspace_protocol'):
                        decisions=[{**d,'checks':[],'blockers':[]} for d in decisions]
                    answer=({'updates':[],'lookups':[],'decisions':decisions} if task.get('workspace_protocol') else
                        {'action':'final','research':[],'draft':{'results':decisions},'working_chain':'','progress':[],'routing':[]})
                    events=[{'type':'thread.started','thread_id':str(uuid.uuid4())},
                            {'type':'turn.completed','usage':{'input_tokens':100,'cached_input_tokens':0,'output_tokens':30}}]
                    return answer,'\n'.join(json.dumps(e) for e in events),''
            opts=setup['arms'][arm]
            return codex_reviewer.run(fixtures.read(opts['config']),task,lambda c,s:Fake())
        with patch.object(worker,'execute',side_effect=execute):
            native=pilot.run_control(root)
            workspace=batch.run_treatment(root)
        self.assertEqual(native['status'],'admitted',native)
        self.assertEqual(workspace['status'],'source_validated',workspace)
        self.assertEqual(pilot.ordinary_windows(packets['control']),pilot.canonical_windows(packets['treatment']['primary']['windows']))
        coverage=fixtures.read(root/'initial-source-coverage.json')
        self.assertTrue(next(iter(coverage.values()))['complete'])
        self.assertEqual(len(next(iter(coverage.values()))['windows']),8)
        opts=setup['arms']['treatment'];bridge=fixtures.NativeWorkspace(fixtures.Namespace(**opts))
        bridge.metadata['source_profile']['targets'][0]['windows'][0]['file_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'profile changed'):
            bridge.check()
        with (root/'source-profile.json').open('a') as stream:stream.write(' ')
        with self.assertRaisesRegex(ValueError,'profile changed'):
            pilot.load_run(root)

    def test_default_native_bucket_retains_two_claims_and_matches_workspace_source(self):
        f,root=self.prepare()
        _,design,setup=pilot.load_run(root)
        manifest=fixtures.read(root/"control/bundles/manifest.json")
        self.assertEqual([len(b["review_ids"]) for b in manifest["bundles"]],[2])
        opts=setup["arms"]["treatment"]
        bridge=fixtures.NativeWorkspace(fixtures.Namespace(**opts))
        groups=[w for w in bridge.workspace.snapshot()["work"].values() if w["claims"]]
        self.assertEqual([len(w["claims"]) for w in groups],[2])
        self.assertNotIn("bundle_max_reviews",bridge.metadata["experiment"])
        parity=fixtures.read(root/"initial-evidence.json")
        self.assertEqual(len(parity),1)
        self.assertEqual(set(next(iter(parity.values()))["review_ids"]),set(design["selected_review_ids"]))
        self.assertFalse(bridge.workspace.snapshot()["calls"])

    def test_full_batch_finalizes_every_original_member_and_reports_without_admission(self):
        f,root=self.prepare()
        _,_,setup=pilot.load_run(root);opts=setup["arms"]["treatment"]
        config=fixtures.read(opts["config"]);command=fixtures.read(opts["command"])
        original=worker.execute;prompts=[]
        def execute(argv,cwd,env,timeout,payload=None):
            if argv!=command:return original(argv,cwd,env,timeout,payload)
            task=json.loads(payload);packet=fixtures.read(task["evidence_packet"])
            self.assertEqual(task["research"]["workspace_budget"]["work_remaining"]["model_calls"],6)
            class Fake:
                def review(instance,prompt,schema,thread_id=None,timeout=600):
                    prompts.append(prompt)
                    answer={"updates":[],"lookups":[],"decisions":[action_fixtures.WorkspaceActionTests.decision(c) for c in packet["native_questions"]]}
                    events=[{"type":"thread.started","thread_id":str(uuid.uuid4())},
                            {"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":30}}]
                    return answer,"\n".join(json.dumps(e) for e in events),""
            return codex_reviewer.run(config,task,lambda c,s:Fake())
        with patch.object(worker,"execute",side_effect=execute):
            result=batch.run_treatment(root)
        self.assertEqual(result["status"],"source_validated",result)
        self.assertEqual(result["usage"]["calls"],1)
        self.assertEqual(len(result["claims"]),2)
        self.assertTrue(all(c["decision"]=="issue" for c in result["claims"].values()))
        self.assertFalse(result["native_admission"])
        self.assertEqual(len(fixtures.read(root/"treatment/findings.json")["decision_records"]),2)
        with self.assertRaises((ValueError,FileExistsError)):
            batch.run_treatment(root)

    def test_ordinary_worker_uses_same_multi_claim_bundle_and_private_study_store(self):
        f,root=self.prepare()
        _,_,setup=pilot.load_run(root);opts=setup["arms"]["control"]
        config=fixtures.read(opts["config"]);command=fixtures.read(opts["command"])
        entries={e["review_id"]:e for e in fixtures.read(f.inventory/"inventory.json")["entries"]}
        original=worker.execute;calls=[]
        def execute(argv,cwd,env,timeout,payload=None):
            if argv!=command:return original(argv,cwd,env,timeout,payload)
            task=json.loads(payload);calls.append(task)
            class Fake:
                def review(instance,prompt,schema,thread_id=None,timeout=600):
                    results=[{**action_fixtures.WorkspaceActionTests.decision(entries[rid]),"checks":[],"blockers":[]} for rid in task["review_ids"]]
                    answer={"action":"final","research":[],"draft":{"results":results},
                        "working_chain":"Exact selected evaluation calls inspected.","progress":[],"routing":[]}
                    events=[{"type":"thread.started","thread_id":str(uuid.uuid4())},
                        {"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":30}}]
                    return answer,"\n".join(json.dumps(e) for e in events),""
            return codex_reviewer.run(config,task,lambda c,s:Fake())
        with patch.object(worker,"execute",side_effect=execute):
            result=pilot.run_control(root)
        self.assertEqual(result["status"],"admitted",result)
        self.assertEqual(len(calls),1)
        self.assertEqual(len(calls[0]["review_ids"]),2)
        self.assertEqual(result["usage"]["observed_calls"],1)
        self.assertEqual(len(fixtures.read(root/"control/worker/findings.json")["decision_records"]),2)


if __name__=="__main__":unittest.main()
