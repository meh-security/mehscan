"""Matched native batch membership and complete workspace report; fake inference."""
import copy
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
    def prepare(self):
        f=fixtures.NativeBridgeTests(methodName="test_rejected_completed_reply_still_records_usage")
        f.setUp();self.addCleanup(f.doCleanups)
        inv=fixtures.read(f.inventory/"inventory.json")
        design={"batch_mode":True,"source_pin":{"local_export":str(f.root),"native_repository_key":"evaluation:workspace-bridge",
            "native_source_fingerprint":inv["identity_catalog"]["source_fingerprint"]},"model":f.config["model"],
            "reasoning_effort":f.config["reasoning_effort"],"selected_review_ids":f.package["payload"]["review_ids"],
            "per_arm_limits":f.limits,"per_arm_experiment":f.experiment,
            "native_case_limits":{"rounds":5,"queries":24,"bytes":524288,"timeout_seconds":900}}
        path=f.base/"design.json";path.write_text(json.dumps(design))
        args=copy.copy(f.args)
        args.design,args.output,args.private=str(path),str(f.base/"batch"),str(f.base/"batch-private")
        args.provider_config,args.provider_executable=str(f.config_path),sys.executable
        with patch.object(pilot.subprocess,"check_output",return_value="codex-cli fixture-1\n"),patch("codex_launcher.Launcher"):
            pilot.prepare(args)
        return f,Path(args.output)

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
