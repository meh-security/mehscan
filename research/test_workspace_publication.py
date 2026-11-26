"""Native freshness at atomic lookup publication; deterministic inference only."""
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_actions as action_fixtures
import review_workspace as state_module
from review_worker import CommandFailure


class LookupPublicationTests(unittest.TestCase):
    def setUp(self):
        self.fx = action_fixtures.WorkspaceActionTests("test_partial_closure_lookup_learning_and_cross_work_knowledge_reuse")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.bridge = self.fx.bridge
        self.rid = next(iter(self.bridge.workspace.snapshot()["claims"]))

    def reply(self,task,packet):
        return {"updates":[],"decisions":[],"lookups":[{
            "question_id":"helper-binding","review_ids":[self.rid],"question":"What implementation reaches the evaluator?",
            "queries":[{"tool":"source","review_id":self.rid,"purpose":"Read the implementation used before evaluation",
                        "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]}

    def failed_publication(self):
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["used"]["queries"],1)
        self.assertEqual(state["used"]["model_calls"],1)
        self.assertEqual(self.bridge.workspace.usage()["totals"]["input_tokens"],100)
        self.assertGreater(state["received_query_bytes"],0)
        self.assertFalse(any(e["path"]=="helper.js" for e in state["evidence"].values()))
        lookup = next(iter(state["lookups"].values()))
        self.assertEqual(lookup["status"],"reserved")
        self.assertEqual(lookup["received_bytes"],state["received_query_bytes"])
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))

    def test_native_source_and_reuse_each_have_one_publication_fence(self):
        original = self.bridge.check
        checks = []
        def check():
            checks.append(True)
            return original()
        with patch.object(self.bridge,"check",side_effect=check):
            first = self.fx.turn("first",self.reply)
            # Prepare: two; review: entry, after paid, exit; publication: one.
            self.assertEqual(len(checks),6)
            checks.clear()
            second = self.fx.turn("reused",self.reply)
            self.assertEqual(len(checks),6)
        state = self.bridge.workspace.snapshot()
        a,b = (state["lookups"][r["lookup_ids"][0]] for r in (first,second))
        self.assertEqual(a["native_query_count"],1)
        self.assertEqual(b["native_query_count"],0)
        self.assertEqual(b["reused_from"],first["lookup_ids"][0])
        self.assertEqual(a["evidence"],b["evidence"])
        self.assertEqual(state["received_query_bytes"],a["received_bytes"]+b["received_bytes"])

    def test_source_change_after_native_read_rejects_capture_with_cost_retained(self):
        native = self.bridge.native
        def changed(arguments,*args,**kwargs):
            result = native(arguments,*args,**kwargs)
            if arguments[:2]==["investigate","source"]:
                # Keep the returned helper text intact; change a different file.
                app = self.bridge.root/"app.js"
                app.write_text(app.read_text()+"// source changed after lookup\n")
            return result
        with patch.object(self.bridge,"native",side_effect=changed):
            with self.assertRaises(CommandFailure):
                self.fx.turn("source-changed",self.reply)
        self.failed_publication()
        with self.assertRaises(CommandFailure):
            self.bridge.prepare("initial",self.fx.fixture.config_path,"no-next-paid-call")
        self.assertEqual(self.bridge.workspace.usage()["calls"],1)

    def test_change_during_transactional_capture_rolls_back_before_publication(self):
        read_source = state_module.source
        changed = []
        def source(root,path):
            data = read_source(root,path)
            if path=="helper.js" and not changed:
                changed.append(True)
                app = root/"app.js"
                app.write_text(app.read_text()+"// changed during source capture\n")
            return data
        with patch.object(state_module,"source",side_effect=source):
            with self.assertRaises(CommandFailure):
                self.fx.turn("capture-changed",self.reply)
        self.assertEqual(changed,[True])
        self.failed_publication()

    def test_owner_generation_change_after_lookup_rejects_publication(self):
        native = self.bridge.native
        def superseded(arguments,*args,**kwargs):
            result = native(arguments,*args,**kwargs)
            if arguments[:2]==["investigate","source"]:
                self.fx.fixture.native("state","claim","--store",str(self.bridge.store),"--stream","pilot",
                    "--inventory",str(self.bridge.inventory),"--source-root",str(self.bridge.root),
                    "--attempt-id","new-owner","--expected-generation","1","--retry","true",
                    "--operation-key","supersede-during-lookup")
            return result
        with patch.object(self.bridge,"native",side_effect=superseded):
            with self.assertRaises(CommandFailure):
                self.fx.turn("owner-changed",self.reply)
        self.failed_publication()
        with self.assertRaises(CommandFailure):
            self.bridge.prepare("initial",self.fx.fixture.config_path,"old-owner-cannot-dispatch")

    def test_changed_provider_descriptor_during_lookup_rejects_publication(self):
        native = self.bridge.native
        def changed(arguments,*args,**kwargs):
            result = native(arguments,*args,**kwargs)
            if arguments[:2]==["investigate","source"]:
                value = json.loads(self.bridge.provider_path.read_text())
                self.bridge.provider_path.write_text(json.dumps({**value,"model":"changed"}))
            return result
        with patch.object(self.bridge,"native",side_effect=changed):
            with self.assertRaisesRegex(ValueError,"provider binding differs"):
                self.fx.turn("provider-changed",self.reply)
        self.failed_publication()

    def test_plan_change_during_lookup_rejects_publication(self):
        native = self.bridge.native
        def changed(arguments,*args,**kwargs):
            result = native(arguments,*args,**kwargs)
            if arguments[:2]==["investigate","source"]:
                fx = self.fx.fixture
                plan = fx.native("state","plan-template","--inventory",str(self.bridge.inventory),
                    "--source-root",str(self.bridge.root),"--policy","comprehensive",
                    "--research-rounds","2","--skill-root",str(self.bridge.skill),
                    "--provider-contract",str(self.bridge.provider_path))
                path = fx.base/"changed-plan.json"
                path.write_text(json.dumps(plan))
                fx.native("state","plan",*fx.common,"--input",str(path),
                    "--expected-plan-id",self.bridge.payload["plan_id"],"--operation-key","plan-during-lookup")
            return result
        with patch.object(self.bridge,"native",side_effect=changed):
            with self.assertRaisesRegex(ValueError,"stale or altered"):
                self.fx.turn("plan-changed",self.reply)
        self.failed_publication()

    def test_changed_trusted_skill_during_capture_rejects_publication(self):
        copied = self.fx.fixture.base/"copied-skill"
        shutil.copytree(self.bridge.skill,copied,ignore=shutil.ignore_patterns("__pycache__"))
        self.bridge.skill = copied
        read_source = state_module.source
        def source(root,path):
            data = read_source(root,path)
            if path=="helper.js":
                reference = copied/"references/runtime-review.md"
                reference.write_text(reference.read_text()+"\nchanged during lookup\n",encoding="utf-8")
            return data
        with patch.object(state_module,"source",side_effect=source):
            with self.assertRaisesRegex(ValueError,"trusted skill changed"):
                self.fx.turn("skill-changed",self.reply)
        self.failed_publication()

    def test_unknown_paid_usage_prevents_lookup_dispatch(self):
        session = self.bridge.prepare("initial",self.fx.fixture.config_path,"unknown")['session_id']
        def unobserved(task):
            return {"workspace_actions":self.reply(task,{})}
        with self.assertRaisesRegex(ValueError,"usage is unknown"):
            self.bridge.review(session,self.fx.fixture.config_path,unobserved)
        state = self.bridge.workspace.snapshot()
        self.assertEqual(self.bridge.workspace.usage()["unobserved_calls"],1)
        self.assertEqual(state["used"]["queries"],0)
        self.assertEqual(state["lookups"],{})


if __name__=="__main__":
    unittest.main()
