"""Bounded notebook delivery across owner-scoped and route-ID effects."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace as fixtures
from review_workspace import Workspace
from review_workspace_notebook import export_notebook, import_notebook
from review_workspace_actions import _lookup


class NotebookTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.WorkspaceTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.code.write_text("function appendUserId(req) { req.body.UserId = verifiedTokenMap[token(req)].data.id; }\n"
            "app.get('/wallet', appendUserId, req => Wallet.findOne({where:{UserId:req.body.UserId}}));\n"
            "app.put('/basket/:id', appendUserId, req => BasketItem.findOne({where:{id:req.params.id}}));\n"
            "app.post('/generated', generateResource);\n")
        self.f.proposition(self.f.capture())
        self.notebook = export_notebook(self.f.workspace)
        self.target = Workspace.create(self.f.directory / "consumer.sqlite",self.f.root,self.f.binding,self.f.claims,self.f.limits)

    def test_notebook_delivery_has_no_applicability_or_verdict_and_keeps_exception(self):
        receipt = import_notebook(self.target,self.notebook,"initial")
        view = self.target.view("initial")
        pid = receipt["propositions"]["body-owner"]["proposition_id"]
        self.assertIn(pid,view["propositions"])
        self.assertIn("Route parameters",view["propositions"][pid]["exclusions"])
        self.assertEqual(view["applicability"],{})
        self.assertTrue(all(c["draft"] is None for c in self.target.snapshot()["claims"].values()))
        self.assertEqual(self.target.usage()["calls"],0)
        for claim,line,verdict in (("safe",2,"not_issue"),("unsafe",3,"issue")):
            proof = self.target.apply("caller:"+claim,self.target.snapshot()["revision"],
                {"kind":"source","path":"routes.ts","start_line":line,"end_line":line,"review_id":claim})["result"]["evidence_id"]
            applies = self.target.apply("applies:"+claim,self.target.snapshot()["revision"],
                {"kind":"applicability","review_id":claim,"proposition_id":pid,"proposition_revision":1,
                 "evidence":[proof],"reason":"Check the selected body owner versus route ID effect"})["result"]["applicability_id"]
            # Use the existing draft fixture against the independent consumer.
            original = self.f.workspace
            self.f.workspace = self.target
            try:
                self.f.draft(claim,verdict,line,[applies])
            finally:
                self.f.workspace = original
        state = self.target.snapshot()
        self.assertEqual(state["claims"]["safe"]["draft"]["result"]["decision"],"not_issue")
        self.assertEqual(state["claims"]["unsafe"]["draft"]["result"]["decision"],"issue")
        self.assertIsNone(state["claims"]["unknown"]["draft"])
        self.target.apply("missing",self.target.snapshot()["revision"],{"kind":"question","question_id":"missing-caller",
            "review_ids":["unknown"],"question":"Does the unavailable generated effect constrain the owner?"})
        self.target.apply("blocked",self.target.snapshot()["revision"],{"kind":"answer","question_id":"missing-caller",
            "status":"blocked","reason":"The generated implementation is not supplied","evidence":[]})
        self.target.apply("unknown-source",self.target.snapshot()["revision"],{"kind":"source","review_id":"unknown",
            "path":"routes.ts","start_line":4,"end_line":4})
        original = self.f.workspace
        self.f.workspace = self.target
        try:
            self.f.draft("unknown","needs_review",4,checks=["Does the generated effect constrain the owner?"])
        finally:
            self.f.workspace = original
        self.assertEqual(self.target.snapshot()["claims"]["unknown"]["draft"]["result"]["decision"],"needs_review")

    def test_same_notebook_can_focus_two_distinct_work_items(self):
        self.target.apply("split",0,{"kind":"split","work_id":"initial","new_work_id":"exception",
            "review_ids":["unsafe"],"strategy":"authorization"})
        import_notebook(self.target,self.notebook,"initial")
        import_notebook(self.target,self.notebook,"exception")
        self.assertEqual(self.target.view("initial")["propositions"],self.target.view("exception")["propositions"])
        self.assertEqual(self.target.view("exception")["applicability"],{})

    def test_disabled_cross_work_lookup_does_not_hide_explicit_notebook(self):
        import_notebook(self.target,self.notebook,"initial")
        bridge = SimpleNamespace(workspace=self.target,metadata={"experiment":{"knowledge_lookup":False}})
        result,evidence,count,_ = _lookup(bridge,{"tool":"knowledge","arguments":{"name":"body-owner"}},[],"disabled")
        self.assertEqual(result["propositions"],{})
        self.assertEqual((evidence,count),([],0))
        self.assertTrue(self.target.view("initial")["propositions"])

    def test_interrupted_import_resumes_without_revising_or_duplicate_source(self):
        original = self.target.apply
        calls = []
        def interrupt(*args):
            calls.append(args[2]["kind"])
            if len(calls) == 2:
                raise InterruptedError("interrupted after source capture")
            return original(*args)
        with patch.object(self.target,"apply",side_effect=interrupt),self.assertRaises(InterruptedError):
            import_notebook(self.target,self.notebook,"initial")
        self.assertEqual(self.target.view("initial")["propositions"],{})
        result = import_notebook(self.target,self.notebook,"initial")
        before = self.target.snapshot()
        self.assertEqual(import_notebook(self.target,self.notebook,"initial"),result)
        self.assertEqual(self.target.snapshot(),before)

    def test_stale_source_wrong_binding_and_overflow_do_not_mutate_recipient(self):
        before = self.target.snapshot()
        changed = copy.deepcopy(self.notebook)
        changed["producer_binding"]["snapshot_id"] = "another-source"
        with self.assertRaisesRegex(ValueError,"binding differs"):
            import_notebook(self.target,changed,"initial")
        with self.assertRaisesRegex(ValueError,"byte limit"):
            export_notebook(self.f.workspace,max_bytes=10)
        self.f.code.write_text(self.f.code.read_text()+"// changed\n")
        with self.assertRaisesRegex(ValueError,"stale"):
            import_notebook(self.target,self.notebook,"initial")
        self.assertEqual(self.target.snapshot(),before)

    def test_updated_note_reopens_consumers_and_old_import_cannot_resurrect_it(self):
        receipt = import_notebook(self.target,self.notebook,"initial")
        pid = receipt["propositions"]["body-owner"]["proposition_id"]
        self.target.apply("dependency",self.target.snapshot()["revision"],{"kind":"applicability","review_id":"safe",
            "proposition_id":pid,"proposition_revision":1,"evidence":list(receipt["evidence"].values()),
            "reason":"Caller relationship separately established"})
        self.f.proposition(self.f.capture(),statement="Binding constrains body.UserId only; route ID ownership remains unproved.")
        newer = export_notebook(self.f.workspace)
        second = import_notebook(self.target,newer,"initial")
        self.assertEqual(second["propositions"]["body-owner"]["recipient_revision"],2)
        self.assertIn(pid,self.target.snapshot()["claims"]["safe"]["reconsideration"])
        self.target.apply("dispute",self.target.snapshot()["revision"],{"kind":"dispute","proposition_id":pid,"reason":"Caller identity contract needs verification"})
        with self.assertRaisesRegex(ValueError,"resurrect"):
            import_notebook(self.target,self.notebook,"initial")


if __name__ == "__main__":
    unittest.main()
