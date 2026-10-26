"""Native AST and source-binding tests for deterministic work formation."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PRODUCT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PRODUCT / "scripts"))
import review_workspace_planner as planner
import review_worker as worker
from review_workspace import Workspace, identity


class WorkPlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-planner-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/"source"
        self.root.mkdir()
        self.scanner = Path(os.environ.get("MEHSCAN_TEST_SCANNER",PRODUCT/"target/debug"/("mehscan.exe" if os.name=="nt" else "mehscan")))
        if not self.scanner.exists(): self.skipTest("native scanner not built")
        self.entries = []
        self.engine = worker.digest_file(self.scanner)

    def file(self,path,text):
        file = self.root/path
        file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text(text,encoding="utf-8")

    def claim(self,path,line,symbol,capability="resource_access",rule="typescript-sequelize-resource-access"):
        self.entries.append(dict(review_id="claim-"+str(len(self.entries)),path=path,line=line,symbol=symbol,
                                 capability=capability,rule_id=rule))

    def native(self,operation,*values):
        result = subprocess.run([str(self.scanner),"investigate",operation,str(self.root),*values],
                                capture_output=True,text=True,encoding="utf-8")
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)

    def plan(self,native=None,**settings):
        self.inventory = {"entries":self.entries,"input_fingerprint":"fixture-inventory",
                          "identity_catalog":{"source_fingerprint":"fixture-snapshot"}}
        return planner.build(self.root,self.inventory,[e["review_id"] for e in self.entries],native or self.native,self.engine,**settings)

    def handler(self):
        self.file("handlers.ts","export function change(req: any) {\n"
                  "  first(req.params.id);\n  second(req.body.amount);\n}\n")
        self.claim("handlers.ts",2,"change")
        self.claim("handlers.ts",3,"change")

    def test_same_implementation_and_bound_wrapped_registration_share_work(self):
        self.handler()
        self.file("server.ts","import * as actions from './handlers'\n"
                  "const regex = /['{}\\/]/g\n"
                  "app.post('/change', auth(), utils.asyncHandler(actions.change()))\n")
        self.claim("server.ts",3,"change","authorization","framework-authorization-review-marker")
        p = self.plan()
        self.assertEqual(len(p["work"]),1)
        self.assertEqual(p["work"][0]["kind"],"shared_operation")
        self.assertEqual(len(p["work"][0]["review_ids"]),3)
        self.assertEqual(p["work"][0]["caller"]["route"],"/change")
        self.assertNotIn('"decision":',json.dumps(p))
        planner.validate(p,self.root,self.inventory,self.engine)

    def test_incompatible_guarded_and_unguarded_callers_stay_separate(self):
        self.handler()
        self.file("server.ts","import { change } from './handlers'\n"
                  "app.post('/guarded', requireAdmin(), change())\napp.post('/open', change())\n")
        p = self.plan()
        self.assertEqual([w["kind"] for w in p["work"]],["singleton","singleton"])
        self.assertTrue(all("multiple" in c["abstention"] for c in p["claims"]))

    def test_named_aliases_resolve_and_same_names_in_other_modules_do_not_merge(self):
        self.handler()
        self.file("other.ts","export function change(req: any) {\n other(req.params.id);\n}\n")
        self.file("server.ts","import { change as edit } from './handlers'\n"
                  "import { change as otherEdit } from './other'\n"
                  "app.post('/one', auth(), edit())\napp.post('/two', otherEdit())\n")
        self.claim("other.ts",2,"change")
        p = self.plan()
        self.assertEqual([w["kind"] for w in p["work"]],["shared_operation","singleton"])
        self.assertEqual(p["work"][0]["caller"]["route"],"/one")

    def test_shadowing_spreads_barrels_and_conditional_registration_abstain(self):
        self.handler()
        variations = [
            "function setup(change: any) {\n app.post('/x', change())\n}\n",
            "app.post('/x', ...guards, change())\n",
            "if (enabled) {\n app.post('/x', change())\n}\n",
            "app.use('/x', change())\n",
        ]
        for tail in variations:
            with self.subTest(tail=tail):
                self.file("server.ts","import { change } from './handlers'\n"+tail)
                self.assertTrue(all(w["kind"]=="singleton" for w in self.plan()["work"]))
        self.file("barrel.ts","export { change } from './handlers'\n")
        self.file("server.ts","import { change } from './barrel'\napp.post('/x', change())\n")
        self.assertTrue(all(w["kind"]=="singleton" for w in self.plan()["work"]))

    def test_namespace_escape_does_not_hide_an_incompatible_caller(self):
        self.handler()
        variants = [
            "import * as actions from './handlers'\nconst alias = actions\n"
            "app.post('/guarded', auth(), actions.change())\napp.post('/open', alias.change())\n",
            "import * as actions from './handlers'\n"
            "app.post('/guarded', auth(), actions.change())\napp.post('/open', actions.change.bind(other))\n",
            "import { change } from './handlers'\n"
            "app.post('/guarded', auth(), change())\napp.post('/open', change.bind(other))\n",
        ]
        for text in variants:
            with self.subTest(text=text):
                self.file("server.ts",text)
                self.assertTrue(all(w["kind"]=="singleton" for w in self.plan()["work"]))

    def test_export_alias_does_not_bind_an_import_to_a_private_same_named_function(self):
        self.handler()
        self.file("handlers.ts","function change(req: any) {\n first(req.params.id);\n second(req.body.amount);\n}\n"
                  "function actual(req: any) { return somethingElse(req); }\nexport { actual as change }\n")
        self.file("server.ts","import { change } from './handlers'\napp.post('/x', change())\n")
        p = self.plan()
        self.assertTrue(all(w["kind"]=="singleton" for w in p["work"]))

    def test_mixed_bound_and_raw_sql_batch_without_verdicts_and_respect_caps(self):
        for n in range(5):
            self.file("sql"+str(n)+".ts", "export function query"+str(n)+"(req: any) {\n"+
                (" return db.query('select * from users where name = $1', { bind: [req.query.name] });\n" if n%2 else
                 " return db.query('select * from users where name = ' + req.query.name);\n")+"}\n")
            self.claim("sql"+str(n)+".ts",2,"query"+str(n),"database_query","typescript-database-query")
        p = self.plan(max_group_size=3)
        self.assertEqual([len(w["review_ids"]) for w in p["work"]],[3,2])
        self.assertTrue(all(w["kind"]=="local_sql" for w in p["work"]))
        self.assertTrue(all(w["caller"] is None for w in p["work"]))
        self.assertNotIn('"decision":',json.dumps(p))
        tiny = self.plan(max_source_bytes=1)
        self.assertTrue(all(w["kind"]=="singleton" for w in tiny["work"]))

    def test_same_file_different_closure_families_remain_singletons(self):
        self.file("fixes.ts","export function fixes(req: any) {\n return load(read(req.body.key));\n}\n")
        self.claim("fixes.ts",2,"fixes","filesystem_read","typescript-filesystem-read")
        self.claim("fixes.ts",2,"fixes","deserialization","typescript-yaml-deserialization")
        def no_queries(*args): self.fail("unsupported families must not trigger discovery")
        p = self.plan(native=no_queries)
        self.assertEqual(len(p["work"]),2)
        self.assertEqual(p["planning"]["native_queries"],0)

        directory = self.root.parent/"inventory";directory.mkdir()
        (directory/"inventory.json").write_text(json.dumps(self.inventory))
        output = self.root.parent/"plan.json"
        result = subprocess.run([sys.executable,str(PRODUCT/"scripts/review_workspace_planner.py"),
            "--scanner",str(self.scanner),"--source-root",str(self.root),"--inventory",str(directory),
            "--review-ids",",".join(e["review_id"] for e in self.entries),"--output",str(output)],
            capture_output=True,text=True,encoding="utf-8")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)["native_queries"],0)
        self.assertIsNone(json.loads(output.read_text())["planning"]["journal_sha256"])

    def test_truncation_source_changes_and_edited_coverage_are_rejected(self):
        self.handler()
        self.file("server.ts","import { change } from './handlers'\napp.post('/x', change())\n")
        def truncated(operation,*args):
            result = self.native(operation,*args)
            if operation == "references": result["truncated"] = True
            return result
        p = self.plan(native=truncated)
        self.assertTrue(all(w["kind"]=="singleton" for w in p["work"]))
        p = self.plan()
        altered = copy.deepcopy(p)
        altered["work"][0]["review_ids"].pop()
        altered["plan_id"] = identity({k:v for k,v in altered.items() if k!="plan_id"})
        with self.assertRaisesRegex(ValueError,"membership"):
            planner.validate(altered,self.root,self.inventory,self.engine)
        self.file("handlers.ts",(self.root/"handlers.ts").read_text()+"// changed\n")
        with self.assertRaisesRegex(ValueError,"source changed"):
            planner.validate(p,self.root,self.inventory,self.engine)


class AtomicPlanningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-plan-atomic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/"source";self.root.mkdir()
        (self.root/"a.js").write_text("function handler(req) {\n return req.body;\n}\n")
        self.workspace = Workspace.create(Path(self.temp.name)/"workspace.sqlite",self.root,
            {"snapshot_id":"snapshot","plan_id":"native-plan","runtime_id":"runtime"},
            [{"review_id":r,"path":"a.js","line":2,"property":"selected relationship","bundle_id":"bundle"}
             for r in ["first","second"]],{"model_calls":6,"queries":8,"source_bytes":4096})

    def action(self):
        digest = worker.digest_file(self.root/"a.js")
        return {"kind":"prepare_work","planning_id":"fixture-plan","max_context_bytes":32768,"work":[
            {"work_id":"together","review_ids":["first","second"],"strategy":"shared operation",
             "evidence_ids":[],"windows":[{"path":"a.js","start_line":1,"end_line":3,
                "file_sha256":digest,"review_id":"first"}],"limits":["Only the supplied caller scope is grouped."]}]}

    def test_atomic_preparation_preserves_claims_and_is_replayable(self):
        action = self.action()
        receipt = self.workspace.apply("plan",0,action)
        state = self.workspace.snapshot()
        self.assertEqual(state["work"]["initial"]["claims"],[])
        self.assertEqual(state["work"]["together"]["claims"],["first","second"])
        self.assertFalse(state["calls"])
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))
        self.assertEqual(self.workspace.apply("plan",0,action),{**receipt,"replayed":True})

    def test_late_failure_duplicate_coverage_and_overflow_leave_no_partial_work(self):
        for variant in ["stale","duplicate","overflow"]:
            action = self.action()
            if variant == "stale": action["work"][0]["windows"][0]["file_sha256"] = "0"*64
            if variant == "duplicate": action["work"][0]["review_ids"].append("first")
            if variant == "overflow": action["max_context_bytes"] = 1
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                self.workspace.apply("failed-"+variant,0,action)
            self.assertEqual(self.workspace.snapshot()["revision"],0)
            self.assertEqual(set(self.workspace.snapshot()["work"]),{"initial"})
            self.assertIsNone(self.workspace.operation("failed-"+variant))

    def test_planning_cannot_replace_an_active_session(self):
        self.workspace.apply("session",0,{"kind":"session","work_id":"initial",
                            "parent_session":None,"max_bytes":32768})
        before = self.workspace.snapshot()
        with self.assertRaisesRegex(ValueError,"fresh unassigned"):
            self.workspace.apply("too-late",before["revision"],self.action())
        self.assertEqual(self.workspace.snapshot(),before)


class NativePlanApplicationTests(unittest.TestCase):
    def test_native_bound_grouping_applies_once_without_model_or_verdicts(self):
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        import test_workspace_bridge as fixtures
        fixture = fixtures.NativeBridgeTests(methodName="test_rejected_completed_reply_still_records_usage")
        fixture.extra_source = {
            "handlers.ts":"import { UserModel, CardModel } from './models'\n"
                "export function change() {\n return async (req: any, res: any) => {\n"
                " const user = await UserModel.findOne({ where: { id: req.params.id } })\n"
                " const card = await CardModel.findOne({ where: { id: req.body.cardId } })\n"
                " res.json({ user, card })\n }\n}\n",
            "server.ts":"import { change } from './handlers'\n"
                "app.post('/change', auth(), change())\n"}
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        bridge = fixture.create()
        inventory = worker.read(fixture.inventory/"inventory.json")
        ids = list(bridge.workspace.snapshot()["claims"])
        native = lambda op,*values:fixture.native("investigate",op,str(fixture.root),*values)
        plan = planner.build(fixture.root,inventory,ids,native,worker.digest_file(fixture.scanner))
        shared = [w for w in plan["work"] if w["kind"]=="shared_operation"]
        self.assertEqual(len(shared),1)
        self.assertEqual(len(shared[0]["review_ids"]),2)
        with bridge.guarded():
            first = planner.apply_plan(bridge,plan)
            revision = bridge.workspace.snapshot()["revision"]
            self.assertEqual(planner.apply_plan(bridge,plan),first)
        state = bridge.workspace.snapshot()
        self.assertEqual(state["revision"],revision)
        self.assertFalse(state["sessions"])
        self.assertFalse(state["calls"])
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))
        self.assertFalse(state["work"]["initial"]["claims"])
        view = bridge.workspace.view(shared[0]["id"])
        self.assertEqual(len(view["claims"]),2)
        self.assertTrue(any(e["path"]=="handlers.ts" and e["start_line"]==2 and e["end_line"]==8
                            for e in view["evidence"].values()))
        self.assertTrue(any(e["path"]=="server.ts" and e["start_line"]==2 for e in view["evidence"].values()))


if __name__ == "__main__":
    unittest.main()
