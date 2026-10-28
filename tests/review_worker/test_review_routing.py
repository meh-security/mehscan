"""Route coverage, bounded evidence and source freshness; no provider or scanner."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PRODUCT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PRODUCT/"scripts"))
import review_routing as routing
import review_worker as worker
import review_workspace_planner as planner
from review_workspace import identity


class ReviewRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-routing-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/"source";self.root.mkdir()
        (self.root/"handlers.ts").write_text("export function change(req) {\n first(req.params.id);\n second(req.body);\n}\n",encoding="utf-8")
        (self.root/"server.ts").write_text("import {change} from './handlers'\napp.post('/x', auth(), change())\n",encoding="utf-8")
        self.inventory = {"input_fingerprint":"input", "identity_catalog":{"source_fingerprint":"snapshot"},"entries":[]}
        self.manifest = {"root":str(self.root),"max_reviews_per_bundle":20,"bundles":[]}

    def entry(self,rid,capability="resource_access",rule="typescript-sequelize-resource-access",line=2):
        entry = dict(review_id=rid,path="handlers.ts",line=line,symbol="change",capability=capability,rule_id=rule)
        self.inventory["entries"].append(entry)
        return entry

    def bundle(self,*ids,bid="original"):
        self.manifest["bundles"].append({"bundle_fingerprint":bid,"review_ids":list(ids),"review_count":len(ids)})

    def window(self,path="handlers.ts",first=1,last=4):
        return dict(path=path,start_line=first,end_line=last,file_sha256=worker.digest_file(self.root/path))

    def planner(self):
        unit = {"id":"unit", "frame":{**self.window(),"bytes":100}}
        caller = {"id":"caller", "frame":{**self.window("server.ts",2,2),"bytes":40},
                  "binding_frames":[{**self.window("server.ts",1,1),"bytes":35}]}
        claims = [{"entry":{k:e[k] for k in planner.ENTRY_FIELDS},"unit":unit,"caller":caller,"abstention":None}
                  for e in self.inventory["entries"]]
        settings = dict(max_group_size=4,max_source_bytes=32768)
        p = {"schema_version":planner.VERSION,"binding":{"source_fingerprint":"snapshot",
             "inventory_input_fingerprint":"input","engine_sha256":"engine","planner_sha256":worker.digest_file(planner.__file__)},
             "selected_review_ids":[e["review_id"] for e in self.inventory["entries"]],"claims":claims,
             "work":planner.form_work(claims,**settings),"files":{p:worker.digest_file(self.root/p) for p in ("handlers.ts","server.ts")},
             "helper_evidence":None,"settings":settings,"planning":{"native_queries":3,"elapsed_ms":12}}
        p["plan_id"] = identity(p)
        return p

    def spec(self,ids,kind="shared_dependency",route="workspace"):
        return dict(review_ids=ids,route=route,kind=kind,deciding_question="Does the shared helper's condition hold in each caller?",
                    reason="Share the helper investigation while checking caller configuration separately.",
                    caller_checks={rid:"Inspect the actual caller arguments and the effect for "+rid for rid in ids} if route=="workspace" else {},
                    evidence_windows=[self.window()] if route=="workspace" else [],
                    limits=["Source binding is not proof of compatible caller behavior."])

    def selections(self,*specs):
        return dict(schema_version=routing.SELECTION_VERSION,binding=routing.input_binding(self.inventory,self.manifest),selections=list(specs))

    def build(self,**options):
        return routing.build(self.root,self.inventory,self.manifest,**options)

    def test_local_and_unsupported_claims_preserve_native_batching_without_caller_discovery(self):
        self.entry("sql","database_query","typescript-database-query")
        self.entry("cookie","cookie_configuration","typescript-auth-cookie-missing-secure")
        self.entry("yaml","deserialization","typescript-yaml-deserialization")
        self.entry("nosql","database_query","typescript-nosql-query-selector")
        self.entry("owner")
        self.bundle("sql","cookie","yaml","nosql","owner")
        p=self.build()
        self.assertEqual([r["strategy"] for r in p["claims"]],["local_sql","local_api","local_api","local_query","native_fallback"])
        self.assertEqual(len(p["native_packets"]),1)
        self.assertEqual(p["native_packets"][0]["review_ids"],p["selected_review_ids"])
        self.assertEqual(p["investigations"],[])
        self.assertFalse(p["dispatch_ready"])
        self.assertEqual(p["preparation"]["native_queries"],0)
        self.assertEqual(p["dispatch_effects"]["dispatch_unit_delta"],0)
        self.assertNotIn('"decision":',json.dumps(p))

    def test_native_normalized_display_root_binds_explicit_physical_source(self):
        self.entry("a");self.bundle("a")
        self.manifest["root"]="."
        p=self.build()
        self.assertEqual(p["binding"]["source_root"],str(self.root.resolve()))
        self.assertEqual(p["files"]["handlers.ts"],worker.digest_file(self.root/"handlers.ts"))

    def test_sql_planner_group_stays_native_while_bound_operation_uses_workspace(self):
        self.entry("sql-a","database_query","typescript-database-query")
        self.entry("sql-b","database_query","typescript-database-query")
        self.entry("owner-a");self.entry("owner-b")
        self.bundle("sql-a","sql-b","owner-a","owner-b")
        p=self.build(planner_plan=self.planner(),engine_sha256="engine")
        self.assertEqual([r["route"] for r in p["claims"]],["native","native","workspace","workspace"])
        self.assertEqual(p["native_packets"][0]["workspace_review_ids"],["owner-a","owner-b"])
        self.assertEqual(p["investigations"][0]["review_ids"],["owner-a","owner-b"])
        self.assertEqual(set(p["investigations"][0]["caller_checks"]),{"owner-a","owner-b"})
        self.assertEqual(p["preparation"]["upstream_planner"]["native_queries"],3)
        self.assertEqual(p["claims"][0]["original_bundle_id"],"original")
        self.assertEqual(p["dispatch_effects"]["dispatch_unit_delta"],1)
        self.assertEqual(p["dispatch_effects"]["split_original_bundle_ids"],["original"])
        self.assertTrue(p["dispatch_effects"]["workspace_groups"][0]["already_one_native_packet"])

    def test_explicit_fact_question_keeps_distinct_caller_checks_and_can_span_original_bundles(self):
        self.entry("safe","html_output","html-rule");self.entry("hooked","html_output","html-rule")
        self.bundle("safe",bid="one");self.bundle("hooked",bid="two")
        options={"selections":self.selections(self.spec(["safe","hooked"]))}
        p=self.build(**options)
        self.assertEqual(p["native_packets"],[])
        self.assertEqual({r["original_bundle_id"] for r in p["claims"]},{"one","two"})
        self.assertEqual(p["investigations"][0]["origin"],"explicit_selection")
        self.assertEqual(p["preparation"]["selection_labor_ms"],None)
        self.assertEqual(p["dispatch_effects"]["dispatch_unit_delta"],-1)
        self.assertFalse(p["dispatch_effects"]["workspace_groups"][0]["already_one_native_packet"])
        text=routing.render(p)
        self.assertIn("actual caller arguments",text)
        self.assertIn(self.window()["file_sha256"],text)
        routing.validate(p,self.root,self.inventory,self.manifest,**options)

    def test_explicit_native_exception_splits_shared_operation_without_losing_peers(self):
        for rid in ("one","two","three"):self.entry(rid)
        self.bundle("one","two","three")
        p=self.build(planner_plan=self.planner(),engine_sha256="engine",
                     selections=self.selections(self.spec(["one"],kind="native_local",route="native")))
        self.assertEqual([r["route"] for r in p["claims"]],["native","workspace","workspace"])
        shared=next(w for w in p["investigations"] if w["route"]=="workspace")
        self.assertEqual(shared["review_ids"],["two","three"])

    def test_targeted_relationship_does_not_promote_every_credential_claim(self):
        self.entry("target","authentication","credential-rule");self.entry("local","authentication","credential-rule")
        self.bundle("target","local")
        p=self.build(selections=self.selections(self.spec(["target"],kind="relationship")))
        self.assertEqual([r["route"] for r in p["claims"]],["workspace","native"])

    def test_oversized_operation_proposal_retains_native_with_visible_limit(self):
        (self.root/"handlers.ts").write_text("call();\n"*401,encoding="utf-8")
        self.entry("a");self.entry("b");self.bundle("a","b")
        pplan=self.planner()
        for info in pplan["claims"]:info["unit"]["frame"]["end_line"]=401
        pplan["plan_id"]=identity({k:v for k,v in pplan.items() if k!="plan_id"})
        p=self.build(planner_plan=pplan,engine_sha256="engine")
        self.assertEqual([r["route"] for r in p["claims"]],["native","native"])
        self.assertTrue(all("source bounds" in r["promotion_limit"] for r in p["claims"]))
        self.assertIn("source bounds",routing.render(p))

    def test_duplicate_missing_foreign_and_singleton_baselines_are_rejected(self):
        self.entry("a");self.entry("b");self.bundle("a","b")
        for variant in ("duplicate","unknown","count","singleton","root"):
            manifest=copy.deepcopy(self.manifest)
            if variant=="duplicate":manifest["bundles"].append(copy.deepcopy(manifest["bundles"][0]))
            if variant=="unknown":manifest["bundles"][0]["review_ids"][1]="foreign"
            if variant=="count":manifest["review_count"]=3
            if variant=="singleton":manifest["max_reviews_per_bundle"]=1
            if variant=="root":manifest["root"]=str(self.base)
            with self.subTest(variant=variant),self.assertRaises(ValueError):
                routing.build(self.root,self.inventory,manifest)

    def test_selections_reject_overlaps_stale_binding_missing_checks_and_unsupported_sharing(self):
        self.entry("a");self.entry("b");self.bundle("a","b")
        for variant in ("overlap","binding","checks","source","path","coordinates","one_shared","kind"):
            specs=self.selections(self.spec(["a","b"]))
            spec=specs["selections"][0]
            if variant=="overlap":specs["selections"].append(copy.deepcopy(spec))
            if variant=="binding":specs["binding"]["source_fingerprint"]="other"
            if variant=="checks":spec["caller_checks"].pop("b")
            if variant=="source":spec["evidence_windows"][0]["file_sha256"]="stale"
            if variant=="path":spec["evidence_windows"][0]["path"]="../outside.ts"
            if variant=="coordinates":spec["evidence_windows"][0]["end_line"]=5
            if variant=="one_shared":spec["review_ids"]=["a"]
            if variant=="kind":spec["kind"]="shared_verdict"
            with self.subTest(variant=variant),self.assertRaises(ValueError):self.build(selections=specs)

    def test_modified_route_and_nonanchor_dependency_source_invalidate_saved_proposal(self):
        self.entry("a");self.entry("b");self.bundle("a","b")
        pplan=self.planner();options=dict(planner_plan=pplan,engine_sha256="engine")
        p=self.build(**options)
        forged=copy.deepcopy(p);forged["claims"][0]["route"]="native"
        forged["routing_id"]=identity({k:v for k,v in forged.items() if k!="routing_id"})
        with self.assertRaisesRegex(ValueError,"differ"):routing.validate(forged,self.root,self.inventory,self.manifest,**options)
        (self.root/"server.ts").write_text("changed();\n",encoding="utf-8")
        with self.assertRaisesRegex(ValueError,"source changed"):routing.validate(p,self.root,self.inventory,self.manifest,**options)

    def test_cli_inspection_roundtrip_refuses_overwrite_and_keeps_output_outside_source(self):
        self.entry("a");self.bundle("a")
        inv=self.base/"inventory.json";manifest=self.base/"manifest.json"
        worker.write(inv,self.inventory);worker.write(manifest,self.manifest)
        command=[sys.executable,str(PRODUCT/"scripts/review_routing.py"),"--source-root",str(self.root),
                 "--inventory",str(inv),"--manifest",str(manifest)]
        output=self.base/"routing"
        result=subprocess.run(command+["--output",str(output)],capture_output=True,text=True,encoding="utf-8")
        self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertEqual((receipt["model_calls"],receipt["native_queries"]),(0,0))
        self.assertEqual(subprocess.run(command+["--check",str(output)],capture_output=True).returncode,0)
        original=(output/"routing.json").read_bytes()
        self.assertNotEqual(subprocess.run(command+["--output",str(output)],capture_output=True).returncode,0)
        self.assertEqual((output/"routing.json").read_bytes(),original)
        self.assertNotEqual(subprocess.run(command+["--output",str(self.root/"invalid")],capture_output=True).returncode,0)
        self.assertFalse((self.root/"invalid").exists())


if __name__ == "__main__":
    unittest.main()
