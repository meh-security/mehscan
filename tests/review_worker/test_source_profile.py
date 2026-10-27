"""Explicit source delivery and binding; no model/security oracle."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_context as context
import review_source_profile as profiles


class SourceProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = {"repository":{"repository_key":"test", "path_prefix":""},
                        "inventory_input_fingerprint":"input", "review_ids":["a", "b", "c"]}
        self.windows = []
        for i in range(8):
            path = self.root / (str(i) + ".ts")
            path.write_text("export const x = " + str(i) + ";\n", encoding="utf-8")
            self.windows.append({"path":path.name, "start_line":1, "end_line":1,
                                 "file_sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
        self.profile = {"schema_version":profiles.VERSION, "repository":self.payload["repository"],
                        "inventory_input_fingerprint":"input",
                        "targets":[{"review_ids":["a","b"], "windows":self.windows}]}

    def test_eight_windows_are_exact_independently_of_four_automatic_leads(self):
        profile = profiles.validate(self.profile,self.payload)
        profiles.check_bundles(profile,[["b","a"],["c"]])
        value = profiles.prepare(self.root,profile,["b","a"],"snapshot")
        self.assertEqual(len(value["windows"]),8)
        self.assertFalse(value["limits"])
        self.assertTrue(all(not w["clipped"] for w in value["windows"]))
        leads=[{"role":"application_policy_context","location":{k:w[k] for k in ("path","start_line","end_line")}}
               for w in self.windows]
        automatic=context.prepare_application(self.root,{"reviews":[{"application_context":leads}]},{},"snapshot")
        self.assertEqual(len(automatic["windows"]),4)
        self.assertTrue(automatic["limits"])
        self.assertFalse(profiles.prepare(self.root,profile,["c"],"snapshot")["windows"])

    def test_wrong_binding_scope_overlap_and_interpretation_fields_are_rejected(self):
        mutations = [lambda p:p.update(inventory_input_fingerprint="other"),
                     lambda p:p.update(repository={"repository_key":"other","path_prefix":""}),
                     lambda p:p["targets"][0].update(review_ids=["foreign"]),
                     lambda p:p["targets"].append(copy.deepcopy(p["targets"][0])),
                     lambda p:p["targets"][0].update(verdict="not_issue"),
                     lambda p:p["targets"][0]["windows"].append(copy.deepcopy(self.windows[0]))]
        for mutation in mutations:
            p=copy.deepcopy(self.profile);mutation(p)
            with self.subTest(profile=p),self.assertRaises(ValueError):
                profiles.validate(p,self.payload)
        with self.assertRaisesRegex(ValueError,"membership"):
            profiles.check_bundles(self.profile,[["a"],["b","c"]])
        with self.assertRaisesRegex(ValueError,"membership"):
            profiles.prepare(self.root,self.profile,["a"],"snapshot")

    def test_stale_source_ranges_escape_and_budget_are_fatal_without_clipping(self):
        for change in ({"path":"../0.ts"},{"start_line":True},{"end_line":401},{"file_sha256":"bad"}):
            p=copy.deepcopy(self.profile);p["targets"][0]["windows"][0].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):
                profiles.validate(p,self.payload)
        p=copy.deepcopy(self.profile);p["targets"][0]["windows"][0]["end_line"]=2
        with self.assertRaisesRegex(ValueError,"range"):
            profiles.prepare(self.root,p,["a","b"],"snapshot")
        (self.root/"0.ts").write_text("changed")
        with self.assertRaisesRegex(ValueError,"changed"):
            profiles.prepare(self.root,self.profile,["a","b"],"snapshot")
        huge=self.root/"huge.ts";huge.write_text("x"*16385)
        p=copy.deepcopy(self.profile);p["targets"][0]["windows"]=[{
            "path":"huge.ts","start_line":1,"end_line":1,"file_sha256":hashlib.sha256(huge.read_bytes()).hexdigest()}]
        with self.assertRaisesRegex(ValueError,"not clipped"):
            profiles.prepare(self.root,p,["a","b"],"snapshot")

    def test_duplicate_source_is_reused_without_losing_pinned_base_or_snapshot_binding(self):
        a=profiles.prepare(self.root,self.profile,["a","b"],"one")["windows"]
        b=profiles.prepare(self.root,self.profile,["a","b"],"two")["windows"]
        self.assertNotEqual(a[0]["artifact_id"],b[0]["artifact_id"])
        self.assertEqual(len(profiles.combine(a,a)),8)
        self.assertEqual(len(profiles.combine(a,[{**a[0],"side":"base"}])) ,9)


if __name__ == "__main__":
    unittest.main()
