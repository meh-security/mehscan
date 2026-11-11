"""Causal presentation and bounded proof selection never change native verdicts."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_second_pass as review


def metadata(identity="one", line=10, **changes):
    return {"review_id":identity, "root":{"path":"shared.ts","start_line":line,"end_line":line},
        "property":"authorization", "applicability":"active", "basis":"The registered route calls this guard.",
        "kind":"application_path", "impact":"source_supported", "conditions":"A restricted authenticated caller.", **changes}


def row(identity="one", decision="issue"):
    return {"review_id":identity, "decision":decision, "summary":"The selected caller lacks the required grant.",
        "diagnosis":{"severity":"high"}, "evidence":[{"path":"shared.ts","start_line":10,"end_line":11}],
        "checks":[]}


class ClaimContext(unittest.TestCase):
    def test_metadata_is_stripped_without_rewriting_the_assessment(self):
        original=row(); draft={"results":[{**original,"claim_context":{k:v for k,v in metadata().items() if k != "review_id"}}]}
        self.assertEqual(review.take_claim_contexts(draft),[metadata()])
        self.assertEqual(draft,{"results":[original]})

    def test_unread_roots_and_invalid_metadata_cannot_drive_grouping(self):
        for value in (metadata(line=12), metadata(impact="invented"),metadata(basis=" "),
                      metadata(root={"path":"shared.ts","start_line":True,"end_line":10}),
                      metadata(root={"path":"shared.ts","start_line":1,"end_line":30})):
            with self.subTest(value=value),self.assertRaises(ValueError):
                review.take_claim_contexts({"results":[{**row(),"claim_context":{k:v for k,v in value.items() if k != "review_id"}}]})

    def test_invalid_advisory_annotation_does_not_discard_the_native_assessment(self):
        original=row(); errors=[]
        value={k:v for k,v in metadata(line=100).items() if k != "review_id"}
        draft={"results":[{**original,"claim_context":value}]}
        self.assertEqual(review.take_claim_contexts(draft,errors=errors),[])
        self.assertEqual(draft,{"results":[original]})
        self.assertEqual(errors[0]["review_id"],"one")

    def test_shared_root_keeps_all_callers_and_distinct_conditions(self):
        rows=[row("one"),row("two")]; before=copy.deepcopy(rows)
        values=[metadata("one"),metadata("two",applicability="supported_optional",conditions="Enabled alternate route.")]
        grouped=review.group_claims(rows,values)
        self.assertEqual((grouped["claim_count"],grouped["group_count"]),(2,1))
        self.assertEqual([m["review_id"] for m in grouped["groups"][0]["members"]],["one","two"])
        self.assertEqual(grouped["groups"][0]["members"][1]["first_pass_context"]["conditions"],"Enabled alternate route.")
        self.assertEqual(rows,before)

    def test_similar_titles_or_cwes_do_not_merge_different_roots_or_decisions(self):
        rows=[row("one"),row("two"),row("three","not_issue"),row("four")]
        values=[metadata("one"),metadata("two",line=20),metadata("three")]
        self.assertEqual(review.group_claims(rows,values)["group_count"],4)
        self.assertEqual(review.group_claims(rows,[])["group_count"],4)

    def test_risky_positive_can_be_selected_without_self_nomination(self):
        rows=[row("one"),row("two","needs_review"),row("three"),row("four")]
        values=[metadata("one",applicability="dormant"),metadata("three")]
        before=copy.deepcopy(rows)
        plan=review.select_followups(rows,[],contexts=values)
        self.assertEqual([n["review_id"] for n in plan["selected"]],["one"])
        self.assertEqual(plan["selected"][0]["selection_source"],"positive_proof_signal")
        self.assertEqual(plan["selection_model_calls"],0)
        self.assertEqual(rows,before)

    def test_positive_checks_diversify_repair_points_and_preserve_deferred_siblings(self):
        rows=[row(str(i)) for i in range(12)]
        values=[metadata(str(i),line=10 if i < 4 else 20+i,impact="unresolved") for i in range(6)]
        plan=review.select_followups(rows,[],contexts=values)
        self.assertEqual(len(plan["selected"]),3)
        self.assertEqual({r["review_id"] for r in plan["selected"]},{"0","4","5"})
        self.assertEqual({r["reason"] for r in plan["deferred"]},{"shared_repair_point"})

    def test_supported_optional_library_contract_is_not_an_activation_error(self):
        value=metadata(kind="security_contract",applicability="supported_optional")
        self.assertEqual(review.select_followups([row()],[],contexts=[value])["selected"],[])
        value["impact"]="conditional"
        plan=review.select_followups([row()],[],contexts=[value])
        self.assertEqual(plan["selected"][0]["reasons"][0]["reason"],"control_applicability")
        self.assertEqual(row()["decision"],"issue")

    def test_scope_and_external_blockers_still_exclude_positive_checks(self):
        value=metadata(impact="unresolved")
        plan=review.select_followups([row()],[],contexts=[value],scope=("needs_review",))
        self.assertEqual(plan["selected"],[])
        pending=row(decision="needs_review")
        note={"review_id":"one","reason":"external_required","question":"Obtain the named external policy."}
        self.assertEqual(review.select_followups([pending],[note],contexts=[value])["selected"],[])
        with self.assertRaises(ValueError):review.select_followups([row()],[],contexts=[metadata("foreign")])

    def test_metadata_is_loaded_only_from_bound_first_pass_investigator_jobs(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/"jobs").mkdir()
            for key,role,cycle in [("first","investigator",None),("audit","investigator","second_pass_fast_check"),("qa","final_qa",None)]:
                (root/"jobs"/(key+".json")).write_text(json.dumps({"binding":{"role":role,"assessment_cycle":cycle,
                    "review_ids":["one"]},"claim_contexts":[metadata()]}))
            self.assertEqual(review.claim_contexts(root,["one"]),[metadata()])
            (root/"jobs/forged.json").write_text(json.dumps({"binding":{"role":"investigator","review_ids":["two"]},
                "claim_contexts":[metadata()]}))
            with self.assertRaises(ValueError):review.claim_contexts(root,["one"])

    def test_export_retains_native_counts_and_marks_first_context_historical(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            def write(path,value):path.write_text(json.dumps(value))
            grouped=review.write_groups(root,[row(),row("two","needs_review")],[metadata(),metadata("two")],write)
            self.assertEqual(grouped["claim_labels"],{"issue":1,"needs_review":1})
            self.assertIn("first_pass",grouped["context_stage"])
            self.assertTrue((root/"finding-groups.md").is_file())


if __name__ == "__main__":unittest.main()
