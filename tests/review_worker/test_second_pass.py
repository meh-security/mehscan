"""Second-pass authority, provenance and partial execution regressions."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import review_second_pass as review


def result(identity="one", decision="not_issue"):
    return {"review_id":identity, "decision":decision, "confidence":"medium", "summary":"Scoped original proof.",
        "checks":[], "investigation":{"decisive_artifacts":[], "reviewer_inferences":[{"claim":"Actual local claim."}],
            "reviewer_origin_leads":[], "blockers":[]}}


def check(identity="one", action="keep", proof="supported", claim=""):
    return {"review_id":identity, "action":action, "claim":claim, "proof_status":proof,
        "investigation_status":"sufficient", "error_codes":[]}


class SecondPass(unittest.TestCase):
    def test_scope_is_explicit_first_pass_decisions_not_truth(self):
        self.assertEqual(review.review_scope("issues,pending"),("issue","needs_review"))
        self.assertEqual(review.review_scope("tp,fp"),("issue","not_issue"))
        self.assertEqual(review.review_scope("pending,pending"),("needs_review",))
        for value in ("all,pending","", "unknown", "issues,"):
            with self.assertRaises(ValueError):review.review_scope(value)

    def test_fast_reopens_instead_of_installing_an_opposite_verdict(self):
        baseline={"results":[result()]}; proposal={"results":[result(decision="issue")]}
        annotations=[check(action="repair", claim="The guard body does not reject the selected input.")]
        combined, rows=review.reconcile(baseline, proposal, annotations, "fast")
        self.assertEqual(combined["results"][0]["decision"], "needs_review")
        self.assertEqual(rows[0]["outcome"], "reopened")
        self.assertEqual(baseline["results"][0]["decision"], "not_issue")

    def test_full_repairs_proof_even_without_label_change(self):
        baseline={"results":[result(decision="issue")]}; proposal=copy.deepcopy(baseline)
        proposal["results"][0]["summary"]="Conditional issue under the actual earlier selector."
        combined, rows=review.reconcile(baseline, proposal, [check(action="repair", claim="The old counterexample is invalid; the alternative is supported.")], "full")
        self.assertEqual(rows[0]["outcome"], "corrected")
        self.assertEqual(combined["results"][0]["summary"], proposal["results"][0]["summary"])

    def test_wrong_proof_cannot_be_certified_by_keeping_a_label(self):
        for change in ({"error_codes":["invalid_counterexample"]}, {"proof_status":"unsupported"}):
            annotation={**check(), **change}
            with self.assertRaises(ValueError):review.checks([annotation], ["one"])
        with self.assertRaises(ValueError):review.checks([check(),check()], ["one"])
        with self.assertRaises(ValueError):review.checks([check("other")], ["one"])

    def test_insufficient_packet_retains_first_result_as_unchecked(self):
        old={"results":[result()]}; proposed={"results":[result(decision="issue")]}
        combined, rows=review.reconcile(old, proposed, [check(action="insufficient", proof="undetermined", claim="The returned packet does not contain the decisive implementation.")], "fast")
        self.assertEqual(combined, old)
        self.assertEqual(rows[0]["outcome"], "not_checked")

    def test_pending_can_be_a_supported_completed_audit(self):
        old={"results":[result(decision="needs_review")]}
        combined, rows=review.reconcile(old, old, [check()], "fast")
        self.assertEqual(rows[0]["outcome"], "unresolved")

    def test_failure_in_one_bundle_does_not_cancel_others_or_install_clean(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            def write(path,value):
                path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value))
            baselines={key:{"results":[result(key)]} for key in ("good","bad")}
            saved={}
            def stage(task):
                rid=task["review_ids"][0]
                if rid=="bad":raise ValueError("source proof rejected")
                return {"response":baselines[rid], "checks":[check(rid)], "receipt":{"job_id":rid}}
            summary=review.run(mode="fast",requests=[(k,root/k,{"review_ids":[k]}) for k in baselines],
                baselines=baselines,first_directory=None,output=root,task_base={},execute_stage=stage,
                finalize=lambda response,filename,request:saved.update({filename:response}),write=write,workers=2,byte_limit=1024)
            self.assertEqual(summary["status"],"partial")
            self.assertEqual(summary["outcomes"]["not_checked"],1)
            self.assertEqual(summary["outcomes"]["confirmed"],1)
            self.assertEqual(saved["bad"],baselines["bad"])

    def test_empty_scope_is_complete_without_model_calls_and_preserves_labels(self):
        with tempfile.TemporaryDirectory() as name:
            def write(path,value):
                path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value))
            def forbidden(*args):raise AssertionError("outside-scope claims must not reach a reviewer")
            summary=review.run(mode="full",requests=[],baselines={},first_directory=None,output=Path(name),
                task_base={},execute_stage=forbidden,finalize=forbidden,write=write,workers=1,byte_limit=1024,
                outside_scope=[result()],scope=("issue",))
            self.assertEqual(summary["status"],"complete")
            self.assertEqual(summary["targeted"],0)
            self.assertEqual(summary["checked"],0)
            self.assertEqual(summary["results"][0]["final_decision"],"not_issue")
            self.assertEqual(summary["results"][0]["reason"],"outside_scope")
            self.assertEqual(summary["label_authority"],"first_pass_only")

    def test_only_original_job_facts_are_shared_without_previous_opinions(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/"jobs").mkdir()
            fact={"result_id":"source", "origin_package_id":"package", "origin_review_id":"one",
                "query":{"tool":"source", "purpose":"Old verdict opinion", "arguments":{"path":"source.rs"}},
                "result":{"operation":"get_source", "results":{"text":"Actual code"}}}
            for key,cycle in [("original",None),("supplement","second_pass_fast_check")]:
                (root/"jobs"/(key+".json")).write_text(json.dumps({"binding":{"review_ids":["one"],"assessment_cycle":cycle},
                    "results":[fact],"working_chain":"Never share this opinion"}))
            facts, trace, frozen=review.prior_material(root,["one"],4096)
            self.assertEqual(len(facts["facts"]),1)
            self.assertNotIn("purpose",facts["facts"][0]["query"])
            self.assertNotIn("working_chain",json.dumps(facts))
            self.assertEqual(len(frozen),1)
            self.assertEqual(trace["history"],"legacy_reconstruction")

    def test_accounting_retains_unknowns_and_exact_configured_rates(self):
        metric={"role":"verification","provider":{"model":"test"},"elapsed_ms":20,
            "usage":{"input_tokens":1000,"cached_input_tokens":800,"output_tokens":20}}
        self.assertIsNone(review.accounting([metric],{"verification"})["cost"])
        rates={"models":{"test":{"input_per_million":1,"cached_input_per_million":0.1,"output_per_million":5}}}
        value=review.accounting([metric],{"verification"},rates)
        self.assertAlmostEqual(value["cost"],0.00038)
        metric["unknown_delta_counters"]=["input_tokens"]
        self.assertFalse(review.accounting([metric],{"verification"},rates)["usage_complete"])
        self.assertIsNone(review.accounting([metric],{"verification"},rates)["cost"])
        self.assertFalse(review.accounting([],set(),expected_calls=1)["usage_complete"])
        self.assertEqual(review.accounting([],set(),expected_calls=1)["calls"],1)


if __name__=="__main__":unittest.main()
