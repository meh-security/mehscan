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
    def test_source_only_options_keep_threat_context_with_no_claims(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);first=root/"first";output=root/"followup"
            first.mkdir();output.mkdir()
            source={"origin":"ai_source_only", "native_selected_claims":0, "source_questions":0,
                "assignments":1,"completed_assignments":1,"coverage":[{"status":"needs_review",
                "path":"flow.ts","start_line":1,"end_line":10,"summary":"Trace the named external effect."}]}
            (first/"source-review.json").write_text(json.dumps(source))
            def write(path,value):path.write_text(json.dumps(value))
            review.write_options(output,review.select_followups([],[]),[],write,source_directory=first)
            options=json.loads((output/"review-options.json").read_text())
            self.assertEqual(options["review_origin"],"ai_source_only")
            self.assertEqual(options["fast"]["selected"],[])
            self.assertFalse(options["threat_model"]["requires_claims"])
            context=options["threat_model"]["source_context"]
            self.assertEqual(context["native_selected_claims"],0)
            self.assertEqual(context["coverage_counts"],{"needs_review":1})
            self.assertEqual(Path(context["coverage_report"]),first/"source-review.json")

    def test_auto_fast_caps_ranked_exact_nominations_and_excludes_external_blockers(self):
        rows = [result(str(i), "needs_review") for i in range(12)]
        rows[0]["confidence"] = "low"  # Confidence alone never nominates a claim.
        notes = [{"review_id":str(i), "reason":"missing_local_evidence", "question":"Read the named guard body."}
                 for i in range(1, 8)]
        notes += [{"review_id":"8", "reason":"conflicting_evidence", "question":"Resolve two incompatible owner bindings."},
                  {"review_id":"9", "reason":"external_required", "question":"Obtain the external tenant policy."}]
        before = copy.deepcopy(rows)
        plan = review.select_followups(rows, notes)
        self.assertEqual(plan["limits"]["effective_cap"], 3)
        self.assertEqual([r["review_id"] for r in plan["selected"]], ["8", "1", "2"])
        self.assertEqual(len(plan["deferred"]), 5)
        excluded = {r["review_id"]:r["reason"] for r in plan["excluded"]}
        self.assertEqual(excluded["9"], "unavailable_deciding_fact")
        self.assertEqual(excluded["0"], "no_actionable_nomination")
        self.assertEqual(plan["full_claims"], 12)
        self.assertEqual(plan["selection_model_calls"], 0)
        self.assertEqual(rows, before)
        self.assertEqual(len(review.select_followups(rows, notes, max_claims=1)["selected"]), 1)

    def test_auto_fast_never_falls_back_to_all_and_respects_scope(self):
        rows = [result("one", "issue"), result("two", "not_issue"), result("three", "needs_review")]
        self.assertEqual(review.select_followups(rows, [])["selected"], [])
        note = {"review_id":"one", "reason":"control_applicability", "question":"Does this handler use the inspected policy?"}
        plan = review.select_followups(rows, [note], scope=("needs_review",))
        self.assertEqual(plan["selected"], [])
        self.assertEqual(plan["full_claims"], 1)
        self.assertEqual(plan["excluded"][0]["reason"], "outside_verdict_scope")
        for limit in (0, 21, True):
            with self.assertRaises(ValueError):review.select_followups(rows, [note], max_claims=limit)
        with self.assertRaises(ValueError):review.select_followups(rows, [{**note,"review_id":"unassigned"}])

    def test_resolved_first_pass_blocker_does_not_break_post_quality_options(self):
        rows=[result("one", "issue")]
        note={"review_id":"one", "reason":"external_required", "question":"Obtain the previously missing policy."}
        plan=review.select_followups(rows,[note])
        self.assertEqual(plan["selected"],[])
        self.assertEqual(plan["excluded"][0]["reason"],"resolved_blocker_nomination")
        self.assertEqual(plan["full_claims"],1)

    def test_followup_metadata_is_removed_from_native_draft_without_changing_verdict(self):
        row = result()
        original = copy.deepcopy(row)
        row["followup"] = {"reason":"control_applicability", "question":"Which registered caller supplies this object?"}
        notes = review.take_followups({"results":[row]})
        self.assertEqual(row, original)
        self.assertEqual(notes[0]["review_id"], "one")
        for note in ({"reason":"invented", "question":"x"}, {"reason":"missing_local_evidence", "question":" "},
                     {"reason":"external_required", "question":"Unknown policy."}):
            with self.assertRaises(ValueError):review.take_followups({"results":[{**original,"followup":note}]})

    def test_nominations_are_exact_job_bound_and_do_not_import_second_pass_or_peer_labels(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/"jobs").mkdir()
            note={"review_id":"one", "reason":"conflicting_evidence", "question":"Resolve the exact binding."}
            for key,cycle,ids,notes in [("first", None, ["one","two"], [note, {**note,"review_id":"two"}]),
                                       ("second", "second_pass_fast_check", ["one"], [note])]:
                (root/"jobs"/(key+".json")).write_text(json.dumps({"binding":{"review_ids":ids,
                    "assessment_cycle":cycle, "role":"investigator"}, "followups":notes}))
            self.assertEqual(review.followup_notes(root, ["one"]), [note])
            path=root/"jobs/forged.json"
            path.write_text(json.dumps({"binding":{"review_ids":["two"]}, "followups":[note]}))
            with self.assertRaises(ValueError):review.followup_notes(root, ["one"])

    def test_scope_is_explicit_first_pass_decisions_not_truth(self):
        self.assertEqual(review.review_scope("issues,pending"),("issue","needs_review"))
        self.assertEqual(review.review_scope("tp,fp"),("issue","not_issue"))
        self.assertEqual(review.review_scope("pending,pending"),("needs_review",))
        for value in ("all,pending","", "unknown", "issues,"):
            with self.assertRaises(ValueError):review.review_scope(value)

    def test_fast_does_not_install_an_unsupported_opposite_verdict(self):
        baseline={"results":[result()]}; proposal={"results":[result(decision="issue")]}
        annotations=[check(action="repair", proof="unsupported", claim="The guard body does not reject the selected input.")]
        combined, rows=review.reconcile(baseline, proposal, annotations, "fast")
        self.assertEqual(combined["results"][0]["decision"], "needs_review")
        self.assertEqual(rows[0]["outcome"], "reopened")
        self.assertEqual(baseline["results"][0]["decision"], "not_issue")

    def test_fast_can_complete_a_supported_reanalysis_in_both_directions(self):
        for before,after in [("not_issue","issue"),("issue","not_issue"),
                             ("needs_review","issue"),("needs_review","not_issue")]:
            with self.subTest(before=before,after=after):
                baseline={"results":[result(decision=before)]}
                combined, rows=review.reconcile(baseline,{"results":[result(decision=after)]},
                    [check(action="repair",claim="The inspected implementation settles the missing relationship.")],"fast")
                self.assertEqual(combined["results"][0]["decision"],after)
                self.assertEqual(rows[0]["outcome"],"corrected")
                self.assertEqual(baseline["results"][0]["decision"],before)

    def test_full_repairs_proof_even_without_label_change(self):
        baseline={"results":[result(decision="issue")]}; proposal=copy.deepcopy(baseline)
        proposal["results"][0]["summary"]="Conditional issue under the actual earlier selector."
        combined, rows=review.reconcile(baseline, proposal, [check(action="repair", claim="The old counterexample is invalid; the alternative is supported.")], "full")
        self.assertEqual(rows[0]["outcome"], "corrected")
        self.assertEqual(combined["results"][0]["summary"], proposal["results"][0]["summary"])

    def test_countercheck_targets_only_supported_closed_repairs(self):
        draft={"results":[result("fix","issue"),result("keep"),result("pending","needs_review")]}
        annotations=[check("fix",action="repair",claim="The old proof omits a reaching branch."),
            check("keep"),check("pending")]
        feedback=review.repair_countercheck(draft,annotations,["fix","keep","pending"])
        self.assertEqual(feedback["review_ids"],["fix"])
        proposed, notes=review.defer_unchecked_repairs(draft,annotations,["fix","keep","pending"])
        self.assertEqual(proposed["results"][0]["decision"],"needs_review")
        self.assertEqual(notes[0]["investigation_status"],"budget_limited")
        self.assertIn("Counter-check the proposed correction",notes[0]["claim"])
        self.assertEqual(proposed["results"][0]["checks"],[notes[0]["claim"]])
        self.assertTrue(proposed["results"][0]["summary"].startswith("Repair validation deferred:"))
        self.assertEqual(proposed["results"][1:],draft["results"][1:])
        self.assertEqual(draft["results"][0]["decision"],"issue")
        self.assertIsNone(review.repair_countercheck({"results":[result()]},[check()],["one"]))

    def test_deferred_validation_does_not_resurrect_answered_baseline_questions(self):
        old={"results":[{**result(decision="needs_review"),"checks":["Who writes this value?"]}]}
        proposal={"results":[{**result(decision="issue"),"summary":"The active writer reaches the selected consumer.",
                             "checks":[],"reason":"The inspected writer and consumer are connected."}]}
        annotations=[check(action="repair",claim="The missing writer gap is closed by the inspected source.")]
        deferred,notes=review.defer_unchecked_repairs(proposal,annotations,["one"])
        combined,outcomes=review.reconcile(old,deferred,notes,"fast")
        value=combined["results"][0]
        self.assertNotIn("Who writes this value?",value["checks"])
        self.assertEqual(value["checks"],[notes[0]["claim"]])
        self.assertEqual(value["reason"],proposal["results"][0]["reason"])
        self.assertEqual(outcomes[0]["investigation_status"],"budget_limited")
        self.assertEqual(annotations[0]["claim"],"The missing writer gap is closed by the inspected source.")

    def test_fast_reserves_validation_inside_the_original_remaining_allowance(self):
        self.assertEqual([review.fast_research_rounds("recovery",n) for n in range(6)],[0,0,1,2,3,4])
        self.assertEqual(review.fast_research_rounds("audit",5),0)
        self.assertEqual(review.fast_research_rounds("repair_check",2,True),2)
        self.assertEqual(review.fast_research_rounds("recovery",2,True),2)

    def test_audit_routes_available_objections_but_keeps_external_and_settled_claims(self):
        ids=["local","external","missing","proposal"]
        draft={"results":[result("local"),result("external","needs_review"),
            {**result("missing","needs_review"),"checks":["Read the actual state writer."]},result("proposal","issue")]}
        notes=[check("local"),{**check("external"),"investigation_status":"external_blocker"},
            {**check("missing",claim="The state writer is unread."),"investigation_status":"missing_available_evidence"},
            check("proposal",action="repair",claim="The local predicate trusts mutable state.")]
        checkpoint=review.audit_checkpoint(draft,notes,ids)
        self.assertEqual(checkpoint["review_ids"],["missing","proposal"])
        replacement={"results":[result(rid,"issue") for rid in ids]}
        repaired, checks=review.retain_settled_audit(replacement,
            [check(rid,action="repair",claim="Changed proof.") for rid in ids],checkpoint,ids)
        self.assertEqual(repaired["results"][:2],draft["results"][:2])
        self.assertEqual(checks[:2],notes[:2])
        self.assertEqual(repaired["results"][2:],[result("missing","issue"),result("proposal","issue")])
        deferred, checks=review.defer_recovery(draft,notes,ids,checkpoint["review_ids"],"No recovery turn remains.")
        self.assertEqual(deferred["results"][:2],draft["results"][:2])
        self.assertEqual(deferred["results"][2]["checks"],["Read the actual state writer."])
        self.assertEqual(checks[3]["claim"],notes[3]["claim"])
        self.assertEqual(draft["results"][3]["decision"],"issue")
        with self.assertRaises(ValueError):review.audit_checkpoint({"results":[result("local")]},notes,ids)

    def test_recovery_can_reject_the_audit_proposal_without_changing_the_baseline(self):
        baseline={"results":[result()]}
        checkpoint=review.audit_checkpoint({"results":[result(decision="issue")]},
            [check(action="repair",claim="A different invocation might expose this operation.")],["one"])
        draft, annotations=review.retain_settled_audit(baseline,[check(claim="The hypothesized invocation is inactive.")],checkpoint,["one"])
        combined, rows=review.reconcile(baseline,draft,annotations,"fast")
        self.assertEqual(combined,baseline)
        self.assertEqual(rows[0]["outcome"],"confirmed")
        self.assertEqual(checkpoint["draft"]["results"][0]["decision"],"issue")

    def test_full_supported_repair_counts_closed_to_pending_as_reopened(self):
        for decision in ("issue", "not_issue", "needs_review"):
            with self.subTest(decision=decision):
                old={"results":[result(decision=decision)]}
                proposed={"results":[result(decision="needs_review")]}
                combined, rows=review.reconcile(old, proposed,
                    [check(action="repair", claim="The effective caller policy remains unknown.")], "full")
                self.assertEqual(combined["results"][0]["decision"], "needs_review")
                self.assertEqual(rows[0]["outcome"], "unresolved" if decision=="needs_review" else "reopened")

    def test_repeated_error_tags_do_not_discard_other_valid_claims(self):
        old={"results":[result("one"), result("two", "issue")]}
        proposed={"results":[result("one", "needs_review"), result("two", "issue")]}
        annotation={**check(action="reopen", proof="undetermined", claim="The actual guard remains unread."),
                    "error_codes":["relied_on_unread_guard", "relied_on_unread_guard"]}
        combined, rows=review.reconcile(old, proposed, [annotation,check("two")], "full")
        self.assertEqual([r["outcome"] for r in rows], ["reopened", "confirmed"])
        self.assertEqual(rows[0]["error_codes"], ["relied_on_unread_guard"])
        self.assertEqual(len(annotation["error_codes"]), 2)
        self.assertEqual(combined["results"][1], old["results"][1])
        with self.assertRaisesRegex(ValueError, "invalid second-pass assessment"):
            review.checks([{**annotation,"error_codes":["invented_error"]}], ["one"])

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

    def test_related_first_source_is_reused_without_peer_verdicts_or_unrelated_facts(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/"jobs").mkdir()
            def fact(key,path,rid):
                return {"result_id":key,"origin_package_id":"package","origin_review_id":rid,
                    "query":{"tool":"source","review_id":rid,"purpose":"Peer opinion must not become evidence.",
                             "arguments":{"path":path,"start_line":1,"end_line":2}},
                    "result":{"operation":"get_source","results":{"text":"Actual implementation."}}}
            own=fact("own","handler.rs","one")
            sibling=fact("related","shared.rs","two")
            for key,ids,cycle,values in [
                ("original",["one"],None,[own]),
                ("peer",["two"],None,[sibling,fact("unrelated","elsewhere.rs","two")]),
                ("audit",["two"],"second_pass_fast_check",[fact("later","shared.rs","two")])]:
                (root/"jobs"/(key+".json")).write_text(json.dumps({
                    "binding":{"review_ids":ids,"assessment_cycle":cycle},"results":values,
                    "draft":{"results":[{"decision":"not_issue"}]},"working_chain":"Peer interpretation."}))
            material,trace,frozen=review.prior_material(root,["one"],8192,related_paths={"shared.rs"})
            self.assertEqual({f["result_id"] for f in material["facts"]},{"own","related"})
            peer=next(f for f in material["facts"] if f["result_id"]=="related")
            self.assertEqual(peer["origin_review_id"],"two")
            self.assertNotIn("purpose",peer["query"])
            self.assertNotIn("decision",json.dumps(material))
            self.assertEqual(len(frozen),2)
            # Sharing is opt-in to deciding paths, not every sibling in a file/category.
            original,_,_=review.prior_material(root,["one"],8192)
            self.assertEqual([f["result_id"] for f in original["facts"]],["own"])

            (root/"review-trace.jsonl").write_text(json.dumps({"event":"progress_changed", "job_id":"peer",
                "round":1,"dropped_open_edges":["A different caller's authority question."]})+'\n')
            _,trace,_=review.prior_material(root,["one"],8192,related_paths={"shared.rs"})
            self.assertFalse(any(f['kind']=='open_relationship_disappeared' for f in trace['flags']))

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
