"""Routing is evidence-driven; shared reservations survive stage/retry changes."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import unittest

from test_worker import worker

flow = worker.orchestration


def policy(calls=4, run_calls=6):
    limits = {"model_calls":calls, "queries":6, "bytes":100, "timeout_seconds":60}
    return {"case_limits":limits, "run_limits":{**limits, "model_calls":run_calls},
            "audit_percent":0, "audit_seed":"fixed"}


class Orchestration(unittest.TestCase):
    def test_unread_control_tail_requires_current_source_from_the_same_file(self):
        partial = {"query":{"tool":"definition"}, "result":{
            "source_complete":False, "symbol_lookup":{"results":[{"name":"allow", "location":{
                "path":"policy.ts", "start":{"line":10}, "end":{"line":150}}}]},
            "source":{"results":{"text":"control prefix", "location":{"path":"policy.ts"},
                "line_range":{"start_line":10,"end_line":129}}}}}
        def window(path, tool="source"):
            return {"query":{"tool":tool}, "result":{"results":{"text":"return allowed;", "location":{"path":path},
                "line_range":{"start_line":130,"end_line":150}}}}
        empty = {"query":{"tool":"definition"}, "result":{"source":None,"source_complete":False,
            "symbol_lookup":{"results":[]}}}
        facts = [empty, partial, window("other-policy.ts"), window("policy.ts", "base_source")]
        gap = flow.evidence_agenda({}, facts)["declaration_query_gaps"]
        self.assertEqual(gap, [{"path":"policy.ts","name":"allow","start_line":130,"end_line":150}])
        self.assertEqual(flow.evidence_agenda({}, [*facts, window("policy.ts")])["declaration_query_gaps"], [])

    def test_shared_control_source_keeps_each_callers_activation_question_on_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            write = lambda path,value:path.write_text(json.dumps(value))
            knowledge = flow.DependencyKnowledge(Path(temp)/"knowledge.json", {}, write)
            requests = [{"question":"Inspect the shared delete guard", "scope":scope, "artifacts":["source"]}
                for scope in ("Safe caller passes request identity", "Unsafe caller passes null identity")]
            key, _ = knowledge.request(requests[0], "safe")
            knowledge.request({**requests[1], "reuse_id":key}, "unsafe")
            knowledge.resolve(key, {"summary":"Safe for the first caller", "remaining":"Activation still unread",
                "status":"collected", "artifacts":["source"]}, {"facts":[],"omitted_facts":0})
            for caller, request in zip(("safe", "unsafe"), requests):
                task = {"stage_context":{"resolved_dependency":knowledge.context(key, caller)}}
                agenda = flow.evidence_agenda(task, [])
                self.assertEqual(agenda["caller_request"], request)
                self.assertIn("conditions activating", " ".join(agenda["questions"]))
                self.assertNotIn("Safe for the first caller", json.dumps(agenda))
                self.assertNotIn("decision", agenda)

    def test_revalidation_requires_new_proposal_or_qa_reopening_and_preserves_siblings(self):
        for decisions, expected in ((["issue","issue"],"issue"),(["issue","not_issue"],"needs_review"),
                (["needs_review","needs_review","issue"],"needs_review"),(["issue","not_issue","issue"],"issue")):
            self.assertEqual(flow.assessment_basis([{"decision":d} for d in decisions]),expected)
        def response(decision):
            return {"results":[{"review_id":"id","decision":decision,"checks":[],
                "investigation":{"journal_summary":None,"blockers":[]}}]}
        stages = [
            {"response":response("needs_review"),"routing":[{"review_id":"id","reason":"conflicting_evidence"}]},
            {"response":response("needs_review"),"routing":[]},
            {"response":response("needs_review"),"routing":[],"receipt":{"role":"adjudication"}}]
        pending, issue = response("needs_review"), response("issue")
        stages[-1]["response"] = issue
        self.assertEqual(flow.revalidation_targets(stages, pending, pending), {"id":"new_source_verdict"})
        self.assertEqual(flow.revalidation_targets(stages, issue, pending), {"id":"quality_reopening"})
        for reason in flow.UNAVAILABLE:
            stages[-1]["routing"] = [{"review_id":"id","reason":reason}]
            self.assertEqual(flow.revalidation_targets(stages, pending, pending), {})
        sibling = {"review_id":"sibling","decision":"not_issue","checks":[],"investigation":{"journal_summary":None,"blockers":[]}}
        baseline, first, second = [copy.deepcopy(pending) for _ in range(3)]
        for value in (baseline,first,second):value["results"].append(copy.deepcopy(sibling))
        first["results"][0]["decision"] = second["results"][0]["decision"] = "issue"
        second["results"][1]["decision"] = "issue"
        chosen = flow.apply_revalidation(baseline, first, second, {"id":"issue"})
        self.assertEqual([r["decision"] for r in chosen["results"]], ["issue","not_issue"])
        second["results"][0]["decision"] = "not_issue"
        self.assertEqual(flow.apply_revalidation(baseline,first,second,{"id":"issue"})["results"][0]["decision"], "needs_review")
        first["results"][0]["decision"] = "not_issue"
        self.assertEqual(flow.apply_revalidation(baseline,first,second,{"id":"issue"})["results"][0]["decision"], "needs_review")

    def test_adjudication_does_not_revalidate_undisputed_pending_siblings(self):
        def response(dispute, sibling):
            return {"results":[{"review_id":"dispute","decision":dispute},
                               {"review_id":"sibling","decision":sibling}]}
        stages = [
            {"response":response("issue","not_issue"),"routing":[]},
            {"response":response("not_issue","needs_review"),"routing":[]},
            {"response":response("issue","not_issue"),"routing":[],"receipt":{"role":"adjudication"}}]
        baseline = response("issue","needs_review")
        self.assertEqual(flow.revalidation_targets(stages,baseline,baseline), {})

    def test_local_exhaustion_hands_off_without_reclassifying_external_or_shared_limits(self):
        reported = [{"review_id":"id", "reason":"budget_exhausted"}]
        room = {"model_calls":5, "queries":4, "bytes":1000, "timeout_seconds":50}
        local = flow.scoped_budget_routing(reported, True, room)
        self.assertEqual(local[0]["reason"], "stage_budget_exhausted")
        self.assertEqual(reported[0]["reason"], "budget_exhausted")
        self.assertTrue(flow.needs_secondary([{"review_id":"id", "decision":"needs_review"}], local, policy()))
        for key in room:
            self.assertEqual(flow.scoped_budget_routing(local, True, {**room, key:0})[0]["reason"], "budget_exhausted")
        self.assertEqual(flow.scoped_budget_routing(local, True, None)[0]["reason"], "budget_exhausted")
        self.assertEqual(flow.scoped_budget_routing(reported, False, room)[0]["reason"], "reasoning_gap")
        external = [{"review_id":"id", "reason":"external_required"}]
        self.assertEqual(flow.scoped_budget_routing(external, True, room), external)

    def test_source_handoff_is_bounded_deduplicated_and_blind_to_prior_intent(self):
        def fact(key):
            return {"result_id":key,"origin_package_id":"package","origin_review_id":"id",
                    "query":{"tool":"source","purpose":"Prove my proposed issue.","arguments":{"path":"app.js"}},
                    "result":{"text":"actual source"},"decision":"issue"}
        original = fact("one")
        stages = [{"source_facts":[original],"response":{"decision":"issue"}},
                  {"source_facts":[original, fact("two")]}]
        result = flow.source_handoff(stages, 10000)
        self.assertEqual(len(result["facts"]), 2)
        self.assertTrue(all("purpose" not in f["query"] and "decision" not in f for f in result["facts"]))
        self.assertEqual(result["facts"][0]["origin_review_id"], "id")
        self.assertIn("purpose", original["query"])
        self.assertEqual(flow.source_handoff(stages, 0), {"facts":[],"omitted_facts":2})

    def test_adjudication_does_not_retry_unavailable_facts_or_vote_on_new_verdicts(self):
        def response(decision):
            return {"results":[{"review_id":"id", "decision":decision, "checks":[],
                "investigation":{"journal_summary":None,"blockers":[],"decisive_artifacts":[]}}]}
        stages = [{"response":response("needs_review"), "routing":[{"review_id":"id", "reason":"external_required"}]},
                  {"response":response("issue"), "routing":[]}]
        self.assertEqual(flow.adjudication_ids(stages), [])
        stages[0]["routing"] = []
        self.assertEqual(flow.adjudication_ids(stages), [])
        stages[0]["response"] = response("not_issue")
        self.assertEqual(flow.adjudication_ids(stages), ["id"])
        stages[0]["response"] = response("needs_review")
        stages[1]["response"] = response("needs_review")
        result = flow.apply_resolution(response("needs_review"), response("issue"), stages, ["id"])
        self.assertEqual(result["results"][0]["decision"], "needs_review")
        self.assertIn("Independently assess", result["results"][0]["checks"][0])
        stages[0]["response"] = response("issue")
        self.assertEqual(flow.apply_resolution(response("needs_review"), response("issue"), stages, ["id"])["results"][0]["decision"], "issue")

    def test_final_qa_preserves_approved_evidence_and_reopens_only_assigned_ids(self):
        baseline = {"results":[{"review_id":"id", "decision":"issue", "summary":"original", "checks":[],
            "investigation":{"journal_summary":{},"blockers":[],"decisive_artifacts":["original"]}}]}
        qa = copy.deepcopy(baseline)
        qa["results"][0]["summary"] = "Rewritten prose should not replace the verdict."
        self.assertEqual(flow.apply_qa(baseline, qa), baseline)
        qa["results"][0]["decision"] = "not_issue"
        with self.assertRaisesRegex(ValueError, "only preserve"):
            flow.apply_qa(baseline, qa)
        qa["results"][0].update(decision="needs_review", checks=["Read the effective guard."])
        self.assertEqual(flow.apply_qa(baseline, qa)["results"][0]["decision"], "needs_review")
        qa["results"][0]["review_id"] = "unassigned"
        with self.assertRaisesRegex(ValueError, "coverage"):
            flow.apply_qa(baseline, qa)

    def test_resolution_requires_source_and_peer_navigation_is_bounded(self):
        draft = {"results":[{"review_id":"id", "decision":"issue", "evidence":[]}]}
        resolution = [{"review_id":"id", "disputed_claim":"Is there a guard?", "reason":"No guard precedes this operation."}]
        with self.assertRaisesRegex(ValueError, "explicit source"):
            flow.validate_resolutions(resolution, ["id"], draft)
        draft["results"][0]["evidence"] = [{"path":"app.ts", "start_line":1, "end_line":2}]
        flow.validate_resolutions(resolution, ["id"], draft)
        self.assertEqual(draft["results"][0]["reason"], resolution[0]["reason"])
        def row(identity, path):
            return {"review_id":identity,"decision":"issue","summary":"source question", "investigation":{
                "decisive_artifacts":[{"location":{"path":path}}]}}
        index = flow.index_peers([{"results":[row("id","app.ts"),row("same1","app.ts"),row("same2","app.ts"),row("other","other.ts")]}])
        context = flow.peer_context(index, {"id"}, 1)
        self.assertEqual([r["review_id"] for r in context["related_reviews"]], ["same1"])
        self.assertEqual(context["omitted_related_reviews"], 1)

    def test_profiles_share_case_and_run_reservations_and_recovery_keeps_spend(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.json"
            budget = flow.SharedReviewBudget(path, policy(calls=2, run_calls=3), worker.write)
            budget.begin_case("one")
            budget.reserve("one", "model_calls", 1)  # routine
            budget.end_case("one")
            budget.begin_case("one")
            budget.reserve("one", "model_calls", 1)  # expert
            with self.assertRaises(flow.BudgetExhausted):
                budget.reserve("one", "model_calls", 1)
            budget.end_case("one")
            budget.close()
            recovered = flow.SharedReviewBudget(Path(directory) / "retry.json", policy(2, 3), worker.write, path)
            recovered.begin_case("two")
            recovered.reserve("two", "model_calls", 1)
            with self.assertRaises(flow.BudgetExhausted):
                recovered.reserve("two", "model_calls", 1)
            self.assertEqual(recovered.state["totals"]["model_calls"], 3)
            recovered.end_case("two")
            recovered.close()

    def test_concurrent_reservations_never_oversubscribe_and_received_bytes_are_not_free(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = flow.SharedReviewBudget(Path(directory) / "budget.json", policy(20, 5), worker.write)
            for identity in ("a", "b"):
                budget.begin_case(identity)
            def reserve(index):
                try:
                    budget.reserve("ab"[index % 2], "model_calls", 1)
                    return True
                except flow.BudgetExhausted:
                    return False
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(sum(pool.map(reserve, range(20))), 5)
            with self.assertRaises(flow.BudgetExhausted):
                budget.reserve("a", "bytes", 101)
            self.assertEqual(budget.state["totals"]["bytes"], 101)
            self.assertLess(budget.remaining("a", "bytes"), 0)
            for identity in ("a", "b"):
                budget.end_case(identity)
            budget.close()

    def test_external_questions_stay_pending_but_reasoning_and_risky_closures_route(self):
        result = {"review_id":"id", "decision":"needs_review"}
        for reason in ("external_required", "human_required", "budget_exhausted"):
            self.assertFalse(flow.needs_secondary([result], [{"review_id":"id", "reason":reason}], policy()))
        self.assertTrue(flow.needs_secondary([result], [], policy()))
        self.assertTrue(flow.needs_secondary([{**result, "decision":"issue"}], [], policy()))
        self.assertTrue(flow.needs_secondary([{**result, "decision":"not_issue"}],
            [{"review_id":"id", "reason":"risky_dismissal"}], policy()))
        sampled = {**policy(), "audit_percent":100}
        self.assertTrue(flow.needs_secondary([{**result, "decision":"not_issue"}], [], sampled))
        with self.assertRaises(ValueError):
            flow.validate_routing([{"review_id":"other", "reason":"risky_dismissal"}], ["id"])

    def test_expert_resolution_of_pending_is_terminal_but_contrary_claims_are_not(self):
        def response(decision):
            return {"results":[{"review_id":"id", "decision":decision, "checks":[],
                "investigation":{"journal_summary":None, "blockers":[]}}]}
        for decision in ("issue", "not_issue", "needs_review"):
            stages = [{"response":response("needs_review"), "routing":[{"review_id":"id","reason":"reasoning_gap"}]},
                {"response":response(decision), "routing":[]}]
            self.assertEqual(flow.adjudication_ids(stages), [])
            self.assertEqual(flow.reconcile(stages[0]["response"], stages[1]["response"], "routine")["results"][0]["decision"],decision)
            self.assertEqual(flow.assessment_basis([{"decision":"needs_review","profile":"routine"},
                {"decision":decision,"profile":"expert"}]),decision)
        self.assertFalse(flow.needs_secondary(response("not_issue")["results"], [], policy(), direct=True))

    def test_dependency_knowledge_shares_exact_scoped_questions_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "knowledge.json"
            request = flow.grounded_note({"question":"What does this guard enforce?", "scope":"Calls with this exact argument.",
                "artifacts":["source-proof"]}, {"source-proof"}, dependency=True)
            book = flow.DependencyKnowledge(path, {"snapshot":"one"}, worker.write)
            key, created = book.request(request, "first")
            self.assertTrue(created)
            self.assertEqual(book.request(request, "second"), (key,False))
            with self.assertRaises(ValueError):book.context(key)
            note = flow.grounded_note({"claim":"Rejects absent membership.", "conditions":"The caller passes the subject's tenant.",
                "limits":"Does not establish the caller's tenant selection.","status":"established","artifacts":["source-proof"]}, {"source-proof"})
            book.resolve(key, note, {"facts":[],"omitted_facts":0})
            recovered = flow.DependencyKnowledge(Path(directory) / "recovered.json", {"snapshot":"one"}, worker.write, path)
            self.assertEqual(recovered.context(key)["conditions"],note["conditions"])
            self.assertNotEqual(recovered.request({**request,"scope":"Another receiver."},"third")[0],key)
            with self.assertRaises(ValueError):
                flow.DependencyKnowledge(Path(directory) / "stale.json", {"snapshot":"two"}, worker.write, path)
            with self.assertRaises(ValueError):
                flow.grounded_note({**note,"artifacts":["invented"]}, {"source-proof"})

    def test_explicit_research_reuse_preserves_each_callers_authority_question(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "knowledge.json"
            book = flow.DependencyKnowledge(path, {"snapshot":"one"}, worker.write)
            shared = {"question":"What checks precede ItemsService.updateMany mutation?",
                "scope":"Implementation only; authority argument is a condition, not a route verdict.",
                "artifacts":["items-source"]}
            key, _ = book.request(shared, "access")
            self.assertEqual(book.catalog()[0]["status"], "waiting")
            comment = {"question":"Does this inherited update use the inspected implementation?",
                "scope":"Comments caller passes request accountability; verify overrides separately.",
                "artifacts":["comments-source"],"reuse_id":key}
            self.assertEqual(book.request(comment, "comments"), (key,False))
            note = {"claim":"The displayed branch checks supplied accountability.",
                "conditions":"Requires non-null accountability and the inspected implementation.",
                "limits":"Does not establish caller argument, overrides, other methods or route access.",
                "status":"established","artifacts":["items-source"]}
            book.resolve(key, note, {"facts":[],"omitted_facts":0})
            internal = {**comment,"scope":"Internal caller passes null accountability; condition may fail."}
            self.assertEqual(book.request(internal, "internal"), (key,False))
            recovered = flow.DependencyKnowledge(Path(directory) / "recovered.json", {"snapshot":"one"}, worker.write, path)
            self.assertNotEqual(recovered.context(key,"comments")["consumer_request"]["scope"],
                                recovered.context(key,"internal")["consumer_request"]["scope"])
            self.assertEqual(recovered.context(key,"internal")["conditions"], note["conditions"])
            self.assertNotIn("decision", recovered.context(key,"internal"))
            unrelated = {**shared,"artifacts":["different-package-same-name"]}
            self.assertNotEqual(book.request(unrelated,"unrelated")[0],key)
            other_action = {**shared,"question":"What checks precede deleteMany?"}
            self.assertNotEqual(book.request(other_action,"delete")[0],key)
            with self.assertRaises(ValueError):
                book.request({**comment,"reuse_id":"f"*64},"unknown")

    def test_conflicts_preserve_pending_while_matching_results_retain_expert_evidence(self):
        first = {"schema_version":"1.3", "results":[{"review_id":"id", "decision":"issue",
            "confidence":"medium", "summary":"first", "checks":[],
            "investigation":{"journal_summary":{}, "blockers":[], "decisive_artifacts":["original"]}}]}
        other = copy.deepcopy(first)
        other["results"][0]["summary"] = "expert"
        result = flow.reconcile(first, other, "routine")["results"][0]
        self.assertEqual(result["summary"], "expert")
        other["results"][0]["decision"] = "not_issue"
        result = flow.reconcile(first, other, "routine")["results"][0]
        self.assertEqual(result["decision"], "needs_review")
        self.assertTrue(result["checks"])
        self.assertIsNone(result["investigation"]["journal_summary"])
        self.assertEqual(first["results"][0]["decision"], "issue")
