"""Compact model actions through native lookups and finalization; fake inference."""
import json
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_bridge as fixtures
import codex_reviewer
import review_workspace_actions as actions


class WorkspaceActionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NativeBridgeTests(methodName="test_rejected_completed_reply_still_records_usage")
        self.fixture.extra_source = {"app.js":"import { normalize } from './helper.js';\n"
            "export function first(request) { return eval(request.query.code); }\n"
            "export function second(request) { return eval(normalize(request.body.code)); }\n"
            "export function third(request) { return eval(normalize(request.query.extra)); }\n",
            "helper.js":"export function normalize(input) { return String(input); }\n",
            **getattr(self,"extra_source",{})}
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.experiment["protocol"] = "workspace-actions-v2"
        self.fixture.limits.update(model_calls=6,queries=8)
        self.bridge = self.fixture.create()
        self.calls = []

    def invoke(self,reply):
        def run(task):
            packet = fixtures.read(task["evidence_packet"])
            outer = self
            class Fake:
                def review(self,prompt,schema,thread_id=None,timeout=600):
                    outer.calls.append({"prompt":prompt,"schema":schema,"thread":thread_id,"packet":packet})
                    response = reply(task,packet)
                    events = [{"type":"thread.started","thread_id":str(uuid.uuid4())},
                              {"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":20}}]
                    return response,"\n".join(json.dumps(e) for e in events),""
            return codex_reviewer.run(self.fixture.config,task,lambda c,s:Fake())
        return run

    def turn(self,key,reply,work="initial"):
        session = self.bridge.prepare(work,self.fixture.config_path,key)["session_id"]
        return self.bridge.review(session,self.fixture.config_path,self.invoke(reply))

    @staticmethod
    def decision(claim):
        return {"review_id":claim["review_id"],"decision":"issue","confidence":"high","summary":"Request data reaches evaluation.",
                "reason":"The selected call interprets request-controlled grammar.","source_leads":[],
                "evidence":[{"path":claim["path"],"start_line":claim["line"],"end_line":claim["line"]}],
                "diagnosis":{"title":"Request-controlled evaluation","cwes":["CWE-94"],"severity":"high",
                             "impact":"Request input is interpreted as program code.","remediation":"Remove request-controlled evaluation."}}

    @staticmethod
    def handle(task,packet,path):
        eid = next(w["artifact_id"] for w in packet["primary"]["windows"] if w["path"] == path)
        return next(k for k,v in task["research"]["artifact_handles"].items() if v == eid)

    def test_v2_provider_packet_delivers_bound_common_api_policy_without_bookkeeping(self):
        ids=list(self.bridge.workspace.snapshot()["claims"])
        self.turn("semantic-policy",lambda task,packet:{"updates":[{"kind":"question","question_id":"selected-question",
            "review_ids":ids,"question":"Which selected relationship remains to be established?"}],"lookups":[],"decisions":[]})
        packet=self.calls[0]["packet"]
        sources=packet["contract"]["sources"]
        self.assertEqual(len(sources),1)
        self.assertEqual(sources[0]["sections"],["api_semantics"])
        self.assertIn("Apply established documented API semantics",sources[0]["text"])
        self.assertEqual(self.calls[0]["prompt"].count(sources[0]["text"]),1)
        self.assertNotIn("Operator commands",sources[0]["text"])

    def test_last_call_exports_supported_and_uncertain_claims_without_extra_inference(self):
        # Spend five calls on explicit unanswered work, then use the final
        # ordinary adapter checkpoint to conclude without additional research.
        for index in range(5):
            self.turn("pending-"+str(index),lambda task,packet:{"updates":[{"kind":"question",
                "question_id":"authority","review_ids":task["review_ids"][1:],
                "question":"Does the relevant caller supply attacker input?"} if index == 0 else {
                    "kind":"answer","question_id":"authority","status":"open",
                    "reason":"The relevant caller binding still needs evidence.","evidence":[]}],"lookups":[],"decisions":[]})
        def conclude(task,packet):
            self.assertEqual(task["research"]["workspace_budget"]["used"]["model_calls"],5)
            results = [self.decision(c) for c in packet["native_questions"]]
            for result in results[1:]:
                result.update(decision="needs_review",diagnosis=None,
                    summary="Caller authority remains unresolved.",
                    reason="The selected input-to-effect binding remains unresolved at the model-call limit.")
            return {"updates":[{"kind":"answer","question_id":"authority","status":"open",
                    "reason":"Caller binding remains unestablished at the six-call limit.","evidence":[]}],
                    "lookups":[],"decisions":results}
        self.turn("last-checkpoint",conclude)
        self.assertEqual(self.calls[-1]["schema"]["properties"]["lookups"]["maxItems"],0)
        self.assertIn("final allowed checkpoint",self.calls[-1]["prompt"])
        self.assertEqual(self.bridge.workspace.usage()["calls"],6)
        self.assertEqual(self.bridge.workspace.usage()["unobserved_calls"],0)
        self.assertFalse(self.bridge.workspace.view("initial")["claims"])
        exported = self.bridge.export_completed()
        self.assertTrue(exported["native_validated"])
        self.assertEqual(len(exported["completed_review_ids"]),3)

    def test_controller_rejects_last_work_call_lookup_from_an_alternate_adapter(self):
        session = self.bridge.prepare("initial",self.fixture.config_path,"alternate-final")["session_id"]
        directory = self.bridge.directory / "sessions" / session
        task,packet = fixtures.read(directory / "task.json"),fixtures.read(directory / "context.json")
        task["research"]["workspace_budget"]["work_remaining"] = {"model_calls":1}
        before = self.bridge.workspace.snapshot()
        response = {"updates":[],"decisions":[],"lookups":[{"question_id":"late",
            "review_ids":task["review_ids"],"question":"Read one more fact?","queries":[{
                "tool":"source","review_id":task["review_ids"][0],"purpose":"Read selected effect",
                "arguments":{"path":"app.js","start_line":1,"end_line":1}}]}]}
        with self.assertRaisesRegex(ValueError,"every offered decision and no lookups"):
            actions.apply_response(self.bridge,session,task,packet,response)
        self.assertEqual(self.bridge.workspace.snapshot(),before)

    def test_invalid_auxiliary_handle_gets_one_same_context_correction(self):
        self.fixture.config['schema_mode']='stable'
        self.fixture.config_path.write_text(json.dumps(self.fixture.config))
        session=self.bridge.prepare('initial',self.fixture.config_path,'correct-proof')['session_id']
        thread=str(uuid.uuid4());turns=[]
        outer=self
        def invoke(task):
            packet=fixtures.read(task['evidence_packet'])
            class Fake:
                def review(self,prompt,schema,thread_id=None,timeout=600):
                    turns.append({'thread':thread_id,'task':json.loads(json.dumps(task)),'prompt':prompt})
                    proof=outer.handle(task,packet,'app.js') if task['research']['round'] else 'invented'
                    claim=packet['native_questions'][0]
                    response={'updates':[{'kind':'proposition','proposition_id':'eval-contract',
                        'statement':'The selected evaluator interprets its argument.','scope':'Only the shown evaluator.',
                        'conditions':'Input reaches this call.','exclusions':'Caller exposure not established.',
                        'evidence':[proof]}],'lookups':[],'decisions':[outer.decision(claim)]}
                    events=[{'type':'thread.started','thread_id':thread},{'type':'turn.completed','usage':{
                        'input_tokens':100*len(turns),'cached_input_tokens':20*len(turns),'output_tokens':20*len(turns)}}]
                    return response,'\n'.join(json.dumps(e) for e in events),''
            try:return codex_reviewer.run(outer.fixture.config,task,lambda c,s:Fake())
            except ValueError as error:raise fixtures.CommandFailure(2,'fixture adapter rejection') from error
        self.bridge.review(session,self.fixture.config_path,invoke)
        self.assertEqual([t['thread'] for t in turns],[None,thread])
        self.assertEqual([t['task']['research']['round'] for t in turns],[0,1])
        self.assertEqual([t['task']['research']['workspace_budget']['used']['model_calls'] for t in turns],[0,1])
        self.assertLessEqual(turns[1]['task']['research']['seconds_remaining'],turns[0]['task']['research']['seconds_remaining'])
        usage=self.bridge.workspace.usage()
        self.assertEqual(usage['calls'],2)
        self.assertEqual(usage['totals']['input_tokens'],200)
        self.assertEqual(usage['unobserved_calls'],0)
        state=self.bridge.workspace.snapshot()
        self.assertEqual(sum(c['draft'] is not None for c in state['claims'].values()),1)
        self.assertEqual(state['used']['queries'],0)
        self.assertTrue(state['propositions']['eval-contract'][-1]['evidence'])

    def test_native_relationship_facts_and_open_leads_reach_actual_provider_packet(self):
        expected = {}
        contracts = {}
        for bundle in self.bridge.metadata["bundles"].values():
            sweep = self.fixture.native("investigate","review-sweep","--bundle",
                str(self.bridge.directory/"run/requests"/bundle["filename"]))
            questions = {q["id"]:q for q in sweep["questions"]}
            for card in sweep["reviews"]:
                expected[card["review_id"]] = (card,questions[card["question_id"]])
            contracts.update({c["contract"]:c for c in sweep["contracts"]})
        def reply(task,packet):
            for entry in packet["native_questions"]:
                card,question = expected[entry["review_id"]]
                basis = entry["native_context"]
                self.assertEqual(basis["relationship"],question["relationship"])
                for key in ("anchor","operand_facts","decision_facts","nearby_locations","truncation"):
                    if key in card:self.assertEqual(basis[key],card[key])
                self.assertIn("not a verdict",basis["authority"])
            keys = {k for e in packet["native_questions"] for k in e["native_context"].get("contract_keys",[])}
            self.assertEqual(packet["workspace_evidence"]["native_contracts"],{k:v for k,v in contracts.items() if k in keys})
            return {"updates":[{"kind":"question","question_id":"still-open","review_ids":task["review_ids"],
                "question":"Which selected relationship needs investigation?"}],"lookups":[],"decisions":[]}
        self.turn("native-context",reply)
        self.assertIn('"native_context"',self.calls[-1]["prompt"])
        self.assertIn('"decision_facts"',self.calls[-1]["prompt"])

    def test_native_relationship_catalog_tampering_cannot_reach_a_provider(self):
        path = self.bridge.directory/"native-binding.json"
        original = fixtures.read(path)
        altered = json.loads(json.dumps(original))
        bundle = next(iter(altered["bundles"].values()))
        bundle["entries"][0]["native_context"]["decision_facts"] = {"established":["Forged caller authority"]}
        path.write_text(json.dumps(altered))
        reopened = fixtures.NativeWorkspace(self.fixture.args)
        with self.assertRaisesRegex(ValueError,"catalog changed"):
            reopened.prepare("initial",self.fixture.config_path,"tampered-native-facts")
        self.assertEqual(reopened.workspace.usage()["calls"],0)
        # Altering both catalog and claimed digest still mismatches SQLite binding.
        altered["catalog_id"] = actions.identity(altered["bundles"])
        path.write_text(json.dumps(altered))
        with self.assertRaisesRegex(ValueError,"binding differs"):
            fixtures.NativeWorkspace(self.fixture.args)

    def test_resolved_implementation_answer_survives_focus_and_can_be_reopened(self):
        claim = next(iter(self.bridge.workspace.snapshot()["claims"].values()))
        def learn(task,packet):
            proof = self.handle(task,packet,"app.js")
            return {"updates":[
                {"kind":"question","question_id":"local-contract","review_ids":[claim["review_id"]],"question":"Does the shown operation interpret its argument?"},
                {"kind":"answer","question_id":"local-contract","status":"answered","reason":"The shown evaluator interprets the supplied argument.","evidence":[proof]},
                {"kind":"question","question_id":"caller-binding","review_ids":[claim["review_id"]],"question":"Which producer supplies this selected argument?"},
                {"kind":"focus","evidence":[],"propositions":[]}],"lookups":[],"decisions":[]}
        self.turn("local-known",learn)
        def follow(task,packet):
            q = packet["workspace_evidence"]["questions"]["local-contract"]
            self.assertEqual(q["status"],"answered")
            self.assertEqual(q["origin"],"reviewer_interpretation")
            self.assertEqual(len(q["attempts"]),1)
            self.assertTrue(q["attempts"][0]["evidence"])
            self.assertTrue(packet["primary"]["windows"])
            self.assertEqual(packet["workspace_evidence"]["questions"]["caller-binding"]["status"],"open")
            return {"updates":[],"decisions":[],"lookups":[{"question_id":"local-contract", "review_ids":[claim["review_id"]],
                "question":"Does the imported implementation preserve this behavior?","queries":[{"tool":"source",
                "review_id":claim["review_id"],"purpose":"Check a material implementation qualification",
                "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]}
        self.turn("reopen-local",follow)
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["local-contract"]["status"],"open")
        self.assertEqual(state["questions"]["local-contract"]["review_ids"],[claim["review_id"]])
        self.assertEqual(len(state["questions"]),2)
        self.assertEqual(state["used"]["queries"],1)
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))

    def test_partial_closure_lookup_learning_and_cross_work_knowledge_reuse(self):
        state = self.bridge.workspace.snapshot()
        ordered = sorted(state["claims"].values(),key=lambda c:c["line"])
        self.assertEqual(len(ordered),3)
        first,second,third = ordered
        self.bridge.apply("split-third",{"kind":"split","work_id":"initial","new_work_id":"third",
            "review_ids":[third["review_id"]],"strategy":"interpreted-input"})
        def initial(task,packet):
            return {"updates":[],"decisions":[self.decision(first)],"lookups":[{
                "question_id":"normalizer-contract","review_ids":[second["review_id"]],"question":"Does normalize constrain interpreted grammar?",
                "queries":[{"tool":"source","review_id":second["review_id"],"purpose":"Inspect normalization before evaluation",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}},
                           {"tool":"references","review_id":second["review_id"],"purpose":"Verify the selected normalizer binding",
                            "arguments":{"symbol":"normalize","path":"app.js","path_prefix":None,"limit":20}},
                           {"tool":"guidance","review_id":second["review_id"],"purpose":"Check evaluator closure criteria",
                            "arguments":{"name":"process-code"}}]}]}
        result = self.turn("initial",initial)
        self.assertEqual(len(result["lookup_ids"]),3)
        after = self.bridge.workspace.snapshot()
        self.assertIsNotNone(after["claims"][first["review_id"]]["draft"])
        self.assertIsNone(after["claims"][second["review_id"]]["draft"])
        self.assertEqual(after["questions"]["normalizer-contract"]["status"],"open")
        self.assertTrue(any(l["native_query_count"] == 1 for l in after["lookups"].values()))
        def learn(task,packet):
            proof = self.handle(task,packet,"helper.js")
            self.assertNotIn(first["review_id"],task["review_ids"])
            self.assertTrue(packet["workspace_guidance"])
            return {"updates":[{"kind":"proposition","proposition_id":"normalize-contract","statement":"normalize converts input to String without constraining code grammar.",
                    "scope":"helper.js normalize","conditions":"The shown import invokes this implementation","exclusions":"Other bindings not assessed","evidence":[proof]},
                    {"kind":"applicability","review_id":second["review_id"],"proposition_id":"normalize-contract","proposition_revision":1,
                     "reason":"The selected second call passes normalized request text into eval.","evidence":[proof]},
                    {"kind":"answer","question_id":"normalizer-contract","status":"answered","reason":"String conversion preserves code grammar.","evidence":[proof]},
                    {"kind":"focus","evidence":[self.handle(task,packet,"app.js")],"propositions":["normalize-contract"]}],
                    "lookups":[],"decisions":[self.decision(second)]}
        self.turn("learn",learn)
        def retrieve(task,packet):
            self.assertNotIn("normalize-contract",packet["workspace_evidence"]["propositions"])
            return {"updates":[],"decisions":[],"lookups":[{"question_id":"known-normalizer","review_ids":[third["review_id"]],
                "question":"What implementation contract is already known for normalize?","queries":[{"tool":"knowledge",
                    "review_id":third["review_id"],"purpose":"Reuse the inspected normalizer implementation","arguments":{"name":"normalize"}}]}]}
        self.turn("retrieve",retrieve,work="third")
        def finish(task,packet):
            proof = self.handle(task,packet,"helper.js")
            self.assertIn("normalize-contract",packet["workspace_evidence"]["propositions"])
            return {"updates":[{"kind":"answer","question_id":"known-normalizer","status":"answered","reason":"The retrieved source-backed contract applies to this import.","evidence":[proof]},
                {"kind":"applicability","review_id":third["review_id"],"proposition_id":"normalize-contract","proposition_revision":1,
                 "reason":"This caller passes request text through the same normalizer into evaluation.","evidence":[proof]}],"lookups":[],"decisions":[self.decision(third)]}
        self.turn("finish",finish,work="third")
        self.assertEqual([c["thread"] for c in self.calls],[None]*4)
        self.assertTrue(all(set(c["schema"]["properties"]) == {"updates","lookups","decisions"} for c in self.calls))
        bundle_id = first["bundle_id"]
        validated = self.bridge.finalize(bundle_id)
        response = fixtures.read(validated["response"])
        self.assertEqual(len(response["results"]),3)
        counts = {r["review_id"]:r["investigation"]["journal_summary"]["query_count"] for r in response["results"]}
        self.assertEqual(counts[first["review_id"]],0)
        self.assertGreaterEqual(counts[second["review_id"]],1)
        self.assertEqual(counts[third["review_id"]],0)
        self.assertEqual(self.bridge.workspace.usage()["totals"]["input_tokens"],400)

    def test_surgical_reopening_keeps_sibling_decisions_local_proof_and_paid_work(self):
        claims = sorted(self.bridge.workspace.snapshot()["claims"].values(),key=lambda c:c["line"])
        first,affected,third = claims
        def settled(task,packet):
            return {"updates":[
                {"kind":"question","question_id":"local-effect","review_ids":[affected["review_id"]],
                 "question":"Does the selected call interpret the argument as code?"},
                {"kind":"answer","question_id":"local-effect","status":"answered",
                 "reason":"The shown selected call invokes eval on its argument.",
                 "evidence":[self.handle(task,packet,"app.js")]}],
                "lookups":[],"decisions":[self.decision(c) for c in claims]}
        self.turn("settled",settled)
        baseline = self.bridge.workspace.snapshot()
        self.bridge.apply("missing-qualification",{"kind":"question","question_id":"helper-contract",
            "review_ids":[affected["review_id"]],"question":"Does the actual normalizer constrain executable grammar?"})
        reopened = self.bridge.workspace.snapshot()
        for sibling in (first,third):
            self.assertEqual(reopened["claims"][sibling["review_id"]],baseline["claims"][sibling["review_id"]])
        self.assertEqual(reopened["evidence"],baseline["evidence"])
        self.assertEqual(reopened["calls"],baseline["calls"])
        self.assertEqual(reopened["used"],baseline["used"])
        with self.assertRaisesRegex(ValueError,"reconsideration|unanswered"):
            self.bridge.finalize(affected["bundle_id"])

        def lookup(query):
            def reply(task,packet):
                self.assertEqual(task["review_ids"],[affected["review_id"]])
                self.assertEqual(packet["workspace_evidence"]["questions"]["local-effect"]["status"],"answered")
                self.assertTrue(any(w["path"]=="app.js" for w in packet["primary"]["windows"]))
                return {"updates":[],"decisions":[],"lookups":[{
                    "question_id":"helper-contract","review_ids":[affected["review_id"]],
                    "question":"Does the actual normalizer constrain executable grammar?","queries":[query]}]}
            return reply
        self.turn("filter-feedback",lookup({"tool":"references","review_id":affected["review_id"],
            "purpose":"Find the normalizer's uses","arguments":{"symbol":"normalize","path_prefix":"helper.js","limit":20}}))
        after_feedback = self.bridge.workspace.snapshot()
        self.assertEqual(after_feedback["evidence"],baseline["evidence"])
        receipt = next(iter(after_feedback["lookups"].values()))
        self.assertEqual(receipt["result"]["code"],"directory_filter_is_file")
        self.assertEqual(receipt["native_query_count"],0)
        self.turn("read-helper",lookup({"tool":"source","review_id":affected["review_id"],
            "purpose":"Inspect the known normalizer implementation","arguments":{"path":"helper.js","start_line":1,"end_line":1}}))
        def correct(task,packet):
            self.assertEqual(task["review_ids"],[affected["review_id"]])
            return {"updates":[{"kind":"answer","question_id":"helper-contract","status":"answered",
                "reason":"The imported helper only converts input to String; executable grammar is preserved.",
                "evidence":[self.handle(task,packet,"helper.js")]}],
                "lookups":[],"decisions":[self.decision(affected)]}
        self.turn("complete-only-affected",correct)
        final = self.bridge.workspace.snapshot()
        for sibling in (first,third):
            self.assertEqual(final["claims"][sibling["review_id"]],baseline["claims"][sibling["review_id"]])
        for eid,evidence in baseline["evidence"].items():
            self.assertEqual(final["evidence"][eid],evidence)
        self.assertEqual(final["questions"]["local-effect"],baseline["questions"]["local-effect"])
        self.assertEqual(final["questions"]["helper-contract"]["status"],"answered")
        self.assertEqual(self.bridge.workspace.usage()["calls"],4)
        self.assertEqual(self.bridge.workspace.usage()["totals"]["input_tokens"],400)
        self.assertEqual(final["used"]["queries"],2)
        self.assertGreater(final["received_query_bytes"],receipt["received_bytes"])
        validated = self.bridge.finalize(affected["bundle_id"])
        results = fixtures.read(validated["response"])["results"]
        self.assertEqual({r["review_id"] for r in results},{c["review_id"] for c in claims})

    def test_invalid_later_lookup_executes_no_query_and_saves_no_earlier_decision(self):
        claims = list(self.bridge.workspace.snapshot()["claims"].values())
        def invalid(task,packet):
            return {"updates":[],"decisions":[self.decision(claims[0])],"lookups":[{
                "question_id":"bad-path","question":"Inspect the selected helper","review_ids":[claims[1]["review_id"]],
                "queries":[{"tool":"source","review_id":claims[1]["review_id"],"purpose":"Read helper", "arguments":{"path":"../escape","start_line":1,"end_line":1}}]}]}
        with self.assertRaisesRegex(ValueError,"relative"):
            self.turn("bad",invalid)
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["used"]["queries"],0)
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))
        self.assertEqual(self.bridge.workspace.usage()["totals"]["input_tokens"],100)

    def test_followup_lookup_keeps_original_question_and_each_requested_fact(self):
        claim = next(iter(self.bridge.workspace.snapshot()["claims"]))
        original = "Does normalization constrain interpreted grammar?"
        refined = "Does the selected helper remove evaluation syntax?"
        def lookup(text):
            return lambda task,packet: {"updates":[],"decisions":[],"lookups":[{
                "question_id":"normalizer","review_ids":[claim],"question":text,
                "queries":[{"tool":"source","review_id":claim,"purpose":"Inspect the normalizer contract",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]}
        self.turn("first",lookup(original))
        self.turn("refined",lookup(refined))
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["normalizer"]["question"],original)
        self.assertEqual(state["questions"]["normalizer"]["status"],"open")
        receipts = sorted(state["lookups"].values(),key=lambda v:v["sequence"])
        self.assertEqual([v["requested_question"] for v in receipts],[original,refined])
        self.assertIsNotNone(receipts[1]["reused_from"])
        view = self.bridge.workspace.view("initial")
        self.assertEqual(len(view["lookups"]),2)
        self.assertEqual({v["requested_question"] for v in view["lookups"].values()},{original,refined})

    def test_declared_question_can_have_a_narrower_lookup_in_the_same_response(self):
        claim = next(iter(self.bridge.workspace.snapshot()["claims"]))
        def reply(task,packet):
            return {"updates":[{"kind":"question","question_id":"declared","review_ids":[claim],
                "question":"Does the selected flow constrain interpreted input?"}],"decisions":[],"lookups":[{
                "question_id":"declared","review_ids":[claim],"question":"Does the helper remove executable syntax?",
                "queries":[{"tool":"source","review_id":claim,"purpose":"Inspect the input helper",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]}
        self.turn("declare-and-refine",reply)
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["declared"]["question"],"Does the selected flow constrain interpreted input?")
        self.assertEqual(next(iter(state["lookups"].values()))["requested_question"],"Does the helper remove executable syntax?")

    def test_followup_lookup_cannot_move_an_existing_question_to_another_claim(self):
        claims = list(self.bridge.workspace.snapshot()["claims"])
        self.bridge.apply("question",{"kind":"question","question_id":"existing","review_ids":[claims[0]],
                                     "question":"Is the selected effect constrained?"})
        def invalid(task,packet):
            return {"updates":[],"decisions":[],"lookups":[{
                "question_id":"existing","review_ids":[claims[1]],"question":"What about another effect?",
                "queries":[{"tool":"source","review_id":claims[1],"purpose":"Read the effect",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]}
        with self.assertRaisesRegex(ValueError,"another scope"):
            self.turn("scope-change",invalid)
        self.assertFalse(self.bridge.workspace.snapshot()["lookups"])

    def test_shared_question_can_retrieve_for_more_claims_without_transferring_answers(self):
        first,second,*_ = list(self.bridge.workspace.snapshot()["claims"])
        self.bridge.apply("first-question",{"kind":"question","question_id":"first-effect",
            "review_ids":[first],"question":"What protects the first selected effect?"})
        self.bridge.apply("second-question",{"kind":"question","question_id":"second-effect",
            "review_ids":[second],"question":"What protects the second selected effect?"})
        self.turn("shared-retrieval",lambda task,packet:{"updates":[],"decisions":[],"lookups":[{
            "question_id":"first-effect","review_ids":[first,second],"question":"Inspect a common helper for both callers.",
            "queries":[{"tool":"source","review_id":first,"purpose":"Read the shared implementation",
                        "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]})
        state=self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["first-effect"]["review_ids"],[first])
        self.assertEqual(state["questions"]["second-effect"]["status"],"open")
        self.assertEqual(next(iter(state["lookups"].values()))["review_ids"],[first,second])
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))
        self.assertEqual(state["used"]["queries"],1)

    def test_wider_lookup_beneficiaries_do_not_change_prompting_question_attribution(self):
        first,second,*_ = list(self.bridge.workspace.snapshot()["claims"])
        self.bridge.apply("question",{"kind":"question","question_id":"first-effect",
            "review_ids":[first],"question":"What protects the first selected effect?"})
        with self.assertRaisesRegex(ValueError,"another scope"):
            self.turn("foreign-prompt",lambda task,packet:{"updates":[],"decisions":[],"lookups":[{
                "question_id":"first-effect","review_ids":[first,second],"question":"Reuse a lookup across callers.",
                "queries":[{"tool":"source","review_id":second,"purpose":"An attribution outside the original question",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]})
        state=self.bridge.workspace.snapshot()
        self.assertFalse(state["lookups"])
        self.assertEqual(state["used"]["queries"],0)
        self.assertEqual(self.bridge.workspace.usage()["calls"],1)

    def test_narrow_lookup_alone_does_not_settle_other_claims(self):
        first,second,*_ = list(self.bridge.workspace.snapshot()["claims"])
        self.bridge.apply("question",{"kind":"question","question_id":"shared",
            "review_ids":[first,second],"question":"Which callers have a complete control?"})
        self.turn("narrow-retrieval",lambda task,packet:{"updates":[],"decisions":[],"lookups":[{
            "question_id":"shared","review_ids":[second],"question":"Inspect the second caller's helper.",
            "queries":[{"tool":"source","review_id":second,"purpose":"Read the remaining implementation",
                        "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]})
        state=self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["shared"]["review_ids"],[first,second])
        self.assertEqual(state["questions"]["shared"]["status"],"open")
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))
        self.assertNotIn("settled_review_ids",self.bridge.workspace.view("initial")["questions"]["shared"])

    def test_new_shared_question_can_settle_only_a_source_cited_first_turn_decision(self):
        first,second,third=sorted(self.bridge.workspace.snapshot()["claims"].values(),key=lambda c:c["line"])
        ids=[first["review_id"],second["review_id"]]
        self.turn("first-turn-partial",lambda task,packet:{
            "updates":[{"kind":"question","question_id":"shared","review_ids":ids,
                        "question":"Which selected evaluators receive unconstrained input?"}],
            "lookups":[{"question_id":"shared","review_ids":[second["review_id"]],
                "question":"Does the remaining caller's normalizer constrain grammar?",
                "queries":[{"tool":"source","review_id":second["review_id"],"purpose":"Read the remaining normalizer",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}],
            "decisions":[self.decision(first),self.decision(third)]})
        state=self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["shared"]["review_ids"],ids)
        self.assertEqual(state["questions"]["shared"]["status"],"open")
        self.assertEqual(state["claims"][first["review_id"]]["draft"]["resolved_questions"],["shared"])
        self.assertIsNone(state["claims"][second["review_id"]]["draft"])
        view=self.bridge.workspace.view("initial")
        self.assertEqual([c["review_id"] for c in view["claims"]],[second["review_id"]])
        self.assertEqual(view["questions"]["shared"]["settled_review_ids"],[first["review_id"]])
        self.assertEqual(state["used"]["queries"],1)

    def test_explicit_partial_decision_keeps_shared_question_open_and_reopens_on_changed_answer(self):
        claims=sorted(self.bridge.workspace.snapshot()["claims"].values(),key=lambda c:c["line"])
        first,second,third=claims
        ids=[first["review_id"],second["review_id"]]
        self.turn("shared-start",lambda task,packet:{"updates":[{"kind":"question","question_id":"shared",
            "review_ids":ids,"question":"Which selected callers have unconstrained evaluation?"}],
            "lookups":[],"decisions":[self.decision(third)]})
        third_before=self.bridge.workspace.snapshot()["claims"][third["review_id"]]
        def partial(task,packet):
            return {"updates":[{"kind":"answer","question_id":"shared","status":"open",
                "reason":"The first evaluator is established; the second normalizer contract remains unknown.",
                "evidence":[self.handle(task,packet,"app.js")]}],
                "decisions":[self.decision(first)],"lookups":[{"question_id":"shared","review_ids":[second["review_id"]],
                    "question":"Which selected callers have unconstrained evaluation?",
                    "queries":[{"tool":"source","review_id":second["review_id"],"purpose":"Inspect the remaining caller's helper",
                                "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]}
        self.turn("partial",partial)
        state=self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["shared"]["status"],"open")
        self.assertEqual(state["questions"]["shared"]["review_ids"],ids)
        self.assertEqual(state["claims"][first["review_id"]]["draft"]["resolved_questions"],["shared"])
        self.assertIsNone(state["claims"][second["review_id"]]["draft"])
        self.assertEqual(state["claims"][third["review_id"]],third_before)
        def finish_second(task,packet):
            self.assertEqual(set(task["review_ids"]),set(ids))
            self.assertEqual(packet["workspace_evidence"]["questions"]["shared"]["settled_review_ids"],[first["review_id"]])
            self.assertEqual(packet["workspace_evidence"]["answer_consumers"][first["review_id"]]["previous_result"],
                             state["claims"][first["review_id"]]["draft"]["result"])
            return {"updates":[{"kind":"answer","question_id":"shared","status":"answered",
                "reason":"String conversion preserves executable grammar in the remaining caller.",
                "evidence":[self.handle(task,packet,"helper.js")]}],"lookups":[],"decisions":[self.decision(second)]}
        self.turn("finish-second",finish_second)
        self.assertTrue(self.bridge.workspace.snapshot()["claims"][first["review_id"]]["reconsideration"])
        with self.assertRaisesRegex(ValueError,"reconsideration"):
            self.bridge.finalize(first["bundle_id"])
        self.turn("confirm-first",lambda task,packet:{"updates":[],"lookups":[],"decisions":[self.decision(first)]})
        self.assertTrue(self.bridge.finalize(first["bundle_id"])["native_validated"])
        self.assertEqual(self.bridge.workspace.usage()["calls"],4)
        self.assertEqual(self.bridge.workspace.snapshot()["used"]["queries"],1)

    def test_partial_resolution_without_source_cannot_commit_or_execute_lookup(self):
        first,second,*_=list(self.bridge.workspace.snapshot()["claims"].values())
        self.bridge.apply("question",{"kind":"question","question_id":"shared",
            "review_ids":[first["review_id"],second["review_id"]],"question":"Which selected effect is constrained?"})
        decision=self.decision(first);decision["evidence"]=[]
        with self.assertRaisesRegex(ValueError,"source evidence"):
            self.turn("unproved-partial",lambda task,packet:{"updates":[],"decisions":[decision],"lookups":[{
                "question_id":"shared","review_ids":[second["review_id"]],"question":"Inspect the remaining helper.",
                "queries":[{"tool":"source","review_id":second["review_id"],"purpose":"Read the helper",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]})
        state=self.bridge.workspace.snapshot()
        self.assertFalse(state["lookups"])
        self.assertEqual(state["used"]["queries"],0)
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))
        self.assertEqual(self.bridge.workspace.usage()["calls"],1)

    def test_independent_work_question_name_collision_is_scoped_without_transferring_answers(self):
        claims = list(self.bridge.workspace.snapshot()["claims"])
        self.bridge.apply("split",{"kind":"split","work_id":"initial","new_work_id":"other",
                                  "review_ids":[claims[1]],"strategy":"another caller"})
        self.bridge.apply("original-question",{"kind":"question","question_id":"same-name",
            "review_ids":[claims[0]],"question":"Does the first caller enforce ownership?"})
        def lookup(task,packet):
            return {"updates":[],"decisions":[],"lookups":[{"question_id":"same-name",
                "review_ids":[claims[1]],"question":"Does the second caller enforce ownership?",
                "queries":[{"tool":"source","review_id":claims[1],"purpose":"Inspect the second caller's helper",
                            "arguments":{"path":"helper.js","start_line":1,"end_line":1}}]}]}
        self.turn("independent",lookup,work="other")
        self.turn("independent-followup",lookup,work="other")
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["questions"]["same-name"]["review_ids"],[claims[0]])
        visible = self.bridge.workspace.view("other")["questions"]
        self.assertEqual(len(visible),1)
        qid = next(iter(visible))
        self.assertNotEqual(qid,"same-name")
        self.assertEqual(visible[qid]["review_ids"],[claims[1]])
        self.assertEqual({v["question_id"] for v in state["lookups"].values()},{qid})
        self.assertTrue(all(v["status"] == "open" for v in state["questions"].values()))
        def foreign_answer(task,packet):
            return {"updates":[{"kind":"answer","question_id":"same-name","status":"blocked",
                                "reason":"This must not answer another work's question.","evidence":[]}],
                    "lookups":[],"decisions":[]}
        with self.assertRaisesRegex(ValueError,"unseen question"):
            self.turn("foreign-answer",foreign_answer,work="other")

    def test_independent_proposition_names_keep_revisions_and_applicability_separate(self):
        claims = list(self.bridge.workspace.snapshot()["claims"])
        self.bridge.apply("split-props",{"kind":"split","work_id":"initial","new_work_id":"other",
            "review_ids":[claims[1]],"strategy":"another caller"})
        def declaration(claim,scope,revision):
            def reply(task,packet):
                proof = self.handle(task,packet,"app.js")
                return {"updates":[{"kind":"proposition","proposition_id":"caller-contract",
                    "statement":"Source interpretation for "+scope,"scope":scope,"conditions":"Selected caller only",
                    "exclusions":"Other callers","evidence":[proof]},
                    {"kind":"applicability","review_id":claim,"proposition_id":"caller-contract",
                     "proposition_revision":revision,"reason":"Same inspected caller","evidence":[proof]},
                    {"kind":"focus","evidence":[proof],"propositions":["caller-contract"]}],"lookups":[],"decisions":[]}
            return reply
        self.turn("first-prop",declaration(claims[0],"first caller",1))
        def unseen(task,packet):
            return {"updates":[{"kind":"applicability","review_id":claims[1],"proposition_id":"caller-contract",
                "proposition_revision":1,"reason":"Must retrieve before using foreign knowledge.",
                "evidence":[self.handle(task,packet,"app.js")]}],"lookups":[],"decisions":[]}
        with self.assertRaisesRegex(ValueError,"retrieve a proposition"):
            self.turn("unseen-prop",unseen,work="other")
        self.turn("second-prop",declaration(claims[1],"second caller",1),work="other")
        self.turn("second-revision",declaration(claims[1],"second caller revised",2),work="other")
        state = self.bridge.workspace.snapshot()
        self.assertEqual(len(state["propositions"]["caller-contract"]),1)
        visible = self.bridge.workspace.view("other")["propositions"]
        self.assertEqual(len(visible),1)
        pid = next(iter(visible))
        self.assertNotEqual(pid,"caller-contract")
        self.assertEqual(visible[pid]["revision"],2)
        self.assertEqual(visible[pid]["scope"],"second caller revised")
        self.assertTrue(all(a["proposition_id"] == pid for a in state["applicability"].values() if a["review_id"] == claims[1]))

    def test_new_question_renders_native_checks_and_blocker_without_model_checklists(self):
        claims = list(self.bridge.workspace.snapshot()["claims"].values())
        question = "Which verified identity reaches the selected effect?"
        obstacle = "The caller identity implementation is not available in this source scope."
        def defer(task,packet):
            uncertain = {**self.decision(claims[0]),"decision":"needs_review","diagnosis":None}
            proof=self.handle(task,packet,'app.js')
            return {"updates":[{"kind":"proposition","proposition_id":"local-effect",
                    "statement":"The selected evaluator call is shown.","scope":"Selected evaluator implementation",
                    "conditions":"The selected caller reaches this implementation.","exclusions":"Caller authorization is not established.",
                    "evidence":[proof]},
                    {"kind":"applicability","review_id":claims[0]['review_id'],'proposition_id':'local-effect',
                     'proposition_revision':1,'evidence':[proof],'reason':'The selected caller contains this evaluator.'},
                    {"kind":"question","question_id":"identity","review_ids":[claims[0]["review_id"]],"question":question},
                    {"kind":"answer","question_id":"identity","status":"blocked","reason":obstacle,"evidence":[]}],
                    "lookups":[],"decisions":[uncertain,*[self.decision(c) for c in claims[1:]]]}
        self.turn("defer",defer)
        draft = self.bridge.workspace.snapshot()["claims"][claims[0]["review_id"]]["draft"]["result"]
        self.assertEqual(draft["checks"],[question])
        self.assertEqual(draft["blockers"],[obstacle])
        self.assertNotIn('checks',self.calls[0]['schema']['properties']['decisions']['items']['anyOf'][0]['properties'])
        before=self.bridge.workspace.snapshot()
        finalized=self.bridge.finalize(claims[0]["bundle_id"])
        response = fixtures.read(finalized["response"])
        native = next(r for r in response['results'] if r['review_id']==claims[0]['review_id'])
        self.assertEqual(native['checks'],[question])
        self.assertEqual(native['investigation']['blockers'],[obstacle])
        package=fixtures.read(finalized['review_package'])
        rendered=Path(finalized['review_markdown']).read_text(encoding='utf-8')
        self.assertEqual([c['result'] for c in package['claims']],[c['draft']['result'] for c in before['claims'].values()])
        by_id={c['review_id']:c for c in package['claims']}
        self.assertEqual(by_id[claims[0]['review_id']]['reviewer_notes'][0]['relationship'],'caller_applicability_recorded')
        self.assertTrue(all(by_id[c['review_id']]['reviewer_notes'][0]['relationship']=='context_only' for c in claims[1:]))
        self.assertIn('Caller authorization is not established.',rendered)
        self.assertNotIn('Caller authorization is not established.',native['investigation']['blockers'])
        receipt=fixtures.read(Path(finalized['response']).parent/'validated.json')
        self.assertEqual(receipt['review_package_sha256'],actions.worker.digest_file(finalized['review_package']))
        self.assertEqual(receipt['review_markdown_sha256'],actions.worker.digest_file(finalized['review_markdown']))
        self.assertEqual(before,self.bridge.workspace.snapshot())

    def test_needs_review_without_saved_question_is_rejected_with_paid_usage_retained(self):
        claim = next(iter(self.bridge.workspace.snapshot()["claims"].values()))
        with self.assertRaisesRegex(ValueError,"saved unresolved"):
            self.turn("missing-question",lambda task,packet:{"updates":[],"lookups":[],
                "decisions":[{**self.decision(claim),"decision":"needs_review","diagnosis":None}]})
        self.assertIsNone(self.bridge.workspace.snapshot()['claims'][claim['review_id']]['draft'])
        self.assertEqual(self.bridge.workspace.usage()['totals']['input_tokens'],100)


class DecisionRenderingTests(unittest.TestCase):
    def test_only_selected_unresolved_questions_render_without_truncation(self):
        state = {"questions":{
            'open':{'review_ids':['one'],'status':'open','question':'What owner reaches the write?','attempts':[]},
            'answered':{'review_ids':['one'],'status':'answered','question':'Resolved work','attempts':[]},
            'other':{'review_ids':['two'],'status':'blocked','question':'Other claim gap','attempts':[{'reason':'Other obstacle'}]}}}
        result = actions.native_decision({'review_id':'one','decision':'needs_review'},state)
        self.assertEqual(result['checks'],['What owner reaches the write?'])
        self.assertEqual(result['blockers'],[])
        state['questions']['open']['question']='x'*301
        with self.assertRaisesRegex(ValueError,'without truncation'):
            actions.native_decision({'review_id':'one','decision':'needs_review'},state)


if __name__ == "__main__":
    unittest.main()
