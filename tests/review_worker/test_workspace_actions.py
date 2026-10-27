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
            "helper.js":"export function normalize(input) { return String(input); }\n"}
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
            return {"updates":[{"kind":"question","question_id":"identity","review_ids":[claims[0]["review_id"]],"question":question},
                    {"kind":"answer","question_id":"identity","status":"blocked","reason":obstacle,"evidence":[]}],
                    "lookups":[],"decisions":[uncertain,*[self.decision(c) for c in claims[1:]]]}
        self.turn("defer",defer)
        draft = self.bridge.workspace.snapshot()["claims"][claims[0]["review_id"]]["draft"]["result"]
        self.assertEqual(draft["checks"],[question])
        self.assertEqual(draft["blockers"],[obstacle])
        self.assertNotIn('checks',self.calls[0]['schema']['properties']['decisions']['items']['anyOf'][0]['properties'])
        response = fixtures.read(self.bridge.finalize(claims[0]["bundle_id"])["response"])
        native = next(r for r in response['results'] if r['review_id']==claims[0]['review_id'])
        self.assertEqual(native['checks'],[question])
        self.assertEqual(native['investigation']['blockers'],[obstacle])

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
