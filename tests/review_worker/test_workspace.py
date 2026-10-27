"""Workspace recovery and evidence reuse; these tests do not establish AI savings."""
import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PRODUCT / "scripts"))
from review_workspace import Workspace
import review_workspace_actions as actions


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-workspace-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "source"
        self.root.mkdir()
        self.code = self.root / "routes.ts"
        self.code.write_text("function bind(req) { req.body.UserId = req.user.id; }\n"
                             "app.put('/safe', bind, updateByBodyOwner);\n"
                             "app.put('/unsafe/:id', bind, updateByPathId);\n"
                             "app.post('/generated', generateResource);\n", encoding="utf-8")
        self.binding = {"snapshot_id":"snapshot-1", "plan_id":"plan-1", "runtime_id":"runtime-1"}
        self.claims = [{"review_id":key, "property":"Is this update bound to its owner?", "path":"routes.ts",
                        "line":line, "bundle_id":"bundle-1"} for key,line in (("safe",2),("unsafe",3),("unknown",4))]
        self.limits = {"model_calls":3, "queries":4, "source_bytes":4096}
        self.path = self.directory / "workspace.sqlite"
        self.workspace = Workspace.create(self.path, self.root, self.binding, self.claims, self.limits)
        self.count = 0

    def apply(self, kind, **fields):
        self.count += 1
        return self.workspace.apply("op-" + str(self.count), self.workspace.snapshot()["revision"],
                                    {"kind":kind, **fields})["result"]

    def capture(self, first=1, last=1, claim="safe"):
        return self.apply("source", path="routes.ts", start_line=first, end_line=last, review_id=claim)["evidence_id"]

    def proposition(self, evidence, statement="The helper binds body.UserId to the authenticated subject."):
        return self.apply("proposition", proposition_id="body-owner", statement=statement, scope="bind in routes.ts",
                          conditions="Middleware runs before effect", exclusions="Route parameters are not constrained",
                          evidence=[evidence])

    def applicability(self, claim, evidence, revision=1):
        return self.apply("applicability", review_id=claim, proposition_id="body-owner", proposition_revision=revision,
                          evidence=[evidence], reason="Check the selected caller and effect separately")["applicability_id"]

    def draft(self, claim, decision, line, applies=(), checks=None):
        return self.apply("draft", result={"review_id":claim, "decision":decision, "confidence":"high",
                          "summary":"The selected relationship is assessed", "reason":"Source-bound test interpretation",
                          "evidence":[{"path":"routes.ts","start_line":line,"end_line":line}],
                          "checks":checks or [], "blockers":[], "source_leads":[],
                          "diagnosis":{"title":"Missing owner constraint", "cwes":["CWE-639"], "severity":"medium",
                                       "impact":"Other users' objects can be updated", "remediation":"Constrain owner"}
                                       if decision == "issue" else None}, applicability=list(applies))

    def test_replay_stale_revision_and_binding_protect_transaction(self):
        action = {"kind":"reserve_queries", "queries":2}
        receipt = self.workspace.apply("reserve", 0, action)
        recovered = Workspace(self.path, self.binding)
        self.assertEqual(recovered.apply("reserve", 0, action), {**receipt, "replayed":True})
        for operation, revision, request in (("reserve",0,{**action,"queries":1}), ("other",0,action)):
            with self.assertRaises(ValueError):
                recovered.apply(operation, revision, request)
        self.assertEqual(recovered.snapshot()["used"]["queries"], 2)
        for field in self.binding:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "binding differs"):
                Workspace(self.path, {**self.binding, field:"changed"})

    def test_citation_projection_preserves_shown_parts_across_blank_line(self):
        (self.root/"helpers.ts").write_text("first();\n\nsecond();\n",encoding="utf-8")
        windows = [{"path":"helpers.ts","start_line":n,"end_line":n} for n in (1,3)]
        original = {"path":"helpers.ts","start_line":1,"end_line":3}
        self.assertEqual(actions.citation_windows(SimpleNamespace(root=self.root),windows,original),windows)
        self.assertEqual(original,{"path":"helpers.ts","start_line":1,"end_line":3})
        touching = [{"path":"helpers.ts","start_line":1,"end_line":2},windows[1]]
        self.assertEqual(actions.citation_windows(SimpleNamespace(root=self.root),touching,original),touching)

    def test_citation_projection_rejects_unseen_code_and_invalid_extent(self):
        (self.root/"helpers.ts").write_text("first();\nreject();\nsecond();\n",encoding="utf-8")
        windows = [{"path":"helpers.ts","start_line":n,"end_line":n} for n in (1,3)]
        for first,last in ((1,3),(1,4),(0,3),(1,1000000000)):
            with self.subTest(first=first,last=last), self.assertRaises(ValueError):
                actions.citation_windows(SimpleNamespace(root=self.root),windows,
                    {"path":"helpers.ts","start_line":first,"end_line":last})

    def test_guidance_loaded_in_one_work_does_not_enter_another_context(self):
        self.apply("split",work_id="initial",new_work_id="other",review_ids=["unsafe"],strategy="separate caller")
        self.apply("question",question_id="policy",review_ids=["safe"],question="Which policy applies?")
        query = {"tool":"guidance","review_id":"safe","purpose":"Read authorization closure guidance",
                 "arguments":{"name":"authorization"}}
        self.apply("lookup_request",lookup_id="guide",question_id="policy",query=query,units=1)
        self.apply("lookup_result",lookup_id="guide",question_id="policy",query=query,
                   result={"name":"authorization","text":"Trusted category guidance"},evidence=[],native_query_count=0,reused_from=None)
        self.assertIn("authorization",self.workspace.view("initial")["guidance"])
        self.assertFalse(self.workspace.view("other")["guidance"])

    def test_failure_rolls_back_state_and_receipt_then_same_key_can_retry(self):
        action = {"kind":"source", "path":"routes.ts", "start_line":1,"end_line":1,"review_id":"safe"}
        with patch.object(Workspace, "_spend", side_effect=RuntimeError("interrupted before commit")):
            with self.assertRaises(RuntimeError):
                self.workspace.apply("capture", 0, action)
        self.assertEqual(self.workspace.snapshot()["revision"], 0)
        self.assertEqual(self.workspace.snapshot()["evidence"], {})
        self.assertFalse(self.workspace.apply("capture", 0, action)["replayed"])

    def test_receipt_failure_rolls_back_an_already_written_state_row(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON receipts BEGIN "
                       "SELECT RAISE(ABORT, 'injected receipt failure'); END")
        action = {"kind":"reserve_queries", "queries":2}
        with self.assertRaisesRegex(sqlite3.IntegrityError, "receipt failure"):
            self.workspace.apply("reserve", 0, action)
        recovered = Workspace(self.path, self.binding)
        self.assertEqual(recovered.snapshot()["revision"], 0)
        self.assertEqual(recovered.snapshot()["used"]["queries"], 0)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)
            db.execute("DROP TRIGGER fail_receipt")
        self.assertFalse(recovered.apply("reserve", 0, action)["replayed"])

    def test_competing_writer_is_rejected_without_lost_updates(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.OperationalError):
                self.apply("reserve_queries", queries=1)
        self.assertEqual(self.workspace.snapshot()["used"]["queries"], 0)

    def test_initialization_publishes_atomically_and_never_overwrites(self):
        before = self.workspace.snapshot()
        with self.assertRaises(FileExistsError):
            Workspace.create(self.path, self.root, self.binding, self.claims, self.limits)
        self.assertEqual(self.workspace.snapshot(), before)
        with self.assertRaisesRegex(ValueError, "outside"):
            Workspace.create(self.root / "state.sqlite", self.root, self.binding, self.claims, self.limits)
        path = self.directory / "interrupted.sqlite"
        with patch("review_workspace.os.link", side_effect=OSError("publish failed")):
            with self.assertRaises(OSError):
                Workspace.create(path, self.root, self.binding, self.claims, self.limits)
        self.assertFalse(path.exists())
        self.assertEqual(list(self.directory.glob("*.tmp")), [])

    def test_capture_preserves_first_attribution_and_does_not_fabricate_queries(self):
        key = self.capture()
        self.assertEqual(self.capture(claim="unsafe"), key)
        state = self.workspace.snapshot()
        self.assertEqual(state["evidence"][key]["origin"], {
            "kind":"workspace_preparation", "review_id":"safe", "native_query_count":0})
        self.assertEqual(state["used"]["queries"], 0)
        self.assertEqual(state["used"]["source_bytes"], len(state["evidence"][key]["text"].encode()))

    def test_native_source_import_never_expands_truncated_or_mismatched_receipts(self):
        query = {"tool":"source","review_id":"safe","arguments":{}}
        result = {"operation":"get_source","results":{"location":{"path":"routes.ts"},
                  "line_range":{"start_line":1,"end_line":1},"text":"shorter than the actual source"}}
        self.assertIsNone(actions._source_capture(query,{**result,"truncated":True},1))
        self.apply("question",question_id="q",review_ids=["safe"],question="What source decides this?")
        self.apply("lookup_request",lookup_id="q0",question_id="q",query=query,units=1)
        before = self.workspace.snapshot()
        with self.assertRaisesRegex(ValueError,"does not match"):
            self.apply("lookup_capture",capture=actions._source_capture(query,result,1),receipt={
                "kind":"lookup_result","lookup_id":"q0","question_id":"q","query":query,
                "result":result,"evidence":[],"native_query_count":1,"reused_from":None})
        self.assertEqual(self.workspace.snapshot(),before)

    def test_lookup_publication_fence_rolls_back_source_but_retains_observed_cost(self):
        query = {"tool":"source","review_id":"safe","arguments":{}}
        result = {"operation":"get_source","results":{"location":{"path":"routes.ts"},
                  "line_range":{"start_line":1,"end_line":1},"text":self.code.read_text().splitlines()[0]}}
        self.apply("question",question_id="q",review_ids=["safe"],question="What source decides this?")
        self.apply("lookup_request",lookup_id="q0",question_id="q",query=query,units=1)
        size = len(json.dumps(result,ensure_ascii=False).encode("utf-8"))
        self.apply("lookup_observed",lookup_id="q0",received_bytes=size)
        # A second accounting receipt cannot charge the same observation again.
        self.apply("lookup_observed",lookup_id="q0",received_bytes=size)
        before = self.workspace.snapshot()
        action = {"kind":"lookup_capture","capture":actions._source_capture(query,result,1),"receipt":{
            "kind":"lookup_result","lookup_id":"q0","question_id":"q","query":query,
            "result":result,"evidence":[],"native_query_count":1,"reused_from":None}}
        fences = []
        def stale():
            # Other readers see neither staged evidence nor a completed receipt.
            self.assertEqual(self.workspace.snapshot(),before)
            raise ValueError("native owner/source changed")
        with self.assertRaisesRegex(ValueError,"owner/source changed"):
            self.workspace.apply("publish",before["revision"],action,before_commit=stale)
        self.assertEqual(self.workspace.snapshot(),before)
        self.assertIsNone(self.workspace.operation("publish"))
        self.assertEqual(before["received_query_bytes"],size)
        self.assertEqual(before["used"]["queries"],1)
        def fresh():
            self.assertEqual(self.workspace.snapshot(),before)
            fences.append("fresh")
        published = self.workspace.apply("publish",before["revision"],action,before_commit=fresh)
        after = self.workspace.snapshot()
        self.assertEqual(len(after["evidence"]),1)
        self.assertEqual(after["lookups"]["q0"]["status"],"complete")
        self.assertEqual(after["received_query_bytes"],size)
        self.assertEqual(after["lookups"]["q0"]["evidence"],published["result"]["evidence"])
        self.workspace.apply("publish",before["revision"],action,before_commit=lambda:fences.append("replay"))
        self.assertEqual(fences,["fresh","replay"])
        with self.assertRaisesRegex(ValueError,"replay stale"):
            self.workspace.apply("publish",before["revision"],action,
                before_commit=lambda:(_ for _ in ()).throw(ValueError("replay stale")))
        self.assertEqual(self.workspace.snapshot(),after)

    def test_lookup_observation_cannot_be_revised_or_mismatched_by_publication(self):
        query = {"tool":"paths","review_id":"safe","arguments":{}}
        self.apply("question",question_id="q",review_ids=["safe"],question="Which source decides this?")
        self.apply("lookup_request",lookup_id="q0",question_id="q",query=query,units=1)
        self.apply("lookup_observed",lookup_id="q0",received_bytes=4)
        before = self.workspace.snapshot()
        with self.assertRaisesRegex(ValueError,"differs from recorded"):
            self.apply("lookup_observed",lookup_id="q0",received_bytes=5)
        with self.assertRaisesRegex(ValueError,"differs from observed"):
            self.apply("lookup_result",lookup_id="q0",question_id="q",query=query,result={},
                       evidence=[],native_query_count=1,reused_from=None)
        self.assertEqual(self.workspace.snapshot(),before)

    def test_known_safe_and_unsafe_callers_reuse_implementation_without_shared_verdict(self):
        helper, safe, unsafe = self.capture(), self.capture(2,2), self.capture(3,3,"unsafe")
        self.proposition(helper)
        safe_applies, unsafe_applies = self.applicability("safe", safe), self.applicability("unsafe", unsafe)
        self.draft("safe", "not_issue", 2, [safe_applies])
        self.apply("split", work_id="initial", new_work_id="exception", review_ids=["unsafe"], strategy="authorization")
        self.workspace = Workspace(self.path, self.binding)
        view = self.workspace.view("exception")
        self.assertEqual([c["review_id"] for c in view["claims"]], ["unsafe"])
        self.assertIn(helper, view["evidence"])
        self.assertIn(unsafe, view["evidence"])
        self.assertNotIn(safe, view["evidence"])
        self.assertIn("Route parameters", view["propositions"]["body-owner"]["exclusions"])
        self.draft("unsafe", "issue", 3, [unsafe_applies])
        self.assertEqual(self.workspace.view("exception")["claims"], [])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.workspace.bundle_draft("bundle-1")
        self.capture(4,4,"unknown")
        self.draft("unknown", "needs_review", 4, checks=["Which generated operation enforces owner binding?"])
        bundle = self.workspace.bundle_draft("bundle-1")
        self.assertEqual({r["review_id"]:r["decision"] for r in bundle["results"]},
                         {"safe":"not_issue", "unsafe":"issue", "unknown":"needs_review"})

    def test_focus_offers_knowledge_before_applicability_is_established(self):
        helper, caller = self.capture(), self.capture(3,3,"unsafe")
        self.proposition(helper)
        self.apply("split", work_id="initial", new_work_id="caller", review_ids=["unsafe"], strategy="authorization")
        self.apply("focus", work_id="caller", evidence_ids=[caller], proposition_ids=["body-owner"])
        view = self.workspace.view("caller")
        self.assertEqual(view["applicability"], {})
        self.assertEqual(set(view["evidence"]), {helper, caller})
        self.assertEqual(view["propositions"]["body-owner"]["origin"], "reviewer_interpretation")
        with self.assertRaisesRegex(ValueError, "context limit"):
            self.workspace.view("caller", max_bytes=100)

    def test_presented_proposition_dependencies_reopen_drafts_without_asserting_applicability(self):
        helper, caller = self.capture(), self.capture(2,2)
        self.proposition(helper)
        result = {"review_id":"safe","decision":"not_issue","summary":"Scoped closure", "checks":[],
                  "evidence":[{"path":"routes.ts","start_line":2,"end_line":2}]}
        self.apply("draft",result=result,applicability=[],propositions=[{"proposition_id":"body-owner","revision":1}])
        self.assertEqual(self.workspace.snapshot()["applicability"],{})
        self.apply("dispute",proposition_id="body-owner",reason="The recorded condition is incomplete")
        self.assertEqual(self.workspace.snapshot()["claims"]["safe"]["reconsideration"],["body-owner"])

    def test_batch_drafts_are_atomic_when_a_later_result_is_invalid(self):
        self.capture(2,3)
        result = {"review_id":"safe","decision":"not_issue","summary":"Scoped closure", "checks":[],
                  "evidence":[{"path":"routes.ts","start_line":2,"end_line":2}]}
        invalid = {**result,"review_id":"unsafe","evidence":[{"path":"unseen.ts","start_line":1,"end_line":1}]}
        before = self.workspace.snapshot()
        with self.assertRaisesRegex(ValueError,"not captured"):
            self.apply("draft_batch",drafts=[{"result":result,"applicability":[]},{"result":invalid,"applicability":[]}])
        self.assertEqual(self.workspace.snapshot(),before)

    def test_dispute_and_revision_reopen_consumers_across_retired_contexts(self):
        helper, caller = self.capture(), self.capture(2,2)
        self.proposition(helper)
        applies = self.applicability("safe", caller)
        self.draft("safe", "not_issue", 2, [applies])
        self.apply("session", work_id="initial", parent_session=None, max_bytes=32768)
        affected = self.apply("dispute", proposition_id="body-owner", reason="Missing condition discovered")
        self.assertEqual(affected["affected_claims"], ["safe"])
        self.assertIn("safe", [c["review_id"] for c in self.workspace.view("initial")["claims"]])
        with self.assertRaisesRegex(ValueError, "stale applicability"):
            self.draft("safe", "not_issue", 2, [applies])
        self.proposition(helper, "Binding is established subject to the recorded condition.")
        self.assertEqual([p["revision"] for p in self.workspace.knowledge("body-owner")], [1,2])
        with self.assertRaisesRegex(ValueError, "stale"):
            self.applicability("safe", caller, revision=1)
        revised = self.applicability("safe", caller, revision=2)
        self.draft("safe", "not_issue", 2, [revised])
        self.assertEqual(len(self.workspace.snapshot()["claims"]["safe"]["draft_history"]), 1)

    def test_budget_and_unknown_usage_survive_context_replacement_and_split(self):
        first = self.apply("session", work_id="initial", parent_session=None, max_bytes=32768)["session_id"]
        call = self.apply("start_call", session_id=first)["call_id"]
        self.workspace = Workspace(self.path, self.binding)
        self.assertEqual(self.workspace.usage()["unobserved_calls"], 1)
        self.assertIsNone(self.workspace.usage()["totals"]["input_tokens"])
        second = self.apply("session", work_id="initial", parent_session=first, max_bytes=32768)["session_id"]
        with self.assertRaisesRegex(ValueError, "replaced"):
            self.apply("start_call", session_id=first)
        self.apply("finish_call", call_id=call, usage={"input_tokens":100,"cached_input_tokens":0,"output_tokens":4,"elapsed_ms":10})
        self.apply("start_call", session_id=second)
        self.apply("split", work_id="initial", new_work_id="split", review_ids=["unsafe"], strategy="sql")
        child = self.apply("session", work_id="split", parent_session=None, max_bytes=32768)["session_id"]
        self.apply("start_call", session_id=child)
        with self.assertRaisesRegex(ValueError, "aggregate budget"):
            self.apply("start_call", session_id=child)
        self.assertEqual(self.workspace.snapshot()["used"]["model_calls"], 3)
        self.assertEqual(self.workspace.usage()["unobserved_calls"], 2)
        with self.assertRaisesRegex(ValueError, "already recorded"):
            self.apply("finish_call", call_id=call, usage={"input_tokens":100,"cached_input_tokens":0,"output_tokens":4,"elapsed_ms":10})

    def test_context_change_requires_explicit_new_session(self):
        session = self.apply("session", work_id="initial", parent_session=None, max_bytes=32768)["session_id"]
        self.apply("question", question_id="q", review_ids=["safe"], question="Which owner reaches the update?")
        with self.assertRaisesRegex(ValueError, "context changed"):
            self.apply("start_call", session_id=session)
        self.assertEqual(self.workspace.snapshot()["used"]["model_calls"], 0)

    def test_retrieval_does_not_answer_deciding_question(self):
        self.apply("question", question_id="q", review_ids=["safe"], question="Does the effect consume the owner?")
        source = self.capture(2,2)
        self.assertEqual(self.workspace.snapshot()["questions"]["q"]["status"], "open")
        with self.assertRaisesRegex(ValueError, "unanswered"):
            self.draft("safe", "not_issue", 2)
        self.apply("answer", question_id="q", status="blocked", reason="Effect implementation unavailable", evidence=[])
        self.draft("safe", "needs_review", 2, checks=["Does updateByBodyOwner consume body.UserId?"])
        self.apply("answer", question_id="q", status="answered", reason="Caller binding inspected", evidence=[source])
        self.draft("safe", "not_issue", 2)
        self.assertEqual(len(self.workspace.snapshot()["questions"]["q"]["attempts"]), 2)
        self.apply("question", question_id="new", review_ids=["safe"], question="Is there a relevant override?")
        self.assertTrue(self.workspace.snapshot()["claims"]["safe"]["reconsideration"])

    def test_received_lookup_json_bytes_include_reuse_separately_from_unique_source(self):
        self.apply("question",question_id="q",review_ids=["safe"],question="What source decides this?")
        query = {"tool":"paths","review_id":"safe","purpose":"Locate helper","arguments":{"name":"helper","limit":20}}
        result = {"operation":"paths","results":["héĺper.ts"]}
        for i in range(2):
            self.apply("lookup_request",lookup_id=str(i),question_id="q",query=query,units=1)
            self.apply("lookup_result",lookup_id=str(i),question_id="q",query=query,result=result,evidence=[],
                       native_query_count=1 if i == 0 else 0,reused_from=None if i == 0 else "0")
        state = self.workspace.snapshot()
        self.assertEqual(state["received_query_bytes"],2 * len(json.dumps(result,ensure_ascii=False).encode("utf-8")))
        self.assertEqual(state["used"]["source_bytes"],0)

    def test_same_question_preserves_distinct_navigation_receipts_and_context_limit(self):
        self.apply("question",question_id="q",review_ids=["safe"],question="Where are the caller and guard?")
        for i,path in enumerate(("caller.ts","guard.ts")):
            query = {"tool":"paths","review_id":"safe","purpose":"Find a required declaration",
                     "arguments":{"name":path,"limit":20}}
            self.apply("lookup_request",lookup_id=str(i),question_id="q",query=query,units=1)
            self.apply("lookup_result",lookup_id=str(i),question_id="q",query=query,
                       result={"operation":"paths","results":[path]},evidence=[],native_query_count=1,reused_from=None)
        view = self.workspace.view("initial")
        self.assertEqual(set(view["lookups"]),{"0","1"})
        self.assertEqual([r["result"]["results"] for r in view["lookups"].values()],[["caller.ts"],["guard.ts"]])
        self.assertTrue(all(r["question_id"] == "q" for r in view["lookups"].values()))
        self.assertEqual(view["questions"]["q"]["status"],"open")
        with self.assertRaisesRegex(ValueError,"context limit"):
            self.workspace.view("initial",max_bytes=100)
        # Reopening the process retains both results, rather than only the last.
        self.assertEqual(Workspace(self.path,self.binding).view("initial")["lookups"],view["lookups"])
        proof = self.capture(1,2)
        self.apply("answer",question_id="q",status="answered",reason="Caller and guard source inspected",evidence=[proof])
        self.assertEqual(self.workspace.view("initial")["lookups"],{})

    def test_stale_source_blocks_reuse_and_assembled_draft(self):
        helper, caller = self.capture(), self.capture(2,4)
        self.proposition(helper)
        applies = self.applicability("safe", caller)
        self.draft("safe", "not_issue", 2, [applies])
        self.apply("focus", work_id="initial", evidence_ids=[], proposition_ids=["body-owner"])
        self.draft("unsafe", "issue", 3)
        self.draft("unknown", "needs_review", 4, checks=["Which generated operation is selected?"])
        self.assertEqual(len(self.workspace.bundle_draft("bundle-1")["results"]), 3)
        self.code.write_text("changed source\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.applicability("unsafe", caller)
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.workspace.view("initial")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.workspace.knowledge("body-owner")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.workspace.bundle_draft("bundle-1")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.capture()

    def test_unknown_references_invalid_ranges_and_foreign_applicability_rollback(self):
        for path, first, last in (("../outside",1,1),("routes.ts",0,1),("routes.ts",1,6),("routes.ts",True,1)):
            with self.subTest(path=path,first=first,last=last), self.assertRaises(ValueError):
                self.apply("source", path=path, start_line=first, end_line=last, review_id="safe")
        with self.assertRaises(ValueError):
            self.proposition("unknown-evidence")
        helper, caller = self.capture(), self.capture(2,3)
        self.proposition(helper)
        applies = self.applicability("safe", caller)
        with self.assertRaisesRegex(ValueError, "foreign"):
            self.draft("unsafe", "issue", 3, [applies])
        before = copy.deepcopy(self.workspace.snapshot())
        with self.assertRaises(ValueError):
            self.apply("reserve_queries", queries=5)
        self.assertEqual(self.workspace.snapshot(), before)

    def test_terminal_eof_source_position_matches_native_only_after_final_lf(self):
        key = self.capture(3,5)
        evidence = self.workspace.snapshot()["evidence"][key]
        self.assertEqual(evidence["end_line"],5)
        self.assertEqual(evidence["text"],"\n".join(self.code.read_text().splitlines()[2:]))
        self.code.write_text("no terminal newline",encoding="utf-8")
        other = self.directory / "without-lf.sqlite"
        workspace = Workspace.create(other,self.root,self.binding,self.claims,self.limits)
        with self.assertRaisesRegex(ValueError,"exceeds file"):
            workspace.apply("eof",0,{"kind":"source","path":"routes.ts","start_line":1,"end_line":2,"review_id":"safe"})

    def test_native_callable_fragment_does_not_add_prefix_or_serve_a_whole_line(self):
        raw = self.code.read_text().splitlines()[0]
        excerpt = raw.removeprefix("function ")
        result = self.apply("source",path="routes.ts",start_line=1,end_line=1,review_id="safe",excerpt=excerpt)
        evidence = self.workspace.snapshot()["evidence"][result["evidence_id"]]
        self.assertEqual(evidence["text"],excerpt)
        self.assertTrue(evidence["fragment"])
        self.assertFalse(evidence["complete_file"])
        before = self.workspace.snapshot()
        with self.assertRaisesRegex(ValueError,"does not match"):
            self.apply("source",path="routes.ts",start_line=1,end_line=1,review_id="safe",excerpt="not in this source")
        self.assertEqual(self.workspace.snapshot(),before)

    def test_cli_init_apply_view_and_status_across_processes(self):
        seed = self.directory / "seed.json"
        seed.write_text(json.dumps({"binding":self.binding,"source_root":str(self.root),"claims":self.claims,"limits":self.limits}))
        path = self.directory / "cli.sqlite"
        def cli(command, *args):
            output = subprocess.check_output([sys.executable,str(PRODUCT/"scripts/review_workspace.py"),command,
                "--workspace",str(path),"--seed",str(seed),*args], text=True, encoding="utf-8")
            return json.loads(output)
        self.assertFalse(cli("init")["native_admission"])
        action = self.directory / "action.json"
        action.write_text(json.dumps({"kind":"reserve_queries","queries":1}))
        result = cli("apply", "--action",str(action),"--operation-key","q","--expected-revision","0")
        self.assertEqual(result["result"]["revision"], 1)
        self.assertEqual(cli("status")["result"]["used"]["queries"], 1)
        self.assertEqual(len(cli("view")["result"]["claims"]), 3)


if __name__ == "__main__":
    unittest.main()
