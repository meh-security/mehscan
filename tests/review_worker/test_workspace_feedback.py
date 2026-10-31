"""Routine filter feedback stays inside paid/query/source freshness boundaries."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_actions as fixtures
import review_worker as worker


class LookupFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.WorkspaceActionTests("test_partial_closure_lookup_learning_and_cross_work_knowledge_reuse")
        self.fx.extra_source = {"nested/code.js":"export const marker = 1;\n"}
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.bridge = self.fx.bridge
        self.claims = list(self.bridge.workspace.snapshot()["claims"].values())
        self.rid = self.claims[0]["review_id"]

    def query(self,tool="references",**arguments):
        return {"tool":tool,"review_id":self.rid,"purpose":"Locate the declaration relevant to the selected relationship",
                "arguments":arguments or {"symbol":"marker","path":"nested/code.js","path_prefix":"nested","limit":20}}

    def reply(self,queries,decisions=None):
        return {"updates":[],"decisions":decisions or [],"lookups":[{
            "question_id":"binding","review_ids":[self.rid],"question":"Which implementation applies to the selected operation?",
            "queries":queries}]}

    def test_mixed_feedback_and_valid_lookup_then_explicit_correction(self):
        invalid = [self.query(),self.query("symbol",name="marker",path="nested",limit=20)]
        valid = self.query("source",path="helper.js",start_line=1,end_line=1)
        other = self.fx.decision(self.claims[1])
        self.fx.turn("mixed",lambda task,packet:self.reply([*invalid,valid],[other]))
        state = self.bridge.workspace.snapshot()
        lookups = sorted(state["lookups"].values(),key=lambda l:l["sequence"])
        for lookup,query,code in zip(lookups,invalid,("conflicting_path_filters","file_filter_is_directory")):
            self.assertEqual(lookup["query"],query)
            self.assertEqual(lookup["evidence"],[])
            self.assertEqual(lookup["native_query_count"],0)
            self.assertIsNone(lookup["reused_from"])
            self.assertEqual(lookup["result"]["code"],code)
            self.assertFalse(lookup["result"]["native_query_executed"])
        self.assertIn("path_prefix",lookups[0]["result"]["allowed_arguments"]["optional"])
        self.assertNotIn("path_prefix",lookups[1]["result"]["allowed_arguments"]["optional"])
        self.assertNotIn("path_prefix",lookups[1]["result"]["message"])
        self.assertIn("omit path",lookups[1]["result"]["message"])
        self.assertEqual(lookups[2]["native_query_count"],1)
        self.assertTrue(lookups[2]["evidence"])
        self.assertEqual(state["used"]["queries"],3)
        self.assertEqual(state["questions"]["binding"]["status"],"open")
        self.assertIsNotNone(state["claims"][other["review_id"]]["draft"])
        self.assertEqual(state["received_query_bytes"],sum(len(json.dumps(l["result"],ensure_ascii=False).encode()) for l in lookups))
        def corrected(task,packet):
            self.assertEqual(sum(l["result"].get("operation")=="lookup_feedback" for l in packet["workspace_evidence"]["lookups"].values()),2)
            return self.reply([self.query("references",symbol="marker",path_prefix="nested",limit=20),
                               self.query("symbol",name="marker",path="nested/code.js",limit=20)])
        self.fx.turn("corrected",corrected)
        current = self.bridge.workspace.snapshot()
        last = sorted(current["lookups"].values(),key=lambda l:l["sequence"])[-2:]
        self.assertTrue(all(l["native_query_count"]==1 and l["result"]["operation"]!="lookup_feedback" for l in last))
        self.assertEqual(current["used"]["queries"],5)
        self.assertEqual(self.bridge.workspace.usage()["totals"]["input_tokens"],200)
        self.assertIn('"lookup_feedback"',self.fx.calls[-1]["prompt"])

    def test_known_directory_intent_executes_once_and_retains_each_request_scope(self):
        directory = self.query("references",symbol="marker",path="nested")
        canonical = self.query("references",symbol="marker",path_prefix="nested")
        duplicate = self.query("references",symbol="marker",path="nested",path_prefix="nested/",limit=20)
        original = json.loads(json.dumps(directory))
        self.fx.turn("directory",lambda task,packet:self.reply([directory]))
        def continued(task,packet):
            old = next(iter(packet["workspace_evidence"]["lookups"].values()))
            self.assertEqual(old["filter_normalization"]["original_arguments"],original["arguments"])
            self.assertEqual(old["filter_normalization"]["effective_arguments"],
                             {"symbol":"marker","path_prefix":"nested","limit":20})
            return self.reply([canonical,duplicate])
        self.fx.turn("same-effective-scope",continued)
        rows = sorted(self.bridge.workspace.snapshot()["lookups"].values(),key=lambda l:l["sequence"])
        self.assertEqual(directory,original)
        self.assertEqual([r["query"]for r in rows],[directory,canonical,duplicate])
        self.assertEqual([r["native_query_count"]for r in rows],[1,0,0])
        self.assertEqual(rows[1]["reused_from"],rows[2]["reused_from"])
        self.assertTrue(all(r["result"]==rows[0]["result"]and not r["evidence"]for r in rows))
        self.assertEqual([r["path"]for r in rows[0]["result"]["results"]],["nested/code.js"])
        self.assertNotIn("filter_normalization",rows[1])
        self.assertEqual(rows[2]["filter_normalization"]["original_arguments"],duplicate["arguments"])
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["used"]["queries"],3)
        self.assertEqual(state["questions"]["binding"]["status"],"open")
        self.assertEqual(state["received_query_bytes"],sum(len(json.dumps(r["result"],ensure_ascii=False).encode())for r in rows))

    def test_normalization_receipt_cannot_change_effective_scope(self):
        self.fx.turn("directory",lambda task,packet:self.reply([self.query("references",symbol="marker",path="nested")]))
        state = self.bridge.workspace.snapshot();key,row=next(iter(state["lookups"].items()))
        receipt = {k:row[k]for k in ("question_id","query","result","evidence","native_query_count","reused_from","filter_normalization")}
        receipt = json.loads(json.dumps(receipt))
        receipt.update(kind="lookup_result",lookup_id=key)
        receipt["filter_normalization"]["effective_arguments"]["path_prefix"]="other"
        with self.assertRaisesRegex(ValueError,"normalization changes its arguments"):
            self.bridge.workspace.preview(receipt)
        self.assertEqual(self.bridge.workspace.snapshot(),state)

    def test_file_in_directory_filter_and_required_file_tool_have_precise_alternatives(self):
        self.fx.turn("inverted",lambda task,packet:self.reply([
            self.query("references",symbol="marker",path_prefix="helper.js",limit=20),
            self.query("outline",path="nested")]))
        rows = sorted(self.bridge.workspace.snapshot()["lookups"].values(),key=lambda l:l["sequence"])
        self.assertEqual(rows[0]["result"]["code"],"directory_filter_is_file")
        self.assertIn("Use path",rows[0]["result"]["message"])
        self.assertEqual(rows[1]["result"]["code"],"file_filter_is_directory")
        self.assertNotIn("omit path",rows[1]["result"]["message"])
        self.assertTrue(all(r["native_query_count"]==0 and not r["evidence"] for r in rows))

    def test_conflicting_filters_return_feedback_without_choosing_or_executing_scope(self):
        query = self.query("references",symbol="marker",path="nested/code.js",path_prefix="nested",limit=20)
        self.fx.turn("conflicting",lambda task,packet:self.reply([query]))
        state = self.bridge.workspace.snapshot()
        row = next(iter(state["lookups"].values()))
        self.assertEqual(row["query"],query)
        self.assertEqual(row["result"]["code"],"conflicting_path_filters")
        self.assertEqual(row["native_query_count"],0)
        self.assertEqual(row["evidence"],[])
        self.assertEqual(state["used"]["queries"],1)
        def corrected(task,packet):
            self.assertIn("conflicting_path_filters",json.dumps(packet["workspace_evidence"]["lookups"]))
            return self.reply([self.query("references",symbol="marker",path_prefix="nested",limit=20)])
        self.fx.turn("explicit-directory",corrected)
        rows = sorted(self.bridge.workspace.snapshot()["lookups"].values(),key=lambda r:r["sequence"])
        self.assertEqual(rows[-1]["query"]["arguments"],{"symbol":"marker","path_prefix":"nested","limit":20})
        self.assertEqual(rows[-1]["native_query_count"],1)
        self.assertEqual(self.bridge.workspace.usage()["calls"],2)

    def test_conflicting_filters_do_not_mask_path_escape_or_invalid_limits(self):
        for args in ({"symbol":"marker","path":"../outside","path_prefix":"nested","limit":20},
                     {"symbol":"marker","path":"nested/code.js","path_prefix":"../outside","limit":20},
                     {"symbol":"marker","path":"nested/code.js","path_prefix":"nested","limit":101}):
            with self.subTest(args=args),self.assertRaises(ValueError) as caught:
                worker.research_arguments(self.query("references",**args),self.bridge.root,[self.rid],self.bridge.directory/"journals")
            self.assertNotIsInstance(caught.exception,worker.ResearchFilterError)

    def test_feedback_cannot_answer_a_question_without_source_proof(self):
        self.fx.turn("invalid",lambda task,packet:self.reply([self.query()]))
        with self.assertRaisesRegex(ValueError,"known references"):
            self.fx.turn("false-proof",lambda task,packet:{"updates":[{
                "kind":"answer","question_id":"binding","status":"answered",
                "reason":"The lookup error means there is no missing protection.","evidence":[]}],"lookups":[],"decisions":[]})
        self.assertEqual(self.bridge.workspace.snapshot()["questions"]["binding"]["status"],"open")
        self.assertEqual(self.bridge.workspace.usage()["calls"],2)

    def test_security_scope_failure_in_later_query_remains_atomic_and_fatal(self):
        queries = [self.query(),self.query("source",path="helper.js",start_line=1,end_line=1),
                   self.query("references",symbol="marker",path="../outside",limit=20)]
        with self.assertRaisesRegex(ValueError,"relative"):
            self.fx.turn("escape",lambda task,packet:self.reply(queries,[self.fx.decision(self.claims[1])]))
        state = self.bridge.workspace.snapshot()
        self.assertEqual(state["lookups"],{})
        self.assertEqual(state["used"]["queries"],0)
        self.assertTrue(all(c["draft"] is None for c in state["claims"].values()))
        self.assertEqual(self.bridge.workspace.usage()["totals"]["input_tokens"],100)

    def test_other_malformed_arguments_are_not_hidden_by_directory_feedback(self):
        for tool,args in (("references",{"symbol":"marker","path":"nested","limit":101}),
                          ("source",{"path":"nested","start_line":1,"end_line":402})):
            with self.subTest(tool=tool),self.assertRaises(ValueError) as caught:
                worker.research_arguments(self.query(tool,**args),self.bridge.root,[self.rid],self.bridge.directory/"journals")
            self.assertNotIsInstance(caught.exception,worker.ResearchFilterError)

    def test_feedback_is_charged_and_never_creates_extra_model_slots(self):
        for index in range(5):
            self.fx.turn("invalid-"+str(index),lambda task,packet:self.reply([self.query()]))
        # The last paid call is a final checkpoint, so it cannot buy another lookup.
        with self.assertRaisesRegex(ValueError,"final workspace checkpoint cannot request lookups"):
            self.fx.turn("invalid-final",lambda task,packet:self.reply([self.query()]))
        before = self.bridge.workspace.snapshot()
        self.assertEqual(before["used"]["queries"],5)
        self.assertEqual(len(before["lookups"]),5)
        self.assertTrue(all(l["native_query_count"]==0 and l["reused_from"] is None for l in before["lookups"].values()))
        self.assertGreater(before["received_query_bytes"],0)
        with self.assertRaisesRegex(ValueError,"budget exhausted"):
            self.fx.turn("no-seventh-call",lambda task,packet:self.reply([self.query()]))
        self.assertEqual(len(self.fx.calls),6)
        self.assertEqual(self.bridge.workspace.usage()["calls"],6)

    def test_feedback_batch_cannot_exceed_query_allowance(self):
        self.bridge.apply("spent",{"kind":"reserve_queries","queries":7})
        with self.assertRaisesRegex(ValueError,"aggregate query allowance"):
            self.fx.turn("no-two-more",lambda task,packet:self.reply([self.query(),self.query()]))
        self.assertEqual(self.bridge.workspace.snapshot()["lookups"],{})
        self.assertEqual(self.bridge.workspace.snapshot()["used"]["queries"],7)

    def test_freshness_failure_before_feedback_publication_still_rejects_it(self):
        original = self.bridge.check
        changed = []
        def check():
            state = self.bridge.workspace.snapshot()
            if any(l.get("received_bytes") for l in state["lookups"].values()) and not changed:
                changed.append(True)
                app = self.bridge.root/"app.js"
                app.write_text(app.read_text()+"// source changed before feedback publication\n")
            return original()
        with patch.object(self.bridge,"check",side_effect=check),self.assertRaises(worker.CommandFailure):
            self.fx.turn("stale-feedback",lambda task,packet:self.reply([self.query()]))
        state = self.bridge.workspace.snapshot()
        self.assertEqual(changed,[True])
        self.assertEqual(next(iter(state["lookups"].values()))["status"],"reserved")
        self.assertGreater(state["received_query_bytes"],0)
        self.assertEqual(self.bridge.workspace.usage()["totals"]["input_tokens"],100)

    def test_unknown_paid_usage_prevents_feedback_processing(self):
        session = self.bridge.prepare("initial",self.fx.fixture.config_path,"unknown")['session_id']
        with self.assertRaisesRegex(ValueError,"usage is unknown"):
            self.bridge.review(session,self.fx.fixture.config_path,lambda task:{"workspace_actions":self.reply([self.query()])})
        self.assertEqual(self.bridge.workspace.usage()["unobserved_calls"],1)
        self.assertEqual(self.bridge.workspace.snapshot()["lookups"],{})


if __name__=="__main__":
    unittest.main()
