"""Case evidence survives worker failure and invalidates explicit consumers only."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from review_case_state import CaseState


class Cases(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "guard.js").write_text("function guard() { return true; }\n", encoding="utf8")
        self.binding = {"snapshot":"one", "plan":"one", "runtime":"one"}
        self.registry = {"items":[{"id":name, "checks":[{"id":"fact"}, {"id":"security"}],
                                  "verify_review_ids":["native-id"] if name == "native" else []}
                                  for name in ("native", "ai-only", "independent")]}
        self.store = CaseState.create(self.base / "state.sqlite", self.root, self.binding, self.registry)
        self.check = dict(id="fact", question="Does this guard return true?", scope="This body.",
                          acceptance="Cite the return expression.")
        self.proof = dict(path="guard.js", start_line=1, end_line=1,
                          quote="function guard() { return true; }")
        self.answer = dict(status="complete", proofs=[self.proof],
            question_provider={"model":"fact-model"}, question_conversation_id="fact-session",
            draft={"work_checks":[dict(check_id="fact", status="satisfied", summary="Returns true.",
                evidence=[{key:self.proof[key] for key in ("path", "start_line", "end_line")}], next_deciding_fact=None)]})

    def write(self, name, value):
        path = self.base / (name + ".json")
        path.write_text(json.dumps(value), encoding="utf8")
        return path

    def question(self, name="answer", answer=None):
        path = self.write(name, self.answer if answer is None else answer)
        return self.store.record_question("native", self.check, path)

    def finish(self, case_id, dependencies):
        rows = [dict(check_id=check, status="satisfied", summary="Scoped source proof.",
                     evidence=[{key:self.proof[key] for key in ("path", "start_line", "end_line")}],
                     next_deciding_fact=None, assertion_dependencies=dependencies if check == "security" else [])
                for check in ("fact", "security")]
        result = dict(case_id=case_id, status="complete", calls=1, proofs=[self.proof],
                      draft=dict(work_checks=rows, results=[], proposals=[]))
        path = self.write(case_id + str(self.store.snapshot()["revision"]), result)
        self.store.record_result(case_id, path)
        return path

    def test_assertions_survive_failed_owner_and_reopening_store(self):
        refs = self.question()
        failed = self.write("failed", dict(case_id="native", status="incomplete", calls=1))
        self.store.record_result("native", failed)
        restored = CaseState(self.store.path, self.binding)
        row = restored.results()[0]
        self.assertEqual(row["status"], "incomplete")
        self.assertEqual(row["partial_fact_checks"][0]["status"], "satisfied")
        self.assertEqual(row["provisional_fact_answers"]["fact"]["assertions"], refs)
        assertion = restored.snapshot()["assertions"][refs[0]["assertion_id"]][-1]
        self.assertEqual(assertion["provider"]["model"], "fact-model")
        self.assertEqual(assertion["conversation_id"], "fact-session")
        self.assertEqual(self.question(), refs, "Identical receipt replay must not create a new revision")
        self.assertEqual(len(restored.snapshot()["assertions"][refs[0]["assertion_id"]]), 1)

    def test_revision_reopens_only_consumers_and_keeps_distinct_conditions(self):
        refs = self.question()
        for case in ("native", "ai-only"):
            self.finish(case, refs)
        self.finish("independent", [])
        changed = copy.deepcopy(self.answer)
        changed["draft"]["work_checks"][0].update(status="violated", summary="The earlier proposition was too broad.")
        newer = self.question("replacement", changed)
        self.assertEqual(newer[0]["version"], 2)
        rows = {row["case_id"]:row for row in self.store.results()}
        self.assertEqual(set(rows["native"]["reconsideration"]), {"security"})
        self.assertEqual(set(rows["ai-only"]["reconsideration"]), {"security"})
        self.assertEqual(rows["independent"]["reconsideration"], {})
        with self.assertRaisesRegex(ValueError, "stale"):
            self.finish("native", refs)
        self.finish("ai-only", [])
        self.assertEqual(next(r for r in self.store.results() if r["case_id"] == "ai-only")["reconsideration"], {})
        self.assertTrue(self.store.snapshot()["cases"]["ai-only"]["result_history"])

    def test_dispute_and_unresolved_replacement_preserve_history(self):
        refs = self.question()
        self.finish("ai-only", refs)
        affected = self.store.submit("dispute", dict(kind="dispute", **refs[0], reason="An early return was omitted."))
        self.assertEqual(affected, [dict(case_id="ai-only", check_id="security")])
        with self.assertRaisesRegex(ValueError, "disputed"):
            self.finish("native", refs)
        unresolved = copy.deepcopy(self.answer)
        unresolved["draft"]["work_checks"][0].update(status="unresolved", next_deciding_fact="Read the effective binding.")
        self.assertEqual(self.question("unresolved", unresolved), [])
        history = self.store.snapshot()["assertions"][refs[0]["assertion_id"]]
        self.assertEqual([entry["status"] for entry in history], ["disputed", "unresolved"])

    def test_source_and_result_tampering_fail_closed(self):
        refs = self.question()
        path = self.finish("ai-only", refs)
        path.write_text("{}")
        with self.assertRaisesRegex(ValueError, "saved case result changed"):
            self.store.results()
        with self.assertRaisesRegex(ValueError, "binding differs"):
            CaseState(self.store.path, {"snapshot":"other"})
        (self.root / "guard.js").write_text("function guard() { return false; }\n")
        with self.assertRaisesRegex(ValueError, "source changed"):
            CaseState.validate_dependencies(self.store.snapshot(), refs)

    def test_native_audit_preserves_assertions_and_marks_case_reconciliation(self):
        refs = self.question()
        self.finish("native", refs)
        self.store.submit("audit", dict(kind="native_audit", case_id="native",
            review_ids=["native-id"], reason="Native proof changed."))
        row = self.store.results()[0]
        self.assertEqual(row["native_reconsideration"], {"native-id":"Native proof changed."})
        self.assertEqual(row["draft"]["work_checks"][1]["status"], "satisfied")
        self.assertEqual(self.store.snapshot()["assertions"][refs[0]["assertion_id"]][-1]["status"], "available")
        with self.assertRaisesRegex(ValueError, "required Verify IDs"):
            self.store.submit("new-proposal-audit", dict(kind="native_audit", case_id="ai-only",
                review_ids=["new-proposal"], reason="Do not expand a fixed target."))


if __name__ == "__main__":
    unittest.main()
