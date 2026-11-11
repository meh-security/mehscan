"""Source coverage identities stay separate from fetched evidence and model prose."""
import copy
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skills/mehscan-security/scripts"))
import codex_protocol
import source_review_protocol


class SourceCoverageTests(unittest.TestCase):
    def setUp(self):
        self.windows = {
            "s0": {"path": "reader.cs", "start_line": 1, "end_line": 40},
            "s1": {"path": "reader.cs", "start_line": 41, "end_line": 80},
        }
        self.task = {"kind": "source_review", "review_ids": [], "research": {
            "rounds_remaining": 1, "artifact_handles": {"s0": "a", "s1": "b", "f0": "lookup"},
            "source_artifact_handles": ["s0", "s1", "f0"], "coverage_windows": self.windows}}
        self.reply = {"action": "final", "research": [], "working_chain": "Inspected source.",
                      "draft": {"results": [], "proposals": [], "coverage": [
                          {"window_ref": ref, "status": "examined", "summary": "Reviewed."}
                          for ref in self.windows]}}

    def test_coverage_expands_from_controller_identity_without_mutating_reply(self):
        original = copy.deepcopy(self.reply)
        Draft202012Validator(codex_protocol.build_schema(self.task)).validate(self.reply)
        result = source_review_protocol.envelope(self.reply, self.task)
        self.assertEqual(result["draft"]["coverage"], [
            {**w, "status": "examined", "summary": "Reviewed."} for w in self.windows.values()])
        self.assertEqual(self.reply, original)

    def test_foreign_lookup_and_model_supplied_ranges_are_rejected(self):
        for update in ({"window_ref": "f0"}, {"path": "helper.cs", "start_line": 3, "end_line": 7}):
            reply = copy.deepcopy(self.reply)
            reply["draft"]["coverage"][0].update(update)
            self.assertTrue(list(Draft202012Validator(codex_protocol.build_schema(self.task)).iter_errors(reply)))

    def test_missing_duplicate_and_foreign_windows_cannot_complete_coverage(self):
        for refs in (["s0"], ["s0", "s0"], ["s0", "f0"]):
            reply = copy.deepcopy(self.reply)
            reply["draft"]["coverage"] = [
                {"window_ref": ref, "status": "examined", "summary": "Reviewed."} for ref in refs]
            with self.subTest(refs=refs), self.assertRaisesRegex(ValueError, "exactly once"):
                source_review_protocol.envelope(reply, self.task)

    def test_wire_schema_remains_stable_across_assignments_and_turns(self):
        other = copy.deepcopy(self.task)
        other["research"].update(rounds_remaining=0, coverage_windows={"s9": {
            "path": "other.py", "start_line": 200, "end_line": 210}})
        self.assertEqual(codex_protocol.build_schema(self.task, bound_handles=False),
                         codex_protocol.build_schema(other, bound_handles=False))
        self.assertNotEqual(codex_protocol.build_schema(self.task), codex_protocol.build_schema(other))

    def test_proposal_reference_limit_matches_native_admission(self):
        schema = codex_protocol.build_schema(self.task, bound_handles=False)
        draft = schema["properties"]["draft"]["anyOf"][0]
        refs = draft["properties"]["proposals"]["items"]["properties"]["evidence"]
        cite = {"path": "reader.cs", "start_line": 1, "end_line": 2}
        validator = Draft202012Validator(refs)
        validator.validate([cite] * 8)
        self.assertTrue(list(validator.iter_errors([])))
        self.assertTrue(list(validator.iter_errors([cite] * 9)))


class SourceCitationTests(unittest.TestCase):
    def test_claim_repair_locator_uses_the_same_bound_source_handles(self):
        self.task["followup_selection"] = True
        value={"root":{"source_ref":"f2","line":23},"property":"resource_bounds",
            "applicability":"local_contract","basis":"The supplied implementation enforces this bound.",
            "kind":"security_contract","impact":"conditional","conditions":"The supported optional decoder mode."}
        for assessed in [self.reply["draft"]["results"][0],self.reply["draft"]["proposals"][0]["assessment"]]:
            assessed.update(claim_context=copy.deepcopy(value),followup=None)
        original=copy.deepcopy(self.reply)
        Draft202012Validator(codex_protocol.build_schema(self.task)).validate(self.reply)
        draft=source_review_protocol.envelope(self.reply,self.task)["draft"]
        for assessed in [draft["results"][0],draft["proposals"][0]["assessment"]]:
            self.assertEqual(assessed["claim_context"]["root"],{"path":"helper.cs","start_line":23,"end_line":23})
        self.assertEqual(self.reply,original)

    def setUp(self):
        SourceCoverageTests.setUp(self)
        self.task["research"]["citation_windows"] = {
            **{ref: {**w, "anchor": True} for ref, w in self.windows.items()},
            "f1": {"path": "helper.cs", "start_line": 10, "end_line": 20, "anchor": False},
            "f2": {"path": "helper.cs", "start_line": 22, "end_line": 24, "anchor": False},
        }
        self.task["review_ids"] = ["native-id"]
        assessment = {"decision": "needs_review", "confidence": "medium",
                      "summary": "Caller binding remains unresolved.", "reason": "Inspect the caller.",
                      "evidence": [{"source_ref": ref, "line": None} for ref in ("f1", "f2")],
                      "checks": ["Inspect the caller."], "blockers": [], "diagnosis": None,
                      "source_leads": [{"question": "Does the adjacent consumer enforce the same bound?",
                                        "security_relevance": "Input reaches a separate consumer.",
                                        "distinct_from_review": "Different consumer.",
                                        "evidence": {"source_ref": "f2", "line": 23}}]}
        self.reply["draft"]["results"] = [{**copy.deepcopy(assessment), "review_id": "native-id"}]
        self.reply["draft"]["proposals"] = [{
            "key": "consumer", "capability": "deserialization", "cwes": ["CWE-400"],
            "question": "Does the caller enforce the bound?", "mechanism": "Input reaches the consumer.",
            "consequence": "Resource amplification if unchecked.", "priority": "value",
            "anchor": {"source_ref": "s0", "line": 3},
            "evidence": copy.deepcopy(assessment["evidence"]), "assessment": copy.deepcopy(assessment)}]

    def test_citations_expand_without_joining_the_unread_gap_or_mutating_the_reply(self):
        original = copy.deepcopy(self.reply)
        Draft202012Validator(codex_protocol.build_schema(self.task)).validate(self.reply)
        draft = source_review_protocol.envelope(self.reply, self.task)["draft"]
        expected = [{"path": "helper.cs", "start_line": 10, "end_line": 20},
                    {"path": "helper.cs", "start_line": 22, "end_line": 24}]
        proposal = draft["proposals"][0]
        for row in (draft["results"][0], proposal, proposal["assessment"]):
            self.assertEqual(row["evidence"], expected)
        self.assertEqual(proposal["anchor"], {"path": "reader.cs", "start_line": 3, "end_line": 3})
        self.assertEqual(draft["results"][0]["source_leads"][0]["evidence"],
                         {"path": "helper.cs", "start_line": 23, "end_line": 23})
        self.assertEqual(self.reply, original)

    def test_wire_schema_cannot_express_a_free_range_or_helper_anchor(self):
        validator = Draft202012Validator(codex_protocol.build_schema(self.task, bound_handles=False))
        for update in ({"end_line": 24}, {"path": "helper.cs", "start_line": 10, "end_line": 24}):
            reply = copy.deepcopy(self.reply)
            reply["draft"]["proposals"][0]["evidence"][0].update(update)
            self.assertTrue(list(validator.iter_errors(reply)))
        for anchor in ({"source_ref": "f1", "line": 10}, {"source_ref": "s0", "line": None}):
            reply = copy.deepcopy(self.reply)
            reply["draft"]["proposals"][0]["anchor"] = anchor
            self.assertTrue(list(validator.iter_errors(reply)))

    def test_local_validation_and_envelope_reject_foreign_or_out_of_extent_references(self):
        validator = Draft202012Validator(codex_protocol.build_schema(self.task))
        for cite in ({"source_ref": "f1", "line": 21}, {"source_ref": "f2", "line": 21},
                     {"source_ref": "f0", "line": None}, {"source_ref": "s0", "line": True}):
            reply = copy.deepcopy(self.reply)
            reply["draft"]["results"][0]["evidence"] = [cite]
            with self.subTest(cite=cite):
                self.assertTrue(list(validator.iter_errors(reply)))
                with self.assertRaisesRegex(ValueError, "source citation"):
                    source_review_protocol.envelope(reply, self.task)
        reply = copy.deepcopy(self.reply)
        reply["draft"]["proposals"][0]["anchor"] = {"source_ref": "f1", "line": 10}
        with self.assertRaisesRegex(ValueError, "source citation"):
            source_review_protocol.envelope(reply, self.task)

    def test_wire_schema_stays_stable_as_delivered_citation_catalog_grows(self):
        other = copy.deepcopy(self.task)
        other["research"]["citation_windows"]["f9"] = {
            "path": "another.cs", "start_line": 100, "end_line": 110, "anchor": False}
        self.assertEqual(codex_protocol.build_schema(self.task, bound_handles=False),
                         codex_protocol.build_schema(other, bound_handles=False))
        self.assertNotEqual(codex_protocol.build_schema(self.task), codex_protocol.build_schema(other))

    def test_empty_catalog_allows_empty_decisions_but_no_invented_citation(self):
        self.task["research"]["citation_windows"] = {}
        schema = codex_protocol.build_schema(self.task)
        Draft202012Validator.check_schema(schema)
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(self.reply)))
        self.task["review_ids"] = []
        self.reply["draft"].update(results=[], proposals=[])
        Draft202012Validator(codex_protocol.build_schema(self.task)).validate(self.reply)


if __name__ == "__main__":
    unittest.main()
