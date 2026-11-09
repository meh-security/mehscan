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


if __name__ == "__main__":
    unittest.main()
