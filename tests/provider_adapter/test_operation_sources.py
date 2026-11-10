"""Prompt sharing preserves exact source, qualifications and per-ID schemas."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_codex as fixtures

protocol = fixtures.protocol


class OperationSources(unittest.TestCase):
    def packet(self):
        loc = {"path": "app.py", "start_line": 2, "end_line": 2,
               "start_column": 5, "end_column": 14, "start_byte_offset": 15, "end_byte_offset": 24}
        source = {"role": "python_orm_effect_context", "location": loc, "excerpt": "return é",
                  "truncated": True, "verified": False, "evidence_id": "anchor-a"}
        return {"operation_groups": [{"review_ids": ["a", "b"], "source_ref": "body"}],
                "primary": {"windows": [{"artifact_id": "body", "side": "current", "path": "app.py",
                    "start_line": 1, "end_line": 2, "text": "def run():\n    return é"}]},
                "sweep": {"source_contexts": [source, {**source, "evidence_id": "anchor-b"}]},
                "sweep_source_handles": [{"source_context_index": i, "artifact_id": "context" + str(i)} for i in range(2)]}

    def test_shared_text_moves_to_one_source_but_locations_and_qualifications_remain(self):
        packet = self.packet()
        before = copy.deepcopy(packet)
        display = protocol.compact_operation_sources(packet, packet)
        for original, shown in zip(packet["sweep"]["source_contexts"], display["sweep"]["source_contexts"]):
            self.assertNotIn("excerpt", shown)
            self.assertEqual(shown["source_ref"], "body")
            self.assertEqual({k: v for k, v in shown.items() if k != "source_ref"},
                             {k: v for k, v in original.items() if k != "excerpt"})
        self.assertEqual(packet, before)
        self.assertEqual(display["operation_source_view"]["removed_duplicate_excerpt_bytes"], 18)

    def test_addressed_prompt_does_not_readdress_redirected_source(self):
        packet = self.packet()
        task = {"research": {"artifact_handles": {"s": "body", "c0": "context0", "c1": "context1"},
                             "source_artifact_handles": ["s", "c0", "c1"]}}
        addressed, _ = protocol.present_source_inputs(task, packet, [], protocol.SOURCE_PRESENTATION)
        view = protocol.compact_operation_sources(packet, addressed)
        self.assertEqual(view["primary"]["windows"][0]["text"], "L1 | def run():\nL2 |     return é")
        self.assertNotIn("excerpt", view["sweep"]["source_contexts"][0])

    def test_inexact_partial_foreign_or_base_source_keeps_its_text(self):
        for mutate in (
            lambda p: p["primary"]["windows"][0].update(side="base"),
            lambda p: p["primary"]["windows"][0].update(clipped=True),
            lambda p: p["primary"]["windows"][0].update(path="other.py"),
            lambda p: p["primary"]["windows"][0].update(text="def run():\n    return x"),
            lambda p: p["sweep"]["source_contexts"][0]["location"].update(end_column=13),
        ):
            p = self.packet()
            mutate(p)
            view = protocol.compact_operation_sources(p, p)
            self.assertIn("excerpt", view["sweep"]["source_contexts"][0])

    def test_identical_source_with_different_anchor_ids_shares_only_the_source(self):
        packet = self.packet()
        packet["primary"]["windows"] = []
        view = protocol.compact_operation_sources(packet, packet)
        self.assertIn("excerpt", view["sweep"]["source_contexts"][0])
        self.assertNotIn("excerpt", view["sweep"]["source_contexts"][1])
        self.assertEqual(view["sweep"]["source_contexts"][1]["source_ref"], "context0")
        self.assertEqual(view["sweep"]["source_contexts"][1]["evidence_id"], "anchor-b")
        packet["operation_groups"] = []
        self.assertEqual(protocol.compact_operation_sources(packet, packet), packet)


if __name__ == "__main__":
    unittest.main()
