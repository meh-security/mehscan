"""Native admission remains independent of bounded AI discovery selection."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_source as source


class SourceSchedule(unittest.TestCase):
    def setUp(self):
        self.plan = {"assignments": [
            {"id": "native-" + str(i), "review_ids": ["candidate-" + str(i)]}
            for i in range(500)] + [{"id": "discovery", "review_ids": []}]}
        self.ids = ["candidate-" + str(i) for i in range(500)]

    def test_hundreds_of_native_candidates_survive_small_ai_selection(self):
        queues = source.investigation_queues(self.plan, self.ids, ["discovery"], {}, 80)
        self.assertEqual(len(queues["native"]), 500)
        self.assertEqual(queues["ai"], ["discovery"])
        self.assertEqual(source.investigation_queues(self.plan, self.ids, [], {}, 80)["native"], queues["native"])

    def test_native_ranking_must_preserve_exact_membership(self):
        ranked = ["native-" + str(i) for i in reversed(range(500))]
        queues = source.investigation_queues(self.plan, self.ids, [], {"native_assignment_ids": ranked}, 80)
        self.assertEqual(queues["native"], ranked)
        for changed in (ranked[:-1], ranked + [ranked[0]], ranked[:-1] + ["discovery"]):
            with self.subTest(changed=len(changed)), self.assertRaises(ValueError):
                source.investigation_queues(self.plan, self.ids, [], {"native_assignment_ids": changed}, 80)

    def test_explicit_modes_and_overlapping_focus_do_not_duplicate_jobs(self):
        queues = source.investigation_queues(self.plan, self.ids, ["native-1", "discovery"], {}, 80)
        self.assertEqual(queues["ai"], ["discovery"])
        self.assertEqual(source.investigation_queues(self.plan, self.ids, ["discovery"], {}, 100)["ai"], [])
        ai = source.investigation_queues(self.plan, self.ids, ["discovery"], {}, 0)
        self.assertEqual(ai, {"native": [], "ai": ["discovery"]})

    def test_empty_discovery_selection_is_valid_and_still_source_bound(self):
        plan = {"plan_id": "plan", "source_fingerprint": "source", "assignments": []}
        selection = {"source_plan_id": "plan", "source_fingerprint": "source", "assignment_ids": [], "assignments": []}
        self.assertEqual(source.validate_selection(selection, plan), ([], {}))
        with self.assertRaises(ValueError):
            source.validate_selection({**selection, "source_fingerprint": "stale"}, plan)


if __name__ == "__main__":
    unittest.main()
