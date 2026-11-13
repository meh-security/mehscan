"""Native admission remains independent of bounded AI discovery selection."""
import sys
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_source as source


class SourceSchedule(unittest.TestCase):
    def test_source_admission_reconciles_superseded_and_new_generic_markers(self):
        draft = {"selected_review_ids": ["checked", "superseded"],
                 "deferred_review_ids": {"pending": "budget", "old-deferred": "prior"},
                 "excluded_review_ids": {"excluded": "scope"}}
        change = source.reconcile_completion_plan(draft, {"checked", "pending", "excluded", "new-marker"})
        self.assertEqual(change, {"displaced_review_ids": ["old-deferred", "superseded"],
                                  "new_unreviewed_ids": ["new-marker"]})
        self.assertEqual(draft["selected_review_ids"], ["checked"])
        self.assertEqual(set(draft["deferred_review_ids"]), {"pending", "new-marker"})
        self.assertIn("no prior verdict transferred", draft["deferred_review_ids"]["new-marker"])
        self.assertEqual(set(draft["excluded_review_ids"]), {"excluded"})

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

    def test_native_cards_export_only_the_started_investigation_and_keep_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            facts = {"anchor": {"captures": {"query": "fixed_procedure"}},
                     "operand_facts": [{"kind": "parameter_binding"}],
                     "decision_facts": {"established": ["bound values"]},
                     "path_steps": [{"kind": "producer"}],
                     "source_configuration": {"parameter": "configured"},
                     "truncation": {"occurred": False},
                     "suggested_lookups": [{"operation": "source"}]}
            questions = [{"id": "question-1", "security_question": "SQL question"},
                         {"id": "question-2", "security_question": "Other SQL question"}]
            calls = []
            def native(arguments):
                calls.append(arguments)
                if arguments[1] == "review-bundles":
                    original = Path(arguments[arguments.index("--output") + 1])
                    original.mkdir(parents=True)
                    (original / "manifest.json").write_text(json.dumps({"bundles": [{"filename": "selected.json"}]}))
                    return {}
                return {"questions": questions, "reviews": [
                    {"review_id": "native-a", "question_id": "question-2", **facts},
                    {"review_id": "native-b", "question_id": "question-1", **facts}]}
            cards = source.load_native_cards(native, "root", "inventory", stage,
                                             ["native-a", "native-b"], "started")
            self.assertEqual(calls[0][calls[0].index("--review-ids") + 1], "native-a,native-b")
            self.assertEqual(calls[0][calls[0].index("--output") + 1], stage / "native-inputs/started")
            self.assertEqual(calls[1], ["investigate", "review-sweep", "--bundle",
                                      stage / "native-inputs/started/requests/selected.json"])
            self.assertEqual(cards["native-a"], {"question": questions[1], "facts": facts})
            self.assertEqual(cards["native-b"], {"question": questions[0], "facts": facts})
            self.assertFalse((stage / "native-inputs/unstarted").exists())

    def test_ai_only_native_card_loading_makes_no_native_call_or_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            native = Mock()
            self.assertEqual(source.load_native_cards(native, "root", "inventory", temporary, [], "ai-only"), {})
            native.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
