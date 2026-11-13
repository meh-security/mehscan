"""Opt-in domain controller against the real native CLI; no inference."""
import json
from pathlib import Path
import subprocess
import unittest

import test_source_review as fixtures


class DomainReview(unittest.TestCase):
    def prepare(self):
        f = fixtures.SourceReview("test_value_without_selection_checkpoints_without_inference")
        f.setUp()
        self.addCleanup(f.doCleanups)
        for directory, text in (("feature", "function run(request) {\n eval(request.query.code);\n eval(request.body.code);\n}\n"),
                ("other", "function run(request) {\n eval(request.query.code);\n eval(request.body.code);\n}\n")):
            (f.root / directory).mkdir()
            (f.root / directory / "app.js").write_text(text)
        f.inventory = f.base / "domain-inventory"
        f.native("investigate", "review-inventory", f.root, "--repository-key", "acceptance:domain", "--output", f.inventory)
        command = f.prepare_worker(proposal=False)
        del command[command.index("--source-selection"):]
        source_selection = json.loads((f.base / "selection.json").read_text())
        rows = {row["owner_path"]: row for row in source_selection["assignments"]}
        inventory = json.loads((f.inventory / "inventory.json").read_text())
        by_path = {}
        for entry in inventory["entries"]:
            by_path.setdefault(entry["path"], []).append(entry["review_id"])
        self.assertEqual(len(by_path["feature/app.js"]), 2)
        self.assertEqual(len(by_path["other/app.js"]), 2)
        cases = [dict(rows["feature/app.js"], id="first", review_roles={"verify": list(reversed(by_path["feature/app.js"])), "cover": [], "context": []}),
                 dict(rows["other/app.js"], id="second", review_roles={"verify": [], "cover": by_path["other/app.js"][:1], "context": by_path["other/app.js"][1:]})]
        manifest = {k: source_selection[k] for k in ("source_plan_id", "source_fingerprint")}
        manifest["domains"] = [{"id": "interpreter", "title": "Shared interpreter contract", "cases": cases,
            "shared_facts": [{"path": "feature/app.js", "start_line": 1, "end_line": 1}]}]
        path = f.base / "domain.json"
        path.write_text(json.dumps(manifest))
        command += ["--domain-plan", str(path)]
        return f, command, by_path

    def test_roles_share_bound_session_context_without_marker_verdicts(self):
        f, command, ids = self.prepare()
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + f.debug_output())
        stage = f.base / "worker/source-review"
        summary = json.loads((stage / "summary.json").read_text())
        self.assertEqual(summary["completed_assignments"], 2)
        self.assertEqual(set(summary["assessments"]), set(ids["feature/app.js"]))
        self.assertEqual(summary["domain_review"]["domains"], 1)
        accounting = json.loads((stage / "lead-accounting.json").read_text())
        self.assertTrue(accounting[ids["feature/app.js"][0]]["reviewed"])
        self.assertEqual(accounting[ids["other/app.js"][0]]["status"], "incorporated")
        self.assertFalse(accounting[ids["other/app.js"][0]]["reviewed"])
        self.assertFalse(accounting[ids["other/app.js"][1]]["assessment_required"])
        frames = [json.loads(p.read_text()) for p in (stage / "jobs").glob("*/0-input.json")]
        frames.sort(key=lambda x: x["domain_session"]["case_index"])
        for frame in frames:
            member = frame["domain_session"]["cases"][frame["domain_session"]["case_index"]]
            self.assertEqual(frame["review_ids"], member["review_ids"])
        self.assertEqual(frames[0]["domain_session"]["id"], frames[1]["domain_session"]["id"])
        self.assertNotEqual(frames[0]["conversation_id"], frames[1]["conversation_id"])
        self.assertIn("s1000", frames[1]["research"]["coverage_windows"])
        self.assertIn("f0", frames[1]["research"]["citation_windows"])
        packets = [json.loads(Path(frame["evidence_packet"]).read_text()) for frame in frames]
        self.assertEqual(packets[0]["contract"], packets[1]["contract"])
        self.assertEqual(packets[1]["native_questions"], [])
        self.assertEqual(len(packets[1]["domain_case"]["coverage_markers"]), 1)
        self.assertEqual(len(packets[1]["domain_case"]["context_facts"]), 1)
        work = json.loads((stage / "work.json").read_text())["payload"]
        self.assertTrue(set(ids["other/app.js"]) <= set(work["deferred_review_ids"]))

    def test_domain_cases_share_one_budget_and_do_not_prepare_deferred_case(self):
        f, command, ids = self.prepare()
        result = subprocess.run(command + ["--max-calls", "1"], capture_output=True, text=True, encoding="utf8", timeout=180)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        stage = f.base / "worker/source-review"
        budget = json.loads((stage / "budget.json").read_text())
        self.assertEqual(budget["reserved_calls"], 1)
        self.assertEqual(budget["observed_input_tokens"], 100)
        accounting = json.loads((stage / "lead-accounting.json").read_text())
        self.assertEqual(accounting[ids["other/app.js"][0]]["status"], "deferred")
        self.assertFalse(accounting[ids["other/app.js"][0]]["reviewed"])
        self.assertEqual(len(list((stage / "jobs").glob("*/context.json"))), 1)
        self.assertEqual(len(list((stage / "native-inputs").iterdir())), 1)
        self.assertTrue((f.base / "worker/review-options.json").exists())


if __name__ == "__main__":
    unittest.main()
