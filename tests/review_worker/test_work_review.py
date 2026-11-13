"""Real-native work-goal integration with a deterministic local reviewer."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

import test_domain_review as domain_fixtures


class WorkReview(unittest.TestCase):
    def prepare(self, unresolved=False, malformed=False):
        fixture = domain_fixtures.DomainReview()
        f, command, ids = fixture.prepare()
        self.addCleanup(fixture.doCleanups)
        path = Path(command[command.index("--domain-plan") + 1])
        domain = json.loads(path.read_text())
        del command[command.index("--domain-plan"):]
        base = domain["domains"][0]["cases"][0]
        base.pop("review_roles")
        items = []
        for index, (name, severity) in enumerate((("lower", "medium"), ("higher", "critical"))):
            item = copy.deepcopy(base)
            item.update(id=name, actor="A caller", conditions="The executable test operation.",
                priority=dict(impact=severity, exposure="unauthenticated", evidence="strong", basis="The supplied source operation."),
                review_roles=dict(verify=[ids["feature/app.js"][index]], cover=[], context=[]),
                checks=[dict(id="execution", question="Is input interpreted by this operation?")],
                estimate=dict(calls=[1,2], input_tokens=[100,1000], output_tokens=[10,100]))
            items.append(item)
        manifest = {key:domain[key] for key in ("source_plan_id", "source_fingerprint")}
        manifest.update(schema_version="mehscanWorkPlan/v1", items=items)
        path.write_text(json.dumps(manifest))
        reviewer = f.base / "reviewer.py"
        source = reviewer.read_text()
        source = source.replace("rows=[dict(assessment,", "assessment.update(decision='not_issue',checks=[])\nassessment.pop('followup',None)\nrows=[dict(assessment,")
        source = source.replace("'proposals':proposals,'coverage':", "'proposals':proposals,'work_checks':[{'check_id':q['id'],'status':STATE,'summary':'Fixture check answer.', 'evidence':[cite], 'next_deciding_fact':GAP} for q in task['research']['required_checks']][0:LIMIT], 'coverage':")
        source = source.replace("STATE", repr("unresolved" if unresolved else "satisfied")).replace("GAP", repr("Provider binding is unavailable." if unresolved else None)).replace("LIMIT", "0" if malformed else "16")
        reviewer.write_text(source)
        return f, command + ["--work-plan", str(path), "--workers", "1"], path, ids

    def run_worker(self, f, command, expected):
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=180)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr + f.debug_output())
        return json.loads((f.base / "worker/source-review/work-ledger.json").read_text())

    def frames(self, f):
        return {json.loads(path.read_text())["domain_session"]["case_id"]: path
                for path in (f.base / "worker/source-review/jobs").glob("*/0-input.json")}

    def test_budget_prioritizes_independent_items_in_the_same_source_packet(self):
        f, command, _, ids = self.prepare()
        ledger = self.run_worker(f, command + ["--max-calls", "1"], 2)
        states = {row["id"]:row["status"] for row in ledger["items"]}
        self.assertEqual(states, {"higher":"closed", "lower":"deferred"})
        stage = f.base / "worker/source-review"
        self.assertEqual(set(self.frames(f)), {"higher"})
        summary = json.loads((stage / "summary.json").read_text())
        self.assertEqual(set(summary["assessments"]), {ids["feature/app.js"][1]})
        self.assertIn("medium", ledger["summary"]["remaining_by_potential_impact"])

    def test_coverage_target_closes_only_selected_checks_and_keeps_other_risk_visible(self):
        f, command, _, _ = self.prepare()
        ledger = self.run_worker(f, command + ["--review-goal", "coverage", "--coverage-target", "lower"], 0)
        self.assertTrue(ledger["target_complete"])
        self.assertEqual(ledger["summary"]["remaining_by_potential_impact"], {"critical":1})

    def test_shared_packet_items_retain_distinct_sessions_and_native_decisions(self):
        f, command, _, ids = self.prepare()
        ledger = self.run_worker(f, command + ["--review-goal", "coverage"], 0)
        self.assertTrue(ledger["target_complete"])
        stage = f.base / "worker/source-review"
        frames = [json.loads(p.read_text()) for p in (stage / "jobs").glob("*/0-input.json")]
        self.assertEqual(len({frame["conversation_id"] for frame in frames}), 2)
        summary = json.loads((stage / "summary.json").read_text())
        self.assertEqual(set(summary["assessments"]), set(ids["feature/app.js"]))
        self.assertEqual(summary["work_review"]["completed_items"], 2)

    def test_unresolved_check_does_not_claim_coverage_completion(self):
        f, command, _, _ = self.prepare(unresolved=True)
        ledger = self.run_worker(f, command + ["--review-goal", "coverage"], 2)
        self.assertFalse(ledger["target_complete"])
        self.assertTrue(all(row["status"] == "investigated_unresolved" for row in ledger["items"]))

    def test_missing_check_answers_fail_without_paid_replay(self):
        f, command, _, _ = self.prepare(malformed=True)
        ledger = self.run_worker(f, command + ["--review-goal", "coverage"], 2)
        self.assertFalse(ledger["target_complete"])
        self.assertTrue(all(row["status"] == "incomplete" for row in ledger["items"]))
        self.assertTrue(all(row["calls"] == 1 for row in ledger["items"]))

    def test_ai_only_control_target_needs_no_native_candidate(self):
        f, command, path, _ = self.prepare()
        value = json.loads(path.read_text())
        for item in value["items"]:
            item["review_roles"] = dict(verify=[], cover=[], context=[])
        path.write_text(json.dumps(value))
        ledger = self.run_worker(f, command + ["--review-goal", "coverage"], 0)
        self.assertTrue(ledger["target_complete"])
        self.assertTrue(ledger["summary"]["unclassified_native_ids"])

    def test_deciding_source_signal_is_delivered_only_for_started_target(self):
        f, command, path, _ = self.prepare()
        value = json.loads(path.read_text())
        for item in value["items"]:
            item["signal"]["evidence"].append(dict(path="other/app.js", start_line=1, end_line=4))
        path.write_text(json.dumps(value))
        self.run_worker(f, command + ["--review-goal", "coverage", "--coverage-target", "lower"], 0)
        stage = f.base / "worker/source-review"
        self.assertEqual(set(self.frames(f)), {"lower"})
        frame = json.loads(self.frames(f)["lower"].read_text())
        facts = json.loads(Path(frame["shared_facts"]).read_text())["facts"]
        self.assertEqual(facts[0]["result"]["results"]["path"], "other/app.js")
        self.assertIn("f0", frame["research"]["citation_windows"])

    def test_item_identifiers_are_not_used_as_windows_file_paths(self):
        f, command, path, _ = self.prepare()
        value = json.loads(path.read_text())
        value["items"][0]["id"] = "auth:lower"
        path.write_text(json.dumps(value))
        ledger = self.run_worker(f, command + ["--review-goal", "coverage", "--coverage-target", "auth:lower"], 0)
        self.assertTrue(ledger["target_complete"])
        self.assertEqual(set(self.frames(f)), {"auth:lower"})


if __name__ == "__main__":
    unittest.main()
