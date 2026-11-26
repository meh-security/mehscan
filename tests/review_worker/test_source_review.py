"""Source admission and default worker acceptance against the real native CLI."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills/mehscan-security"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(SKILL / "scripts"))

import review_source


class SourceReuse(unittest.TestCase):
    def test_followup_carries_only_source_cited_by_exact_parent(self):
        linked = {"id": "linked", "review_ids": ["child"]}
        unrelated = {"id": "unrelated", "review_ids": ["sibling"]}
        cite = {"path": "producer.py", "start_line": 3, "end_line": 4}
        proof = {**cite, "quote": "first\nsecond"}
        entries = {"child": {"value_hint": {"depends_on": "parent"}}, "sibling": {}}
        result = {"status": "complete", "draft": {"results": [
            {"review_id": "parent", "decision": "needs_review", "evidence": [cite]},
        ]}, "proofs": [proof, {**proof, "path": "unrelated.py"}]}
        self.assertEqual(review_source.prepare_followup([unrelated, linked], entries, [result]), [
            {**linked, "_followup_sources": [("parent", proof)]}, unrelated,
        ])
        result["status"] = "incomplete"
        self.assertEqual(review_source.prepare_followup([unrelated, linked], entries, [result]), [
            unrelated, {**linked, "_followup_sources": []},
        ])

    def test_comprehensive_splits_mixed_assignments_without_mutating_plan(self):
        assignment = {"id": "shared", "windows": [], "review_ids": ["deferred", "value"]}
        first, followup = review_source.comprehensive_assignments([assignment], {"value"})
        self.assertEqual(first[0]["review_ids"], ["value"])
        self.assertEqual(followup[0]["review_ids"], ["deferred"])
        self.assertEqual(first[0]["id"], followup[0]["id"])
        self.assertNotEqual(first[0]["id"], followup[0]["_job_id"])
        self.assertEqual(assignment, {"id": "shared", "windows": [], "review_ids": ["deferred", "value"]})

    def test_comprehensive_followup_promotes_only_exact_open_dependencies(self):
        later = [{"id": rid, "review_ids": [rid]} for rid in ("one", "two", "three")]
        entries = {
            "one": {"value_hint": {"depends_on": "settled"}},
            "two": {"value_hint": {"depends_on": "unresolved"}},
            "three": {"value_hint": {}},
        }
        results = [{"status": "complete", "draft": {"results": [
            {"review_id": "settled", "decision": "not_issue"},
            {"review_id": "unresolved", "decision": "needs_review"},
        ]}}]
        ordered = review_source.prioritize_dependents(later, entries, results)
        self.assertEqual([row["id"] for row in ordered], ["two", "one", "three"])

    def test_comprehensive_keeps_remaining_native_and_workflows_in_one_ranked_queue(self):
        cases = [
            {"id": name, "review_ids": ids, "case": {"priority": {"impact": impact, "evidence": "moderate"}}}
            for name, ids, impact in (
                ("priority-workflow", [], "high"), ("native-followup", ["deferred"], "high"),
                ("value-case", ["value"], "medium"), ("workflow-followup", [], "medium"),
            )
        ]
        first, followup = review_source.comprehensive_cases(cases, {"value"})
        self.assertEqual([row["id"] for row in first], ["priority-workflow", "value-case"])
        self.assertEqual([row["id"] for row in followup], ["native-followup", "workflow-followup"])

    def test_comprehensive_stays_incomplete_with_pending_native_or_open_named_checks(self):
        for pending, items in ((["native"], []), ([], [{"id": "workflow", "status": "investigated_unresolved"}])):
            with self.subTest(pending=pending, items=items):
                result = {"status": "admitted", "completion": {"review_work_complete": True, "pending_review_ids": pending}}
                review_source.report_comprehensive(result, {"items": items})
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["comprehensive_coverage"]["pending_native_ids"], pending)
                self.assertEqual(result["comprehensive_coverage"]["open_work_items"], [row["id"] for row in items])

    def test_unplanned_source_keeps_comprehensive_coverage_incomplete(self):
        result = {"status": "admitted", "completion": {"review_work_complete": True}}
        review_source.report_comprehensive(result, unplanned_source=["unnamed"])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["comprehensive_coverage"]["unplanned_source_assignments"], ["unnamed"])

    def test_prior_reuse_alias_requires_exact_original_and_provenance(self):
        assignment = {"id":"one"}
        original = {"assignment_id":"one", "draft":{"results":[]}, "proofs":[]}
        path = Path.cwd() / "original-result.json"
        alias = {**original, "reuse":{"prior_result":str(path), "prior_plan_id":"plan"}}
        source = (assignment, original, path, "plan")
        review_source.validate_reuse_alias(alias, assignment, source)
        changed = copy.deepcopy(alias)
        changed["draft"]["results"].append({"review_id":"invented"})
        with self.assertRaises(ValueError):
            review_source.validate_reuse_alias(changed, assignment, source)
        with self.assertRaises(ValueError):
            review_source.validate_reuse_alias(alias, assignment, None)

    def test_reconstructed_source_proof_rejects_membership_and_quote_changes(self):
        window = {"path":"app.js", "start_line":1, "end_line":1,
                  "source_sha256":"hash", "text":"safe();"}
        assignment = {"id":"one", "windows":[window], "review_ids":["id"]}
        cite = {"path":"app.js", "start_line":1, "end_line":1}
        result = {"assignment_id":"one", "status":"complete", "unknown_provider_calls":0,
                  "inspected":[], "proofs":[{**cite, "quote":"safe();"}], "proposals":[],
                  "draft":{"coverage":[{**cite, "status":"examined"}],
                           "results":[{"review_id":"id", "evidence":[cite]}], "proposals":[]}}
        admission = review_source.reused_source_result(assignment, result, {"plan_id":"current"})
        self.assertEqual(admission["assessment_evidence"], result["proofs"])
        changed = copy.deepcopy(result)
        changed["proofs"][0]["quote"] = "invented"
        with self.assertRaises(ValueError):
            review_source.reused_source_result(assignment, changed, {})
        changed = copy.deepcopy(result)
        changed["draft"]["results"][0]["review_id"] = "other"
        with self.assertRaises(ValueError):
            review_source.reused_source_result(assignment, changed, {})
        changed = copy.deepcopy(result)
        changed["unknown_provider_calls"] = 1
        with self.assertRaises(ValueError):
            review_source.reused_source_result(assignment, changed, {})


class SourceReview(unittest.TestCase):
    def prepare_comprehensive_followup(self, shared_lookup=False):
        (self.root / "Widget.razor").unlink()
        for directory in ("feature", "other"):
            (self.root / directory).mkdir()
        (self.root / "feature/app.js").write_text("function run(request) { eval(request.query.code); }\n")
        (self.root / "other/View.vue").write_text(
            "<script setup>\nimport { markup } from 'fixture-module';\n</script>\n"
            "<template><article v-html='markup' /></template>\n")
        self.inventory = self.base / "followup-inventory"
        self.native("investigate", "review-inventory", self.root, "--repository-key", "acceptance:staged",
                    "--output", self.inventory)
        entries = json.loads((self.inventory / "inventory.json").read_text())["entries"]
        by_path = {entry["path"]: entry for entry in entries}
        self.assertIsNone(by_path["feature/app.js"].get("value_hint"))
        self.assertTrue(by_path["other/View.vue"].get("value_hint"))
        command = self.prepare_worker(proposal=False, policy="comprehensive")
        del command[command.index("--source-selection"):]
        reviewer = self.base / "reviewer.py"
        text = reviewer.read_text().replace(
            "rows=[dict(assessment,", "assessment.update(decision='not_issue',checks=[])\n"
            "assessment.pop('followup',None)\nrows=[dict(assessment,")
        if shared_lookup:
            text = text.replace("windows=packet['primary']['windows']", """\
with Path(__file__).with_name('calls.jsonl').open('a') as log:
    log.write(json.dumps(task['review_ids'])+'\\n')
if task['research']['round']==0:
    print(json.dumps({'research':[{'tool':'source','review_id':None,'purpose':'Read the shared fixture definition.',
        'arguments':{'path':'feature/app.js','start_line':1,'end_line':1}}]}))
    sys.exit()
windows=packet['primary']['windows']""")
        reviewer.write_text(text)
        return command, by_path["feature/app.js"]["review_id"], by_path["other/View.vue"]["review_id"]

    def test_comprehensive_stages_value_and_never_packages_unfunded_ids(self):
        (self.root / "helper.js").write_text("export function format(value) { return String(value); }\n")
        command, value, deferred = self.prepare_comprehensive_followup()
        result = subprocess.run(command + ["--max-calls", "1"], capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr + self.debug_output())
        output = self.base / "worker"
        stage = output / "source-review"
        record = json.loads((output / "worker.json").read_text())
        self.assertTrue(record["native_admission"])
        self.assertEqual(record["comprehensive_coverage"]["missing_native_ids"], [deferred])
        self.assertEqual(record["comprehensive_coverage"]["status"], "incomplete")
        unplanned = record["comprehensive_coverage"]["unplanned_source_assignments"]
        self.assertTrue(unplanned)
        progress = json.loads((stage / "progress.json").read_text())
        skipped = [row for row in progress if row["assignment_id"] in unplanned]
        self.assertCountEqual([row["assignment_id"] for row in skipped], unplanned)
        self.assertTrue(all(row["error"] == "SourceNotSelected" and row["calls"] == 0 for row in skipped))
        self.assertTrue(all(not (stage / "jobs" / identity).exists() for identity in unplanned))
        for directory in [stage / "bundles", *(stage / "native-inputs").iterdir()]:
            manifest = json.loads((directory / "manifest.json").read_text())
            self.assertEqual([rid for packet in manifest["bundles"] for rid in packet["review_ids"]], [value])
        budget = json.loads((stage / "budget.json").read_text())
        self.assertEqual(budget["reserved_calls"], 1)

    def test_comprehensive_zero_native_requires_source_selection(self):
        command = self.prepare_worker(proposal=False, policy="comprehensive")
        del command[command.index("--source-selection"):]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.debug_output())
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["status"], "selection_required")
        self.assertEqual(record["calls"], 0)
        self.assertFalse((self.base / "worker/source-review/jobs").exists())

    def test_comprehensive_followup_reuses_a_verified_source_read(self):
        command, value, deferred = self.prepare_comprehensive_followup(shared_lookup=True)
        result = subprocess.run(command + ["--max-calls", "4"], capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.debug_output())
        calls = [json.loads(line) for line in (self.base / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls, [[value], [value], [deferred], [deferred]])
        output = self.base / "worker"
        summary = json.loads((output / "source-review/summary.json").read_text())
        self.assertEqual(summary["research_cache_hits"], 1)
        record = json.loads((output / "worker.json").read_text())
        self.assertEqual(record["comprehensive_coverage"]["status"], "complete")

    def test_comprehensive_checks_native_scope_beyond_the_declared_target(self):
        command, value, deferred = self.prepare_comprehensive_followup()
        selection = json.loads((self.base / "selection.json").read_text())
        focus = next(row for row in selection["assignments"] if row["owner_path"] == "feature/app.js")
        work_plan = self.base / "named-plan.json"
        work_plan.write_text(json.dumps({
            "schema_version": "mehscanWorkPlan/v1",
            **{key: selection[key] for key in ("source_plan_id", "source_fingerprint")},
            "items": [{
                **focus, "id": "value", "actor": "Fixture caller", "conditions": "Fixture operation",
                "priority": {"impact": "high", "exposure": "authenticated", "evidence": "moderate",
                             "basis": "The selected fixture operation."},
                "review_roles": {"verify": [value]},
                "checks": [{"id": "operation", "question": "What operation is visible?"}],
            }],
        }))
        reviewer = self.base / "reviewer.py"
        reviewer.write_text(reviewer.read_text().replace(
            "'proposals':proposals,'coverage':", "'proposals':proposals,'work_checks':["
            "dict(check_id='operation',status='satisfied',summary='Fixture operation inspected.',"
            "evidence=[cite],next_deciding_fact=None)],'coverage':"))
        result = subprocess.run(command + ["--work-plan", str(work_plan)], capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr + self.debug_output())
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertTrue(record["work_goal"]["target_complete"])
        self.assertEqual(record["comprehensive_coverage"]["status"], "incomplete")
        self.assertEqual(record["comprehensive_coverage"]["missing_native_ids"], [deferred])

    def test_partial_comprehensive_retains_answers_without_replacement_inference(self):
        for folder in ('feature','other'):
            (self.root/folder).mkdir()
            (self.root/folder/'app.js').write_text('function run(request) { eval(request.query.code); }\n')
        self.inventory=self.base/'partial-inventory'
        self.native('investigate','review-inventory',self.root,'--repository-key','acceptance:partial','--output',self.inventory)
        command=self.prepare_worker(proposal=False)
        del command[command.index('--source-selection'):]
        claim=json.loads((self.base/'claim.json').read_text())['result']
        common=['--store',self.base/'state','--stream','source','--inventory',self.inventory,'--source-root',self.root,'--generation',claim['generation'],'--owner',claim['owner'],'--skill-root',SKILL]
        old=json.loads((self.base/'work.json').read_text())['payload']['plan_id']
        plan=self.native('state','plan-template','--inventory',self.inventory,'--source-root',self.root,'--policy','comprehensive','--skill-root',SKILL)
        path=self.base/'comprehensive.json';path.write_text(json.dumps(plan))
        self.native('state','plan',*common,'--input',path,'--expected-plan-id',old,'--operation-key','comprehensive')
        (self.base/'work.json').write_text(json.dumps(self.native('state','work',*common)))
        reviewer=self.base/'reviewer.py'
        reviewer.write_text(reviewer.read_text().replace("if False: raise RuntimeError('fixture source failure')", "if packet['primary']['windows'][0]['path']=='feature/app.js': raise RuntimeError('fixture source failure')"))
        result=subprocess.run(command,capture_output=True,text=True,encoding='utf8',timeout=180)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr+self.debug_output())
        output=self.base/'worker'
        record=json.loads((output/'worker.json').read_text())
        self.assertTrue(record.get('source_unanswered_results'),record)
        self.assertTrue(record.get('native_admission'),record)
        report=json.loads((output/'findings.json').read_text())
        self.assertGreater(len(report['decision_records']),0)
        source=json.loads((output/'source-review/summary.json').read_text())
        self.assertTrue(source['native_unreviewed_ids'])
        for frame in (output/'source-review/jobs').glob('*/0-input.json'):
            self.assertEqual(json.loads(frame.read_text())['kind'],'source_review')

    def test_budget_partial_review_exports_options_for_completed_native_decisions(self):
        for directory in ("feature", "other"):
            (self.root / directory).mkdir()
            (self.root / directory / "app.js").write_text("function run(request) { eval(request.query.code); }\n")
        self.inventory = self.base / "partial-inventory"
        self.native("investigate", "review-inventory", self.root, "--repository-key", "acceptance:partial",
                    "--output", self.inventory)
        command = self.prepare_worker(proposal=False) + ["--max-calls", "1", "--native-share", "100", "--workers", "1"]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        output = self.base / "worker"
        record = json.loads((output / "worker.json").read_text())
        self.assertEqual(record["status"], "incomplete", record)
        report = json.loads((output / "findings.json").read_text())
        self.assertEqual(len(report["decision_records"]), 1)
        self.assertEqual(record["review_options"], "review-options.json")
        self.assertTrue((output / "review-options.md").is_file())
        self.assertTrue((output / "finding-groups.json").is_file())

    def test_last_budget_call_is_offered_as_final_without_research(self):
        command = self.prepare_worker(proposal=False) + ["--max-calls", "1"]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.debug_output())
        frame = json.loads(next((self.base / "worker/source-review/jobs").glob("*/0-input.json")).read_text())
        self.assertEqual(frame["research"]["rounds_remaining"], 0)
        self.assertEqual(frame["research"]["queries_remaining"], 0)

    def test_mixed_review_keeps_native_candidate_outside_ai_selection(self):
        (self.root / "feature").mkdir()
        (self.root / "feature/app.js").write_text("function run(request) { eval(request.query.code); }\n")
        self.inventory = self.base / "mixed-inventory"
        self.native("investigate", "review-inventory", self.root, "--repository-key", "acceptance:mixed",
                    "--output", self.inventory)
        command = self.prepare_worker(proposal=False)
        path = self.base / "selection.json"
        value = json.loads(path.read_text())
        value["assignments"] = [row for row in value["assignments"] if row["owner_path"] == "Widget.razor"]
        value["assignment_ids"] = [row["assignment_id"] for row in value["assignments"]]
        path.write_text(json.dumps(value))
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.debug_output())
        summary = json.loads((self.base / "worker/source-review/summary.json").read_text())
        original_ids = {e["review_id"] for e in json.loads((self.inventory / "inventory.json").read_text())["entries"]}
        self.assertTrue(original_ids)
        self.assertEqual(set(summary["native_admitted_ids"]), original_ids)
        self.assertTrue(original_ids <= set(summary["assessments"]))
        self.assertEqual(summary["native_unreviewed_ids"], [])
        self.assertEqual(summary["calls"], 2)
        schedule = json.loads((self.base / "worker/source-review/schedule.json").read_text())
        self.assertEqual(len(schedule["native_investigations"]), 1)
        self.assertEqual(len(schedule["ai_investigations"]), 1)

    def test_value_without_selection_checkpoints_without_inference(self):
        command = self.prepare_worker(fail=True)
        del command[command.index("--source-selection"):]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = self.base / "worker"
        record = json.loads((output / "worker.json").read_text())
        self.assertEqual(record["status"], "selection_required")
        self.assertEqual(record["calls"], 0)
        self.assertFalse(list((output / "source-review").rglob("*-input.json")))
        self.assertFalse((output / "source-review/budget.json").exists())
        options = json.loads((output / "source-review/selection-options.json").read_text())
        self.assertEqual(options["source_plan_id"], record["source_plan_id"])
        self.assertNotIn("text", options["assignments"][0]["windows"][0])

    def test_bad_selection_binding_stops_before_any_provider(self):
        command = self.prepare_worker(fail=True)
        selection = self.base / "selection.json"
        value = json.loads(selection.read_text())
        value["source_plan_id"] = "altered"
        selection.write_text(json.dumps(value))
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 2)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["status"], "incomplete")
        self.assertIn("native plan or source fingerprint", record["detail"])
        self.assertFalse(list((self.base / "worker/source-review").rglob("*-input.json")))

    def test_ai_only_defers_native_operations_without_calls(self):
        (self.root / "feature").mkdir()
        (self.root / "feature/app.js").write_text("function run(request) { eval(request.query.code); }\n")
        self.inventory = self.base / "selection-inventory"
        self.native("investigate", "review-inventory", self.root, "--repository-key", "acceptance:selection",
                    "--output", self.inventory)
        command = self.prepare_worker(proposal=False)
        command += ["--native-share", "0"]
        path = self.base / "selection.json"
        value = json.loads(path.read_text())
        native_plan = self.native("investigate", "source-review-plan", self.root, "--inventory", self.inventory,
                                  "--review-ids", ",".join(json.loads((self.base / "work.json").read_text())["payload"]["review_ids"]))
        value["native_assignment_ids"] = [a["id"] for a in native_plan["assignments"] if a["review_ids"]]
        value["assignments"] = [row for row in value["assignments"] if row["owner_path"] == "Widget.razor"]
        self.assertEqual(len(value["assignments"]), 1)
        value["assignment_ids"] = [row["assignment_id"] for row in value["assignments"]]
        path.write_text(json.dumps(value))
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.debug_output())
        summary = json.loads((self.base / "worker/source-review/summary.json").read_text())
        self.assertEqual(summary["native_selected_claims"], 0)
        deferred = [r for r in summary["results"] if r["status"] == "deferred"]
        self.assertTrue(deferred)
        self.assertTrue(all(r["calls"] == 0 for r in deferred))
        self.assertEqual(summary["calls"], 1)
        ledger = json.loads((self.base / "worker/source-review/budget.json").read_text())
        self.assertEqual(ledger["reserved_calls"], 1)
        self.assertEqual(ledger["observed_input_tokens"], 100)
        self.assertTrue(any(w["status"] == "deferred" for w in summary["coverage"]))
        work = json.loads((self.base / "worker/source-review/work.json").read_text())["payload"]
        original_ids = {e["review_id"] for e in json.loads((self.inventory / "inventory.json").read_text())["entries"]}
        self.assertTrue(original_ids)
        self.assertTrue(original_ids <= set(work["deferred_review_ids"]))
        self.assertEqual(work["review_ids"], [])

    def test_supporting_source_is_queryable_but_native_questions_are_not_reviewed(self):
        (self.root / "perf").mkdir()
        (self.root / "perf/load.js").write_text(
            "// LOOKUP_ONLY_BODY_SENTINEL\nfunction run(request) { eval(request.query.code); }\n", encoding="utf8"
        )
        (self.root / "Models").mkdir()
        (self.root / "Models/RequestModel.cs").write_text(
            "// PASSIVE_SHAPE_BODY_SENTINEL\npublic class RequestModel { public string Value { get; set; } }\n",
            encoding="utf8",
        )
        self.inventory = self.base / "supporting-inventory"
        self.native("investigate", "review-inventory", self.root,
                    "--repository-key", "acceptance:source", "--output", self.inventory)
        entries = json.loads((self.inventory / "inventory.json").read_text())["entries"]
        omitted = {e["review_id"] for e in entries if e["path"] == "perf/load.js"}
        self.assertTrue(omitted)
        result = subprocess.run(self.prepare_worker(proposal=False), capture_output=True,
                                text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.debug_output())
        summary = json.loads((self.base / "worker/source-review/summary.json").read_text())
        self.assertEqual(summary["native_selected_claims"], 0)
        self.assertTrue(any(s["path"] == "perf/load.js" for s in summary["excluded_sources"]))
        self.assertTrue(any(s["path"] == "Models/RequestModel.cs" for s in summary["excluded_sources"]))
        self.assertFalse(omitted.intersection(summary["assessments"]))
        self.assertFalse(any(w["path"] == "perf/load.js" for w in summary["coverage"]))
        for packet in (self.base / "worker/source-review/jobs").glob("*/context.json"):
            self.assertNotIn("LOOKUP_ONLY_BODY_SENTINEL", packet.read_text(encoding="utf8"))
            self.assertNotIn("PASSIVE_SHAPE_BODY_SENTINEL", packet.read_text(encoding="utf8"))
        for frame in (self.base / "worker/source-review/jobs").glob("*/0-facts.json"):
            self.assertNotIn("LOOKUP_ONLY_BODY_SENTINEL", frame.read_text(encoding="utf8"))
        # Exclusion affects scheduling, not the inventory's source lookup surface.
        lookup = self.native("investigate", "source", self.root, "--path", "perf/load.js",
                             "--start-line", "2", "--end-line", "2")
        self.assertIn("eval(request.query.code)", json.dumps(lookup))

    def test_template_source_is_assigned_without_native_candidates(self):
        (self.root / "Page.svelte").write_text("<p>{value}</p>\n", encoding="utf8")
        current = self.base / "template-inventory"
        self.native(
            "investigate",
            "review-inventory",
            self.root,
            "--repository-key",
            "acceptance:template",
            "--output",
            current,
        )
        plan = self.native(
            "investigate", "source-review-plan", self.root, "--inventory", current
        )
        self.assertIn(
            "Page.svelte",
            [w["path"] for a in plan["assignments"] for w in a["windows"]],
        )

    def test_citations_can_join_visible_chunks_but_cannot_bridge_an_unread_line(self):
        for name, rows, start, end, accepted in (
            ("joined", [f"line {i}" for i in range(1, 451)], 398, 402, True),
            ("gap", ["start", "x" * (49 * 1024), "end"], 1, 3, False),
        ):
            with self.subTest(name=name):
                (self.root / "Chunk.razor").write_text(
                    "\n".join(rows) + "\n", encoding="utf8"
                )
                self.inventory = self.base / (name + "-inventory")
                self.native(
                    "investigate",
                    "review-inventory",
                    self.root,
                    "--repository-key",
                    "acceptance:chunks",
                    "--output",
                    self.inventory,
                )
                self.plan = self.native(
                    "investigate",
                    "source-review-plan",
                    self.root,
                    "--inventory",
                    self.inventory,
                )
                data = self.admission()
                q = data["proposals"][0]
                q["anchor"] = {
                    "path": "Chunk.razor",
                    "start_line": start,
                    "end_line": end,
                    "quote": rows[start - 1],
                }
                q["evidence"] = [q["anchor"]]
                self.admit(data, name + "-admission", okay=accepted)

    def test_delivered_text_is_validated_and_hash_bound_without_a_file_type_allowlist(
        self,
    ):
        for relative in ("Widget.csproj", "Widget.reviewdata"):
            with self.subTest(path=relative):
                file = self.root / relative
                file.write_text("context version=one\n", encoding="utf8")
                source = self.native(
                    "investigate",
                    "source",
                    self.root,
                    "--path",
                    relative,
                    "--start-line",
                    1,
                    "--end-line",
                    1,
                )
                self.assertIn("version=one", source["results"]["text"])
                paths = self.native(
                    "investigate", "paths", self.root, "--name", relative
                )
                self.assertIn(relative, paths["results"])
                references=self.native("investigate","references",self.root,"--path",relative,"--symbol","version")
                self.assertEqual(len(references["results"]),1)
                data = self.admission()
                data["proposals"] = []
                data["inspected"] = [
                    {
                        "path": relative,
                        "start_line": 1,
                        "end_line": 1,
                        "text": "context version=one",
                        "source_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                    }
                ]
                name = relative + "-admitted"
                self.admit(data, name)
                cached = json.loads((self.base / name / "scan-cache.json").read_text())
                self.assertEqual(
                    cached["source_inputs"]["additional_sources"][0]["path"], relative
                )
                file.write_text("context version=two\n", encoding="utf8")
                self.native(
                    "investigate",
                    "source-review-plan",
                    self.root,
                    "--inventory",
                    self.base / name,
                    okay=False,
                )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-source-review-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        self.scanner = Path(
            os.environ.get(
                "MEHSCAN_TEST_SCANNER",
                ROOT
                / "target/debug"
                / ("mehscan.exe" if os.name == "nt" else "mehscan"),
            )
        )
        self.inventory = self.base / "inventory"
        (self.root / "Widget.razor").write_text(
            "@code { string Run(string input) => CustomInterpreter.Run(input); }\n",
            encoding="utf8",
        )
        (self.root / "tests").mkdir()
        (self.root / "tests/control.js").write_text(
            "eval(request.query.code);\n", encoding="utf8"
        )
        self.native(
            "investigate",
            "review-inventory",
            self.root,
            "--repository-key",
            "acceptance:source",
            "--output",
            self.inventory,
        )
        self.plan = self.native(
            "investigate",
            "source-review-plan",
            self.root,
            "--inventory",
            self.inventory,
        )

    def native(self, *args, okay=True):
        result = subprocess.run(
            [str(self.scanner), *map(str, args)],
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        if not okay:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            return result.stderr
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def admission(self):
        window = self.plan["assignments"][0]["windows"][0]
        citation = {k: window[k] for k in ("path", "start_line", "end_line")}
        citation["quote"] = "CustomInterpreter.Run(input)"
        question = {
            "key": "interpreter",
            "assignment_id": self.plan["assignments"][0]["id"],
            "capability": "dynamic_code_execution",
            "cwes": ["CWE-94"],
            "question": "Does the interpreter execute caller-controlled instructions?",
            "mechanism": "Input is passed to the custom interpreter.",
            "consequence": "Instruction execution if the callee interprets untrusted text.",
            "priority": "value",
            "anchor": citation,
            "evidence": [citation],
        }
        return {
            "plan": copy.deepcopy(self.plan),
            "inspected": [],
            "proposals": [question],
        }

    def admit(self, data, name="admitted", okay=True):
        path = self.base / (name + ".json")
        path.write_text(json.dumps(data), encoding="utf8")
        return self.native(
            "investigate",
            "source-review-admit",
            self.root,
            "--inventory",
            self.inventory,
            "--input",
            path,
            "--output",
            self.base / name,
            okay=okay,
        )

    def test_zero_candidates_receive_real_source_assignments_and_separate_questions(
        self,
    ):
        self.assertEqual(
            json.loads((self.inventory / "inventory.json").read_text())["entries"], []
        )
        self.assertEqual(
            [w["path"] for a in self.plan["assignments"] for w in a["windows"]],
            ["Widget.razor"],
        )
        data = self.admission()
        other = copy.deepcopy(data["proposals"][0])
        other.update(
            key="authorization",
            capability="authorization",
            cwes=["CWE-862"],
            question="Does the action require authority before its effect?",
        )
        data["proposals"].append(other)
        result = self.admit(data)
        self.assertEqual(len(set(result["mapping"].values())), 2)
        inventory = json.loads((self.base / "admitted/inventory.json").read_text())
        self.assertEqual(len(inventory["entries"]), 2)

    def test_zero_candidate_rust_worker_receives_the_bound_language_router(self):
        import review_context as context
        (self.root / "Widget.razor").unlink()
        (self.root / "lib.rs").write_text("pub fn answer() -> u8 { 42 }\n", encoding="utf8")
        from unittest.mock import patch
        self.inventory = self.base / "rust-inventory"
        config = self.base / "project-config.json"
        config.write_text(json.dumps({"repository_key": "acceptance:rust-source", "stream": "source"}))
        with patch.dict(os.environ, {"MEHSCAN_STATE_HOME": str(self.base / "state-home")}):
            project = self.native("project", "prepare", self.root, "--config", config, "--output", self.inventory)
        self.assertEqual(json.loads((self.inventory / "inventory.json").read_text())["entries"], [])
        command = self.prepare_worker(proposal=False, project=project)
        del command[command.index("--source-selection"):]
        selection = json.loads((self.base / "selection.json").read_text())
        item = dict(selection["assignments"][0], id="answer", actor="Library caller", conditions="Calling answer().",
                    question="What does answer() return to its caller?", protected_effect="The library return value",
                    area="Library interface", reason="The return value is exposed to library callers.",
                    next_deciding_fact="Identify the deployed caller.",
                    priority=dict(impact="unknown", exposure="unknown", evidence="strong", basis="Visible source."),
                    checks=[{"id":"value", "question":"Does the function return zero?"},
                            {"id":"caller", "question":"Which deployment calls the function?"}])
        manifest = {k:selection[k] for k in ("source_plan_id", "source_fingerprint")}
        manifest.update(schema_version="mehscanWorkPlan/v1", items=[item])
        work_plan = self.base / "checks.json"
        work_plan.write_text(json.dumps(manifest))
        reviewer = self.base / "reviewer.py"
        reviewer.write_text(reviewer.read_text().replace("'proposals':proposals,'coverage':", """'proposals':proposals,
    'work_checks':[{'check_id':'value','status':'violated','summary':'The body returns 42.',
        'evidence':[cite],'next_deciding_fact':None},
        {'check_id':'caller','status':'unresolved','summary':'No deployment is shown.',
        'evidence':[],'next_deciding_fact':'Identify the deployed caller.'}], 'coverage':"""))
        command += ["--work-plan", str(work_plan), "--max-calls", "1", "--review-goal", "coverage"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr + self.debug_output())
        worker = json.loads(result.stdout)
        self.assertEqual(worker["work_goal"]["remaining_items"], 1)
        close = self.native("state", "end", "--project-run", worker["project_run"], "--claim", worker["private_claim"],
                            "--status", "incomplete", "--operation-key", "close-source")
        receipt = self.base / "close.json"
        receipt.write_text(json.dumps(close))
        exports = self.native("report", "--close-receipt", receipt, "--format", "json-sarif")
        report = exports["report"]
        self.assertEqual(report["summary"]["reviewed"], 0)
        self.assertEqual(exports["sarif"]["runs"][0]["results"], [])
        case, = report["source_review_cases"]
        self.assertEqual((case["id"], case["status"]), ("answer", "investigated_unresolved"))
        answered, open_check = case["checks"]
        self.assertEqual(answered["status"], "violated")
        self.assertEqual(answered["evidence"], [{"path":"lib.rs", "start_line":1, "end_line":1}])
        self.assertEqual((open_check["status"], open_check["next_deciding_fact"]),
                         ("unresolved", "Identify the deployed caller."))
        markdown = subprocess.check_output([self.scanner, "report", "--close-receipt", receipt, "--format", "markdown"], text=True)
        for value in ("Named source checks", answered["question"], answered["summary"], "lib.rs:1-1",
                      open_check["question"], open_check["next_deciding_fact"]):
            self.assertIn(value, markdown)
        claim = self.base / "broader-claim.json"
        claim.write_text(json.dumps(self.native("state", "claim", "--close-receipt", receipt,
            "--policy", "comprehensive", "--attempt-id", "broader", "--operation-key", "claim-broader")))
        broader = self.native("investigate", "source-review-plan", "--close-receipt", receipt)
        manifest.update(source_plan_id=broader["plan_id"], source_fingerprint=broader["source_fingerprint"])
        manifest["items"].append(dict(item, id="response", checks=[{"id":"other", "question":"Is a caller documented?"}]))
        expanded = self.base / "expanded.json"
        expanded.write_text(json.dumps(manifest))
        output = self.base / "broader"
        result = subprocess.run([*command[:3], "--scanner", self.scanner, "--close-receipt", receipt, "--claim", claim,
            "--reviewer-command", self.base / "command.json", "--reviewer-label", "fixture/source",
            "--work-plan", expanded, "--output", output], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        continued = json.loads((output / "worker.json").read_text())
        self.assertEqual(continued["continuation"]["new_source_calls"], 0, continued)
        self.assertEqual(continued["continuation"]["carried_cases"], 1)
        latest = json.loads((output / "findings.json").read_text())
        unfunded = next(case for case in latest["source_review_cases"] if case["id"] == "response")
        self.assertEqual(unfunded["checks"][0]["status"], "not_checked")
        self.assertEqual(self.native("report", "--close-receipt", receipt), report)
        packets = list((self.base / "worker/source-review/jobs").glob("*/context.json"))
        self.assertTrue(packets)
        router = context.language_contracts(SKILL, ["lib.rs"])[0]["text"]
        for path in packets:
            packet = json.loads(path.read_text(encoding="utf8"))
            self.assertEqual(packet["native_questions"], [])
            self.assertIn(router, packet["contract"])
            self.assertNotIn("pub fn bad_bytes", packet["contract"])

    def test_native_admission_rejects_unseen_fabricated_and_altered_plans(self):
        for name in ("quote", "range", "plan", "zero", "duplicate"):
            with self.subTest(name=name):
                data = self.admission()
                if name == "quote":
                    data["proposals"][0]["anchor"]["quote"] = "invented()"
                elif name == "range":
                    data["proposals"][0]["anchor"]["end_line"] = 2
                elif name == "plan":
                    data["plan"]["assignments"] = []
                elif name == "zero":
                    data["proposals"][0]["anchor"]["start_line"] = 0
                else:
                    data["proposals"].append(copy.deepcopy(data["proposals"][0]))
                self.admit(data, name, okay=False)
                self.assertFalse((self.base / name).exists())
        data = self.admission()
        (self.root / "Widget.razor").write_text("changed\n")
        self.admit(data, "stale", okay=False)

    def prepare_worker(self, *, proposal=True, fail=False, lookup=False, policy="value", project=None):
        if lookup:
            (self.root / "context.reviewdata").write_text(
                "configuration reference\n", encoding="utf8"
            )
        store = Path(project["state_store"]) if project else self.base / "state"
        claim = self.native(
            "state",
            "claim",
            "--store",
            store,
            "--stream",
            "source",
            "--inventory",
            self.inventory,
            "--source-root",
            self.root,
            "--expected-generation",
            "0",
            "--attempt-id",
            "initial",
            "--operation-key",
            "claim",
        )
        common = [
            "--store",
            store,
            "--stream",
            "source",
            "--inventory",
            self.inventory,
            "--source-root",
            self.root,
            "--generation",
            "1",
            "--owner",
            claim["result"]["owner"],
            "--skill-root",
            SKILL,
        ]
        plan = self.native(
            "state",
            "plan-template",
            "--inventory",
            self.inventory,
            "--source-root",
            self.root,
            "--policy",
            policy,
            "--selection",
            "policy",
            "--skill-root",
            SKILL,
        )
        for name, data in (("claim", claim), ("plan", plan)):
            (self.base / (name + ".json")).write_text(json.dumps(data))
        self.native(
            "state",
            "plan",
            *common,
            "--input",
            self.base / "plan.json",
            "--operation-key",
            "plan",
        )
        work = self.native("state", "work", *common)
        (self.base / "work.json").write_text(json.dumps(work))
        source_plan = self.native("investigate", "source-review-plan", self.root, "--inventory", self.inventory,
                                  "--review-ids", ",".join(work["payload"]["review_ids"]))
        native_entries = json.loads((self.inventory / "inventory.json").read_text())["entries"]
        assignments = []
        for assignment in source_plan["assignments"][:6]:
            window = max(assignment["windows"], key=lambda w: sum(
                e["path"] == w["path"] and w["start_line"] <= e["line"] <= w["end_line"] for e in native_entries))
            assignments.append({"assignment_id": assignment["id"], "owner_path": window["path"],
                "start_line": window["start_line"], "end_line": window["end_line"],
                "question": "Does the operation interpret supplied input?", "protected_effect": "Interpreter invocation",
                "area": "Input interpretation", "reason": "The operation invokes an interpreter with supplied input.",
                "next_deciding_fact": "The implementation of the interpreter determines how input is used.",
                "signal": {"kind": "source_relationship", "evidence": [{k: window[k] for k in ("path", "start_line", "end_line")}]}})
        selection = {"source_plan_id": source_plan["plan_id"], "source_fingerprint": source_plan["source_fingerprint"],
                     "assignment_ids": [a["assignment_id"] for a in assignments], "assignments": assignments}
        (self.base / "selection.json").write_text(json.dumps(selection))
        reviewer = self.base / "reviewer.py"
        reviewer.write_text(
            """import json,sys
from pathlib import Path
task=json.load(sys.stdin)
with Path(task['provider_metrics']).open('a',encoding='utf8') as receipt:
    receipt.write(json.dumps({'conversation_id':task['conversation_id'],'round':task['research']['round'],
        'provider':None,'elapsed_ms':1,'usage':{'input_tokens':100,'cached_input_tokens':0,'output_tokens':10}})+'\\n')
role=task.get('review_role')
if role in ('verification', 'second_pass_compare', 'second_pass_fast'):
    packet=json.loads(Path(task['evidence_packet']).read_text())
    if role=='verification':
        assert 'stage_context' not in packet and not packet['work']['parent_decisions']
    elif role=='second_pass_compare':
        assert packet['stage_context']['baseline'] and packet['stage_context']['assessment']
        assert task['research']['queries_remaining']==0
    else:
        assert packet['source_handoff']['fact_count']>0, 'Original source facts must reach Fast'
    rows=[{'review_id':i,'decision':'needs_review','confidence':'medium','summary':'Interpreter behavior needs source inspection.',
        'reason':'The custom callee behavior remains unavailable.','evidence':[{'path':'Widget.razor','start_line':1,'end_line':1}],
        'checks':['Read CustomInterpreter.Run to establish whether input is interpreted.'],'blockers':[]} for i in task['review_ids']]
    answer={'draft':{'results':rows}, 'working_chain':'','progress':[]}
    if role!='verification':
        answer['review_checks']=[{'review_id':i,'action':'keep','claim':'The deciding callee remains unavailable.',
            'proof_status':'supported','investigation_status':'sufficient','error_codes':[]} for i in task['review_ids']]
    print(json.dumps(answer))
    sys.exit()
assert task['kind']=='source_review', 'Must reuse source assessment without another native model call'
packet=json.loads(Path(task['evidence_packet']).read_text())
if FAIL: raise RuntimeError('fixture source failure')
if LOOKUP and task['research']['round']==0:
    print(json.dumps({'research':[{'tool':'guidance','review_id':None,'purpose':'Clarify the deciding code execution relationship','arguments':{'name':'process-code'}},
        {'tool':'source','review_id':None,'purpose':'Read the exact interpreter expression','arguments':{'path':'Widget.razor','start_line':1,'end_line':1}},
        {'tool':'source','review_id':None,'purpose':'Read the supplied application context','arguments':{'path':'context.reviewdata','start_line':1,'end_line':1}}], 'working_chain':'Need interpreter guidance.'}))
    sys.exit()
if LOOKUP:
    facts=json.loads(Path(task['shared_facts']).read_text())['facts']
    assert facts[0]['result']['authority']=='trusted_skill_guidance_not_application_evidence'
windows=packet['primary']['windows']
w=windows[0]
cite={k:w[k] for k in ('path','start_line','end_line')}
assessment={'decision':'needs_review','confidence':'medium','summary':'Interpreter behavior needs source inspection.',
    'reason':'The custom callee behavior is not established by its name.',
    'evidence':[cite], 'checks':['Read CustomInterpreter.Run to establish whether input is interpreted.'], 'blockers':[],
    'followup':{'reason':'missing_local_evidence','question':'Read CustomInterpreter.Run to determine the actual interpreter contract.'}}
if LOOKUP:assessment['evidence'].append({'path':'context.reviewdata','start_line':1,'end_line':1})
proposals=[]
if PROPOSAL:
    assessment['claim_context']={'root':cite,'property':'input_interpretation','applicability':'local_contract',
        'basis':'The assigned implementation calls the custom interpreter.', 'kind':'security_contract',
        'impact':'unresolved','conditions':'The exact interpretation contract remains unread.'}
    proposals=[{'key':'interpreter','capability':'dynamic_code_execution','cwes':['CWE-94'],
        'question':'Does the interpreter execute caller-controlled instructions?',
        'mechanism':'Input is passed to the custom interpreter.','consequence':'Execution if untrusted text is interpreted.',
        'priority':'value','anchor':cite,
        'evidence':[cite],'assessment':assessment}]
rows=[dict(assessment,review_id=q['review_id'],evidence=[{'path':q['path'],'start_line':q['line'],'end_line':q['line']},*([cite] if PROPOSAL else [])]) for q in packet['native_questions']]
print(json.dumps({'draft':{'results':rows,
    'proposals':proposals,'coverage':[{**{k:w[k] for k in ('path','start_line','end_line')},'status':'examined','summary':'Inspected the assigned source.'} for w in windows]}}))
""".replace("PROPOSAL", repr(proposal))
            .replace("FAIL", repr(fail))
            .replace("LOOKUP", repr(lookup)),
            encoding="utf8",
        )
        (self.base / "command.json").write_text(
            json.dumps([sys.executable, str(reviewer)])
        )
        return [
            sys.executable,
            "-B",
            str(ROOT / "scripts/review_worker.py"),
            "--scanner",
            str(self.scanner),
            *(["--project-run", project["project_run"]] if project else [
                "--source-root", str(self.root), "--inventory", str(self.inventory),
                "--store", str(store), "--stream", "source",
            ]),
            "--claim",
            str(self.base / "claim.json"),
            "--work-package",
            str(self.base / "work.json"),
            "--reviewer-command",
            str(self.base / "command.json"),
            "--reviewer-label",
            "fixture/source",
            "--output",
            str(self.base / "worker"),
            "--source-selection",
            str(self.base / "selection.json"),
        ]

    def test_project_close_reports_the_admitted_generation(self):
        from unittest.mock import patch
        config = self.base / "project-config.json"
        config.write_text(json.dumps({"repository_key": "acceptance:source", "stream": "source"}))
        self.inventory = self.base / "prepared"
        with patch.dict(os.environ, {"MEHSCAN_STATE_HOME": str(self.base / "state-home")}):
            project = self.native("project", "prepare", self.root, "--config", config,
                                  "--output", self.inventory)
            command = self.prepare_worker(project=project)
            worker = subprocess.run(command, capture_output=True, text=True, check=True)
        attempt = json.loads(worker.stdout)
        self.assertEqual(attempt["generation"], 2)
        end = ["state", "end", "--project-run", attempt["project_run"], "--status", "finished",
               "--operation-key", "close-project"]
        self.assertIn("generation", self.native(*end, "--claim", self.base / "claim.json", okay=False))
        prepared_end = ["state", "end", "--project-run", project["project_run"], "--status", "finished",
                        "--operation-key", "close-project", "--claim", attempt["private_claim"]]
        self.assertIn("project inventory differs", self.native(*prepared_end, okay=False))
        close = self.native(*end, "--claim", attempt["private_claim"])
        self.assertEqual(close["result"], {"generation": 2, "status": "finished"})
        self.assertEqual(close["memory"]["status"], "retained")
        replay = self.native(*end, "--claim", attempt["private_claim"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["sequence"], close["sequence"])
        self.assertEqual(replay["admitted_report"], close["admitted_report"])
        receipt = self.base / "close.json"
        receipt.write_text(json.dumps(close))
        self.assertNotIn(json.loads(Path(attempt["private_claim"]).read_text())["result"]["owner"],
                         receipt.read_text())
        findings = Path(attempt["directory"]) / "findings.json"
        exports = self.native("report", "--close-receipt", receipt, "--format", "json-sarif")
        self.assertEqual(exports["report"], json.loads(findings.read_text()))
        self.assertEqual(exports["sarif"]["version"], "2.1.0")
        claim_args = ["state", "claim", "--close-receipt", receipt, "--attempt-id", "fast",
                      "--operation-key", "claim-fast"]
        receipt.write_text(json.dumps({**close, "sequence": close["sequence"] - 1}))
        self.assertIn("journal close", self.native(*claim_args, okay=False))
        receipt.write_text(json.dumps(close))
        fresh = self.native(*claim_args)
        self.assertEqual(fresh["result"]["generation"], 3)
        self.assertEqual(self.native(*claim_args)["result"], fresh["result"])
        self.assertIn("generation changed", self.native(*claim_args[:-1], "different-claim", okay=False))
        audit_claim = self.base / "audit-claim.json"
        audit_claim.write_text(json.dumps(fresh))
        audit = self.base / "audit"
        invocation = [*command[:3], "--scanner", str(self.scanner), "--close-receipt", str(receipt),
                      "--claim", attempt["private_claim"], "--second-pass", "fast", "--second-pass-scope", "pending",
                      "--supersede", "--reviewer-command", str(self.base / "command.json"),
                      "--reviewer-label", "fixture/source", "--output", str(audit)]
        stale = subprocess.run(invocation, capture_output=True, text=True)
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("fresh claim", stale.stderr)
        self.assertFalse(audit.exists())
        invocation[invocation.index("--claim") + 1] = str(audit_claim)
        reviewed = subprocess.run(invocation, capture_output=True, text=True)
        self.assertEqual(reviewed.returncode, 0, reviewed.stderr + reviewed.stdout)
        checked = json.loads((audit / "second-pass.json").read_text())
        self.assertEqual(checked["checked"], 1)
        self.assertEqual(checked["accounting"]["second_pass"]["calls"], 1)
        self.assertTrue(all(json.loads(p.read_text())["review_role"] == "second_pass_fast"
                            for p in (audit / "training-turns").glob("*/*-input.json")))
        self.assertEqual(json.loads(findings.read_text()), exports["report"])
        # Close the Fast audit and independently recheck the pending result in generation four.
        fast_result = json.loads(reviewed.stdout)
        full_receipt = self.base / "fast-close.json"
        full_receipt.write_text(json.dumps(self.native(
            "state", "end", "--project-run", fast_result["project_run"], "--claim", fast_result["private_claim"],
            "--status", "finished", "--operation-key", "close-fast")))
        full_claim = self.base / "full-claim.json"
        full_claim.write_text(json.dumps(self.native("state", "claim", "--close-receipt", full_receipt,
                                                     "--attempt-id", "full", "--operation-key", "claim-full")))
        full = self.base / "full"
        for flag, value in (("--close-receipt", full_receipt), ("--claim", full_claim),
                            ("--second-pass", "full"), ("--output", full)):
            invocation[invocation.index(flag) + 1] = str(value)
        audited = subprocess.run(invocation, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(audited.stdout)["generation"], 4)
        summary = json.loads((full / "second-pass.json").read_text())
        self.assertEqual((summary["checked"], summary["accounting"]["second_pass"]["calls"]), (1, 2))
        first_turns = (json.loads(p.read_text()) for p in (full / "training-turns").glob("*/0-input.json"))
        turns = {turn["review_role"]: turn for turn in first_turns}
        self.assertEqual(set(turns), {"verification", "second_pass_compare"})
        self.assertNotIn("work_package", turns["verification"])
        self.assertNotEqual(turns["verification"]["conversation_id"], turns["second_pass_compare"]["conversation_id"])
        self.assertEqual(self.native("report", "--close-receipt", receipt), exports["report"])
        findings.write_bytes(findings.read_bytes() + b"\n")
        self.assertIn("findings differ", self.native("report", "--close-receipt", receipt, okay=False))
        replacement = json.loads(Path(attempt["project_run"]).read_text())
        replacement["admitted_report"]["findings_sha256"] = hashlib.sha256(findings.read_bytes()).hexdigest()
        Path(attempt["project_run"]).write_text(json.dumps(replacement))
        self.assertIn("different command", self.native(*end, "--claim", attempt["private_claim"], okay=False))

    def test_default_worker_finalizes_a_discovered_question_without_a_second_investigation(
        self,
    ):
        result = subprocess.run(
            self.prepare_worker(lookup=True),
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr + self.debug_output()
        )
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["source_review"]["source_questions"], 1)
        options=json.loads((self.base / "worker/review-options.json").read_text())
        self.assertEqual(options["review_origin"],"ai_source_only")
        self.assertEqual(options["threat_model"]["source_context"]["native_selected_claims"],0)
        self.assertEqual(len(options["fast"]["selected"]),1)
        self.assertEqual(options["fast"]["selection_model_calls"],0)
        summary = json.loads(
            (self.base / "worker/source-review/summary.json").read_text()
        )
        self.assertEqual(summary["results"][0]["inspected"][0]["path"], "Widget.razor")
        frame = json.loads(next((self.base / "worker/source-review/jobs").glob("*/1-input.json")).read_text())
        citations = frame["research"]["citation_windows"]
        self.assertTrue(citations["s0"]["anchor"])
        self.assertNotIn("f0", citations)  # Guidance is not source evidence.
        self.assertEqual(citations["f1"], {
            "path": "Widget.razor", "start_line": 1, "end_line": 1, "anchor": False})
        self.assertEqual(citations["f2"], {
            "path": "context.reviewdata", "start_line": 1, "end_line": 1, "anchor": False})
        report = json.loads((self.base / "worker/findings.json").read_text())
        self.assertEqual(options["fast"]["selected"][0]["review_id"],report["decision_records"][0]["response"]["review_id"])
        self.assertNotIn("followup", report["decision_records"][0]["response"])
        self.assertNotIn("claim_context", report["decision_records"][0]["response"])
        grouped=json.loads((self.base / "worker/finding-groups.json").read_text())
        member=grouped["groups"][0]["members"][0]
        self.assertEqual(member["review_id"],report["decision_records"][0]["response"]["review_id"])
        self.assertEqual(member["first_pass_context"]["root"]["path"],"Widget.razor")
        self.assertEqual(len(report["decision_records"]), 1)
        admitted = json.loads(
            (self.base / "worker/source-review/admission-result.json").read_text()
        )
        self.assertEqual(
            set(admitted["mapping"].values()),
            {report["decision_records"][0]["response"]["review_id"]},
        )
        self.assertEqual(
            report["decision_records"][0]["response"]["decision"], "needs_review"
        )

    def debug_output(self):
        paths = list((self.base / "worker").rglob("result.json"))
        if (self.base / "worker/worker.json").is_file():
            paths.append(self.base / "worker/worker.json")
        return "\n".join(
            str(p.relative_to(self.base)) + ":" + p.read_text()[:4000] for p in paths
        )

    def test_preflight_rejection_retains_diagnostics_without_starting_a_reviewer(self):
        command = self.prepare_worker()
        path = self.base / "work.json"
        work = json.loads(path.read_text(encoding="utf8"))
        work["package_id"] = "altered-package"
        path.write_text(json.dumps(work), encoding="utf8")
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8")
        self.assertNotEqual(result.returncode, 0)
        output = self.base / "worker"
        record = json.loads((output / "worker.json").read_text(encoding="utf8"))
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(record["generation"], 1)
        self.assertIn("current unaltered native work", record["detail"])
        self.assertFalse((output / "source-review/plan.json").exists())
        self.assertFalse(list((output / "source-review").rglob("*-input.json")))

    def test_no_leads_is_coverage_without_a_fake_not_issue(self):
        result = subprocess.run(
            [*self.prepare_worker(proposal=False), "--second-pass", "fast"],
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr + self.debug_output()
        )
        report = json.loads((self.base / "worker/findings.json").read_text())
        self.assertEqual(report.get("decision_records", []), [])
        options=json.loads((self.base / "worker/review-options.json").read_text())
        self.assertEqual(options["review_origin"],"ai_source_only")
        self.assertFalse(options["threat_model"]["requires_claims"])
        self.assertTrue(Path(options["threat_model"]["source_context"]["coverage_report"]).is_file())
        fast=json.loads((self.base / "worker/second-pass.json").read_text())
        self.assertEqual(fast["targeted"],0)
        self.assertEqual(fast["accounting"]["second_pass"]["calls"],0)
        self.assertEqual(
            json.loads((self.base / "worker/source-review.json").read_text())[
                "completed_assignments"
            ],
            1,
        )

    def test_failed_assignment_is_incomplete_and_does_not_retry(self):
        result = subprocess.run(
            self.prepare_worker(fail=True),
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertEqual(result.returncode, 2)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(record["source_review"]["completed_assignments"], 0)
        self.assertEqual(
            len(list((self.base / "worker/source-review/jobs").rglob("0-input.json"))),
            1,
        )

    def test_native_and_new_questions_share_source_without_changing_old_identities(
        self,
    ):
        (self.root / "app.js").write_text(
            "function run(request) { eval(request.query.code); }\n"
        )
        self.inventory = self.base / "mixed-inventory"
        self.native(
            "investigate",
            "review-inventory",
            self.root,
            "--repository-key",
            "acceptance:source",
            "--output",
            self.inventory,
        )
        before = {
            e["review_id"]
            for e in json.loads((self.inventory / "inventory.json").read_text())[
                "entries"
            ]
        }
        self.assertTrue(before)
        empty = self.native(
            "investigate",
            "review-bundles",
            self.root,
            "--inventory",
            self.inventory,
            "--review-ids",
            "",
            "--output",
            self.base / "explicit-empty",
        )
        self.assertEqual(
            json.loads((self.base / "explicit-empty/manifest.json").read_text())[
                "review_count"
            ],
            0,
        )
        result = subprocess.run(
            self.prepare_worker(),
            capture_output=True,
            text=True,
            encoding="utf8",
            timeout=120,
        )
        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr + self.debug_output()
        )
        report = json.loads((self.base / "worker/findings.json").read_text())
        after = {r["response"]["review_id"] for r in report["decision_records"]}
        self.assertTrue(before < after)
        self.assertEqual(
            len(list((self.base / "worker/source-review/jobs").rglob("0-input.json"))),
            1,
        )
        self.assertTrue(
            all(
                json.loads(p.read_text())["calls"] == 0
                for p in (self.base / "worker/jobs").glob("*.json")
            )
        )

    def test_schema_and_addressed_prompt_keep_zero_candidate_source_and_trusted_guidance(
        self,
    ):
        import codex_protocol
        from jsonschema import Draft202012Validator

        task = {
            "kind": "source_review",
            "review_ids": [],
            "research": {
                "rounds_remaining": 1,
                "artifact_handles": {"s0": "source"},
                "source_artifact_handles": ["s0"],
            },
        }
        schema = codex_protocol.build_schema(task)
        Draft202012Validator.check_schema(schema)
        window = self.plan["assignments"][0]["windows"][0]
        packet = {
            "contract": "Review assigned source.",
            "primary": {"windows": [dict(window, artifact_id="source")]},
        }
        prompt = codex_protocol.build_prompt(
            task, packet, [], None, source_presentation="line-addressed-v1"
        )
        self.assertIn("L1 | @code", prompt)
        self.assertIn("Available broker lookups", prompt)
        self.assertNotIn("source-assignment-no-native-claims", prompt)

    def test_fast_pass_receives_original_source_and_counts_source_calls(self):
        result = subprocess.run(
            [*self.prepare_worker(), "--second-pass", "fast"],
            capture_output=True,
            text=True,
            encoding="utf8",
            timeout=120,
        )
        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr + self.debug_output()
        )
        output = self.base / "worker"
        summary = json.loads((output / "second-pass.json").read_text())
        self.assertEqual(summary["accounting"]["first_pass"]["calls"], 1)
        self.assertEqual(summary["accounting"]["second_pass"]["calls"], 1)
        self.assertEqual(summary["accounting"]["combined"]["calls"], 2)
        turns = list((output / "training-turns").glob("*/*-input.json"))
        self.assertEqual(len(turns), 2)
        source_turn = next(p for p in turns if json.loads(p.read_text())["kind"] == "source_review")
        captured = next((output / "source-review/jobs").glob("*/*-input.json"))
        self.assertEqual(source_turn.read_bytes(), captured.read_bytes())
        source_frame = json.loads(captured.read_text())
        self.assertTrue(source_frame["research"]["coverage_windows"])
        self.assertEqual(set(source_frame["research"]["coverage_windows"]["s0"]),
                         {"path", "start_line", "end_line"})
        self.assertTrue(source_turn.with_name("0-facts.json").is_file())
        self.assertTrue(source_turn.with_name("0-response.json").is_file())
        self.assertTrue(source_turn.with_name("context.json").is_file())

    def test_ai_only_first_pass_can_resume_fast_without_repeating_discovery(self):
        command=self.prepare_worker()
        first=subprocess.run(command,capture_output=True,text=True,encoding="utf8",timeout=120)
        self.assertEqual(first.returncode,0,first.stdout+first.stderr+self.debug_output())
        initial=self.base/"worker"
        saved=(initial/"findings.json").read_bytes()
        summary=json.loads((initial/"source-review/summary.json").read_text())
        self.assertEqual(summary["native_selected_claims"],0)
        self.assertEqual(summary["origin"],"ai_source_only")
        effective=summary["effective_args"]
        claim=json.loads(Path(effective["claim"]).read_text())["result"]
        work=self.native("state","work","--store",self.base/"state","--stream","source",
            "--inventory",effective["inventory"],"--source-root",self.root,"--generation",claim["generation"],
            "--owner",claim["owner"],"--skill-root",SKILL)
        work_path=self.base/"fast-work.json";work_path.write_text(json.dumps(work))
        changes={"--inventory":effective["inventory"],"--claim":effective["claim"],
                 "--work-package":str(work_path),"--output":str(self.base/"fast-followup")}
        for flag,value in changes.items():command[command.index(flag)+1]=value
        command += ["--run",effective["run"],"--phase","native","--first-pass",str(initial),"--second-pass","fast","--supersede"]
        followup=subprocess.run(command,capture_output=True,text=True,encoding="utf8",timeout=120)
        self.assertEqual(followup.returncode,0,followup.stdout+followup.stderr)
        output=self.base/"fast-followup"
        fast=json.loads((output/"second-pass.json").read_text())
        self.assertEqual(fast["checked"],1)
        self.assertEqual(fast["accounting"]["first_pass"]["calls"],1)
        self.assertEqual(fast["accounting"]["second_pass"]["calls"],1)
        self.assertEqual((initial/"findings.json").read_bytes(),saved)
        options=json.loads((output/"review-options.json").read_text())
        self.assertEqual(options["review_origin"],"ai_source_only")
        self.assertTrue(Path(options["threat_model"]["source_context"]["coverage_report"]).samefile(initial/"source-review.json"))
        turns=[json.loads(p.read_text()) for p in (output/"training-turns").glob("*/*-input.json")]
        self.assertTrue(turns)
        self.assertTrue(all(t.get("review_role")=="second_pass_fast" for t in turns))


if __name__ == "__main__":
    unittest.main()
