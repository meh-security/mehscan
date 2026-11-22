"""Real-native work-goal integration with a deterministic local reviewer."""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
import sys
from unittest.mock import patch
import test_worker

import test_domain_review as domain_fixtures


class WorkReview(unittest.TestCase):
    def invoke(self, command):
        worker = test_worker.worker
        with patch.object(sys, "argv", [worker.__file__, *command[3:]]):
            return worker.main()

    def source_resume(self, f, command):
        resumed = list(command)
        resumed[resumed.index("--output") + 1] = str(f.base / "recovered")
        return resumed + ["--resume-from", str(f.base / "worker")]

    def test_saved_draft_finalizes_at_exhausted_budget_without_replay(self):
        for boundary in ("draft", "raw_response"):
            with self.subTest(boundary=boundary):
                f, command, _, _ = self.prepare()
                command += ["--max-calls", "1"]
                worker = test_worker.worker
                original_execute, original_write = worker.execute, worker.write
                provider_calls, interrupted = [], []
                def execute(argv, cwd, env, timeout, payload=None, **kwargs):
                    if len(argv) == 2 and str(argv[1]).endswith("reviewer.py"):
                        provider_calls.append(True)
                    if boundary == "draft" and list(argv[1:3]) == ["investigate", "source-review-check"] and not interrupted:
                        interrupted.append(True)
                        raise KeyboardInterrupt()
                    return original_execute(argv, cwd, env, timeout, payload, **kwargs)
                def write(path, value):
                    original_write(path, value)
                    if boundary == "raw_response" and Path(path).name == "0-response.json" and not interrupted:
                        interrupted.append(True)
                        raise KeyboardInterrupt()
                with patch.object(worker, "execute", side_effect=execute), patch.object(worker, "write", side_effect=write):
                    with self.assertRaises(KeyboardInterrupt):
                        self.invoke(command)
                    parent = f.base / "worker/source-review"
                    self.assertFalse((parent / "summary.json").exists())
                    raw = next((parent / "jobs").glob("*/0-response.json")).read_bytes()
                    self.assertEqual(self.invoke(self.source_resume(f, command)), 2)
                self.assertEqual(len(provider_calls), 1)
                stage = f.base / "recovered/source-review"
                summary = json.loads((stage / "summary.json").read_text())
                self.assertEqual(summary["calls"], 1)
                self.assertEqual(summary["unknown_provider_calls"], 0)
                ledger = json.loads((stage / "work-ledger.json").read_text())
                self.assertEqual({row["id"]:row["status"] for row in ledger["items"]},
                    {"higher":"closed", "lower":"deferred"})
                self.assertEqual(next((parent / "jobs").glob("*/0-response.json")).read_bytes(), raw)
                self.assertEqual(Path(summary["budget_path"]), parent / "budget.json")
                import review_work
                review_work.read_handoff(f.base / "recovered", f.root, worker)
                metrics = (stage / "provider-metrics.jsonl").read_text().splitlines()
                self.assertEqual(len(metrics), 1)
                self.assertEqual(json.loads(metrics[0])["work_item_id"], "higher")

    def test_completed_case_is_retained_and_unstarted_case_uses_original_allowance(self):
        f, command, _, _ = self.prepare()
        worker = test_worker.worker
        original_write, original_execute = worker.write, worker.execute
        interrupted, provider_calls = [], []
        def write(path, value):
            original_write(path, value)
            if Path(path).name == "progress.json" and isinstance(value, list) and any(row.get("case_id") == "higher" for row in value) and not interrupted:
                interrupted.append(True)
                raise KeyboardInterrupt()
        def execute(argv, cwd, env, timeout, payload=None, **kwargs):
            if len(argv) == 2 and str(argv[1]).endswith("reviewer.py"):
                provider_calls.append(True)
            return original_execute(argv, cwd, env, timeout, payload, **kwargs)
        with patch.object(worker, "write", side_effect=write), patch.object(worker, "execute", side_effect=execute):
            with self.assertRaises(KeyboardInterrupt):
                self.invoke(command)
            self.assertEqual(len(provider_calls), 1)
            parent = f.base / "worker/source-review"
            database = (parent / "case-state.sqlite").read_bytes()
            self.assertEqual(self.invoke(self.source_resume(f, command)), 0)
        self.assertEqual(len(provider_calls), 2)
        self.assertEqual((parent / "case-state.sqlite").read_bytes(), database)
        budget = json.loads((parent / "budget.json").read_text())
        self.assertEqual(budget["reserved_calls"], 2)
        summary = json.loads((f.base / "recovered/source-review/summary.json").read_text())
        self.assertEqual(summary["calls"], 2)
        self.assertEqual(summary["work_review"]["completed_items"], 2)

    def test_unknown_dispatch_is_not_repeated_and_fences_remaining_cases(self):
        f, command, _, _ = self.prepare()
        worker = test_worker.worker
        with patch.object(worker, "execute_provider", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.invoke(command)
        with patch.object(worker, "execute_provider", side_effect=AssertionError("No paid replay")):
            self.assertEqual(self.invoke(self.source_resume(f, command)), 2)
        summary = json.loads((f.base / "recovered/source-review/summary.json").read_text())
        self.assertEqual(summary["calls"], 1)
        self.assertEqual(summary["unknown_provider_calls"], 1)
        budget = json.loads((f.base / "worker/source-review/budget.json").read_text())
        self.assertEqual(budget["reserved_calls"], 1)
        self.assertTrue(budget["fenced"])
        ledger = json.loads((f.base / "recovered/source-review/work-ledger.json").read_text())
        self.assertEqual(ledger["summary"]["closed"], 0)

    def test_native_handoff_recovery_does_not_repeat_source_calls(self):
        f, command, _, _ = self.prepare()
        worker = test_worker.worker
        original = worker.execute
        provider_calls = []
        interrupted = []
        def execute(argv, cwd, env, timeout, payload=None, **kwargs):
            if len(argv) >= 3 and list(argv[1:3]) == ["state", "record"] and not interrupted:
                interrupted.append(True)
                raise worker.CommandFailure(argv, 2, "Synthetic native publication interruption")
            if len(argv) == 2 and str(argv[1]).endswith("reviewer.py"):
                provider_calls.append(True)
            return original(argv, cwd, env, timeout, payload, **kwargs)
        with patch.object(worker, "execute", side_effect=execute):
            with patch.object(sys, "argv", [worker.__file__, *command[3:]]):
                self.assertEqual(worker.main(), 2)
            self.assertEqual(len(provider_calls), 2)
            previous = f.base / "worker"
            before = json.loads((previous/"source-review/budget.json").read_text())["reserved_calls"]
            resumed = list(command)
            resumed[resumed.index("--output")+1] = str(f.base/"recovered")
            resumed += ["--resume-from", str(previous)]
            with patch.object(sys, "argv", [worker.__file__, *resumed[3:]]):
                self.assertEqual(worker.main(), 0)
        self.assertEqual(len(provider_calls), 2)
        self.assertEqual(json.loads((previous/"source-review/budget.json").read_text())["reserved_calls"], before)
        result = json.loads((f.base/"recovered/worker.json").read_text())
        self.assertEqual(result["work_goal"]["completed_items"], 2)
        self.assertEqual(Path(result["work_goal"]["continuation_of"]), previous)

    def test_ai_only_work_first_pass_can_use_fast(self):
        f = domain_fixtures.fixtures.SourceReview("test_value_without_selection_checkpoints_without_inference")
        f.setUp();self.addCleanup(f.doCleanups)
        command = f.prepare_worker()
        selection_path = Path(command[command.index("--source-selection")+1])
        selection = json.loads(selection_path.read_text())
        index=command.index("--source-selection");del command[index:index+2]
        item = dict(selection["assignments"][0], id="ai-source", actor="Caller",
            conditions="Selected source operation.", checks=[dict(id="interpretation", question="Is the selected operand interpreted?")],
            priority=dict(impact="unknown", exposure="unknown", evidence="strong", basis="Shown interpreter invocation."),
            review_roles=dict(verify=[], cover=[], context=[]))
        manifest = {key:selection[key] for key in ("source_plan_id", "source_fingerprint")}
        manifest.update(schema_version="mehscanWorkPlan/v1", items=[item])
        path=f.base/"ai-work.json";path.write_text(json.dumps(manifest))
        reviewer=f.base/"reviewer.py"
        reviewer.write_text(reviewer.read_text().replace("'proposals':proposals,'coverage':",
            "'proposals':proposals,'work_checks':[dict(check_id=q['id'],status='satisfied',summary='Fixture property.',evidence=[cite],next_deciding_fact=None) for q in task['research']['required_checks']], 'coverage':"))
        self.run_worker(f, command + ["--work-plan",str(path),"--second-pass","fast"], 0)
        source=json.loads((f.base/"worker/source-review/summary.json").read_text())
        self.assertEqual(source["native_selected_claims"],0)
        self.assertEqual(source["origin"],"ai_source_only")
        audit=json.loads((f.base/"worker/second-pass.json").read_text())
        self.assertEqual(audit["accounting"]["first_pass"]["calls"],1)
        self.assertEqual(audit["accounting"]["second_pass"]["calls"],1)
    def audit_provider(self, f, nominate=True, reopen=False):
        reviewer = f.base / "reviewer.py"
        source = reviewer.read_text()
        if nominate:
            source = source.replace("assessment.pop('followup',None)",
                "assessment['followup']={'reason':'missing_local_evidence','question':'Check the selected interpreter operand against its actual expression.'}")
        original = f.base / "source-only-reviewer.py"
        original.write_text(source)
        reviewer.write_text("""import json,sys,subprocess
from pathlib import Path
task=json.load(sys.stdin)
if task['kind']=='source_review':
    print(subprocess.check_output([sys.executable,ORIGINAL],input=json.dumps(task),text=True))
    sys.exit()
packet=json.loads(Path(task['evidence_packet']).read_text())
role=task.get('review_role')
if role=='verification':
    assert 'stage_context' not in packet
else:
    assert role in ('second_pass_fast','second_pass_compare')
    assert packet['source_handoff']['fact_count']>0
rows=[]
for card in packet['sweep']['reviews']:
    if card['review_id'] not in task['review_ids']:continue
    loc=card['anchor']['location']
    cite={'path':loc['path'],'start_line':loc['start_line'],'end_line':loc['start_line']}
    rows.append(dict(review_id=card['review_id'],decision='not_issue',confidence='medium',
        summary='Fixture scoped proof retained.',reason='Transport fixture checks the selected expression.',
        checks=[],blockers=[],evidence=[cite]))
with Path(task['provider_metrics']).open('a') as handle:
    handle.write(json.dumps(dict(conversation_id=task['conversation_id'],round=task['research']['round'],
        provider=None,elapsed_ms=1,usage=dict(input_tokens=100,cached_input_tokens=0,output_tokens=10)))+'\\n')
value={'draft':{'results':rows},'working_chain':'','progress':[]}
if role!='verification':
    value['review_checks']=[dict(review_id=rid,action='keep',claim='Selected source proof retained.',
        proof_status='supported',investigation_status='sufficient',error_codes=[]) for rid in task['review_ids']]
if REOPEN and role!='verification':
    for row in rows:row.update(decision='needs_review',checks=['Verify the external deployment prerequisite.'])
    for note in value['review_checks']:
        note.update(action='reopen',proof_status='undetermined',investigation_status='external_blocker')
print(json.dumps(value))
""".replace("ORIGINAL", repr(str(original))).replace("REOPEN", repr(reopen)))

    def test_changed_native_proof_reopens_work_target_without_rewriting_first_checks(self):
        f, command, _, _ = self.prepare()
        self.audit_provider(f, reopen=True)
        ledger=self.run_worker(f, command + ["--review-goal","coverage","--second-pass","fast"], 2)
        self.assertFalse(ledger["target_complete"])
        affected=[row for row in ledger["items"] if row["native_reconsideration"]]
        self.assertEqual(len(affected),1)
        self.assertEqual(affected[0]["status"],"investigated_unresolved")
        self.assertEqual(affected[0]["check_results"][0]["status"],"satisfied")
        self.assertEqual(ledger["native_admission_status"],"admitted")

    def test_value_fast_reuses_source_and_retains_knowledge_for_comprehensive(self):
        f, command, _, _ = self.prepare()
        self.audit_provider(f)
        output = f.base / "worker"
        with patch.dict(os.environ, {"MEHSCAN_STATE_HOME": str(f.base / "memory-home")}):
            self.run_worker(f, command + ["--second-pass", "fast"], 0)
            summary = json.loads((output / "source-review/summary.json").read_text())
            effective = summary["effective_args"]
            claim = json.loads(Path(effective["claim"]).read_text())["result"]
            scope = ["--inventory", effective["inventory"], "--source-root", f.root]
            stream = ["--store", f.base / "state", "--stream", "source", *scope]
            ended = f.native("state", "end", *stream, "--generation", claim["generation"],
                             "--owner", claim["owner"], "--status", "incomplete", "--operation-key", "end-value")
            self.assertEqual(ended["memory"]["status"], "retained")
            self.assertGreater(ended["memory"]["new_knowledge_revisions"], 0)

            next_claim = f.native("state", "claim", *stream, "--expected-generation", claim["generation"],
                                  "--retry", "true", "--attempt-id", "broader-review", "--operation-key", "claim-broader")
            owner = ["--generation", next_claim["result"]["generation"], "--owner", next_claim["result"]["owner"]]
            skill = ["--skill-root", domain_fixtures.fixtures.SKILL]
            plan = f.native("state", "plan-template", *scope, *skill, "--policy", "comprehensive", "--selection", "policy")
            plan_file = f.base / "comprehensive.json"
            plan_file.write_text(json.dumps(plan))
            f.native("state", "plan", *stream, *owner, *skill, "--input", plan_file, "--operation-key", "plan-broader")
            work = f.native("state", "work", *stream, *owner, *skill)["payload"]

        self.assertEqual(work["policy"], "comprehensive")
        self.assertEqual(work["review_ids"], plan["selected_review_ids"])
        retained = work["knowledge"]["items"]
        self.assertTrue(retained)
        self.assertTrue(all(item["origin"] == "source_observation" and item["source_sha256"] for item in retained))
        self.assertEqual(set(work["knowledge"]["by_review"]), set(summary["assessments"]))

        audit = json.loads((output / "second-pass.json").read_text())
        self.assertEqual(audit["accounting"]["first_pass"]["calls"], 2)
        self.assertEqual(audit["accounting"]["second_pass"]["calls"], 1)
        self.assertEqual(audit["accounting"]["combined"]["calls"], 3)
        self.assertEqual(json.loads((f.base/"worker/source-review/budget.json").read_text())["reserved_calls"], 3)
        self.assertTrue((f.base/"worker/source-review/work-handoff.json").is_file())

    def test_work_plan_full_uses_independent_and_comparison_roles(self):
        f, command, _, _ = self.prepare()
        self.audit_provider(f)
        self.run_worker(f, command + ["--second-pass", "full"], 0)
        audit = json.loads((f.base/"worker/second-pass.json").read_text())
        self.assertEqual(audit["accounting"]["first_pass"]["calls"], 2)
        self.assertEqual(audit["accounting"]["second_pass"]["calls"], 2)
        self.assertEqual(audit["checked"], 2)

    def test_completed_value_extends_to_comprehensive_without_rebuying_priority_work(self):
        self.exercise_comprehensive_continuation(close_value=True, cap=8)

    def test_active_value_continuation_with_no_allowance_keeps_new_scope_open(self):
        self.exercise_comprehensive_continuation(close_value=False, cap=3)

    def exercise_comprehensive_continuation(self, *, close_value, cap):
        fixture, command, manifest_path, ids = self.prepare(unresolved=not close_value)
        if close_value:
            self.audit_provider(fixture)
        else:
            reviewer = fixture.base / "reviewer.py"
            source = reviewer.read_text().replace("'status':'unresolved'", "'status':('satisfied' if task['research'].get('scoped_resolution') else 'unresolved')")
            source = source.replace("'next_deciding_fact':'Provider binding is unavailable.'",
                "'next_deciding_fact':(None if task['research'].get('scoped_resolution') else 'Provider binding is unavailable.')")
            source = source.replace("'check_id':q['id']", "'assertion_dependencies':[], 'assertion_dispositions':[], 'conditions':[], 'limitations':[], 'check_id':q['id']")
            reviewer.write_text(source)
        root = fixture.root
        initial = fixture.base / "worker"
        skill = ["--skill-root", domain_fixtures.fixtures.SKILL]
        with patch.dict(os.environ, {"MEHSCAN_STATE_HOME": str(fixture.base / "memory-home")}):
            self.run_worker(fixture, command + ["--max-calls", str(cap)], 0)
            summary = json.loads((initial / "source-review/summary.json").read_text())
            original_findings = (initial / "findings.json").read_bytes()
            original_cases = (initial / "source-review/case-state.sqlite").read_bytes()
            checkpoint = initial
            if not close_value:
                checkpoint = fixture.base / "named-correction"
                request = fixture.base / "named-checks.json"
                request.write_text(json.dumps({"schema_version":"mehscanWorkResolution/v1",
                    "checks":[{"case_id":"higher", "check_ids":["execution"]}]}))
                correction = list(command) + ["--max-calls", str(cap), "--resolve-checks", str(request), "--resume-from", str(initial)]
                correction[correction.index("--output") + 1] = str(checkpoint)
                checked = subprocess.run(correction, capture_output=True, text=True, timeout=300)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            effective = summary["effective_args"]
            claim = json.loads(Path(effective["claim"]).read_text())
            old_claim = claim["result"]
            source = ["--inventory", effective["inventory"], "--source-root", root]
            stream = ["--store", fixture.base / "state", "--stream", "source", *source]
            old_owner = ["--generation", old_claim["generation"], "--owner", old_claim["owner"]]
            parent_plan = ["--expected-plan-id", json.loads(Path(effective["work_package"]).read_text())["payload"]["plan_id"]]
            if close_value:
                ended = fixture.native("state", "end", *stream, *old_owner,
                                       "--status", "finished", "--operation-key", "close-value")
                self.assertEqual(ended["memory"]["status"], "retained")
                claim = fixture.native("state", "claim", *stream, "--expected-generation", old_claim["generation"],
                                       "--attempt-id", "comprehensive", "--operation-key", "extend", "--retry", "true")
                parent_plan = []
            owner = ["--generation", claim["result"]["generation"], "--owner", claim["result"]["owner"]]
            plan = fixture.native("state", "plan-template", *source, *skill, "--policy", "comprehensive", "--selection", "policy")
            plan_path = fixture.base / "comprehensive-native.json"
            plan_path.write_text(json.dumps(plan))
            fixture.native("state", "plan", *stream, *owner, *skill, *parent_plan,
                           "--input", plan_path, "--operation-key", "wider-plan")
            work = fixture.native("state", "work", *stream, *owner, *skill)
            work_path = fixture.base / "comprehensive-work.json"
            work_path.write_text(json.dumps(work))
            claim_path = fixture.base / "comprehensive-claim.json"
            claim_path.write_text(json.dumps(claim))
            source_plan = fixture.native("investigate", "source-review-plan", root, "--inventory", effective["inventory"],
                                         "--review-ids", ",".join(work["payload"]["review_ids"]))
            manifest = json.loads(manifest_path.read_text())
            manifest.update(source_plan_id=source_plan["plan_id"], source_fingerprint=source_plan["source_fingerprint"])
            for item in manifest["items"]:
                item["assignment_id"] = next(row["id"] for row in source_plan["assignments"]
                    if set(item["review_roles"]["verify"]) <= set(row["review_ids"]))
            other = next(row for row in source_plan["assignments"] if set(ids["other/app.js"]) <= set(row["review_ids"]))
            added = copy.deepcopy(manifest["items"][0])
            added.update(id="wider-native", owner_path="other/app.js", assignment_id=other["id"],
                         review_roles={"verify":ids["other/app.js"]})
            added["signal"]["evidence"][0]["path"] = "other/app.js"
            named = copy.deepcopy(added)
            named.update(id="wider-source", review_roles={"verify":[]})
            manifest["items"].extend([added, named])
            expanded = fixture.base / "comprehensive-plan.json"
            output = fixture.base / "wider"
            followup = list(command) + ["--continue-comprehensive", str(checkpoint), "--max-calls", "20"]
            for flag, value in {"--inventory":effective["inventory"], "--claim":claim_path,
                "--work-package":work_path, "--work-plan":expanded, "--output":output}.items():
                followup[followup.index(flag) + 1] = str(value)
            if close_value:
                expanded.write_text(json.dumps({**manifest, "items":manifest["items"][1:]}))
                rejected = subprocess.run(followup, capture_output=True, text=True, timeout=180)
                self.assertEqual(rejected.returncode, 2, rejected.stderr)
                refusal = json.loads((output / "worker.json").read_text())
                self.assertIn("keep prior case identities", refusal["detail"])
            else:
                expanded.write_text(json.dumps(manifest))
                changing = root / "other/app.js"
                original = changing.read_bytes()
                try:
                    changing.write_bytes(original + b"\n// changed after the saved review\n")
                    rejected = subprocess.run(followup, capture_output=True, text=True, timeout=180)
                    self.assertEqual(rejected.returncode, 2, rejected.stderr)
                finally:
                    changing.write_bytes(original)
            self.assertFalse((checkpoint / "source-review/continued-to.json").exists())
            self.assertFalse((output / "source-review/jobs").exists())
            expanded.write_text(json.dumps(manifest))
            output = fixture.base / "continued"
            followup[followup.index("--output") + 1] = str(output)
            if close_value:
                worker = test_worker.worker
                write = worker.write
                interrupted = []

                def stop_after_case(path, value):
                    write(path, value)
                    if Path(path) == output / "source-review/progress.json" and any(
                            row.get("case_id") == "wider-native" and row["status"] == "complete" for row in value):
                        interrupted.append(True)
                        raise KeyboardInterrupt()

                with patch.object(worker, "write", side_effect=stop_after_case), self.assertRaises(KeyboardInterrupt):
                    self.invoke(followup)
                self.assertTrue(interrupted)
                resume = followup[:-4] + ["--max-calls", "20", "--resume-from", str(output), "--second-pass", "full"]
                output = fixture.base / "recovered-extension"
                resume[resume.index("--output") + 1] = str(output)
                result = subprocess.run(resume, capture_output=True, text=True, timeout=300)
            else:
                result = subprocess.run(followup, capture_output=True, text=True, timeout=300)
            self.assertEqual(result.returncode, 0 if close_value else 2,
                             result.stdout + result.stderr + (output / "worker.json").read_text())
            if close_value:
                expanded_summary = json.loads((output / "source-review/summary.json").read_text())
                final_args = expanded_summary["effective_args"]
                final_owner = json.loads(Path(final_args["claim"]).read_text())["result"]
                retained = fixture.native("state", "end", "--store", fixture.base / "state", "--stream", "source",
                    "--inventory", final_args["inventory"], "--source-root", root, "--generation", final_owner["generation"],
                    "--owner", final_owner["owner"], "--status", "finished", "--operation-key", "retain-comprehensive")
                self.assertEqual(retained["memory"]["status"], "retained")
                self.assertEqual(retained["memory"]["assessments"], 4)

        stage = output / "source-review"
        continuation = json.loads((stage / "summary.json").read_text())["continuation"]
        self.assertEqual(continuation["carried_cases"], 2)
        self.assertCountEqual(continuation["carried_native_ids"], ids["feature/app.js"])
        self.assertEqual(continuation["prior_reserved_calls"], 2 if close_value else cap)
        self.assertEqual(continuation["new_source_calls"], 2 if close_value else 0)
        self.assertEqual(json.loads((output / "worker.json").read_text())["continuation"], continuation)
        stage_summary = json.loads((stage / "summary.json").read_text())
        self.assertEqual(stage_summary["calls"], 4 if close_value else cap)
        report = json.loads((stage / "work-ledger.json").read_text())
        self.assertEqual(report["comprehensive_coverage"]["status"], "complete" if close_value else "incomplete")
        self.assertCountEqual(report["comprehensive_coverage"]["missing_native_ids"], [] if close_value else ids["other/app.js"])
        budget = json.loads(Path(summary["budget_path"]).read_text())
        self.assertEqual(budget["max_calls"], cap)
        if close_value:
            audit = json.loads((output / "second-pass.json").read_text())
            self.assertEqual(report["summary"]["closed"], 4)
            self.assertEqual(audit["checked"], 4)
            self.assertEqual(budget["reserved_calls"], 4 + audit["accounting"]["second_pass"]["calls"])
        else:
            corrected = next(row for row in report["items"] if row["id"] == "higher")
            self.assertEqual(corrected["check_results"][0]["status"], "satisfied")
            self.assertTrue(corrected["native_reconsideration"])
            self.assertEqual(budget["reserved_calls"], cap)
        self.assertEqual((initial / "findings.json").read_bytes(), original_findings)
        self.assertEqual((initial / "source-review/case-state.sqlite").read_bytes(), original_cases)

    def test_native_fast_reconciles_scoped_correction_under_original_allowance(self):
        f, command, _, _ = self.prepare(unresolved=True)
        reviewer = f.base/'reviewer.py'
        source = reviewer.read_text().replace("'status':'unresolved'", "'status':('satisfied' if task['research'].get('scoped_resolution') else 'unresolved')")
        source = source.replace("'next_deciding_fact':'Provider binding is unavailable.'", "'next_deciding_fact':(None if task['research'].get('scoped_resolution') else 'Provider binding is unavailable.')")
        source = source.replace("'check_id':q['id']", "'assertion_dependencies':[], 'assertion_dispositions':[], 'conditions':[], 'limitations':[], 'check_id':q['id']")
        reviewer.write_text(source)
        self.audit_provider(f)
        self.run_worker(f, command, 0)
        initial = f.base/'worker'
        request = f.base/'resolve.json'
        request.write_text(json.dumps(dict(schema_version='mehscanWorkResolution/v1',
            checks=[dict(case_id='higher', check_ids=['execution'])])))
        correction = list(command)
        correction[correction.index('--output')+1] = str(f.base/'corrected')
        correction += ['--resolve-checks', str(request), '--resume-from', str(initial)]
        result = subprocess.run(correction, capture_output=True, text=True, encoding='utf8', timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        corrected_ledger = (f.base/'corrected/source-review/work-ledger.json').read_bytes()
        summary = json.loads((initial/'source-review/summary.json').read_text())
        effective = summary['effective_args']
        claim = json.loads(Path(effective['claim']).read_text())['result']
        current = f.native('state','work','--store',f.base/'state','--stream','source',
            '--inventory',effective['inventory'],'--source-root',f.root,'--generation',claim['generation'],
            '--owner',claim['owner'],'--skill-root',Path(__file__).resolve().parents[2]/'skills/mehscan-security')
        current_path = f.base/'followup-work.json';current_path.write_text(json.dumps(current))
        followup = list(command)
        index = followup.index('--work-plan'); del followup[index:index+2]
        for flag, value in {'--inventory':effective['inventory'], '--claim':effective['claim'],
                '--work-package':str(current_path), '--output':str(f.base/'followup')}.items():
            followup[followup.index(flag)+1] = value
        followup += ['--run',effective['run'],'--phase','native','--first-pass',str(f.base/'corrected'),
            '--second-pass','fast','--supersede']
        result = subprocess.run(followup, capture_output=True, text=True, encoding='utf8', timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr+(f.base/'followup/worker.json').read_text())
        ledger = json.loads((f.base/'followup/work-ledger.json').read_text())
        higher = next(r for r in ledger['items'] if r['id']=='higher')
        self.assertEqual(higher['status'], 'closed')
        self.assertEqual(higher['native_reconsideration'], {})
        self.assertEqual(next(r for r in ledger['items'] if r['id']=='lower')['status'], 'investigated_unresolved')
        self.assertEqual((f.base/'corrected/source-review/work-ledger.json').read_bytes(), corrected_ledger)
        contexts = [json.loads(p.read_text()) for p in (f.base/'followup').glob('context-*.json')]
        self.assertTrue(any(c.get('stage_context', {}).get('source_corrections') for c in contexts))

    def test_later_fast_inherits_work_allowance_without_repeating_first_pass(self):
        f, command, _, _ = self.prepare()
        self.audit_provider(f)
        self.run_worker(f, command, 0)
        initial = f.base / "worker"
        original_findings = (initial/"findings.json").read_bytes()
        original_ledger = (initial/"source-review/work-ledger.json").read_bytes()
        summary = json.loads((initial/"source-review/summary.json").read_text())
        effective = summary["effective_args"]
        claim = json.loads(Path(effective["claim"]).read_text())["result"]
        work = f.native("state","work","--store",f.base/"state","--stream","source",
            "--inventory",effective["inventory"],"--source-root",f.root,
            "--generation",claim["generation"],"--owner",claim["owner"],
            "--skill-root",Path(__file__).resolve().parents[2]/"skills/mehscan-security")
        work_path=f.base/"followup-work.json";work_path.write_text(json.dumps(work))
        command = list(command)
        index=command.index("--work-plan");del command[index:index+2]
        for flag,value in {"--inventory":effective["inventory"],"--claim":effective["claim"],
            "--work-package":str(work_path),"--output":str(f.base/"followup")}.items():
            command[command.index(flag)+1]=value
        command += ["--run",effective["run"],"--phase","native","--first-pass",str(initial),
                    "--second-pass","fast","--supersede"]
        budget_path=initial/"source-review/budget.json"
        original_budget=budget_path.read_bytes()
        changed=json.loads(original_budget)
        changed["max_calls"]+=1
        budget_path.write_text(json.dumps(changed))
        refused=subprocess.run(command,capture_output=True,text=True,encoding="utf8",timeout=180)
        self.assertEqual(refused.returncode,2)
        self.assertEqual(json.loads(refused.stdout)["reason"],"ValueError")
        self.assertFalse((f.base/"followup").exists())
        budget_path.write_bytes(original_budget)
        result=subprocess.run(command,capture_output=True,text=True,encoding="utf8",timeout=180)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr+f.debug_output())
        followup=json.loads((f.base/"followup/worker.json").read_text())
        self.assertEqual(Path(followup["work_followup"]["budget_path"]),initial/"source-review/budget.json")
        self.assertEqual(json.loads((initial/"source-review/budget.json").read_text())["reserved_calls"],3)
        self.assertEqual((initial/"findings.json").read_bytes(), original_findings)
        self.assertEqual((initial/"source-review/work-ledger.json").read_bytes(), original_ledger)
        frames=[json.loads(path.read_text()) for path in (f.base/"followup/training-turns").glob("*/*-input.json")]
        self.assertEqual([frame["review_role"] for frame in frames], ["second_pass_fast"])
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
