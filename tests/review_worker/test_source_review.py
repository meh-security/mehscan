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


class SourceReview(unittest.TestCase):
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
        self.base = Path(self.temp.name)
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
        self.inventory = self.base / "rust-inventory"
        self.native("investigate", "review-inventory", self.root,
                    "--repository-key", "acceptance:rust-source", "--output", self.inventory)
        self.assertEqual(json.loads((self.inventory / "inventory.json").read_text())["entries"], [])
        result = subprocess.run(self.prepare_worker(proposal=False), capture_output=True,
                                text=True, encoding="utf8", timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.debug_output())
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

    def prepare_worker(self, *, proposal=True, fail=False, lookup=False):
        if lookup:
            (self.root / "context.reviewdata").write_text(
                "configuration reference\n", encoding="utf8"
            )
        store = self.base / "state"
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
            "value",
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
        reviewer = self.base / "reviewer.py"
        reviewer.write_text(
            """import json,sys
from pathlib import Path
task=json.load(sys.stdin)
if task.get('review_role')=='second_pass_fast':
    packet=json.loads(Path(task['evidence_packet']).read_text())
    assert packet['source_handoff']['fact_count']>0, 'Original source facts must reach Fast'
    rows=[{'review_id':i,'decision':'needs_review','confidence':'medium','summary':'Interpreter behavior needs source inspection.',
        'reason':'The custom callee behavior remains unavailable.','evidence':[{'path':'Widget.razor','start_line':1,'end_line':1}],
        'checks':['Read CustomInterpreter.Run to establish whether input is interpreted.'],'blockers':[]} for i in task['review_ids']]
    print(json.dumps({'draft':{'results':rows},'review_checks':[{'review_id':i,'action':'keep','claim':'The deciding callee remains unavailable.',
        'proof_status':'supported','investigation_status':'sufficient','error_codes':[]} for i in task['review_ids']], 'working_chain':'','progress':[]}))
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
    'evidence':[cite], 'checks':['Read CustomInterpreter.Run to establish whether input is interpreted.'], 'blockers':[]}
if LOOKUP:assessment['evidence'].append({'path':'context.reviewdata','start_line':1,'end_line':1})
proposals=[]
if PROPOSAL:
    proposals=[{'key':'interpreter','capability':'dynamic_code_execution','cwes':['CWE-94'],
        'question':'Does the interpreter execute caller-controlled instructions?',
        'mechanism':'Input is passed to the custom interpreter.','consequence':'Execution if untrusted text is interpreted.',
        'priority':'value','anchor':cite,
        'evidence':[cite],'assessment':assessment}]
rows=[dict(assessment,review_id=q['review_id'],evidence=[{'path':q['path'],'start_line':q['line'],'end_line':q['line']}]) for q in packet['native_questions']]
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
            "--source-root",
            str(self.root),
            "--inventory",
            str(self.inventory),
            "--store",
            str(store),
            "--stream",
            "source",
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
        ]

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
        summary = json.loads(
            (self.base / "worker/source-review/summary.json").read_text()
        )
        self.assertEqual(summary["results"][0]["inspected"][0]["path"], "Widget.razor")
        report = json.loads((self.base / "worker/findings.json").read_text())
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
            self.prepare_worker(proposal=False),
            capture_output=True,
            text=True,
            encoding="utf8",
        )
        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr + self.debug_output()
        )
        report = json.loads((self.base / "worker/findings.json").read_text())
        self.assertEqual(report.get("decision_records", []), [])
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


if __name__ == "__main__":
    unittest.main()
