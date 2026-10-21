"""Real native/controller acceptance; reviewer output is deterministic, not AI truth."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("mehscan_review_worker", ROOT / "scripts/review_worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class ArtifactCopy(unittest.TestCase):
    def test_artifact_copy_preserves_bytes_without_requiring_metadata(self):
        with tempfile.TemporaryDirectory(prefix="mehscan-artifact-") as name:
            root = Path(name)
            source = root / "requests"
            source.mkdir()
            data = b'{"source_bound":"actual bytes"}\n'
            (source / "request.json").write_bytes(data)
            with patch("shutil.copystat", side_effect=PermissionError("metadata unsupported")):
                worker.copy_review_files(source, root / "copied")
            self.assertEqual((root / "copied/request.json").read_bytes(), data)
            (source / "unexpected-directory").mkdir()
            with self.assertRaises(ValueError):
                worker.copy_review_files(source, root / "rejected")


class Worker(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-worker-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.scanner = Path(os.environ.get("MEHSCAN_TEST_SCANNER", ROOT / "target/debug" / ("mehscan.exe" if os.name == "nt" else "mehscan")))
        if not self.scanner.is_file():
            self.fail("worker tests require a built native CLI")
        self.git("init", "--quiet")
        self.git("config", "user.name", "Worker fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / "app.js").write_text("const harmless = true;\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "base")
        self.old = self.git("rev-parse", "HEAD")
        (self.root / "app.js").write_text("function handle(request) { eval(request.query.code); }\n")
        self.inventory = self.base / "inventory"
        self.store = self.base / "state"
        self.run = self.base / "run"
        self.native("investigate", "review-inventory", str(self.root), "--changed-from", self.old, "--diff-mode", "files",
                    "--repository-key", "evaluation:worker", "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--attempt-id", "first", "--expected-generation", "0", "--operation-key", "claim")
        self.claim = self.base / "private-claim.json"
        self.claim.write_text(json.dumps(claim))
        self.owner = claim["result"]["owner"]
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--generation", "1", "--owner", self.owner]
        draft = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"), "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive")
        self.ids = draft["selected_review_ids"]
        self.assertTrue(self.ids)
        plan = self.base / "plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--operation-key", "plan")
        self.native("investigate", "review-bundles", str(self.root), "--inventory", str(self.inventory), "--review-ids", ",".join(self.ids),
            "--output", str(self.run))
        self.package = self.base / "work.json"
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        self.reviewer = self.base / "reviewer.py"
        self.reviewer.write_text('''import json,sys
from pathlib import Path
task=json.load(sys.stdin)
package=json.loads(Path(task["work_package"]).read_text())["payload"]
if task["kind"]=="change_pass":
    print(json.dumps({"change_pass":[{"path":"app.js","status":"reviewed","summary":"Inspected the changed operation and its previous source.",
        "questions":[],"native_review_ids":package["review_ids"],"evidence":[{"side":"base","path":"app.js","start_line":1,"end_line":1},
        {"side":"current","path":"app.js","start_line":1,"end_line":1}]}]}))
else:
    print(json.dumps({"results":[{"review_id":review_id,"decision":"issue","confidence":"medium",
        "summary":"Synthetic operation issue for controller acceptance.","reason":"The current code passes request.query.code into eval.",
        "evidence":[{"path":"app.js","start_line":1,"end_line":1}],"checks":[],"blockers":[]} for review_id in task["review_ids"]]}))
''')
        self.command = self.base / "reviewer-command.json"
        self.command.write_text(json.dumps([sys.executable, str(self.reviewer)]))

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def native(self, *args):
        if args[:2] in (("state", "work"), ("state", "plan"), ("state", "record")) and "--skill-root" not in args:
            args = (*args, "--skill-root", str(ROOT / "skills/mehscan-security"))
        result = subprocess.run([str(self.scanner), *args], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def invoke(self, name="worker", extra=()):
        return subprocess.run([sys.executable, str(ROOT / "scripts/review_worker.py"), "--scanner", str(self.scanner),
            "--source-root", str(self.root), "--inventory", str(self.inventory), "--store", str(self.store), "--stream", "local-review",
            "--claim", str(self.claim), "--work-package", str(self.package), "--reviewer-command", str(self.command),
            "--reviewer-label", "deterministic/medium", "--run", str(self.run), "--output", str(self.base / name), *extra],
            capture_output=True, text=True, encoding="utf-8", timeout=60)

    def test_full_repository_work_preserves_null_scope_and_native_admission(self):
        self.inventory = self.base / "full-inventory"
        self.store = self.base / "full-state"
        self.run = self.base / "full-run"
        self.native("investigate", "review-inventory", str(self.root), "--repository-key", "evaluation:worker",
                    "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review",
            "--inventory", str(self.inventory), "--source-root", str(self.root), "--attempt-id", "full",
            "--expected-generation", "0", "--operation-key", "claim")
        self.claim.write_text(json.dumps(claim))
        self.owner = claim["result"]["owner"]
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
                      "--source-root", str(self.root), "--generation", "1", "--owner", self.owner]
        plan = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"),
                          "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive")
        self.assertEqual(plan["change_pass"], [])
        self.ids = plan["selected_review_ids"]
        (self.base / "plan.json").write_text(json.dumps(plan))
        self.native("state", "plan", *self.common, "--input", str(self.base / "plan.json"), "--operation-key", "plan")
        self.native("investigate", "review-bundles", str(self.root), "--inventory", str(self.inventory),
                    "--review-ids", ",".join(self.ids), "--output", str(self.run))
        package = self.native("state", "work", *self.common)
        self.assertIsNone(package["payload"]["impact_scope"])
        self.package.write_text(json.dumps(package))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["status"], "admitted", record)
        self.assertTrue(record["completion"]["review_work_complete"])
        self.assertEqual(record["completion"]["security_resolution"], "not_established")
        self.assertEqual(json.loads((self.base / "worker/prepared-changes.json").read_text())["windows"], [])

    def test_change_pass_native_finalization_and_state_admission_share_one_bound_workflow(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["status"], "admitted", record)
        self.assertTrue(record["completion"]["review_work_complete"])
        self.assertEqual(record["completion"]["security_resolution"], "not_established")
        self.assertEqual(len(record["completion"]["issue_review_ids"]), len(self.ids))
        self.assertNotIn(self.owner, (self.base / "worker/worker.json").read_text())
        self.assertNotIn(self.owner, (self.base / "worker/work.json").read_text())

    def test_native_csharp_policy_source_reaches_reviewer_and_admits_both_verdicts(self):
        (self.root / "app.js").unlink()
        (self.root / "App.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"/>\n')
        (self.root / "Program.cs").write_text('builder.Services.AddControllers();\nbuilder.Services.AddAuthorization(o => o.FallbackPolicy = null);\napp.MapControllers();\n')
        (self.root / "Base.cs").write_text('using Microsoft.AspNetCore.Mvc;\n[IgnoreAntiforgeryToken]\npublic abstract class DemoBase : ControllerBase {}\n')
        fixture = ROOT / 'tests/fixtures/v11-review-effects/Actions.cs'
        (self.root / "Actions.cs").write_text(fixture.read_text().replace('ActionsController : ControllerBase', 'ActionsController : DemoBase'))
        self.inventory, self.store, self.run = [self.base / name for name in ('policy-inventory', 'policy-state', 'policy-run')]
        self.native('investigate', 'review-inventory', str(self.root), '--repository-key', 'evaluation:worker', '--output', str(self.inventory))
        claim = self.native('state', 'claim', '--store', str(self.store), '--stream', 'local-review', '--inventory', str(self.inventory),
            '--source-root', str(self.root), '--attempt-id', 'policy', '--expected-generation', '0', '--operation-key', 'claim')
        self.claim.write_text(json.dumps(claim))
        self.owner = claim['result']['owner']
        self.common = ['--store', str(self.store), '--stream', 'local-review', '--inventory', str(self.inventory),
            '--source-root', str(self.root), '--generation', '1', '--owner', self.owner]
        plan = self.native('state', 'plan-template', '--inventory', str(self.inventory), '--source-root', str(self.root),
            '--policy', 'comprehensive', '--skill-root', str(ROOT / 'skills/mehscan-security'))
        self.ids = plan['selected_review_ids']
        (self.base / 'plan.json').write_text(json.dumps(plan))
        self.native('state', 'plan', *self.common, '--input', str(self.base / 'plan.json'), '--operation-key', 'plan')
        self.native('investigate', 'review-bundles', str(self.root), '--inventory', str(self.inventory), '--review-ids', ','.join(self.ids), '--output', str(self.run))
        self.package.write_text(json.dumps(self.native('state', 'work', *self.common)))
        self.reviewer.write_text('''import json,sys
from pathlib import Path
task=json.load(sys.stdin)
packet=json.loads(Path(task['evidence_packet']).read_text())
windows=packet['primary']['windows']
assert any(w['path']=='Program.cs' and w['complete_file'] and 'FallbackPolicy' in w['text'] for w in windows)
assert any(w['path']=='Base.cs' and 'IgnoreAntiforgeryToken' in w['text'] for w in windows)
source=Path(task['source_root'],'Actions.cs').read_text().splitlines()
results=[]
for question in packet['native_questions']:
    symbol=question['symbol']
    mutation=symbol=='ResetPassword'
    start=next(n for n,text in enumerate(source) if ' '+symbol+'(' in text)
    line=next(n for n,text in enumerate(source[start:],start+1) if ('password = next;' if mutation else 'return Ok(new { success = true') in text)
    results.append({'review_id':question['review_id'],'decision':'issue' if mutation else 'not_issue','confidence':'high',
        'summary':'Deterministic fixture: actual write.' if mutation else 'Deterministic fixture: simulated operation.',
        'reason':'Fixture source writes the credential.' if mutation else 'Fixture source only returns a success response.',
        'evidence':[{'path':'Actions.cs','start_line':line,'end_line':line}],'checks':[],'blockers':[]})
print(json.dumps({'results':results}))
''')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / 'worker/worker.json').read_text())
        self.assertEqual(record['status'], 'admitted', record)
        self.assertTrue(record['completion']['review_work_complete'])
        decisions = json.loads((self.base / 'worker/findings.json').read_text())['decision_records']
        self.assertEqual({d['response']['decision'] for d in decisions}, {'issue', 'not_issue'})

    def test_invalid_reviewer_output_and_stale_package_do_not_admit_decisions(self):
        self.reviewer.write_text('print("not valid review JSON")\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        state = self.native("state", "history", "--store", str(self.store), "--stream", "local-review", "--repository-key", "evaluation:worker")
        self.assertEqual(state["decisions"], {})
        value = json.loads(self.package.read_text())
        value["payload"]["generation"] = 999
        self.package.write_text(json.dumps(value))
        result = self.invoke("altered-worker")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads((self.base / "altered-worker/worker.json").read_text())["status"], "incomplete")

    def test_timeout_and_cancelled_controller_never_invent_responses(self):
        script = self.base / "slow.py"
        script.write_text("import time; time.sleep(10)\n")
        with self.assertRaises(TimeoutError):
            worker.execute([sys.executable, str(script)], self.base, dict(os.environ), 0.1, "{}")
        worker._cancelled = True
        try:
            with self.assertRaises(InterruptedError):
                worker.execute([sys.executable, str(script)], self.base, dict(os.environ), 1)
        finally:
            worker._cancelled = False

    def test_pending_native_answers_are_registered_without_resolving_security(self):
        text = self.reviewer.read_text()
        text = text.replace('"decision":"issue"', '"decision":"needs_review"')
        text = text.replace('"checks":[]', '"checks":["Confirm the exact request authority."]')
        text = text.replace('"blockers":[]', '"blockers":["Confirm whether the named caller enforces its admin gate."]')
        self.reviewer.write_text(text)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["completion"]["pending_review_ids"], self.ids)
        self.assertTrue(list((self.base / "worker").glob("pending-*.json")))
        current = self.native("state", "work", *self.common)
        self.assertEqual(len(current["payload"]["pending_questions"]), 2 * len(self.ids))
        self.assertEqual(current["payload"]["evidence_updates"], [])

    def test_source_only_changed_effect_is_preserved_without_a_native_queue(self):
        (self.root / "app.js").write_text("function requireAdmin(user) { return true; }\n")
        self.inventory = self.base / "inventory-source-only"
        self.native("investigate", "review-inventory", str(self.root), "--changed-from", self.old, "--diff-mode", "files",
                    "--repository-key", "evaluation:worker", "--output", str(self.inventory))
        claim = self.native("state", "claim", "--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--attempt-id", "source-only", "--expected-generation", "1", "--operation-key", "claim-source-only")
        self.claim.write_text(json.dumps(claim))
        self.common = ["--store", str(self.store), "--stream", "local-review", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--generation", "2", "--owner", claim["result"]["owner"]]
        draft = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"), "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive")
        self.assertEqual(draft["selected_review_ids"], [])
        plan = self.base / "source-only-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--operation-key", "source-only-plan")
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
        text = self.reviewer.read_text().replace('"status":"reviewed"', '"status":"needs_review"')
        self.reviewer.write_text(text.replace('"questions":[]', '"questions":["Which unchanged callers rely on the removed admin guard?"]'))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["completion"]["selected_review_count"], 0)
        self.assertEqual(len(record["completion"]["pending_changed_effects"]), 1)
        current = self.native("state", "work", *self.common)
        self.assertEqual(len(current["payload"]["pending_questions"]), 1)

    def research_reviewer(self, query_expression):
        original = self.reviewer.read_text()
        prefix, final = original.split('if task["kind"]=="change_pass":', 1)
        self.reviewer.write_text(prefix + '''if task["research"]["round"] == 0:
    print(json.dumps({"research": ''' + query_expression + '''}))
else:
    assert task["research"]["results"]
    assert "eval" in json.dumps(task["research"]["results"])
    if task["kind"]=="change_pass":''' + '\n'.join('\n    ' + line if line else '' for line in final.splitlines()))

    def assert_no_decisions(self):
        history = self.native("state", "history", "--store", str(self.store), "--stream", "local-review", "--repository-key", "evaluation:worker")
        self.assertEqual(history["decisions"], {})

    def test_model_directed_queries_are_source_bound_and_journaled_only_to_prompting_native_id(self):
        self.research_reviewer('[{"tool":"source", "review_id":task["review_ids"][0] if task["kind"] == "native_bundle" else None, '
                              '"arguments":{"path":"app.js","start_line":1,"end_line":1}}]')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = self.base / "worker"
        audit = [json.loads(line) for line in (directory / "research.jsonl").read_text().splitlines()]
        self.assertEqual([entry["kind"] for entry in audit], ["change_pass", "native_bundle"])
        self.assertIsNone(audit[0]["query"]["review_id"])
        self.assertEqual(audit[1]["query"]["review_id"], self.ids[0])
        self.assertFalse((directory / "journals" / (self.ids[0] + ".jsonl")).exists())
        self.assertEqual([entry["reused"] for entry in audit], [False, True])
        self.assertIsNone(audit[1]["origin_review_id"])
        self.assertNotIn(self.owner, (directory / "research.jsonl").read_text())
        report = json.loads((directory / "findings.json").read_text())
        trace = report["decision_records"][0]["response"]["investigation"]
        self.assertEqual(trace["journal_summary"]["query_count"], 0)

    def test_first_native_query_is_executed_and_journaled_without_fabricating_sibling_activity(self):
        self.research_reviewer('[{"tool":"references", "review_id":task["review_ids"][0], '
                              '"arguments":{"symbol":"eval","limit":20}}]')
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((self.base / "worker/findings.json").read_text())
        self.assertEqual(report["decision_records"][0]["response"]["investigation"]["journal_summary"]["query_count"], 1)

    def test_progress_uses_short_handles_but_saved_proof_is_full_current_identity(self):
        original = self.reviewer.read_text()
        # Run the existing deterministic adapter as a trusted subprocess, then wrap
        # its final draft; no duplicated native verdict implementation here.
        normal = self.base / "normal.py"
        normal.write_text(original)
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'draft=json.loads(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n'
            'handle=next(iter(task["research"]["artifact_handles"]))\n'
            'print(json.dumps({"draft":draft,"working_chain":"Inspected supplied exact source.","progress":['
            '{"edge":"Exact source evidence","status":"inspected","cause":None,"artifacts":[handle]}]}))\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path in (self.base / "worker").glob("progress-*.json"):
            value = json.loads(path.read_text())
            self.assertTrue(value["edges"][0]["artifacts"][0].startswith("mehscan"))
            self.assertEqual(value["assertion"], "reviewer_hypothesis")

    def test_conditional_protocol_feedback_repairs_once_without_admitting_rejected_draft(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' print(json.dumps({"draft":{"change_pass":[]},"progress":[{"edge":"Available consumer",'
            '"status":"open","cause":None,"artifacts":[]}]}))\n'
            'else:\n'
            ' assert "not admitted" in task["research"]["feedback"]["instruction"]\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["protocol_corrections"], 2)  # One conditional repair per bound conversation.
        feedback = [json.loads(line) for line in (self.base / "worker/review-feedback.jsonl").read_text().splitlines()]
        self.assertEqual(len(feedback), 2)
        self.assertTrue(all(item["round"] == 0 for item in feedback))
        self.assertEqual(record["status"], "admitted")

    def test_invalid_source_window_gets_one_repair_and_never_executes_its_batch(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        for name, repair in (("repeated-window", False), ("repaired-window", True)):
            self.reviewer.write_text('import json,sys,subprocess\ntask=json.load(sys.stdin)\n'
                'if not ' + repr(repair) + ' or task["research"]["round"] == 0:\n'
                ' print(json.dumps({"research":[{"tool":"source","review_id":task["review_ids"][0],'
                '"arguments":{"path":"app.js","start_line":1,"end_line":1}},'
                '{"tool":"source","review_id":task["review_ids"][0],'
                '"arguments":{"path":"app.js","start_line":1,"end_line":401}}]}))\n'
                'else:\n'
                ' assert "400 lines" in task["research"]["feedback"]["reason"]\n'
                ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
            result = self.invoke(name, extra=["--phase", "native"])
            directory = self.base / name
            record = json.loads((directory / "worker.json").read_text())
            self.assertEqual(record["protocol_corrections"], 1)
            self.assertFalse((directory / "research.jsonl").exists())
            if repair:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(record["status"], "admitted")
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_decisions()

    def test_evidence_handles_remain_stable_after_new_query_facts(self):
        normal = self.base / "normal.py"
        normal.write_text(self.reviewer.read_text())
        self.reviewer.write_text('import json,sys,subprocess\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            'saved=Path("initial-handles.json")\n'
            'if task["kind"] == "change_pass":\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n'
            'elif task["research"]["round"] == 0:\n'
            ' assert any(key.startswith("evidence") for key in task["research"]["artifact_handles"])\n'
            ' saved.write_text(json.dumps(task["research"]["artifact_handles"]))\n'
            ' print(json.dumps({"research":[{"tool":"references","review_id":task["review_ids"][0],'
            '"arguments":{"symbol":"eval","limit":20}}]}))\n'
            'else:\n'
            ' initial=json.loads(saved.read_text())\n'
            ' assert all(task["research"]["artifact_handles"][key] == value for key,value in initial.items())\n'
            ' assert "fact1" in task["research"]["artifact_handles"]\n'
            ' print(subprocess.check_output([sys.executable,' + repr(str(normal)) + '],input=json.dumps(task),text=True))\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_progress_rejects_unknown_proof_and_open_final_local_edges(self):
        for index, edge in enumerate((
                {"edge":"Unknown source","status":"inspected","cause":None,"artifacts":["source999"]},
                {"edge":"Named available consumer","status":"open","cause":None,"artifacts":[]})):
            self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\nprint(json.dumps({"draft":{"change_pass":[]},'
                '"working_chain":"Incomplete", "progress":[' + repr(edge) + ']}))\n')
            result = self.invoke("bad-progress-" + str(index))
            self.assertNotEqual(result.returncode, 0)
            self.assert_no_decisions()

    def test_base_source_is_pinned_and_current_source_is_not_labeled_as_old_proof(self):
        self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' print(json.dumps({"research":[{"tool":"base_source","review_id":None,"purpose":"Read exact old primary",'
            '"arguments":{"path":"app.js","start_line":1,"end_line":1}}]}))\n'
            'else:\n'
            ' result=task["research"]["results"][0]["result"]\n'
            ' assert result["results"]["side"] == "base" and "harmless" in result["results"]["text"]\n'
            ' print("invalid final draft")\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        audit = json.loads((self.base / "worker/research.jsonl").read_text().splitlines()[0])
        self.assertEqual(audit["query"]["tool"], "base_source")
        self.assertIn("harmless", audit["result"]["results"]["text"])
        self.assertEqual(list((self.base / "worker/journals").iterdir()), [])
        self.assert_no_decisions()

    def test_discovery_queries_preserve_actual_native_results_and_explicit_limits(self):
        self.research_reviewer('[{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}},'
            '{"tool":"symbol","review_id":None,"arguments":{"name":"handle","path":"app.js","limit":1}},'
            '{"tool":"references","review_id":None,"arguments":{"symbol":"request","path":"app.js","limit":2}},'
            '{"tool":"paths","review_id":None,"arguments":{"name":"app","limit":1}}]')
        result = self.invoke(extra=["--phase", "change-pass"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + (self.base / "worker/worker.json").read_text())
        audit = [json.loads(line) for line in (self.base / "worker/research.jsonl").read_text().splitlines()]
        self.assertEqual([entry["query"]["tool"] for entry in audit], ["source", "symbol", "references", "paths"])
        self.assertTrue(all(entry["result"] is not None for entry in audit))
        self.assertTrue(all(entry["query"]["review_id"] is None for entry in audit))
        self.assertEqual(list((self.base / "worker/journals").iterdir()), [])
        self.assert_no_decisions()

    def test_invalid_batch_paths_and_unrelated_ids_execute_no_queries(self):
        for index, bad in enumerate((
                '{"tool":"source","review_id":None,"arguments":{"path":"../private-claim.json","start_line":1,"end_line":1}}',
                '{"tool":"source","review_id":"other-id","arguments":{"path":"app.js","start_line":1,"end_line":1}}',
                '{"tool":"shell","review_id":None,"arguments":{"name":"anything"}}')):
            self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\nprint(json.dumps({"research":['
                '{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}},' + bad + ']}))\n')
            name = "invalid-" + str(index)
            result = self.invoke(name)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse((self.base / name / "research.jsonl").exists())
            self.assert_no_decisions()

    def test_exhausted_round_and_output_budgets_preserve_incomplete_work_without_inventing_verdicts(self):
        self.reviewer.write_text('import json,sys\ntask=json.load(sys.stdin)\nprint(json.dumps({"research":['
            '{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}}]}))\n')
        for name, extra in (("round-budget", ["--research-rounds", "1"]), ("byte-budget", ["--research-bytes", "1"]),
                            ("query-budget", ["--research-queries", "0"])):
            current = self.native("state", "work", *self.common)
            draft = self.native("state", "plan-template", "--skill-root", str(ROOT / "skills/mehscan-security"),
                "--inventory", str(self.inventory), "--source-root", str(self.root), "--policy", "comprehensive", *extra)
            plan = self.base / (name + "-plan.json")
            plan.write_text(json.dumps(draft))
            self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"], "--operation-key", name + "-plan")
            self.package.write_text(json.dumps(self.native("state", "work", *self.common)))
            result = self.invoke(name)
            self.assertNotEqual(result.returncode, 0)
            record = json.loads((self.base / name / "worker.json").read_text())
            self.assertEqual(record["status"], "incomplete")
            self.assertFalse((self.base / name / "findings.json").exists())
            self.assert_no_decisions()

    def test_source_changed_during_reviewer_is_rejected_before_research_or_admission(self):
        self.reviewer.write_text('import json,sys\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            '(Path(task["source_root"])/"app.js").write_text("const changed = true;\\n")\n'
            'print(json.dumps({"research":[{"tool":"source","review_id":None,"arguments":{"path":"app.js","start_line":1,"end_line":1}}]}))\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "worker/research.jsonl").exists())
        self.assert_no_decisions()

    def test_native_runtime_matches_python_package_and_rejects_worker_override(self):
        package = json.loads(self.package.read_text())
        runtime = package["payload"]["runtime"]
        self.assertEqual(runtime["skill_bundle_id"], worker.context.skill_bundle_id(ROOT / "skills/mehscan-security"))
        result = self.invoke(extra=["--research-rounds", "1"])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertIn("override differs", record["detail"])
        self.assertFalse(list((self.base / "worker").glob("context-*.json")))
        self.assert_no_decisions()

    def test_legacy_manual_plan_remains_cli_usable_but_cannot_enter_ai_worker(self):
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--policy", "comprehensive")
        self.assertNotIn("runtime", draft)
        plan = self.base / "manual-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan),
            "--expected-plan-id", current["payload"]["plan_id"], "--operation-key", "manual-plan")
        package = self.native("state", "work", *self.common)
        self.assertNotIn("runtime", package["payload"])
        self.package.write_text(json.dumps(package))
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertIn("requires a native runtime-bound plan", record["detail"])
        self.assertFalse(list((self.base / "worker").glob("context-*.json")))
        self.assert_no_decisions()

    def test_changed_trusted_skill_cannot_run_a_bound_review(self):
        skill = self.base / "skill"
        shutil.copytree(ROOT / "skills/mehscan-security", skill)
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--skill-root", str(skill), "--inventory", str(self.inventory),
            "--source-root", str(self.root), "--policy", "comprehensive")
        plan = self.base / "skill-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"], "--operation-key", "skill-plan", "--skill-root", str(skill))
        self.package.write_text(json.dumps(self.native("state", "work", *self.common, "--skill-root", str(skill))))
        with (skill / "references/runtime-review.md").open("a", encoding="utf-8") as stream:
            stream.write("\nChanged trusted policy.\n")
        result = self.invoke(extra=["--skill-root", str(skill)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "worker/worker.json").read_text())
        self.assertEqual(record["step"], "native/state/work")
        self.assertIn("review command failed", record["detail"])
        self.assertFalse(list((self.base / "worker").glob("context-*.json")))
        self.assert_no_decisions()

    def test_directory_filters_are_rejected_before_any_native_query(self):
        directory = self.root / "module"
        directory.mkdir()
        for arguments in ({"symbol":"eval","path":"module"}, {"symbol":"eval","path_prefix":"app.js"}):
            with self.assertRaises(ValueError):
                worker.research_arguments({"tool":"references","review_id":None,"arguments":arguments}, self.root, [], self.base)
        compiled = worker.research_arguments({"tool":"references","review_id":None,
            "arguments":{"symbol":"eval","path_prefix":"module"}}, self.root, [], self.base)
        self.assertIn("--path-prefix", compiled)

    def test_research_rejects_symlink_escape_and_boolean_ranges(self):
        for arguments in ({"path":"app.js","start_line":True,"end_line":1},
                          {"path":"C:/outside.js","start_line":1,"end_line":1},
                          {"path":".git/config","start_line":1,"end_line":1}):
            with self.assertRaises(ValueError):
                worker.research_arguments({"tool":"source","review_id":None,"arguments":arguments}, self.root, [], self.base)
        link = self.root / "external.js"
        try:
            link.symlink_to(self.claim)
        except OSError:
            return  # Windows runners without symlink privileges still cover traversal above.
        with self.assertRaises(ValueError):
            worker.research_arguments({"tool":"source","review_id":None,"arguments":{
                "path":"external.js","start_line":1,"end_line":1}}, self.root, [], self.base)

    def test_bound_provider_rejects_unprotected_argv_and_different_actual_model(self):
        provider = {"schema_version":"1","provider":"codex-cli",
            "executable_version":"0.162.0-alpha.17.2",
            "model":"gpt-6-luna","reasoning_effort":"medium"}
        descriptor = self.base / "provider.json"
        descriptor.write_text(json.dumps(provider))
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(ROOT / "skills/mehscan-security"), "--provider-contract", str(descriptor))
        plan = self.base / "provider-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"],
            "--operation-key", "provider-plan", "--provider-contract", str(descriptor))
        self.package.write_text(json.dumps(self.native("state", "work", *self.common, "--provider-contract", str(descriptor))))
        result = self.invoke("unsafe-provider", extra=["--provider-contract", str(descriptor)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "unsafe-provider/worker.json").read_text())
        self.assertIn("requires the bundled BYOK adapter", record["detail"])
        config = self.base / "provider-config.json"
        config.write_text(json.dumps({**provider, "model":"different-model"}))
        self.command.write_text(json.dumps([sys.executable,str(ROOT / "skills/mehscan-security/scripts/codex_reviewer.py"),"--config",str(config)]))
        result = self.invoke("wrong-model", extra=["--provider-contract", str(descriptor)])
        self.assertNotEqual(result.returncode, 0)
        record = json.loads((self.base / "wrong-model/worker.json").read_text())
        self.assertIn("actual provider configuration differs", record["detail"])
        self.assertFalse(list((self.base / "wrong-model").glob("context-*.json")))
        self.assert_no_decisions()

    @unittest.skipUnless(os.name == "posix", "CLI fixture uses a POSIX executable")
    def test_bound_byok_adapter_runs_change_pass_and_native_admission(self):
        executable = self.base / "codex-fixture"
        executable.write_text("#!" + sys.executable + "\n" + r'''import json, pathlib, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli fixture-1")
elif "--help" in args:
    print("--ignore-user-config --ignore-rules --strict-config --output-schema --json")
elif args == ["features", "list"]:
    print("\n".join(["shell_tool","multi_agent","apps","plugins","hooks","view_image"]))
else:
    assert "--last" not in args
    assert 'permissions.mehscan_review.network.enabled=false' in args
    prompt = sys.stdin.read()
    schema = json.loads(pathlib.Path(args[args.index("--output-schema")+1]).read_text())
    shape = schema["properties"]["draft"]["anyOf"][0]["properties"]
    if "change_pass" in shape:
        phase = json.loads(prompt.split("Current phase and available native coverage (inspect before claiming a source-only gap):\n")[1].split("\n")[0])
        ids = [q["review_id"] for q in phase["available_native_questions"]]
        draft = {"change_pass":[{"path":"app.js","status":"reviewed","summary":"Inspected changed operation.",
            "questions":[],"native_review_ids":ids,"evidence":[{"side":"base","path":"app.js","start_line":1,"end_line":1},
            {"side":"current","path":"app.js","start_line":1,"end_line":1}]}]}
    else:
        ids = shape["results"]["items"]["properties"]["review_id"]["enum"]
        draft = {"results":[{"review_id":i,"decision":"issue","confidence":"medium",
            "summary":"Synthetic operation issue for BYOK integration acceptance.",
            "reason":"The current code passes request.query.code into eval.",
            "evidence":[{"path":"app.js","start_line":1,"end_line":1}],"checks":[],"blockers":[]} for i in ids]}
    pathlib.Path(args[args.index("--output-last-message")+1]).write_text(json.dumps({"action":"final","research":[],
        "draft":draft,"working_chain":"Inspected supplied source.","progress":[]}))
    print(json.dumps({"type":"thread.started","thread_id":"12345678-1234-1234-1234-123456789abc"}))
    print(json.dumps({"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}}))
''')
        executable.chmod(0o700)
        auth = self.base / "provider-auth.json"
        auth.write_text('{"fixture":"not-a-real-key"}')
        config = {"schema_version":"1","executable":str(executable),"executable_version":"fixture-1",
            "model":"gpt-6-luna","reasoning_effort":"medium","auth_file":str(auth),
            "private_directory":str(self.base / "provider-private")}
        descriptor = self.base / "provider.json"
        provider = {"schema_version":"1","provider":"codex-cli",
            **{key:config[key] for key in ("executable_version","model","reasoning_effort")}}
        descriptor.write_text(json.dumps(provider))
        current = json.loads(self.package.read_text())
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(ROOT / "skills/mehscan-security"), "--provider-contract", str(descriptor))
        plan = self.base / "provider-plan.json"
        plan.write_text(json.dumps(draft))
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", current["payload"]["plan_id"],
            "--operation-key", "byok-plan", "--provider-contract", str(descriptor))
        self.package.write_text(json.dumps(self.native("state", "work", *self.common, "--provider-contract", str(descriptor))))
        config_path = self.base / "provider-config.json"
        config_path.write_text(json.dumps(config))
        self.command.write_text(json.dumps([sys.executable,str(ROOT / "skills/mehscan-security/scripts/codex_reviewer.py"),"--config",str(config_path)]))
        result = self.invoke("byok-worker", extra=["--provider-contract",str(descriptor)])
        self.assertEqual(result.returncode,0,result.stdout + result.stderr)
        record = json.loads((self.base / "byok-worker/worker.json").read_text())
        self.assertEqual(record["status"],"admitted",record)
        self.assertEqual(len(record["completion"]["issue_review_ids"]),len(self.ids))
        self.assertEqual(record["runtime"]["provider"],provider)
        self.assertTrue((self.base / "byok-worker/provider-metrics.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
