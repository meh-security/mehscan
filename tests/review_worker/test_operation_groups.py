"""Bounded operation packets retain exact IDs and source provenance."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_source_profile as profiles


class OperationGroups(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = "def run(keys):\n    Row.objects.filter(pk__in=keys).delete()\n    Other.objects.filter(pk__in=keys).delete()\n"
        (self.root / "app.py").write_text(self.source, encoding="utf-8")
        self.location = {"path": "app.py", "start": {"line": 1, "byte_offset": 0},
                         "end": {"line": 3, "byte_offset": len(self.source.encode()) - 1}}
        self.entries = [self.entry("a", 2), self.entry("b", 3)]

    def entry(self, rid, line):
        return {"review_id": rid, "path": "app.py", "line": line, "symbol": "run",
                "rule_id": "python-django-orm-resource-access", "capability": "resource_access",
                "cwe_candidates": ["CWE-639"], "operand_facts": [{"kind": "query_structure",
                "value": "local_callable_context", "role": "resource_operation", "location": copy.deepcopy(self.location)}]}

    def prepare(self, entries=None, ids=None, windows=None, snapshot="one"):
        return profiles.prepare_operations(self.root, entries or self.entries, ["a", "b"],
            ["a", "b"] if ids is None else ids, snapshot, windows or [])

    def test_complete_shared_source_has_two_independent_ids_and_no_verdict(self):
        before = copy.deepcopy(self.entries)
        result = self.prepare()
        self.assertEqual(result["groups"][0]["review_ids"], ["a", "b"])
        self.assertFalse(result["groups"][0]["verified"])
        self.assertEqual(result["windows"][0]["text"], self.source.rstrip("\n"))
        self.assertEqual(result["groups"][0]["source_ref"], result["windows"][0]["artifact_id"])
        self.assertNotEqual(result["groups"][0]["group_id"], self.prepare(snapshot="two")["groups"][0]["group_id"])
        self.assertEqual(self.entries, before)

    def test_existing_complete_source_is_reused_but_base_and_clipped_source_are_distinct(self):
        window = {"artifact_id": "existing", "path": "app.py", "start_line": 1, "end_line": 3,
                  "text": self.source.rstrip("\n"), "side": "current", "clipped": False}
        result = self.prepare(windows=[window])
        self.assertFalse(result["windows"])
        self.assertEqual(result["groups"][0]["source_ref"], "existing")
        for change in ({"side": "base"}, {"clipped": True}, {"text": "wrong\nsource\ntext"}):
            with self.subTest(change=change):
                self.assertEqual(len(self.prepare(windows=[{**window, **change}])["windows"]), 1)
        record = {"location": {"path": "app.py", "start_line": 1, "end_line": 3},
                  "excerpt": self.source.rstrip("\n"), "truncated": True}
        reused = profiles.prepare_operations(self.root, self.entries, ["a", "b"], ["a", "b"],
            "one", [], source_contexts=[record])
        self.assertFalse(reused["windows"])
        self.assertTrue(reused["groups"][0]["source_ref"].startswith("mehscanSweepSource/v1:"))

    def test_no_group_for_split_jobs_different_callables_or_ambiguous_locations(self):
        split = self.prepare(ids=["a"])
        self.assertFalse(split["groups"])
        self.assertIn("different review jobs", split["limits"][0]["reason"])
        for mutation in (lambda e: e[1]["operand_facts"][0]["location"]["start"].update(line=2, byte_offset=15),
                         lambda e: e[1]["operand_facts"].append({**e[1]["operand_facts"][0], "location": {"path": "other.py"}}),
                         lambda e: e[1].update(cwe_candidates=["CWE-89"])):
            entries = copy.deepcopy(self.entries)
            mutation(entries)
            self.assertFalse(self.prepare(entries=entries)["groups"])

    def test_budget_and_invalid_byte_ranges_do_not_clip_a_callable(self):
        entries = self.entries + [self.entry(str(i), 2) for i in range(5)]
        result = profiles.prepare_operations(self.root, entries, [e["review_id"] for e in entries],
            [e["review_id"] for e in entries], "one", [])
        self.assertFalse(result["groups"])
        self.entries[0]["operand_facts"][0]["location"]["end"]["byte_offset"] += 20
        self.entries[1]["operand_facts"] = copy.deepcopy(self.entries[0]["operand_facts"])
        with self.assertRaisesRegex(ValueError, "range differs"):
            self.prepare()

    def test_crlf_and_unicode_coordinates_use_original_bytes(self):
        raw = self.source.replace("Row", "Röw").replace("\n", "\r\n").encode()
        (self.root / "app.py").write_bytes(raw)
        for entry in self.entries:
            entry["operand_facts"][0]["location"]["end"]["byte_offset"] = len(raw) - 2
        self.assertIn("Röw", self.prepare()["windows"][0]["text"])
        with self.assertRaisesRegex(ValueError, "selection"):
            self.prepare(ids=["a", "a"])


class WorkerOperationIntegration(unittest.TestCase):
    def test_grouping_mode_cannot_change_on_recovery(self):
        import test_worker as fixture
        case = fixture.Worker(methodName="runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.reviewer.write_text("raise SystemExit(2)\n", encoding="utf-8")
        failed = case.invoke(name="grouped-failure", extra=["--phase", "native", "--group-operations"])
        self.assertNotEqual(failed.returncode, 0)
        resumed = case.invoke(name="changed-grouping", extra=["--phase", "native", "--resume-from", str(case.base / "grouped-failure")])
        self.assertNotEqual(resumed.returncode, 0)
        record = json.loads((case.base / "changed-grouping/worker.json").read_text())
        self.assertIn("same current source", record["detail"])
        self.assertFalse(list((case.base / "changed-grouping").glob("context-*.json")))

    def test_native_worker_keeps_every_id_and_shared_source_handles(self):
        import test_worker as fixture
        case = fixture.Worker(methodName="runTest")
        case.extra_source_files = {"app.py": "def clean(keys):\n    Row.objects.filter(pk__in=keys).delete()\n    Other.objects.filter(pk__in=keys).delete()\n"}
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.reviewer.write_text('''import json,sys
from pathlib import Path
task=json.load(sys.stdin)
packet=json.loads(Path(task["evidence_packet"]).read_text())
questions={q["review_id"]:q for q in packet["native_questions"]}
for group in packet.get("operation_groups",[]):
    assert len(group["review_ids"])==2 and not group["verified"]
    assert group["source_ref"] in task["research"]["artifact_handles"].values()
    body=next(w for w in packet["primary"]["windows"] if w["artifact_id"]==group["source_ref"])
    assert body["text"].count(".delete()")==2
print(json.dumps({"results":[{"review_id":rid,"decision":"needs_review","confidence":"medium",
    "summary":"Caller authority remains unresolved for this effect.",
    "reason":"Synthetic controller check retains each selected effect independently.",
    "evidence":[{"path":questions[rid]["path"],"start_line":questions[rid]["line"],"end_line":questions[rid]["line"]}],
    "checks":["Confirm caller authority before this selected effect."],"blockers":[]} for rid in task["review_ids"]]}))
''', encoding="utf-8")
        completed = case.invoke(extra=["--phase", "native", "--group-operations"])
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        output = case.base / "worker"
        record = json.loads((output / "worker.json").read_text())
        self.assertTrue(record["group_operations"])
        self.assertEqual(sum(c["operation_grouped_review_count"] for c in record["prepared_contexts"]), 2)
        findings = json.loads((output / "findings.json").read_text())
        self.assertEqual({r["response"]["review_id"] for r in findings["decision_records"]}, set(case.ids))
        self.assertTrue(all(r["response"]["decision"] == "needs_review" for r in findings["decision_records"]))
        invalid = case.invoke(name="wrong-phase", extra=["--group-operations"])
        self.assertNotEqual(invalid.returncode, 0)
        self.assertFalse((case.base / "wrong-phase").exists())


if __name__ == "__main__":
    unittest.main()
