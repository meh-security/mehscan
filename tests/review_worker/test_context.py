"""Actual pinned Git blobs and independent old/current coordinates, not model truth."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PRODUCT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PRODUCT / "scripts"))
import review_context as context


class Context(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-context-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "base")
        return self.git("rev-parse", "HEAD")

    def prepare(self, base, changed):
        scanner = Path(os.environ.get("MEHSCAN_TEST_SCANNER", PRODUCT / "target/debug" / ("mehscan.exe" if os.name == "nt" else "mehscan")))
        def native(args):
            result = subprocess.run([str(scanner), *args], capture_output=True, text=True, encoding="utf-8")
            if result.returncode:
                raise RuntimeError("native enclosing unavailable")
            return json.loads(result.stdout)
        return context.prepare_changes(self.root, {"comparison":{"base_commit":base}, "changed_files":changed}, native, dict(os.environ), 30)

    def test_late_edit_and_inserted_prefix_keep_old_and_new_enclosing_coordinates(self):
        old = "".join("// padding " + str(n) + "\n" for n in range(600)) + "function guard(user) {\n  if (!user.admin) return false;\n  return true;\n}\n"
        (self.root / "app.js").write_text(old, encoding="utf-8")
        base = self.commit()
        current = "".join("// inserted " + str(n) + "\n" for n in range(20)) + old.replace("!user.admin", "false && !user.admin")
        (self.root / "app.js").write_text(current, encoding="utf-8")
        value = self.prepare(base, [{"path":"app.js","status":"modified","changed_lines":[{"start":622,"end":622}]}])
        before = [x for x in value["windows"] if x["side"] == "base" and x["start_line"] > 400][0]
        after = [x for x in value["windows"] if x["side"] == "current" and x["start_line"] > 400][0]
        self.assertIn("if (!user.admin)", before["text"])
        self.assertIn("false && !user.admin", after["text"])
        self.assertIn("function guard", before["text"])
        self.assertIn("function guard", after["text"])
        self.assertNotEqual(before["start_line"], after["start_line"])

    def test_rename_only_and_deletion_preserve_actual_pinned_old_paths(self):
        (self.root / "old name.js").write_text("const value = 'old';\n", encoding="utf-8")
        base = self.commit()
        (self.root / "old name.js").rename(self.root / "new name.js")
        renamed = self.prepare(base, [{"path":"new name.js","previous_path":"old name.js","status":"renamed","changed_lines":[]}])
        self.assertEqual([(x["side"],x["path"]) for x in renamed["windows"]], [("base","old name.js"),("current","new name.js")])
        deleted = self.prepare(base, [{"path":"old name.js","status":"deleted","changed_lines":[]}])
        self.assertEqual([(x["side"],x["path"]) for x in deleted["windows"]], [("base","old name.js")])

    def test_added_empty_and_binary_paths_have_truthful_evidence_or_limits(self):
        (self.root / "base.js").write_text("const value = 0;\n")
        base = self.commit()
        (self.root / "empty.js").write_bytes(b"")
        (self.root / "binary.js").write_bytes(b"\xff")
        value = self.prepare(base, [{"path":"empty.js","status":"added","changed_lines":[]},
                                    {"path":"binary.js","status":"added","changed_lines":[]}])
        empty = value["windows"][0]
        self.assertEqual((empty["path"],empty["side"],empty["start_line"],empty["end_line"],empty["text"]), ("empty.js","current",1,1,""))
        self.assertTrue(any(item["path"] == "binary.js" and "UTF-8" in item["reason"] for item in value["limits"]))

    def test_large_deleted_unit_is_clipped_explicitly_and_missing_old_blob_is_rejected(self):
        text = "".join("const item" + str(n) + " = " + str(n) + ";\n" for n in range(800))
        (self.root / "large.js").write_text(text)
        base = self.commit()
        (self.root / "large.js").unlink()
        value = self.prepare(base, [{"path":"large.js","status":"deleted","changed_lines":[]}])
        self.assertTrue(value["windows"][0]["clipped"])
        self.assertEqual(value["windows"][0]["end_line"], 400)
        self.assertTrue(value["limits"])
        with self.assertRaises(ValueError):
            self.prepare(base, [{"path":"missing.js","status":"deleted","changed_lines":[]}])

    def test_runtime_contract_is_compiled_from_versioned_trusted_sections(self):
        skill = PRODUCT / "skills/mehscan-security"
        native = context.compile_contract(skill, "native_bundle", [{"capability":"html_output"}], [])
        text = "\n".join(x["text"] for x in native["sources"])
        self.assertIn("same-user", text)
        self.assertIn("URLSearchParams", text)
        self.assertIn("not_issue", text)
        self.assertNotIn("review-bundle-finalize", text)
        self.assertTrue(native["contract_id"].startswith("mehscanRuntime/v1:"))
        self.assertEqual(native, context.compile_contract(skill, "native_bundle", [{"capability":"html_output"}], []))

    def test_source_coordinates_preserve_lone_cr_and_non_newline_separators(self):
        self.assertEqual(context.source_lines("a\r\nb\rc\vlast\r"), ["a", "b\rc\vlast\r"])
        self.assertEqual(context.source_lines("a\n\n"), ["a", ""])
        self.assertEqual(context.source_lines(""), [""])

    def test_application_policy_is_deduplicated_source_with_stable_binding(self):
        text = 'builder.Services.AddAuthorization(o => o.FallbackPolicy = policy);\napp.UseAuthorization();\n'
        file = self.root / 'Program.cs'
        file.write_text(text, encoding='utf-8')
        lead = {'role':'application_policy_context','location':{'path':'Program.cs','start_line':1,'end_line':2}}
        sweep = {'reviews':[{'application_context':[lead]},{'application_context':[lead]}]}
        cache = {}
        first = context.prepare_application(self.root, sweep, cache, 'snapshot-a')
        self.assertEqual(len(first['windows']), 1)
        self.assertEqual(first['windows'][0]['text'], text.rstrip('\n'))
        self.assertTrue(first['windows'][0]['complete_file'])
        from unittest.mock import patch
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('redundant source read')):
            second = context.prepare_application(self.root, sweep, cache, 'snapshot-a')
        self.assertEqual(first, second)
        other = context.prepare_application(self.root, sweep, cache, 'snapshot-b')
        self.assertNotEqual(first['windows'][0]['artifact_id'], other['windows'][0]['artifact_id'])

    def test_application_policy_clipping_is_explicit_and_paths_stay_in_source(self):
        (self.root / 'Program.cs').write_text('// padding\n' * 450 + 'app.UseAuthorization();\n', encoding='utf-8')
        lead = {'location':{'path':'Program.cs','start_line':1,'end_line':451}}
        result = context.prepare_application(self.root, {'reviews':[{'application_context':[lead]}]}, {}, 'snapshot')
        self.assertTrue(result['windows'][0]['clipped'])
        self.assertFalse(result['windows'][0]['complete_file'])
        self.assertTrue(result['limits'])
        lead['location']['path'] = '../outside.cs'
        with self.assertRaises(ValueError):
            context.prepare_application(self.root, {'reviews':[{'application_context':[lead]}]}, {}, 'snapshot')

    def test_shared_startup_is_prepared_before_many_inherited_controllers(self):
        (self.root/'Program.cs').write_text('app.UseAuthorization();\n', encoding='utf-8')
        leads = [{'role':'application_policy_context','location':{'path':'Program.cs','start_line':1,'end_line':1}}]
        for n in range(6):
            path = 'Base' + str(n) + '.cs'
            (self.root/path).write_text('[Authorize] class Base {}\n', encoding='utf-8')
            leads.append({'role':'inherited_policy_context','location':{'path':path,'start_line':1,'end_line':1}})
        result = context.prepare_application(self.root, {'reviews':[{'application_context':leads}]}, {}, 'snapshot')
        self.assertEqual(result['windows'][0]['path'], 'Program.cs')
        self.assertEqual(len(result['windows']), 4)
        self.assertEqual(len(result['limits']), 3)

    def test_native_contract_retains_the_actual_non_html_bucket_policy(self):
        value = context.compile_contract(PRODUCT / "skills/mehscan-security", "native_bundle",
            [{"capability":"sql"}], [], {"review-1":{"bucket":"interpreted_input"}})
        self.assertTrue(any("**SQL:**" in item["text"] for item in value["sources"]))
        with self.assertRaises(ValueError):
            context.compile_contract(PRODUCT / "skills/mehscan-security", "native_bundle", [], [],
                {"review-1":{"bucket":"../../operator"}})

    def test_subdirectory_base_lookup_uses_repository_prefix_without_widening_source(self):
        folder = self.root / "app"
        folder.mkdir()
        (folder / "code.js").write_text("const old = 1;\n")
        base = self.commit()
        obj = context.base_object(folder.resolve(), base, "code.js", dict(os.environ), 10)
        self.assertEqual(obj, base + ":app/code.js")
        with self.assertRaises(ValueError):
            context.base_object(folder.resolve(), base, "../outside.js", dict(os.environ), 10)


if __name__ == "__main__":
    unittest.main()
