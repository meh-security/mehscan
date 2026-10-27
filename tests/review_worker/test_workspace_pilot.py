"""Pilot source parity and native freeze; provider preflight is stubbed, no inference."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_bridge as fixtures
import review_workspace_pilot as pilot


class PilotTests(unittest.TestCase):
    def test_native_fragment_can_coexist_with_full_source_but_cannot_supply_a_full_line(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);file=root/'a.ts';file.write_text('  const value = input;\n')
            required=[{'path':'a.ts','start_line':1,'end_line':1,
                       'file_sha256':hashlib.sha256(file.read_bytes()).hexdigest()}]
            fragment={'path':'a.ts','start_line':1,'text':'value = input'}
            self.assertFalse(pilot.source_coverage(root,required,[fragment])['complete'])
            full={'path':'a.ts','start_line':1,'text':'  const value = input;'}
            self.assertTrue(pilot.source_coverage(root,required,[fragment,full])['complete'])
            with self.assertRaisesRegex(ValueError,'conflicting'):
                pilot.source_coverage(root,required,[full,{**fragment,'text':'invented'}])

    def test_blank_ending_explicit_window_keeps_coverage_after_repeated_normalization(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);file=root/'a.ts';file.write_text('one\n\nthree\n')
            required=[{'path':'a.ts','start_line':1,'end_line':2,
                       'file_sha256':hashlib.sha256(file.read_bytes()).hexdigest()}]
            delivered=[{'path':'a.ts','start_line':1,'end_line':2,'text':'one\n\n',
                        'line_range':{'start_line':1,'end_line':2,'inclusive':True}}]
            canonical=pilot.canonical_windows(delivered)
            self.assertEqual(canonical,pilot.canonical_windows(canonical))
            self.assertTrue(pilot.source_coverage(root,required,canonical)['complete'])
            with self.assertRaisesRegex(ValueError,'differs'):
                pilot.canonical_windows([{**delivered[0],'text':'one'}])

    def test_equal_packets_can_still_omit_required_source(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "a.ts").write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
            required = [{"path":"a.ts", "start_line":1, "end_line":4,
                         "file_sha256":hashlib.sha256((root / "a.ts").read_bytes()).hexdigest()}]
            # The two arms agree, but neither delivered the deciding last line.
            delivered = [{"path":"a.ts", "start_line":1, "text":"one\ntwo\nthree"}]
            receipt = pilot.source_coverage(root,required,delivered)
            self.assertFalse(receipt["complete"])
            self.assertEqual(receipt["windows"][0]["missing_lines"],[4])
            delivered.append({"path":"a.ts", "start_line":4, "text":"four\n"})
            self.assertTrue(pilot.source_coverage(root,required,delivered)["complete"])
            delivered[-1]["text"] = "invented"
            with self.assertRaisesRegex(ValueError,"differ"):
                pilot.source_coverage(root,required,delivered)
            (root / "a.ts").write_text("changed\n")
            with self.assertRaisesRegex(ValueError,"stale"):
                pilot.source_coverage(root,required,[])

    def test_source_requirements_reject_escape_invalid_ranges_and_conflicting_text(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "a.ts").write_text("one\ntwo\n")
            required = {"path":"a.ts", "start_line":1, "end_line":2,
                        "file_sha256":hashlib.sha256((root / "a.ts").read_bytes()).hexdigest()}
            for change in ({"path":"../a.ts"},{"start_line":True},{"end_line":3},{"end_line":401}):
                with self.subTest(change=change),self.assertRaises(ValueError):
                    pilot.source_coverage(root,[{**required,**change}],[])
            with self.assertRaisesRegex(ValueError,"conflicting"):
                pilot.source_coverage(root,[required],[{"path":"a.ts","start_line":1,"text":"one"},
                                                      {"path":"a.ts","start_line":1,"text":"other"}])

    def test_expanded_native_case_limits_are_explicit_and_do_not_change_defaults(self):
        self.assertEqual(pilot.native_case_limits({})['rounds'],3)
        expanded = pilot.native_case_limits({'native_case_limits':{'rounds':5,'queries':24,'bytes':524288,'timeout_seconds':900}})
        self.assertEqual(expanded['rounds'],5)
        with self.assertRaises(ValueError):
            pilot.native_case_limits({'native_case_limits':{'rounds':6}})
    def test_execution_reservation_blocks_restart_even_without_a_result(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            started = pilot.begin_execution(root,"control")
            self.assertGreater(started["started_epoch"],0)
            with self.assertRaises(FileExistsError):
                pilot.begin_execution(root,"control")
            (root / "treatment").mkdir()
            (root / "treatment/result.json").write_text('{"status":"incomplete"}')
            with self.assertRaisesRegex(ValueError,"already has a result"):
                pilot.begin_execution(root,"treatment")

    def test_incomplete_metrics_keep_observed_cost_separate_from_unknown_total(self):
        with tempfile.TemporaryDirectory() as name:
            row = {"conversation_id":"one","round":0,"elapsed_ms":12,
                   "usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":5}}
            (Path(name) / "provider-metrics.jsonl").write_text(json.dumps(row) + "\n")
            usage = pilot.metrics(name,attempted_calls=2)
            self.assertEqual(usage["unobserved_calls"],1)
            self.assertEqual(usage["observed_totals"]["input_tokens"],100)
            self.assertIsNone(usage["input_tokens"])
            self.assertIsNone(usage["cumulative_model_call_ms"])
            with self.assertRaisesRegex(ValueError,"unknown"):
                pilot.enforce_usage(usage,{"max_input_tokens":200,"max_output_tokens":20})
            self.assertEqual(pilot.metrics(name,attempted_calls=1)["input_tokens"],100)
            with self.assertRaisesRegex(ValueError,"exceed reserved"):
                pilot.metrics(name,attempted_calls=0)

    def test_source_parity_normalizes_reader_newline_and_deduplicates_only_identical_ranges(self):
        a = {"path":"a.ts","start_line":1,"end_line":2,"text":"first\r\nsecond\r\n"}
        b = {"location":{"path":"a.ts","start_line":1,"end_line":2},"excerpt":"first\nsecond"}
        self.assertEqual(len(pilot.canonical_windows([a,b])),1)
        self.assertEqual(pilot.canonical_windows([a]),pilot.canonical_windows([{**b,"location":{**b['location'],"end_line":3}}]))
        self.assertEqual(len(pilot.canonical_windows([a,{**b,"excerpt":"different"}])),2)

    def test_unknown_usage_and_observed_overspend_prevent_another_call(self):
        limits = {"max_input_tokens":100,"max_output_tokens":50}
        with self.assertRaisesRegex(ValueError,"unknown"):
            pilot.enforce_usage({"input_tokens":None,"output_tokens":1},limits)
        with self.assertRaisesRegex(ValueError,"ceiling"):
            pilot.enforce_usage({"input_tokens":100,"output_tokens":1},limits)

    def test_native_freeze_has_matching_initial_source_and_no_model_call(self):
        f = fixtures.NativeBridgeTests(methodName="test_rejected_completed_reply_still_records_usage")
        f.extra_source = {"policy.ts":"export const pending = true;\n"}
        f.setUp()
        self.addCleanup(f.doCleanups)
        inv = fixtures.read(f.inventory / "inventory.json")
        design = {"source_pin":{"local_export":str(f.root),"native_repository_key":"evaluation:workspace-bridge",
                                "native_source_fingerprint":inv["identity_catalog"]["source_fingerprint"]},
                  "model":f.config["model"],"reasoning_effort":f.config["reasoning_effort"],
                  "selected_review_ids":f.package["payload"]["review_ids"],"per_arm_limits":f.limits,
                  "per_arm_experiment":f.experiment,
                  "native_case_limits":{"rounds":5,"queries":24,"bytes":524288,"timeout_seconds":900}}
        design_path = f.base / "design.json"
        design_path.write_text(json.dumps(design))
        args = copy.copy(f.args)
        args.design, args.output, args.private = str(design_path),str(f.base / "pilot"),str(f.base / "pilot-private")
        args.provider_config, args.provider_executable = str(f.config_path),sys.executable
        required = {"path":"policy.ts","start_line":1,"end_line":1,
                    "file_sha256":hashlib.sha256((f.root / "policy.ts").read_bytes()).hexdigest()}
        key = design["selected_review_ids"][0]
        design["required_initial_source"] = {key:[required]}
        design_path.write_text(json.dumps(design))
        with patch.object(pilot.subprocess,"check_output",return_value="codex-cli fixture-1\n"),patch("codex_launcher.Launcher") as launcher:
            with self.assertRaisesRegex(ValueError,"not fully delivered"):
                pilot.prepare(args)
        self.assertEqual(launcher.call_count,0)
        missing = fixtures.read(Path(args.output) / "initial-source-coverage.json")
        self.assertFalse(missing[key]["complete"])
        original = pilot.context.prepare_application
        def include_source(root,sweep,cache,snapshot):
            supplied = copy.deepcopy(sweep)
            for card in supplied["reviews"]:
                card.setdefault("application_context",[]).append({"role":"application_policy_context",
                    "location":{"path":"policy.ts","start_line":1,"end_line":1}})
            return original(root,supplied,cache,snapshot)
        args.output, args.private = str(f.base / "complete-pilot"),str(f.base / "complete-private")
        with patch.object(pilot.subprocess,"check_output",return_value="codex-cli fixture-1\n"),patch("codex_launcher.Launcher") as launcher:
            with patch.object(pilot.context,"prepare_application",side_effect=include_source):
                result = pilot.prepare(args)
        self.assertEqual(result["model_calls"],0)
        self.assertEqual(launcher.call_count,1)
        root,loaded,setup = pilot.load_run(args.output)
        parity = fixtures.read(root / "initial-evidence.json")
        self.assertEqual(set(parity),set(design["selected_review_ids"]))
        self.assertTrue(all(v["windows"] for v in parity.values()))
        self.assertEqual(fixtures.read(root / "run-binding.json")["provider"]["model"],f.config["model"])
        self.assertEqual(fixtures.read(Path(setup['arms']['treatment']['work_package']))['payload']['runtime']['limits']['rounds'],5)
        coverage_path = root / "initial-source-coverage.json"
        self.assertTrue(fixtures.read(coverage_path)[key]["complete"])
        original_coverage = coverage_path.read_bytes()
        coverage_path.write_text("{}")
        with self.assertRaisesRegex(ValueError,"coverage changed"):
            pilot.load_run(args.output)
        coverage_path.write_bytes(original_coverage)
        (root / "initial-evidence.json").write_text("{}")
        with self.assertRaisesRegex(ValueError,"input changed"):
            pilot.load_run(args.output)


if __name__ == "__main__":
    unittest.main()
