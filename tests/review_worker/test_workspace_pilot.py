"""Pilot source parity and native freeze; provider preflight is stubbed, no inference."""
import copy
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
        with patch.object(pilot.subprocess,"check_output",return_value="codex-cli fixture-1\n"),patch("codex_launcher.Launcher") as launcher:
            result = pilot.prepare(args)
        self.assertEqual(result["model_calls"],0)
        self.assertEqual(launcher.call_count,1)
        root,loaded,setup = pilot.load_run(args.output)
        parity = fixtures.read(root / "initial-evidence.json")
        self.assertEqual(set(parity),set(design["selected_review_ids"]))
        self.assertTrue(all(v["windows"] for v in parity.values()))
        self.assertEqual(fixtures.read(root / "run-binding.json")["provider"]["model"],f.config["model"])
        self.assertEqual(fixtures.read(Path(setup['arms']['treatment']['work_package']))['payload']['runtime']['limits']['rounds'],5)
        (root / "initial-evidence.json").write_text("{}")
        with self.assertRaisesRegex(ValueError,"input changed"):
            pilot.load_run(args.output)


if __name__ == "__main__":
    unittest.main()
