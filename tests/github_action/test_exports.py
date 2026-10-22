"""Artifact usage is numeric, bounded and explicit about missing counters."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("review_export", Path(__file__).resolve().parents[2] / "scripts/review_export.py")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "metrics.jsonl"
        self.runtime = {"provider":{"provider":"codex-cli"}, "policy":"value", "limits":{}}

    def row(self, round=0, **values):
        return {"schema_version":"1", "provider":self.runtime["provider"], "usage_basis":"conversation_delta",
                "conversation_id":"session", "round":round, **values}

    def put(self, *rows):
        self.path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    def test_absent_counters_are_unknown_and_partial_sums_are_identified(self):
        missing = export.usage(self.path, self.runtime)
        self.assertFalse(missing["usage_available"])
        self.assertIsNone(missing["reported_token_sums"]["input_tokens"])
        self.put(self.row(usage={"input_tokens":7}, prompt="private prompt"), self.row(1))
        result = export.usage(self.path, self.runtime)
        self.assertEqual(result["round_count"], 2)
        self.assertEqual(result["reported_token_sums"]["input_tokens"], 7)
        self.assertEqual(result["counter_reporting_rounds"]["input_tokens"], 1)
        self.assertIsNone(result["reported_token_sums"]["output_tokens"])
        self.assertNotIn("private prompt", json.dumps(result))
        self.assertIsNone(result["cost"])
        self.assertFalse(result["usage_complete"])

    def test_failed_or_unobserved_calls_prevent_complete_usage_claim(self):
        self.put(self.row(usage={"input_tokens":7, "cached_input_tokens":3, "output_tokens":2}))
        self.assertTrue(export.usage(self.path, self.runtime)["usage_complete"])
        partial = export.usage(self.path, self.runtime, unobserved_provider_calls=1)
        self.assertFalse(partial["usage_complete"])
        self.assertEqual(partial["reported_token_sums"]["input_tokens"], 7)

    def test_tiered_usage_keeps_actual_counters_by_bound_provider(self):
        expert = {"provider":"codex-cli", "model":"gpt-6-sol"}
        self.runtime["orchestration"] = {"expert":expert}
        self.put(self.row(usage={"input_tokens":7}), self.row(1, provider=expert, role="verification", usage={"input_tokens":11}))
        result = export.usage(self.path, self.runtime)
        self.assertEqual(result["reported_token_sums"]["input_tokens"], 18)
        self.assertEqual([row["reported_token_sums"]["input_tokens"] for row in result["profiles"]], [7,11])
        self.assertEqual(result["profiles"][1]["roles"], {"verification":1})

    def test_duplicate_or_mismatched_provider_metrics_are_rejected(self):
        self.put(self.row(), self.row())
        with self.assertRaises(ValueError): export.usage(self.path, self.runtime)
        self.put(self.row(provider={"provider":"other"}))
        with self.assertRaises(ValueError): export.usage(self.path, self.runtime)
        self.put(self.row(usage_basis="conversation_total"))
        with self.assertRaises(ValueError): export.usage(self.path, self.runtime)

    def test_negative_boolean_and_noninteger_counts_are_rejected(self):
        for value in (-1, True, "7", 1.5):
            with self.subTest(value=value):
                self.put(self.row(usage={"input_tokens":value}))
                with self.assertRaises(ValueError): export.usage(self.path, self.runtime)

    def test_malformed_records_fail_with_a_controlled_error(self):
        for row in ([], self.row(usage=[]), self.row(usage=None), self.row(round=True), self.row(conversation_id=[])):
            with self.subTest(row=row):
                self.put(row)
                with self.assertRaises(ValueError): export.usage(self.path, self.runtime)


if __name__ == "__main__":
    unittest.main()
