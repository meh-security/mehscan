"""Direct API transport tests without paid inference or real credentials."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "skills/mehscan-security/scripts"))

import codex_reviewer
import openai_responses


class ResponsesTransport(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        auth = self.root / "auth.json"
        auth.write_text(json.dumps({"OPENAI_API_KEY": "sk-project-fixture-key"}), encoding="utf-8")
        self.model = "gpt-6.1-terra"
        self.config = {"model": self.model, "reasoning_effort": "medium", "auth_file": str(auth)}
        self.response = {"model": self.model, "output": [
            {"type": "reasoning", "encrypted_content": "opaque", "summary": []},
            {"type": "message", "role": "assistant", "status": "completed",
             "content": [{"type": "output_text", "text": '{"decision":"fixture"}'}]}],
            "usage": {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 2},
                      "output_tokens": 6, "output_tokens_details": {"reasoning_tokens": 1}}}

    def test_stateless_continuation_has_no_tools_and_reports_each_request(self):
        launcher = openai_responses.ResponsesLauncher(self.config, self.root)
        schema = {"type": "object"}
        with patch.object(openai_responses, "request_response", return_value=self.response) as request:
            reply, events, _ = launcher.review("first", schema)
            thread, usage = codex_reviewer.parse_events(events)
            self.assertEqual(reply, {"decision": "fixture"})
            self.assertEqual(usage, {"input_tokens": 10, "cached_input_tokens": 2,
                                    "output_tokens": 6, "reasoning_output_tokens": 1})
            payload = request.call_args.args[0]
            self.assertFalse(payload["store"])
            self.assertEqual(payload["tools"], [])
            self.assertEqual(payload["reasoning"], {"effort": "medium"})
            self.assertEqual(payload["text"]["format"]["schema"], schema)
            _, events, _ = launcher.review("new bound evidence", schema, thread)
            self.assertEqual(codex_reviewer.parse_events(events, thread), (thread, usage))
            self.assertEqual(request.call_args.args[0]["input"], [{"role": "user", "content": "first"},
                *self.response["output"], {"role": "user", "content": "new bound evidence"}])
            with self.assertRaises(ValueError):
                launcher.review("unsupported restart", schema)
            Path(self.config["auth_file"]).write_text(json.dumps({"OPENAI_API_KEY": "sk-different-project-fixture"}))
            with self.assertRaises(ValueError):
                openai_responses.ResponsesLauncher(self.config, self.root).review("different payer", schema, thread)
            self.assertEqual(request.call_count, 2)

    def test_tool_output_cannot_enter_private_continuation(self):
        launcher = openai_responses.ResponsesLauncher(self.config, self.root)
        with patch.object(openai_responses, "request_response", return_value={"model": self.model,
                "output": [{"type": "function_call"}]}):
            with self.assertRaises(ValueError):
                launcher.review("source description", {})
        self.assertFalse(launcher.history.exists())


if __name__ == "__main__":
    unittest.main()
