"""Adapter, exact continuation and real process tests; no model credentials or inference."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "skills/mehscan-security/scripts"))
import codex_launcher as launcher
import codex_reviewer as reviewer
import codex_protocol as protocol

THREAD = "12345678-1234-1234-1234-123456789abc"


class Adapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mehscan-provider-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "source"
        self.public = self.base / "artifacts"
        self.source.mkdir()
        self.public.mkdir()
        self.binary = self.base / "trusted-codex"
        self.binary.write_bytes(b"synthetic executable")
        self.auth = self.base / "auth.json"
        self.auth.write_text('{"test_secret":"private-only"}')
        self.config = {"schema_version":"1","executable":str(self.binary),"executable_version":"0.162.0-alpha.17.2",
            "model":"gpt-6-luna","reasoning_effort":"medium",
            "auth_file":str(self.auth),"private_directory":str(self.base / "provider-private")}
        self.packet = self.public / "context.json"
        self.facts = self.public / "facts.json"
        self.body = {"work":{"runtime":{"provider":launcher.provider_contract(self.config)}},
            "contract":{"sources":[{"text":"Trusted native review contract."}]},"native_questions":[],
            "primary":{"source":"Untrusted source bytes."}}
        self.packet.write_text(json.dumps(self.body))
        self.facts.write_text('{"facts":[]}')
        self.task = {"kind":"change_pass","conversation_id":"a"*64,"source_root":str(self.source),
            "artifact_root":str(self.public),"evidence_packet":str(self.packet),"shared_facts":str(self.facts),
            "research":{"round":0,"results":[],"artifact_handles":{},"rounds_remaining":2}}
        self.calls = []

    def factory(self, config, session):
        calls = self.calls
        class Fake:
            def review(self, prompt, schema, thread_id=None, timeout=600):
                calls.append((prompt, thread_id, schema))
                response = {"action":"final","research":[],"draft":{"change_pass":[]},"working_chain":"Inspected supplied facts.","progress":[]}
                total = 2 if thread_id else 1
                events = [{"type":"thread.started","thread_id":THREAD},{"type":"turn.completed",
                    "usage":{"input_tokens":100*total,"cached_input_tokens":60*total,"output_tokens":20*total}}]
                return response, "\n".join(map(json.dumps, events)), "private diagnostics"
        return Fake()

    def invoke(self):
        return reviewer.run(self.config, self.task, self.factory)

    def test_exact_resume_sends_new_facts_only_and_metrics_exclude_private_data(self):
        self.invoke()
        self.task["research"]["round"] = 1
        self.facts.write_text(json.dumps({"facts":[{"result_id":"fact-new","text":"new actual code"}]}))
        self.invoke()
        self.assertEqual([call[1] for call in self.calls], [None, THREAD])
        self.assertNotIn("Trusted native review contract", self.calls[1][0])
        self.assertIn("new actual code", self.calls[1][0])
        metrics = (self.public / "provider-metrics.jsonl").read_text()
        self.assertNotIn("private-only", metrics)
        self.assertNotIn("private diagnostics", metrics)
        self.assertNotIn(str(self.auth), metrics)
        self.assertEqual(json.loads(metrics.splitlines()[1])["usage"]["cached_input_tokens"], 60)
        self.assertEqual(sum(json.loads(row)["usage"]["input_tokens"] for row in metrics.splitlines()), 200)
        self.assertEqual(json.loads(metrics.splitlines()[1])["reported_conversation_usage"]["input_tokens"], 200)
        self.assertFalse(Path(self.config["private_directory"]).is_relative_to(self.public))

    def test_parallel_first_conversations_initialize_once_and_keep_separate_metrics(self):
        barrier = threading.Barrier(4)
        def start(letter):
            task = {**self.task, "conversation_id": letter * 64,
                    "provider_metrics": str(self.public / (letter + "-metrics.jsonl"))}
            barrier.wait(timeout=5)
            return reviewer.run(self.config, task, self.factory)
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(len(list(pool.map(start, "abcd"))), 4)
        marker = Path(self.config["private_directory"]) / "mehscan-provider.json"
        self.assertEqual(json.loads(marker.read_text()), launcher.provider_contract(self.config))
        for letter in "abcd":
            rows = (self.public / (letter + "-metrics.jsonl")).read_text().splitlines()
            self.assertEqual(len(rows), 1)
            self.assertEqual(json.loads(rows[0])["conversation_id"], letter * 64)
        self.assertFalse((self.public / "provider-metrics.jsonl").exists())

    def test_progress_handles_are_exhaustive_in_schema_and_each_prompt(self):
        self.task["research"]["artifact_handles"] = {"sweep":"bound-sweep"}
        self.invoke()
        prompt, _, schema = self.calls[-1]
        self.assertIn('Available artifact handles (exhaustive for this turn):\n["sweep"]', prompt)
        artifacts = schema["properties"]["progress"]["items"]["properties"]["artifacts"]
        self.assertEqual(artifacts["items"]["enum"], ["sweep"])
        self.assertNotIn("source1", artifacts["items"]["enum"])
        self.task["research"]["round"] = 1
        self.task["research"]["artifact_handles"]["fact1"] = "bound-fact"
        self.invoke()
        self.assertIn('["sweep", "fact1"]', self.calls[-1][0])
        self.assertEqual(self.calls[-1][2]["properties"]["progress"]["items"]["properties"]["artifacts"]["items"]["enum"], ["sweep", "fact1"])
        self.task["research"]["artifact_handles"] = {}
        empty = protocol.build_schema(self.task)["properties"]["progress"]["items"]["properties"]["artifacts"]
        self.assertEqual(empty["maxItems"], 0)

    def test_changed_packet_model_and_repeated_round_cannot_resume(self):
        self.invoke()
        with self.assertRaises(ValueError): self.invoke()
        self.task["research"]["round"] = 1
        self.body["primary"]["source"] = "changed evidence"
        self.packet.write_text(json.dumps(self.body))
        with self.assertRaises(ValueError): self.invoke()
        self.config["model"] = "another-model"
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(len(self.calls), 1)

    def test_cumulative_counter_delta_missing_baseline_and_reset(self):
        self.assertEqual(reviewer.usage_delta({"input_tokens":100},None,False), ({"input_tokens":100},[]))
        self.assertEqual(reviewer.usage_delta({"input_tokens":170},{"input_tokens":100},True), ({"input_tokens":70},[]))
        for prior in ({}, {"input_tokens":200}):
            self.assertEqual(reviewer.usage_delta({"input_tokens":100},prior,True), ({},["input_tokens"]))

    def test_missing_session_never_uses_last_or_restarts(self):
        self.task["research"]["round"] = 1
        with self.assertRaises(ValueError): self.invoke()
        self.assertFalse(self.calls)

    def test_private_sessions_and_auth_cannot_live_under_the_whole_artifact_root(self):
        child = self.public / "review"
        child.mkdir()
        self.packet = child / "context.json"
        self.packet.write_text(json.dumps(self.body))
        self.task["evidence_packet"] = str(self.packet)
        self.config["private_directory"] = str(self.public / "sibling-private")
        with self.assertRaises(ValueError): self.invoke()
        self.config["private_directory"] = str(self.base / "provider-private")
        self.config["auth_file"] = str(self.facts)
        with self.assertRaises(ValueError): self.invoke()
        self.assertFalse(self.calls)

    def test_existing_arbitrary_directory_is_not_chmodded_or_used(self):
        self.config["private_directory"] = str(self.base)
        with self.assertRaises(ValueError): self.invoke()
        self.assertFalse(self.calls)

    def test_config_rejects_extra_flags_and_option_like_models(self):
        path = self.base / "config.json"
        path.write_text(json.dumps(self.config))
        self.assertEqual(launcher.load_config(path), self.config)
        for key, value in (("extra_args",["--dangerously-bypass-approvals-and-sandbox"]), ("model","--unsafe")):
            config = {**self.config, key:value}
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError): launcher.load_config(path)

    def test_tool_events_failed_turn_and_changed_thread_are_rejected(self):
        for event in ({"type":"item.completed","item":{"type":"command_execution"}}, {"type":"turn.failed"},
                      {"type":"thread.started","thread_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}):
            with self.assertRaises((ValueError,RuntimeError)):
                reviewer.parse_events(json.dumps(event), THREAD)
        with self.assertRaises(ValueError): reviewer.parse_events('{"type":"turn.started"}')

    def test_only_exact_disabled_code_mode_startup_notice_is_nonfatal(self):
        thread = {"type":"thread.started", "thread_id":THREAD}
        notice = {"type":"item.completed", "item":{"type":"error", "message":reviewer.CODE_MODE_DISABLED_NOTICE}}
        started = {"type":"turn.started"}
        finished = {"type":"turn.completed", "usage":{}}
        events = lambda values: "\n".join(map(json.dumps, values))
        self.assertEqual(reviewer.parse_events(events([thread,notice,started,finished])), (THREAD,{}))
        for values in ([thread,started,notice,finished],
                       [thread,{**notice,"item":{"type":"error","message":"authentication failed"}},finished],
                       [thread,{**notice,"type":"item.started"},finished],
                       [thread,{"type":"error","message":reviewer.CODE_MODE_DISABLED_NOTICE},finished]):
            with self.assertRaises((ValueError, RuntimeError)):
                reviewer.parse_events(events(values))

    def test_wire_queries_are_data_and_null_filters_are_removed(self):
        response = {"action":"research","draft":None,"research":[{"tool":"references","review_id":None,
            "purpose":"Inspect consumer","arguments":{"symbol":"handle","path":None,"path_prefix":"src","limit":20}}],
            "working_chain":"Follow issuer","progress":[]}
        value = protocol.envelope(response)
        self.assertNotIn("path", value["research"][0]["arguments"])
        response["draft"] = {"change_pass":[]}
        with self.assertRaises(ValueError): protocol.envelope(response)

    def test_start_resume_use_upstream_controls_without_unknown_feature_allowlist(self):
        item = launcher.Launcher.__new__(launcher.Launcher)
        item.config = self.config
        item.work, item.home = self.base / "work with spaces", self.base / "home"
        item.features = launcher.REQUIRED_FEATURES | {"new_client_feature", "browser_use"}
        options = item.options()
        for name in launcher.REQUIRED_FEATURES | {"browser_use"}:
            self.assertIn(["--disable",name], [options[i:i+2] for i in range(len(options)-1)])
        self.assertNotIn("new_client_feature", options)
        self.assertIn('default_permissions="mehscan_review"', options)
        self.assertIn('permissions.mehscan_review.network.enabled=false', options)
        self.assertIn("--ignore-user-config",options)
        self.assertIn("--ignore-rules",options)
        self.assertIn('suppress_unstable_features_warning=true', options)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", options)
        import tomllib
        filesystem = next(value for value in options if value.startswith("permissions.mehscan_review.filesystem="))
        self.assertEqual(tomllib.loads(filesystem)["permissions"]["mehscan_review"]["filesystem"][str(item.work)], "read")

    def test_process_environment_excludes_workflow_credentials_and_uses_private_home(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN":"secret", "OPENAI_API_KEY":"secret", "PYTHONPATH":"injection"}):
            env = launcher.process_environment(self.base / "home")
        self.assertFalse({"GITHUB_TOKEN", "OPENAI_API_KEY", "PYTHONPATH"} & env.keys())
        self.assertEqual(env["CODEX_HOME"],str(self.base / "home"))

    def test_provider_deadline_must_be_finite_and_bounded(self):
        for value in (0,3601,float("nan"),True):
            with self.assertRaises(ValueError): launcher.run_process(["not-executed"],timeout=value)


class ProcessIntegration(unittest.TestCase):
    setUp = Adapter.setUp
    @unittest.skipUnless(os.name == "posix", "native executable fixture uses a POSIX shebang")
    def test_actual_launcher_start_resume_auth_refresh_and_failure_without_bubblewrap(self):
        # Exercise the real subprocess path with a deterministic CLI fixture.
        # This proves adapter integration, not actual Codex or model acceptance.
        self.binary.write_text("#!" + sys.executable + "\n" + r'''import json, os, pathlib, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli 0.162.0-alpha.17.2")
elif "--help" in args:
    print("--ignore-user-config --ignore-rules --strict-config --output-schema --json")
elif args == ["features", "list"]:
    print("\n".join(["shell_tool", "multi_agent", "apps", "plugins", "hooks", "view_image", "browser_use"]))
else:
    home = pathlib.Path(os.environ["CODEX_HOME"])
    assert "GITHUB_TOKEN" not in os.environ
    assert "OPENAI_API_KEY" not in os.environ
    assert pathlib.Path.cwd().name == "work"
    required = {"shell_tool", "multi_agent", "apps", "plugins", "hooks", "view_image", "browser_use"}
    disabled = {args[i+1] for i, arg in enumerate(args[:-1]) if arg == "--disable"}
    assert required <= disabled
    assert 'permissions.mehscan_review.network.enabled=false' in args
    assert "--last" not in args
    prompt = sys.stdin.read()
    auth = json.loads((home / "auth.json").read_text())
    if "resume" in args:
        assert "12345678-1234-1234-1234-123456789abc" in args
        assert auth == {"refreshed":"private"}
        assert "new actual code" in prompt
        assert "Trusted native review contract" not in prompt
    else:
        assert auth == {"test_secret":"private-only"}
        (home / "auth.json").write_text(json.dumps({"refreshed":"private"}))
    if "fail-provider" in prompt:
        print("raw credential-bearing failure", file=sys.stderr)
        sys.exit(7)
    output = pathlib.Path(args[args.index("--output-last-message")+1])
    output.write_text(json.dumps({"action":"final","research":[],"draft":{"change_pass":[]},"working_chain":"Inspected facts.","progress":[]}))
    print(json.dumps({"type":"thread.started","thread_id":"12345678-1234-1234-1234-123456789abc"}))
    print(json.dumps({"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}}))
''')
        self.binary.chmod(0o700)
        with patch.dict(os.environ, {"GITHUB_TOKEN":"secret", "OPENAI_API_KEY":"secret"}):
            reviewer.run(self.config,self.task)
            self.task["research"]["round"] = 1
            self.facts.write_text(json.dumps({"facts":[{"result_id":"new","text":"new actual code"}]}))
            reviewer.run(self.config,self.task)
            self.task["research"]["round"] = 2
            self.facts.write_text(json.dumps({"facts":[{"result_id":"new","text":"new actual code"},{"result_id":"fail","text":"fail-provider"}]}))
            with self.assertRaises(RuntimeError): reviewer.run(self.config,self.task)
        state = json.loads((Path(self.config["private_directory"]) / self.task["conversation_id"] / "conversation.json").read_text())
        self.assertEqual(state["round"],1)
        self.assertEqual(len((self.public / "provider-metrics.jsonl").read_text().splitlines()),2)

    def test_real_process_deadline_stops_client(self):
        with self.assertRaises(TimeoutError):
            launcher.run_process([sys.executable,"-c","import time; time.sleep(30)"], timeout=0.1)


if __name__ == "__main__":
    unittest.main()
