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
    def test_distinct_source_leads_survive_wire_without_changing_selected_verdict(self):
        task = {**self.task, "kind":"native_bundle", "review_ids":["one"]}
        schema = protocol.build_schema(task)
        item = schema["properties"]["draft"]["anyOf"][0]["properties"]["results"]["items"]
        self.assertEqual(item["properties"]["source_leads"]["maxItems"], 3)
        lead = {"question":"Can delivery skip rejection?", "security_relevance":"External delivery.",
                "distinct_from_review":"Separate from signing.",
                "evidence":{"path":"app.ts","start_line":7,"end_line":9}}
        draft = {"results":[{"review_id":"one","decision":"not_issue","source_leads":[lead]}]}
        out = protocol.envelope({"action":"final","research":[],"draft":draft,
                                 "working_chain":"Signing checked.","progress":[]})
        self.assertEqual(out["draft"], draft)

    def test_collection_protocol_has_no_verdict_and_only_inspected_source_handles(self):
        task = {**self.task,"kind":"native_bundle","review_ids":["one"],"review_role":"collection"}
        task["research"] = {**task["research"],"source_artifact_handles":["source1"],"rounds_remaining":0}
        schema = protocol.build_schema(task)
        self.assertEqual(schema["properties"]["action"]["enum"],["collection"])
        self.assertNotIn("draft",schema["properties"])
        self.assertNotIn("knowledge",schema["properties"])
        self.assertEqual(schema["properties"]["collection"]["properties"]["artifacts"]["items"]["enum"],["source1"])
        note = {"summary":"Retrieved implementation.","remaining":"Caller binding unread.",
            "status":"incomplete","artifacts":["source1"]}
        self.assertEqual(protocol.envelope({"action":"collection","research":[],"collection":note}),{"collection":note})
        with self.assertRaises(ValueError):
            protocol.envelope({"action":"collection","research":[{}],"collection":note})

    def test_decision_focus_retains_selected_caller_when_shared_source_has_an_unsafe_neighbor(self):
        packet = {"native_questions":[{"review_id":"safe-id","path":"app.ts","line":5},
                                       {"review_id":"other-file","path":"missing.ts","line":5}],
            "primary":{"windows":[{"path":"app.ts","start_line":4,
                "text":"middleware();\napp.delete('/safe', safe);\napp.delete('/unsafe', unsafe);"}]}}
        targets = protocol.decision_targets(packet)
        self.assertEqual(targets[0]["selected_source_line"], "app.delete('/safe', safe);")
        self.assertNotIn("selected_source_line",targets[1])

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

    def test_rejected_envelope_keeps_usage_and_resume_deltas_without_admitting_draft(self):
        with patch.object(reviewer, "envelope", side_effect=ValueError("invalid reply")):
            with self.assertRaisesRegex(ValueError, "invalid reply"):
                self.invoke()
        rows = [json.loads(line) for line in (self.public / "provider-metrics.jsonl").read_text().splitlines()]
        self.assertEqual(rows[0]["usage"]["input_tokens"], 100)
        self.task["research"]["round"] = 1
        self.invoke()
        rows = [json.loads(line) for line in (self.public / "provider-metrics.jsonl").read_text().splitlines()]
        self.assertEqual([r["usage"]["input_tokens"] for r in rows], [100, 100])
        self.assertEqual(self.calls[1][1], THREAD)

    def test_quality_roles_require_explicit_policy_and_resolution_wire_contract(self):
        primary = launcher.provider_contract(self.config)
        self.config["model"] = "gpt-6-sol"
        expert = launcher.provider_contract(self.config)
        self.body["work"]["runtime"].update(provider=primary, orchestration={"expert":expert})
        self.task.update(kind="native_bundle", review_ids=["id"], adjudicate_ids=["id"], profile="expert", review_role="adjudication")
        self.body["job_binding"] = {"profile":"expert", "role":"adjudication", "provider":expert}
        self.packet.write_text(json.dumps(self.body))
        with self.assertRaisesRegex(ValueError, "not enabled"):
            self.invoke()
        self.assertEqual(self.calls, [])
        schema = protocol.build_schema(self.task)
        self.assertIn("resolutions", schema["required"])
        self.assertEqual(schema["properties"]["resolutions"]["items"]["properties"]["review_id"]["enum"], ["id"])
        resolutions = [{"review_id":"id", "disputed_claim":"Actual guard?", "reason":"The supplied source contains the effective check."}]
        output = protocol.envelope({"action":"final", "research":[], "draft":{"results":[]}, "working_chain":"", "progress":[], "resolutions":resolutions})
        self.assertEqual(output["resolutions"], resolutions)
        self.task["review_role"] = "final_qa"
        self.assertNotIn("resolutions", protocol.build_schema(self.task)["properties"])

    def test_native_routing_ids_do_not_constrain_prose_paths_or_queries(self):
        self.task.update(kind="native_bundle", review_ids=["review-a", "review-b"])
        schema = protocol.build_schema(self.task)
        # Enumerations belong to identity/status fields. A shared string schema
        # must not make actual paths and reasoning accept only review IDs.
        def visit(value, path=()):
            if isinstance(value, dict):
                if value.get("enum") == self.task["review_ids"]:
                    self.assertEqual(path[-1], "review_id", path)
                for key, child in value.items():
                    visit(child, (*path, key))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, (*path, index))
        visit(schema)
        properties = schema["properties"]["draft"]["anyOf"][0]["properties"]["results"]["items"]["properties"]
        self.assertEqual(properties["summary"], {"type":"string"})
        self.assertEqual(properties["evidence"]["items"]["properties"]["path"], {"type":"string"})
        self.assertEqual(schema["properties"]["routing"]["items"]["properties"]["review_id"]["enum"], self.task["review_ids"])

    def test_pending_blocker_question_is_retained_without_inventing_checks(self):
        draft = {"results":[
            {"decision":"needs_review", "checks":[], "blockers":["Inspect the effective guard."]},
            {"decision":"needs_review", "checks":["Read the caller."], "blockers":["Caller scope unresolved."]},
            {"decision":"needs_review", "checks":[], "blockers":[]},
            {"decision":"not_issue", "checks":[], "blockers":[]}]}
        value = protocol.envelope({"action":"final", "research":[], "draft":draft, "working_chain":"", "progress":[]})
        self.assertEqual([r["checks"] for r in value["draft"]["results"]],
                         [["Inspect the effective guard."], ["Read the caller."], [], []])

    def test_dependency_and_knowledge_have_separate_wire_actions_and_source_handles(self):
        task = {**self.task,"kind":"native_bundle","review_ids":["one"],"dependency_allowed":True}
        task["research"] = {**task["research"],"artifact_handles":{"source1":"proof","fact1":"navigation"},
            "source_artifact_handles":["source1"],"rounds_remaining":0}
        schema = protocol.build_schema(task)
        self.assertEqual(schema["properties"]["action"]["enum"],["final","dependency"])
        self.assertEqual(schema["properties"]["dependency"]["anyOf"][0]["properties"]["artifacts"]["items"]["enum"],["source1"])
        self.assertEqual(schema["properties"]["dependency"]["anyOf"][0]["properties"]["reuse_id"], {"type":"null"})
        stable = protocol.build_schema(task, bound_handles=False)
        task["research"]["dependency_catalog"] = [{"dependency_id":"a"*64,"status":"waiting",
            "question":"Guard implementation?","scope":"Not caller applicability."}]
        offered = protocol.build_schema(task)["properties"]["dependency"]["anyOf"][0]["properties"]["reuse_id"]
        self.assertEqual(offered["anyOf"][0]["enum"],["a"*64])
        self.assertEqual(stable, protocol.build_schema(task, bound_handles=False))
        request = {"question":"What does this guard establish?","scope":"This receiver only.","artifacts":["source1"]}
        self.assertEqual(protocol.envelope({"action":"dependency","research":[],"draft":None,"dependency":request}),{"dependency":request})
        task.update(review_role="research",profile="expert",dependency_allowed=False)
        schema = protocol.build_schema(task)
        self.assertEqual(schema["properties"]["action"]["enum"],["knowledge"])
        self.assertNotIn("draft",schema["properties"])
        self.assertEqual(schema["properties"]["knowledge"]["properties"]["artifacts"]["items"]["enum"],["source1"])
        note = {"claim":"Rejects missing membership.","conditions":"Caller supplies subject tenant.",
            "limits":"Tenant selection is not established.","status":"established","artifacts":["source1"]}
        self.assertEqual(protocol.envelope({"action":"knowledge","research":[],"knowledge":note}),{"knowledge":note})
        with self.assertRaises(ValueError):
            protocol.envelope({"action":"knowledge","research":[{}],"knowledge":note})

    def test_exhausted_research_is_final_only_without_changing_continuation_binding(self):
        self.task.update(kind="native_bundle", review_ids=["review-a"])
        stable = protocol.build_schema(self.task, bound_handles=False)
        self.assertEqual(protocol.build_schema(self.task)["properties"]["action"]["enum"], ["research", "final"])
        for key in ("rounds_remaining", "queries_remaining", "bytes_remaining"):
            with self.subTest(key=key):
                task = copy.deepcopy(self.task)
                task["research"][key] = 0
                schema = protocol.build_schema(task)
                self.assertEqual(schema["properties"]["action"]["enum"], ["final"])
                self.assertEqual(schema["properties"]["research"]["maxItems"], 0)
                self.assertIn("results", schema["properties"]["draft"]["properties"])
                variants = schema["properties"]["progress"]["items"]["anyOf"]
                self.assertEqual([v["properties"]["status"]["enum"] for v in variants], [["blocked"]])
                self.assertNotIn(None, variants[0]["properties"]["cause"]["enum"])
                self.assertEqual(protocol.build_schema(task, bound_handles=False), stable)
        self.task["research"].update(rounds_remaining=0, artifact_handles={"source1":"source-hash"})
        inspected = protocol.build_schema(self.task)["properties"]["progress"]["items"]["anyOf"][1]["properties"]
        self.assertEqual(inspected["cause"], {"type":"null"})
        self.assertEqual(inspected["artifacts"]["minItems"], 1)
        self.assertEqual(inspected["artifacts"]["items"]["enum"], ["source1"])

    def test_definition_is_not_offered_when_its_two_query_reservations_do_not_fit(self):
        self.task["research"]["queries_remaining"] = 1
        def tools(schema):
            return [v["properties"]["tool"]["enum"][0] for v in schema["properties"]["research"]["items"]["anyOf"]]
        self.assertNotIn("definition", tools(protocol.build_schema(self.task)))
        self.assertIn("source", tools(protocol.build_schema(self.task)))
        self.assertEqual(protocol.build_schema(self.task)["properties"]["research"]["maxItems"], 1)
        self.assertIn("definition", tools(protocol.build_schema(self.task, bound_handles=False)))

    def test_native_lookup_numeric_domains_are_present_in_actual_wire_schema(self):
        variants = protocol.build_schema(self.task)["properties"]["research"]["items"]["anyOf"]
        for variant in variants:
            arguments = variant["properties"]["arguments"]["properties"]
            for name in ("start_line", "end_line", "limit"):
                if name in arguments:
                    self.assertEqual(arguments[name]["minimum"], 1)
            if "limit" in arguments:
                self.assertEqual(arguments["limit"]["maximum"], 100)

    def test_qa_intent_survives_the_wire_even_with_the_same_verdict(self):
        self.task.update(kind="native_bundle",review_role="final_qa",review_ids=["id"])
        schema = protocol.build_schema(self.task)
        self.assertIn("qa_actions",schema["required"])
        actions = [{"review_id":"id","action":"repair","claim":"Verify the narrower reaching condition."}]
        out = protocol.envelope({"action":"final","draft":{"results":[]},"research":[],"working_chain":"","progress":[],"qa_actions":actions})
        self.assertEqual(out["qa_actions"],actions)

    def test_expert_job_uses_only_its_bound_profile_and_role(self):
        primary = launcher.provider_contract(self.config)
        self.config["model"] = "gpt-6-sol"
        expert = launcher.provider_contract(self.config)
        self.body["work"]["runtime"].update(provider=primary, orchestration={"expert":expert})
        self.body["job_binding"] = {"profile":"expert", "role":"verification", "provider":expert}
        self.packet.write_text(json.dumps(self.body))
        self.task.update(profile="expert", review_role="verification")
        self.invoke()
        self.assertEqual(len(self.calls), 1)
        self.task["profile"] = "routine"
        with self.assertRaisesRegex(ValueError, "native work binding"):
            self.invoke()
        self.task["profile"] = "expert"
        self.task["review_role"] = "investigator"
        with self.assertRaisesRegex(ValueError, "job provider/role"):
            self.invoke()
        self.assertEqual(len(self.calls), 1)

    def test_progress_handles_are_exhaustive_in_schema_and_each_prompt(self):
        self.task["research"]["artifact_handles"] = {"sweep":"bound-sweep"}
        self.task["research"]["evidence_agenda"] = {"declaration_query_gaps":[{"path":"policy.ts","start_line":164,"end_line":175}]}
        self.invoke()
        prompt, _, schema = self.calls[-1]
        self.assertIn('Available artifact handles (exhaustive for this turn):\n["sweep"]', prompt)
        artifacts = schema["properties"]["progress"]["items"]["properties"]["artifacts"]
        self.assertEqual(artifacts["items"]["enum"], ["sweep"])
        self.assertNotIn("source1", artifacts["items"]["enum"])
        self.assertIn('"start_line": 164', prompt)
        self.task["research"]["round"] = 1
        self.task["research"]["artifact_handles"]["fact1"] = "bound-fact"
        self.invoke()
        self.assertIn('"start_line": 164', self.calls[-1][0])  # Agenda survives provider continuation.
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
