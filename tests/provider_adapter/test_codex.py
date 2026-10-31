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
import boundary_review

THREAD = "12345678-1234-1234-1234-123456789abc"


class Adapter(unittest.TestCase):
    def stable_factory(self, config, session):
        fake = self.factory(config, session)
        original = fake.review
        def review(*args, **kwargs):
            response, events, stderr = original(*args, **kwargs)
            response["routing"] = []
            if getattr(self, "invalid_stable_handle", False):
                response["progress"] = [{"edge":"Inspected", "status":"inspected",
                                         "cause":None, "artifacts":["invented"]}]
            return response, events, stderr
        fake.review = review
        return fake

    def test_stable_wire_schema_survives_new_handles_and_final_only_budget(self):
        self.config["schema_mode"] = "stable"
        reviewer.run(self.config, self.task, self.stable_factory)
        self.task["research"].update(round=1, rounds_remaining=0, queries_remaining=0,
                                     artifact_handles={"new":"actual"})
        reviewer.run(self.config, self.task, self.stable_factory)
        self.assertEqual(self.calls[0][2], self.calls[1][2])
        self.assertEqual([c[1] for c in self.calls], [None, THREAD])
        receipts = [json.loads(l) for l in (self.public / "provider-metrics.jsonl").read_text().splitlines()]
        self.assertEqual([r["usage"]["input_tokens"] for r in receipts], [100,100])

    def test_stable_invalid_handle_keeps_paid_usage_and_continuation_before_rejection(self):
        self.config["schema_mode"] = "stable"
        self.invalid_stable_handle = True
        with self.assertRaisesRegex(ValueError, "current-turn schema"):
            reviewer.run(self.config, self.task, self.stable_factory)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue((self.public / "provider-metrics.jsonl").exists())
        state = json.loads((Path(self.config["private_directory"]) / ("a"*64) / "conversation.json").read_text())
        self.assertEqual(state["round"], 0)
        diagnostic = json.loads(next(self.public.glob("schema-validation-*.jsonl")).read_text())
        self.assertFalse(diagnostic["valid"])
        self.assertEqual(len(list(self.public.glob("provider-metrics*.jsonl"))), 1)
        reply = Path(self.config["private_directory"]) / ("a"*64) / "round-0/response.json"
        self.assertTrue(reply.is_file())
        self.assertEqual(json.loads(reply.read_text())["action"], "final")
        self.assertEqual(json.loads(reply.read_text())["progress"][0]["artifacts"], ["invented"])
        self.assertFalse(list(self.public.rglob("response.json")))

    def test_stable_missing_dependency_and_mid_conversation_switch_fail_before_provider(self):
        self.config["schema_mode"] = "stable"
        with patch.dict(sys.modules, {"jsonschema":None}), self.assertRaisesRegex(ValueError, "requirements.txt"):
            reviewer.run(self.config, self.task, self.stable_factory)
        self.assertFalse(self.calls)
        self.config.pop("schema_mode")
        self.invoke()
        self.config["schema_mode"] = "stable"
        self.task["research"]["round"] = 1
        with self.assertRaisesRegex(ValueError, "incompatible"):
            reviewer.run(self.config, self.task, self.stable_factory)
        self.assertEqual(len(self.calls), 1)

    def test_bound_proof_correction_resumes_same_thread_and_preserves_reply(self):
        self.config["schema_mode"] = "stable"
        self.task["research"]["artifact_handles"] = {"source1":"actual-source"}
        def factory(config,session):
            fake = self.stable_factory(config,session); original = fake.review
            def review(*args,**kwargs):
                response,events,stderr = original(*args,**kwargs)
                response["progress"] = [{"edge":"Inspected", "status":"inspected", "cause":None,
                                         "artifacts":["source1" if kwargs.get("thread_id") or len(self.calls)>1 else "invented"]}]
                return response,events,stderr
            fake.review = review
            return fake
        with self.assertRaisesRegex(ValueError,"current-turn schema"):
            reviewer.run(self.config,self.task,factory)
        diagnostic = json.loads(next(self.public.glob("reply-validation-*.json")).read_text())
        self.assertTrue(diagnostic["repairable_proof_references"])
        self.task["research"].update(round=1,feedback={"kind":"local_response_validation"})
        value = reviewer.run(self.config,self.task,factory)
        self.assertEqual(value["progress"][0]["artifacts"],["source1"])
        self.assertEqual([c[1] for c in self.calls],[None,THREAD])
        receipts = [json.loads(l) for l in (self.public / "provider-metrics.jsonl").read_text().splitlines()]
        self.assertEqual(sum(r["usage"]["input_tokens"] for r in receipts),200)
        state = json.loads((Path(self.config["private_directory"]) / ("a"*64) / "conversation.json").read_text())
        self.assertNotIn("rejected_intent_sha256",state)

    def test_proof_correction_cannot_drop_references_or_change_review_intent(self):
        original = {"progress":[{"artifacts":["invented","source1"]}], "draft":{"results":[{"decision":"issue"}]}}
        task = {"research":{"artifact_handles":{"source1":"actual"},"source_artifact_handles":["source1"]}}
        corrected = copy.deepcopy(original);corrected["progress"][0]["artifacts"][0] = "source1"
        self.assertTrue(reviewer.proof_correction_matches(original,corrected,task))
        corrected["progress"][0]["artifacts"].pop()
        self.assertFalse(reviewer.proof_correction_matches(original,corrected,task))
        corrected = copy.deepcopy(original);corrected["draft"]["results"][0]["decision"] = "not_issue"
        self.assertNotEqual(reviewer.review_intent(original),reviewer.review_intent(corrected))

    def test_rejected_correction_retains_paid_reply_usage_and_protected_intent(self):
        self.config['schema_mode']='stable'
        self.task['research']['artifact_handles']={'source1':'actual'}
        for index,change in enumerate(('intent','strip','unbound'),2):
            with self.subTest(change=change):
                task=copy.deepcopy(self.task);task['conversation_id']=str(index)*64
                def factory(config,session):
                    fake=self.stable_factory(config,session);original=fake.review
                    def review(*args,**kwargs):
                        response,events,stderr=original(*args,**kwargs)
                        correction=task['research']['round']>0
                        response['progress']=[{'edge':'Inspected','status':'inspected','cause':None,
                                               'artifacts':['source1' if correction else 'invented']}]
                        if correction and change=='intent':response['working_chain']='Changed review conclusion.'
                        if correction and change=='strip':response['progress'][0]['artifacts']=[]
                        return response,events,stderr
                    fake.review=review;return fake
                with self.assertRaisesRegex(ValueError,'current-turn schema'):reviewer.run(self.config,task,factory)
                task['research']['round']=1
                if change!='unbound':task['research']['feedback']={'kind':'local_response_validation'}
                with self.assertRaisesRegex(ValueError,'protected review intent|explicit bound correction'):
                    reviewer.run(self.config,task,factory)
                private=Path(self.config['private_directory'])/task['conversation_id']
                state=json.loads((private/'conversation.json').read_text())
                self.assertIn('rejected_intent_sha256',state)
                self.assertEqual(state['round'],0 if change=='unbound' else 1)
                self.assertEqual((private/'round-1/response.json').exists(),change!='unbound')
                rows=[json.loads(l) for l in (self.public/'provider-metrics.jsonl').read_text().splitlines()]
                matching=[r for r in rows if r['conversation_id']==task['conversation_id']]
                self.assertEqual(len(matching),1 if change=='unbound' else 2)

    def test_failed_launcher_diagnostics_are_preserved_without_fabricating_usage(self):
        class Failed:
            def review(*args, **kwargs):
                raise launcher.ProviderExecutionError(2, '{"type":"error"}', "private diagnostics")
        with self.assertRaises(launcher.ProviderExecutionError):
            reviewer.run(self.config, self.task, lambda *args:Failed())
        log = Path(self.config["private_directory"]) / ("a"*64) / "round-0"
        self.assertEqual((log / "stderr.txt").read_text(), "private diagnostics")
        self.assertTrue((log / "events.jsonl").exists())
        self.assertFalse((self.public / "provider-metrics.jsonl").exists())

    def test_generic_review_scope_covers_roles_without_repeating_on_resume(self):
        for role in ("investigator", "research", "collection"):
            with self.subTest(role=role):
                task = {**self.task, "review_role": role}
                prompt = protocol.build_prompt(task, self.body, [], None)
                self.assertTrue(prompt.startswith(protocol.REVIEW_SCOPE))
                self.assertEqual(prompt.count(protocol.REVIEW_SCOPE), 1)
                for source in self.body["contract"]["sources"]:
                    self.assertIn(source["text"], prompt)
                continued = protocol.build_prompt(task, self.body, [],
                                                  {"sent_facts": [], "sent_results": 0})
                self.assertNotIn(protocol.REVIEW_SCOPE, continued)
        self.assertNotIn("Juice", protocol.REVIEW_SCOPE)

    def test_diagnosis_cwe_schema_matches_native_identifier_syntax_and_count(self):
        import re
        self.task.update(kind="native_bundle",review_ids=["one"])
        schema=protocol.build_schema(self.task)
        draft=schema["properties"]["draft"]["anyOf"][0]
        cwes=draft["properties"]["results"]["items"]["properties"]["diagnosis"]["anyOf"][0]["properties"]["cwes"]
        self.assertEqual(cwes["maxItems"],5)
        pattern=cwes["items"]["pattern"]
        for value in ("CWE-1","CWE-94","CWE-999999"):
            self.assertIsNotNone(re.fullmatch(pattern,value))
        for value in ("CWE- mass-assignment","CWE-0","CWE-01","CWE-1234567","CWE-94\n"):
            self.assertIsNone(re.fullmatch(pattern,value))

    def test_on_demand_guidance_has_typed_names_and_is_not_presented_as_source(self):
        schema = protocol.build_schema(self.task)
        variant = next(v for v in schema["properties"]["research"]["items"]["anyOf"]
                       if v["properties"]["tool"]["enum"] == ["guidance"])
        names = variant["properties"]["arguments"]["properties"]["name"]["enum"]
        self.assertIn("mass-assignment", names)
        self.assertNotIn("../../source/AGENTS.md", names)
        facts = [{"result_id":"guide1", "result":{"operation":"review_guidance", "name":"mass-assignment",
                  "text":"Inspect sensitive writable fields and actual persistence."}}]
        prompt = protocol.build_prompt(self.task, self.body, facts, None)
        before, after = prompt.split("Additional trusted skill guidance", 1)
        self.assertNotIn("Inspect sensitive writable fields", before)
        self.assertIn("Inspect sensitive writable fields", after)
        self.assertNotIn("guide1", self.task["research"]["artifact_handles"])

    def test_export_navigation_schema_uses_exact_arguments_and_deciding_question(self):
        import re
        schema = protocol.build_schema(self.task)
        variants = schema["properties"]["research"]["items"]["anyOf"]
        for tool, keys in (("import-targets", {"path"}), ("export-target", {"path", "name"})):
            variant = next(v for v in variants if v["properties"]["tool"]["enum"] == [tool])
            self.assertIn("purpose", variant["required"])
            self.assertEqual(variant["properties"]["purpose"],{"type":"string","minLength":1,"maxLength":300})
            arguments = variant["properties"]["arguments"]
            self.assertEqual(set(arguments["properties"]), keys)
            self.assertEqual(set(arguments["required"]), keys)
        pattern = variant["properties"]["arguments"]["properties"]["name"]["pattern"]
        for name in ("guard", "default", "$guard", "_guard2"):
            self.assertIsNotNone(re.fullmatch(pattern, name))
        for name in ("guard.call", "guard()", "../guard", "guard\n", "1guard"):
            self.assertIsNone(re.fullmatch(pattern, name))

    def boundary_task(self):
        self.body["native_questions"] = [{"review_id":"one","capability":"authorization"}]
        self.packet.write_text(json.dumps(self.body))
        self.task.update(kind="native_bundle",review_ids=["one"])
        self.task["research"].update(artifact_handles={"source1":"actual-source-id","locator":"navigation-id"},
            source_artifact_handles=["source1"])
        return {"action":"final","research":[],"draft":{"results":[{"review_id":"one",
            "decision":"not_issue","source_leads":[]}]},"working_chain":"The selected control applies.","progress":[],
            "boundary_checks":[{"review_id":"one","effect":"Delete the selected record",
                "requirement":"Actor owns that record","example":"A different actor fails the shown owner check",
                "observation":"Rejection precedes deletion","status":"enforced","cause":None,
                "artifacts":["source1"],"controls":[{"condition":"Owner matches actor",
                    "failure_enforcement":"Throws before deletion","boundary_result":"Other owner rejected",
                    "artifacts":["source1"]}],"value_bindings":[]}]}

    def test_boundary_review_uses_bound_sources_without_rewriting_the_selected_verdict(self):
        response = self.boundary_task()
        native_draft = copy.deepcopy(response["draft"])
        factory = self.factory
        def provider(config, session):
            client = factory(config, session)
            original = client.review
            def review(*args, **kwargs):
                _, events, stderr = original(*args, **kwargs)
                return response, events, stderr
            client.review = review
            return client
        result = reviewer.run(self.config,self.task,provider)
        self.assertEqual(result["draft"],native_draft)
        self.assertNotIn("boundary_checks",result)
        observation = json.loads(next(self.public.glob("boundary-checks-*.json")).read_text())
        self.assertEqual(observation["source_artifacts"],{"source1":"actual-source-id"})
        self.assertEqual(observation["interpretation"],"unvalidated_reviewer_observation")
        initial = protocol.build_schema(self.task,bound_handles=False)
        later = copy.deepcopy(self.task)
        later["research"].update(rounds_remaining=0,queries_remaining=0,
            artifact_handles={"source1":"actual-source-id","source2":"second"},source_artifact_handles=["source1","source2"])
        self.assertEqual(initial,protocol.build_schema(later,bound_handles=False))
        schema = protocol.build_schema(later)
        self.assertEqual(schema["properties"]["action"]["enum"],["final"])
        self.assertEqual(schema["properties"]["boundary_checks"]["minItems"],1)
        self.assertEqual(protocol.build_schema(self.task)["properties"]["boundary_checks"]["minItems"],0)
        self.assertEqual(schema["properties"]["boundary_checks"]["items"]["properties"]["artifacts"]["items"]["enum"],
            ["source1","source2"])

    def test_boundary_review_rejects_duplicate_ids_and_locator_citations_in_nested_tables(self):
        response = self.boundary_task()
        response["boundary_checks"][0]["controls"][0]["artifacts"] = ["locator"]
        with self.assertRaisesRegex(ValueError,"uninspected"):
            boundary_review.review_envelope(response,self.task,self.body,protocol.envelope)
        response = self.boundary_task()
        response["boundary_checks"] *= 2
        with self.assertRaisesRegex(ValueError,"exactly once"):
            boundary_review.review_envelope(response,self.task,self.body,protocol.envelope)
        self.assertEqual(list(self.public.glob("boundary-checks-*.json")),[])

    def test_boundary_research_omits_tables_but_early_final_still_requires_complete_checks(self):
        response = self.boundary_task()
        final = copy.deepcopy(response)
        query = {"tool":"source", "review_id":"one", "purpose":"Read the deciding control",
                 "arguments":{"path":"app.ts", "start_line":1, "end_line":20}}
        response.update(action="research", research=[query], draft=None, boundary_checks=[])
        out = boundary_review.review_envelope(response,self.task,self.body,protocol.envelope)
        self.assertEqual(out["research"],[query])
        self.assertNotIn("boundary_checks",out)
        self.assertEqual(list(self.public.glob("boundary-checks-*.json")),[])
        response["boundary_checks"] = final["boundary_checks"]
        with self.assertRaisesRegex(ValueError,"only to the final"):
            boundary_review.review_envelope(response,self.task,self.body,protocol.envelope)
        final["boundary_checks"] = []
        with self.assertRaisesRegex(ValueError,"exactly once"):
            boundary_review.review_envelope(final,self.task,self.body,protocol.envelope)

    def test_direct_schema_disables_routing_without_disabling_research_or_decisions(self):
        task = {**self.task, "kind":"native_bundle", "review_ids":["one"]}
        direct = protocol.build_schema(task)
        self.assertEqual(direct["properties"]["routing"]["maxItems"], 0)
        self.assertEqual(direct["properties"]["action"]["enum"], ["research", "final"])
        self.assertNotIn("dependency", direct["properties"])
        tiered = protocol.build_schema({**task, "routing_allowed":True})
        self.assertNotIn("maxItems", tiered["properties"]["routing"])
        self.assertEqual(tiered["properties"]["routing"]["items"]["properties"]["review_id"]["enum"], ["one"])

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
                    "usage":{"input_tokens":100*total,"cached_input_tokens":60*total,"output_tokens":20*total,
                             "cache_write_input_tokens":7*total,"reasoning_output_tokens":5*total}}]
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
        self.assertEqual(json.loads(metrics.splitlines()[1])["usage"]["cache_write_tokens"], 7)
        self.assertEqual(json.loads(metrics.splitlines()[1])["usage"]["reasoning_output_tokens"], 5)
        self.assertEqual(json.loads(metrics.splitlines()[1])["usage"]["output_tokens"], 20)
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
        self.assertEqual(properties["summary"], {"type":"string","minLength":1,"maxLength":500})
        self.assertEqual(properties["checks"]["maxItems"],5)
        self.assertEqual(properties["checks"]["items"]["maxLength"],300)
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

    def test_native_lookup_domains_are_present_in_actual_wire_schema(self):
        variants = protocol.build_schema(self.task)["properties"]["research"]["items"]["anyOf"]
        for variant in variants:
            arguments = variant["properties"]["arguments"]["properties"]
            for name in ("start_line", "end_line", "limit"):
                if name in arguments:
                    self.assertEqual(arguments[name]["minimum"], 1)
            if "limit" in arguments:
                self.assertEqual(arguments["limit"]["maximum"], 100)
            for name in ("name", "symbol"):
                if name in arguments:
                    self.assertEqual(arguments[name]["minLength"], 1)
                    self.assertEqual(arguments[name]["maxLength"], 200)

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

    def test_optional_usage_counters_are_not_invented_for_old_events_or_continuations(self):
        events = [json.dumps({"type":"thread.started","thread_id":THREAD}),
                  json.dumps({"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}})]
        _, usage = reviewer.parse_events("\n".join(events))
        self.assertNotIn("cache_write_tokens",usage)
        self.assertNotIn("reasoning_output_tokens",usage)
        delta, unknown = reviewer.usage_delta({**usage,"cache_write_tokens":7,"reasoning_output_tokens":5},usage,True)
        self.assertEqual(delta,{"input_tokens":0,"output_tokens":0})
        self.assertEqual(set(unknown),{"cache_write_tokens","reasoning_output_tokens"})

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
        path.write_text(json.dumps({**self.config,"schema_mode":"stable"}))
        self.assertEqual(launcher.load_config(path)["schema_mode"], "stable")
        path.write_text(json.dumps({**self.config,"schema_mode":"invalid"}))
        with self.assertRaises(ValueError): launcher.load_config(path)
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
        instructions = next(value for value in options if value.startswith("model_instructions_file="))
        self.assertEqual(Path(tomllib.loads(instructions)["model_instructions_file"]), launcher.REVIEWER_INSTRUCTIONS)
        self.assertTrue(launcher.REVIEWER_INSTRUCTIONS.is_file())

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
