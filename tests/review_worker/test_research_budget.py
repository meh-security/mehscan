"""Budget scheduling must preserve source, progress and recovery accounting."""
import json
from pathlib import Path
import tempfile
import unittest

import test_worker as fixture

worker = fixture.worker


def source(path="app.js"):
    return {"tool":"source", "review_id":"id",
            "arguments":{"path":path, "start_line":1, "end_line":1}}


def definition():
    return {"tool":"definition", "review_id":"id", "arguments":{"name":"guard"}}


class BudgetPlan(unittest.TestCase):
    def test_exact_fit_and_priority_order_without_splitting_a_definition(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            requests = [source(), definition(), source("last.js")]
            queries, commands, feedback = worker.research_batch_plan(requests, root, ["id"], root/"journals", 4)
            self.assertEqual(queries, requests)
            self.assertEqual(len(commands), 3)
            self.assertIsNone(feedback)
            queries, commands, feedback = worker.research_batch_plan(requests, root, ["id"], root/"journals", 2)
            self.assertEqual(queries, [requests[0], requests[2]])
            self.assertEqual([command[1] for command in commands], ["source", "source"])
            self.assertEqual(feedback["scheduled_query_indices"], [0, 2])
            self.assertEqual(feedback["reserved_query_units"], 2)
            self.assertEqual(feedback["queries_remaining"], 0)
            deferred = feedback["deferred_queries"]
            self.assertEqual([(row["query_index"], row["required_query_units"], row["executed"]) for row in deferred], [(1, 2, False)])
            self.assertEqual(deferred[0]["query"], requests[1])
            self.assertNotIn("result_id", deferred[0])
            self.assertFalse((root/"journals").exists())

    def test_zero_budget_and_an_unaffordable_first_request_provide_no_free_lookup(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            for budget, requests, expected in [(0, [source(), definition()], []),
                                                (1, [definition(), source()], [source()]),
                                                (1, [definition()], [])]:
                with self.subTest(budget=budget, requests=requests):
                    queries, commands, feedback = worker.research_batch_plan(requests, root, ["id"], root/"journals", budget)
                    self.assertEqual(queries, expected)
                    self.assertEqual(len(commands), len(expected))
                    self.assertEqual(feedback["reserved_query_units"], len(expected))
                    self.assertTrue(all(not row["executed"] for row in feedback["deferred_queries"]))
            self.assertFalse((root/"journals").exists())

    def test_invalid_later_or_unaffordable_requests_still_reject_the_entire_batch(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            for invalid in [source("../outside.js"), {**source(), "review_id":"foreign"},
                            {**source(), "arguments":{"path":"app.js", "start_line":1, "end_line":401}}]:
                for budget in (0, 1):
                    with self.subTest(invalid=invalid, budget=budget), self.assertRaises(ValueError):
                        worker.research_batch_plan([source(), definition(), invalid], root, ["id"], root/"journals", budget)
            self.assertFalse((root/"journals").exists())

    def test_recovery_retains_reserved_units_results_and_deferral_feedback(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            _, _, feedback = worker.research_batch_plan([source(), definition()], root, ["id"], root/"journals", 2)
            first, second = root/"first/jobs/job.json", root/"second/jobs/job.json"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            job = worker.JobCheckpoint(first, {"runtime":"fixture"})
            actual = {"result_id":"actual-source", "query":source(), "result":{"operation":"get_source"}}
            job.save(calls=1, queries=1, results=[actual], research_budget_feedback=feedback)
            job.fail(TimeoutError("interrupted after received source"))
            recovered = worker.JobCheckpoint(second, {"runtime":"fixture"}, first)
            self.assertEqual(recovered.state["queries"], 1)
            self.assertEqual(recovered.state["results"], [actual])
            self.assertEqual(recovered.state["research_budget_feedback"], feedback)
            queries, _, _ = worker.research_batch_plan([definition()], root, ["id"], root/"journals", 2-recovered.state["queries"])
            self.assertEqual(queries, [])  # Recovery cannot refund the received read.

    def test_reservations_use_the_bound_catalog_costs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            api = worker.context.research_api(fixture.ROOT/"skills/mehscan-security")
            next(tool for tool in api["tools"] if tool["name"] == "definition")["query_units"] = 3
            queries, _, feedback = worker.research_batch_plan([definition(), source()], root, ["id"], root/"journals", 2, api=api)
            self.assertEqual(queries, [source()])
            self.assertEqual(feedback["deferred_queries"][0]["required_query_units"], 3)
            self.assertEqual(worker.research_cost(queries, api=api), 1)


class BudgetWorker(unittest.TestCase):
    setUp = fixture.Worker.setUp
    native = fixture.Worker.native
    git = fixture.Worker.git
    invoke = fixture.Worker.invoke
    assert_no_decisions = fixture.Worker.assert_no_decisions

    def bind_small_limits(self, query_units=5):
        draft = self.native("state", "plan-template", "--inventory", str(self.inventory), "--source-root", str(self.root),
            "--policy", "comprehensive", "--skill-root", str(fixture.ROOT/"skills/mehscan-security"),
            "--research-rounds", "1", "--research-queries", str(query_units))
        plan = self.base/"small-plan.json"
        plan.write_text(json.dumps(draft), encoding="utf-8")
        parent = json.loads(self.package.read_text())["payload"]["plan_id"]
        self.native("state", "plan", *self.common, "--input", str(plan), "--expected-plan-id", parent,
                    "--operation-key", "small-budget-plan")
        self.package.write_text(json.dumps(self.native("state", "work", *self.common)), encoding="utf-8")

    def test_last_research_batch_delivers_affordable_source_and_traces_unread_definition(self):
        self.bind_small_limits()
        normal = self.base/"normal.py"
        normal.write_text(self.reviewer.read_text(), encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' id=task["review_ids"][0]\n'
            ' source={"tool":"source","review_id":id,"arguments":{"path":"app.js","start_line":1,"end_line":1}}\n'
            ' definition={"tool":"definition","review_id":id,"arguments":{"name":"never_requested"}}\n'
            ' print(json.dumps({"research":[source]*4+[definition]}))\n'
            'else:\n'
            ' feedback=task["research"]["feedback"]\n'
            ' assert task["research"]["rounds_remaining"] == 0 and task["research"]["queries_remaining"] == 1\n'
            ' assert feedback["scheduled_query_indices"] == [0,1,2,3]\n'
            ' assert feedback["deferred_queries"][0]["query_index"] == 4\n'
            ' assert feedback["deferred_queries"][0]["executed"] is False\n'
            ' assert len(task["research"]["results"]) == 4\n'
            ' assert all(r["query"]["tool"] == "source" for r in task["research"]["results"])\n'
            ' facts=json.loads(Path(task["shared_facts"]).read_text())["facts"]\n'
            ' assert len(facts) == 1 and facts[0]["query"]["tool"] == "source"\n'
            ' print(subprocess.check_output([sys.executable,'+repr(str(normal))+'],input=json.dumps(task),text=True))\n', encoding="utf-8")
        result = self.invoke(extra=["--phase", "native"])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        directory = self.base/"worker"
        record = json.loads((directory/"worker.json").read_text())
        self.assertEqual(record["status"], "admitted")
        self.assertEqual(record.get("protocol_corrections", 0), 0)
        self.assertEqual((record["research_queries"], record["research_budget_deferrals"]), (4, 1))
        job = json.loads(next((directory/"jobs").glob("*.json")).read_text())
        self.assertEqual((job["calls"], job["queries"], len(job["results"])), (2, 4, 4))
        from review_trace import summarize
        report = summarize(directory)
        flags = report["jobs"][0]["attention_flags"]
        deferred = [flag for flag in flags if flag["kind"] == "research_budget_deferral"]
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0]["deferred_queries"][0]["query"]["tool"], "definition")
        self.assertEqual(len(report["jobs"][0]["queries"]), 4)

    def test_an_unaffordable_definition_creates_no_fact_or_query_receipt(self):
        self.check_unaffordable_definition(invent_progress=False)

    def test_deferred_lookup_cannot_be_claimed_as_inspected(self):
        self.check_unaffordable_definition(invent_progress=True)

    def check_unaffordable_definition(self, *, invent_progress):
        self.bind_small_limits(query_units=1)
        normal = self.base/"normal.py"
        normal.write_text(self.reviewer.read_text(), encoding="utf-8")
        self.reviewer.write_text('import json,sys,subprocess\nfrom pathlib import Path\ntask=json.load(sys.stdin)\n'
            'if task["research"]["round"] == 0:\n'
            ' print(json.dumps({"research":[{"tool":"definition","review_id":task["review_ids"][0],"arguments":{"name":"guard"}}]}))\n'
            'else:\n'
            ' feedback=task["research"]["feedback"]\n'
            ' assert feedback["scheduled_query_indices"] == []\n'
            ' assert feedback["reserved_query_units"] == 0 and task["research"]["queries_remaining"] == 1\n'
            ' assert not task["research"]["results"]\n'
            ' assert not json.loads(Path(task["shared_facts"]).read_text())["facts"]\n'
            ' assert "fact1" not in task["research"]["artifact_handles"]\n'
            ' draft=json.loads(subprocess.check_output([sys.executable,'+repr(str(normal))+'],input=json.dumps(task),text=True))\n'
            ' if '+repr(invent_progress)+': draft={"draft":draft,"progress":[{"edge":"Deferred implementation","status":"inspected","cause":None,"artifacts":["fact1"]}]}\n'
            ' print(json.dumps(draft))\n', encoding="utf-8")
        result = self.invoke(extra=["--phase", "native"])
        directory = self.base/"worker"
        record = json.loads((directory/"worker.json").read_text())
        job = json.loads(next((directory/"jobs").glob("*.json")).read_text())
        self.assertEqual((job["calls"], job["queries"], len(job["results"])), (2, 0, 0))
        self.assertEqual(record.get("protocol_corrections", 0), 0)
        self.assertEqual(record["research_budget_deferrals"], 1)
        self.assertFalse((directory/"research.jsonl").exists())
        if invent_progress:
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(record["status"], "incomplete")
            self.assertEqual(list((directory/"decisions").glob("*.json")), [])
        else:
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(record["status"], "admitted")
