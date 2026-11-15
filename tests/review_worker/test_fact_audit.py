"""Bounded selection and source-grounded challenges, never automatic verdict flips."""
import copy
import unittest

import test_case_state
import review_fact_audit as audits


class Selection(unittest.TestCase):
    def setUp(self):
        fact = dict(id="guard", question="Does the guard return before the write?", route="source_fact",
            task_kind="bounded_proposition", usefulness="Prepares the owner check.", scope="Shown body.",
            acceptance="Cite the branch and write.", routing_pattern="guard-return")
        self.registry = {"cases":[{"id":name, "priority":{"impact":impact},
            "checks":[copy.deepcopy(fact), {"id":"security", "question":"Is the actor authorized?"}]}
            for name, impact in (("first", "high"), ("second", "medium"), ("third", "low"))]}
        self.policy = dict(schema_version=audits.VERSION, max_audits=1, seed="fixed", sample_percent=100)

    def test_explicit_gap_precedes_sampling_and_limit_is_visible(self):
        self.policy["checks"] = [{"case_id":"third", "check_id":"guard", "reason":"Check the early return omitted from the answer."}]
        result = audits.plan(self.policy, self.registry)
        self.assertEqual([(r["case_id"], r["check_id"]) for r in result["selected"]], [("third", "guard")])
        self.assertEqual(len(result["outside_limit"]), 2)
        self.assertTrue(result["selected"][0]["reasons"][0].startswith("Explicit:"))
        self.assertEqual(result, audits.plan(self.policy, self.registry))

    def test_no_implicit_sampling_or_consequence_default(self):
        self.policy.pop("sample_percent")
        self.assertEqual(audits.plan(self.policy, self.registry)["selected"], [])
        self.policy["impacts"] = ["high"]
        self.assertEqual([r["case_id"] for r in audits.plan(self.policy, self.registry)["selected"]], ["first"])

    def test_sampler_is_reproducible_per_case_and_not_confidence(self):
        self.policy.update(max_audits=10, sample_percent=50)
        one = audits.plan(self.policy, self.registry)
        self.registry["cases"].reverse()
        two = audits.plan(self.policy, self.registry)
        self.assertEqual({r["case_id"] for r in one["selected"]}, {r["case_id"] for r in two["selected"]})

    def test_foreign_security_or_duplicate_selection_is_rejected(self):
        for specs in ([{"case_id":"first", "check_id":"security", "reason":"A security decision."}],
                      [{"case_id":"foreign", "check_id":"guard", "reason":"Outside target."}],
                      [{"case_id":"first", "check_id":"guard", "reason":"Repeated."}]*2):
            with self.subTest(specs=specs), self.assertRaises(ValueError):
                audits.plan({**self.policy, "checks":specs}, self.registry)

    def test_missing_audit_usage_stays_unknown_instead_of_zero_cost(self):
        records=[dict(conversation_id='audit',calls=1,unknown_provider_calls=0,provider={'model':'owner'})]
        metrics=[dict(conversation_id='audit',usage=dict(input_tokens=100,output_tokens=10),
                      unknown_delta_counters=['cached_input_tokens'])]
        row=audits.with_usage(records,metrics,{'cost':{'provider_rates':{'owner':dict(
            input_per_million='1',cached_input_per_million='0.1',output_per_million='2')}}})[0]
        self.assertFalse(row['usage_complete'])
        self.assertIsNone(row['estimated_cost_micros'])
        self.assertEqual(row['usage']['input_tokens'],100)


class AuditState(unittest.TestCase):
    setUp = test_case_state.Cases.setUp
    write = test_case_state.Cases.write
    question = test_case_state.Cases.question
    finish = test_case_state.Cases.finish
    def audit(self, target, status="violated", name="audit", **updates):
        value = dict(status="complete", proofs=[self.proof], review_role="fact_auditor", fact_audit=target,
            question_provider={"model":"owner-model"}, question_conversation_id="audit-session",
            calls=1, queries=0, bytes=0, unknown_provider_calls=0, seconds=0.1,
            draft=dict(results=[], proposals=[], coverage=[], work_checks=[dict(check_id="fact", status=status,
                summary="The conditional early return is a counterexample.", evidence=[{k:self.proof[k] for k in ("path", "start_line", "end_line")}],
                next_deciding_fact="Bind the helper." if status=="unresolved" else None)]))
        value.update(updates)
        path = self.write(name, value)
        return self.store.record_audit("native", "fact", target, path,
            {"reasons":["Explicit omitted branch."], "routing_pattern":"guard-return", "suspend_pattern":True}, {"model":"owner-model"})

    def test_challenge_reopens_only_consumers_and_retains_original_results(self):
        self.proof["quote"] = "function guard(active) { if (!active) return false; return true; }"
        (self.root / "guard.js").write_text(self.proof["quote"] + "\n")
        self.answer["proofs"] = [self.proof]
        target = self.question()[0]
        originals = {name:self.finish(name, [target] if name!="independent" else []).read_bytes()
                     for name in ("native", "ai-only", "independent")}
        record = self.audit(target)
        self.assertEqual(record["outcome"], "challenged")
        self.assertEqual(len(record["affected"]), 2)
        self.assertEqual(self.audit(target), record, "Receipt replay must not append or charge another audit")
        state = self.store.snapshot()
        self.assertEqual(state["assertions"][target["assertion_id"]][-1]["status"], "disputed")
        self.assertIn("guard-return", state["suspended_patterns"])
        for case in ("native", "ai-only"):
            self.assertEqual(set(state["cases"][case]["reconsideration"]), {"security"})
        self.assertEqual(state["cases"]["independent"]["reconsideration"], {})
        for case, data in originals.items():
            self.assertEqual(self.store._read_result(state["cases"][case]["result"])["draft"]["work_checks"][1]["status"], "satisfied")
            self.assertEqual((self.base/state["cases"][case]["result"]["path"]).read_bytes(),data)
        corrected=copy.deepcopy(self.answer)
        corrected["draft"]["work_checks"][0].update(status="violated",summary="The early-return branch returns false.")
        replacement=self.question("explicit-correction",corrected)
        self.assertEqual(replacement[0]["version"],2)
        self.assertTrue(self.store.snapshot()["cases"]["ai-only"]["reconsideration"], "A new fact does not silently settle a security case")

    def test_unresolved_audit_is_not_a_demonstrated_error_or_pattern_failure(self):
        target=self.question()[0]
        self.finish("ai-only",[target])
        record=self.audit(target,"unresolved")
        self.assertEqual(record["outcome"],"unresolved")
        state=self.store.snapshot()
        self.assertEqual(state["assertions"][target["assertion_id"]][-1]["status"],"available")
        self.assertEqual(state["cases"]["ai-only"]["reconsideration"],{})
        self.assertFalse(state.get("suspended_patterns"))

    def test_stale_role_provider_and_unseen_proof_cannot_change_state(self):
        target=self.question()[0]
        for updates in ({"review_role":"question_answerer"}, {"question_provider":{"model":"fact-model"}}, {"proofs":[]}):
            with self.subTest(updates=updates),self.assertRaises(ValueError):
                self.audit(target,**updates)
        self.assertFalse(self.store.snapshot()["cases"]["native"].get("factual_audits"))
        self.question("replacement",copy.deepcopy(self.answer))
        with self.assertRaisesRegex(ValueError,"current assertion"):
            self.audit(target,name="stale-audit")


if __name__ == "__main__":
    unittest.main()
