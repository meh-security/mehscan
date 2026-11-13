"""Required property identities and their delivered citations survive the adapter."""
import copy
import unittest
from jsonschema import Draft202012Validator

import test_source_coverage as fixtures
import codex_protocol
import source_review_protocol as protocol
import test_domain_protocol as domain_fixtures


class WorkChecks(unittest.TestCase):
    def test_factual_audit_requires_bound_expert_role_and_assertion_version(self):
        fixture=domain_fixtures.DomainProtocol();fixture.setUp();self.addCleanup(fixture.doCleanups)
        task,packet=fixture.tasks[0],fixture.packets[0]
        response=fixture.final(0)
        task.pop('domain_session')
        task.update(profile='expert',review_role='fact_auditor',review_ids=[])
        target=dict(assertion_id='a'*64,version=1)
        task['research'].update(question_only=True,factual_audit=target,
            required_checks=[dict(id='fact',question='Is the earlier scoped answer correct?',route='source_fact',
                scope='This function.',acceptance='Cite support or a counterexample.')])
        provider=packet['work']['runtime']['provider']
        packet['work']['runtime']['orchestration']={'expert':provider}
        packet['work']['runtime']['provider']={**provider,'model':'routine-model'}
        packet['job_binding']=dict(profile='expert',role='fact_auditor',provider=provider)
        packet['factual_audit']={**target,'original_answer':{'summary':'The return is unconditional.'},'selection':{'reasons':['Explicit omitted branch.']}}
        packet['native_questions']=[];fixture.update_packet(0)
        response['draft']['results']=[]
        for row in response['draft']['coverage']:row['status']='deferred'
        response['draft']['work_checks']=[dict(check_id='fact',status='violated',summary='The cited branch contradicts that answer.',
            evidence=[dict(source_ref='s0',line=1)],next_deciding_fact=None)]
        fixture.responses=[response]
        value=fixture.invoke(0)
        self.assertEqual(value['draft']['work_checks'][0]['status'],'violated')
        task['research']['factual_audit']['version']=2
        with self.assertRaisesRegex(ValueError,'assertion version'):fixture.invoke(0)
        task['research']['factual_audit']['version']=1
        task['profile']='routine'
        with self.assertRaisesRegex(ValueError,'explicit source facts'):fixture.invoke(0)

    def test_owner_dispositions_bind_qualifications_and_rejections(self):
        ref = dict(assertion_id="fact-one", version=2)
        self.task["research"].update(available_assertions=[ref], considered_assertions=[ref])
        row = self.reply["draft"]["work_checks"][0]
        row.update(conditions=[], limitations=[], assertion_dependencies=[ref],
            assertion_dispositions=[dict(**ref, disposition="qualified", reason="Only the shown route.", conditions=["This route."])])
        Draft202012Validator(codex_protocol.build_schema(self.task)).validate(self.reply)
        result = protocol.envelope(self.reply, self.task)
        self.assertEqual(result["draft"]["work_checks"][0]["assertion_dispositions"], row["assertion_dispositions"])
        row["assertion_dispositions"][0]["disposition"] = "rejected"
        with self.assertRaisesRegex(ValueError, "reliance"):
            protocol.envelope(self.reply, self.task)
        row["assertion_dependencies"] = []
        protocol.envelope(self.reply, self.task)

    def test_owner_dependencies_must_name_offered_assertion_versions(self):
        self.task["research"]["available_assertions"] = [{"assertion_id":"fact-one", "version":2}]
        check = self.reply["draft"]["work_checks"][0]
        check["assertion_dependencies"] = [{"assertion_id":"fact-one", "version":2}]
        validator = Draft202012Validator(codex_protocol.build_schema(self.task))
        validator.validate(self.reply)
        self.assertEqual(protocol.envelope(self.reply, self.task)["draft"]["work_checks"][0]["assertion_dependencies"],
                         check["assertion_dependencies"])
        for invalid in ([{"assertion_id":"other", "version":2}],
                        [{"assertion_id":"fact-one", "version":1}],
                        check["assertion_dependencies"] * 2):
            bad = copy.deepcopy(self.reply)
            bad["draft"]["work_checks"][0]["assertion_dependencies"] = invalid
            with self.assertRaisesRegex(ValueError, "assertion dependency"):
                protocol.envelope(bad, self.task)
        del self.reply["draft"]["work_checks"][0]["assertion_dependencies"]
        self.assertTrue(list(validator.iter_errors(self.reply)))

    def test_bound_question_role_runs_evidence_only_adapter(self):
        fixture=domain_fixtures.DomainProtocol();fixture.setUp();self.addCleanup(fixture.doCleanups)
        task,packet=fixture.tasks[0],fixture.packets[0]
        response=fixture.final(0)
        task.pop('domain_session')
        task.update(profile='routine',review_role='question_answerer',review_ids=[])
        task['research'].update(question_only=True,required_checks=[dict(id='fact',question='Is this value returned?',route='source_fact',scope='This function.',acceptance='Cite the return expression.')])
        provider=packet['work']['runtime']['provider']
        packet['work']['runtime']['orchestration']={'expert':{**provider,'model':'expert-model'}}
        packet['job_binding']=dict(profile='routine',role='question_answerer',provider=provider)
        packet['native_questions']=[]
        fixture.update_packet(0)
        response['draft']['results']=[]
        for row in response['draft']['coverage']:row['status']='deferred'
        response['draft']['work_checks']=[dict(check_id='fact',status='satisfied',summary='The source returns the value.',evidence=[dict(source_ref='s0',line=1)],next_deciding_fact=None)]
        fixture.responses=[response]
        answer=fixture.invoke(0)
        self.assertEqual(answer['draft']['results'],[])
        self.assertEqual(answer['draft']['work_checks'][0]['evidence'][0]['path'],'operation0.py')
        task['research']['required_checks'][0]['route']='security_decision'
        with self.assertRaisesRegex(ValueError,'explicit source facts'):
            fixture.invoke(0)

    def test_question_only_schema_and_envelope_reject_verdicts_and_audit_claims(self):
        self.task['research']['question_only'] = True
        self.reply['draft']['results'] = []
        self.reply['draft']['proposals'] = []
        for row in self.reply['draft']['coverage']:
            row['status'] = 'deferred'
        validator = Draft202012Validator(codex_protocol.build_schema(self.task))
        validator.validate(self.reply)
        protocol.envelope(self.reply, self.task)
        bad = copy.deepcopy(self.reply)
        bad['draft']['coverage'][0]['status'] = 'examined'
        self.assertTrue(list(validator.iter_errors(bad)))
        with self.assertRaisesRegex(ValueError, 'question worker'):
            protocol.envelope(bad, self.task)

    def setUp(self):
        f = fixtures.SourceCoverageTests()
        f.setUp()
        self.task, self.reply = f.task, f.reply
        self.task["research"]["required_checks"] = [{"id":"binding", "question":"Does the control bind this actor?"}]
        self.task["research"]["citation_windows"] = {"s0":dict(path="reader.cs", start_line=1, end_line=40, anchor=True)}
        self.reply["draft"]["work_checks"] = [dict(check_id="binding", status="satisfied", summary="The cited control binds the actor.",
            evidence=[dict(source_ref="s0", line=12)], next_deciding_fact=None)]

    def test_schema_requires_checks_and_adapter_expands_their_source_handles(self):
        Draft202012Validator(codex_protocol.build_schema(self.task)).validate(self.reply)
        value = protocol.envelope(self.reply, self.task)
        self.assertEqual(value["draft"]["work_checks"][0]["evidence"], [dict(path="reader.cs", start_line=12, end_line=12)])
        other = copy.deepcopy(self.reply)
        del other["draft"]["work_checks"]
        self.assertTrue(list(Draft202012Validator(codex_protocol.build_schema(self.task)).iter_errors(other)))

    def test_foreign_or_duplicate_check_identity_is_rejected(self):
        for rows in ([], [self.reply["draft"]["work_checks"][0]] * 2,
                     [{**self.reply["draft"]["work_checks"][0], "check_id":"foreign"}]):
            reply = copy.deepcopy(self.reply)
            reply["draft"]["work_checks"] = rows
            with self.assertRaisesRegex(ValueError, "check identities"):
                protocol.envelope(reply, self.task)

    def test_check_cannot_cite_unseen_source(self):
        reply = copy.deepcopy(self.reply)
        reply["draft"]["work_checks"][0]["evidence"] = [dict(source_ref="f999", line=1)]
        with self.assertRaisesRegex(ValueError, "not offered"):
            protocol.envelope(reply, self.task)

    def test_stable_schema_keeps_check_ids_out_of_schema_prefix(self):
        other = copy.deepcopy(self.task)
        other["research"]["required_checks"] = [{"id":"different", "question":"Another control?"}]
        self.assertEqual(codex_protocol.build_schema(self.task, bound_handles=False),
                         codex_protocol.build_schema(other, bound_handles=False))

    def test_domain_adapter_transports_checks_with_receipts_and_case_identity(self):
        fixture = domain_fixtures.DomainProtocol()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.tasks[0]["research"]["required_checks"] = [{"id":"binding", "question":"Does the control bind this actor?"}]
        response = fixture.final(0)
        response["draft"]["work_checks"] = copy.deepcopy(self.reply["draft"]["work_checks"])
        response["draft"]["work_checks"][0]["evidence"] = [dict(source_ref="s0", line=1)]
        fixture.responses = [response]
        result = fixture.invoke(0)
        self.assertEqual(result["draft"]["work_checks"][0]["evidence"][0]["path"], "operation0.py")
        self.assertEqual(len(fixture.calls), 1)


if __name__ == "__main__":
    unittest.main()
