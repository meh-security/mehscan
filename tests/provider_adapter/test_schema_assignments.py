"""Stable wire formats across assignments; local admission keeps exact bindings."""
import copy
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_codex as fixtures
import workspace_protocol as workspace


def result(identity):
    return {"review_id":identity,"decision":"not_issue","confidence":"high",
            "summary":"The inspected control covers this operation.","reason":"Source-bound control.",
            "evidence":[],"checks":[],"blockers":[],"diagnosis":None,"source_leads":[]}


class AssignmentSchemas(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.Adapter(methodName='test_exact_resume_sends_new_facts_only_and_metrics_exclude_private_data')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.task.update(kind='native_bundle',review_ids=['one','two'])

    def test_native_roles_keep_one_wire_schema_for_different_assignments(self):
        for role in ['investigator','verification','adjudication','final_qa','second_pass_fast','second_pass_compare']:
            before=copy.deepcopy(self.f.task)
            before.update(review_role=role,adjudicate_ids=['one'],routing_allowed=True)
            after=copy.deepcopy(before)
            after.update(review_ids=['three','four','five'],adjudicate_ids=['four','five'])
            after['research'].update(artifact_handles={'source9':'actual'},rounds_remaining=0,queries_remaining=0)
            with self.subTest(role=role):
                self.assertEqual(fixtures.protocol.build_schema(before,bound_handles=False),
                                 fixtures.protocol.build_schema(after,bound_handles=False))
                self.assertNotEqual(fixtures.protocol.build_schema(before),fixtures.protocol.build_schema(after))

    def test_fast_phases_keep_the_wire_schema_but_audit_disallows_queries_locally(self):
        audit=copy.deepcopy(self.f.task)
        audit.update(review_role='second_pass_fast',fast_phase='audit')
        audit['research'].update(rounds_remaining=0,queries_remaining=0)
        recovery=copy.deepcopy(audit);recovery['fast_phase']='recovery'
        recovery['research'].update(rounds_remaining=3,queries_remaining=24)
        self.assertEqual(fixtures.protocol.build_schema(audit,bound_handles=False),
                         fixtures.protocol.build_schema(recovery,bound_handles=False))
        self.assertEqual(fixtures.protocol.build_schema(audit)['properties']['action']['enum'],['final'])
        self.assertIn('research',fixtures.protocol.build_schema(recovery)['properties']['action']['enum'])
        prompt=fixtures.protocol.build_prompt(audit,self.f.body,[],None)
        self.assertIn('Fast audit checkpoint',prompt)
        self.assertNotIn('Research is finished.',prompt)

    def test_local_native_rejects_foreign_verdict_after_recording_usage(self):
        f=self.f
        f.config['schema_mode']='stable'
        reply={'action':'final','research':[],'draft':{'results':[result('foreign')]},
               'working_chain':'Inspected the selected control.','progress':[],'routing':[]}
        self.assertFalse(list(Draft202012Validator(fixtures.protocol.build_schema(f.task,bound_handles=False)).iter_errors(reply)))
        def factory(config,session):
            fake=f.factory(config,session)
            original=fake.review
            def review(*args,**kwargs):
                _,events,stderr=original(*args,**kwargs)
                return reply,events,stderr
            fake.review=review
            return fake
        with self.assertRaisesRegex(ValueError,'current-turn schema'):
            fixtures.reviewer.run(f.config,f.task,factory)
        receipt=json.loads((f.public/'provider-metrics.jsonl').read_text())
        self.assertEqual(receipt['usage']['input_tokens'],100)
        self.assertFalse(json.loads(next(f.public.glob('schema-validation-*.jsonl')).read_text())['valid'])
        self.assertFalse(json.loads(next(f.public.glob('reply-validation-*.json')).read_text())['repairable_proof_references'])

    def test_workspace_wire_is_assignment_independent_but_local_membership_and_counts_are_not(self):
        before=copy.deepcopy(self.f.task)
        before['research'].update(source_artifact_handles=['source1'],queries_remaining=4,
                                  workspace_budget={'limits':{'model_calls':4},'used':{'model_calls':0}})
        after=copy.deepcopy(before)
        after['review_ids']=['three','four','five']
        after['research'].update(source_artifact_handles=[],queries_remaining=0,rounds_remaining=0)
        self.assertEqual(workspace.schema(before,bound_handles=False),workspace.schema(after,bound_handles=False))
        wire=Draft202012Validator(workspace.schema(before,bound_handles=False))
        local=Draft202012Validator(workspace.schema(before))
        def decision(identity):
            value=result(identity)
            value.pop('checks');value.pop('blockers')
            return value
        for decisions in [[decision('foreign')],[decision('one'),decision('two'),decision('one')]]:
            response={'updates':[],'lookups':[],'decisions':decisions}
            with self.subTest(decisions=decisions):
                self.assertFalse(list(wire.iter_errors(response)))
                self.assertTrue(list(local.iter_errors(response)))

    def test_boundary_wire_does_not_embed_eligible_ids_or_their_count(self):
        f=self.f
        f.boundary_task()
        first=fixtures.protocol.build_schema(f.task,bound_handles=False)
        f.task['review_ids']=['three','four']
        f.body['native_questions']=[{'review_id':identity,'capability':'authorization'} for identity in f.task['review_ids']]
        f.packet.write_text(json.dumps(f.body))
        self.assertEqual(first,fixtures.protocol.build_schema(f.task,bound_handles=False))
        local=fixtures.protocol.build_schema(f.task)
        self.assertEqual(local['properties']['boundary_checks']['maxItems'],2)
        self.assertEqual(local['properties']['boundary_checks']['items']['properties']['review_id']['enum'],['three','four'])


if __name__ == '__main__':
    unittest.main()
