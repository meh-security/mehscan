"""Bounded domain continuation; fake provider only, with no credentials or inference."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_codex as fixtures
import domain_review_protocol as domain


class DomainProtocol(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.Adapter('test_exact_resume_sends_new_facts_only_and_metrics_exclude_private_data')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.config.update(schema_mode='stable', source_presentation='line-addressed-v1')
        self.calls, self.responses = [], []
        cases = [{'id': 'case-' + str(i), 'conversation_id': letter * 64,
                  'assignment_id': 'assignment-' + str(i), 'review_ids': ['review-' + str(i)]}
                 for i, letter in enumerate(('a', 'b'))]
        self.tasks, self.packets = [], []
        for index, case in enumerate(cases):
            directory = self.f.public / str(index)
            directory.mkdir()
            path = 'operation' + str(index) + '.py'
            (self.f.source / path).write_text('return value\n')
            ref = 's' + str(index * 1000)
            window = {'path': path, 'start_line': 1, 'end_line': 1,
                      'text': 'return value', 'artifact_id': 'artifact-' + str(index)}
            packet = {'work': {'runtime': {'provider': fixtures.launcher.provider_contract(self.f.config)},
                               'review_ids': case['review_ids']},
                      'source_binding': {'snapshot_id': 'snapshot', 'inventory_input_fingerprint': 'input'},
                      'contract': 'TRUSTED SHARED DOMAIN CONTRACT',
                      'source_assignment_id': case['assignment_id'],
                      'native_questions': [{'review_id': case['review_ids'][0], 'path': path, 'line': 1}],
                      'domain_case': {'id': case['id'], 'domain_id': 'shared-control',
                                      'review_roles': {'verify': case['review_ids'], 'cover': [], 'context': []}},
                      'domain_shared_facts': [{'path': 'shared.py', 'start_line': 1, 'end_line': 1,
                                               'quote': 'SHARED CITED FACT'}],
                      'primary': {'windows': [window]}}
            packet_path = directory / 'context.json'
            packet_path.write_text(json.dumps(packet))
            facts_path = directory / 'facts.json'
            facts_path.write_text('{"facts":[]}')
            task = {'kind': 'source_review', 'conversation_id': case['conversation_id'],
                    'source_root': str(self.f.source), 'artifact_root': str(self.f.public),
                    'evidence_packet': str(packet_path), 'shared_facts': str(facts_path),
                    'provider_metrics': str(directory / 'provider-metrics.jsonl'),
                    'review_ids': case['review_ids'], 'review_role': 'investigator',
                    'domain_session': {'id': 'd' * 64, 'binding': 'e' * 64,
                                       'case_id': case['id'], 'case_index': index, 'cases': cases},
                    'research': {'round': 0, 'rounds_remaining': 2, 'queries_remaining': 4,
                                 'bytes_remaining': 1024, 'seconds_remaining': 60, 'results': [],
                                 'artifact_handles': {ref: window['artifact_id']},
                                 'source_artifact_handles': [ref],
                                 'coverage_windows': {ref: {k: window[k] for k in ('path', 'start_line', 'end_line')}},
                                 'citation_windows': {ref: {**{k: window[k] for k in ('path', 'start_line', 'end_line')},
                                                          'anchor': True}}}}
            self.tasks.append(task)
            self.packets.append(packet)

    def final(self, index):
        task = self.tasks[index]
        ref = next(iter(task['research']['coverage_windows']))
        return {'action': 'final', 'research': [], 'working_chain': 'Inspected current case.',
                'draft': {'results': [{'review_id': task['review_ids'][0], 'decision': 'not_issue',
                    'confidence': 'high', 'summary': 'The inspected control applies.',
                    'reason': 'This case supplies the deciding source.', 'evidence': [{'source_ref': ref, 'line': 1}],
                    'checks': [], 'blockers': [], 'diagnosis': None, 'source_leads': []}],
                    'proposals': [], 'coverage': [{'window_ref': ref, 'status': 'examined', 'summary': 'Scoped review.'}]}}

    def factory(self, config, session):
        outer = self
        class Fake:
            def review(self, prompt, schema, thread_id=None, timeout=600):
                outer.calls.append((prompt, schema, thread_id, str(session)))
                count = len(outer.calls)
                response = outer.responses.pop(0)
                events = [{'type': 'thread.started', 'thread_id': fixtures.THREAD},
                          {'type': 'turn.completed', 'usage': {'input_tokens': 100 * count,
                           'cached_input_tokens': 60 * count, 'output_tokens': 20 * count}}]
                return response, '\n'.join(json.dumps(e) for e in events), ''
        return Fake()

    def invoke(self, index):
        return fixtures.reviewer.run(self.f.config, self.tasks[index], self.factory)

    def update_packet(self, index):
        Path(self.tasks[index]['evidence_packet']).write_text(json.dumps(self.packets[index]))

    def test_two_sealed_cases_share_thread_with_distinct_citations_and_usage_receipts(self):
        self.responses = [self.final(0), self.final(1)]
        first, second = self.invoke(0), self.invoke(1)
        self.assertEqual([c[2] for c in self.calls], [None, fixtures.THREAD])
        self.assertEqual(self.calls[0][3], self.calls[1][3])
        self.assertEqual(self.calls[0][1], self.calls[1][1])
        self.assertEqual(second['draft']['results'][0]['evidence'][0]['path'], 'operation1.py')
        self.assertEqual(first['draft']['results'][0]['review_id'], 'review-0')
        self.assertIn('TRUSTED SHARED DOMAIN CONTRACT', self.calls[0][0])
        self.assertIn('SHARED CITED FACT', self.calls[0][0])
        self.assertNotIn('TRUSTED SHARED DOMAIN CONTRACT', self.calls[1][0])
        self.assertNotIn('SHARED CITED FACT', self.calls[1][0])
        self.assertNotIn('operation0.py', self.calls[1][0])
        self.assertIn('"s1000"', self.calls[1][0])
        receipts = [json.loads(Path(t['provider_metrics']).read_text()) for t in self.tasks]
        self.assertEqual([r['conversation_id'] for r in receipts], ['a' * 64, 'b' * 64])
        self.assertEqual([r['usage']['input_tokens'] for r in receipts], [100, 100])
        self.assertEqual([r['domain_turn'] for r in receipts], [0, 1])
        self.assertTrue(receipts[1]['resumed'])
        self.assertTrue(receipts[1]['domain_case_start'])
        self.assertEqual(receipts[0]['domain_prefix_sha256'], receipts[1]['domain_prefix_sha256'])

    def test_bound_expert_owner_uses_real_adapter_with_domain_metadata(self):
        packet=self.packets[0]
        expert=fixtures.launcher.provider_contract(self.f.config)
        packet['work']['runtime']['orchestration']={'expert':expert}
        packet['work']['runtime']['provider']={**expert,'model':'other-routine-model'}
        packet['job_binding']={'profile':'expert','role':'investigator','provider':expert}
        self.tasks[0]['profile']='expert'
        self.update_packet(0)
        self.responses=[self.final(0)]
        result=self.invoke(0)
        self.assertEqual(result['draft']['results'][0]['review_id'],'review-0')
        self.assertEqual(len(self.calls),1)

    def test_unbound_expert_domain_is_rejected_before_provider(self):
        self.tasks[0]['profile']='expert'
        with self.assertRaisesRegex(ValueError,'ordinary source-review'):
            self.invoke(0)
        self.assertEqual(self.calls,[])

    def test_research_continuation_does_not_allow_next_case_before_final(self):
        research = {'action': 'research', 'research': [{'tool': 'source', 'review_id': None,
                    'purpose': 'Inspect the deciding helper.', 'arguments': {'path': 'shared.py',
                    'start_line': 1, 'end_line': 1, 'context': None}}], 'draft': None, 'working_chain': 'Need the helper.'}
        # Use an offered tool shape rather than relying on a free-form source query.
        arguments = fixtures.protocol.build_schema(self.tasks[0], bound_handles=False)['properties']['research']['items']['anyOf']
        source = next(v for v in arguments if v['properties']['tool']['enum'] == ['source'])
        research['research'][0]['arguments'] = {k: None for k in source['properties']['arguments']['properties']}
        research['research'][0]['arguments'].update(path='shared.py', start_line=1, end_line=1)
        self.responses = [research, self.final(0), self.final(1)]
        self.invoke(0)
        with self.assertRaisesRegex(ValueError, 'sequentially'):
            self.invoke(1)
        self.tasks[0]['research']['round'] = 1
        self.invoke(0)
        self.invoke(1)
        self.assertEqual([c[2] for c in self.calls], [None, fixtures.THREAD, fixtures.THREAD])

    def test_replayed_sealed_case_and_changed_case_packet_are_rejected_before_provider(self):
        self.responses = [self.final(0)]
        self.invoke(0)
        with self.assertRaisesRegex(ValueError, 'sealed'):
            self.invoke(0)
        self.packets[0]['primary']['windows'][0]['text'] = 'changed source'
        self.update_packet(0)
        self.tasks[0]['research']['round'] = 1
        with self.assertRaisesRegex(ValueError, 'sealed|changed'):
            self.invoke(0)
        self.assertEqual(len(self.calls), 1)

    def test_changed_shared_contract_or_declared_sequence_is_rejected(self):
        self.responses = [self.final(0)]
        self.invoke(0)
        self.packets[1]['contract'] += ' changed'
        self.update_packet(1)
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            self.invoke(1)
        self.assertEqual(len(self.calls), 1)

    def test_previous_case_verdict_and_source_reference_cannot_be_accepted(self):
        self.responses = [self.final(0)]
        self.invoke(0)
        wrong = self.final(1)
        wrong['draft']['results'][0].update(review_id='review-0', evidence=[{'source_ref': 's0', 'line': 1}])
        self.responses = [wrong]
        with self.assertRaisesRegex(ValueError, 'schema rejected'):
            self.invoke(1)
        with self.assertRaisesRegex(ValueError, 'rejected paid turn'):
            self.invoke(1)
        self.assertEqual(len(self.calls), 2)

    def reject_unsealed_final(self, response, message):
        self.responses = [response]
        with self.assertRaisesRegex(ValueError, message):
            self.invoke(0)
        state = json.loads((Path(self.f.config['private_directory']) /
                            ('domain-' + 'd' * 64) / 'conversation.json').read_text())
        self.assertFalse(state['domain_accepted'])
        self.assertFalse(state['domain_sealed'])
        self.assertTrue(Path(self.tasks[0]['provider_metrics']).is_file())
        with self.assertRaisesRegex(ValueError, 'unfinished or rejected'):
            self.invoke(1)
        self.assertEqual(len(self.calls), 1)

    def two_verification_targets(self):
        ids = ['review-0', 'review-other']
        self.tasks[0]['review_ids'] = ids
        self.tasks[0]['domain_session']['cases'][0]['review_ids'] = ids
        self.packets[0]['work']['review_ids'] = ids
        self.packets[0]['domain_case']['review_roles']['verify'] = ids
        self.packets[0]['native_questions'].append({'review_id': 'review-other',
                                                   'path': 'operation0.py', 'line': 1})
        self.update_packet(0)

    def test_missing_verification_result_cannot_seal_or_advance_domain(self):
        self.two_verification_targets()
        self.reject_unsealed_final(self.final(0), 'native IDs exactly once')

    def test_duplicate_verification_result_cannot_seal_or_advance_domain(self):
        self.two_verification_targets()
        response = self.final(0)
        response['draft']['results'].append(copy.deepcopy(response['draft']['results'][0]))
        self.reject_unsealed_final(response, 'native IDs exactly once')

    def test_duplicate_coverage_reference_cannot_seal_or_advance_domain(self):
        self.packets[0]['primary']['windows'].append({'path': 'operation0.py', 'start_line': 2,
            'end_line': 2, 'text': 'return other', 'artifact_id': 'second-window'})
        self.tasks[0]['research']['artifact_handles']['s1'] = 'second-window'
        self.tasks[0]['research']['source_artifact_handles'].append('s1')
        self.tasks[0]['research']['coverage_windows']['s1'] = {
            'path': 'operation0.py', 'start_line': 2, 'end_line': 2}
        self.tasks[0]['research']['citation_windows']['s1'] = {
            'path': 'operation0.py', 'start_line': 2, 'end_line': 2, 'anchor': True}
        self.update_packet(0)
        response = self.final(0)
        response['draft']['coverage'].append(copy.deepcopy(response['draft']['coverage'][0]))
        self.reject_unsealed_final(response, 'assigned windows exactly once')

    def test_missing_case_session_and_undeclared_current_membership_never_launch(self):
        with self.assertRaisesRegex(ValueError, 'missing domain'):
            self.invoke(1)
        self.tasks[0]['review_ids'] = ['foreign']
        with self.assertRaisesRegex(ValueError, 'membership'):
            self.invoke(0)
        self.assertEqual(self.calls, [])

    def test_unknown_provider_turn_fences_continuation_and_case_switch(self):
        class Failed:
            def review(self, *args, **kwargs):
                raise RuntimeError('provider outcome unknown')
        with self.assertRaisesRegex(RuntimeError, 'outcome unknown'):
            fixtures.reviewer.run(self.f.config, self.tasks[0], lambda *args: Failed())
        for index in (0, 1):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'unfinished'):
                self.invoke(index)
        self.assertEqual(self.calls, [])

    def test_counter_reset_fences_session_after_recording_paid_reply(self):
        self.responses = [self.final(0), self.final(1)]
        self.invoke(0)
        original = self.factory
        def factory(config, session):
            fake = original(config, session)
            invoke = fake.review
            def reset(*args, **kwargs):
                reply, events, stderr = invoke(*args, **kwargs)
                rows = [json.loads(line) for line in events.splitlines()]
                rows[-1]['usage']['input_tokens'] = 99
                return reply, '\n'.join(json.dumps(r) for r in rows), stderr
            fake.review = reset
            return fake
        with self.assertRaisesRegex(ValueError, 'usage is incomplete'):
            fixtures.reviewer.run(self.f.config, self.tasks[1], factory)
        receipt = json.loads(Path(self.tasks[1]['provider_metrics']).read_text())
        self.assertIn('input_tokens', receipt['unknown_delta_counters'])
        with self.assertRaisesRegex(ValueError, 'unfinished or rejected'):
            self.invoke(1)
        self.assertEqual(len(self.calls), 2)

    def test_one_active_turn_per_domain(self):
        fixtures.reviewer.initialize_store(Path(self.f.config['private_directory']),
                                            fixtures.launcher.provider_contract(self.f.config))
        with domain.exclusive(self.f.config['private_directory'], 'd' * 64):
            with self.assertRaisesRegex(ValueError, 'already active'):
                self.invoke(0)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
