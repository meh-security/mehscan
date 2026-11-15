"""Delegation is explicit, source-scoped and cannot generate security verdicts."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import review_questions as questions

class Questions(unittest.TestCase):
    def test_routing_requires_explicit_useful_factual_work(self):
        check = dict(id='q', question='Which predicate?', route='source_fact',
                     scope='This query.', acceptance='Cite the predicate.',
                     source_ranges=[dict(path='a.js', start_line=1, end_line=2)])
        self.assertEqual(questions.route_check(check)['effective_route'], 'owner')
        check.update(task_kind='extraction', usefulness='Supplies the actual selector operands.')
        route = questions.route_check(check)
        self.assertEqual(route['effective_route'], 'prepare')
        self.assertEqual(route['policy_version'], questions.ROUTING_POLICY)
        check['task_kind'] = 'security_decision'
        self.assertEqual(questions.route_check(check)['effective_route'], 'owner')
        with self.assertRaises(ValueError):
            questions.validate_check({**check, 'task_kind':'all-billing'})
    def test_named_prerequisites_preserve_partial_source_and_missing_bindings(self):
        check = dict(id='q', question='Which guard?', route='source_fact',
                     scope='Named implementations.', acceptance='Cite their complete bodies.',
                     source_definitions=[dict(path='guard.js', name='guard'), dict(path='guard.js', name='missing')])
        source = dict(path='guard.js', start_line=1, end_line=2, quote='function guard() {}')
        def collect(spec):
            if spec['name'] == 'guard':
                return dict(status='ready', reason='Complete declaration.'), source
            return dict(status='not_ready', reason='ambiguous_declaration'), None
        note, prepared = questions.prepare_check(check, lambda _: self.fail('No fixed ranges'), collect)
        self.assertEqual(note['status'], 'not_ready')
        self.assertEqual(note['reason'], 'ambiguous_declaration')
        self.assertEqual(prepared, [source])
        self.assertEqual(len(note['definitions']), 2)
        for spec in (dict(path='../guard.js', name='guard'), dict(path='/guard.js', name='guard'),
                     dict(path='guard.js', name=''), dict(path='guard.js', name='guard', limit=100)):
            with self.assertRaises(ValueError):
                questions.validate_check({**check, 'source_definitions':[spec]})

    def test_preparation_requires_declared_deliverable_evidence(self):
        check = dict(id='q', question='Which operand?', route='source_fact',
                     scope='This selector.', acceptance='Cite its operands.')
        called = []
        note, prepared = questions.prepare_check(check, lambda cite: called.append(cite))
        self.assertEqual(note['status'], 'not_ready')
        self.assertEqual((called, prepared), ([], []))
        cite = dict(path='a.js', start_line=1, end_line=2)
        check['source_ranges'] = [cite]
        note, prepared = questions.prepare_check(check, lambda value: {**value, 'quote':'a\nb'})
        self.assertEqual(note['status'], 'ready')
        self.assertEqual(prepared[0]['quote'], 'a\nb')
        def missing(value):
            raise ValueError('Named body not in the bound snapshot.')
        note, prepared = questions.prepare_check(check, missing)
        self.assertEqual(note['status'], 'not_ready')
        self.assertEqual(prepared, [])
        self.assertIn('Named body', note['reason'])
        for invalid in ([], [dict(cite, start_line=True)], [dict(cite, end_line=500)]):
            with self.assertRaises(ValueError):
                questions.validate_check({**check, 'source_ranges':invalid})

    def test_unspecified_questions_stay_with_owner_and_facts_require_scope(self):
        self.assertEqual(questions.validate_check({'id':'a','question':'Decide the boundary.'}),'security_decision')
        for check in [dict(id='a',question='Is it safe?',route='automatic'),
                      dict(id='a',question='Which field?',route='source_fact'),
                      dict(id='a',question='Which field?',route='source_fact',scope='This handler.',acceptance='')]:
            with self.assertRaises(ValueError):questions.validate_check(check)

    def test_owner_excerpt_does_not_preload_neighboring_bodies(self):
        assignment={'windows':[dict(path='a.js',start_line=1,end_line=3,text='before\ncontrol\nafter'),
                               dict(path='other.js',start_line=1,end_line=1,text='unrelated')]}
        focus=dict(owner_path='a.js',start_line=2,end_line=2)
        self.assertEqual(questions.owner_windows(assignment,focus),[dict(path='a.js',start_line=2,end_line=2,text='control')])
        with self.assertRaises(ValueError):questions.owner_windows(assignment,{**focus,'owner_path':'foreign.js'})

    def test_failed_question_never_becomes_a_closed_fact_item(self):
        result=questions.fact_only_result({'id':'a'},[{'id':'q'}],[({'id':'q'},{'status':'incomplete'})])
        self.assertEqual(result['status'],'incomplete')
        self.assertNotIn('draft',result)

    def test_skipped_preparation_is_distinct_from_attempted_unresolved_answer(self):
        checks=[dict(id=key,question='Locate the registered producer.',route='source_fact',
                     scope='The named route.',acceptance='Cite the registration and assignment.') for key in ('a','b')]
        checks.append(dict(id='owner',question='Does this violate account authority?'))
        answer=dict(status='complete',calls=1,question_conversation_id='turn-a',
                    draft=dict(work_checks=[dict(check_id='a',status='unresolved')]))
        notes=questions.execution_notes(checks,[(checks[0],answer)],{'model':'routine'},
                                       lambda key:'jobs/'+key,'Owner capacity reserved.')
        self.assertEqual([row['check_id'] for row in notes],['a','b'])
        self.assertEqual(notes[0]['answer_status'],'unresolved')
        self.assertEqual(notes[0]['conversation_id'],'turn-a')
        self.assertEqual(notes[1]['status'],'skipped')
        self.assertEqual(notes[1]['calls'],0)
        self.assertIsNone(notes[1]['directory'])
        self.assertIsNone(notes[1]['conversation_id'])
        self.assertEqual(notes[1]['reason'],'Owner capacity reserved.')

if __name__=='__main__':unittest.main()
