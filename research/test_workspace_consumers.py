"""Actionable same-work answer consumers without changing claim completion."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace as fixtures
from review_workspace import MAX_CONTEXT_BYTES


class AnswerConsumerTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.WorkspaceTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.proof=self.f.capture(1,4)

    def partial(self, *, status='open'):
        f=self.f
        f.apply('question',question_id='shared',review_ids=['safe','unsafe'],question='Which selected callers have an effective guard?')
        if status=='answered':
            f.apply('answer',question_id='shared',status='answered',reason='Initial guard interpretation.',evidence=[self.proof])
            f.draft('safe','not_issue',2)
        else:
            f.apply('draft',result={'review_id':'safe','decision':'not_issue','confidence':'high',
                    'summary':'This caller has a scoped guard.','reason':'The shown body owner is bound; other caller arguments are excluded.',
                    'checks':[],'blockers':[],'source_leads':[],'diagnosis':None,
                    'evidence':[{'path':'routes.ts','start_line':2,'end_line':2}]},
                    applicability=[],resolved_questions=['shared'])
        f.draft('unknown','not_issue',4)

    def test_partial_consumer_is_actionable_but_not_active_and_keeps_exact_result(self):
        self.partial();f=self.f;before=f.workspace.snapshot();view=f.workspace.view('initial')
        self.assertEqual([c['review_id']for c in view['claims']],['unsafe'])
        self.assertEqual(set(view['answer_consumers']),{'safe'})
        self.assertEqual(view['answer_consumers']['safe']['previous_result'],before['claims']['safe']['draft']['result'])
        self.assertEqual(view['answer_consumers']['safe']['question_ids'],['shared'])
        self.assertEqual(f.workspace.snapshot(),before)
        self.assertNotIn('unknown',view['answer_consumers'])
        f.apply('answer',question_id='shared',status='answered',reason='The actual remaining guard is inspected.',evidence=[self.proof])
        self.assertTrue(f.workspace.snapshot()['claims']['safe']['reconsideration'])
        with self.assertRaisesRegex(ValueError,'reconsideration'):f.workspace.bundle_draft('bundle-1')

    def test_answered_question_revision_can_also_invalidate_its_current_consumer(self):
        self.partial(status='answered');view=self.f.workspace.view('initial')
        self.assertEqual(view['answer_consumers']['safe']['question_ids'],['shared'])
        self.f.apply('answer',question_id='shared',status='answered',reason='A revised caller condition changes the old proof.',evidence=[self.proof])
        self.assertTrue(self.f.workspace.snapshot()['claims']['safe']['reconsideration'])

    def test_connected_questions_include_their_consumers_without_unrelated_claims(self):
        self.partial();f=self.f
        f.apply('question',question_id='second',review_ids=['safe','unknown'],question='Which shared producer is configured?')
        f.apply('answer',question_id='second',status='answered',reason='Configured producer source inspected.',evidence=[self.proof])
        f.apply('draft',result={'review_id':'safe','decision':'not_issue','summary':'A scoped negative.',
                    'reason':'Guard for this caller is established.','checks':[],
                    'evidence':[{'path':'routes.ts','start_line':2,'end_line':2}]},
                    applicability=[],resolved_questions=['shared'])
        f.draft('unknown','not_issue',4)
        view=f.workspace.view('initial')
        self.assertEqual([c['review_id']for c in view['claims']],['unsafe'])
        self.assertEqual(set(view['answer_consumers']),{'safe','unknown'})
        self.assertEqual(set(view['questions']),{'shared','second'})

    def test_foreign_work_consumer_does_not_gain_authority_or_expose_its_draft(self):
        self.partial();f=self.f
        f.apply('split',work_id='initial',new_work_id='other',review_ids=['safe'],strategy='Separate caller investigation')
        view=f.workspace.view('initial')
        self.assertEqual(view['answer_consumers'],{})
        self.assertIn('safe',view['questions']['shared']['review_ids'])
        self.assertEqual([c['review_id']for c in view['claims']],['unsafe'])
        f.apply('answer',question_id='shared',status='blocked',reason='A changed guard condition is unavailable.',evidence=[])
        self.assertTrue(f.workspace.snapshot()['claims']['safe']['reconsideration'])
        self.assertEqual([c['review_id']for c in f.workspace.view('other')['claims']],['safe'])

    def test_all_settled_terminates_even_with_an_open_partially_resolved_question(self):
        self.partial();f=self.f
        f.apply('draft',result={'review_id':'unsafe','decision':'not_issue','summary':'Separate caller assessment.',
                    'reason':'The selected relationship is scoped.','checks':[],
                    'evidence':[{'path':'routes.ts','start_line':3,'end_line':3}]},
                    applicability=[],resolved_questions=['shared'])
        self.assertEqual(f.workspace.view('initial')['claims'],[])
        self.assertEqual(f.workspace.view('initial')['answer_consumers'],{})
        self.assertEqual(f.workspace.view('initial')['questions'],{})

    def test_consumers_retain_applicability_dependencies_and_current_source_checks(self):
        self.partial();f=self.f;f.proposition(self.proof)
        aid=f.applicability('safe',self.proof)
        old=copy.deepcopy(f.workspace.snapshot()['claims']['safe']['draft']['result'])
        f.apply('draft',result=old,applicability=[aid],propositions=[{'proposition_id':'body-owner','revision':1}],resolved_questions=['shared'])
        f.apply('focus',work_id='initial',evidence_ids=[],proposition_ids=[])
        view=f.workspace.view('initial')
        self.assertIn(aid,view['applicability']);self.assertIn('body-owner',view['propositions']);self.assertIn(self.proof,view['evidence'])
        self.assertEqual(view['propositions']['body-owner']['exclusions'],'Route parameters are not constrained')
        f.code.write_text('changed source\n')
        with self.assertRaisesRegex(ValueError,'source changed'):f.workspace.view('initial')

    def test_changed_previous_result_invalidates_a_prepared_session(self):
        self.partial();f=self.f
        sid=f.apply('session',work_id='initial',parent_session=None,max_bytes=32768)['session_id']
        result=copy.deepcopy(f.workspace.snapshot()['claims']['safe']['draft']['result']);result['reason']='Revised scoped judgment.'
        f.apply('draft',result=result,applicability=[],resolved_questions=['shared'])
        with self.assertRaisesRegex(ValueError,'context changed'):f.apply('start_call',session_id=sid)
        self.assertEqual(f.workspace.snapshot()['used']['model_calls'],0)

    def test_context_upper_bound_is_explicit_and_does_not_change_action_credit(self):
        self.assertEqual(MAX_CONTEXT_BYTES,144*1024)
        f=self.f;before=f.workspace.snapshot()
        with self.assertRaisesRegex(ValueError,'144 KiB'):
            f.apply('prepare_work',planning_id='too-large',work=[],max_context_bytes=MAX_CONTEXT_BYTES+1)
        self.assertEqual(f.workspace.snapshot(),before)


if __name__=='__main__':unittest.main()
