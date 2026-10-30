"""Paid-candidate integrity, real native validation, no inference or admission."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_bridge as fixtures
import test_workspace_actions as actions
import codex_reviewer


class CandidatePreviewTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.NativeBridgeTests('test_rejected_completed_reply_still_records_usage')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.config['schema_mode']='stable'
        self.f.config_path.write_text(json.dumps(self.f.config))
        self.f.experiment['protocol']='workspace-actions-v2'
        self.f.limits['model_calls']=getattr(self,'call_limit',1)
        self.b=self.f.create()
        self.ids=list(self.b.workspace.snapshot()['claims'])
        self.b.apply('question',{'kind':'question','question_id':'closure','review_ids':self.ids,
                                'question':'Does the selected evaluator interpret the supplied request value?'})
        self.sid=self.b.prepare('initial',self.f.config_path,'prepared')['session_id']
        self.turns=[]
        self.thread=str(uuid.uuid4())

    def rejected(self,mutate=None, *, unknown=False):
        outer=self
        def invoke(task):
            packet=fixtures.read(task['evidence_packet'])
            class Fake:
                def review(self,prompt,schema,thread_id=None,timeout=600):
                    outer.turns.append(copy.deepcopy(task))
                    response={'updates':[{'kind':'answer','question_id':'closure','status':'answered',
                        'reason':'The shown operation interprets its input.','evidence':['source132']}],
                        'lookups':[],'decisions':[actions.WorkspaceActionTests.decision(q) for q in packet['native_questions']]}
                    if mutate:mutate(response)
                    usage={'input_tokens':100*len(outer.turns),'cached_input_tokens':None if unknown else 0,'output_tokens':20*len(outer.turns)}
                    events=[{'type':'thread.started','thread_id':outer.thread},
                            {'type':'turn.completed','usage':usage}]
                    return response,'\n'.join(json.dumps(e) for e in events),''
            try:return codex_reviewer.run(outer.f.config,task,lambda c,s:Fake())
            except ValueError as error:raise fixtures.CommandFailure(2,'fixture local rejection') from error
        with self.assertRaises((ValueError,fixtures.CommandFailure)):
            self.b.review(self.sid,self.f.config_path,invoke)
        self.assertEqual(len(self.turns),min(self.f.limits['model_calls'],2))
        self.session=self.b.directory/'sessions'/self.sid
        self.log=Path(self.f.config['private_directory'])/self.sid/'round-0'

    def export(self):return self.b.export_candidates(self.sid,self.f.config_path)

    def test_exhausted_rejection_previews_without_changing_state_or_usage_and_retries(self):
        self.rejected();before=self.b.workspace.snapshot();usage=self.b.workspace.usage()
        raw=(self.log/'response.json').read_bytes()
        with patch.object(codex_reviewer,'Launcher',side_effect=AssertionError('no model launcher permitted')):
            request={'directory':str(self.session),'session_id':self.sid,'round':0,
                'candidate_sha256':before['calls']['call:'+self.sid]['candidate_rejection_sha256'],
                'packet_sha256':before['sessions'][self.sid]['artifacts']['files']['context.json'],
                'task_file_sha256':before['sessions'][self.sid]['artifacts']['files']['task.json'],
                'usage':before['calls']['call:'+self.sid]['usage']}
            inspected=codex_reviewer.inspect_candidate(self.f.config,request)
        result=self.export()
        self.assertEqual(result['status'],'candidate_only')
        self.assertTrue(result['native_source_validated'])
        self.assertTrue(result['semantic_review_required'])
        self.assertFalse(result['workspace_response_accepted'])
        self.assertFalse(result['auxiliary_actions_applied'])
        self.assertFalse(result['native_admission'])
        self.assertEqual(fixtures.read(result['model_decisions']),inspected['decisions'])
        self.assertEqual(before,self.b.workspace.snapshot())
        self.assertEqual(usage,self.b.workspace.usage())
        self.assertEqual(self.b.workspace.usage()['calls'],1)
        self.assertEqual(before['questions']['closure']['status'],'open')
        self.assertTrue(all(c['draft'] is None for c in before['claims'].values()))
        self.assertEqual(raw,(self.log/'response.json').read_bytes())
        self.assertEqual(result,self.export())
        self.assertEqual(self.b.export_completed()['completed_review_ids'],[])
        status=self.f.native('state','status','--store',str(self.f.store),'--stream','pilot',
                             '--repository-key','evaluation:workspace-bridge')
        self.assertEqual({s['state'] for s in status['subjects']},{'unassessed'})
        # No pre-existing final artifact is trusted after a source change.
        (self.f.root/'app.js').write_text('changed source\n')
        with self.assertRaises((ValueError,fixtures.CommandFailure)):self.export()

    def test_needs_review_preserves_saved_question_and_uncertainty(self):
        def uncertain(reply):
            for r in reply['decisions']:
                r.update(decision='needs_review',confidence='medium',diagnosis=None,reason='Selected input authority remains unresolved.')
        self.rejected(uncertain);before=self.b.workspace.snapshot()
        result=self.export();report=fixtures.read(result['candidate_report'])
        self.assertEqual({r['response']['decision'] for r in report['decision_records']},{'needs_review'})
        self.assertTrue(all(r['response']['checks'] for r in report['decision_records']))
        self.assertEqual(before,self.b.workspace.snapshot())

    def test_preview_after_deadline_expiry_does_not_buy_another_call(self):
        self.rejected();before=self.b.workspace.snapshot()
        import review_workspace_bridge as module
        current=module.time.time()
        with patch.object(module.time,'time',return_value=current+2000):
            with self.assertRaisesRegex(ValueError,'ceiling|deadline'):self.b._remaining_seconds('initial')
            self.assertEqual(self.export()['status'],'candidate_only')
        self.assertEqual(before,self.b.workspace.snapshot())

    def test_latest_rejected_correction_is_bound_and_old_turn_is_stale(self):
        self.f.doCleanups();self.call_limit=2;self.setUp()
        self.rejected()
        with self.assertRaisesRegex(ValueError,'latest'):self.b.export_candidates(self.sid,self.f.config_path,0)
        result=self.export()
        self.assertEqual(result['status'],'candidate_only')
        self.assertEqual(self.b.workspace.usage()['calls'],2)
        self.assertEqual(self.b.workspace.usage()['totals']['input_tokens'],200)
        manifest=fixtures.read(Path(result['model_decisions']).parent/'binding.json')
        self.assertEqual(manifest['round'],1)

    def test_unseen_decision_citation_is_not_repaired(self):
        self.rejected(lambda reply:reply['decisions'][0]['evidence'][0].update(end_line=9999))
        with self.assertRaises(fixtures.CommandFailure):self.export()
        self.assertFalse((self.b.directory/'candidate-previews').exists())

    def test_foreign_claim_is_not_an_eligible_auxiliary_only_rejection(self):
        self.rejected(lambda reply:reply['decisions'][0].update(review_id='unassigned'))
        with self.assertRaisesRegex(ValueError,'no eligible'):self.export()

    def test_same_claim_lookup_and_decision_cannot_be_previewed_as_settled(self):
        def research(reply):
            rid=reply['decisions'][0]['review_id']
            reply['lookups']=[{'question_id':'closure','review_ids':[rid],'question':'What remains to decide this claim?',
                'queries':[{'tool':'source','review_id':rid,'purpose':'Read deciding code.',
                            'arguments':{'path':'app.js','start_line':1,'end_line':2}}]}]
        self.rejected(research)
        with self.assertRaises(fixtures.CommandFailure):self.export()

    def test_changed_private_reply_is_not_accepted_even_after_existing_preview(self):
        self.rejected();self.export()
        p=self.log/'response.json';v=fixtures.read(p);v['decisions'][0]['summary']='Changed paid decision.'
        p.write_text(json.dumps(v))
        with self.assertRaises(fixtures.CommandFailure):self.export()

    def test_changed_manifest_is_rejected_by_recorded_call_digest(self):
        self.rejected();p=next(self.session.glob('reply-candidate-*.json'));v=fixtures.read(p)
        v['response_sha256']='0'*64;p.write_text(json.dumps(v))
        with self.assertRaises(fixtures.CommandFailure):self.export()

    def test_changed_dispatch_assignment_is_rejected(self):
        self.rejected();p=self.log/'dispatched-task.json';v=fixtures.read(p);v['review_ids']=[]
        p.write_text(json.dumps(v))
        with self.assertRaises(fixtures.CommandFailure):self.export()

    def test_missing_receipt_cannot_be_treated_as_free_or_inferred(self):
        self.rejected();(self.session/'provider-metrics.jsonl').unlink()
        with self.assertRaises(fixtures.CommandFailure):self.export()
        self.assertEqual(self.b.workspace.usage()['calls'],1)

    def test_changed_receipt_cannot_reprice_a_candidate(self):
        self.rejected();p=self.session/'provider-metrics.jsonl';r=json.loads(p.read_text())
        r['usage']['input_tokens']=0;p.write_text(json.dumps(r)+'\n')
        with self.assertRaises(fixtures.CommandFailure):self.export()

    def test_unknown_usage_is_not_eligible(self):
        self.rejected(unknown=True)
        with self.assertRaises(fixtures.CommandFailure):self.export()
        self.assertIsNone(self.b.workspace.usage()['totals']['cached_input_tokens'])

    def test_changed_working_context_or_retired_session_is_not_current(self):
        self.rejected()
        self.b.apply('later-question',{'kind':'question','question_id':'later','review_ids':self.ids,
                                     'question':'Does a new condition change this decision?'})
        with self.assertRaisesRegex(ValueError,'context changed'):self.export()
        self.b.prepare('initial',self.f.config_path,'replacement',self.sid)
        with self.assertRaisesRegex(ValueError,'retired'):self.export()

    def test_preview_failure_after_native_validation_does_not_apply_any_state(self):
        self.rejected();before=self.b.workspace.snapshot()
        import review_workspace_bridge as module
        write=module.worker.write
        def interrupted(path,value):
            if Path(path).name=='preview.json':raise RuntimeError('interrupted preview publication')
            return write(path,value)
        with patch.object(module.worker,'write',side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError,'publication'):self.export()
        self.assertEqual(before,self.b.workspace.snapshot())
        self.assertEqual(self.export()['status'],'candidate_only')


if __name__=='__main__':unittest.main()
