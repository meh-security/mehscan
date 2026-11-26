"""Fresh native-bound closure under an unchanged final-call allowance."""
from argparse import Namespace
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_bridge as fixtures
import test_workspace_actions as action_fixtures
from review_workspace import MAX_CONTEXT_BYTES
from review_workspace_bridge import NativeWorkspace


class ConsumerBridgeTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.NativeBridgeTests(methodName='test_rejected_completed_reply_still_records_usage')
        f.extra_source={'app.js':"import { normalize } from './helper.js';\n"
            "export function first(request) { return eval(request.query.code); }\n"
            "export function second(request) { return eval(normalize(request.body.code)); }\n"
            "export function third(request) { return eval(request.query.extra); }\n",
            'helper.js':'export function normalize(input) { return String(input); }\n'}
        f.setUp();self.addCleanup(f.doCleanups)
        f.experiment.update(protocol='workspace-actions-v2',context_max_bytes=MAX_CONTEXT_BYTES)
        f.limits.update(model_calls=6,queries=8)
        self.f=f;self.bridge=f.create()
        self.a=action_fixtures.WorkspaceActionTests(methodName='test_v2_provider_packet_delivers_bound_common_api_policy_without_bookkeeping')
        self.a.fixture=f;self.a.bridge=self.bridge;self.a.calls=[]
        self.claims=sorted(self.bridge.workspace.snapshot()['claims'].values(),key=lambda c:c['line'])

    def partial(self):
        first,second,third=self.claims;b=self.bridge
        b.apply('shared',{'kind':'question','question_id':'shared','review_ids':[first['review_id'],second['review_id']],
                         'question':'Does the inspected helper constrain the selected input grammar?'})
        proof=b.apply('known-helper',{'kind':'source','path':'helper.js','start_line':1,'end_line':1,
                                     'review_id':second['review_id']})['evidence_id']
        focus=b.workspace.snapshot()['work']['initial']
        b.apply('include-known-helper',{'kind':'focus','work_id':'initial','evidence_ids':sorted(set(focus['evidence_ids'])|{proof}),
                                        'proposition_ids':focus['proposition_ids']})
        for index,claim in enumerate((first,third)):
            result={**self.a.decision(claim),'checks':[],'blockers':[]}
            if claim==first:
                result['reason']='The direct caller evaluates request grammar. Condition: this registration is used; no verdict about other callers.'
            b.apply('prior-'+str(index),{'kind':'draft','result':result,'applicability':[],
                     **({'resolved_questions':['shared']}if claim==first else {})})
        return first,second,third

    def test_sixth_call_can_explicitly_reconfirm_old_consumer_and_finalize(self):
        first,second,third=self.partial();b=self.bridge;f=self.f
        prior=copy.deepcopy(b.workspace.snapshot()['claims'][first['review_id']]['draft']['result'])
        # These are synthetic observed fixture costs, not paid turns or a claim
        # that five otherwise empty investigations would be useful.
        for n in range(5):
            sid=b.apply('fixture-session-'+str(n),{'kind':'session','work_id':'initial','parent_session':None,
                        'max_bytes':MAX_CONTEXT_BYTES})['session_id']
            b.apply('fixture-call-'+str(n),{'kind':'start_call','session_id':sid})
            b.apply('fixture-usage-'+str(n),{'kind':'finish_call','call_id':'fixture-call-'+str(n),
                    'usage':{'input_tokens':10,'cached_input_tokens':0,'output_tokens':1,'elapsed_ms':1}})
        def reply(task,packet):
            self.assertEqual(task['research']['rounds_remaining'],0)
            self.assertEqual(task['research']['workspace_budget']['used']['model_calls'],5)
            self.assertEqual(set(task['review_ids']),{first['review_id'],second['review_id']})
            self.assertEqual({q['review_id']for q in packet['native_questions']},set(task['review_ids']))
            consumers=packet['workspace_evidence']['answer_consumers']
            self.assertEqual(consumers[first['review_id']]['previous_result'],prior)
            self.assertNotIn(third['review_id'],consumers)
            schema=self.a.calls[-1]['schema']
            allowed=schema['properties']['decisions']['items']['anyOf'][0]['properties']['review_id']['enum']
            self.assertEqual(set(allowed),set(task['review_ids']))
            confirmed={k:v for k,v in prior.items()if k not in ('checks','blockers')}
            # Explicit deterministic reviewer confirmation, never controller reuse.
            return {'updates':[{'kind':'answer','question_id':'shared','status':'answered',
                     'reason':'The shown helper converts text without constraining grammar.',
                     'evidence':[self.a.handle(task,packet,'helper.js')]}],
                    'lookups':[],'decisions':[confirmed,self.a.decision(second)]}
        self.a.turn('last-confirmation',reply)
        self.assertEqual(b.workspace.snapshot()['used']['model_calls'],6)
        self.assertEqual(b.workspace.snapshot()['used']['queries'],0)
        self.assertEqual(b.workspace.view('initial')['claims'],[])
        self.assertEqual(b.workspace.view('initial')['answer_consumers'],{})
        self.assertFalse(any(c['reconsideration']for c in b.workspace.snapshot()['claims'].values()))
        with self.assertRaisesRegex(ValueError,'no active'):b.prepare('initial',f.config_path,'no-seventh')
        self.assertTrue(b.finalize(first['bundle_id'])['native_validated'])
        self.assertEqual(len(self.a.calls),1)

    def test_offered_consumers_are_not_automatically_confirmed(self):
        first,second,_=self.partial();b=self.bridge;previous=copy.deepcopy(b.workspace.snapshot()['claims'][first['review_id']]['draft'])
        self.a.turn('answer-only',lambda task,packet:{'updates':[{'kind':'answer','question_id':'shared','status':'answered',
            'reason':'New helper evidence changes the shared interpretation.','evidence':[self.a.handle(task,packet,'helper.js')]}],
            'lookups':[],'decisions':[self.a.decision(second)]})
        current=b.workspace.snapshot()['claims'][first['review_id']]
        self.assertEqual(current['draft'],previous)
        self.assertTrue(current['reconsideration'])
        with self.assertRaisesRegex(ValueError,'reconsideration'):b.finalize(first['bundle_id'])

    def test_fresh_context_bound_is_explicit_and_paid_limits_do_not_grow(self):
        self.assertEqual(self.bridge.metadata['experiment']['context_max_bytes'],144*1024)
        self.assertEqual(self.bridge.workspace.snapshot()['limits'],self.f.limits)
        self.assertEqual(self.bridge.workspace.snapshot()['used']['model_calls'],0)
        target=self.f.base/'too-wide'
        args=Namespace(**{**vars(self.f.args),'directory':str(target)})
        with self.assertRaisesRegex(ValueError,'bounded checkpoint'):
            NativeWorkspace.create(args,self.f.limits,{**self.f.experiment,'context_max_bytes':MAX_CONTEXT_BYTES+1})
        self.assertFalse(target.exists())

    def test_foreign_work_consumer_cannot_be_decided_through_a_shared_question(self):
        first,second,_=self.partial();b=self.bridge
        b.apply('separate-first',{'kind':'split','work_id':'initial','new_work_id':'foreign',
                                'review_ids':[first['review_id']],'strategy':'Separate caller authority'})
        before=copy.deepcopy(b.workspace.snapshot()['claims'][first['review_id']])
        def reply(task,packet):
            self.assertEqual(task['review_ids'],[second['review_id']])
            self.assertNotIn('answer_consumers',packet['workspace_evidence'])
            self.assertEqual([q['review_id']for q in packet['native_questions']],[second['review_id']])
            return {'updates':[],'lookups':[],'decisions':[self.a.decision(first)]}
        with self.assertRaisesRegex(ValueError,'unassigned'):self.a.turn('foreign-attempt',reply)
        self.assertEqual(b.workspace.snapshot()['claims'][first['review_id']],before)
        self.assertEqual(b.workspace.snapshot()['used']['queries'],0)
        self.assertEqual(b.workspace.usage()['unobserved_calls'],0)


if __name__=='__main__':unittest.main()
