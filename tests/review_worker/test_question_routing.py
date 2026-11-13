"""Bound question roles with real native handoff and deterministic providers."""
import copy,json,sys,unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch
import test_work_review as work_fixture
import test_worker

worker=test_worker.worker

class Questions(unittest.TestCase):
    def prepare(self, facts=True, ai_only=False):
        fixture=work_fixture.WorkReview();self.addCleanup(fixture.doCleanups)
        f,command,path,ids=fixture.prepare()
        self.f=f
        self.expect_native_facts=not ai_only
        manifest=json.loads(path.read_text())
        # One control with both a factual proposition and an owner decision.
        manifest['items']=manifest['items'][:1]
        item=manifest['items'][0]
        if facts:
            item['checks'][0].update(route='source_fact',scope='The supplied operation only.',
                acceptance='Cite the actual input operand and evaluation call.')
        item['checks'].append(dict(id='authority',question='Does the actor cross the protected boundary?'))
        if ai_only:item['review_roles']=dict(verify=[],cover=[],context=[])
        path.write_text(json.dumps(manifest))
        primary=dict(schema_version='1',provider='codex-cli',executable_version='fixture-1',model='gpt-6-luna',reasoning_effort='medium')
        expert={**primary,'model':'gpt-6-sol'}
        providers=f.base/'provider.json';providers.write_text(json.dumps(primary))
        bounds=dict(model_calls=5,queries=20,bytes=524288,timeout_seconds=300)
        policy=dict(expert=expert,case_limits=bounds,run_limits={**bounds,'model_calls':12},max_reviews_per_job=5,audit_percent=0,audit_seed='questions')
        policy_path=f.base/'routing.json';policy_path.write_text(json.dumps(policy))
        claim=json.loads((f.base/'claim.json').read_text())['result']
        skill=test_worker.ROOT/'skills/mehscan-security'
        common=['--store',f.base/'state','--stream','source','--inventory',f.inventory,'--source-root',f.root,'--generation',claim['generation'],'--owner',claim['owner'],'--skill-root',skill]
        old=json.loads((f.base/'work.json').read_text())['payload']['plan_id']
        plan=f.native('state','plan-template','--inventory',f.inventory,'--source-root',f.root,'--policy','value','--selection','policy','--skill-root',skill,'--provider-contract',providers,'--review-orchestration',policy_path)
        plan_path=f.base/'tiered-plan.json';plan_path.write_text(json.dumps(plan))
        f.native('state','plan',*common,'--input',plan_path,'--expected-plan-id',old,'--provider-contract',providers,'--operation-key','question-plan')
        (f.base/'work.json').write_text(json.dumps(f.native('state','work',*common,'--provider-contract',providers)))
        for name,descriptor in [('routine',primary),('expert',expert)]:
            config=f.base/(name+'-config.json');config.write_text(json.dumps({**descriptor,'schema_mode':'stable'}))
            argv=[sys.executable,str(skill/'scripts/codex_reviewer.py'),'--config',str(config)]
            (f.base/(name+'-command.json')).write_text(json.dumps(argv))
        at=command.index('--reviewer-command');command[at+1]=str(f.base/'routine-command.json')
        command += ['--question-routing','--provider-contract',str(providers),'--expert-command',str(f.base/'expert-command.json')]
        return f,command

    def invoke(self,command, *, owner_unresolved=False, bad_question=False):
        calls=[];self.call_cases=[];original=worker.execute
        def execute(argv,cwd,env,timeout,payload=None,**kwargs):
            if len(argv)!=4 or not argv[1].endswith('codex_reviewer.py'):
                return original(argv,cwd,env,timeout,payload,**kwargs)
            task=json.loads(payload);packet=json.loads(Path(task['evidence_packet']).read_text())
            self.assertEqual(task['kind'],'source_review','No replacement native inference')
            q=task.get('review_role')=='question_answerer'
            case_id=packet['work_item']['id']
            self.call_cases.append((case_id,task['profile'],task['review_role']))
            if q:
                self.assertEqual(packet['native_questions'],[])
                self.assertEqual(bool(packet['supporting_native_facts']),
                    self.expected_native_by_case.get(case_id,False) if hasattr(self,'expected_native_by_case') else self.expect_native_facts)
            calls.append((task['profile'],task['review_role']))
            self.assertEqual(task['review_ids'],[] if q else task['review_ids'])
            provider=packet['job_binding']['provider']
            with Path(task['provider_metrics']).open('a') as handle:
                handle.write(json.dumps(dict(conversation_id=task['conversation_id'],round=task['research']['round'],provider=provider,elapsed_ms=1,usage=dict(input_tokens=100,cached_input_tokens=0,output_tokens=10)))+'\n')
            windows=packet['primary']['windows'];w=windows[0]
            cite=dict(path=w['path'],start_line=w['start_line'],end_line=w['start_line'])
            if q and task['research']['round']==0:
                return {'research':[dict(tool='source',review_id=None,purpose='Collect the deciding helper source.',arguments=dict(path='other/app.js',start_line=1,end_line=1))],'working_chain':'Need helper.'}
            if not q and packet.get('question_answers'):
                facts=json.loads(Path(task['shared_facts']).read_text())['facts']
                self.assertTrue(any(f['query'].get('arguments',{}).get('path')=='other/app.js' for f in facts))
                self.assertEqual(packet['question_answers'][0]['provider']['model'],'gpt-6-luna')
                self.assertNotEqual(packet['question_answers'][0]['conversation_id'],task['conversation_id'])
                if packet['question_answers'][0]['answers']:
                    self.assertEqual(packet['question_answers'][0]['answers'][0]['status'],'satisfied')
                else:
                    self.assertEqual(packet['question_answers'][0]['status'],'incomplete')
            assessment=dict(decision='not_issue',confidence='medium',summary='Fixture decision.',reason='Scoped fixture transport.',checks=[],blockers=[],evidence=[cite])
            state='unresolved' if owner_unresolved and not q else 'satisfied'
            checks=[dict(check_id=c['id'],status=state,summary='Fixture property answer.',evidence=[cite],next_deciding_fact='Unresolved actor binding.' if state=='unresolved' else None) for c in task['research']['required_checks']]
            rows=[dict(assessment,review_id=rid) for rid in task['review_ids']]
            if q and bad_question and (not isinstance(bad_question,str) or case_id==bad_question):
                rows=[dict(assessment,review_id='forbidden')]
            return {'draft':dict(results=rows,proposals=[],work_checks=checks,coverage=[{**{k:w[k] for k in ['path','start_line','end_line']},'status':'deferred' if q else 'examined','summary':'Only the named question.'} for w in windows])}
        with patch.object(worker,'execute',side_effect=execute),patch.object(sys,'argv',[worker.__file__,*command[3:]]):
            code=worker.main()
        record=json.loads((self.f.base/'worker/worker.json').read_text())
        self.assertIn(record['status'],('admitted','incomplete'),record)
        return code,calls,record

    def test_native_ai_only_fact_only_and_owner_routes_share_one_bound_run(self):
        f,command=self.prepare()
        path=Path(command[command.index('--work-plan')+1])
        plan=json.loads(path.read_text());base=plan['items'][0]
        items=[]
        for name in ('native','facts-only','owner-only','ai-only','bad-fact'):
            item=copy.deepcopy(base);item['id']=name
            if name!='native':item['review_roles']=dict(verify=[],cover=[],context=[])
            if name=='facts-only':item['checks']=item['checks'][:1]
            if name=='owner-only':item['checks']=item['checks'][1:]
            items.append(item)
        plan['items']=items
        path.write_text(json.dumps(plan))
        self.expected_native_by_case={'native':True}
        code,calls,record=self.invoke(command,owner_unresolved=True,bad_question='bad-fact')
        self.assertEqual(code,0,record)
        ledger=json.loads((f.base/'worker/source-review/work-ledger.json').read_text())
        states={row['id']:row['status'] for row in ledger['items']}
        self.assertEqual(states,{'native':'investigated_unresolved','facts-only':'closed',
            'owner-only':'investigated_unresolved','ai-only':'investigated_unresolved','bad-fact':'investigated_unresolved'})
        counts=Counter((case,profile) for case,profile,_ in self.call_cases)
        self.assertEqual(counts,Counter({('native','routine'):2,('native','expert'):1,
            ('facts-only','routine'):2,('owner-only','expert'):1,('ai-only','routine'):2,
            ('ai-only','expert'):1,('bad-fact','routine'):2,('bad-fact','expert'):1}))
        self.assertEqual(ledger['summary']['routing']['question_worker_calls'],8)
        self.assertEqual(ledger['summary']['routing']['owner_calls'],4)
        self.assertTrue((f.base/'worker/findings.json').exists())

    def test_single_call_allowance_is_reserved_for_owner(self):
        _,command=self.prepare()
        code,calls,record=self.invoke(command+['--max-calls','1'])
        self.assertEqual(code,0,record)
        self.assertEqual(calls,[('expert','investigator')],record)
        ledger=json.loads((self.f.base/'worker/source-review/work-ledger.json').read_text())
        self.assertEqual(ledger['summary']['routing']['skipped_question_checks'],1)
        self.assertEqual(ledger['summary']['routing']['question_worker_calls'],0)
        self.assertEqual(ledger['summary']['routing']['owner_calls'],1)
        note=ledger['items'][0]['question_work'][0]
        self.assertEqual(note['status'],'skipped')
        self.assertIsNone(note['conversation_id'])

if __name__=='__main__':unittest.main()
