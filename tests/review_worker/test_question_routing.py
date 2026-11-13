"""Bound question roles with real native handoff and deterministic providers."""
import copy,json,sys,unittest,sqlite3
from contextlib import closing
from collections import Counter
from pathlib import Path
from unittest.mock import patch
import test_work_review as work_fixture
import test_worker

worker=test_worker.worker

class Questions(unittest.TestCase):
    def audit_policy(self,f,command,**changes):
        policy=dict(schema_version='mehscanFactAuditPolicy/v1',max_audits=1,seed='fixed',sample_percent=100)
        policy.update(changes)
        path=f.base/'audit-policy.json';path.write_text(json.dumps(policy))
        return command+['--fact-audit-policy',str(path)]

    def test_factual_audit_uses_expert_and_separate_usage_before_owner(self):
        f,command=self.prepare()
        rates=f.base/'rates.json';rates.write_text(json.dumps(dict(currency='USD',models={model:dict(
            input_per_million='1',cached_input_per_million='0.1',output_per_million='2') for model in ('gpt-6-luna','gpt-6-sol')})))
        code,calls,record=self.invoke(self.audit_policy(f,command)+['--cost-rates',str(rates)])
        self.assertEqual(code,0,record)
        self.assertEqual(calls,[('routine','question_answerer')]*2+[('expert','fact_auditor'),('expert','investigator')])
        stage=f.base/'worker/source-review'
        ledger=json.loads((stage/'work-ledger.json').read_text())
        routing=ledger['summary']['routing']
        self.assertEqual((routing['question_worker_calls'],routing['owner_calls'],routing['factual_audit_calls']),(2,1,1))
        self.assertEqual(routing['factual_audit_outcomes'],{'supported':1})
        self.assertTrue(ledger['items'][0]['usage_complete'])
        self.assertEqual(ledger['items'][0]['usage']['input_tokens'],400)
        self.assertEqual(json.loads((stage/'budget.json').read_text())['reserved_calls'],4)
        self.assertEqual(json.loads((stage/'summary.json').read_text())['calls'],4)
        self.assertTrue(ledger['items'][0]['factual_audits'][0]['selection']['reasons'])
        audit=ledger['items'][0]['factual_audits'][0]
        self.assertEqual(audit['usage'],dict(input_tokens=100,cached_input_tokens=0,output_tokens=10))
        self.assertEqual(audit['estimated_cost_micros'],120)
        self.assertGreaterEqual(audit['seconds'],0)

    def test_optional_audit_defers_to_original_owner_reservation(self):
        f,command=self.prepare()
        path=Path(command[command.index('--work-plan')+1]);plan=json.loads(path.read_text())
        plan['items'][0]['estimate']['owner_calls']=[1,1];path.write_text(json.dumps(plan))
        code,calls,record=self.invoke(self.audit_policy(f,command)+['--max-calls','3'])
        self.assertEqual(code,0,record)
        self.assertEqual(calls,[('routine','question_answerer')]*2+[('expert','investigator')])
        ledger=json.loads((f.base/'worker/source-review/work-ledger.json').read_text())
        self.assertEqual(ledger['summary']['routing']['factual_audit_calls'],0)
        self.assertEqual(ledger['items'][0]['factual_audits'][0]['outcome'],'incomplete')
        audit=ledger['items'][0]['factual_audits'][0]
        self.assertEqual(audit['calls'],0)
        self.assertEqual(ledger['items'][0]['completion_reservation']['consumed'],1)

    def test_challenge_suspends_only_unsent_matching_pattern(self):
        f,command=self.prepare()
        path=Path(command[command.index('--work-plan')+1]);plan=json.loads(path.read_text())
        base=plan['items'][0];items=[]
        for name,pattern in [('a','guard-return'),('b','guard-return'),('c','another-pattern')]:
            item=copy.deepcopy(base);item['id']=name
            item['checks'][0]['routing_pattern']=pattern
            if name!='a':item['review_roles']=dict(verify=[],cover=[],context=[])
            items.append(item)
        plan['items']=items;path.write_text(json.dumps(plan))
        self.expected_native_by_case={'a':True}
        command=self.audit_policy(f,command,suspend_patterns=True,sample_percent=0,
            checks=[dict(case_id='a',check_id='execution',reason='Inspect an omitted branch.')])
        code,calls,record=self.invoke(command,audit_state='violated')
        self.assertEqual(code,0,record)
        counts=Counter((case,role) for case,_,role in self.call_cases)
        self.assertEqual(counts[('a','fact_auditor')],1)
        self.assertEqual(counts[('b','question_answerer')],0)
        self.assertEqual(counts[('c','question_answerer')],2)
        self.assertEqual(len(calls),8)
        stage=f.base/'worker/source-review'
        with closing(sqlite3.connect(stage/'case-state.sqlite')) as db:
            state=json.loads(db.execute('SELECT body FROM workspace').fetchone()[0])
        self.assertEqual(set(state['suspended_patterns']),{'guard-return'})
        self.assertTrue(any(history[-1]['status']=='disputed' for history in state['assertions'].values()))
        self.assertEqual(state['cases']['a']['dependencies']['authority'],[],
            'Owner must use an independent source proof after a challenge, not the disputed version')

    def test_saved_audit_draft_recovers_without_repeating_factual_or_audit_calls(self):
        f,command=self.prepare();command=self.audit_policy(f,command)
        original=worker.write;stopped=[]
        def write(path,value):
            original(path,value)
            if Path(path).name=='recovery.json' and value.get('phase')=='draft' and not stopped:
                packet=json.loads((Path(path).parent/'context.json').read_text())
                if packet['job_binding']['role']=='fact_auditor':
                    stopped.append(True)
                    raise KeyboardInterrupt()
        with patch.object(worker,'write',side_effect=write):
            with self.assertRaises(KeyboardInterrupt):self.invoke(command)
        self.assertEqual(len(self.call_cases),3)
        resumed=list(command);resumed[resumed.index('--output')+1]=str(f.base/'recovered')
        resumed+=['--resume-from',str(f.base/'worker')]
        code,calls,record=self.invoke(resumed)
        self.assertEqual(code,0,record)
        self.assertEqual(calls,[('expert','investigator')])
        stage=f.base/'recovered/source-review'
        summary=json.loads((stage/'summary.json').read_text())
        self.assertEqual(summary['calls'],4)
        self.assertEqual(summary['recovery']['new_receipted_calls'],1)
        self.assertEqual(json.loads((stage/'work-ledger.json').read_text())['summary']['routing']['factual_audit_calls'],1)

    def test_challenged_factual_only_answer_cannot_close_without_owner_resolution(self):
        f,command=self.prepare(ai_only=True)
        path=Path(command[command.index('--work-plan')+1]);plan=json.loads(path.read_text())
        plan['items'][0]['checks']=plan['items'][0]['checks'][:1];path.write_text(json.dumps(plan))
        code,calls,record=self.invoke(self.audit_policy(f,command),audit_state='violated')
        self.assertEqual(code,2,record)
        self.assertEqual(calls,[('routine','question_answerer')]*2+[('expert','fact_auditor')])
        ledger=json.loads((f.base/'worker/source-review/work-ledger.json').read_text())
        self.assertEqual(ledger['summary']['closed'],0)
        self.assertEqual(ledger['summary']['routing']['factual_audit_calls'],1)

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
                task_kind='bounded_proposition', usefulness='Prepares the owner input-binding decision.',
                acceptance='Cite the actual input operand and evaluation call.',
                source_ranges=[dict(path=item['owner_path'], start_line=item['start_line'], end_line=item['end_line'])])
        item['checks'].append(dict(id='authority',question='Does the actor cross the protected boundary?'))
        if ai_only:item['review_roles']=dict(verify=[],cover=[],context=[])
        path.write_text(json.dumps(manifest))
        primary=dict(schema_version='1',provider='codex-cli',executable_version='fixture-1',model='gpt-6-luna',reasoning_effort='medium')
        expert={**primary,'model':'gpt-6-sol'}
        providers=f.base/'provider.json';providers.write_text(json.dumps(primary))
        bounds=dict(model_calls=5,queries=20,bytes=524288,timeout_seconds=300)
        policy=dict(expert=expert,case_limits=bounds,run_limits={**bounds,'model_calls':16},max_reviews_per_job=5,audit_percent=0,audit_seed='questions')
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

    def invoke(self,command, *, owner_unresolved=False, bad_question=False, owner_lookup=False, audit_state='satisfied'):
        calls=[];self.call_cases=[];original=worker.execute
        def execute(argv,cwd,env,timeout,payload=None,**kwargs):
            if len(argv)!=4 or not argv[1].endswith('codex_reviewer.py'):
                return original(argv,cwd,env,timeout,payload,**kwargs)
            task=json.loads(payload);packet=json.loads(Path(task['evidence_packet']).read_text())
            self.assertEqual(task['kind'],'source_review','No replacement native inference')
            q=task.get('review_role')=='question_answerer'
            audit=task.get('review_role')=='fact_auditor'
            case_id=packet['work_item']['id']
            self.call_cases.append((case_id,task['profile'],task['review_role']))
            if q or audit:
                self.assertEqual(packet['native_questions'],[])
                self.assertEqual(bool(packet['supporting_native_facts']),
                    self.expected_native_by_case.get(case_id,False) if hasattr(self,'expected_native_by_case') else self.expect_native_facts)
            calls.append((task['profile'],task['review_role']))
            self.assertEqual(task['review_ids'],[] if q else task['review_ids'])
            provider=packet['job_binding']['provider']
            if audit:
                self.assertEqual(task['profile'],'expert')
                self.assertEqual(packet['factual_audit']['version'],task['research']['factual_audit']['version'])
                self.assertTrue(packet['factual_audit']['original_answer']['answers'])
            with Path(task['provider_metrics']).open('a') as handle:
                handle.write(json.dumps(dict(conversation_id=task['conversation_id'],round=task['research']['round'],provider=provider,elapsed_ms=1,usage=dict(input_tokens=100,cached_input_tokens=0,output_tokens=10)))+'\n')
            windows=packet['primary']['windows'];w=windows[0]
            cite=dict(path=w['path'],start_line=w['start_line'],end_line=w['start_line'])
            named = q and bool(task['research']['required_checks'][0].get('source_definitions'))
            if named:
                facts=json.loads(Path(task['shared_facts']).read_text())['facts']
                helper=[f for f in facts if f['query'].get('arguments',{}).get('path')=='other/app.js']
                self.assertTrue(helper)
                self.assertIn('function run(request)', helper[-1]['result']['results']['text'])
                cite=dict(path='other/app.js',start_line=1,end_line=4)
            if q and not named and task['research']['round']==0:
                return {'research':[dict(tool='source',review_id=None,purpose='Collect the deciding helper source.',arguments=dict(path='other/app.js',start_line=1,end_line=1))],'working_chain':'Need helper.'}
            if not q and not audit and packet.get('question_answers'):
                facts=json.loads(Path(task['shared_facts']).read_text())['facts']
                self.assertTrue(any(f['query'].get('arguments',{}).get('path')=='other/app.js' for f in facts))
                self.assertEqual(packet['question_answers'][0]['provider']['model'],'gpt-6-luna')
                self.assertNotEqual(packet['question_answers'][0]['conversation_id'],task['conversation_id'])
                if packet['question_answers'][0]['answers']:
                    self.assertEqual(packet['question_answers'][0]['answers'][0]['status'],'satisfied')
                else:
                    self.assertEqual(packet['question_answers'][0]['status'],'incomplete')
            if not q and owner_lookup and task['research']['round'] == 0:
                return {'research':[dict(tool='source',review_id=None,purpose='Read the remaining deciding expression.',
                    arguments=dict(path='other/app.js',start_line=2,end_line=2))],'working_chain':'Need the effect expression.'}
            assessment=dict(decision='not_issue',confidence='medium',summary='Fixture decision.',reason='Scoped fixture transport.',checks=[],blockers=[],evidence=[cite])
            state=audit_state if audit else 'unresolved' if owner_unresolved and not q else 'satisfied'
            checks=[dict(check_id=c['id'],status=state,summary='Fixture property answer.',evidence=[cite],next_deciding_fact='Unresolved actor binding.' if state=='unresolved' else None) for c in task['research']['required_checks']]
            if 'available_assertions' in task['research']:
                for check in checks:
                    check['assertion_dependencies'] = task['research']['available_assertions'] if check['check_id'] == 'authority' else []
            rows=[dict(assessment,review_id=rid) for rid in task['review_ids']]
            if q and bad_question and (not isinstance(bad_question,str) or case_id==bad_question):
                rows=[dict(assessment,review_id='forbidden')]
            return {'draft':dict(results=rows,proposals=[],work_checks=checks,coverage=[{**{k:w[k] for k in ['path','start_line','end_line']},'status':'deferred' if q or audit else 'examined','summary':'Only the named question.'} for w in windows])}
        with patch.object(worker,'execute',side_effect=execute),patch.object(sys,'argv',[worker.__file__,*command[3:]]):
            code=worker.main()
        record=json.loads((Path(command[command.index('--output')+1])/'worker.json').read_text())
        self.assertIn(record['status'],('admitted','incomplete'),record)
        return code,calls,record

    def test_saved_factual_answers_survive_interruption_before_owner(self):
        for boundary in ('owner_start', 'owner_draft', 'research'):
            with self.subTest(boundary=boundary):
                f,command=self.prepare()
                original=worker.write
                stopped=[]
                def write(path,value):
                    original(path,value)
                    owner_start=(Path(path).name=='context.json' and value.get('job_binding',{}).get('profile')=='expert')
                    owner_draft=(Path(path).name=='recovery.json' and value.get('phase')=='draft'
                        and (value.get('provider') or {}).get('model')=='gpt-6-sol')
                    research=(Path(path).name=='recovery.json' and value.get('phase')=='ready'
                        and value.get('turn')==1 and (value.get('provider') or {}).get('model')=='gpt-6-luna')
                    if not stopped and {'owner_start':owner_start, 'owner_draft':owner_draft, 'research':research}[boundary]:
                        stopped.append(True)
                        raise KeyboardInterrupt()
                with patch.object(worker,'write',side_effect=write):
                    with self.assertRaises(KeyboardInterrupt):
                        self.invoke(command)
                expected=2 if boundary=='research' else 3
                self.assertEqual(len(self.call_cases),{'owner_start':2, 'owner_draft':3, 'research':1}[boundary])
                parent=f.base/'worker/source-review'
                with closing(sqlite3.connect(parent/'case-state.sqlite')) as db:
                    old=json.loads(db.execute('SELECT body FROM workspace').fetchone()[0])
                resumed=list(command)
                resumed[resumed.index('--output')+1]=str(f.base/'recovered')
                resumed+=['--resume-from',str(f.base/'worker')]
                code,calls,record=self.invoke(resumed)
                self.assertEqual(code,0,record)
                self.assertEqual(calls,[] if boundary=='owner_draft' else [('expert','investigator')])
                stage=f.base/'recovered/source-review'
                with closing(sqlite3.connect(stage/'case-state.sqlite')) as db:
                    new=json.loads(db.execute('SELECT body FROM workspace').fetchone()[0])
                self.assertEqual(new['assertions'],old['assertions'])
                self.assertEqual(bool(new['cases']['lower']['dependencies']['authority']),boundary!='research')
                summary=json.loads((stage/'summary.json').read_text())
                self.assertEqual(summary['calls'],expected)
                self.assertEqual(summary['unknown_provider_calls'],0)
                budget=json.loads((parent/'budget.json').read_text())
                self.assertEqual(budget['reserved_calls'],expected)
                self.assertEqual(len((stage/'provider-metrics.jsonl').read_text().splitlines()),expected)
                self.assertEqual(summary['recovery']['new_receipted_calls'],len(calls))

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
        with closing(sqlite3.connect(f.base/'worker/source-review/case-state.sqlite')) as db:
            state = json.loads(db.execute('SELECT body FROM workspace').fetchone()[0])
        self.assertEqual(len(state['assertions']), 3)
        self.assertTrue(state['cases']['native']['dependencies']['authority'])
        self.assertEqual(state['cases']['owner-only']['dependencies']['authority'], [])
        self.assertTrue(state['cases']['facts-only']['questions']['execution']['assertions'])
        self.assertTrue(next(row for row in ledger['items'] if row['id']=='native')['provisional_fact_answers'])
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

    def test_expert_owner_empty_fast_queue_makes_no_extra_calls(self):
        f, command = self.prepare()
        code, calls, record = self.invoke(command + ['--second-pass', 'fast', '--max-calls', '1'])
        self.assertEqual(code, 0, record)
        self.assertEqual(calls, [('expert','investigator')])
        audit = json.loads((f.base/'worker/second-pass.json').read_text())
        self.assertEqual(audit['accounting']['second_pass']['calls'], 0)
        summary=json.loads((f.base/'worker/source-review/summary.json').read_text())
        self.assertEqual(Path(summary['effective_args']['reviewer_command']), f.base/'expert-command.json')

    def test_completion_reserves_two_owner_turns_after_optional_preparation(self):
        f, command = self.prepare()
        code, calls, record = self.invoke(command + ['--max-calls', '3'], owner_lookup=True)
        self.assertEqual(code, 0, record)
        self.assertEqual(calls, [('routine','question_answerer'), ('expert','investigator'), ('expert','investigator')])
        ledger=json.loads((f.base/'worker/source-review/work-ledger.json').read_text())
        row=ledger['items'][0]
        self.assertEqual(row['status'], 'closed')
        self.assertEqual(row['question_work'][0]['status'], 'incomplete')
        self.assertEqual(row['completion_reservation']['granted'], 2)
        self.assertEqual(row['completion_reservation']['consumed'], 2)
        self.assertEqual(row['completion_reservation']['remaining'], 0)
        self.assertEqual(ledger['budget']['reserved_calls'], 3)

    def test_factual_kind_must_be_selected_before_delegation(self):
        f, command = self.prepare()
        path = Path(command[command.index('--work-plan')+1])
        plan = json.loads(path.read_text())
        del plan['items'][0]['checks'][0]['task_kind']
        path.write_text(json.dumps(plan))
        code, calls, record = self.invoke(command)
        self.assertEqual(code, 0, record)
        self.assertEqual(calls, [('expert','investigator')])
        ledger=json.loads((f.base/'worker/source-review/work-ledger.json').read_text())
        self.assertEqual(ledger['items'][0]['routing'][0]['effective_route'], 'owner')
        self.assertEqual(ledger['items'][0]['routing'][0]['policy_version'], 'mehscanQuestionRouting/v1')

    def test_unprepared_fact_stays_with_owner_without_routine_call(self):
        f, command = self.prepare()
        path = Path(command[command.index('--work-plan')+1])
        plan = json.loads(path.read_text())
        del plan['items'][0]['checks'][0]['source_ranges']
        path.write_text(json.dumps(plan))
        code, calls, record = self.invoke(command)
        self.assertEqual(code, 0, record)
        self.assertEqual(calls, [('expert', 'investigator')])
        ledger = json.loads((f.base/'worker/source-review/work-ledger.json').read_text())
        note = ledger['items'][0]['question_work'][0]
        self.assertEqual(note['preparation']['status'], 'not_ready')
        self.assertEqual(note['calls'], 0)
        self.assertIsNone(note['conversation_id'])

    def test_named_body_is_prepared_once_reused_and_missing_name_stays_with_owner(self):
        f, command = self.prepare()
        path = Path(command[command.index('--work-plan')+1])
        plan = json.loads(path.read_text())
        base = plan['items'][0]
        items = []
        for name, symbol in (('native', 'run'), ('reuse', 'run'), ('missing', 'doesNotExist')):
            item = copy.deepcopy(base)
            item['id'] = name
            if name != 'native':
                item['review_roles'] = dict(verify=[], cover=[], context=[])
            check = item['checks'][0]
            del check['source_ranges']
            check['source_definitions'] = [dict(path='other/app.js', name=symbol)]
            items.append(item)
        plan['items'] = items
        path.write_text(json.dumps(plan))
        self.expected_native_by_case = {'native': True}
        code, calls, record = self.invoke(command)
        self.assertEqual(code, 0, record)
        self.assertEqual(Counter(calls), Counter({('routine', 'question_answerer'):2, ('expert', 'investigator'):3}))
        ledger = json.loads((f.base/'worker/source-review/work-ledger.json').read_text())
        notes = {row['id']:row['question_work'][0] for row in ledger['items']}
        self.assertFalse(notes['native']['preparation']['definitions'][0]['reused'])
        self.assertTrue(notes['reuse']['preparation']['definitions'][0]['reused'])
        self.assertEqual(notes['missing']['preparation']['status'], 'not_ready')
        self.assertEqual(notes['missing']['calls'], 0)
        self.assertIsNone(notes['missing']['conversation_id'])
        for name in ('native', 'reuse'):
            self.assertEqual(notes[name]['calls'], 1, 'No model turn to discover the implementation')
            receipt = notes[name]['preparation']['definitions'][0]['receipt']
            self.assertTrue((f.base/'worker/source-review'/receipt).is_file())

if __name__=='__main__':unittest.main()
