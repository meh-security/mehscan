"""Real native import/AST navigation; same-name and registry ambiguity controls."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
PRODUCT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PRODUCT/'scripts'))
import review_source_profile as profiles

class DependencySource(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.scanner=Path(os.environ.get('MEHSCAN_TEST_SCANNER',PRODUCT/'target/release/mehscan.exe'))
        self.sources={
          'app.ts':"import { Gate } from './gate';\nimport { DataStore as Store } from './selected';\n@UseGuards(Gate)\nexport class Controller {\n constructor(private data: Store) {}\n read() { return this.data.read(); }\n}\n",
          'gate.ts':"import { AuthGuard as SelectGuard } from '@nestjs/passport';\nexport class Gate extends SelectGuard('api') {}\n",
          'selected.ts':"export class DataStore { read() { return 'selected'; } }\n",
          'unrelated.ts':"export class DataStore { read() { return 'unrelated'; } }\n",
          'producer.ts':"import { PassportStrategy as Register } from '@nestjs/passport';\nimport { Strategy } from 'some-provider';\nexport class ActualStrategy extends Register(Strategy, 'api') { validate() { return false; } }\n",
          'registry.ts':"import { ActualStrategy } from './producer';\nexport const providers = [ActualStrategy];\n",
          'fake.ts':"// PassportStrategy(Strategy, 'api')\nconst text = \"PassportStrategy(Strategy, 'api')\";\n"}
        for path,text in self.sources.items():(self.root/path).write_text(text,encoding='utf-8')
        self.card={'review_id':'one','anchor':{'location':{'path':'app.ts','start_line':6,'end_line':6}}}
        self.payload={'repository':'fixture','inventory_input_fingerprint':'snapshot','review_ids':['one']}
    def lookup(self,argv):
        return json.loads(subprocess.check_output([str(self.scanner),*argv],encoding='utf-8'))
    def collect(self):
        return profiles.build_from_sweeps(self.root,self.payload,[{'reviews':[self.card]}],self.lookup,dependencies=True)
    def test_explicit_alias_receiver_and_literal_registry_keep_actual_source(self):
        result=self.collect();paths={w['path'] for t in result['profile']['targets'] for w in t['windows']}
        self.assertTrue({'gate.ts','selected.ts','producer.ts','registry.ts'}<=paths,paths)
        self.assertNotIn('unrelated.ts',paths);self.assertNotIn('fake.ts',paths)
        self.assertTrue(any(r['status']=='registration_declaration_provider_unproven' for r in result['trace']))
        self.assertNotIn('decision',json.dumps(result))
    def test_two_registrations_remain_candidates_and_dynamic_key_is_not_guessed(self):
        (self.root/'other.ts').write_text(self.sources['producer.ts'].replace('ActualStrategy','OtherStrategy'),encoding='utf-8')
        result=self.collect()
        candidates={r['path'] for r in result['trace'] if r['status']=='registration_declaration_provider_unproven'}
        self.assertEqual(candidates,{'producer.ts','other.ts'})
        (self.root/'gate.ts').write_text(self.sources['gate.ts'].replace("'api'",'configuredKey'),encoding='utf-8')
        result=self.collect()
        self.assertFalse(any(r['status']=='registration_declaration_provider_unproven' for r in result['trace']))
    def test_decorator_anchor_follows_invoked_member_before_passive_types(self):
        unused=''.join("import { T%d } from './type%d';\n"%(i,i) for i in range(10))
        for i in range(10):(self.root/('type%d.ts'%i)).write_text('export class T%d {}\n'%i,encoding='utf-8')
        text=unused+self.sources['app.ts'].replace(" read() { return this.data.read(); }", " @Action()\n read("+','.join('a%d: T%d'%(i,i) for i in range(10))+") { return this.data.read(); }")
        (self.root/'app.ts').write_text(text,encoding='utf-8')
        # Large implementation requires an exact member window, not whole-file loading.
        (self.root/'selected.ts').write_text('// filler\n'*410+self.sources['selected.ts'],encoding='utf-8')
        first=next(i for i,line in enumerate(text.splitlines(),1) if '@Action()' in line)
        self.card['anchor']['location'].update(start_line=first,end_line=first+1)
        result=self.collect();windows=result['profile']['targets'][0]['windows']
        self.assertEqual(windows[0]['path'],'selected.ts')
        self.assertEqual(windows[0]['start_line'],411)
    def test_failed_navigation_stays_explicit_and_does_not_invent_source(self):
        def failed(argv):raise subprocess.CalledProcessError(1,argv)
        result=profiles.build_from_sweeps(self.root,self.payload,[{'reviews':[self.card]}],failed,dependencies=True)
        self.assertIsNone(result['profile'])
        self.assertTrue(any(r['status']=='dependency_navigation_failed' for r in result['trace']))

    def test_shared_guard_chain_survives_many_unrelated_invoked_services(self):
        cards=[];ids=[]
        for i in range(4):
            rid='caller'+str(i);ids.append(rid)
            declarations=''.join("import { S%d } from './service%d';\n"%(j,j) for j in range(i*3,i*3+3))
            for j in range(i*3,i*3+3):
                (self.root/('service%d.ts'%j)).write_text('export class S%d { run() { return %d; } }\n'%(j,j),encoding='utf-8')
            text=declarations+"import { Gate } from './gate';\n@UseGuards(Gate)\nexport class C%d {\n"%i
            text+=' constructor('+','.join('private s%d: S%d'%(j,j) for j in range(i*3,i*3+3))+') {}\n'
            text+=' run() { '+''.join('this.s%d.run();'%j for j in range(i*3,i*3+3))+' }\n}\n'
            path='caller%d.ts'%i;(self.root/path).write_text(text,encoding='utf-8')
            cards.append({'review_id':rid,'anchor':{'captures':{'operation':'run'},'location':{'path':path,'start_line':8,'end_line':8}}})
        payload={**self.payload,'review_ids':ids}
        result=profiles.build_from_sweeps(self.root,payload,[{'reviews':cards}],self.lookup,
                                          dependencies=True,dependency_chains=True)
        windows=result['profile']['targets'][0]['windows'];paths={w['path'] for w in windows}
        self.assertTrue({'gate.ts','producer.ts','registry.ts'}<=paths)
        self.assertTrue({'service0.ts','service3.ts','service6.ts','service9.ts'}<=paths)
        self.assertLessEqual(len(windows),8)
        groups=[r for r in result['trace'] if r.get('kind')=='credential_registration' and r['status']=='source_chain_delivered']
        self.assertEqual({g['review_id'] for g in groups},set(ids))
        self.assertEqual(sum(g['reused'] for g in groups),3)
        self.assertTrue(all(len(g['delivered_windows'])==3 and g['question'] for g in groups))
        profiles.prepare(self.root,result['profile'],ids,'snapshot')

    def test_oversized_registration_chain_is_not_partially_selected(self):
        # No strategy is preferred merely because it happens to sort first.
        for i in range(8):
            (self.root/('alternative%d.ts'%i)).write_text(self.sources['producer.ts'].replace('ActualStrategy','Alternative%d'%i),encoding='utf-8')
        result=profiles.build_from_sweeps(self.root,self.payload,[{'reviews':[self.card]}],self.lookup,
                                          dependencies=True,dependency_chains=True)
        windows=result['profile']['targets'][0]['windows']
        self.assertEqual({w['path'] for w in windows},{'selected.ts'})
        omitted=[r for r in result['trace'] if r.get('kind')=='credential_registration' and r['status']=='source_chain_omitted']
        self.assertEqual(omitted[0]['reason'],'window_count_bound')
        self.assertEqual(omitted[0]['delivered_windows'],[])
        self.assertGreater(len(omitted[0]['requested_windows']),8)

    def test_chain_profiles_retain_hash_and_caller_scope_guards(self):
        result=profiles.build_from_sweeps(self.root,self.payload,[{'reviews':[self.card]}],self.lookup,
                                          dependencies=True,dependency_chains=True)
        with self.assertRaisesRegex(ValueError,'membership'):
            profiles.check_bundles(result['profile'],[['different']])
        (self.root/'producer.ts').write_text('export const changed = true;\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'changed'):
            profiles.prepare(self.root,result['profile'],['one'],'snapshot')

    def test_chain_byte_limit_keeps_other_work_without_partial_credentials(self):
        for i in range(5):
            path='producer.ts' if i==0 else 'candidate%d.ts'%i
            text=self.sources['producer.ts'].replace('ActualStrategy','Candidate%d'%i)+'// '+'x'*14000+'\n'
            (self.root/path).write_text(text,encoding='utf-8')
        result=profiles.build_from_sweeps(self.root,self.payload,[{'reviews':[self.card]}],self.lookup,
                                          dependencies=True,dependency_chains=True)
        self.assertEqual({w['path'] for w in result['profile']['targets'][0]['windows']},{'selected.ts'})
        omitted=[r for r in result['trace'] if r.get('kind')=='credential_registration' and r['status']=='source_chain_omitted']
        self.assertEqual(omitted[0]['reason'],'total_byte_bound')

    def test_missing_required_source_does_not_deliver_only_the_strategy(self):
        (self.root/'gate.ts').write_text(self.sources['gate.ts']+'// filler\n'*401,encoding='utf-8')
        result=profiles.build_from_sweeps(self.root,self.payload,[{'reviews':[self.card]}],self.lookup,
                                          dependencies=True,dependency_chains=True)
        self.assertEqual({w['path'] for w in result['profile']['targets'][0]['windows']},{'selected.ts'})
        omitted=[r for r in result['trace'] if r.get('kind')=='credential_registration' and r['status']=='source_chain_omitted']
        self.assertEqual(omitted[0]['reason'],'missing_dependency_source')
        self.assertIn('gate.ts',omitted[0]['missing_paths'])

if __name__=='__main__':unittest.main()
