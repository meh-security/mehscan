"""Export navigation through the real worker, with synthetic reviewer replies."""
from argparse import Namespace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_worker as fixture
worker, ROOT = fixture.worker, fixture.ROOT


class ExportArguments(unittest.TestCase):
    def test_bad_question_is_repairable_without_masking_source_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            valid={'tool':'export-target','review_id':'a','purpose':'Which implementation supplies guard?',
                   'arguments':{'path':'entry.ts','name':'guard'}}
            for purpose in (' ', 'q'*301, None):
                invalid={**valid,'purpose':purpose}
                with self.assertRaises(worker.ResearchBatchError) as caught:
                    worker.research_batch_arguments([valid,invalid],root,['a'],root/'journals')
                self.assertEqual(caught.exception.errors[0]['query_index'],1)
                self.assertEqual(caught.exception.errors[0]['lookup_feedback']['code'],'invalid_deciding_question')
                for query in ({**invalid,'arguments':{'path':'../entry.ts','name':'guard'}},
                              {**invalid,'review_id':'foreign'}):
                    with self.assertRaises(ValueError) as fatal:
                        worker.research_batch_arguments([valid,query],root,['a'],root/'journals')
                    self.assertNotIsInstance(fatal.exception,(worker.ResearchFilterError,worker.ResearchBatchError))
            self.assertFalse((root/'journals').exists())

    def test_exact_commands_questions_scope_and_shared_units(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root/'folder').mkdir()
            queries = [
                {'tool':'import-targets','review_id':'a','purpose':'Which module supplies the used helper?',
                 'arguments':{'path':'caller.ts'}},
                {'tool':'export-target','review_id':'b','purpose':'Which implementation supplies guard?',
                 'arguments':{'path':'entry.ts','name':'guard'}}]
            commands = worker.research_batch_arguments(queries,root,['a','b'],root/'journals',query_units_remaining=2)
            self.assertEqual(worker.research_cost(queries),2)
            for query, command in zip(queries, commands):
                self.assertEqual(command[:3],['investigate',query['tool'],str(root)])
                self.assertNotIn('--limit',command)
                self.assertEqual(command[-2:],['--journal',str(root/'journals'/(query['review_id']+'.jsonl'))])
            with self.assertRaises(worker.ResearchBatchError):
                worker.research_batch_arguments(queries,root,['a','b'],root/'journals',query_units_remaining=1)
            for change, error in [
                ({'purpose':None},ValueError),
                ({'arguments':{'path':'folder','name':'guard'}},worker.ResearchFilterError),
                ({'arguments':{'path':'../entry.ts','name':'guard'}},ValueError),
                ({'arguments':{'path':'entry.ts','name':'guard.call()'}},worker.ResearchFilterError),
                ({'arguments':{'path':'entry.ts','name':'guard','limit':20}},ValueError),
                ({'review_id':'outside'},ValueError),
            ]:
                with self.subTest(change=change), self.assertRaises(error):
                    worker.research_arguments({**queries[1],**change},root,['a','b'],root/'journals')
            no_question = dict(queries[1]);no_question.pop('purpose')
            with self.assertRaisesRegex(worker.ResearchFilterError,'purpose'):
                worker.research_arguments(no_question,root,['a','b'],root/'journals')
            self.assertFalse((root/'journals').exists())

    def test_only_exact_missing_or_unsupported_navigation_is_recoverable(self):
        for tool in ('import-targets','export-target'):
            query={'tool':tool,'arguments':{'path':'absent.ts','name':'guard'}}
            message='error: scannable text file "absent.ts" was not found under the scan root'
            result=worker.missing_source_result(query,worker.CommandFailure(2,message))
            self.assertEqual(result['error']['code'],'not_found')
            self.assertNotIn('get_source',result['operation'])
            for code, text in [(1,message),(2,message+'\npermission denied'),(2,message.replace('absent','different'))]:
                self.assertIsNone(worker.missing_source_result(query,worker.CommandFailure(code,text)))
        query={'tool':'import-targets','arguments':{'path':'app.py'}}
        result=worker.missing_source_result(query,worker.CommandFailure(2,'error: import targets currently require JavaScript or TypeScript'))
        self.assertEqual(result['error']['code'],'unsupported_language')


class ExportWorker(unittest.TestCase):
    # Reuse only the real worker fixture/operations, not its unrelated test suite.
    setUp = fixture.Worker.setUp
    native = fixture.Worker.native
    git = fixture.Worker.git
    invoke = fixture.Worker.invoke
    assert_no_decisions = fixture.Worker.assert_no_decisions
    extra_source_files = {
        'entry.ts':"export { evalGate as guard } from './helper';\n",
        'helper.ts':"export function evalGate(value: string) { return value; }\n",
        'second.js':"function other(request) { eval(request.query.code); }\n",
        'library.py':"def guard(value):\n    return value\n",
    }

    def install_reviewer(self):
        normal = self.base/'normal.py'
        normal.write_text(self.reviewer.read_text(),encoding='utf-8')
        self.reviewer.write_text('''import json,sys,subprocess
from pathlib import Path
task=json.load(sys.stdin); round=task['research']['round']; ids=task['review_ids']
if round == 0:
    queries=[{'tool':'import-targets','review_id':ids[0],'purpose':'Which modules are imported here?', 'arguments':{'path':'entry.ts'}}]
    for i,label in enumerate(('first caller','second caller')):
        queries.append({'tool':'export-target','review_id':ids[min(i,len(ids)-1)], 'purpose':'Which helper implementation serves '+label+'?', 'arguments':{'path':'entry.ts','name':'guard'}})
    queries.extend([
        {'tool':'export-target','review_id':ids[0],'purpose':'Is the separately suggested entry available?', 'arguments':{'path':'missing.ts','name':'guard'}},
        {'tool':'import-targets','review_id':ids[0],'purpose':'Can this navigation operation inspect the other language?', 'arguments':{'path':'library.py'}}])
    print(json.dumps({'research':queries}))
elif round == 1:
    results=task['research']['results']
    found=[r for r in results if r['query']['tool']=='export-target' and r['query']['arguments']['path']=='entry.ts']
    assert len(found)==2 and found[0]['result_id']==found[1]['result_id']
    candidate=found[0]['result']['results']['candidate']
    assert candidate['path']=='helper.ts' and candidate['name']=='evalGate'
    handles=task['research']['artifact_handles']; source=task['research']['source_artifact_handles']
    assert not any(handles[h]==found[0]['result_id'] for h in source)
    print(json.dumps({'research':[{'tool':'definition','review_id':ids[0], 'purpose':'Read the located implementation before assessing behavior.', 'arguments':{'path':candidate['path'],'name':candidate['name'],'limit':20}}]}))
else:
    assert any(r['result'].get('source_complete') for r in task['research']['results'])
    print(subprocess.check_output([sys.executable, NORMAL],input=json.dumps(task),text=True))
'''.replace('NORMAL',repr(str(normal))),encoding='utf-8')

    def test_navigation_reuses_source_with_separate_questions_then_reads_body(self):
        self.install_reviewer()
        result=self.invoke(extra=['--phase','native','--validate-only','--query-workers','2'])
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        directory=self.base/'worker'
        record=json.loads((directory/'worker.json').read_text())
        self.assertEqual(record['status'],'source_validated')
        rows=[json.loads(s) for s in (directory/'research.jsonl').read_text().splitlines()]
        exports=[r for r in rows if r['query']['tool']=='export-target' and r['query']['arguments']['path']=='entry.ts']
        self.assertGreaterEqual(len(exports),2)
        self.assertEqual(len({r['result_id'] for r in exports}),1)
        self.assertEqual(sum(not r['reused'] for r in exports),1)
        self.assertEqual(len({r['query']['purpose'] for r in exports}),2)
        self.assertGreater(len({r['query']['review_id'] for r in exports}),1)
        self.assertEqual({r['result']['error']['code'] for r in rows if 'error' in r['result']},{'not_found','unsupported_language'})
        self.assertEqual(record['research_queries'],sum(2 if r['query']['tool']=='definition' else 1 for r in rows))
        self.assertGreater(record['research_cache_hits'],0)
        for row in exports:
            self.assertIn(row['query']['review_id'],self.ids)
        journals=[json.loads(line) for p in (directory/'journals').glob('*.jsonl') for line in p.read_text().splitlines()]
        self.assertEqual(sum(r['operation']=='export-target' for r in journals),2)  # One success and the missing-file failure.
        self.assertEqual(sum((r.get('output') or {}).get('operation')=='get_export_target' for r in journals),1)
        self.assert_no_decisions()

    def test_transitive_source_change_is_rejected_before_facts_reach_reviewer(self):
        self.install_reviewer()
        original=worker.execute
        executed=[]
        def changing_query(command,*args,**kwargs):
            result=original(command,*args,**kwargs)
            if command[1:3]==['investigate','export-target']:
                executed.append(True)
                (self.root/'helper.ts').write_text('export function evalGate(value: string) { return "changed"; }\n')
            return result
        args=Namespace(scanner=str(self.scanner),source_root=str(self.root),inventory=str(self.inventory),
            store=str(self.store),stream='local-review',claim=str(self.claim),work_package=str(self.package),
            reviewer_command=str(self.command),reviewer_label='deterministic/medium',run=str(self.run),
            output=str(self.base/'drift'),provider_contract=None,artifact_root=None,phase='native',supersede=False,
            timeout=None,skill_root=str(ROOT/'skills/mehscan-security'),research_rounds=None,research_queries=None,research_bytes=None)
        with patch.object(worker,'execute',side_effect=changing_query):
            record=worker.run(args)
        self.assertTrue(executed)
        self.assertEqual(record['status'],'incomplete')
        self.assertFalse((self.base/'drift/research.jsonl').exists())
        facts=self.base/'drift/source-facts.json'
        self.assertFalse(facts.exists() and json.loads(facts.read_text())['facts'])
        self.assert_no_decisions()

    def test_invalid_question_repairs_once_before_any_batch_lookup(self):
        normal=self.base/'normal.py';normal.write_text(self.reviewer.read_text(),encoding='utf-8')
        self.reviewer.write_text('''import json,sys,subprocess
task=json.load(sys.stdin); round=task['research']['round']; rid=task['review_ids'][0]
q={'tool':'export-target','review_id':rid,'purpose':'Which implementation supplies guard?', 'arguments':{'path':'entry.ts','name':'guard'}}
if round==0:
    print(json.dumps({'research':[q,{**q,'purpose':'q'*301}]}))
elif round==1:
    assert not task['research']['results']
    feedback=task['research']['feedback']
    assert feedback['query_errors'][0]['lookup_feedback']['code']=='invalid_deciding_question'
    print(json.dumps({'research':[q]}))
else:
    assert len(task['research']['results'])==1
    print(subprocess.check_output([sys.executable,NORMAL],input=json.dumps(task),text=True))
'''.replace('NORMAL',repr(str(normal))),encoding='utf-8')
        result=self.invoke(extra=['--phase','native','--validate-only'])
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        record=json.loads((self.base/'worker/worker.json').read_text())
        self.assertEqual(record['research_queries'],1)
        self.assertEqual(record['research_executions'],1)
        self.assert_no_decisions()


if __name__=='__main__':unittest.main()
