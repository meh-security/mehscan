"""Audit recorded authority and boundaries without replaying controller code."""
import copy
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import review_workspace_audit as audit


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.root=self.base/'source';self.root.mkdir()
        self.file=self.root/'app.ts';self.file.write_text('guard();\neffect();\n')
        self.directory=self.base/'workspace';self.directory.mkdir();self.sid='a'*64
        self.result={'review_id':'settled','decision':'issue','summary':'Conditional mechanism.',
                     'reason':'Requires the selected cookie and caller.','evidence':[{'path':'app.ts','start_line':1,'end_line':2}]}
        self.evidence={'proof':{'path':'app.ts','start_line':1,'end_line':2,'file_sha256':audit.file_digest(self.file),'text':self.file.read_text()}}
        self.question={'question':'Does the accepted request reach this effect?','review_ids':['settled','active'],
            'status':'open','attempts':[],'settled_review_ids':['settled']}
        self.claims={rid:{'review_id':rid,'property':'Selected relationship','path':'app.ts','line':i,
            'draft':{'result':copy.deepcopy(self.result if rid=='settled'else {**self.result,'review_id':rid})},
            'reconsideration':['question:shared'] if rid=='settled'else []}for i,rid in enumerate(('settled','active'),1)}

    def save(self, *, consumers=False, committed=True, unknown=False, lookup=False):
        active=copy.deepcopy(self.claims['active']);active.update(draft=None,reconsideration=[])
        self.view={'claims':[active],'answer_consumers':{'settled':{'previous_result':self.result,'question_ids':['shared']}}if consumers else {},
            'questions':{'shared':self.question},'propositions':{},'applicability':{},'lookups':{},'work_id':'work',
            'budget':{'limits':{'model_calls':6,'queries':24,'source_bytes':524288},'used':{'model_calls':0,'queries':0,'source_bytes':18}}}
        self.rows=[]
        def append(key,action,result):
            rev=len(self.rows);self.rows.append((key,{'revision':rev,'action':action},{'revision':rev+1,'result':result}))
        append('old-draft',{'kind':'draft','result':self.result},{'review_id':'settled'})
        append('prepare',{'kind':'session'},{'session_id':self.sid,'packet_digest':audit.digest(self.view)})
        folder=self.directory/'sessions'/self.sid;folder.mkdir(parents=True,exist_ok=True)
        ids=['active','settled']if consumers else ['active']
        self.task={'conversation_id':self.sid,'review_ids':ids,'research':{'rounds_remaining':0}}
        packet={'native_questions':[{'review_id':rid}for rid in ids],'workspace_evidence':{'answer_consumers':self.view['answer_consumers']}}
        for name,value in [('task.json',self.task),('context.json',packet),('facts.json',{'facts':[]})]:
            (folder/name).write_text(json.dumps(value))
        artifacts={'files':{name:audit.file_digest(folder/name)for name in ('task.json','context.json','facts.json')}}
        append('attach',{'kind':'attach_session','session_id':self.sid,'artifacts':artifacts},{})
        append('call:'+self.sid,{'kind':'start_call','session_id':self.sid},{})
        usage=None if unknown else {'input_tokens':10,'cached_input_tokens':0,'output_tokens':2,'elapsed_ms':3}
        if committed:
            append('actions:'+self.sid,{'kind':'review_updates','updates':[
                {'kind':'answer','question_id':'shared','status':'answered','reason':'The condition remains explicit.','evidence':['proof']},
                {'kind':'draft','result':{**self.result,'review_id':'active'},'resolved_questions':['shared']}]},[])
        lookups={}
        if lookup:
            lid=self.sid+':0'
            action={'kind':'lookup_request','lookup_id':lid,'question_id':'shared','query':{'tool':'source','arguments':{'path':'app.ts'},'purpose':'Inspect the deciding effect.'},'units':1,'requested_question':'Does the guard dominate this effect?','review_ids':['active']}
            append('request',action,{})
            lookups[lid]={'status':'complete','evidence':['proof'],'result':{'operation':'get_source'},'received_bytes':20,'native_query_count':1}
            append('later-answer',{'kind':'answer','question_id':'shared','status':'answered','reason':'The returned guard is inspected.','evidence':['proof']},{})
        self.state={'revision':len(self.rows),'source_root':str(self.root),'binding':{'snapshot_id':'snapshot'},'claims':self.claims,
            'evidence':self.evidence,'propositions':{},'work':{'work':{'claims':list(self.claims)}},'lookups':lookups,
            'sessions':{self.sid:{'packet':self.view,'work_id':'work','artifacts':artifacts}},
            'calls':{'call:'+self.sid:{'session_id':self.sid,'usage':usage}}}
        self.publish()

    def publish(self):
        path=self.directory/'workspace.sqlite'
        with closing(sqlite3.connect(path))as db,db:
            db.executescript('DROP TABLE IF EXISTS workspace; DROP TABLE IF EXISTS receipts; CREATE TABLE workspace(id INTEGER,body TEXT); CREATE TABLE receipts(key TEXT,request TEXT,response TEXT);')
            db.execute('INSERT INTO workspace VALUES(1,?)',(json.dumps(self.state),))
            db.executemany('INSERT INTO receipts VALUES(?,?,?)',[(k,json.dumps(q),json.dumps(r))for k,q,r in self.rows])

    def test_legacy_hidden_consumers_and_final_flags_are_observed_without_replay(self):
        self.save();before=audit.file_digest(self.directory/'workspace.sqlite')
        report=audit.audit_directory(self.directory);turn=report['turns'][0]
        self.assertEqual(turn['hidden_settled_consumer_ids'],['settled'])
        self.assertFalse(turn['answer_consumers']['settled']['previous_judgment_was_delivered'])
        self.assertEqual(report['previous_judgments'][audit.digest(self.result)],self.result)
        self.assertEqual(turn['observed_after']['recorded_reconsideration']['settled'],['question:shared'])
        self.assertEqual(turn['schema_eligibility']['status'],'not_attached')
        self.assertEqual(audit.file_digest(self.directory/'workspace.sqlite'),before)

    def test_delivered_prior_result_is_not_a_confirmation(self):
        self.save(consumers=True);report=audit.audit_directory(self.directory);turn=report['turns'][0]
        self.assertEqual(turn['hidden_settled_consumer_ids'],[])
        self.assertTrue(turn['answer_consumers']['settled']['previous_judgment_was_delivered'])
        self.assertEqual([d['review_id']for d in turn['committed_decisions']],['active'])
        self.assertEqual(turn['observed_after']['active_ids'],['settled'])
        self.assertEqual(turn['draft_dependencies']['active']['resolved_questions'],['shared'])

    def test_unknown_usage_and_missing_dispatch_are_not_free_credit(self):
        self.save(unknown=True);turn=audit.audit_directory(self.directory)['turns'][0]
        self.assertEqual(turn['usage_status'],'unknown');self.assertIsNone(turn['recorded_dispatch_offer'])
        self.assertTrue(any('actual remaining credit'in gap for gap in turn['gaps']))

    def test_uncommitted_answer_file_is_not_an_accepted_decision(self):
        self.save(committed=False)
        (self.directory/'sessions'/self.sid/'answer.json').write_text(json.dumps({'workspace_actions':{'decisions':[self.result]}}))
        turn=audit.audit_directory(self.directory)['turns'][0]
        self.assertEqual(turn['committed_decisions'],[]);self.assertIsNone(turn['committed_response_revision'])

    def test_stale_source_keeps_historical_result_and_reports_its_limit(self):
        self.save();self.file.write_text('changed\n')
        report=audit.audit_directory(self.directory)
        self.assertEqual(report['source_status']['files'][0]['status'],'stale')
        self.assertEqual(report['previous_judgments'][audit.digest(self.result)],self.result)

    @unittest.skipIf(os.name == 'nt', 'POSIX directory aliases')
    def test_root_alias_preserves_source_status_without_trusting_source_links(self):
        self.save()
        alias = self.base / 'host-alias'
        alias.symlink_to(self.base.resolve(), target_is_directory=True)
        self.state['source_root'] = str(alias / 'source')
        def status():
            return audit.source_status(self.state)['files'][0]['status']
        self.assertEqual(status(), 'current')
        self.file.write_text('changed\n')
        self.assertEqual(status(), 'stale')
        self.file.unlink()
        self.assertEqual(status(), 'unavailable')
        target = self.root / 'other.ts'
        target.write_text('inside')
        self.file.symlink_to(target.resolve())
        self.assertEqual(status(), 'unavailable')
        self.file.unlink()
        outside = self.base / 'outside.ts'
        outside.write_text('outside')
        self.file.symlink_to(outside.resolve())
        self.assertEqual(status(), 'unavailable')

    def test_bound_artifact_tampering_is_rejected(self):
        self.save();(self.directory/'sessions'/self.sid/'task.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'hash differs'):audit.audit_directory(self.directory)

    def test_lookup_links_receipt_source_and_later_explicit_answer(self):
        self.save(lookup=True);turn=audit.audit_directory(self.directory)['turns'][0];lookup=turn['lookups'][0]
        self.assertEqual(lookup['charged_query_units'],1)
        self.assertEqual(lookup['returned_fact'],{'operation':'get_source'})
        self.assertEqual(lookup['evidence'][0]['path'],'app.ts')
        self.assertEqual(lookup['later_same_question_answers'][0]['shared_evidence_ids'],['proof'])
        self.assertEqual(lookup['presented_in_sessions'],[])
        self.assertEqual(len(turn['observed_after']['intervening_receipts']),1)

    def test_receipt_gap_is_visible(self):
        self.save();self.rows[0][1]['revision']=5;self.publish()
        report=audit.audit_directory(self.directory)
        self.assertTrue(report['receipt_chain_gaps']);self.assertTrue(any('incomplete'in s for s in report['turns'][0]['gaps']))

    def test_runtime_trace_append_is_outside_immutable_provider_artifacts(self):
        self.save();trace=self.directory/'bridge-trace.jsonl';trace.write_text('old\n')
        first=audit.audit_directory(self.directory);trace.write_text('old\nnew\n')
        self.assertEqual(first,audit.audit_directory(self.directory))

    def test_diagnostic_projection_has_schema_but_no_dispatch_or_new_spending(self):
        self.save(consumers=True);projection=self.base/'projection';projection.mkdir()
        packet={'work':{'review_ids':['active','settled']},'workspace_evidence':{'answer_consumers':self.view['answer_consumers']}}
        schema={'properties':{'decisions':{'items':{'anyOf':[{'properties':{'review_id':{'enum':['active','settled']}}}]}}}}
        for name,value in [('projected-view.json',self.view),('projected-packet.json',packet),('projected-schema.json',schema),('pre-answer-state.json',self.state)]:
            (projection/name).write_text(json.dumps(value))
        report=audit.audit_projection(projection);turn=report['turns'][0]
        self.assertEqual(report['kind'],'diagnostic_projection');self.assertEqual(turn['usage_status'],'diagnostic_only')
        self.assertEqual(turn['recorded_calls'],[]);self.assertIsNone(turn['observed_after'])
        self.assertEqual(turn['schema_eligibility']['ids'],['active','settled'])
        packet['work']['review_ids']=['active'];(projection/'projected-packet.json').write_text(json.dumps(packet))
        with self.assertRaisesRegex(ValueError,'eligibility differs'):audit.audit_projection(projection)

    def test_next_view_is_labeled_as_a_boundary_instead_of_an_immediate_post_state(self):
        self.save();sid='b'*64;view=copy.deepcopy(self.view)
        view['claims']=[copy.deepcopy(self.claims['settled'])]
        n=len(self.rows)
        self.rows.append(('next-prepare',{'revision':n,'action':{'kind':'session'}},
            {'revision':n+1,'result':{'session_id':sid,'packet_digest':audit.digest(view)}}))
        self.state['revision']=n+1;self.state['sessions'][sid]={'packet':view,'work_id':'work'};self.publish()
        turn=audit.audit_directory(self.directory,self.sid)['turns'][0]
        self.assertEqual(turn['observed_after']['kind'],'next_same_work_prepared_view')
        self.assertEqual(turn['observed_after']['active_ids'],['settled'])
        self.assertEqual(turn['ordinal'],1)

    def test_unsafe_source_path_is_not_followed(self):
        self.save();self.state['evidence']['proof']['path']='../outside.ts';self.publish()
        self.assertEqual(audit.audit_directory(self.directory)['source_status']['files'][0]['status'],'unavailable')

    def test_focus_and_markdown_keep_qualifications_and_clear_authority(self):
        self.save();report=audit.audit_directory(self.directory,self.sid);text=audit.render(report)
        self.assertIn('Requires the selected cookie and caller.',text)
        self.assertIn('no runtime revalidation',text);self.assertIn('app.ts:2',text)
        self.assertIn('| Turn |',text)
        with self.assertRaisesRegex(ValueError,'unknown saved session'):audit.audit_directory(self.directory,'../other')


if __name__=='__main__':unittest.main()
