"""Review-package fidelity, scoped interpretations and unchanged native results."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace as fixtures
from review_workspace import Workspace, captured_source_rows, identity, render_review_package


class ReviewPackageTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.WorkspaceTests()
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.workspace=self.f.workspace
        self.evidence=self.f.capture(1,4)

    def result(self, claim, decision='not_issue'):
        line=next(c['line'] for c in self.f.claims if c['review_id']==claim)
        return {'review_id':claim,'decision':decision,'confidence':'high','summary':'Selected relationship assessed.',
                'reason':'The remaining permission evaluator is unread.' if decision=='needs_review' else 'Local relationship established.',
                'checks':['Does the permission evaluator reject the selected keys?'] if decision=='needs_review' else [],
                'blockers':['Permission composition remains unread.'] if decision=='needs_review' else [],
                'source_leads':[], 'diagnosis':None,
                'evidence':[{'path':'routes.ts','start_line':line,'end_line':line}]}

    def draft_all(self, dependencies=None, applies=None, decisions=None):
        for claim in self.f.claims:
            rid=claim['review_id']
            self.f.apply('draft',result=self.result(rid,(decisions or {}).get(rid,'not_issue')),
                         applicability=(applies or {}).get(rid,[]),propositions=(dependencies or {}).get(rid,[]))

    def test_same_response_qualification_survives_without_rewriting_verdict_or_blockers(self):
        self.f.proposition(self.evidence,statement='Checks use post-hook keys; storage still uses original keys.')
        aid=self.f.applicability('safe',self.evidence)
        self.f.apply('question',question_id='permission',review_ids=['safe'],question='Does the permission evaluator reject the selected keys?')
        self.f.apply('answer',question_id='permission',status='blocked',reason='Permission composition remains unread.',evidence=[self.evidence])
        self.draft_all(dependencies={'safe':[{'proposition_id':'body-owner','revision':1}]},
                       applies={'safe':[aid]},decisions={'safe':'needs_review'})
        before=self.workspace.snapshot();draft=self.workspace.bundle_draft('bundle-1')
        package=self.workspace.review_package();text=render_review_package(package)
        self.assertEqual([c['result'] for c in package['claims']],draft['results'])
        claim=next(c for c in package['claims'] if c['review_id']=='safe')
        self.assertEqual(claim['result'],self.result('safe','needs_review'))
        note=package['notes'][claim['reviewer_notes'][0]['note_id']]
        self.assertEqual(note['conditions'],'Middleware runs before effect')
        self.assertEqual(note['exclusions'],'Route parameters are not constrained')
        self.assertIn('storage still uses original keys',text)
        self.assertIn('Permission composition remains unread.',text)
        self.assertEqual(package['evidence'][self.evidence]['file_sha256'],before['evidence'][self.evidence]['file_sha256'])
        self.assertEqual(self.workspace.snapshot(),before)
        self.assertEqual(package,self.workspace.review_package())

    def test_context_dependency_is_not_applicability_and_unlinked_notes_are_excluded(self):
        self.f.proposition(self.evidence)
        self.f.apply('proposition',proposition_id='unrelated',statement='Unrelated interpretation.',scope='different effect',
                     conditions='Unknown',exclusions='Not this caller',evidence=[self.evidence])
        self.draft_all(dependencies={'unsafe':[{'proposition_id':'body-owner','revision':1}]})
        package=self.workspace.review_package()
        claims={c['review_id']:c for c in package['claims']}
        self.assertFalse(claims['safe']['reviewer_notes'])
        self.assertEqual(claims['unsafe']['reviewer_notes'][0]['relationship'],'context_only')
        self.assertFalse(claims['unsafe']['reviewer_notes'][0]['applicability_ids'])
        self.assertEqual([n['proposition_id'] for n in package['notes'].values()],['body-owner'])
        self.assertIn('context only; applicability not recorded',render_review_package(package))

    def test_explicit_applicability_without_context_dependency_is_retained(self):
        self.f.proposition(self.evidence);aid=self.f.applicability('safe',self.evidence)
        self.draft_all(applies={'safe':[aid]})
        package=self.workspace.review_package()
        safe=next(c for c in package['claims'] if c['review_id']=='safe')
        self.assertEqual(safe['reviewer_notes'][0]['relationship'],'caller_applicability_recorded')
        self.assertEqual(package['applicability'][aid]['review_id'],'safe')
        self.assertEqual(len(package['evidence']),1)

    def test_revised_disputed_and_changed_source_cannot_export_current_package(self):
        self.f.proposition(self.evidence);aid=self.f.applicability('safe',self.evidence)
        self.draft_all(applies={'safe':[aid]})
        original=self.workspace.review_package()
        self.f.proposition(self.evidence,statement='Revised behavior.')
        with self.assertRaisesRegex(ValueError,'reconsideration'):
            self.workspace.review_package()
        self.assertEqual(next(iter(original['notes'].values()))['revision'],1)
        self.draft_all(dependencies={'unsafe':[{'proposition_id':'body-owner','revision':2}]})
        self.f.apply('dispute',proposition_id='body-owner',reason='Contradictory source.')
        with self.assertRaisesRegex(ValueError,'reconsideration'):
            self.workspace.review_package()
        self.draft_all()
        self.f.code.write_text('changed source\n')
        with self.assertRaisesRegex(ValueError,'source changed'):
            self.workspace.review_package()

    def test_question_resolution_is_per_claim_and_its_last_proof_is_source_bound(self):
        hook=self.f.root/'hook.ts';hook.write_text('export const hook = external;\n')
        proof=self.f.apply('source',path='hook.ts',start_line=1,end_line=1,review_id='safe')['evidence_id']
        self.f.apply('question',question_id='shared',review_ids=['safe','unsafe'],question='Does the configured hook change these keys?')
        self.f.apply('answer',question_id='shared',status='blocked',reason='Installed hook state is unavailable.',evidence=[proof])
        self.f.apply('draft',result=self.result('safe'),applicability=[],resolved_questions=['shared'])
        self.f.apply('draft',result=self.result('unsafe','needs_review'),applicability=[])
        self.f.apply('draft',result=self.result('unknown'),applicability=[])
        package=self.workspace.review_package();claims={c['review_id']:c for c in package['claims']}
        self.assertTrue(claims['safe']['questions'][0]['resolved_for_claim'])
        self.assertFalse(claims['unsafe']['questions'][0]['resolved_for_claim'])
        self.assertEqual(package['questions']['shared']['status'],'blocked')
        rendered=render_review_package(package)
        self.assertEqual(rendered.count('### Question 1\n'),1)
        self.assertIn('[Question 1](#question-1) — resolved for this claim',rendered)
        self.assertIn('[Question 1](#question-1) — blocked',rendered)
        self.assertIn('Resolved for these shown claims: [Claim 1](#claim-1)',rendered)
        self.assertIn('Installed hook state is unavailable.',rendered)
        self.assertIn(proof,package['evidence'])
        hook.write_text('changed hook\n')
        with self.assertRaisesRegex(ValueError,'source changed'):
            self.workspace.review_package()

    def test_explicit_bundle_scope_discloses_omissions_and_incomplete_sibling_is_not_exported(self):
        claims=copy.deepcopy(self.f.claims);claims[-1]['bundle_id']='bundle-2'
        self.workspace=Workspace.create(self.f.directory/'split.sqlite',self.f.root,self.f.binding,claims,self.f.limits)
        self.f.workspace=self.workspace
        self.f.capture(1,4)
        for rid in ('safe','unsafe'):
            self.f.apply('draft',result=self.result(rid),applicability=[])
        package=self.workspace.review_package(['bundle-1'])
        self.assertEqual(package['omitted_review_ids'],['unknown'])
        with self.assertRaisesRegex(ValueError,'incomplete'):
            self.workspace.review_package()
        with self.assertRaisesRegex(ValueError,'distinct known'):
            self.workspace.review_package(['bundle-1','bundle-1'])

    def test_cli_and_markdown_keep_literal_notes_and_share_one_source_catalog(self):
        text='Literal ``` fence and <script>untrusted()</script>'
        self.f.proposition(self.evidence,statement=text)
        self.draft_all(dependencies={rid:[{'proposition_id':'body-owner','revision':1}] for rid in ('safe','unsafe')})
        package=self.workspace.review_package();rendered=render_review_package(package)
        self.assertIn('````text\n',rendered)
        self.assertEqual(rendered.count('### Source 1\n'),1)
        self.assertEqual(len(package['evidence']),1)
        seed=self.f.directory/'seed.json';seed.write_text(json.dumps({'binding':self.f.binding}))
        command=[sys.executable,str(fixtures.PRODUCT/'scripts/review_workspace.py'),'review-package',
                 '--workspace',str(self.workspace.path),'--seed',str(seed)]
        actual=json.loads(subprocess.check_output(command,text=True,encoding='utf-8'))
        self.assertEqual(actual['result'],package)
        self.assertEqual(subprocess.check_output(command+['--format','markdown'],text=True,encoding='utf-8').strip(),rendered.strip())
        payload=copy.deepcopy(package);pid=payload.pop('package_id')
        self.assertEqual(pid,identity(payload))

    def test_shared_records_render_once_without_losing_caller_qualifications(self):
        self.f.proposition(self.evidence,statement='Shared helper interpretation with its exact qualifications.')
        aid=self.f.applicability('safe',self.evidence)
        question='Does the configured external policy accept these callers?'
        reason='Missing configured policy; do not infer a safe default. ' * 15
        self.f.apply('question',question_id='policy',review_ids=['safe','unsafe'],question=question)
        self.f.apply('answer',question_id='policy',status='blocked',reason=reason,evidence=[self.evidence])
        self.draft_all(dependencies={rid:[{'proposition_id':'body-owner','revision':1}] for rid in ('safe','unsafe')},
                       applies={'safe':[aid]},decisions={'safe':'needs_review','unsafe':'needs_review'})
        package=self.workspace.review_package();before=copy.deepcopy(package)
        rendered=render_review_package(package)
        self.assertEqual(rendered.count(question),1)
        self.assertEqual(rendered.count('Shared helper interpretation with its exact qualifications.'),1)
        self.assertEqual(rendered.count(reason),1)
        self.assertEqual(rendered.count('### Note 1\n'),1)
        self.assertEqual(rendered.count('### Source 1\n'),1)
        self.assertIn('Shown affected claims: [Claim 1](#claim-1), [Claim 3](#claim-3)',rendered)
        self.assertIn('[Note 1](#note-1) — caller applicability recorded',rendered)
        self.assertIn('[Note 1](#note-1) — context only; applicability not recorded',rendered)
        note=next(iter(package['notes'].values()))
        for field in ('conditions','exclusions','origin','scope'):
            self.assertIn(str(note[field]),rendered)
        for claim in package['claims']:
            self.assertIn(claim['property'],rendered)
        self.assertEqual(package,before)

    def test_focus_cli_keeps_package_identity_source_and_hidden_scope(self):
        self.f.apply('question',question_id='shared',review_ids=['safe','unsafe'],question='Which caller uses the external policy? Unicode: \u00e9\u2192\u2028')
        self.f.apply('answer',question_id='shared',status='blocked',reason='Policy implementation unavailable.',evidence=[self.evidence])
        self.draft_all(decisions={'safe':'needs_review','unsafe':'needs_review'})
        package=self.workspace.review_package();before=self.workspace.path.read_bytes()
        seed=self.f.directory/'seed.json';seed.write_text(json.dumps({'binding':self.f.binding}))
        command=[sys.executable,str(fixtures.PRODUCT/'scripts/review_workspace.py'),'review-package',
                 '--workspace',str(self.workspace.path),'--seed',str(seed)]
        focus=subprocess.check_output(command+['--format','markdown','--review-id','unsafe'],text=True,encoding='utf-8')
        self.assertIn('## Claim 3\n',focus)
        self.assertNotIn('## Claim 1\n',focus)
        self.assertNotIn('## Claim 2\n',focus)
        self.assertIn('Included package claims outside this view:',focus)
        self.assertIn('Other affected IDs (not shown):\n```text\nsafe\n```',focus)
        self.assertNotIn('](#claim-1)',focus)
        self.assertIn(package['package_id'],focus)
        self.assertIn('Unicode: \u00e9\u2192\u2028',focus)
        self.assertEqual(focus.count('### Source 1\n'),1)
        self.assertEqual(self.workspace.path.read_bytes(),before)
        self.assertEqual(self.workspace.review_package(),package)
        both=render_review_package(package,['unsafe','safe'])
        self.assertIn('## Claim 1\n',both);self.assertIn('## Claim 3\n',both)
        for args in (['--review-id','safe'],['--format','markdown','--review-id','missing'],
                     ['--format','markdown','--review-id','safe','--review-id','safe']):
            failed=subprocess.run(command+args,capture_output=True,text=True,encoding='utf-8')
            self.assertEqual(failed.returncode,2,failed.stdout)
        self.f.code.write_text('source changed\n')
        failed=subprocess.run(command+['--format','markdown','--review-id','unsafe'],capture_output=True,text=True,encoding='utf-8')
        self.assertEqual(failed.returncode,2)
        self.assertIn('source changed',failed.stdout)

    def test_line_addresses_preserve_blank_lines_fragments_unicode_and_eof(self):
        for evidence in (
            {'start_line':3,'end_line':5,'text':'third\nfourth'},
            {'start_line':3,'end_line':5,'text':'third\nfourth\n'},
            {'start_line':1,'end_line':1,'text':''},
            {'start_line':8,'end_line':9,'text':'partial\u2028text\rkept\nfragment','fragment':True},
        ):
            with self.subTest(evidence=evidence):
                rows=captured_source_rows(evidence)
                self.assertEqual('\n'.join(row['text'] for row in rows),evidence['text'])
                self.assertEqual([r['line'] for r in rows],list(range(evidence['start_line'],evidence['start_line']+len(rows))))
        self.assertEqual(captured_source_rows({'start_line':3,'end_line':5,'text':'third\nfourth'})[-1]['line'],4)
        for first,last,text in ((0,1,''),(1,1,'a\nb'),(1,4,'a'),(True,1,'')):
            with self.subTest(first=first,last=last),self.assertRaises(ValueError):
                captured_source_rows({'start_line':first,'end_line':last,'text':text})
        self.draft_all();package=self.workspace.review_package()
        evidence=package['evidence'][self.evidence]
        evidence.update(start_line=8,end_line=9,text='partial\u2028text\rkept\nfragment',fragment=True,complete_file=False)
        before=copy.deepcopy(package);rendered=render_review_package(package)
        self.assertIn('Partial-line fragment; columns are not supplied.',rendered)
        self.assertIn('L8 | partial\u2028text\rkept\nL9 | fragment',rendered)
        self.assertEqual(package,before)


if __name__=='__main__':unittest.main()
