"""Delegation is explicit, source-scoped and cannot generate security verdicts."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import review_questions as questions

class Questions(unittest.TestCase):
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

if __name__=='__main__':unittest.main()
