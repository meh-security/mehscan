"""Source-only preparation keeps ambiguity, changed bytes and caller scope visible."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/"scripts"))
import review_source_profile as profiles

class DecidingSource(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'helper.py').write_text('def guard(user):\n    return user.owner\n',encoding='utf-8')
        self.payload={'repository':'fixture','inventory_input_fingerprint':'snapshot','review_ids':['a','b']}
        self.location={'path':'helper.py','start':{'line':1},'end':{'line':2}}
    def sweep(self,ids):
        return {'reviews':[{'review_id':rid,'anchor':{'captures':{'related_handler_1':'guard'}}} for rid in ids]}
    def test_shared_declaration_source_reused_but_each_bundle_keeps_scope(self):
        calls=[]
        def lookup(args):
            calls.append(args);return {'results':[{'location':self.location}],'truncated':False}
        result=profiles.build_from_sweeps(self.root,self.payload,[self.sweep(['a']),self.sweep(['b'])],lookup)
        self.assertEqual(len(calls),1)
        self.assertEqual([t['review_ids'] for t in result['profile']['targets']],[['a'],['b']])
        prepared=profiles.prepare(self.root,result['profile'],['a'],'snapshot')
        self.assertIn('return user.owner',prepared['windows'][0]['text'])
        self.assertTrue(prepared['windows'][0]['complete_file'])
        with self.assertRaises(ValueError):profiles.prepare(self.root,result['profile'],['a','b'],'snapshot')
        (self.root/'helper.py').write_text('def guard(user):\n    return True\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'changed'):profiles.prepare(self.root,result['profile'],['a'],'snapshot')
    def test_ambiguous_or_truncated_discovery_never_picks_a_definition(self):
        for discovery in ({'results':[{'location':self.location},{'location':{**self.location,'path':'other.py'}}]},
                          {'results':[{'location':self.location}],'truncated':True}):
            with self.subTest(discovery=discovery):
                value=profiles.build_from_sweeps(self.root,self.payload,[self.sweep(['a'])],lambda _:discovery)
                self.assertIsNone(value['profile'])
                self.assertEqual(value['trace'][0]['status'],'ambiguous_or_missing')
    def test_native_null_captures_still_prepare_explicit_source_lead(self):
        sweep={'reviews':[{'review_id':'a','anchor':{'captures':None},'suggested_lookups':[
            {'operation':'source','arguments':{'path':'helper.py','start-line':'1','end-line':'82'}}]}]}
        value=profiles.build_from_sweeps(self.root,self.payload,[sweep],lambda _:self.fail('No named helper'))
        self.assertEqual(value['profile']['targets'][0]['windows'][0]['path'],'helper.py')
        self.assertEqual(value['profile']['targets'][0]['windows'][0]['end_line'],2)
        self.assertEqual(value['trace'][0]['returned_end_line'],2)
    def test_large_declaration_is_explicitly_unread_not_silently_clipped(self):
        (self.root/'helper.py').write_text('pass\n'*401,encoding='utf-8')
        loc={**self.location,'end':{'line':401}}
        value=profiles.build_from_sweeps(self.root,self.payload,[self.sweep(['a'])],lambda _:{'results':[{'location':loc}]})
        self.assertIsNone(value['profile'])
        self.assertEqual(value['trace'][-1]['status'],'range_bound')
    def test_outside_source_and_outside_claims_fail_closed(self):
        with self.assertRaises(ValueError):
            profiles.build_from_sweeps(self.root,self.payload,[self.sweep(['c'])],lambda _: {})
        with self.assertRaises(ValueError):
            profiles.build_from_sweeps(self.root,self.payload,[self.sweep(['a'])],lambda _:{'results':[{'location':{**self.location,'path':'../outside.py'}}]})

if __name__=='__main__':unittest.main()
