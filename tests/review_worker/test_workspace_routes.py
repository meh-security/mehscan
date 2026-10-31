"""Native-reference source preparation; locator text never supplies verdicts."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2] / "scripts"))
from review_workspace import Workspace
from review_workspace_routes import reference_route_windows, attach_route_context
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_bridge as native_fixtures
import review_context as context
import review_worker as worker


class RouteContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "source"
        self.root.mkdir()
        (self.root / "server.ts").write_text("import { getWalletBalance } from './wallet'\n"
            "map.get(key)\n"
            "app.get('/wallet', appendUserId(), getWalletBalance())\n"
            "app.post('/deluxe', appendUserId(), upgradeToDeluxe())\n"
            "const unrelated = 1\n")
        self.result = {"operation":"find_text_references","truncated":False,"results":[{
            "path":"server.ts","lines":[1,2,3,4],"previews":[{"line":3,"text":"invented preview"}],"locations_truncated":False}]}

    def test_materializes_actual_route_source_and_merges_overlap(self):
        prepared = reference_route_windows(self.root,self.result)
        self.assertEqual(len(prepared["windows"]),1)
        window = prepared["windows"][0]
        self.assertEqual((window["start_line"],window["end_line"]),(2,5))
        self.assertIn("appendUserId()",window["text"])
        self.assertNotIn("invented preview",window["text"])
        self.assertNotIn("propositions",prepared)

    def test_limits_dynamic_registration_and_invalid_paths_remain_explicit(self):
        limited = reference_route_windows(self.root,self.result,max_bytes=1)
        self.assertEqual(limited["windows"],[])
        self.assertTrue(limited["limits"])
        with self.assertRaisesRegex(ValueError,"exceeds 8 KiB"):
            reference_route_windows(self.root,self.result,max_bytes=8193)
        dynamic = {**self.result,"truncated":True,"results":[{"path":"server.ts","lines":[1,2],"locations_truncated":True}]}
        self.assertTrue(reference_route_windows(self.root,dynamic)["limits"])
        with self.assertRaises(ValueError):
            reference_route_windows(self.root,{**self.result,"results":[{"path":"../outside.ts","lines":[1]}]})
        with self.assertRaisesRegex(ValueError,"outside current source"):
            reference_route_windows(self.root,{**self.result,"results":[{"path":"server.ts","lines":[999]}]})

    def test_capture_focus_is_source_bound_and_transfers_no_judgment(self):
        binding = {"snapshot_id":"snapshot","plan_id":"plan","runtime_id":"runtime"}
        claims = [{"review_id":"wallet","property":"Selected authorization relationship","path":"server.ts","line":3,"bundle_id":"one"}]
        workspace = Workspace.create(self.directory/'state.sqlite',self.root,binding,claims,{"model_calls":1,"queries":4,"source_bytes":8192})
        def apply(key,action):
            old = workspace.operation(key)
            return workspace.apply(key,old['request']['revision'] if old else workspace.snapshot()['revision'],action)['result']
        bridge = SimpleNamespace(workspace=workspace,root=self.root,apply=apply,check=lambda:None)
        receipt = {"snapshot_id":"snapshot","query":{"tool":"references","review_id":"wallet"},"result":self.result}
        prepared = attach_route_context(bridge,"initial",receipt)
        before = workspace.snapshot()
        self.assertEqual(attach_route_context(bridge,"initial",receipt),prepared)
        self.assertEqual(before,workspace.snapshot())
        self.assertTrue(workspace.view('initial')['evidence'])
        self.assertEqual(workspace.view('initial')['propositions'],{})
        self.assertEqual(workspace.usage()['calls'],0)
        partial = {**receipt,'result':{**self.result,'truncated':True}}
        attach_route_context(bridge,'initial',partial)
        self.assertTrue(workspace.view('initial')['preparation_limits'])
        workspace.apply('split',workspace.snapshot()['revision'],{'kind':'split','work_id':'initial','new_work_id':'child',
            'review_ids':['wallet'],'strategy':'authorization'})
        self.assertEqual(workspace.view('initial')['preparation_limits'],workspace.view('child')['preparation_limits'])
        with self.assertRaisesRegex(ValueError,"binding differs"):
            attach_route_context(bridge,'initial',{**receipt,'snapshot_id':'other'})


class NativeRouteContextTests(unittest.TestCase):
    def test_native_reference_site_is_present_in_fresh_model_packet(self):
        fixture = native_fixtures.NativeBridgeTests(methodName='test_rejected_completed_reply_still_records_usage')
        fixture.extra_source = {'server.js':"import { first } from './app.js';\napp.get('/wallet', appendUserId(), first);\n"}
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.experiment['protocol']='workspace-actions-v2'
        bridge = fixture.create()
        claim = next(c for c in bridge.workspace.snapshot()['claims'].values() if c['path']=='app.js')
        query = {'tool':'references','review_id':claim['review_id'],'purpose':'Inspect the selected handler registration',
                 'arguments':{'symbol':'first','path':'server.js','limit':20}}
        with bridge.guarded():
            bridge.apply('route-reference-reservation',{'kind':'reserve_queries','queries':1})
            result = bridge.native(worker.research_arguments(query,bridge.root,bridge.payload['review_ids'],bridge.directory/'journals',
                api=context.research_api(bridge.skill),guidance=context.guidance_catalog(bridge.skill)))
            prepared = attach_route_context(bridge,'initial',{'snapshot_id':bridge.binding()['snapshot_id'],'query':query,'result':result})
            bridge.apply('explicit-partial-scope',{'kind':'preparation_limits','work_id':'initial','preparation_id':'partial-scope',
                'origin':'fixture locator scope','limits':['Other registration sites remain outside the returned scope.']})
        self.assertTrue(prepared['evidence_ids'])
        session = bridge.prepare('initial',fixture.config_path,'with-route')['session_id']
        packet = native_fixtures.read(bridge.directory/'sessions'/session/'context.json')
        self.assertTrue(any(w['path']=='server.js' and "appendUserId()" in w['text'] for w in packet['primary']['windows']))
        self.assertEqual(packet['workspace_evidence']['propositions'],{})
        self.assertTrue(any('outside the returned scope' in limit['reason'] for limit in packet['primary']['limits']))
        self.assertEqual(bridge.workspace.usage()['calls'],0)
        self.assertEqual(bridge.workspace.snapshot()['used']['queries'],1)


if __name__ == "__main__":
    unittest.main()
