"""Audit a fresh native-bound explicit consumer confirmation, without new dispatch."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_workspace_consumer_bridge as fixtures
import review_workspace_audit as audit


class NativeAuditTests(unittest.TestCase):
    def test_explicit_confirmation_and_native_finalization_are_recorded(self):
        f=fixtures.ConsumerBridgeTests();f.setUp();self.addCleanup(f.doCleanups)
        first,second,_=f.partial();b=f.bridge
        f.a.turn('confirmed',lambda task,packet:{'updates':[{'kind':'answer','question_id':'shared','status':'answered',
            'reason':'The shown conversion does not constrain grammar.','evidence':[f.a.handle(task,packet,'helper.js')]}],
            'lookups':[],'decisions':[f.a.decision(first),f.a.decision(second)]})
        self.assertTrue(b.finalize(first['bundle_id'])['native_validated'])
        before=audit.file_digest(b.directory/'workspace.sqlite')
        report=audit.audit_directory(b.directory);turn=report['turns'][0]
        self.assertEqual(set(turn['offered_ids']),{first['review_id'],second['review_id']})
        self.assertTrue(turn['answer_consumers'][first['review_id']]['previous_judgment_was_delivered'])
        self.assertEqual({r['review_id']for r in turn['committed_decisions']},set(turn['offered_ids']))
        self.assertEqual(turn['observed_after']['active_ids'],[])
        self.assertEqual(turn['usage_status'],'observed')
        self.assertEqual(audit.file_digest(b.directory/'workspace.sqlite'),before)
        self.assertEqual(len(f.a.calls),1)


if __name__=='__main__':unittest.main()
