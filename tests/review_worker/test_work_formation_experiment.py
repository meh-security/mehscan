"""Planning diagnostics must retain claims/costs without admitting AI proposals."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"scripts"))
import review_work_formation_experiment as experiment


class WorkFormationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mehscan-work-formation-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/"source";self.root.mkdir()
        (self.root/"a.ts").write_text("first();\nsecond();\n",encoding="utf-8")
        self.output=self.base/"output";self.output.mkdir()
        self.packet={"claims":{"a":{"application":"app"},"b":{"application":"app"}},
            "source_catalog":{"app":{"a.ts":{"file_sha256":experiment.worker.digest_file(self.root/"a.ts"),"lines":2}}}}
        self.freeze={"freeze_id":"fixture","spec":{"applications":{"app":{"source_root":str(self.root)}}},
            "limits":{"elapsed_seconds":60,"input_tokens":10000,"output_tokens":1000}}
        self.private=self.base/"private"

    def proposal(self):
        return {"action":"propose","lookups":[],"investigations":[
            {"kind":"separate","members":[rid],"deciding_question":"local question","evidence_ids":[],"caller_checks":[]}
            for rid in ("a","b")],"shared_facts":[],"packet_batches":[["a","b"]],"limits":[]}

    def query(self):
        return {"application":"app","path":"a.ts","start_line":1,"end_line":2,"question":"Do the calls share implementation work?"}

    def fake(self,answers,usage=None):
        calls=[]
        class Launcher:
            def __init__(instance,*args): pass
            def review(instance,prompt,schema,**kwargs):
                calls.append(json.loads(prompt))
                answer=answers[len(calls)-1]
                events="\n".join(json.dumps(e) for e in [
                    {"type":"thread.started","thread_id":"00000000-0000-0000-0000-000000000001"},
                    {"type":"turn.started"},{"type":"turn.completed","usage":usage if usage is not None else
                        {"input_tokens":100,"cached_input_tokens":0,"output_tokens":20}}])
                return answer,events,""
        return calls,Launcher

    def run_fake(self,answers,usage=None):
        calls,launcher=self.fake(answers,usage)
        with patch.object(experiment,"check",return_value=(self.freeze,self.packet,{})),patch.object(experiment,"Launcher",launcher):
            result=experiment.run(self.output,self.base/"config.json",self.private)
        return result,calls

    def test_partition_and_packet_batching_are_separate_without_shared_policy(self):
        experiment.validate_proposal(self.proposal(),self.packet,set())
        for variant in ("missing","duplicate","cross_app","unseen"):
            answer=self.proposal();packet=json.loads(json.dumps(self.packet))
            if variant=="missing": answer["investigations"].pop()
            if variant=="duplicate": answer["packet_batches"]=[["a"],["a"]]
            if variant=="cross_app": packet["claims"]["b"]["application"]="other"
            if variant=="unseen": answer["investigations"][0]["evidence_ids"]=["source-999"]
            with self.subTest(variant=variant),self.assertRaises(ValueError):
                experiment.validate_proposal(answer,packet,set())

    def test_lookup_is_pinned_and_cannot_escape_catalog_or_source(self):
        receipt=experiment.lookup(self.freeze,self.packet,self.query(),1)
        self.assertEqual(receipt["text"],"first();\nsecond();")
        for change in ({"path":"../secret"},{"end_line":121},{"start_line":0},{"question":""}):
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):
                experiment.lookup(self.freeze,self.packet,{**self.query(),**change},2)
        (self.root/"a.ts").write_text("changed\n",encoding="utf-8")
        with self.assertRaisesRegex(ValueError,"changed"):
            experiment.lookup(self.freeze,self.packet,self.query(),2)

    def test_invalid_operation_span_fails_before_locator_or_output_creation(self):
        spec={"version":"mehscanWorkFormationCases/experimental-v1",
            "applications":{"app":{"source_root":str(self.root)}},"operations":[
                {"id":"op","application":"app","path":"a.ts","start_line":1,"end_line":3,"review_ids":["a"]}]}
        path=self.base/"spec.json";path.write_text(json.dumps(spec))
        with patch.object(experiment,"load_config",return_value={}),patch.object(experiment.worker,"execute") as native:
            with self.assertRaisesRegex(ValueError,"invalid operation span"):
                experiment.prepare(path,self.base/"not-created",self.base/"scanner",self.base/"config")
        native.assert_not_called()
        self.assertFalse((self.base/"not-created").exists())

    def test_fresh_call_receives_receipt_and_complete_original_metadata(self):
        lookup={"action":"lookup","lookups":[self.query()],"investigations":[],"shared_facts":[],"packet_batches":[],"limits":[]}
        result,calls=self.run_fake([lookup,self.proposal()])
        self.assertEqual(result["status"],"proposed_unvalidated")
        self.assertEqual(result["usage"]["input_tokens"],200)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0]["returned_source"],[])
        self.assertEqual(calls[1]["metadata"],self.packet)
        self.assertEqual(calls[1]["returned_source"][0]["id"],"source-1")
        self.assertTrue((self.output/"proposal.json").is_file())
        with patch.object(experiment,"check",return_value=(self.freeze,self.packet,{})),self.assertRaisesRegex(ValueError,"already reserved"):
            experiment.run(self.output,self.base/"config.json",self.private)

    def test_paid_invalid_proposal_preserves_usage_without_retry(self):
        answer=self.proposal();answer["investigations"][0]["evidence_ids"]=["source-999"]
        result,calls=self.run_fake([answer])
        self.assertEqual(result["status"],"stopped")
        self.assertEqual(result["model_calls"],1)
        self.assertEqual(result["usage"]["input_tokens"],100)
        self.assertFalse((self.output/"proposal.json").exists())

    def test_incomplete_usage_stops_and_retains_known_partial_counters(self):
        result,calls=self.run_fake([self.proposal()],usage={"output_tokens":17})
        self.assertEqual(len(calls),1)
        self.assertEqual(result["unknown_usage"],1)
        self.assertIsNone(result["usage"])
        self.assertEqual(result["observed_usage"]["output_tokens"],17)


if __name__=="__main__":
    unittest.main()
