#!/usr/bin/env python3
"""Fresh matched singleton/group comparison using source-only saved preparation."""
from argparse import Namespace
import argparse
import copy
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

import review_workspace_pilot as pilot
import review_worker as worker
from review_workspace_bridge import NativeWorkspace, provider_environment
from review_workspace import identity


def run_arm(root, arm):
    root = Path(root).resolve(strict=True)
    _,design,setup = pilot.load_run(root)
    binding = pilot.read(root / "matrix-binding.json")
    for name,digest in binding["files"].items():
        if worker.digest_file(root / name) != digest:
            raise ValueError("expanded comparison artifact changed: "+name)
    for item in binding["provider_inputs"].values():
        if worker.digest_file(item["path"]) != item["sha256"]:
            raise ValueError("expanded comparison provider config changed")
    spec = binding["arms"][arm]
    opts = setup["arms"][arm]
    bridge = NativeWorkspace(Namespace(**opts))
    if time.time() >= binding["deadline_epoch"]:
        raise ValueError("whole comparison deadline elapsed")
    pilot.begin_execution(root,arm)
    started = time.time()
    arm_deadline = min(binding["deadline_epoch"],started+2400)
    original_remaining = bridge._remaining_seconds
    outcomes,work_results = {},[]
    stop_arm = False
    try:
        for work in spec["work_items"]:
            work_id,ids = work["id"],work["review_ids"]
            work_started = time.time()
            work_deadline = min(arm_deadline,work_started+900)
            def remaining():
                value = min(original_remaining(),work_deadline-time.time())
                if value <= 0:
                    raise ValueError("work/arm deadline reached")
                return value
            bridge._remaining_seconds = remaining
            calls = 0
            parent = None
            error = None
            try:
                while bridge.workspace.view(work_id,max_bytes=131072)["claims"]:
                    usage = bridge.workspace.usage()
                    pilot.enforce_usage(usage["totals"],design["per_arm_experiment"])
                    if usage["unobserved_calls"]:
                        raise ValueError("unknown provider usage prevents more calls in this arm")
                    if calls >= 6 or usage["calls"] >= 48 or remaining() <= 10:
                        raise ValueError("six-call work or arm allowance reached")
                    state = bridge.workspace.snapshot()
                    query_units = work["preparation_queries"]+sum(2 if l["query"]["tool"]=="definition" else 1
                        for l in state["lookups"].values() if l["query"]["review_id"] in ids)
                    session = bridge.prepare(work_id,opts["config"],arm+":"+work_id+":"+str(calls),parent)["session_id"]
                    parent = session
                    def invoke(task):
                        pending = bridge.workspace.snapshot()
                        left = min(6-calls,49-len(pending["calls"]))
                        task["research"]["queries_remaining"] = min(task["research"]["queries_remaining"],max(0,24-query_units)) if left>1 else 0
                        task["research"]["workspace_budget"]["work_remaining"] = {"model_calls":left,"queries":task["research"]["queries_remaining"]}
                        outer = min(305,task["research"]["seconds_remaining"],work_deadline-time.time())
                        task["research"]["seconds_remaining"] = max(0.1,outer-5)
                        worker.write(bridge.directory / "sessions" / session / "invoked-task.json",task)
                        reply = worker.execute(pilot.read(opts["command"]),bridge.directory,provider_environment(),outer,json.dumps(task))
                        units = sum(2 if q["tool"]=="definition" else 1 for l in reply["workspace_actions"]["lookups"] for q in l["queries"])
                        if units > task["research"]["queries_remaining"]:
                            raise ValueError("returned lookups exceed work allowance")
                        return reply
                    result = bridge.review(session,opts["config"],invoke)
                    calls += 1
                    print(json.dumps({"arm":arm,"work":work_id,"turn":calls,"active":len(bridge.workspace.view(work_id,max_bytes=131072)["claims"]),"usage":result["usage"]}),flush=True)
            except Exception as exc:
                error = {"type":type(exc).__name__}
                if isinstance(exc,(ValueError,TimeoutError)):
                    error["message"] = str(exc)
            state = bridge.workspace.snapshot()
            for claim_id in ids:
                claim = state["claims"][claim_id]
                record = {"review_id":claim_id,"work_id":work_id,"decision":None,"status":"unassessed"}
                if claim["draft"] and not claim["reconsideration"]:
                    record.update(decision=claim["draft"]["result"]["decision"],status="drafted")
                    try:
                        record.update(status="source_validated",validated=bridge.finalize(claim["bundle_id"]))
                    except Exception as exc:
                        record.update(status="finalization_failed",error_type=type(exc).__name__)
                elif claim["reconsideration"]:
                    record.update(status="reconsideration_required",reconsideration=claim["reconsideration"])
                outcomes[claim_id] = record
            work_results.append({"id":work_id,"review_ids":ids,"model_turns":calls,"elapsed_ms":round((time.time()-work_started)*1000),"error":error})
            usage = bridge.workspace.usage()
            checkpoint = {"status":"running","arm":arm,"claims":outcomes,"work":work_results,"usage":usage,"elapsed_ms":round((time.time()-started)*1000),"native_admission":False}
            worker.write(root / arm / "matrix-result.json",checkpoint)
            if usage["unobserved_calls"] or usage["calls"]>=48 or time.time()>=arm_deadline:
                stop_arm = True
                break
    finally:
        bridge._remaining_seconds = original_remaining
        state = bridge.workspace.snapshot()
        for claim_id in design["selected_review_ids"]:
            if claim_id not in outcomes:
                outcomes[claim_id] = {"review_id":claim_id,"status":"not_reached","decision":None}
            if state["claims"][claim_id]["reconsideration"]:
                outcomes[claim_id]["status"] = "reconsideration_required"
        summary = {"status":"bounded_stop" if stop_arm else "finished","arm":arm,"claims":outcomes,"work":work_results,
            "usage":bridge.workspace.usage(),"elapsed_ms":round((time.time()-started)*1000),
            "used_query_units":state["used"]["queries"],"received_query_bytes":state["received_query_bytes"],"native_admission":False}
        worker.write(root / arm / "matrix-result.json",summary)
    return summary



def prepare(args):
    started = time.time()
    reference = Path(args.reference).resolve(strict=True)
    previous = pilot.read(reference / "design.json")
    matrix = pilot.read(reference / "matrix-binding.json")
    old_setup = pilot.read(reference / "setup.json")
    preparation = pilot.read(reference / "preparation-report.json")
    source_directory = Path(old_setup["arms"]["treatment"]["directory"])
    with sqlite3.connect(source_directory / "workspace.sqlite") as db:
        old_state = json.loads(db.execute("SELECT body FROM workspace WHERE id=1").fetchone()[0])
    ids = previous["selected_review_ids"]
    profiles = {}
    for index,rid in enumerate(ids):
        calls = [c for c in old_state["calls"].values()
                 if old_state["sessions"][c["session_id"]]["work_id"] == "claim-"+str(index)]
        sid = min(calls,key=lambda c:c["started_epoch_ms"])["session_id"]
        packet = old_state["sessions"][sid]["packet"]
        if identity(pilot.canonical_windows(packet["evidence"].values())) != preparation["treatment:claim-"+str(index)]["source_sha256"]:
            raise ValueError("reference first session differs from its pre-model preparation receipt")
        if any(e["origin"]["kind"] != "workspace_preparation" for e in packet["evidence"].values()):
            raise ValueError("reference profile contains investigated rather than prepared source")
        profiles[rid] = {"reference_session":sid,"evidence":list(packet["evidence"].values()),
                         "limits":packet["preparation_limits"]}
    design = {k:copy.deepcopy(previous[k]) for k in ("source_pin","model","reasoning_effort",
              "selected_review_ids","per_arm_limits","per_arm_experiment","native_case_limits")}
    design.update(schema_version="mehscanFixedControllerConfirmation/v1",
        purpose="Fresh complete-operation singletons versus identical-source investigation groups; no seed or dependency additions.")
    root = Path(args.output).resolve()
    design_path = root.with_name(root.name+"-design.json")
    with design_path.open("x",encoding="utf-8") as handle:
        json.dump(design,handle,indent=2)
    pilot.prepare(Namespace(**{**vars(args),"design":str(design_path)}))
    setup = pilot.read(root / "setup.json")
    singleton_specs = copy.deepcopy(matrix["arms"]["treatment"]["work_items"])
    group_specs = copy.deepcopy(matrix["arms"]["complete_groups"]["work_items"])
    for group in group_specs:
        expected = [e for rid in group["review_ids"] for e in profiles[rid]["evidence"]]
        if identity(pilot.canonical_windows(expected)) != preparation["complete_groups:"+group["id"]]["source_sha256"]:
            raise ValueError("reference grouped source differs from singleton profile union")
    specs = {"control":singleton_specs,"treatment":group_specs}
    parity = {}
    for arm in ("control","treatment"):
        opts = setup["arms"][arm]
        if arm == "treatment":
            # The generic pilot prepares an unused singleton workspace. Keep it
            # as preparation history, and create fresh grouped state separately.
            opts["directory"] = str(root / arm / "grouped-workspace")
        experiment = {**design["per_arm_experiment"],"protocol":"workspace-actions-v2",
            "bundle_max_reviews":1,"prepare_application":True,
            "max_received_query_bytes":design["per_arm_limits"]["source_bytes"]}
        bridge = NativeWorkspace.create(Namespace(**opts),design["per_arm_limits"],experiment)
        with bridge.guarded():
            for work in specs[arm]:
                wid = work["id"]
                bridge.apply("split:"+wid,{"kind":"split","work_id":"initial","new_work_id":wid,
                    "review_ids":work["review_ids"],"strategy":"fixed source-profile confirmation"})
                evidence = []
                expected = []
                for rid in work["review_ids"]:
                    profile = profiles[rid]
                    for index,item in enumerate(profile["evidence"]):
                        action = {"kind":"source","path":item["path"],"start_line":item["start_line"],
                            "end_line":item["end_line"],"review_id":rid}
                        if item.get("fragment"):
                            action["excerpt"] = item["text"]
                        eid = bridge.apply("profile:"+wid+":"+rid+":"+str(index),action)["evidence_id"]
                        captured = bridge.workspace.snapshot()["evidence"][eid]
                        if any(captured[k] != item[k] for k in ("file_sha256","text","path","start_line","end_line")):
                            raise ValueError("saved initial source profile differs from current snapshot")
                        evidence.append(eid); expected.append(item)
                    for index,limit in enumerate(profile["limits"]):
                        bridge.apply("limits:"+wid+":"+rid+":"+str(index),{"kind":"preparation_limits",
                            "work_id":wid,"preparation_id":identity([rid,index,limit]),
                            "origin":"frozen source-profile locator scope","limits":[limit["reason"]]})
                bridge.apply("focus:"+wid,{"kind":"focus","work_id":wid,
                    "evidence_ids":sorted(set(evidence)),"proposition_ids":[]})
                # Preserve K's effective research allowance. These are nominal
                # fixed-profile preparation units, not fabricated native calls.
                if work["preparation_queries"]:
                    bridge.apply("profile-units:"+wid,{"kind":"reserve_queries","queries":work["preparation_queries"]})
                actual = bridge.workspace.view(wid,max_bytes=131072)
                if pilot.canonical_windows(actual["evidence"].values()) != pilot.canonical_windows(expected):
                    raise ValueError("working source differs from frozen complete profile")
                if actual["propositions"] or actual["questions"] or actual["guidance"]:
                    raise ValueError("confirmation preparation contains learned interpretations")
                parity[arm+":"+wid] = {"sha256":identity(pilot.canonical_windows(expected)),
                    "source_windows":len(actual["evidence"]),"review_ids":work["review_ids"]}
    # Every group gets exactly the union of its singleton source profiles.
    for group in group_specs:
        expected = [e for rid in group["review_ids"] for e in profiles[rid]["evidence"]]
        if parity["treatment:"+group["id"]]["sha256"] != identity(pilot.canonical_windows(expected)):
            raise ValueError("group/singleton source union differs")
    pilot.worker.write(root / "setup.json",setup)
    pilot.worker.write(root / "source-profiles.json",profiles)
    pilot.worker.write(root / "comparison-source-parity.json",parity)
    frozen_script = root / "package/scripts/review_workspace_comparison.py"
    shutil.copyfile(Path(__file__),frozen_script)
    run_binding = pilot.read(root / "run-binding.json")
    run_binding["setup_sha256"] = worker.digest_file(root / "setup.json")
    run_binding["files"]["package/scripts/review_workspace_comparison.py"] = worker.digest_file(frozen_script)
    run_binding["case_policy"] = "Six calls/work, 24 query units including fixed-profile preparation, 48 calls/arm; native defaults unchanged."
    run_binding["byte_policy"] = "4 MiB unique source and received results per arm, both enforced; actual counters retained."
    worker.write(root / "run-binding.json",run_binding)
    provider_inputs = {}
    for arm,opts in setup["arms"].items():
        for name in ("config","command"):
            provider_inputs[arm+":"+name] = {"path":opts[name],"sha256":worker.digest_file(opts[name])}
    frozen = {"schema_version":"mehscanFixedControllerComparison/v1","started_epoch":time.time(),
        "deadline_epoch":time.time()+6000,"arm_order":["control","treatment"],
        "labels":{"control":"complete-operation singletons","treatment":"complete-operation groups"},
        "arms":{arm:{"work_items":work} for arm,work in specs.items()},
        "files":{name:worker.digest_file(root/name) for name in
            ("source-profiles.json","comparison-source-parity.json","package/scripts/review_workspace_comparison.py")},
        "provider_inputs":provider_inputs,"preparation_elapsed_ms":round((time.time()-started)*1000),
        "reference":str(reference),"source_policy":"Only initial source windows, raw bytes and locator limits from first singleton sessions; no decisions, propositions, answers or evaluator labels.",
        "preparation_query_policy":"Reserve the same nominal preparation units as K; no new reference locator execution is claimed.",
        "git_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=Path(__file__).resolve().parents[1],text=True).strip(),
        "repair_policy":"No controller edits or paid repair repeats inside this confirmation. Retain failures and report incomplete comparison."}
    worker.write(root / "matrix-binding.json",frozen)
    return {"prepared":True,"root":str(root),"claims":len(ids),"model_calls":0,
            "preparation_elapsed_ms":frozen["preparation_elapsed_ms"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command",required=True)
    prep = commands.add_parser("prepare")
    for name in ("reference","output","private","scanner","provider-config","provider-executable"):
        prep.add_argument("--"+name,required=True)
    arm = commands.add_parser("arm")
    arm.add_argument("--root",required=True);arm.add_argument("--arm",choices=("control","treatment"),required=True)
    run = commands.add_parser("run")
    run.add_argument("--root",required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args)
    elif args.command == "arm":
        result = run_arm(args.root,args.arm)
    else:
        root = Path(args.root).resolve(strict=True)
        pilot.load_run(root)
        binding = pilot.read(root/"matrix-binding.json")
        results = {}
        for name in binding["arm_order"]:
            if time.time() >= binding["deadline_epoch"]:
                break
            print(json.dumps({"starting":name}),flush=True)
            with (root/name/"console.log").open("x",encoding="utf-8") as handle:
                code = subprocess.run([sys.executable,str(root/"package/scripts/review_workspace_comparison.py"),
                    "arm","--root",str(root),"--arm",name],stdout=handle,stderr=subprocess.STDOUT).returncode
            results[name] = code
            print(json.dumps({"finished":name,"exit_code":code}),flush=True)
        result = {"exit_codes":results,"native_admission":False}
        worker.write(root/"execution-result.json",result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
