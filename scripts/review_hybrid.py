#!/usr/bin/env python3
"""Experimental routed native/workspace execution with shared original-bundle budgets."""
import argparse
from argparse import Namespace
import json
from pathlib import Path
import time
from unittest.mock import patch

import review_context as context
import review_routing as routing
import review_worker as worker
import review_workspace_pilot as pilot
from review_workspace import identity, render_review_package
from review_workspace_bridge import NativeWorkspace, provider_environment


VERSION = "mehscanHybridReview/experimental-v1"
COUNTERS = ("input_tokens","cached_input_tokens","output_tokens","elapsed_ms")


def schedule(plan, manifest, case):
    """Connected original bundles share allowances; split units never add credit."""
    members = {b["bundle_fingerprint"]:list(b["review_ids"]) for b in manifest["bundles"]}
    original = {rid:bid for bid,ids in members.items() for rid in ids}
    if len(original) != sum(map(len,members.values())) or set(original)!=set(plan["selected_review_ids"]):
        raise ValueError("hybrid original coverage differs")
    units = []
    for group in plan["investigations"]:
        if group["route"]=="workspace":
            units.append({"id":group["id"],"route":"workspace","review_ids":group["review_ids"],"selection":group})
    for packet in plan["native_packets"]:
        units.append({"id":"native-"+identity(packet)[:20],"route":"native","review_ids":packet["review_ids"],"selection":None})
    flat = [rid for unit in units for rid in unit["review_ids"]]
    if len(flat)!=len(set(flat)) or set(flat)!=set(original) or not 1<=len(units)<=32:
        raise ValueError("hybrid units must partition all claims in 1..32 work items")
    expected = {r["review_id"]:r["route"] for r in plan["claims"]}
    if any(expected.get(rid)!=unit["route"] for unit in units for rid in unit["review_ids"]):
        raise ValueError("hybrid routes disagree with claim rows")
    parents = {bid:bid for bid in members}
    def find(bid):
        while parents[bid]!=bid: bid=parents[bid]
        return bid
    for unit in units:
        bids = sorted({original[rid] for rid in unit["review_ids"]})
        unit["original_bundle_ids"] = bids
        for bid in bids[1:]: parents[find(bid)]=find(bids[0])
    groups = {}
    for bid in members: groups.setdefault(find(bid),[]).append(bid)
    components,ordered = [],[]
    base = {"model_calls":case["rounds"]+1,"queries":case["queries"],"received_bytes":case["bytes"],"seconds":case["timeout_seconds"]}
    for bids in groups.values():
        cid = "component-"+identity(sorted(bids))[:20]
        selected = [u for u in units if set(u["original_bundle_ids"]) & set(bids)]
        limits = {key:value*len(bids) for key,value in base.items()}
        if len(selected)>limits["model_calls"]:
            raise ValueError("hybrid split cannot fund one final call per unit within original allowances")
        for unit in selected: unit["component_id"]=cid
        components.append({"id":cid,"original_bundle_ids":bids,"unit_ids":[u["id"] for u in selected],"limits":limits})
        ordered.extend(selected)  # Workspace first, then native; each component is contiguous.
    return {"components":components,"units":ordered,"per_unit_limits":base,
            "original_review_ids":list(original),"authority":"Connected-component ceilings equal original-bundle ceilings summed once. Unit limits and global limits also apply."}


class Ledger:
    def __init__(self, path, compiled, limits, experiment, *, clock=time.time):
        self.path,self.clock = Path(path),clock
        if self.path.exists(): raise ValueError("hybrid ledger already exists; no implicit paid restart")
        self.state = {"schedule":compiled,"global_limits":{**limits,**experiment},"started_epoch":clock(),
            "units":{u["id"]:{"component_id":u["component_id"],"status":"pending","started_epoch":None,"model_calls":0,"queries":0,"received_bytes":0} for u in compiled["units"]},
            "components":{c["id"]:{"started_epoch":None} for c in compiled["components"]},"calls":[],"events":[]}
        if len(compiled["units"])>limits["model_calls"]:
            raise ValueError("global hybrid allowance cannot fund one final call per unit")
        self.save()

    def save(self): worker.write(self.path,self.state)

    def totals(self):
        return {key:sum(u[key] for u in self.state["units"].values()) for key in ("model_calls","queries","received_bytes")}

    def component(self, uid):
        cid=self.state["units"][uid]["component_id"]
        return next(c for c in self.state["schedule"]["components"] if c["id"]==cid)

    def seconds(self, uid):
        component=self.component(uid);now=self.clock()
        start=self.state["components"][component["id"]]["started_epoch"]
        unit_start=self.state["units"][uid]["started_epoch"]
        return min(self.state["global_limits"]["max_elapsed_seconds"]-(now-self.state["started_epoch"]),
                   component["limits"]["seconds"]-(now-(start if start is not None else now)),
                   self.state["schedule"]["per_unit_limits"]["seconds"]-(now-(unit_start if unit_start is not None else now)))

    def start(self, uid):
        unit=self.state["units"][uid];component=self.component(uid)
        if unit["started_epoch"] is None:
            unit["started_epoch"]=self.clock();unit["status"]="running"
        if self.state["components"][component["id"]]["started_epoch"] is None:
            self.state["components"][component["id"]]["started_epoch"]=self.clock()
        self.save()

    def offer(self, uid):
        units=self.state["units"];unit=units[uid];component=self.component(uid)
        if any(c["usage"] is None or any(c["usage"].get(k) is None for k in COUNTERS) for c in self.state["calls"]):
            raise ValueError("unknown paid usage prevents further hybrid dispatch")
        if any(u["status"]=="failed" for u in units.values()) or unit["status"]=="complete":
            raise ValueError("hybrid unit is complete or execution has failed")
        seconds=self.seconds(uid)
        counts=self.totals();per=self.state["schedule"]["per_unit_limits"];maximum=self.state["global_limits"]
        future=[key for key,u in units.items() if key!=uid and u["status"]!="complete"]
        remaining={}
        for key,glob in (("model_calls","model_calls"),("queries","queries"),("received_bytes","source_bytes")):
            local=sum(units[key_id][key] for key_id in component["unit_ids"])
            remaining[key]=min(per[key]-unit[key],component["limits"][key]-local,maximum[glob]-counts[key])
        remaining["model_calls"]=min(remaining["model_calls"],
            component["limits"]["model_calls"]-sum(units[key]["model_calls"] for key in component["unit_ids"])-len(set(future)&set(component["unit_ids"])),
            maximum["model_calls"]-counts["model_calls"]-len(future))
        if remaining["model_calls"]<=0 or min(remaining["queries"],remaining["received_bytes"])<0 or seconds<=5:
            raise ValueError("hybrid original/global allowance exhausted")
        for key in ("input_tokens","output_tokens"):
            value=sum((c["usage"] or {}).get(key,0) or 0 for c in self.state["calls"])
            if value>=maximum["max_"+key]: raise ValueError("hybrid observed token ceiling reached")
        if remaining["model_calls"]==1: remaining["queries"]=0
        return {**remaining,"seconds":seconds}

    def reserve_call(self, uid, task):
        offer=self.offer(uid);unit=self.state["units"][uid];component=self.component(uid)
        self.start(uid);unit["model_calls"]+=1
        self.state["calls"].append({"unit_id":uid,"conversation_id":task["conversation_id"],"round":task["research"]["round"],"usage":None,"offer":offer})
        self.save()
        return len(self.state["calls"])-1,offer

    def observe_call(self, index, task, provider):
        path=Path(task["provider_metrics"])
        rows=[json.loads(s) for s in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
        rows=[r for r in rows if r["conversation_id"]==task["conversation_id"] and r["round"]==task["research"]["round"]]
        if len(rows)!=1 or rows[0]["provider"]!=provider:
            self.state["events"].append({"kind":"unknown_usage","call":index});self.save()
            return
        row=rows[0];usage={k:row.get("usage",{}).get(k) for k in COUNTERS if k!="elapsed_ms"};usage["elapsed_ms"]=row.get("elapsed_ms")
        if any(v is not None and (type(v) is not int or v<0) for v in usage.values()):
            raise ValueError("invalid hybrid provider counters")
        if usage["cached_input_tokens"] is not None and usage["input_tokens"] is not None and usage["cached_input_tokens"]>usage["input_tokens"]:
            raise ValueError("hybrid cached input exceeds total input")
        self.state["calls"][index]["usage"]=usage;self.save()

    def charge_queries(self, uid, queries, offered):
        count=sum(2 if q.get("tool")=="definition" else 1 for q in queries)
        self.state["units"][uid]["queries"]+=count
        self.state["events"].append({"kind":"requested_queries","unit_id":uid,"units":count})
        self.save()  # Rejected batches stay charged, before any source operation.
        if count>offered: raise ValueError("hybrid query batch exceeds advertised remainder")

    def observe_bytes(self, uid, count):
        unit=self.state["units"][uid]
        if count<unit["received_bytes"]: raise ValueError("hybrid byte observation cannot shrink")
        unit["received_bytes"]=count;self.save()
        component=self.component(uid);units=self.state["units"]
        if (count>self.state["schedule"]["per_unit_limits"]["received_bytes"]
                or sum(units[u]["received_bytes"] for u in component["unit_ids"])>component["limits"]["received_bytes"]
                or self.totals()["received_bytes"]>self.state["global_limits"]["source_bytes"]):
            raise ValueError("hybrid received-byte ceiling exceeded; observation retained")

    def finish(self, uid, success):
        self.state["units"][uid]["status"]="complete" if success else "failed";self.save()

    def usage(self):
        calls=self.state["calls"]
        return {"attempted_calls":len(calls),"observed_calls":sum(c["usage"] is not None and all(c["usage"].get(k) is not None for k in COUNTERS) for c in calls),
                "unobserved_calls":sum(c["usage"] is None or any(c["usage"].get(k) is None for k in COUNTERS) for c in calls),
                "totals":{k:None if any(c["usage"] is None or c["usage"].get(k) is None for c in calls) else sum(c["usage"][k] for c in calls) for k in COUNTERS},
                "spent":self.totals()}


def _routing_inputs(args):
    return {"planner_plan":worker.read(args.planner_plan) if args.planner_plan else None,
            "selections":worker.read(args.selections) if args.selections else None,
            "engine_sha256":worker.digest_file(args.scanner) if args.planner_plan else None}


def prepare(args):
    design=worker.read(args.design)
    if not design.get("batch_mode") or not design.get("hybrid_mode"):
        raise ValueError("hybrid preparation requires batch_mode and hybrid_mode")
    plan=worker.read(args.routing);options=_routing_inputs(args)
    # Validate the proposal before creating native claims or a prepared run.
    inventory=worker.read(args.routing_inventory)
    manifest=worker.read(args.routing_manifest)
    routing.validate(plan,design["source_pin"]["local_export"],inventory,manifest,**options)
    case=pilot.native_case_limits(design);compiled=schedule(plan,manifest,case)
    if len(compiled["units"])>design["per_arm_limits"]["model_calls"]:
        raise ValueError("hybrid global allowance cannot fund the frozen split")
    pilot.prepare(args)
    root,design,setup=pilot.load_run(args.output)
    opts=setup["arms"]["treatment"];bridge=NativeWorkspace(Namespace(**opts))
    actual=worker.read(root/"control/bundles/manifest.json");inv=worker.read(Path(setup["inventory"])/"inventory.json")
    routing.validate(plan,bridge.root,inv,actual,**options)
    if set(plan["selected_review_ids"])!=set(bridge.payload["review_ids"]): raise ValueError("hybrid/native claim coverage differs")
    worker.write(root/"hybrid-routing.json",plan)
    worker.write(root/"hybrid-inputs.json",options)
    specs=[];native_inputs={}
    for unit in compiled["units"]:
        ids=unit["review_ids"];selection=unit["selection"]
        specs.append({"work_id":unit["id"],"review_ids":ids,"strategy":"hybrid "+unit["route"]+": independent verdicts",
            "evidence_ids":sorted({eid for rid in ids for eid in bridge.metadata["initial_evidence"][rid]}),
            "windows":[{**frame,"review_id":ids[0]} for frame in selection["evidence_windows"]] if selection else [],
            "limits":[selection["deciding_question"],*selection["caller_checks"].values(),*selection["limits"]] if selection else ["Native worker reviews this fragment; no caller applicability is transferred."]})
        if unit["route"]=="native":
            directory=root/"treatment/native-inputs"/unit["id"];directory.mkdir(parents=True)
            with bridge.guarded():
                package=bridge.native(["state","work",*bridge.common,"--review-ids",",".join(ids)])
                worker.write(directory/"work.json",package)
                bridge.native(["investigate","review-bundles",str(bridge.root),"--inventory",str(bridge.inventory),
                               "--review-ids",",".join(ids),"--output",str(directory/"bundles")])
            profile=bridge.source_profile
            if profile is not None:
                targets=[t for t in profile["targets"] if set(t["review_ids"]) & set(ids)]
                if len(targets)>1: raise ValueError("native fragment crosses explicit source targets")
                if targets:
                    profile={**profile,"targets":[{**targets[0],"review_ids":ids}]}
                    worker.write(directory/"source-profile.json",profile)
                else: profile=None
            native_inputs[unit["id"]]={"work_package":str(directory/"work.json"),"run":str(directory/"bundles"),
                "source_profile":str(directory/"source-profile.json") if profile else None}
    with bridge.guarded():
        bridge.apply("hybrid-plan:"+plan["routing_id"],{"kind":"prepare_work","planning_id":plan["routing_id"],
            "work":specs,"max_context_bytes":bridge.metadata["experiment"]["context_max_bytes"]})
    worker.write(root/"hybrid-schedule.json",compiled)
    worker.write(root/"hybrid-native-inputs.json",native_inputs)
    files=[root/"hybrid-routing.json",root/"hybrid-inputs.json",root/"hybrid-schedule.json",root/"hybrid-native-inputs.json"]
    files.extend(p for p in (root/"treatment/native-inputs").rglob("*.json") if p.is_file())
    runtime={name:worker.digest_file(Path(__file__).parent/name) for name in ("review_hybrid.py","review_routing.py","review_workspace_pilot.py","review_worker.py")}
    worker.write(root/"hybrid-binding.json",{"schema_version":VERSION,"files":{str(p.relative_to(root)):worker.digest_file(p) for p in files},
        "runtime":runtime,"routing_id":plan["routing_id"],"prepared_state_id":identity(bridge.workspace.snapshot()),"native_admission":False})
    return {"prepared":True,"claims":len(plan["claims"]),"units":len(compiled["units"]),"components":len(compiled["components"]),"model_calls":0,"native_admission":False}


def load(root):
    root,design,setup=pilot.load_run(root)
    binding=worker.read(root/"hybrid-binding.json")
    if binding["schema_version"]!=VERSION: raise ValueError("hybrid version differs")
    for name,digest in binding["files"].items():
        if worker.digest_file(root/name)!=digest: raise ValueError("frozen hybrid input changed: "+name)
    for name,digest in binding["runtime"].items():
        if worker.digest_file(Path(__file__).parent/name)!=digest: raise ValueError("hybrid runtime changed: "+name)
    plan=worker.read(root/"hybrid-routing.json");options=worker.read(root/"hybrid-inputs.json")
    routing.validate(plan,setup["source_root"],worker.read(Path(setup["inventory"])/"inventory.json"),worker.read(root/"control/bundles/manifest.json"),**options)
    compiled=schedule(plan,worker.read(root/"control/bundles/manifest.json"),pilot.native_case_limits(design))
    if compiled!=worker.read(root/"hybrid-schedule.json"): raise ValueError("hybrid component schedule changed")
    return root,design,setup,compiled


def _metrics_call(ledger, uid, task, command, cwd, timeout, provider):
    index,offer=ledger.reserve_call(uid,task)
    research=task["research"]
    research["queries_remaining"]=min(research["queries_remaining"],offer["queries"])
    research["bytes_remaining"]=(offer["received_bytes"] if task.get("workspace_protocol") else
        min(research.get("bytes_remaining",offer["received_bytes"]),offer["received_bytes"]))
    research["rounds_remaining"]=min(research["rounds_remaining"],offer["model_calls"]-1)
    research["seconds_remaining"]=min(research["seconds_remaining"],offer["seconds"]-5)
    if "workspace_budget" in research: research["workspace_budget"]["work_remaining"]=offer
    worker.write(Path(task["provider_metrics"]).parent/("hybrid-invoked-"+str(research["round"])+".json"),task)
    try:
        response=command(task,min(timeout,research["seconds_remaining"]))
    finally:
        ledger.observe_call(index,task,provider)
    if task.get("workspace_protocol"):
        queries=[q for lookup in response["workspace_actions"]["lookups"] for q in lookup["queries"]]
    else: queries=response.get("research",[])
    ledger.charge_queries(uid,queries,research["queries_remaining"])
    return response


def _native_bytes(directory):
    path=directory/"research.jsonl"
    return sum(len(json.dumps(json.loads(s)["result"],ensure_ascii=False).encode("utf-8"))
               for s in path.read_text(encoding="utf-8").splitlines()) if path.exists() else 0


def run_native(root, unit, opts, inputs, bridge, ledger):
    uid=unit["id"];directory=root/"treatment/native"/uid
    command=worker.read(opts["command"]);original=worker.execute;provider=bridge.runtime["provider"]
    offer=ledger.offer(uid)
    def execute(argv,cwd,env,timeout,payload=None):
        if argv!=command:
            seconds=min(timeout,ledger.seconds(uid))
            if seconds<=0: raise ValueError("hybrid native deadline reached")
            return original(argv,cwd,env,seconds,payload)
        ledger.observe_bytes(uid,_native_bytes(directory))
        task=json.loads(payload)
        return _metrics_call(ledger,uid,task,lambda frame,seconds:original(argv,cwd,env,seconds,json.dumps(frame)),cwd,timeout,provider)
    per=ledger.state["schedule"]["per_unit_limits"]
    args=Namespace(**{k:opts[k] for k in ("scanner","source_root","inventory","store","stream","claim","skill_root","provider_contract")},
        work_package=inputs["work_package"],reviewer_command=opts["command"],reviewer_label="hybrid-native",run=inputs["run"],
        source_profile=inputs["source_profile"],output=str(directory),phase="native",validate_only=True,supersede=False,artifact_root=None,
        resume_from=None,timeout=per["seconds"],research_rounds=per["model_calls"]-1,research_queries=per["queries"],research_bytes=per["received_bytes"],
        workers=1,query_workers=1,expert_workers=1,expert_command=None,expert_review_ids=None,source_collector_profile=None)
    try:
        with patch.object(worker,"execute",side_effect=execute): result=worker.run(args)
    finally: ledger.observe_bytes(uid,_native_bytes(directory))
    if result["status"]!="source_validated" or not result.get("usage_complete"):
        raise ValueError("native hybrid fragment incomplete; inspect preserved worker artifacts")
    native_drafts=[worker.read(path)["draft"] for path in (directory/"jobs").glob("*.json")]
    results=[r for draft in native_drafts for r in draft["results"]]
    if len(results)!=len(unit["review_ids"]) or {r["review_id"] for r in results}!=set(unit["review_ids"]):
        raise ValueError("native fragment result coverage differs")
    captures,drafts=[],[]
    for result in results:
        for window in result["evidence"]:
            for first in range(window["start_line"],window["end_line"]+1,400):
                captures.append({"kind":"source","review_id":result["review_id"],"path":window["path"],
                    "start_line":first,"end_line":min(first+399,window["end_line"])})
        drafts.append({"result":result,"applicability":[],"propositions":[]})
    with bridge.guarded():
        for index,capture in enumerate(captures): bridge.apply("native-source:"+uid+":"+str(index),capture)
        bridge.apply("native-import:"+uid,{"kind":"draft_batch","drafts":drafts})
    worker.write(directory/"hybrid-import.json",{"review_ids":unit["review_ids"],"drafts":native_drafts,
        "findings_sha256":worker.digest_file(directory/"findings.json"),"authority":"Exact native fragment drafts; no shared propositions or caller applicability inferred.","native_admission":False})
    return {"unit_id":uid,"route":"native","review_ids":unit["review_ids"],"directory":str(directory)}


def run_workspace(unit, opts, bridge, ledger):
    uid=unit["id"];parent=None
    command=worker.read(opts["command"]);original_remaining=bridge._remaining_seconds
    before=bridge.workspace.snapshot()["received_query_bytes"]
    # During a reserved call, usage is temporarily unknown; lookup deadlines must
    # use the already advertised deadline rather than requesting another offer.
    deadline=[time.time()+ledger.offer(uid)["seconds"]]
    bridge._remaining_seconds=lambda:min(original_remaining(),deadline[0]-time.time())
    try:
        while bridge.workspace.view(uid,bridge.metadata["experiment"]["context_max_bytes"])["claims"]:
            offer=ledger.offer(uid);deadline[0]=time.time()+offer["seconds"]
            session=bridge.prepare(uid,opts["config"],"hybrid:"+uid+":"+str(ledger.state["units"][uid]["model_calls"]),parent)["session_id"]
            parent=session
            def invoke(task):
                task["research"]["rounds_remaining"]=offer["model_calls"]-1
                return _metrics_call(ledger,uid,task,
                    lambda frame,seconds:worker.execute(command,bridge.directory,provider_environment(),seconds,json.dumps(frame)),
                    bridge.directory,offer["seconds"],bridge.runtime["provider"])
            try: bridge.review(session,opts["config"],invoke)
            finally: ledger.observe_bytes(uid,bridge.workspace.snapshot()["received_query_bytes"]-before)
    finally: bridge._remaining_seconds=original_remaining
    return {"unit_id":uid,"route":"workspace","review_ids":unit["review_ids"]}


def run(root):
    root,design,setup,compiled=load(root)
    opts=setup["arms"]["treatment"];bridge=NativeWorkspace(Namespace(**opts))
    with bridge.guarded():
        state=bridge.workspace.snapshot()
        if (identity(state)!=worker.read(root/"hybrid-binding.json")["prepared_state_id"] or
                state["sessions"] or state["calls"] or any(c["draft"] for c in state["claims"].values())):
            raise ValueError("hybrid execution requires prepared, undispatched state")
    pilot.begin_execution(root,"treatment")
    ledger=Ledger(root/"treatment/hybrid-ledger.json",compiled,design["per_arm_limits"],design["per_arm_experiment"])
    started=time.monotonic();completed=[];summary={"status":"running","units":completed,"native_admission":False}
    try:
        native_inputs=worker.read(root/"hybrid-native-inputs.json")
        for unit in compiled["units"]:
            ledger.start(unit["id"])
            result=(run_native(root,unit,opts,native_inputs[unit["id"]],bridge,ledger) if unit["route"]=="native"
                    else run_workspace(unit,opts,bridge,ledger))
            ledger.finish(unit["id"],True);completed.append(result)
            worker.write(root/"treatment/result.json",{**summary,"usage":ledger.usage()})
        if ledger.usage()["unobserved_calls"]: raise ValueError("unknown hybrid usage prevents completion")
        responses=root/"treatment/report-responses";responses.mkdir()
        finalized=[]
        for bid,bundle in bridge.metadata["bundles"].items():
            result=bridge.finalize(bid);finalized.append(result)
            worker.write(responses/bundle["filename"],worker.read(result["response"]))
        with bridge.guarded():
            report=bridge.native(["report","--run",str(bridge.directory/"run"),"--responses",str(responses),
                                  "--source-root",str(bridge.root),"--reviewer","hybrid-study"])
            package=bridge.workspace.review_package(list(bridge.metadata["bundles"]))
            drafts={p["bundles"][0]["bundle_id"]:p["bundles"][0]["draft_id"] for p in (worker.read(r["review_package"]) for r in finalized)}
            if any(drafts[b["bundle_id"]]!=b["draft_id"] for b in package["bundles"]):
                raise ValueError("hybrid review package differs from finalized original drafts")
            worker.write(root/"treatment/review-package.json",package)
            worker.write_text(root/"treatment/review-package.md",render_review_package(package))
        worker.write(root/"treatment/findings.json",report)
        summary["status"]="source_validated"
    except Exception as error:
        if len(completed)<len(compiled["units"]): ledger.finish(compiled["units"][len(completed)]["id"],False)
        summary["error"]={"type":type(error).__name__,"message":str(error) if isinstance(error,(ValueError,TimeoutError)) else "execution failed; inspect artifacts"}
        summary["status"]="incomplete"
    finally:
        summary.update(usage=ledger.usage(),workspace_usage=bridge.workspace.usage(),elapsed_ms=round(1000*(time.monotonic()-started)))
        worker.write(root/"treatment/result.json",summary)
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("prepare","run","check"))
    for name in ("root","design","output","private","scanner","provider-config","provider-executable","routing","routing-inventory","routing-manifest","planner-plan","selections"):
        parser.add_argument("--"+name)
    args=parser.parse_args()
    if args.command=="prepare":
        required=("design","output","private","scanner","provider_config","provider_executable","routing","routing_inventory","routing_manifest")
        if not all(getattr(args,key) for key in required): parser.error("prepare requires native/design/provider and bound routing inputs")
        result=prepare(args)
    else:
        if not args.root: parser.error("--root is required")
        result=run(args.root) if args.command=="run" else {"valid":bool(load(args.root)),"model_calls":0}
    print(json.dumps(result))


if __name__=="__main__": main()
