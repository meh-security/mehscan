#!/usr/bin/env python3
"""Freeze and run the bounded ordinary/workspace comparison. No target execution."""
from argparse import Namespace
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import review_context as context
import review_worker as worker
from review_workspace import encoded, identity
from review_workspace_bridge import NativeWorkspace, provider_environment


def read(path):
    return worker.read(path)


def canonical_windows(windows):
    result = {}
    for window in windows:
        location = window.get("location",window)
        text = window.get("text",window.get("excerpt"))
        lines = context.source_lines(text)
        value = {"path":location["path"],"start_line":location["start_line"],
                 "end_line":location["start_line"] + len(lines) - 1,"text":"\n".join(lines)}
        key = identity(value)
        result[key] = value
    return sorted(result.values(),key=lambda w:(w["path"],w["start_line"],w["end_line"],w["text"]))


def ordinary_windows(packet):
    return canonical_windows([*packet["primary"]["windows"],*packet["sweep"]["source_contexts"]])


def metrics(directory, attempted_calls=None):
    rows = {}
    for path in Path(directory).rglob("provider-metrics*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            key = (row["conversation_id"],row["round"])
            if key in rows and row != rows[key]:
                raise ValueError("conflicting provider metrics")
            rows[key] = row
    totals = {}
    for key in ("input_tokens","cached_input_tokens","output_tokens"):
        values = [r.get("usage",{}).get(key) for r in rows.values()]
        totals[key] = None if None in values else sum(values)
    observed = {"cumulative_model_call_ms":sum(r["elapsed_ms"] for r in rows.values()),**totals}
    if attempted_calls is None:
        return {"observed_calls":len(rows),**observed}
    if attempted_calls < len(rows):
        raise ValueError("provider metrics exceed reserved calls")
    unknown = attempted_calls - len(rows)
    return {"attempted_calls":attempted_calls,"observed_calls":len(rows),"unobserved_calls":unknown,
            "observed_totals":observed,**({k:None for k in observed} if unknown else observed)}


def begin_execution(root, arm):
    """Reserve an execution once, including failed/interrupted attempts."""
    directory = Path(root) / arm
    directory.mkdir(exist_ok=True)
    if (directory / "result.json").exists():
        raise ValueError("pilot arm already has a result; create a new bound run")
    reservation = directory / ".execution"
    reservation.mkdir(exist_ok=False)
    started = {"started_epoch":time.time(),"arm":arm}
    worker.write(reservation / "started.json",started)
    return started


def enforce_usage(usage, experiment):
    if any(usage[k] is None for k in ("input_tokens","output_tokens")):
        raise ValueError("unknown provider counters prevent more pilot dispatch")
    if usage["input_tokens"] >= experiment["max_input_tokens"] or usage["output_tokens"] >= experiment["max_output_tokens"]:
        raise ValueError("pilot observed token ceiling reached")


def native_case_limits(design):
    values = {"rounds":3,"queries":12,"bytes":131072,"timeout_seconds":600,
              **design.get("native_case_limits",{})}
    if set(values) != {"rounds","queries","bytes","timeout_seconds"}:
        raise ValueError("unknown native case limit")
    if any(type(v) is not int or v < 1 for v in values.values()) or values["rounds"] > 5 or values["timeout_seconds"] > 900:
        raise ValueError("native case limits exceed bounded comparison settings")
    return values


def prepare(args):
    design = read(args.design)
    root, private = Path(args.output).resolve(),Path(args.private).resolve()
    source = Path(design["source_pin"]["local_export"]).resolve(strict=True)
    if root.is_relative_to(source) or private.is_relative_to(source) or private.is_relative_to(root):
        raise ValueError("private state and outputs must be outside source and separate")
    root.mkdir(parents=True,exist_ok=False)
    private.mkdir(parents=True,exist_ok=False)
    package = root / "package"
    (package / "scripts").mkdir(parents=True)
    product = Path(__file__).resolve().parents[1]
    for name in ("review_workspace_pilot.py","review_workspace_bridge.py","review_workspace_actions.py","review_workspace.py","review_workspace_notebook.py","review_workspace_routes.py","review_workspace_planner.py",
                 "review_worker.py","review_context.py","review_orchestration.py","review_trace.py","review_export.py"):
        shutil.copyfile(product / "scripts" / name,package / "scripts" / name)
    shutil.copytree(product / "skills/mehscan-security",package / "skills/mehscan-security",
                    ignore=shutil.ignore_patterns("__pycache__",".git"))
    scanner = package / "mehscan.exe"
    shutil.copyfile(args.scanner,scanner)
    old = read(args.provider_config)
    executable = Path(args.provider_executable).resolve(strict=True)
    version = subprocess.check_output([str(executable),"--version"],text=True,encoding="utf-8").strip().removeprefix("codex-cli ")
    descriptor = {"schema_version":"1","provider":"codex-cli","executable_version":version,
                  "model":design["model"],"reasoning_effort":design["reasoning_effort"]}
    worker.write(root / "provider-contract.json",descriptor)
    skill = package / "skills/mehscan-security"
    def native(*arguments):
        return worker.execute([str(scanner),*arguments],root,provider_environment(),600)
    inventory = root / "inventory"
    native("investigate","review-inventory",str(source),"--repository-key",design["source_pin"]["native_repository_key"],"--output",str(inventory))
    inv = read(inventory / "inventory.json")
    if inv["identity_catalog"]["source_fingerprint"] != design["source_pin"]["native_source_fingerprint"]:
        raise ValueError("pilot source differs from the saved baseline")
    selected = design["selected_review_ids"]
    if not set(selected) <= {e["review_id"] for e in inv["entries"]}:
        raise ValueError("current native inventory lost frozen claim IDs; do not silently remap")
    setup = {"source_root":str(source),"scanner":str(scanner),"inventory":str(inventory),"skill_root":str(skill),
             "provider_contract":str(root / "provider-contract.json"),"arms":{}}
    for arm in ("control","treatment"):
        output, secret = root / arm, private / arm
        output.mkdir(); secret.mkdir()
        config = {**old,"executable":str(executable),"executable_version":version,"model":design["model"],
                  "reasoning_effort":design["reasoning_effort"],"private_directory":str(secret / "sessions")}
        worker.write(secret / "config.json",config)
        command = [sys.executable,str(skill / "scripts/codex_reviewer.py"),"--config",str(secret / "config.json")]
        worker.write(secret / "command.json",command)
        store = secret / "state"
        claim = native("state","claim","--store",str(store),"--stream","pilot","--inventory",str(inventory),
                       "--source-root",str(source),"--attempt-id","first","--expected-generation","0","--operation-key","claim")
        worker.write(secret / "claim.json",claim)
        common = ["--store",str(store),"--stream","pilot","--inventory",str(inventory),"--source-root",str(source),
                  "--generation",str(claim["result"]["generation"]),"--owner",claim["result"]["owner"],"--skill-root",str(skill),
                  "--provider-contract",str(root / "provider-contract.json")]
        case = native_case_limits(design)
        plan = native("state","plan-template","--inventory",str(inventory),"--source-root",str(source),"--policy","value",
                      "--skill-root",str(skill),"--provider-contract",str(root / "provider-contract.json"),
                      "--research-rounds",str(case["rounds"]),"--research-queries",str(case["queries"]),
                      "--research-bytes",str(case["bytes"]),"--timeout",str(case["timeout_seconds"]))
        plan["selected_review_ids"] = selected
        plan["deferred_review_ids"] = {e["review_id"]:"Outside the frozen 12-claim workspace pilot" for e in inv["entries"] if e["review_id"] not in selected}
        worker.write(output / "plan.json",plan)
        native("state","plan",*common,"--input",str(output / "plan.json"),"--operation-key","plan")
        work = native("state","work",*common,"--review-ids",",".join(selected))
        worker.write(output / "work.json",work)
        opts = {**{k:setup[k] for k in ("scanner","source_root","inventory","skill_root","provider_contract")},
                "store":str(store),"stream":"pilot","claim":str(secret / "claim.json"),"work_package":str(output / "work.json"),
                "directory":str(output / "workspace"),"config":str(secret / "config.json"),"command":str(secret / "command.json")}
        setup["arms"][arm] = opts
        if arm == "control":
            native("investigate","review-bundles",str(source),"--inventory",str(inventory),"--review-ids",",".join(selected),
                   "--max-reviews","1","--output",str(output / "bundles"))
        else:
            exp = {**design["per_arm_experiment"],"protocol":"workspace-actions-v2","bundle_max_reviews":1,
                   "prepare_application":True,"max_received_query_bytes":design["per_arm_limits"]["source_bytes"]}
            bridge = NativeWorkspace.create(Namespace(**opts),design["per_arm_limits"],exp)
            ids = list(selected)
            for i,claim_id in enumerate(ids):
                work_id = "claim-" + str(i)
                bridge.apply("split:" + claim_id,{"kind":"split","work_id":"initial","new_work_id":work_id,
                    "review_ids":[claim_id],"strategy":"selected-relationship"})
                bridge.apply("focus:" + claim_id,{"kind":"focus","work_id":work_id,
                    "evidence_ids":bridge.metadata["initial_evidence"][claim_id],"proposition_ids":[]})
    # Verify actual line content, including native application-policy preparation.
    parity = {}
    control_run = root / "control/bundles"
    manifest = read(control_run / "manifest.json")
    for bundle in manifest["bundles"]:
        claim_id = bundle["review_ids"][0]
        sweep = native("investigate","review-sweep","--bundle",str(control_run / "requests" / bundle["filename"]))
        app = context.prepare_application(source,sweep,{},bridge.payload["snapshot_id"])
        expected = canonical_windows([*sweep["source_contexts"],*app["windows"]])
        evidence = bridge.workspace.snapshot()["evidence"]
        actual = canonical_windows([evidence[k] for k in bridge.metadata["initial_evidence"][claim_id]])
        if actual != expected:
            raise ValueError("initial source parity failed for " + claim_id)
        parity[claim_id] = {"windows":expected,"sha256":identity(expected),"bytes":sum(len(w["text"].encode()) for w in expected)}
    worker.write(root / "initial-evidence.json",parity)
    worker.write(root / "setup.json",setup)
    worker.write(root / "design.json",design)
    # Offline launcher capability check; no inference call or evaluator labels.
    sys.path.insert(0,str(skill / "scripts"))
    from codex_launcher import Launcher
    preflight = private / "preflight"
    preflight.mkdir()
    Launcher(read(setup["arms"]["control"]["config"]),preflight)
    files = [p for p in package.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    binding = {"schema_version":"mehscanWorkspacePilotRun/v1","created_epoch_ms":round(time.time()*1000),
               "design_sha256":worker.digest_file(root / "design.json"),"initial_evidence_sha256":worker.digest_file(root / "initial-evidence.json"),
               "setup_sha256":worker.digest_file(root / "setup.json"),"provider":descriptor,
               "source_fingerprint":inv["identity_catalog"]["source_fingerprint"],"inventory_input_fingerprint":inv["input_fingerprint"],
               "files":{str(p.relative_to(root)).replace("\\","/"):worker.digest_file(p) for p in files},
               "source_parity":"Same returned line ranges and canonical UTF-8 line bytes; CRLF and reader terminal newline normalized. Source-table AST endpoints are not treated as extra source lines. Packet formatting differs.",
               "byte_policy":"Both arms count every received/reused result JSON using ensure_ascii=False, including guidance/navigation. Global 1.5MiB and native per-claim 128KiB. Unique source bytes additionally tracked in workspace.",
               "case_policy":"Maximum 4 calls and 12 query units per claim; same native runtime. Global limits remain binding.","selected_claims":selected}
    worker.write(root / "run-binding.json",binding)
    return {"prepared":True,"directory":str(root),"claims":len(selected),"model_calls":0,"provider":descriptor}


def load_run(root):
    root = Path(root).resolve(strict=True)
    binding = read(root / "run-binding.json")
    for name,key in (("design.json","design_sha256"),("initial-evidence.json","initial_evidence_sha256"),("setup.json","setup_sha256")):
        if worker.digest_file(root / name) != binding[key]: raise ValueError("frozen pilot input changed")
    for name,digest in binding["files"].items():
        if worker.digest_file(root / name) != digest: raise ValueError("frozen package changed")
    return root,read(root / "design.json"),read(root / "setup.json")


def run_control(root):
    root,design,setup = load_run(root)
    execution = begin_execution(root,"control")
    opts = setup["arms"]["control"]
    output = root / "control/worker"
    budget = {"reserved_calls":0,"queries":0,"started_epoch":execution["started_epoch"]}
    command = read(opts["command"])
    original = worker.execute
    parity = read(root / "initial-evidence.json")
    def execute(argv,cwd,env,timeout,payload=None):
        if argv != command:
            return original(argv,cwd,env,timeout,payload)
        usage = metrics(output,budget["reserved_calls"])
        enforce_usage(usage,design["per_arm_experiment"])
        if usage["observed_calls"] != budget["reserved_calls"]:
            raise ValueError("unobserved ordinary call prevents another dispatch")
        if budget["reserved_calls"] >= design["per_arm_limits"]["model_calls"]:
            raise ValueError("ordinary aggregate call ceiling reached")
        elapsed = time.time() - budget["started_epoch"]
        remaining = design["per_arm_experiment"]["max_elapsed_seconds"] - elapsed
        if remaining <= 0: raise ValueError("ordinary pilot deadline reached")
        task = json.loads(payload)
        if task["research"]["round"] == 0:
            packet = read(task["evidence_packet"])
            if len(task["review_ids"]) != 1 or identity(ordinary_windows(packet)) != parity[task["review_ids"][0]]["sha256"]:
                raise ValueError("actual ordinary context differs from frozen source parity receipt")
        rows = [json.loads(s) for s in (output / "research.jsonl").read_text().splitlines()] if (output / "research.jsonl").exists() else []
        received = sum(len(json.dumps(r["result"],ensure_ascii=False).encode()) for r in rows)
        if received >= design["per_arm_limits"]["source_bytes"]:
            raise ValueError("ordinary aggregate received-byte ceiling reached")
        budget["reserved_calls"] += 1
        worker.write(root / "control/budget.json",{**budget,"usage":usage,"received_query_bytes":received})
        value = original(argv,cwd,env,min(timeout,remaining),payload)
        units = worker.research_cost(value.get("research",[]))
        if budget["queries"] + units > design["per_arm_limits"]["queries"]:
            raise ValueError("ordinary aggregate query ceiling reached")
        budget["queries"] += units
        worker.write(root / "control/budget.json",{**budget,"usage":metrics(output,budget["reserved_calls"]),"received_query_bytes":received})
        return value
    args = Namespace(**{k:opts[k] for k in ("scanner","source_root","inventory","store","stream","claim","work_package","skill_root","provider_contract")},
        reviewer_command=opts["command"],reviewer_label="pilot-ordinary",run=str(root / "control/bundles"),output=str(output),
        phase="native",supersede=False,artifact_root=None,resume_from=None,timeout=None,research_rounds=None,research_queries=None,research_bytes=None,
        workers=1,query_workers=1,expert_workers=1,expert_command=None,expert_review_ids=None,source_collector_profile=None)
    worker.execute = execute
    started = time.monotonic()
    try:
        result = worker.run(args)
        summary = {"status":result["status"],"usage":metrics(output,budget["reserved_calls"]),"elapsed_ms":round((time.monotonic()-started)*1000)}
    except Exception as error:
        summary = {"status":"incomplete","error":type(error).__name__ + ": " + str(error),"usage":metrics(output,budget["reserved_calls"]),
                   "elapsed_ms":round((time.monotonic()-started)*1000)}
    finally:
        worker.execute = original
    worker.write(root / "control/result.json",summary)
    return summary


def run_treatment(root):
    root,design,setup = load_run(root)
    execution = begin_execution(root,"treatment")
    opts = setup["arms"]["treatment"]
    bridge = NativeWorkspace(Namespace(**opts))
    command = read(opts["command"])
    binding = read(root / "run-binding.json")
    prior = binding.get("prior_treatment_calls_by_claim",{})
    deadline = binding.get("treatment_deadline_epoch",execution["started_epoch"] + design["per_arm_experiment"]["max_elapsed_seconds"])
    started, outcomes = time.monotonic(),[]
    try:
        for index,claim_id in enumerate(design["selected_review_ids"]):
            work_id,case_calls,case_queries = "claim-" + str(index),prior.get(claim_id,0),0
            case_started = time.monotonic()
            while bridge.workspace.view(work_id)["claims"]:
                if time.time() >= deadline: raise ValueError("workspace whole-trial deadline reached")
                if case_calls >= 4: raise ValueError("workspace native case call allowance exhausted for " + claim_id)
                session = bridge.prepare(work_id,opts["config"],f"case:{index}:turn:{case_calls}")["session_id"]
                def invoke(task):
                    task["research"]["queries_remaining"] = min(task["research"]["queries_remaining"],12-case_queries) if case_calls < 3 else 0
                    task["research"]["workspace_budget"]["case_remaining"] = {"model_calls":4-case_calls,"queries":12-case_queries}
                    task["research"]["seconds_remaining"] = min(task["research"]["seconds_remaining"],600-(time.monotonic()-case_started),deadline-time.time())
                    value = worker.execute(command,bridge.directory,provider_environment(),task["research"]["seconds_remaining"],json.dumps(task))
                    lookups = value["workspace_actions"]["lookups"]
                    units = sum(2 if q["tool"] == "definition" else 1 for l in lookups for q in l["queries"])
                    if (case_calls >= 3 and lookups) or units > 12-case_queries:
                        raise ValueError("workspace response exceeds native case lookup allowance")
                    return value
                result = bridge.review(session,opts["config"],invoke)
                case_calls += 1
                state = bridge.workspace.snapshot()
                case_queries = sum(2 if l["query"]["tool"] == "definition" else 1 for l in state["lookups"].values() if l["query"]["review_id"] == claim_id)
                received = sum(len(json.dumps(l["result"],ensure_ascii=False).encode()) for l in state["lookups"].values()
                               if l["status"] == "complete" and l["query"]["review_id"] == claim_id)
                if received > 131072: raise ValueError("workspace native case received-byte allowance exceeded")
                print(json.dumps({"arm":"treatment","claim":index+1,"turn":case_calls,"usage":result["usage"]}),flush=True)
            claim = bridge.workspace.snapshot()["claims"][claim_id]
            validated = bridge.finalize(claim["bundle_id"])
            outcomes.append({"review_id":claim_id,"decision":claim["draft"]["result"]["decision"],"calls":case_calls,"validated":validated})
        summary = {"status":"source_validated","claims":outcomes,"usage":bridge.workspace.usage(),"elapsed_ms":round((time.monotonic()-started)*1000)}
    except Exception as error:
        summary = {"status":"incomplete","error":type(error).__name__ + ": " + str(error),"claims":outcomes,
                   "usage":bridge.workspace.usage(),"elapsed_ms":round((time.monotonic()-started)*1000)}
    worker.write(root / "treatment/result.json",summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("prepare","control","treatment"))
    parser.add_argument("--output",required=True)
    parser.add_argument("--private")
    parser.add_argument("--design")
    parser.add_argument("--scanner")
    parser.add_argument("--provider-config")
    parser.add_argument("--provider-executable")
    args = parser.parse_args()
    result = prepare(args) if args.command == "prepare" else (run_control if args.command == "control" else run_treatment)(args.output)
    print(json.dumps(result,ensure_ascii=False))


if __name__ == "__main__":
    main()
