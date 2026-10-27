"""Matched native-bucket batches versus persistent workspace batches; experiment only."""
import argparse
from argparse import Namespace
import json
from pathlib import Path
import time

import review_workspace_pilot as pilot
import review_worker as worker
from review_workspace_bridge import NativeWorkspace, provider_environment
from review_workspace import render_review_package


def run_treatment(root):
    root,design,setup = pilot.load_run(root)
    if not design.get("batch_mode"):
        raise ValueError("batch comparison requires a batch-mode freeze")
    execution = pilot.begin_execution(root,"treatment")
    opts = setup["arms"]["treatment"]
    bridge = NativeWorkspace(Namespace(**opts))
    command = pilot.read(opts["command"])
    deadline = execution["started_epoch"]+design["per_arm_experiment"]["max_elapsed_seconds"]
    started,work_results = time.monotonic(),[]
    original_remaining = bridge._remaining_seconds
    summary = {"status":"running","work":work_results,"native_admission":False}
    try:
        for fingerprint,bundle in bridge.metadata["bundles"].items():
            wid,ids = "bundle-"+fingerprint,bundle["review_ids"]
            parent,calls = None,0
            bundle_deadline = min(deadline,time.time()+900)
            def remaining():
                seconds = min(original_remaining(),bundle_deadline-time.time())
                if seconds<=5: raise ValueError("matched bundle deadline reached")
                return seconds
            bridge._remaining_seconds = remaining
            while bridge.workspace.view(wid,131072)["claims"]:
                if calls>=6: raise ValueError("matched six-call bundle allowance reached")
                state = bridge.workspace.snapshot()
                units = sum(2 if l["query"]["tool"]=="definition" else 1 for l in state["lookups"].values()
                            if l["query"]["review_id"] in ids)
                received = sum(len(json.dumps(l["result"],ensure_ascii=False).encode()) for l in state["lookups"].values()
                               if l["status"]=="complete" and l["query"]["review_id"] in ids)
                if units>24 or received>=524288: raise ValueError("matched bundle research allowance reached")
                session = bridge.prepare(wid,opts["config"],f"batch:{fingerprint}:{calls}",parent)["session_id"]
                parent = session
                def invoke(task):
                    task["research"]["queries_remaining"] = min(task["research"]["queries_remaining"],max(0,24-units)) if calls<5 else 0
                    task["research"]["workspace_budget"]["work_remaining"] = {
                        "model_calls":6-calls,"queries":task["research"]["queries_remaining"],"received_bytes":524288-received}
                    seconds = min(task["research"]["seconds_remaining"],bundle_deadline-time.time())
                    task["research"]["seconds_remaining"] = max(0.1,seconds-5)
                    worker.write(bridge.directory/"sessions"/session/"invoked-task.json",task)
                    reply = worker.execute(command,bridge.directory,provider_environment(),seconds,json.dumps(task))
                    returned = sum(2 if q["tool"]=="definition" else 1 for l in reply["workspace_actions"]["lookups"] for q in l["queries"])
                    if returned>task["research"]["queries_remaining"]:
                        raise ValueError("response exceeds matched bundle lookup allowance")
                    return reply
                response = bridge.review(session,opts["config"],invoke)
                calls += 1
                print(json.dumps({"bundle":fingerprint,"turn":calls,"active":len(bridge.workspace.view(wid,131072)["claims"]),"usage":response["usage"]}),flush=True)
            validated = bridge.finalize(fingerprint)
            work_results.append({"bundle":fingerprint,"review_ids":ids,"calls":calls,"validated":validated})
            summary.update(usage=bridge.workspace.usage())
            worker.write(root/"treatment/result.json",summary)
        # Same native reporter validates full coverage; only control performs a
        # subsequent record into its fresh private study store via ordinary worker.
        responses = root/"treatment/report-responses";responses.mkdir()
        for fingerprint,bundle in bridge.metadata["bundles"].items():
            finalized = bridge.directory/"finalized"/fingerprint/"response.json"
            if not finalized.exists():
                finalized = Path(next(w["validated"]["response"] for w in work_results if w["bundle"]==fingerprint))
            worker.write(responses/bundle["filename"],pilot.read(finalized))
        with bridge.guarded():
            report = bridge.native(["report","--run",str(bridge.directory/"run"),"--responses",str(responses),
                "--source-root",str(bridge.root),"--reviewer","batch-workspace-study"])
            review = bridge.workspace.review_package(list(bridge.metadata["bundles"]))
            finalized_ids = {w["bundle"]:pilot.read(w["validated"]["review_package"])["bundles"][0]["draft_id"]
                             for w in work_results}
            if any(finalized_ids[b["bundle_id"]] != b["draft_id"] for b in review["bundles"]):
                raise ValueError("review package differs from the finalized native drafts")
            worker.write(root/"treatment/review-package.json",review)
            worker.write_text(root/"treatment/review-package.md",render_review_package(review))
        worker.write(root/"treatment/findings.json",report)
        summary["status"]="source_validated"
        summary["review_package"]=str(root/"treatment/review-package.json")
        summary["review_markdown"]=str(root/"treatment/review-package.md")
    except Exception as error:
        summary.update(status="incomplete",error={"type":type(error).__name__,"message":str(error) if isinstance(error,(ValueError,TimeoutError)) else "execution failed; inspect preserved artifacts"})
    finally:
        bridge._remaining_seconds = original_remaining
        state = bridge.workspace.snapshot()
        summary.update(usage=bridge.workspace.usage(),elapsed_ms=round(1000*(time.monotonic()-started)),
            claims={rid:{"decision":c["draft"]["result"]["decision"] if c["draft"] else None,
                         "reconsideration":c["reconsideration"]} for rid,c in state["claims"].items()})
        worker.write(root/"treatment/result.json",summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("prepare","control","treatment"))
    parser.add_argument("--root")
    for name in ("design","output","private","scanner","provider-config","provider-executable"):
        parser.add_argument("--"+name)
    args = parser.parse_args()
    if args.command=="prepare":
        if not all(getattr(args,k) for k in ("design","output","private","scanner","provider_config","provider_executable")):
            parser.error("prepare requires complete native/design/provider inputs")
        result = pilot.prepare(args)
    else:
        if not args.root: parser.error("execution requires --root")
        result = pilot.run_control(args.root) if args.command=="control" else run_treatment(args.root)
    print(json.dumps(result))


if __name__=="__main__":
    main()
