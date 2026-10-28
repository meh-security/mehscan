#!/usr/bin/env python3
"""Read saved workspace turns without executing controllers, providers or targets."""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3

VERSION = "mehscanWorkspaceTurnAudit/v1"
AUTHORITY = "Read-only audit of archived records; no runtime revalidation, native admission or permission to dispatch. Reviewer judgments remain interpretations."


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def returned_fact(result):
    """Keep navigation/limits verbatim; source text is addressed by its receipt."""
    if not isinstance(result,dict):
        return result
    if result.get("operation") in ("get_source","prepared_source"):
        value = {**result}
        if isinstance(result.get("results"),dict):
            value["results"] = {k:v for k,v in result["results"].items() if k!="text"}
        return value
    if result.get("operation")=="get_definition" and "source" in result:
        return {**result,"source":returned_fact(result["source"])}
    return result


def children(action):
    if action.get("kind") == "review_updates":
        return [a for item in action["updates"] for a in children(item)]
    if action.get("kind") == "draft_batch":
        return [{"kind":"draft",**item} for item in action["drafts"]]
    return [action]


def load_records(directory):
    path = Path(directory).resolve() / "workspace.sqlite"
    # mode=ro also refuses to create a missing database. A transaction gives one
    # consistent snapshot of state and receipts, including any existing WAL.
    with closing(sqlite3.connect(path.as_uri()+"?mode=ro",uri=True)) as db:
        db.execute("BEGIN")
        state = json.loads(db.execute("SELECT body FROM workspace WHERE id=1").fetchone()[0])
        receipts = [{"key":key,"request":json.loads(q),"response":json.loads(r)}
                    for key,q,r in db.execute("SELECT key,request,response FROM receipts")]
    receipts.sort(key=lambda r:r["request"]["revision"])
    gaps = []
    for expected,record in enumerate(receipts):
        if record["request"]["revision"] != expected or record["response"]["revision"] != expected+1:
            gaps.append(record["key"])
    if len(receipts) != state["revision"]:
        gaps.append("final_revision_does_not_match_receipt_count")
    return state,receipts,gaps


def source_status(state):
    root = Path(state["source_root"])
    expected = {}
    for evidence in state.get("evidence",{}).values():
        expected.setdefault(evidence["path"],set()).add(evidence["file_sha256"])
    rows = []
    for relative,hashes in sorted(expected.items()):
        item = {"path":relative,"recorded_sha256":sorted(hashes)}
        path = root / relative
        try:
            if (Path(relative).is_absolute() or ".." in Path(relative).parts or
                    not path.resolve().is_relative_to(root.resolve()) or
                    any(p.is_symlink() for p in (path,*path.parents))):
                raise ValueError("unsafe source path")
            actual = file_digest(path)
            item.update(status="current" if hashes=={actual} else "stale",current_sha256=actual)
        except (OSError,ValueError):
            item["status"] = "unavailable"
        rows.append(item)
    return {"authority":"Current captured-file hashes only; not whole-snapshot or runtime revalidation.",
            "files":rows,"all_captured_files_current":bool(rows) and all(r["status"]=="current" for r in rows)}


def saved_inputs(directory,sid,session,gaps):
    if not re.fullmatch(r"[0-9a-f]{64}",sid):
        raise ValueError("invalid saved session ID")
    folder = directory / "sessions" / sid
    artifacts = session.get("artifacts")
    if not artifacts:
        gaps.append("No attached provider artifacts; offered IDs and dispatch are unknown.")
        return None,None,None
    for name in ("task.json","context.json","facts.json"):
        if not (folder/name).is_file():
            gaps.append("Missing attached artifact: "+name)
            return None,None,None
        if file_digest(folder/name) != artifacts["files"].get(name):
            raise ValueError("saved provider artifact hash differs: "+sid+"/"+name)
    task,packet = read(folder/"task.json"),read(folder/"context.json")
    if task.get("conversation_id") != sid:
        raise ValueError("saved task does not identify its session")
    ids = task["review_ids"]
    if len(ids)!=len(set(ids)) or set(ids)!={q["review_id"] for q in packet["native_questions"]}:
        raise ValueError("saved task and native question IDs differ")
    if packet.get("workspace_evidence",{}).get("answer_consumers",{}) != session["packet"].get("answer_consumers",{}):
        raise ValueError("provider and working-view answer consumers differ")
    # Do not rebuild a historical output schema using today's adapter.
    gaps.append("Output schema is not attached; task IDs record decision authority, not a recovered schema enum.")
    dispatch = None
    invoked = folder/"hybrid-invoked-0.json"
    if invoked.is_file():
        value = read(invoked)
        if {k:v for k,v in value.items() if k!="research"} != {k:v for k,v in task.items() if k!="research"}:
            raise ValueError("recorded dispatch differs from the attached task outside research")
        # Dispatch budgets are separate mutable observations, never session identity.
        dispatch = {"authority":"Recorded dispatch file, outside the prepared artifact hash binding.",
                    "file_sha256":file_digest(invoked),"research":{k:value["research"].get(k) for k in
                        ("rounds_remaining","queries_remaining","bytes_remaining","seconds_remaining")},
                    "work_remaining":value["research"].get("workspace_budget",{}).get("work_remaining")}
    else:
        gaps.append("No dispatch offer saved; prepared research limits are not actual remaining credit.")
    return task,packet,dispatch


def boundary(state,sessions,index,revision):
    sid,session,created = sessions[index]
    for next_id,next_session,next_revision in sessions[index+1:]:
        if next_session["work_id"] == session["work_id"] and next_revision > revision:
            view = next_session["packet"]
            return {"kind":"next_same_work_prepared_view","session_id":next_id,"revision":next_revision,
                    "active_ids":[c["review_id"] for c in view["claims"]],
                    "recorded_reconsideration":{c["review_id"]:c["reconsideration"] for c in view["claims"]},
                    "authority":"Observed next preparation boundary, not necessarily immediate response state."}
    members = state["work"].get(session["work_id"],{}).get("claims",[])
    return {"kind":"final_workspace_snapshot","revision":state["revision"],
            "active_ids":[rid for rid in members if state["claims"][rid]["draft"] is None or state["claims"][rid]["reconsideration"]],
            "recorded_reconsideration":{rid:state["claims"][rid]["reconsideration"] for rid in members},
            "authority":"Observed final state; later receipts may contribute to these flags."}


def audit_directory(directory,session_id=None):
    directory = Path(directory).resolve()
    state,receipts,chain_gaps = load_records(directory)
    by_key = {r["key"]:r for r in receipts}
    flat = [(r,a) for r in receipts for a in children(r["request"]["action"])]
    created = {r["response"]["result"]["session_id"]:r for r in receipts if r["request"]["action"]["kind"]=="session"}
    sessions = sorted([(sid,s,created[sid]["response"]["revision"]) for sid,s in state["sessions"].items()],key=lambda row:row[2])
    if session_id and session_id not in state["sessions"]:
        raise ValueError("unknown saved session")
    judgments,turns = {},[]
    for index,(sid,session,revision) in enumerate(sessions):
        if session_id and sid!=session_id:
            continue
        gaps = []
        if chain_gaps:
            gaps.append("Receipt chain is incomplete; historical action/previous-judgment links may be incomplete.")
        view = session["packet"]
        if digest(view) != created[sid]["response"]["result"]["packet_digest"]:
            raise ValueError("saved working view digest differs: "+sid)
        task,packet,dispatch = saved_inputs(directory,sid,session,gaps)
        active = [c["review_id"] for c in view["claims"]]
        consumers = view.get("answer_consumers",{})
        offered = task["review_ids"] if task else None
        prior = {}
        for record,action in flat:
            if record["response"]["revision"] >= revision:
                break
            if action["kind"]=="draft":
                prior[action["result"]["review_id"]] = action["result"]
        consumer_rows = {}
        named = {rid for q in view["questions"].values() for rid in q.get("settled_review_ids",[])}|set(consumers)
        for rid in sorted(named):
            result = consumers.get(rid,{}).get("previous_result") or prior.get(rid)
            key = digest(result) if result else None
            if result:
                judgments[key] = result
            consumer_rows[rid] = {"offered":rid in offered if offered is not None else None,
                "previous_judgment_sha256":key,"previous_judgment_was_delivered":"previous_result" in consumers.get(rid,{}),
                "question_ids":[qid for qid,q in view["questions"].items() if rid in q["review_ids"]]}
        committed = by_key.get("actions:"+sid) or by_key.get("answer:"+sid)
        actions = children(committed["request"]["action"]) if committed else []
        accepted_revision = committed["response"]["revision"] if committed else revision
        post = boundary(state,sessions,index,accepted_revision)
        post["intervening_receipts"] = [{"key":r["key"],"kind":r["request"]["action"]["kind"],"revision":r["response"]["revision"]}
            for r in receipts if accepted_revision < r["response"]["revision"] < post["revision"]]
        answers = [{"question_id":a["question_id"],"before":view["questions"].get(a["question_id"]),
                    "committed_update":a} for a in actions if a["kind"]=="answer"]
        lookups = []
        for record,action in flat:
            if action["kind"]!="lookup_request" or not action["lookup_id"].startswith(sid+":"):
                continue
            lid = action["lookup_id"];saved = state["lookups"].get(lid,{})
            evidence = saved.get("evidence",[])
            later_answers = [{"revision":r["response"]["revision"],"question_id":a["question_id"],"status":a["status"],
                              "reason":a["reason"],"shared_evidence_ids":sorted(set(a.get("evidence",[]))&set(evidence))}
                for r,a in flat if r["request"]["revision"]>=record["response"]["revision"] and
                a["kind"]=="answer" and a["question_id"]==action["question_id"]]
            lookups.append({"lookup_id":lid,"requested_question":action.get("requested_question"),"beneficiary_ids":action.get("review_ids"),
                "question_id":action["question_id"],"query":action["query"],"charged_query_units":action["units"],
                "status":saved.get("status","missing"),"result_operation":(saved.get("result") or {}).get("operation"),
                "returned_fact":returned_fact(saved.get("result")),
                "result_sha256":digest(saved["result"]) if saved.get("result") is not None else None,
                "received_bytes":saved.get("received_bytes"),"native_query_count":saved.get("native_query_count"),
                "reused_from":saved.get("reused_from"),"evidence":[{"evidence_id":eid,**{k:state["evidence"][eid][k]
                    for k in ("path","start_line","end_line","file_sha256")}} for eid in evidence],
                "presented_in_sessions":[other for other,s,_ in sessions if lid in s["packet"].get("lookups",{})],
                "later_same_question_answers":later_answers})
        calls = [c for c in state["calls"].values() if c["session_id"]==sid]
        if not committed:
            gaps.append("No committed response receipt; submitted answers are not accepted decisions.")
        turns.append({"ordinal":index+1,"session_id":sid,"work_id":session["work_id"],"prepared_revision":revision,
            "active_ids":active,"offered_ids":offered,"answer_consumers":consumer_rows,
            "hidden_settled_consumer_ids":[rid for rid,c in consumer_rows.items() if c["offered"] is False],
            "schema_eligibility":{"status":"not_attached","task_authority_ids":offered},
            "presented_questions":view["questions"],"presented_propositions":view["propositions"],"presented_applicability":view["applicability"],
            "prepared_budget":view["budget"],"recorded_dispatch_offer":dispatch,
            "usage_status":"not_dispatched" if not calls else "unknown" if any(c["usage"] is None or any(c["usage"].get(k) is None for k in ("input_tokens","cached_input_tokens","output_tokens","elapsed_ms")) for c in calls) else "observed",
            "recorded_calls":calls,"committed_response_revision":committed["response"]["revision"] if committed else None,
            "committed_decisions":[a["result"] for a in actions if a["kind"]=="draft"],
            "draft_dependencies":{a["result"]["review_id"]:{k:v for k,v in a.items() if k not in ("kind","result")} for a in actions if a["kind"]=="draft"},
            "answer_changes":answers,"lookups":lookups,"observed_after":post,"gaps":gaps})
    return {"schema_version":VERSION,"kind":"archived_workspace","authority":AUTHORITY,
        "workspace":str(directory),"database_sha256":file_digest(directory/"workspace.sqlite"),
        "binding":state["binding"],"receipt_chain_gaps":chain_gaps,"source_status":source_status(state),
        "claim_catalog":{rid:{k:c[k] for k in ("path","line","property")} for rid,c in state["claims"].items()},
        "turns":turns,"previous_judgments":judgments,
        "qualified_propositions":state.get("propositions",{}),
        "final_claims":{rid:{"drafted":c["draft"] is not None,"reconsideration":c["reconsideration"]} for rid,c in state["claims"].items()}}


def audit_projection(directory):
    directory = Path(directory).resolve()
    view,packet,schema = [read(directory/name) for name in ("projected-view.json","projected-packet.json","projected-schema.json")]
    state = read(directory/"pre-answer-state.json")
    offered = packet["work"]["review_ids"]
    enums = schema["properties"]["decisions"]["items"]["anyOf"]
    eligible = sorted({rid for variant in enums for rid in variant["properties"]["review_id"]["enum"]})
    consumers = view["answer_consumers"]
    if packet.get("workspace_evidence",{}).get("answer_consumers",{}) != consumers:
        raise ValueError("diagnostic provider and view consumers differ")
    if set(offered)!=set(eligible) or set(offered)!={c["review_id"] for c in view["claims"]}|set(consumers):
        raise ValueError("diagnostic projection eligibility differs")
    judgments,rows = {},{}
    for rid,c in consumers.items():
        if c["previous_result"] != state["claims"][rid]["draft"]["result"]:
            raise ValueError("diagnostic previous judgment differs")
        key = digest(c["previous_result"]);judgments[key] = c["previous_result"]
        rows[rid] = {"offered":True,"previous_judgment_sha256":key,"previous_judgment_was_delivered":True,"question_ids":c["question_ids"]}
    return {"schema_version":VERSION,"kind":"diagnostic_projection","authority":AUTHORITY+" This derivative has no bound session, dispatch or new verdict.",
        "input_sha256":{name:file_digest(directory/name) for name in ("projected-view.json","projected-packet.json","projected-schema.json","pre-answer-state.json")},
        "source_status":source_status(state),"previous_judgments":judgments,"qualified_propositions":view["propositions"],
        "claim_catalog":{rid:{k:c[k] for k in ("path","line","property")} for rid,c in state["claims"].items()},
        "turns":[{"session_id":None,"work_id":view["work_id"],"active_ids":[c["review_id"] for c in view["claims"]],
            "offered_ids":offered,"answer_consumers":rows,"hidden_settled_consumer_ids":[],
            "schema_eligibility":{"status":"saved_diagnostic_schema","ids":eligible},
            "presented_questions":view["questions"],"presented_propositions":view["propositions"],"presented_applicability":view["applicability"],
            "prepared_budget":{"authority":"Copied historical counters, not new spending or usable credit.","value":view["budget"]},
            "recorded_dispatch_offer":None,"usage_status":"diagnostic_only","recorded_calls":[],
            "committed_decisions":[],"draft_dependencies":{},"answer_changes":[],"lookups":[],"observed_after":None,
            "gaps":["Projection only: no reviewer action or resulting state exists."]}]}


def block(value):
    text = json.dumps(value,ensure_ascii=False,indent=2)
    fence = "`"*max(3,1+max((len(s) for s in re.findall(r"`+",text)),default=0))
    return fence+"json\n"+text+"\n"+fence


def render(report):
    def claim(rid):
        entry = report["claim_catalog"].get(rid,{})
        return rid+" ("+entry.get("path","unknown")+":"+str(entry.get("line","?"))+")"
    lines = ["# Workspace turn audit","",report["authority"],"", "Record kind: "+report["kind"],"",
        "Current captured source hashes: "+("match" if report["source_status"]["all_captured_files_current"] else "stale, unavailable or absent"),"",
        "Historical decisions remain recorded judgments even when current source differs.","",
        "| Turn | Active | Offered | Settled consumers | Hidden | Committed decisions | Remaining at boundary | Usage |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    for i,turn in enumerate(report["turns"],1):
        remaining = len(turn["observed_after"]["active_ids"]) if turn["observed_after"] is not None else "unobserved"
        offered = len(turn["offered_ids"]) if turn["offered_ids"] is not None else "unknown"
        lines.append(f"| {turn.get('ordinal',i)} | {len(turn['active_ids'])} | {offered} | {len(turn['answer_consumers'])} | {len(turn['hidden_settled_consumer_ids'])} | {len(turn['committed_decisions'])} | {remaining} | {turn['usage_status']} |")
    lines.append("")
    for i,turn in enumerate(report["turns"],1):
        lines.extend([f"## Turn {turn.get('ordinal',i)}","",block({k:turn.get(k) for k in ("session_id","work_id","schema_eligibility")}),"",
            "Active claims:",block([claim(rid) for rid in turn["active_ids"]]),"",
            "Settled consumers (previous judgments linked by digest):",block(turn["answer_consumers"]),"",
            "Presented deciding questions:",block({qid:{"question":q["question"],"status":q["status"],"latest_answer":q["attempts"][-1] if q["attempts"] else None} for qid,q in turn["presented_questions"].items()}),"",
            "Presented proposition revisions (full qualified records below):",block({pid:p["revision"] for pid,p in turn["presented_propositions"].items()}),"",
            "Presented caller applicability:",block(turn["presented_applicability"]),"",
            "### Recorded credit and usage","",block({k:turn.get(k) for k in ("recorded_dispatch_offer","usage_status","recorded_calls")}),"",
            "Prepared aggregate budget, which may exceed actual dispatch credit:",block(turn["prepared_budget"]),"",
            "### Deciding lookups","","Later same-question answers are recorded links, not proof that a lookup caused a verdict.",""])
        for lookup in turn["lookups"]:
            lines.extend([block({k:lookup[k] for k in ("lookup_id","question_id","requested_question","query","charged_query_units","status","result_operation","returned_fact","received_bytes","native_query_count","reused_from","evidence","presented_in_sessions","later_same_question_answers")}),""])
        if not turn["lookups"]:
            lines.extend(["No committed lookup requests in this turn.",""])
        lines.extend(["### Committed answer changes and decisions","",block({k:turn.get(k) for k in ("committed_response_revision","answer_changes","committed_decisions","draft_dependencies")}),"",
            "### Observed remaining work","",block(turn["observed_after"]),"","Evidence gaps:",block(turn["gaps"]),""])
    lines.extend(["## Previous judgments","","Exact results, indexed by their digest; interpretations, not automatic confirmations.","",block(report["previous_judgments"]),"",
        "## Qualified propositions","",block(report["qualified_propositions"]),"","## Current captured-file checks","",block(report["source_status"]),""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--directory",help="saved workspace directory containing workspace.sqlite and sessions/")
    inputs.add_argument("--projection-directory",help="AS-style diagnostic projection directory; never a runnable session")
    parser.add_argument("--session-id",help="focus one saved session; final state and source checks retain their full scope")
    parser.add_argument("--format",choices=("json","markdown"),default="markdown")
    args = parser.parse_args()
    if args.session_id and not args.directory:
        parser.error("session-id requires directory")
    try:
        result = audit_directory(args.directory,args.session_id) if args.directory else audit_projection(args.projection_directory)
    except (OSError,ValueError,KeyError,sqlite3.Error) as error:
        parser.exit(2,"Audit unavailable: "+str(error)+"\n")
    print(render(result) if args.format=="markdown" else json.dumps(result,ensure_ascii=False,indent=2))


if __name__ == "__main__":
    main()
