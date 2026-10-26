"""Controller execution of compact reviewer changes and deciding lookups."""
import copy
import time

import review_context as context
import review_worker as worker
from review_workspace import identity, label, references, shape, source

VERSION = "workspace-actions-v2"
ALLOWED = {"proposition","applicability","question","answer","dispute","focus"}


def citation_windows(bridge, windows, citation):
    """Split a spanning citation into supplied windows; never bridge unseen code.

    Adjacent captured definitions often have an uncaptured blank separator. The
    controller may verify that whitespace and cite the shown parts separately,
    without changing the reviewer's judgment or delivering new substantive code.
    """
    shape(citation,("path","start_line","end_line"))
    first,last = citation["start_line"],citation["end_line"]
    if type(first) is not int or type(last) is not int or not 1 <= first <= last:
        raise ValueError("invalid decision citation range")
    spans = sorted((max(first,w["start_line"]),min(last,w["end_line"])) for w in windows
                   if w["path"] == citation["path"] and w["start_line"] <= last and first <= w["end_line"])
    if any(a == first and b == last for a,b in spans):
        return [citation]
    if not spans:
        raise ValueError("decision cites source outside its context")
    visible = set(line for a,b in spans for line in range(a,b+1))
    # No unbounded range allocation or out-of-file whitespace projection.
    if last-first > 2000:
        raise ValueError("decision cites source outside its context")
    missing = set(range(first,last+1))-visible
    if missing:
        lines = source(bridge.root,citation["path"]).decode("utf-8-sig").splitlines()
        if last > len(lines) or any(lines[line-1].strip() for line in missing):
            raise ValueError("decision cites source outside its context")
    selected,through = [],first-1
    for a,b in spans:
        if b <= through:
            continue
        # Each output range stays inside one actual supplied window.
        selected.append({"path":citation["path"],"start_line":max(a,through+1),"end_line":b})
        through = b
    return selected


def native_decision(result, state):
    """Render outstanding native work from saved questions, never from a checklist."""
    if "checks" in result or "blockers" in result:
        raise ValueError("native checks and blockers are controller-owned")
    result = copy.deepcopy(result)
    checks, blockers = [],[]
    if result["decision"] == "needs_review":
        for _,question in sorted(state["questions"].items()):
            if result["review_id"] not in question["review_ids"] or question["status"] == "answered":
                continue
            checks.append(question["question"])
            if question["status"] == "blocked":
                blockers.append(question["attempts"][-1]["reason"])
        if not checks:
            raise ValueError("needs_review requires a saved unresolved deciding question")
    checks,blockers = list(dict.fromkeys(checks)),list(dict.fromkeys(blockers))
    for values,limit in ((checks,300),(blockers,700)):
        if len(values) > 5 or any(not v.strip() or len(v) > limit or
                any(ord(c)<32 or 127<=ord(c)<=159 for c in v) for v in values):
            raise ValueError("saved questions exceed native check/blocker limits; narrow or split without truncation")
    return {**result,"checks":checks,"blockers":blockers}


def _source(bridge, query, result, key, native_count):
    value = result.get("source") if result.get("operation") == "get_definition" else result
    if not value or value.get("operation") not in ("get_source","prepared_source") or value.get("truncated"):
        return []
    body = value["results"]
    lines, path = body["line_range"], body["location"]["path"]
    action = {"kind":"source","path":path,
        "start_line":lines["start_line"],"end_line":lines["end_line"],"review_id":query["review_id"],
        "origin":{"kind":"native_lookup" if native_count else "workspace_preparation",
                  "review_id":query["review_id"],"native_query_count":native_count}}
    preview = bridge.workspace.preview(action)
    captured = next(e for e in preview["evidence"].values() if e["path"] == path and
                    e["start_line"] == lines["start_line"] and e["end_line"] == lines["end_line"] and not e.get("fragment"))
    if captured["text"] != "\n".join(context.source_lines(body["text"])):
        raise ValueError("native source receipt does not match captured bytes")
    evidence = bridge.apply("source:" + key,action)["evidence_id"]
    return [evidence]


def _lookup(bridge, query, arguments, key):
    state = bridge.workspace.snapshot()
    for old_id, old in state["lookups"].items():
        if query["tool"] != "knowledge" and old["status"] == "complete" and (old["query"]["tool"],old["query"]["arguments"]) == (query["tool"],query["arguments"]):
            if old["evidence"]:
                bridge.workspace._evidence(state,old["evidence"])
            return old["result"],old["evidence"],0,old_id
    tool, values = query["tool"],query["arguments"]
    if tool == "knowledge":
        if not bridge.metadata["experiment"].get("knowledge_lookup",True):
            return {"operation":"workspace_knowledge","propositions":{},
                    "limit":"Cross-work knowledge lookup disabled for this experiment; supplied notes and source lookup remain available."},[],0,None
        found = {k:v[-1] for k,v in state["propositions"].items() if values["name"].casefold() in
                 (k + " " + v[-1]["scope"] + " " + v[-1]["statement"]).casefold()}
        found = dict(list(sorted(found.items()))[:8])
        evidence = sorted({e for p in found.values() for e in p["evidence"]})
        if evidence:
            bridge.workspace._evidence(state,evidence)
        return {"operation":"workspace_knowledge","propositions":found},evidence,0,None
    if tool == "guidance":
        return context.load_guidance(bridge.skill,values["name"]),[],0,None
    if tool == "source":
        for eid,e in state["evidence"].items():
            if not e.get("fragment") and e["path"] == values["path"] and e["start_line"] <= values["start_line"] <= values["end_line"] <= e["end_line"]:
                bridge.workspace._evidence(state,[eid])
                text = "\n".join(e["text"].split("\n")[values["start_line"]-e["start_line"]:values["end_line"]-e["start_line"]+1])
                return {"operation":"prepared_source","results":{"location":{"path":e["path"]},"text":text,
                    "line_range":{"start_line":values["start_line"],"end_line":values["end_line"]}}},[eid],0,None
    count = 0
    def execute(q, args):
        nonlocal count
        count += 1
        try:
            return bridge.native(args,timeout=bridge._remaining_seconds())
        except worker.CommandFailure as error:
            result = worker.missing_source_result(q,error)
            if result is None:
                raise
            return result
    result = execute(query,arguments)
    if tool == "definition":
        def read_source(values):
            child = {**query,"tool":"source","arguments":values}
            args = worker.research_arguments(child,bridge.root,bridge.payload["review_ids"],bridge.directory / "journals",
                api=context.research_api(bridge.skill),guidance=context.guidance_catalog(bridge.skill))
            return execute(child,args)
        result = worker.definition_result(result,read_source)
    bridge.check()  # A native receipt cannot cross a source/plan/owner change.
    return result,_source(bridge,query,result,key,count),count,None


def apply_response(bridge, session_id, task, packet, response):
    shape(response,("updates","lookups","decisions"))
    if any(not isinstance(response[k],list) for k in response) or not any(response.values()):
        raise ValueError("workspace response must contain bounded actions")
    if len(response["updates"]) > 8 or len(response["lookups"]) > 4:
        raise ValueError("workspace action limit exceeded")
    response = copy.deepcopy(response)
    projections = []
    for decision in response["decisions"]:
        original = decision.get("evidence",[])
        projected = [part for citation in original for part in citation_windows(bridge,packet["primary"]["windows"],citation)]
        if projected != original:
            projections.append({"review_id":decision["review_id"],"original":original,"projected":projected})
            decision["evidence"] = projected
    state = bridge.workspace.snapshot()
    view = state["sessions"][session_id]["packet"]
    scoped_ids = {}
    declarations = [u for u in response["updates"] if u.get("kind") == "question"] + response["lookups"]
    for declaration in declarations:
        qid = declaration["question_id"]
        if qid in state["questions"] and qid not in view["questions"]:
            # Independent fresh contexts cannot coordinate model-chosen names.
            # An unseen collision creates/continues this work's local question;
            # it never grants access to the other investigation's question.
            scoped_ids[qid] = "q-" + identity([view["work_id"],qid])
    for item in [*response["updates"],*response["lookups"]]:
        if item.get("question_id") in scoped_ids:
            item["question_id"] = scoped_ids[item["question_id"]]
    scoped_props = {}
    for declaration in response["updates"]:
        if declaration.get("kind") != "proposition":
            continue
        pid = declaration["proposition_id"]
        if pid in state["propositions"] and pid not in view["propositions"]:
            scoped_props[pid] = "p-" + identity([view["work_id"],pid])
    for update in response["updates"]:
        if update.get("proposition_id") in scoped_props:
            update["proposition_id"] = scoped_props[update["proposition_id"]]
        if update.get("kind") == "focus":
            update["propositions"] = [scoped_props.get(pid,pid) for pid in update["propositions"]]
    proof = {k:v for k,v in task["research"]["artifact_handles"].items() if k in task["research"]["source_artifact_handles"]}
    updates = copy.deepcopy(response["updates"])
    selected_focus = None
    interpretations = []
    new_props = []
    declared_questions = {}
    for update in updates:
        if update.get("kind") not in ALLOWED:
            raise ValueError("reviewer cannot invoke privileged workspace operations")
        if "evidence" in update:
            references(update["evidence"],proof,nonempty=False)
            update["evidence"] = [proof[e] for e in update["evidence"]]
        if update["kind"] == "focus":
            shape(update,("kind","evidence","propositions"))
            if selected_focus is not None:
                raise ValueError("only one context focus update is allowed per turn")
            selected_focus = update
            continue
        interpretations.append(update)
        if update["kind"] == "proposition":
            pid = update["proposition_id"]
            if pid in state["propositions"] and pid not in view["propositions"]:
                raise ValueError("reviewer cannot revise unseen knowledge")
            new_props.append(pid)
        elif update["kind"] in ("applicability","dispute"):
            if update["proposition_id"] not in set(view["propositions"]) | set(new_props):
                raise ValueError("reviewer must retrieve a proposition before using it")
        if "review_id" in update:
            references([update["review_id"]],task["review_ids"])
        if update["kind"] == "question":
            references(update["review_ids"],task["review_ids"])
            if update["question_id"] in declared_questions or update["question_id"] in state["questions"]:
                raise ValueError("question already exists; use an answer update")
            declared_questions[update["question_id"]] = update
        if update["kind"] == "answer" and update["question_id"] not in set(view["questions"]) | set(declared_questions):
            raise ValueError("reviewer cannot answer an unseen question")
    references(new_props, new_props, nonempty=False)
    updates = interpretations
    journals = bridge.directory / "journals"
    journals.mkdir(exist_ok=True)
    api, guidance = context.research_api(bridge.skill),context.guidance_catalog(bridge.skill)
    tools = {t["name"]:t for t in api["tools"] if t["name"] != "base_source"}
    tools["knowledge"] = {"query_units":1}
    queries, requested, questions = [],set(),[]
    for lookup in response["lookups"]:
        shape(lookup,("question_id","review_ids","question","queries"))
        label(lookup["question_id"])
        label(lookup["question"])
        references(lookup["review_ids"],task["review_ids"])
        if not isinstance(lookup["queries"],list) or not 1 <= len(lookup["queries"]) <= 4:
            raise ValueError("expected focused lookup batch")
        question = {"kind":"question","question_id":lookup["question_id"],"review_ids":lookup["review_ids"],"question":lookup["question"]}
        old = state["questions"].get(lookup["question_id"]) or declared_questions.get(lookup["question_id"])
        if old:
            if lookup["question_id"] not in set(view["questions"]) | set(declared_questions):
                raise ValueError("reviewer cannot continue an unseen question")
            if set(old["review_ids"]) != set(question["review_ids"]):
                raise ValueError("question ID already has another scope")
            # A follow-up lookup can narrow the fact being sought. Keep the
            # original deciding question open; record the requested wording on
            # each receipt rather than replacing that question or its answers.
        else:
            questions.append(question)
        requested.update(lookup["review_ids"])
        for query in lookup["queries"]:
            if query["tool"] not in tools:
                raise ValueError("unsupported workspace lookup")
            references([query["review_id"]],lookup["review_ids"])
            if query["tool"] == "knowledge":
                shape(query,("tool","review_id","purpose","arguments"))
                shape(query["arguments"],("name",))
                label(query["purpose"])
                label(query["arguments"]["name"])
                arguments = []
            else:
                arguments = worker.research_arguments(query,bridge.root,task["review_ids"],journals,api=api,guidance=guidance)
            queries.append((lookup["question_id"],query,arguments,tools[query["tool"]]["query_units"],lookup["question"]))
    if sum(q[3] for q in queries) > state["limits"]["queries"] - state["used"]["queries"]:
        raise ValueError("workspace lookup batch exceeds aggregate query allowance")
    decided = [r["review_id"] for r in response["decisions"]]
    references(decided,task["review_ids"],nonempty=False)
    if set(decided) & requested:
        raise ValueError("cannot decide a claim while requesting deciding evidence")
    work = state["work"][view["work_id"]]
    if selected_focus:
        references(selected_focus["propositions"],set(view["propositions"]) | set(new_props),nonempty=False)
    focus = {"kind":"focus","work_id":view["work_id"],
             "evidence_ids":selected_focus["evidence"] if selected_focus else work["evidence_ids"],
             "proposition_ids":selected_focus["propositions"] if selected_focus else sorted(set(work["proposition_ids"]) | set(new_props))}
    transaction = {"kind":"review_updates","updates":[*questions,*updates,focus]}
    preview = bridge.workspace.preview(transaction)
    dependencies = [{"proposition_id":p,"revision":preview["propositions"][p][-1]["revision"]}
                    for p in sorted(set(view["propositions"]) | set(new_props))
                    if preview["propositions"][p][-1]["status"] == "available"]
    for result in response["decisions"]:
        result = native_decision(result,preview)
        for window in result.get("evidence",[]):
            if not any(w["path"] == window["path"] and w["start_line"] <= window["start_line"] <= window["end_line"] <= w["end_line"]
                       for w in packet["primary"]["windows"]):
                raise ValueError("decision cites source outside its context")
        applies = [k for k,a in preview["applicability"].items() if a["review_id"] == result["review_id"] and
                   a["proposition_id"] in {p["proposition_id"] for p in dependencies} and
                   a["proposition_revision"] == preview["propositions"][a["proposition_id"]][-1]["revision"]]
        transaction["updates"].append({"kind":"draft","result":result,"applicability":applies,"propositions":dependencies})
    bridge.workspace.preview(transaction)  # Invalid later actions cannot leave earlier judgments saved.
    accepted = bridge.apply("actions:" + session_id,transaction)
    receipts = []
    for index,(qid,query,arguments,units,requested_question) in enumerate(queries):
        bridge._remaining_seconds()
        key = session_id + ":" + str(index)
        bridge.apply("reserve:" + key,{"kind":"lookup_request","lookup_id":key,"question_id":qid,"query":query,"units":units,
                                       "requested_question":requested_question})
        started = time.monotonic()
        result,evidence,count,reused = _lookup(bridge,query,arguments,key)
        bridge.check()
        receipt = {"kind":"lookup_result","lookup_id":key,"question_id":qid,"query":query,"result":result,
                   "evidence":evidence,"native_query_count":count,"reused_from":reused}
        bridge.apply("receipt:" + key,receipt)
        if bridge.workspace.snapshot()["received_query_bytes"] > bridge.metadata["experiment"].get("max_received_query_bytes",2**63):
            raise ValueError("experiment received-query byte ceiling exceeded; observed overspend retained")
        current = bridge.workspace.snapshot()["work"][view["work_id"]]
        props = list(result.get("propositions",{})) if result.get("operation") == "workspace_knowledge" else []
        bridge.apply("focus:" + key,{"kind":"focus","work_id":view["work_id"],
            "evidence_ids":sorted(set(current["evidence_ids"]) | set(evidence)),
            "proposition_ids":sorted(set(current["proposition_ids"]) | set(props))})
        bridge.trace("deciding_lookup",question_id=qid,lookup_id=key,tool=query["tool"],native_query_count=count,
                     reused_from=reused,elapsed_ms=round((time.monotonic()-started)*1000))
        receipts.append(key)
    if projections:
        bridge.trace("citation_projection",session_id=session_id,projections=projections)
    if scoped_ids:
        bridge.trace("question_id_projection",session_id=session_id,work_id=view["work_id"],mapping=scoped_ids)
    if scoped_props:
        bridge.trace("proposition_id_projection",session_id=session_id,work_id=view["work_id"],mapping=scoped_props)
    return {"updates":accepted,"lookup_ids":receipts,"citation_projections":projections,"usage":bridge.workspace.usage(),"native_admission":False}
