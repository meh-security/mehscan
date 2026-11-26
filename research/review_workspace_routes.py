"""Bounded route source from native reference locations; no applicability inference."""
import re
from pathlib import Path

import review_context as context
from review_workspace import identity, number, source

# A locator filter, not a JavaScript parser or proof that this receiver is Express.
ROUTE = re.compile(r"^\s*[\w$]+(?:\.[\w$]+)*\.(?:get|post|put|patch|delete|use|all|options|head)\s*\(\s*(?:['\"`]/|$)")


def reference_route_windows(root, result, max_bytes=8192):
    number(max_bytes,positive=True)
    if max_bytes > 8192:
        raise ValueError("route source budget exceeds 8 KiB")
    if result.get("operation") != "find_text_references":
        raise ValueError("route preparation requires a native reference result")
    windows,limits,cache = [],[],{}
    if result.get("truncated"):
        limits.append("Reference search is truncated; unreturned callers remain unknown.")
    sites = 0
    for row in result.get("results",[]):
        path = row["path"]
        if row.get("locations_truncated"):
            limits.append("Reference locations truncated in " + path)
        for line in row.get("lines",[]):
            sites += 1
            if sites > 64:
                limits.append("Route preparation stopped after 64 reference sites.")
                return {"windows":windows,"limits":list(dict.fromkeys(limits))}
            if path not in cache:
                cache[path] = context.source_lines(source(Path(root),path).decode("utf-8"))
            lines = cache[path]
            if type(line) is not int or not 1 <= line <= len(lines):
                raise ValueError("native reference lies outside current source")
            if not ROUTE.match(lines[line-1]):
                continue
            first,last = max(1,line-1),min(len(lines),line+2)
            if any(w["path"]==path and w["start_line"]<=first<=last<=w["end_line"] for w in windows):
                continue
            candidates = list(windows)
            overlapping = [w for w in candidates if w["path"]==path and w["start_line"]<=last+1 and first<=w["end_line"]+1]
            if overlapping:
                first = min(first,*(w["start_line"] for w in overlapping))
                last = max(last,*(w["end_line"] for w in overlapping))
                candidates = [w for w in candidates if w not in overlapping]
            window = {"path":path,"start_line":first,"end_line":last,"text":"\n".join(lines[first-1:last])}
            candidates.append(window)
            if len(candidates) > 8 or sum(len(w["text"].encode("utf-8")) for w in candidates) > max_bytes:
                limits.append("Route source preparation limit reached; remaining reference sites were not read into context.")
                continue
            windows = candidates
    if not windows:
        limits.append("No route-shaped reference site was materialized; dynamic or indirect registration remains unresolved.")
    return {"windows":windows,"limits":list(dict.fromkeys(limits))}


def attach_route_context(bridge, work_id, receipt):
    """Call under the native controller lock before preparing provider sessions.

    The caller retains the bound native locator receipt and this preparation
    receipt, and counts locator execution separately. Actual source is captured
    as preparation, not as another native/model lookup or an authorization fact.
    """
    bridge.check()
    state = bridge.workspace.snapshot()
    query = receipt["query"]
    if receipt["snapshot_id"] != state["binding"]["snapshot_id"] or query["tool"] != "references":
        raise ValueError("route locator source binding differs")
    if query["review_id"] not in state["work"][work_id]["claims"]:
        raise ValueError("route locator belongs to another claim")
    prepared = reference_route_windows(bridge.root,receipt["result"])
    key = identity(receipt)
    evidence = []
    for i,window in enumerate(prepared["windows"]):
        action = {"kind":"source","review_id":query["review_id"],
                  **{k:window[k] for k in ("path","start_line","end_line")},"excerpt":window["text"],
                  "origin":{"kind":"workspace_preparation","review_id":query["review_id"],"native_query_count":0}}
        evidence.append(bridge.apply("route-source:"+key+":"+str(i),action)["evidence_id"])
    work = bridge.workspace.snapshot()["work"][work_id]
    bridge.apply("route-limits:"+work_id+":"+key,{"kind":"preparation_limits","work_id":work_id,
        "preparation_id":key,"origin":"native textual reference source preparation","limits":prepared["limits"]})
    bridge.apply("route-focus:"+work_id+":"+key,{"kind":"focus","work_id":work_id,
        "evidence_ids":sorted(set(work["evidence_ids"]) | set(evidence)),"proposition_ids":work["proposition_ids"]})
    bridge.check()
    return {"locator_sha256":key,"evidence_ids":evidence,"limits":prepared["limits"],
            "source_bytes":sum(len(w["text"].encode("utf-8")) for w in prepared["windows"]),
            "native_query_count":0,"authority":"source preparation only; verify receiver, registration and guard-to-effect relationship"}
