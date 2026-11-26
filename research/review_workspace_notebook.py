"""Bounded handoff of source-backed interpretations; no verdict transfer."""
import copy
import hashlib
from pathlib import Path

from review_workspace import encoded, identity, shape, source

VERSION = "mehscanWorkspaceNotebook/v1"
FIELDS = ("statement","scope","conditions","exclusions","evidence")


def export_notebook(workspace, max_bytes=8192):
    state = workspace.snapshot()
    propositions = {k:copy.deepcopy(v[-1]) for k,v in state["propositions"].items()
                    if v[-1]["status"] == "available"}
    if not propositions or len(propositions) > 4:
        raise ValueError("notebook requires one to four available propositions")
    evidence_ids = sorted({e for p in propositions.values() for e in p["evidence"]})
    workspace._evidence(state,evidence_ids)
    notebook = {"version":VERSION,"producer_binding":state["binding"],
                "producer_selection":state["selection_id"],"producer_revision":state["revision"],
                "source_root":state["source_root"],"propositions":propositions,
                "evidence":{k:state["evidence"][k] for k in evidence_ids}}
    if len(encoded(notebook).encode("utf-8")) > max_bytes:
        raise ValueError("notebook exceeds byte limit; narrow supporting evidence before export")
    return notebook


def import_notebook(workspace, notebook, work_id):
    """Preflight all changes; retries resume receipts before finally focusing notes.

    Call under the native controller lock. The returned receipt and original
    notebook retain producer attribution/revisions; recipient preparation is not
    another native lookup. Applicability, decisions, questions and usage are never
    imported. Source/proposition steps are idempotent across interruption.
    """
    shape(notebook,("version","producer_binding","producer_selection","producer_revision",
                    "source_root","propositions","evidence"))
    if notebook["version"] != VERSION or not 1 <= len(notebook["propositions"]) <= 4:
        raise ValueError("unsupported or empty notebook")
    if len(encoded(notebook).encode("utf-8")) > 8192:
        raise ValueError("notebook exceeds byte limit")
    state = workspace.snapshot()
    if (notebook["producer_binding"]["snapshot_id"] != state["binding"]["snapshot_id"] or
            Path(notebook["source_root"]).resolve() != Path(state["source_root"]).resolve()):
        raise ValueError("notebook source binding differs")
    if any(p["status"] != "available" for p in notebook["propositions"].values()):
        raise ValueError("notebook contains unavailable propositions")
    for e in notebook["evidence"].values():
        if hashlib.sha256(source(Path(state["source_root"]),e["path"])).hexdigest() != e["file_sha256"]:
            raise ValueError("notebook source is stale")
    key = identity(notebook)
    namespace = identity([notebook["producer_binding"],notebook["producer_selection"]])[:12]
    shadow, actions = copy.deepcopy(state),[]

    def step(suffix, action):
        operation = "notebook:" + key + ":" + suffix
        old = workspace.operation(operation)
        if old:
            if old["request"]["action"] != action:
                raise ValueError("notebook retry changed")
            return old["response"]["result"]
        result = workspace._action(shadow,copy.deepcopy(action),operation)
        shadow["revision"] += 1
        actions.append((operation,action))
        return result

    claim = state["work"][work_id]["claims"][0]
    evidence = {}
    for original,e in sorted(notebook["evidence"].items()):
        evidence[original] = step("source:" + work_id + ":" + original,{"kind":"source","review_id":claim,
            **{k:e[k] for k in ("path","start_line","end_line")},"excerpt":e["text"],
            "origin":{"kind":"workspace_preparation","review_id":claim,"native_query_count":0}})["evidence_id"]
    mapping = {}
    for original,p in sorted(notebook["propositions"].items()):
        target = "notebook-" + namespace + "-" + original
        action = {"kind":"proposition","proposition_id":target,**{k:p[k] for k in FIELDS}}
        action["evidence"] = [evidence[e] for e in p["evidence"]]
        old = workspace.operation("notebook:" + key + ":proposition:" + original)
        if old:
            latest = state["propositions"][target][-1]
            if latest["status"] != "available" or any(latest[k] != action[k] for k in FIELDS):
                raise ValueError("imported proposition changed; do not resurrect an old notebook")
        result = step("proposition:" + original,action)
        mapping[original] = {"proposition_id":target,"producer_revision":p["revision"],
                             "recipient_revision":result["revision"]}
    current = shadow["work"][work_id]
    step("focus:" + work_id,{"kind":"focus","work_id":work_id,"evidence_ids":current["evidence_ids"],
                  "proposition_ids":sorted(set(current["proposition_ids"]) | {p["proposition_id"] for p in mapping.values()})})
    for operation,action in actions:
        workspace.apply(operation,workspace.snapshot()["revision"],action)
    return {"notebook_sha256":key,"producer_binding":notebook["producer_binding"],
            "producer_revision":notebook["producer_revision"],"propositions":mapping,
            "evidence":evidence,"producer_evidence_origins":{k:e["origin"] for k,e in notebook["evidence"].items()},
            "native_query_count":0,"native_admission":False}
