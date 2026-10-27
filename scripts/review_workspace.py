#!/usr/bin/env python3
"""Experimental review working state; native finalization remains authoritative.

The seed binding is supplied by a trusted controller, not authenticated here.
No model execution, native admission or full-snapshot freshness is implied.
"""
import argparse
import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time

import review_context as context


VERSION = "mehscanWorkspace/experimental-v1"
RESOURCES = ("model_calls", "queries", "source_bytes")
COUNTERS = ("input_tokens", "cached_input_tokens", "output_tokens", "elapsed_ms")
MAX_ACTION_BYTES = 128 * 1024


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def identity(value):
    return hashlib.sha256(encoded(value).encode("utf-8")).hexdigest()


def label(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 1000:
        raise ValueError("expected bounded nonempty text")
    return value


def number(value, *, positive=False):
    if type(value) is not int or value < int(positive):
        raise ValueError("expected a nonnegative integer" if not positive else "expected a positive integer")
    return value


def shape(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ValueError("unexpected or missing fields")


def references(values, known, *, nonempty=True):
    if (not isinstance(values, list) or (nonempty and not values)
            or any(not isinstance(v, str) or v not in known for v in values)
            or len(values) != len(set(values))):
        raise ValueError("expected distinct known references")
    return values


def source(root, path):
    file = context.relative_file(root, path)
    if any(parent.is_symlink() for parent in (file, *file.parents) if parent != root.parent):
        raise ValueError("source symlinks are not supported")
    data = file.read_bytes()
    if len(data) > context.MAX_FILE_BYTES:
        raise ValueError("source file exceeds preparation limit")
    return data


class Workspace:
    """Atomic state + idempotent receipts in one SQLite transaction per action.

    Working JSON is intentionally small for the pilot. BEGIN IMMEDIATE and a
    revision comparison reject competing writers instead of merging judgments.
    """

    def __init__(self, path, binding):
        self.path = Path(path).resolve()
        self.binding = copy.deepcopy(binding)
        if not self.path.is_file():
            raise ValueError("workspace does not exist")
        self.snapshot()

    @staticmethod
    def create(path, root, binding, claims, limits):
        path, root = Path(path).resolve(), Path(root).resolve(strict=True)
        shape(binding, ("snapshot_id", "plan_id", "runtime_id"))
        for value in binding.values():
            label(value)
        shape(limits, RESOURCES)
        for value in limits.values():
            number(value)
        if path.is_relative_to(root) or not root.is_dir():
            raise ValueError("workspace must be outside the source directory")
        if not isinstance(claims, list) or not claims:
            raise ValueError("workspace requires selected native claims")
        selected = {}
        for claim in claims:
            shape(claim, ("review_id", "property", "path", "line", "bundle_id"))
            for key in ("review_id", "property", "bundle_id"):
                label(claim[key])
            context.relative_file(root, claim["path"])
            number(claim["line"], positive=True)
            if claim["review_id"] in selected:
                raise ValueError("duplicate selected claim")
            selected[claim["review_id"]] = {**claim, "draft":None, "draft_history":[], "reconsideration":[]}
        state = {"version":VERSION, "binding":binding, "source_root":str(root),
                 "selection_id":identity(sorted(claims, key=lambda c:c["review_id"])),
                 "revision":0, "claims":selected, "evidence":{}, "propositions":{},
                 "applicability":{}, "questions":{}, "lookups":{}, "sessions":{}, "calls":{}, "preparation_limits":{},
                 "limits":limits, "used":dict.fromkeys(RESOURCES, 0), "received_query_bytes":0,
                 "work":{"initial":{"strategy":"unassigned", "claims":list(selected), "parent":None,
                                      "evidence_ids":[], "proposition_ids":[]}}}
        # Exclusive creation: never replace an existing workspace or its receipts.
        descriptor, pending = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        os.close(descriptor)
        try:
            with closing(sqlite3.connect(pending)) as db, db:
                db.executescript("CREATE TABLE workspace (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);"
                                 "CREATE TABLE receipts (key TEXT PRIMARY KEY, request TEXT NOT NULL, response TEXT NOT NULL);")
                db.execute("INSERT INTO workspace VALUES (1, ?)", (encoded(state),))
            # Atomic publication without replacing any existing workspace.
            os.link(pending, path)
        finally:
            os.unlink(pending)
        return Workspace(path, binding)

    def _load(self, db):
        state = json.loads(db.execute("SELECT body FROM workspace WHERE id=1").fetchone()[0])
        if state["version"] != VERSION or state["binding"] != self.binding:
            raise ValueError("workspace source/plan/runtime binding differs")
        return state

    def snapshot(self):
        with closing(sqlite3.connect(self.path, timeout=0)) as db:
            return self._load(db)

    def operation(self, operation_key):
        """Read an original receipt/revision for a controller's explicit retry."""
        label(operation_key)
        with closing(sqlite3.connect(self.path, timeout=0)) as db:
            self._load(db)
            row = db.execute("SELECT request, response FROM receipts WHERE key=?", (operation_key,)).fetchone()
            return None if row is None else {"request":json.loads(row[0]),"response":json.loads(row[1])}

    def apply(self, operation_key, expected_revision, action, *, before_commit=None):
        """Optionally fence staged state before publication, including receipt replay.

        The trusted controller supplies the callback, never model action data.
        It may read committed workspace state but must not write this workspace.
        A failed fence rolls back interpretations, not separately reserved costs.
        """
        label(operation_key)
        number(expected_revision)
        request = encoded({"revision":expected_revision, "action":action})
        if len(request.encode("utf-8")) > MAX_ACTION_BYTES:
            raise ValueError("workspace action exceeds intake limit")
        with closing(sqlite3.connect(self.path, timeout=0)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            state = self._load(db)
            old = db.execute("SELECT request, response FROM receipts WHERE key=?", (operation_key,)).fetchone()
            if old:
                if old[0] != request:
                    raise ValueError("operation key reused for different input")
                if before_commit is not None:
                    before_commit()
                return {**json.loads(old[1]), "replayed":True}
            if expected_revision != state["revision"]:
                raise ValueError("stale workspace revision")
            result = self._action(state, action, operation_key)
            state["revision"] += 1
            receipt = {"revision":state["revision"], "result":result, "replayed":False,
                       "native_admission":False}
            if before_commit is not None:
                before_commit()
            db.execute("UPDATE workspace SET body=? WHERE id=1", (encoded(state),))
            db.execute("INSERT INTO receipts VALUES (?, ?, ?)", (operation_key, request, encoded(receipt)))
            return receipt

    def preview(self, action):
        """Validate a complete interpretation update before any external lookup."""
        state = self.snapshot()
        self._action(state, copy.deepcopy(action), "preview")
        return state

    @staticmethod
    def _spend(state, amounts):
        shape(amounts, (), RESOURCES)
        for key, amount in amounts.items():
            number(amount)
            if state["used"][key] + amount > state["limits"][key]:
                raise ValueError("workspace aggregate budget exhausted: " + key)
        for key, amount in amounts.items():
            state["used"][key] += amount

    @staticmethod
    def _evidence(state, ids):
        if not isinstance(ids, list) or any(not isinstance(key, str) for key in ids):
            raise ValueError("expected evidence references")
        ids = sorted(set(ids))
        references(ids, state["evidence"])
        for key in ids:
            evidence = state["evidence"][key]
            data = source(Path(state["source_root"]), evidence["path"])
            if hashlib.sha256(data).hexdigest() != evidence["file_sha256"]:
                raise ValueError("cited source changed; create a newly bound workspace")

    def _action(self, state, action, operation_key):
        if isinstance(action, dict) and action.get("kind") == "prepare_evidence":
            import review_workspace_evidence
            return review_workspace_evidence.apply(state, self, action, operation_key)
        if not isinstance(action, dict):
            raise ValueError("action must be an object")
        kind = action.get("kind")
        if kind == "prepare_work":
            shape(action,("kind","planning_id","work","max_context_bytes"),("deciding_targets",))
            label(action["planning_id"])
            maximum = number(action["max_context_bytes"],positive=True)
            if maximum > 128*1024:
                raise ValueError("planned context exceeds 128 KiB")
            if (set(state["work"]) != {"initial"} or state["sessions"] or state["calls"] or
                    state["questions"] or state["propositions"] or state["lookups"] or state.get("deciding_evidence") or
                    any(c["draft"] for c in state["claims"].values())):
                raise ValueError("planning requires a fresh unassigned workspace")
            specs = action["work"]
            if not isinstance(specs,list) or not 1 <= len(specs) <= 32:
                raise ValueError("expected 1..32 planned work items")
            covered,work_ids = [],[]
            for spec in specs:
                shape(spec,("work_id","review_ids","strategy","evidence_ids","windows","limits"))
                covered.extend(spec["review_ids"])
                work_ids.append(spec["work_id"])
            references(covered,state["claims"])
            if set(covered) != set(state["claims"]) or len(set(work_ids)) != len(work_ids):
                raise ValueError("plan must cover every claim exactly once with distinct work IDs")
            for spec in specs:
                wid = spec["work_id"]
                self._action(state,{"kind":"split","work_id":"initial","new_work_id":wid,
                    "review_ids":spec["review_ids"],"strategy":spec["strategy"]},operation_key)
                references(spec["evidence_ids"],state["evidence"],nonempty=False)
                evidence = set(spec["evidence_ids"])
                if not isinstance(spec["windows"],list) or len(spec["windows"]) > 128:
                    raise ValueError("too many planned source windows")
                for window in spec["windows"]:
                    shape(window,("path","start_line","end_line","review_id","file_sha256"))
                    references([window["review_id"]],spec["review_ids"])
                    capture = {k:v for k,v in window.items() if k != "file_sha256"}
                    eid = self._action(state,{"kind":"source",**capture},operation_key)["evidence_id"]
                    if state["evidence"][eid]["file_sha256"] != window["file_sha256"]:
                        raise ValueError("planned source changed")
                    evidence.add(eid)
                # Full supplied source subsumes a contained AST fragment/window.
                evidence = sorted(eid for eid in evidence if not any(other != eid and
                    not state["evidence"][other].get("fragment") and
                    state["evidence"][other]["path"] == state["evidence"][eid]["path"] and
                    state["evidence"][other]["start_line"] <= state["evidence"][eid]["start_line"] and
                    state["evidence"][eid]["end_line"] <= state["evidence"][other]["end_line"]
                    for other in evidence))
                self._action(state,{"kind":"focus","work_id":wid,"evidence_ids":evidence,
                                   "proposition_ids":[]},operation_key)
                self._action(state,{"kind":"preparation_limits","work_id":wid,
                    "preparation_id":action["planning_id"],"origin":"source-bound deterministic work planner",
                    "limits":spec["limits"]},operation_key)
            if action.get("deciding_targets"):
                self._action(state,{"kind":"prepare_evidence","targets":action["deciding_targets"]},operation_key)
            for wid in work_ids:
                self._view(state,wid,maximum)  # Late overflow rolls back the entire preparation.
            return {"planning_id":action["planning_id"],"work_ids":work_ids,"native_admission":False}
        if kind == "source":
            shape(action, ("kind", "path", "start_line", "end_line", "review_id"), ("origin","excerpt"))
            references([action["review_id"]], state["claims"])
            first, last = action["start_line"], action["end_line"]
            number(first, positive=True)
            number(last, positive=True)
            if not first <= last < first + 400:
                raise ValueError("source windows require 1..400 inclusive lines")
            data = source(Path(state["source_root"]), action["path"])
            file_hash = hashlib.sha256(data).hexdigest()
            if any(e["path"] == action["path"] and e["file_sha256"] != file_hash for e in state["evidence"].values()):
                raise ValueError("captured source changed; create a newly bound workspace")
            lines = context.source_lines(data.decode("utf-8"))
            # Native windows may include the terminating empty source position
            # after a final LF. Match the native reader without inventing text.
            if last > len(lines) + int(data.endswith(b"\n")):
                raise ValueError("source window exceeds file")
            text = "\n".join(lines[first-1:last])
            fragment = False
            if "excerpt" in action:
                if not isinstance(action["excerpt"],str):
                    raise ValueError("source excerpt must be text")
                excerpt = "\n".join(context.source_lines(action["excerpt"]))
                offset = text.find(excerpt)
                if offset < 0 or "\n" in text[:offset] or "\n" in text[offset+len(excerpt):]:
                    raise ValueError("native excerpt does not match the selected source lines")
                fragment = excerpt != text
                text = excerpt
            item = {"path":action["path"], "start_line":first, "end_line":last,
                    "text":text, "file_sha256":file_hash,
                    "complete_file":first == 1 and last >= len(lines)}
            if fragment:
                item.update(fragment=True,complete_file=False)
            key = identity([state["binding"]["snapshot_id"], item])
            if key not in state["evidence"]:
                self._spend(state, {"source_bytes":len(item["text"].encode("utf-8"))})
                origin = action.get("origin", {"kind":"workspace_preparation", "review_id":action["review_id"],"native_query_count":0})
                shape(origin, ("kind","review_id","native_query_count"))
                if origin["kind"] not in ("workspace_preparation","native_lookup") or origin["review_id"] != action["review_id"]:
                    raise ValueError("invalid source attribution")
                number(origin["native_query_count"])
                state["evidence"][key] = {**item, "origin":origin}
            return {"evidence_id":key}
        if kind == "proposition":
            shape(action, ("kind", "proposition_id", "statement", "scope", "conditions", "exclusions", "evidence"))
            key = label(action["proposition_id"])
            for field in ("statement", "scope", "conditions", "exclusions"):
                label(action[field])
            self._evidence(state, action["evidence"])
            history = state["propositions"].setdefault(key, [])
            if history:
                self._invalidate(state, key)
            history.append({k:v for k,v in action.items() if k not in ("kind", "proposition_id")})
            history[-1].update(revision=len(history), status="available", origin="reviewer_interpretation")
            return {"proposition_id":key, "revision":len(history)}
        if kind == "dispute":
            shape(action, ("kind", "proposition_id", "reason"))
            label(action["reason"])
            history = state["propositions"][action["proposition_id"]]
            history[-1].update(status="disputed", dispute_reason=action["reason"])
            self._invalidate(state, action["proposition_id"])
            return {"affected_claims":sorted(c for c,v in state["claims"].items() if v["reconsideration"])}
        if kind == "applicability":
            shape(action, ("kind", "review_id", "proposition_id", "proposition_revision", "evidence", "reason"))
            references([action["review_id"]], state["claims"])
            prop = state["propositions"][action["proposition_id"]][-1]
            if prop["status"] != "available" or type(action["proposition_revision"]) is not int or prop["revision"] != action["proposition_revision"]:
                raise ValueError("proposition is disputed or stale")
            self._evidence(state, [*prop["evidence"], *action["evidence"]])
            label(action["reason"])
            key = identity(action)
            state["applicability"][key] = {k:v for k,v in action.items() if k != "kind"}
            return {"applicability_id":key}
        if kind == "question":
            shape(action, ("kind", "question_id", "review_ids", "question"))
            key = label(action["question_id"])
            references(action["review_ids"], state["claims"])
            label(action["question"])
            if key in state["questions"]:
                raise ValueError("question already exists")
            state["questions"][key] = {"review_ids":action["review_ids"], "question":action["question"],
                                       "status":"open", "attempts":[]}
            for claim_id in action["review_ids"]:
                claim = state["claims"][claim_id]
                if claim["draft"] is not None:
                    claim["reconsideration"].append("question:" + key)
            return {"question_id":key}
        if kind == "answer":
            shape(action, ("kind", "question_id", "status", "reason", "evidence"))
            if action["status"] not in ("open", "answered", "blocked"):
                raise ValueError("invalid question state")
            label(action["reason"])
            references(action["evidence"], state["evidence"], nonempty=action["status"] == "answered")
            if action["evidence"]:
                self._evidence(state, action["evidence"])
            question = state["questions"][action["question_id"]]
            answer = {k:v for k,v in action.items() if k not in ("kind","question_id")}
            if not question["attempts"] or answer != question["attempts"][-1]:
                self._reopen_question(state,action["question_id"])
            question["attempts"].append(answer)
            question["status"] = action["status"]
            return {"question_id":action["question_id"]}
        if kind == "split":
            shape(action, ("kind", "work_id", "new_work_id", "review_ids", "strategy"))
            parent = state["work"][action["work_id"]]
            key = label(action["new_work_id"])
            label(action["strategy"])
            references(action["review_ids"], parent["claims"])
            if key in state["work"]:
                raise ValueError("work item already exists")
            state["work"][key] = {"claims":action["review_ids"], "strategy":action["strategy"], "parent":action["work_id"],
                                  "evidence_ids":list(parent["evidence_ids"]), "proposition_ids":list(parent["proposition_ids"])}
            parent["claims"] = [c for c in parent["claims"] if c not in action["review_ids"]]
            if action["work_id"] in state.get("preparation_limits",{}):
                state["preparation_limits"][key] = copy.deepcopy(state["preparation_limits"][action["work_id"]])
            if action["work_id"] in state.get("deciding_evidence",{}):
                state["deciding_evidence"][key] = copy.deepcopy(state["deciding_evidence"][action["work_id"]])
            return {"work_id":key}
        if kind == "preparation_limits":
            shape(action,("kind","work_id","preparation_id","origin","limits"))
            references([action["work_id"]],state["work"])
            label(action["preparation_id"])
            label(action["origin"])
            if not isinstance(action["limits"],list) or len(action["limits"]) > 16:
                raise ValueError("expected bounded preparation limits")
            for value in action["limits"]:
                label(value)
            records = state.setdefault("preparation_limits",{}).setdefault(action["work_id"],{})
            record = {"origin":action["origin"],"limits":action["limits"]}
            if action["preparation_id"] in records and records[action["preparation_id"]] != record:
                raise ValueError("preparation receipt changed")
            records[action["preparation_id"]] = record
            return {"preparation_id":action["preparation_id"]}
        if kind == "focus":
            shape(action, ("kind", "work_id", "evidence_ids", "proposition_ids"))
            references(action["evidence_ids"], state["evidence"], nonempty=False)
            references(action["proposition_ids"], state["propositions"], nonempty=False)
            work = state["work"][action["work_id"]]
            work.update(evidence_ids=action["evidence_ids"], proposition_ids=action["proposition_ids"])
            return {"work_id":action["work_id"]}
        if kind == "session":
            shape(action, ("kind", "work_id", "parent_session", "max_bytes"))
            parent = action["parent_session"]
            if parent is not None and (parent not in state["sessions"] or state["sessions"][parent]["work_id"] != action["work_id"]):
                raise ValueError("parent session must belong to the work item")
            packet = self._view(state, action["work_id"], action["max_bytes"])
            key = identity([state["binding"], operation_key, packet])
            for session in state["sessions"].values():
                if session["work_id"] == action["work_id"]:
                    session["retired"] = True
            state["sessions"][key] = {"work_id":action["work_id"], "parent_session":parent,
                                      "packet_digest":identity(packet), "packet":packet, "retired":False}
            return {"session_id":key, "packet_digest":identity(packet)}
        if kind == "attach_session":
            shape(action, ("kind", "session_id", "artifacts"))
            shape(action["artifacts"], ("provider_config_digest", "files"))
            shape(action["artifacts"]["files"], ("context.json", "facts.json", "task.json"))
            for digest in [action["artifacts"]["provider_config_digest"], *action["artifacts"]["files"].values()]:
                if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                    raise ValueError("session artifacts require SHA-256 digests")
            session = state["sessions"][action["session_id"]]
            if session["retired"] or "artifacts" in session:
                raise ValueError("session artifacts are already attached or retired")
            session["artifacts"] = action["artifacts"]
            return {"session_id":action["session_id"]}
        if kind == "start_call":
            shape(action, ("kind", "session_id"))
            self._current_session(state, action["session_id"])
            self._spend(state, {"model_calls":1})
            state["calls"][operation_key] = {"session_id":action["session_id"], "usage":None,
                                            "started_epoch_ms":round(time.time() * 1000)}
            return {"call_id":operation_key}
        if kind == "finish_call":
            shape(action, ("kind", "call_id", "usage"))
            shape(action["usage"], COUNTERS)
            for value in action["usage"].values():
                if value is not None:
                    number(value)
            usage = action["usage"]
            if usage["cached_input_tokens"] is not None and usage["input_tokens"] is not None and usage["cached_input_tokens"] > usage["input_tokens"]:
                raise ValueError("cached input cannot exceed total input")
            call = state["calls"][action["call_id"]]
            if call["usage"] is not None:
                raise ValueError("call usage already recorded")
            call["usage"] = usage
            return {"call_id":action["call_id"]}
        if kind == "reserve_queries":
            shape(action, ("kind", "queries"))
            self._spend(state, {"queries":number(action["queries"], positive=True)})
            return {"used":state["used"]}
        if kind == "review_updates":
            shape(action, ("kind", "updates"))
            if not isinstance(action["updates"],list) or not action["updates"] or len(action["updates"]) > 64:
                raise ValueError("expected bounded interpretation updates")
            permitted = {"proposition","applicability","answer","dispute","question","focus","draft"}
            if any(not isinstance(a,dict) or a.get("kind") not in permitted for a in action["updates"]):
                raise ValueError("interpretation updates cannot invoke privileged workspace operations")
            return [self._action(state,a,operation_key) for a in action["updates"]]
        if kind == "lookup_observed":
            shape(action,("kind","lookup_id","received_bytes"))
            previous = state["lookups"][label(action["lookup_id"])]
            size = number(action["received_bytes"])
            if "received_bytes" in previous:
                if previous["received_bytes"] != size:
                    raise ValueError("lookup observation differs from recorded spending")
            elif previous["status"] != "reserved":
                raise ValueError("lookup observation requires a reserved query")
            else:
                previous["received_bytes"] = size
                state["received_query_bytes"] += size
            return {"lookup_id":action["lookup_id"],"received_bytes":size}
        if kind == "lookup_capture":
            shape(action,("kind","receipt","capture"))
            receipt = copy.deepcopy(action["receipt"])
            if receipt.get("kind") != "lookup_result":
                raise ValueError("lookup capture requires a result receipt")
            if action["capture"] is not None:
                capture = action["capture"]
                shape(capture,("action","text_sha256"))
                if (capture["action"].get("kind") != "source" or receipt["evidence"] or
                        receipt["reused_from"] is not None or
                        capture["action"].get("review_id") != receipt["query"]["review_id"]):
                    raise ValueError("invalid lookup source capture")
                evidence = self._action(state,capture["action"],operation_key)["evidence_id"]
                if hashlib.sha256(state["evidence"][evidence]["text"].encode("utf-8")).hexdigest() != capture["text_sha256"]:
                    raise ValueError("native source receipt does not match captured bytes")
                receipt["evidence"] = [evidence]
            if receipt["evidence"]:
                self._evidence(state,receipt["evidence"])
            self._action(state,receipt,operation_key)
            return {"lookup_id":receipt["lookup_id"],"evidence":receipt["evidence"]}
        if kind == "lookup_result":
            shape(action, ("kind","lookup_id","question_id","query","result","evidence","native_query_count","reused_from"))
            key = label(action["lookup_id"])
            previous = state["lookups"].get(key)
            if previous and previous["status"] != "reserved":
                raise ValueError("lookup result already recorded")
            if previous and any(previous[k] != action[k] for k in ("question_id","query")):
                raise ValueError("lookup receipt differs from reservation")
            if action["question_id"] not in state["questions"]:
                raise ValueError("lookup needs a deciding question")
            references(action["evidence"],state["evidence"],nonempty=False)
            number(action["native_query_count"])
            if action["reused_from"] is not None and action["reused_from"] not in state["lookups"]:
                raise ValueError("unknown lookup reuse origin")
            size = len(json.dumps(action["result"],ensure_ascii=False).encode("utf-8"))
            observed = previous.get("received_bytes") if previous else None
            if observed is not None and observed != size:
                raise ValueError("lookup receipt differs from observed byte spending")
            state["lookups"][key] = {k:v for k,v in action.items() if k not in ("kind","lookup_id")}
            if observed is not None:
                state["lookups"][key]["received_bytes"] = observed
            if previous and "requested_question" in previous:
                state["lookups"][key]["requested_question"] = previous["requested_question"]
            if previous and "review_ids" in previous:
                state["lookups"][key]["review_ids"] = previous["review_ids"]
            state["lookups"][key].update(status="complete",sequence=state["revision"] + 1)
            # Match ordinary worker accounting: every received/reused result JSON
            # counts, separately from unique captured source and actual native I/O.
            if observed is None:
                state["received_query_bytes"] += size
            return {"lookup_id":key}
        if kind == "lookup_request":
            shape(action,("kind","lookup_id","question_id","query","units"),("requested_question","review_ids"))
            key = label(action["lookup_id"])
            if key in state["lookups"] or action["question_id"] not in state["questions"]:
                raise ValueError("lookup reservation needs a new ID and known question")
            if "requested_question" in action:
                label(action["requested_question"])
            question = state["questions"][action["question_id"]]
            beneficiaries = action.get("review_ids",question["review_ids"])
            references(beneficiaries,state["claims"])
            if (action["query"]["review_id"] not in question["review_ids"] or
                    action["query"]["review_id"] not in beneficiaries):
                raise ValueError("lookup attribution belongs to another question scope")
            self._spend(state,{"queries":number(action["units"],positive=True)})
            settled = any(state["claims"][rid]["draft"] and action["question_id"] in
                          state["claims"][rid]["draft"].get("resolved_questions",[])
                          for rid in set(beneficiaries) & set(question["review_ids"]))
            if question["status"] == "answered" or settled:
                self._reopen_question(state,action["question_id"])
                state["questions"][action["question_id"]]["attempts"].append({
                    "status":"open","reason":"A deciding lookup reopened this relationship.","evidence":[],
                    "origin":"controller_lookup_reservation"})
            state["lookups"][key] = {"question_id":action["question_id"],"query":action["query"],"status":"reserved",
                "result":None,"evidence":[],"native_query_count":None,"reused_from":None,"sequence":state["revision"] + 1}
            if "requested_question" in action:
                state["lookups"][key]["requested_question"] = action["requested_question"]
            state["lookups"][key]["review_ids"] = list(beneficiaries)
            return {"lookup_id":key}
        if kind == "draft_batch":
            shape(action, ("kind", "drafts"))
            drafts = action["drafts"]
            if not isinstance(drafts, list) or not drafts:
                raise ValueError("draft batch requires results")
            references([d["result"]["review_id"] for d in drafts], state["claims"])
            return [self._action(state, {**d, "kind":"draft"}, operation_key) for d in drafts]
        if kind == "draft":
            shape(action, ("kind", "result", "applicability"), ("propositions","resolved_questions"))
            result = action["result"]
            if not isinstance(result, dict):
                raise ValueError("draft result must be an object")
            claim = state["claims"][result["review_id"]]
            if result.get("decision") not in ("issue", "not_issue", "needs_review"):
                raise ValueError("invalid native verdict")
            label(result.get("summary"))
            self._draft_evidence(state, result)
            checks = result.get("checks")
            if not isinstance(checks, list) or any(not isinstance(c, str) or not c.strip() for c in checks):
                raise ValueError("draft requires explicit checks")
            if bool(checks) != (result["decision"] == "needs_review"):
                raise ValueError("only needs_review retains deciding checks")
            resolved = action.get("resolved_questions",[])
            references(resolved,state["questions"],nonempty=False)
            if resolved and (result["decision"] == "needs_review" or any(
                    result["review_id"] not in state["questions"][qid]["review_ids"] for qid in resolved)):
                raise ValueError("question resolution requires a settled decision for that claim")
            pending = [q for qid,q in state["questions"].items() if result["review_id"] in q["review_ids"] and
                       q["status"] != "answered" and qid not in resolved]
            if pending and result["decision"] != "needs_review":
                raise ValueError("unanswered deciding question prevents closure")
            references(action["applicability"], state["applicability"], nonempty=False)
            dependencies = action.get("propositions", [])
            self._proposition_dependencies(state, dependencies)
            for key in action["applicability"]:
                applies = state["applicability"][key]
                prop = state["propositions"][applies["proposition_id"]][-1]
                if applies["review_id"] != result["review_id"] or prop["status"] != "available" or applies["proposition_revision"] != prop["revision"]:
                    raise ValueError("draft relies on foreign or stale applicability")
                self._evidence(state, [*prop["evidence"], *applies["evidence"]])
            if claim["draft"] is not None:
                claim["draft_history"].append(claim["draft"])
            claim["draft"] = {"result":result, "applicability":action["applicability"], "propositions":dependencies}
            if resolved:
                # Per-claim reviewer interpretation, backed by this draft's
                # source. The shared question and other claims stay open.
                claim["draft"]["resolved_questions"] = list(resolved)
            claim["reconsideration"] = []
            return {"review_id":result["review_id"], "status":"drafted"}
        raise ValueError("unknown workspace action")

    @staticmethod
    def _reopen_question(state, question_id):
        question = state["questions"][question_id]
        question["status"] = "open"
        for rid in question["review_ids"]:
            claim = state["claims"][rid]
            marker = "question:" + question_id
            if claim["draft"] is not None and marker not in claim["reconsideration"]:
                claim["reconsideration"].append(marker)

    @staticmethod
    def _invalidate(state, proposition_id):
        consumers = {a["review_id"] for a in state["applicability"].values() if a["proposition_id"] == proposition_id}
        for claim_id, claim in state["claims"].items():
            if claim["draft"] and any(p["proposition_id"] == proposition_id for p in claim["draft"].get("propositions", [])):
                consumers.add(claim_id)
        for claim_id in consumers:
            claim = state["claims"][claim_id]
            if proposition_id not in claim["reconsideration"]:
                claim["reconsideration"].append(proposition_id)

    def _proposition_dependencies(self, state, dependencies):
        if not isinstance(dependencies, list):
            raise ValueError("expected proposition dependency list")
        keys = []
        for dependency in dependencies:
            shape(dependency, ("proposition_id", "revision"))
            key = dependency["proposition_id"]
            references([key], state["propositions"])
            prop = state["propositions"][key][-1]
            if prop["status"] != "available" or type(dependency["revision"]) is not int or prop["revision"] != dependency["revision"]:
                raise ValueError("draft relies on a stale or disputed proposition")
            self._evidence(state, prop["evidence"])
            keys.append(key)
        references(keys, state["propositions"], nonempty=False)

    def _draft_evidence(self, state, result):
        windows = result.get("evidence")
        if not isinstance(windows, list) or (not windows and result["decision"] != "needs_review"):
            raise ValueError("settled draft requires inspected source evidence")
        ids = []
        for window in windows:
            shape(window, ("path", "start_line", "end_line"))
            first, last = window["start_line"], window["end_line"]
            number(first, positive=True)
            number(last, positive=True)
            if last < first:
                raise ValueError("invalid draft evidence range")
            candidates = [key for key,e in state["evidence"].items() if e["path"] == window["path"]
                          and e["start_line"] <= first <= last <= e["end_line"]]
            if not candidates:
                raise ValueError("draft cites source not captured in the workspace")
            ids.append(candidates[0])
        if ids:
            self._evidence(state, sorted(set(ids)))
        return sorted(set(ids))

    def view(self, work_id, max_bytes=32768):
        return self._view(self.snapshot(), work_id, max_bytes)

    def _current_session(self, state, session_id):
        session = state["sessions"][session_id]
        if session["retired"]:
            raise ValueError("session was replaced; use its successor")
        packet = self._view(state, session["work_id"], 1024 * 1024)
        # Reservations/usage do not invalidate evidence packets; claim state does.
        packet.pop("budget")
        original = copy.deepcopy(session["packet"])
        original.pop("budget")
        if packet != original:
            raise ValueError("session working context changed; create a new session")

    def check_session(self, session_id):
        self._current_session(self.snapshot(), session_id)

    def _view(self, state, work_id, max_bytes):
        import review_workspace_evidence
        deciding = review_workspace_evidence.visible(state, work_id)
        number(max_bytes, positive=True)
        ids = [c for c in state["work"][work_id]["claims"] if state["claims"][c]["draft"] is None or state["claims"][c]["reconsideration"]]
        applies = {k:a for k,a in state["applicability"].items() if a["review_id"] in ids}
        prop_ids = set(state["work"][work_id]["proposition_ids"]) | {a["proposition_id"] for a in applies.values()}
        propositions = {key:state["propositions"][key][-1] for key in sorted(prop_ids)}
        questions = {}
        settled_evidence = set()
        for key,question in state["questions"].items():
            if not set(question["review_ids"]) & set(ids):
                continue
            questions[key] = copy.deepcopy(question)
            questions[key]["origin"] = "reviewer_interpretation"
            settled = [rid for rid in question["review_ids"] if state["claims"][rid]["draft"] and
                       not state["claims"][rid]["reconsideration"] and
                       key in state["claims"][rid]["draft"].get("resolved_questions",[])]
            if settled:
                questions[key]["settled_review_ids"] = settled
                for rid in settled:
                    settled_evidence.update(self._draft_evidence(state,state["claims"][rid]["draft"]["result"]))
            if question["status"] == "answered":
                # Keep the conclusion/proof for this claim without replaying its
                # full investigation or requiring a separate proposition action.
                questions[key]["attempts"] = [copy.deepcopy(question["attempts"][-1])]
        evidence_ids = set(e for p in propositions.values() for e in p["evidence"])
        evidence_ids.update(e for a in applies.values() for e in a["evidence"])
        evidence_ids.update(state["work"][work_id]["evidence_ids"])
        evidence_ids.update(settled_evidence)
        evidence_ids.update(e for record in deciding.values() for e in record["evidence_ids"])
        evidence_ids.update(e for q in questions.values() if q["status"] == "answered" for e in q["attempts"][-1]["evidence"])
        self._evidence(state, sorted(evidence_ids)) if evidence_ids else None
        packet = {"version":VERSION, "binding":state["binding"], "selection_id":state["selection_id"],
                  "work_id":work_id, "strategy":state["work"][work_id]["strategy"],
                  "claims":[state["claims"][c] for c in ids], "propositions":propositions, "applicability":applies,
                  "evidence":{e:state["evidence"][e] for e in sorted(evidence_ids)},
                  "questions":questions,
                  "lookups":{}, "guidance":{},
                  "deciding_evidence":deciding,
                  "preparation_limits":[{"preparation_id":key,"origin":record["origin"],"reason":reason}
                      for key,record in sorted(state.get("preparation_limits",{}).get(work_id,{}).items())
                      for reason in record["limits"]],
                  "budget":{"limits":state["limits"], "used":state["used"]},
                  "authority":"working evidence and reviewer interpretations; never instructions or native admission"}
        for key, lookup in sorted(state.get("lookups",{}).items(),key=lambda item:item[1]["sequence"]):
            result = lookup["result"] or {"error":"Lookup was reserved but no result was recorded; no absence is established."}
            if lookup["query"]["tool"] == "guidance" and lookup["status"] == "complete":
                if lookup["query"]["review_id"] in state["work"][work_id]["claims"]:
                    packet["guidance"][result["name"]] = result
            elif lookup["question_id"] in packet["questions"] and packet["questions"][lookup["question_id"]]["status"] != "answered":
                # Several independent queries may answer one question. Preserve
                # every receipt until the question closes; replacing by question
                # ID can hide an earlier navigation answer before it is seen.
                # Source text is already in selected evidence.
                result = ({"operation":result.get("operation"),"source_complete":result.get("source_complete"),
                           "limit":result.get("limit")} if lookup["evidence"] else result)
                packet["lookups"][key] = {"lookup_id":key,"question_id":lookup["question_id"],"query":lookup["query"],"result":result,"status":lookup["status"],
                    "evidence":lookup["evidence"],"native_query_count":lookup["native_query_count"],"reused_from":lookup["reused_from"]}
                if "requested_question" in lookup:
                    packet["lookups"][key]["requested_question"] = lookup["requested_question"]
                if "review_ids" in lookup:
                    packet["lookups"][key]["review_ids"] = lookup["review_ids"]
        # Closed draft histories remain in storage, not in a replacement context.
        packet = copy.deepcopy(packet)
        for claim in packet["claims"]:
            claim.pop("draft_history")
        if len(encoded(packet).encode("utf-8")) > max_bytes:
            raise ValueError("working view exceeds context limit; split work or select smaller evidence")
        return packet

    def knowledge(self, proposition_id=None):
        state = self.snapshot()
        # Explicit lookup first; no semantic/name-based equivalence is assumed.
        selected = state["propositions"] if proposition_id is None else {proposition_id:state["propositions"][proposition_id]}
        for history in selected.values():
            self._evidence(state, history[-1]["evidence"])
        return copy.deepcopy(state["propositions"] if proposition_id is None else state["propositions"][proposition_id])

    def usage(self):
        calls = list(self.snapshot()["calls"].values())
        totals = {}
        for counter in COUNTERS:
            values = [(c["usage"] or {}).get(counter) for c in calls]
            totals[counter] = None if None in values else sum(values)
        return {"calls":len(calls), "unobserved_calls":sum(c["usage"] is None for c in calls), "totals":totals}

    def bundle_draft(self, bundle_id):
        state = self.snapshot()
        claims, _ = self._bundle_claims(state, bundle_id)
        return {"results":[c["draft"]["result"] for c in claims]}

    def _bundle_claims(self, state, bundle_id):
        claims = [c for c in state["claims"].values() if c["bundle_id"] == bundle_id]
        if not claims or any(c["draft"] is None or c["reconsideration"] for c in claims):
            raise ValueError("bundle working draft is incomplete or requires reconsideration")
        evidence = set()
        for claim in claims:
            if claim["draft"]["result"]["decision"] != "needs_review" and any(
                    claim["review_id"] in q["review_ids"] and q["status"] != "answered" and
                    qid not in claim["draft"].get("resolved_questions",[]) for qid,q in state["questions"].items()):
                raise ValueError("unanswered deciding question prevents bundle closure")
            evidence.update(self._draft_evidence(state, claim["draft"]["result"]))
            self._proposition_dependencies(state, claim["draft"].get("propositions", []))
            for dependency in claim["draft"].get("propositions", []):
                evidence.update(state["propositions"][dependency["proposition_id"]][-1]["evidence"])
            for key in claim["draft"]["applicability"]:
                applies = state["applicability"][key]
                prop = state["propositions"][applies["proposition_id"]][-1]
                if (applies["review_id"] != claim["review_id"] or prop["status"] != "available" or
                        applies["proposition_revision"] != prop["revision"]):
                    raise ValueError("draft relies on foreign or stale applicability")
                self._evidence(state, sorted(set([*applies["evidence"], *prop["evidence"]])))
                evidence.update([*applies["evidence"], *prop["evidence"]])
        return claims, evidence

    def review_package(self, bundle_ids=None):
        """Project existing judgments; do not infer applicability or new blockers."""
        state = self.snapshot()
        known = {c["bundle_id"] for c in state["claims"].values()}
        bundle_ids = sorted(known) if bundle_ids is None else bundle_ids
        references(bundle_ids, known)
        claims, bundles, evidence_ids = [], [], set()
        for bundle_id in sorted(bundle_ids):
            members, evidence = self._bundle_claims(state, bundle_id)
            claims.extend(members); evidence_ids.update(evidence)
            bundles.append({"bundle_id":bundle_id,"review_ids":[c["review_id"] for c in members],
                            "draft_id":identity({"results":[c["draft"]["result"] for c in members]})})
        notes, applicability, questions, projected = {}, {}, {}, []
        for claim in claims:
            draft = claim["draft"]
            applies = {key:state["applicability"][key] for key in draft["applicability"]}
            ids = {p["proposition_id"] for p in draft.get("propositions", [])}
            ids.update(a["proposition_id"] for a in applies.values())
            linked = []
            for pid in sorted(ids):
                prop = state["propositions"][pid][-1]
                nid = identity([pid,prop["revision"]])
                notes[nid] = {"proposition_id":pid, **copy.deepcopy(prop)}
                aids = sorted(k for k,a in applies.items() if a["proposition_id"] == pid)
                linked.append({"note_id":nid,"relationship":"caller_applicability_recorded" if aids else "context_only",
                               "applicability_ids":aids})
            applicability.update(copy.deepcopy(applies))
            linked_questions = []
            for qid, question in sorted(state["questions"].items()):
                if claim["review_id"] not in question["review_ids"]:
                    continue
                last = copy.deepcopy(question["attempts"][-1]) if question["attempts"] else None
                if last:
                    evidence_ids.update(last.get("evidence", []))
                questions[qid] = {"question":question["question"],"review_ids":question["review_ids"],
                                  "status":question["status"],"last_attempt":last,
                                  "attempt_count":len(question["attempts"]),"origin":"reviewer_interpretation"}
                linked_questions.append({"question_id":qid,
                    "resolved_for_claim":qid in draft.get("resolved_questions", [])})
            projected.append({**{k:claim[k] for k in ("review_id","property","path","line","bundle_id")},
                              "result":copy.deepcopy(draft["result"]),"reviewer_notes":linked,"questions":linked_questions})
        if evidence_ids:
            self._evidence(state, sorted(evidence_ids))
        package = {"schema_version":"mehscanWorkspaceReviewPackage/v1", "binding":state["binding"],
                   "selection_id":state["selection_id"],"workspace_revision":state["revision"],
                   "native_admission":False,
                   "authority":"Results are unchanged workspace drafts. Notes, applicability and questions are reviewer interpretations, not certified facts or additional verdict blockers. Source hashes are checked; native validation is separate.",
                   "bundles":bundles,"claims":projected,"notes":notes,"applicability":applicability,"questions":questions,
                   "omitted_review_ids":sorted(set(state["claims"]) - {c["review_id"] for c in claims}),
                   "evidence":{key:copy.deepcopy(state["evidence"][key]) for key in sorted(evidence_ids)}}
        package["package_id"] = identity(package)
        return package


def render_review_package(package):
    """Human view of the same attributed records, with no prose interpretation."""
    def block(value):
        text = str(value)
        fence = "`" * max(3, max((len(m[0])+1 for m in re.finditer(r'`+',text)),default=0))
        return fence + "text\n" + text + "\n" + fence
    evidence_numbers = {key:i for i,key in enumerate(package["evidence"],1)}
    def links(ids):
        return ", ".join(f"[Source {evidence_numbers[key]}](#source-{evidence_numbers[key]})" for key in ids)
    lines = ["# Workspace review package", "", package["authority"], "",
             "Package: `" + package["package_id"] + "`", "",
             f"Included claims: {len(package['claims'])}; omitted claims: {len(package['omitted_review_ids'])}.", ""]
    if package["omitted_review_ids"]:
        lines.extend(["Omitted claim IDs:", block("\n".join(package["omitted_review_ids"])), ""])
    for index,claim in enumerate(package["claims"],1):
        result = claim["result"]
        lines.extend([f"## Claim {index}", "", block(claim["review_id"]),
                      block(f"{claim['path']}:{claim['line']}\n{claim['property']}"), "",
                      "Decision: " + result["decision"], block(result["summary"]), block(result["reason"]), ""])
        # Preserve every remaining native result field, including diagnosis,
        # outstanding checks, blockers and adjacent source leads.
        details = {k:v for k,v in result.items() if k not in ("review_id","decision","summary","reason")}
        lines.extend(["Claim result details:",block(json.dumps(details,ensure_ascii=False,indent=2)),""])
        for link in claim["reviewer_notes"]:
            note = package["notes"][link["note_id"]]
            lines.extend(["### Reviewer note: " + ("caller applicability recorded" if link["applicability_ids"] else "context only; applicability not recorded"), "",
                          block(f"{note['proposition_id']} (revision {note['revision']})\nScope: {note['scope']}\nStatement: {note['statement']}\nConditions: {note['conditions']}\nExclusions: {note['exclusions']}"),
                          links(note["evidence"]), ""])
            for aid in link["applicability_ids"]:
                applies = package["applicability"][aid]
                lines.extend(["Caller applicability (reviewer interpretation):", block(applies["reason"]),links(applies["evidence"]),""])
        for link in claim["questions"]:
            question = package["questions"][link["question_id"]]
            status = "resolved for this claim" if link["resolved_for_claim"] else question["status"]
            last = question["last_attempt"]
            lines.extend(["### Deciding question", "", block(question["question"]), "Status: " + status,
                          block(last["reason"]) if last else "No answer recorded.",
                          links(last.get("evidence",[])) if last else "", ""])
    lines.extend(["## Captured source", "", "Shared source is listed once. Notes do not certify caller applicability.", ""])
    for key,evidence in package["evidence"].items():
        lines.extend([f"### Source {evidence_numbers[key]}", "",
            block(f"{evidence['path']}:{evidence['start_line']}-{evidence['end_line']}\nSHA-256: {evidence['file_sha256']}"),
            block(evidence["text"]), ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "status", "apply", "view", "knowledge", "bundle-draft", "review-package"))
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--seed", required=True, help="trusted experimental binding/claim/limit JSON; not a native admission")
    parser.add_argument("--action", help="JSON action file for apply")
    parser.add_argument("--operation-key")
    parser.add_argument("--expected-revision", type=int)
    parser.add_argument("--work-id", default="initial")
    parser.add_argument("--max-bytes", type=int, default=32768)
    parser.add_argument("--proposition-id")
    parser.add_argument("--bundle-id")
    parser.add_argument("--format", choices=("json","markdown"), default="json", help="review-package output format")
    args = parser.parse_args()
    if args.format == "markdown" and args.command != "review-package":
        parser.error("markdown format requires review-package")
    seed = json.loads(Path(args.seed).read_text(encoding="utf-8"))
    if args.command == "init":
        workspace = Workspace.create(args.workspace, seed["source_root"], seed["binding"], seed["claims"], seed["limits"])
    else:
        workspace = Workspace(args.workspace, seed["binding"])
    if args.command in ("init", "status"):
        state = workspace.snapshot()
        result = {k:state[k] for k in ("version", "binding", "selection_id", "revision", "limits", "used", "work")}
        result.update(claims={k:{"drafted":v["draft"] is not None, "reconsideration":v["reconsideration"]} for k,v in state["claims"].items()},
                      usage=workspace.usage())
    elif args.command == "apply":
        if args.action is None or args.operation_key is None or args.expected_revision is None:
            parser.error("apply requires --action, --operation-key and --expected-revision")
        result = workspace.apply(args.operation_key, args.expected_revision, json.loads(Path(args.action).read_text(encoding="utf-8")))
    elif args.command == "view":
        result = workspace.view(args.work_id, args.max_bytes)
    elif args.command == "knowledge":
        result = workspace.knowledge(args.proposition_id)
    elif args.command == "review-package":
        result = workspace.review_package([args.bundle_id] if args.bundle_id else None)
    else:
        result = workspace.bundle_draft(args.bundle_id)
    if args.format == "markdown":
        print(render_review_package(result))
        return
    print(json.dumps({"native_admission":False, "result":result}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, sqlite3.Error) as error:
        print(json.dumps({"native_admission":False, "error":str(error)}))
        raise SystemExit(2)
