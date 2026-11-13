"""Durable case evidence and interpretation dependencies; no native verdict writes."""
import copy
import hashlib
import json
from pathlib import Path
import threading

import review_context as context
from review_evidence import AtomicState


class CaseState(AtomicState):
    version = "mehscanCaseState/v1"
    action_limit = 2 * 1024 * 1024

    def __init__(self, path, binding):
        self.lock = threading.RLock()
        super().__init__(path, binding)

    @classmethod
    def create(cls, path, root, binding, registry):
        path, root = Path(path).resolve(), Path(root).resolve(strict=True)
        if path.is_relative_to(root):
            raise ValueError("case state must be outside reviewed source")
        cases = {item["id"]:{"checks":[check["id"] for check in item["checks"]],
            "questions":{}, "execution":"unstarted", "result":None, "result_history":[],
            "evidence":[], "dependencies":{}, "reconsideration":{}, "native_reconsideration":{},
            "verify_review_ids":list(item.get("verify_review_ids", []))}
            for item in registry["items"]}
        cls.publish(path, {"version":cls.version, "binding":copy.deepcopy(binding), "revision":0,
            "source_root":str(root), "cases":cases, "assertions":{}, "evidence":{}})
        return cls(path, binding)

    def submit(self, key, action):
        with self.lock:
            old = self.operation(key)
            revision = old["request"]["revision"] if old else self.snapshot()["revision"]
            return self.apply(key, revision, action)["result"]

    def result_reference(self, path):
        path = Path(path).resolve()
        if not path.is_relative_to(self.path.parent) or path.is_symlink():
            raise ValueError("case result must be a controller artifact")
        data = path.read_bytes()
        return {"path":str(path.relative_to(self.path.parent)), "sha256":hashlib.sha256(data).hexdigest()}

    def _read_result(self, ref):
        path = self.path.parent / ref["path"]
        if path.is_symlink() or not path.resolve().is_relative_to(self.path.parent):
            raise ValueError("case result escapes its controller artifacts")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != ref["sha256"]:
            raise ValueError("saved case result changed")
        return json.loads(data.decode("utf8"))

    @staticmethod
    def _capture(state, proofs):
        ids = []
        root = Path(state["source_root"])
        for proof in proofs:
            window = context.delivered_source_window(root, {"operation":"prepared_source", "results":{
                **{key:proof[key] for key in ("path", "start_line", "end_line")}, "text":proof["quote"]}})
            if window is None or window["end_line"] != proof["end_line"] or window["text"] != proof["quote"]:
                raise ValueError("case evidence must contain exact complete source lines")
            record = {key:window[key] for key in ("path", "start_line", "end_line", "source_sha256")}
            eid = context.digest(record)
            state["evidence"][eid] = record
            ids.append(eid)
        return sorted(set(ids))

    @staticmethod
    def _fresh(state, ids):
        checked = {}
        for eid in ids:
            record = state["evidence"][eid]
            path = record["path"]
            if path not in checked:
                checked[path] = hashlib.sha256(context.source_file(Path(state["source_root"]), path).read_bytes()).hexdigest()
            if checked[path] != record["source_sha256"]:
                raise ValueError("case evidence source changed")

    @classmethod
    def validate_dependencies(cls, state, dependencies):
        if not isinstance(dependencies, list):
            raise ValueError("assertion dependencies require a list")
        seen = set()
        for dep in dependencies:
            if not isinstance(dep, dict) or set(dep) != {"assertion_id", "version"}:
                raise ValueError("invalid assertion dependency")
            aid = dep["assertion_id"]
            history = state["assertions"].get(aid)
            if (not history or aid in seen or type(dep["version"]) is not int
                    or history[-1]["version"] != dep["version"] or history[-1]["status"] != "available"):
                raise ValueError("assertion dependency is foreign, duplicate, disputed or stale")
            cls._fresh(state, history[-1]["evidence"])
            seen.add(aid)

    @staticmethod
    def _invalidate(state, aid, reason):
        affected = []
        for case_id, case in state["cases"].items():
            for check_id, dependencies in case["dependencies"].items():
                if any(dep["assertion_id"] == aid for dep in dependencies):
                    case["reconsideration"][check_id] = reason
                    affected.append({"case_id":case_id, "check_id":check_id})
        return affected

    def _action(self, state, action, operation_key):
        kind = action["kind"]
        if kind == "resolve":
            case = state["cases"][action["case_id"]]
            ticket = action["ticket"]
            if ticket != self._resolution_ticket(state, action["case_id"], ticket["check_ids"]):
                raise ValueError("scoped resolution became stale")
            result = self._read_result(action["result"])
            if result.get("resolution_ticket") != ticket:
                raise ValueError("resolution requires a result bound to its ticket")
            case.setdefault("resolution_attempts", []).append({"ticket":copy.deepcopy(ticket), "result":action["result"]})
            if result.get("status") != "complete":
                return {"case_id":action["case_id"], "check_ids":ticket["check_ids"], "status":"incomplete"}
            draft = result["draft"]
            if draft.get("results") or draft.get("proposals"):
                raise ValueError("scoped check resolution cannot replace native verdicts")
            from review_work import check_results
            available = [{"assertion_id":aid, "version":history[-1]["version"]}
                for aid, history in state["assertions"].items() if history[-1]["status"] == "available"]
            considered = [{"assertion_id":aid, "version":entry["version"]}
                for aid, history in state["assertions"].items() for entry in history]
            check_results([{"id":value} for value in ticket["check_ids"]], draft.get("work_checks"), available, considered)
            evidence = self._capture(state, result["proofs"])
            offered = {(p["path"], p["start_line"], p["end_line"]) for p in result["proofs"]}
            for row in draft["work_checks"]:
                if any((p["path"], p["start_line"], p["end_line"]) not in offered for p in row["evidence"]):
                    raise ValueError("resolution cites source outside validated proofs")
                self.validate_dependencies(state, row["assertion_dependencies"])
                check_id = row["check_id"]
                case["dependencies"][check_id] = copy.deepcopy(row["assertion_dependencies"])
                case.setdefault("owner_dispositions", {})[check_id] = copy.deepcopy(row["assertion_dispositions"])
                case.setdefault("resolved_checks", {})[check_id] = {"result":action["result"], "answer":copy.deepcopy(row)}
                case["reconsideration"].pop(check_id, None)
            case["evidence"] = sorted(set(case["evidence"] + evidence))
            for review_id in case.get("verify_review_ids", []):
                case["native_reconsideration"][review_id] = "Owner check corrected; reconcile the native proof through normal admission."
            case.setdefault("resolutions", []).append({"ticket":copy.deepcopy(ticket), "result":action["result"]})
            return {"case_id":action["case_id"], "check_ids":ticket["check_ids"]}
        if kind == "fact_audit":
            aid, version = action["assertion_id"], action["version"]
            history = state["assertions"].get(aid, [])
            case = state["cases"][action["case_id"]]
            check_id = action["check_id"]
            if (not history or type(version) is not int or history[-1]["version"] != version
                    or {"assertion_id":aid, "version":version} not in case["questions"].get(check_id, {}).get("assertions", [])):
                raise ValueError("factual audit requires this check's current assertion version")
            if context.digest([aid, version]) in case.get("factual_audits", {}):
                raise ValueError("assertion version already audited; preserve its original audit")
            self._fresh(state, history[-1]["evidence"])
            result = self._read_result(action["result"])
            if (result.get("fact_audit") != {"assertion_id":aid, "version":version}
                    or result.get("review_role") != "fact_auditor" or result.get("question_provider") != action["provider"]):
                raise ValueError("factual audit result lacks its bound owner role and target")
            outcome, summary, evidence = "incomplete", result.get("detail", "Audit did not finalize."), []
            if result["status"] == "complete":
                from review_questions import check_draft
                from review_work import check_results
                check_draft(result["draft"])
                check_results([{"id":check_id}], result["draft"].get("work_checks"))
                answer = result["draft"]["work_checks"][0]
                offered = {(proof["path"], proof["start_line"], proof["end_line"]) for proof in result["proofs"]}
                if any((cite["path"], cite["start_line"], cite["end_line"]) not in offered for cite in answer["evidence"]):
                    raise ValueError("factual audit cites source outside its validated proofs")
                evidence = self._capture(state, result["proofs"])
                outcome = {"satisfied":"supported", "violated":"challenged"}.get(answer["status"], "unresolved")
                summary = answer["summary"]
                if outcome in ("supported", "challenged") and not evidence:
                    raise ValueError("factual audit conclusion requires deciding source")
            record = {"assertion_id":aid, "version":version, "outcome":outcome, "summary":summary,
                "selection":copy.deepcopy(action["selection"]), "result":action["result"], "evidence":evidence,
                **{key:result.get(key, 0) for key in ("calls", "queries", "bytes", "unknown_provider_calls", "seconds")},
                "provider":copy.deepcopy(action["provider"]), "conversation_id":result.get("question_conversation_id")}
            case.setdefault("factual_audits", {})[context.digest([aid, version])] = record
            if outcome == "challenged":
                history[-1].update(status="disputed", dispute_reason=summary, audit=action["result"])
                record["affected"] = self._invalidate(state, aid, "Factual audit challenge: " + summary)
                pattern = action["selection"].get("routing_pattern")
                if pattern and action["selection"].get("suspend_pattern"):
                    state.setdefault("suspended_patterns", {})[pattern] = record["result"]
            return record
        if kind == "native_audit":
            case = state["cases"][action["case_id"]]
            if not action["review_ids"] or not set(action["review_ids"]) <= set(case.get("verify_review_ids", [])):
                raise ValueError("native audit must select this case's required Verify IDs")
            for review_id in action["review_ids"]:
                case["native_reconsideration"][review_id] = action["reason"]
            return {"case_id":action["case_id"]}
        if kind == "start":
            state["cases"][action["case_id"]]["execution"] = "running"
            return {"case_id":action["case_id"]}
        if kind == "question":
            case = state["cases"][action["case_id"]]
            check = action["check"]
            if check["id"] not in case["checks"]:
                raise ValueError("foreign factual check")
            result = self._read_result(action["result"])
            refs = []
            if result["status"] == "complete":
                evidence = self._capture(state, result["proofs"])
                for row in result["draft"]["work_checks"]:
                    if row["check_id"] != check["id"]:
                        raise ValueError("question assertion changed check identity")
                    closed = row["status"] in ("satisfied", "violated")
                    if closed and not evidence:
                        raise ValueError("assertion requires deciding source")
                    aid = context.digest(["case-assertion", action["case_id"], check["id"]])
                    history = state["assertions"].setdefault(aid, [])
                    if history:
                        self._invalidate(state, aid, "A consumed assertion was replaced.")
                    history.append({"version":len(history)+1, "status":"available" if closed else "unresolved",
                        "proposition":check["question"], "scope":check["scope"], "acceptance":check["acceptance"],
                        "answer":copy.deepcopy(row), "evidence":evidence,
                        "provider":copy.deepcopy(result.get("question_provider")),
                        "conversation_id":result.get("question_conversation_id"), "origin":action["result"]})
                    if closed:
                        refs.append({"assertion_id":aid, "version":len(history)})
            case["questions"][check["id"]] = {"result":action["result"], "assertions":refs}
            return refs
        if kind == "result":
            case = state["cases"][action["case_id"]]
            result = self._read_result(action["result"])
            dependencies = {}
            if result["status"] == "complete":
                rows = result["draft"]["work_checks"]
                if {row["check_id"] for row in rows} != set(case["checks"]):
                    raise ValueError("case result changed required checks")
                evidence = self._capture(state, result["proofs"])
                self._fresh(state, evidence)
                case["evidence"] = evidence
                for row in rows:
                    deps = row.get("assertion_dependencies", [])
                    if result.get("authority", "").startswith("Factual propositions answered"):
                        deps = case["questions"].get(row["check_id"], {}).get("assertions", [])
                    self.validate_dependencies(state, deps)
                    from review_work import validate_dispositions
                    offered = [{"assertion_id":aid, "version":entry["version"]}
                        for aid, history in state["assertions"].items() for entry in history]
                    validate_dispositions({**row, "assertion_dependencies":deps}, offered)
                    case.setdefault("owner_dispositions", {})[row["check_id"]] = copy.deepcopy(row.get("assertion_dispositions", []))
                    dependencies[row["check_id"]] = copy.deepcopy(deps)
                if case.get("resolved_checks"):
                    case.setdefault("resolution_history", []).extend(case.get("resolutions", []))
                    case["resolved_checks"], case["resolutions"], case["resolution_attempts"] = {}, [], []
                case["reconsideration"] = {}
                case["native_reconsideration"] = {}
                case["dependencies"] = dependencies
            if case["result"]:
                case["result_history"].append(case["result"])
            case["result"] = action["result"]
            return {"case_id":action["case_id"]}
        if kind == "dispute":
            aid = action["assertion_id"]
            history = state["assertions"][aid]
            if type(action["version"]) is not int or history[-1]["version"] != action["version"]:
                raise ValueError("cannot dispute a stale assertion version")
            if not isinstance(action["reason"], str) or not 1 <= len(action["reason"].strip()) <= 4000:
                raise ValueError("dispute requires a bounded reason")
            history[-1].update(status="disputed", dispute_reason=action["reason"])
            return self._invalidate(state, aid, action["reason"])
        raise ValueError("unknown case state action")

    def _resolution_ticket(self, state, case_id, check_ids):
        case = state["cases"][case_id]
        if (not isinstance(check_ids, list) or not check_ids or any(not isinstance(v, str) for v in check_ids)
                or len(set(check_ids)) != len(check_ids) or not set(check_ids) <= set(case["checks"])):
            raise ValueError("resolution requires distinct existing check identities")
        if not case["result"]:
            raise ValueError("resolution requires an existing owner result")
        self._fresh(state, case["evidence"])
        prior = self._read_result(case["result"])
        answers = {row["check_id"]:row for row in prior.get("draft", {}).get("work_checks", [])}
        answers.update({key:value["answer"] for key, value in case.get("resolved_checks", {}).items()})
        if any(identity not in case["reconsideration"] and answers.get(identity, {}).get("status")
                not in ("unresolved", "not_checked") and (prior.get("status") == "complete" or identity in case.get("resolved_checks", {})) for identity in check_ids):
            raise ValueError("resolution requires reopened or unresolved checks")
        return {"case_id":case_id, "check_ids":sorted(check_ids), "binding":copy.deepcopy(state["binding"]),
            "basis":context.digest({"result":case["result"], "resolved_checks":case.get("resolved_checks", {}),
                "reconsideration":case["reconsideration"], "assertions":state["assertions"]})}

    def resolution_ticket(self, case_id, check_ids):
        with self.lock:
            return self._resolution_ticket(self.snapshot(), case_id, check_ids)

    def record_resolution(self, ticket, result_path):
        ref = self.result_reference(result_path)
        return self.submit(context.digest(["resolve", ticket, ref]),
            {"kind":"resolve", "case_id":ticket["case_id"], "ticket":ticket, "result":ref})

    def record_question(self, case_id, check, result_path):
        ref = self.result_reference(result_path)
        return self.submit(context.digest(["question", case_id, check["id"], ref]),
            {"kind":"question", "case_id":case_id, "check":check, "result":ref})

    def record_result(self, case_id, result_path):
        ref = self.result_reference(result_path)
        return self.submit(context.digest(["result", case_id, ref]),
            {"kind":"result", "case_id":case_id, "result":ref})

    def record_audit(self, case_id, check_id, target, result_path, selection, provider):
        ref = self.result_reference(result_path)
        return self.submit(context.digest(["fact-audit", case_id, target, ref]),
            {"kind":"fact_audit", "case_id":case_id, "check_id":check_id, **target,
             "result":ref, "selection":selection, "provider":provider})

    def results(self):
        with self.lock:
            state = self.snapshot()
            results = []
            for case_id, case in state["cases"].items():
                if case["execution"] == "unstarted" and not case["result"] and not case["questions"]:
                    continue
                row = self._read_result(case["result"]) if case["result"] else {
                    "case_id":case_id, "status":case["execution"], "calls":0}
                if case.get("resolved_checks") and row.get("status") != "complete":
                    # Explicit owner correction can salvage an incomplete parent.
                    # Only validated available facts survive; every other check stays open.
                    answers = {}
                    for saved in case["questions"].values():
                        for ref in saved["assertions"]:
                            assertion = state["assertions"][ref["assertion_id"]][-1]
                            self._fresh(state, assertion["evidence"])
                            if assertion["version"] == ref["version"] and assertion["status"] == "available":
                                answers[assertion["answer"]["check_id"]] = copy.deepcopy(assertion["answer"])
                    row["status"] = "complete"
                    row["draft"] = {"results":[], "proposals":[], "coverage":[], "work_checks":[answers.get(check_id, {
                        "check_id":check_id, "status":"not_checked", "summary":"No settled owner answer retained.",
                        "evidence":[], "next_deciding_fact":"Resolve this required check from deciding source."}) for check_id in case["checks"]]}
                    row.setdefault("proofs", [])
                    row.setdefault("inspected", [])
                    row.setdefault("proposals", [])
                if case.get("resolution_attempts", case.get("resolved_checks")) and row.get("status") == "complete":
                    for index, answer in enumerate(row["draft"]["work_checks"]):
                        replacement = case.get("resolved_checks", {}).get(answer["check_id"])
                        if replacement:
                            self._read_result(replacement["result"])
                            row["draft"]["work_checks"][index] = copy.deepcopy(replacement["answer"])
                    row["resolutions"] = copy.deepcopy(case.get("resolutions", []))
                    for resolution in case.get("resolution_attempts", case.get("resolutions", [])):
                        update = self._read_result(resolution["result"])
                        for counter in ("calls", "queries", "bytes", "unknown_provider_calls", "seconds"):
                            row[counter] = row.get(counter, 0) + update.get(counter, 0)
                        for field in ("proofs", "facts", "inspected"):
                            row.setdefault(field, []).extend(copy.deepcopy(update.get(field, [])))
                self._fresh(state, case["evidence"])
                row["reconsideration"] = copy.deepcopy(case["reconsideration"])
                row["native_reconsideration"] = copy.deepcopy(case.get("native_reconsideration", {}))
                partial = []
                for question in case["questions"].values():
                    answer = self._read_result(question["result"])
                    if answer.get("status") != "complete":
                        continue
                    for check in answer.get("draft", {}).get("work_checks", []):
                        check = copy.deepcopy(check)
                        for dep in question.get("assertions", []):
                            assertion = state["assertions"][dep["assertion_id"]][-1]
                            self._fresh(state, assertion["evidence"])
                            if assertion["version"] != dep["version"] or assertion["status"] != "available":
                                check.update(status="not_checked", next_deciding_fact="Factual assertion requires reconsideration.")
                        partial.append(check)
                row["owner_dispositions"] = copy.deepcopy(case.get("owner_dispositions", {}))
                row["partial_fact_checks"] = partial
                row["provisional_fact_answers"] = copy.deepcopy(case["questions"])
                row["factual_audits"] = copy.deepcopy(list(case.get("factual_audits", {}).values()))
                results.append(row)
            return results
