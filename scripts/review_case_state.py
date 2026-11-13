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
            "evidence":[], "dependencies":{}, "reconsideration":{}}
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
                    dependencies[row["check_id"]] = copy.deepcopy(deps)
                case["reconsideration"] = {}
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

    def record_question(self, case_id, check, result_path):
        ref = self.result_reference(result_path)
        return self.submit(context.digest(["question", case_id, check["id"], ref]),
            {"kind":"question", "case_id":case_id, "check":check, "result":ref})

    def record_result(self, case_id, result_path):
        ref = self.result_reference(result_path)
        return self.submit(context.digest(["result", case_id, ref]),
            {"kind":"result", "case_id":case_id, "result":ref})

    def results(self):
        with self.lock:
            state = self.snapshot()
            results = []
            for case_id, case in state["cases"].items():
                if case["execution"] == "unstarted" and not case["result"] and not case["questions"]:
                    continue
                row = self._read_result(case["result"]) if case["result"] else {
                    "case_id":case_id, "status":case["execution"], "calls":0}
                self._fresh(state, case["evidence"])
                row["reconsideration"] = copy.deepcopy(case["reconsideration"])
                row["provisional_fact_answers"] = copy.deepcopy(case["questions"])
                results.append(row)
            return results
