"""Bound review routing and shared reservations, independent of provider loops."""
import copy
import hashlib
import json
import threading
import time


ROUTING_REASONS = {"reasoning_gap", "control_applicability", "conflicting_evidence", "risky_dismissal",
                   "external_required", "human_required", "budget_exhausted", "stage_budget_exhausted"}
UNAVAILABLE = {"external_required", "human_required", "budget_exhausted"}


def grounded_note(value, known, *, dependency=False):
    """Validate source references, never certify a model's interpretation."""
    fields = {"question":500, "scope":500} if dependency else {"claim":700, "conditions":700, "limits":700}
    expected = set(fields) | {"artifacts"} | (set() if dependency else {"status"})
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid grounded research note")
    for key, limit in fields.items():
        if not isinstance(value[key], str) or not 1 <= len(value[key].strip()) <= limit:
            raise ValueError("grounded research note requires bounded explicit scope and limits")
    if (not isinstance(value["artifacts"], list) or not 1 <= len(value["artifacts"]) <= 8
            or any(not isinstance(a, str) or a not in known for a in value["artifacts"])):
        raise ValueError("grounded research note requires inspected source handles")
    if not dependency and value["status"] not in ("established", "unresolved"):
        raise ValueError("invalid research resolution status")
    result = copy.deepcopy(value)
    result["artifacts"] = sorted(set(result["artifacts"]))
    return result


class DependencyKnowledge:
    """Snapshot-bound research register. Controller owns scheduling, not verdicts.

    Exact question/scope/evidence identity only: no fuzzy semantic merging or
    inheritance of safe labels. Completed notes remain model interpretations.
    """
    def __init__(self, path, binding, write, previous=None):
        self.path, self.write = path, write
        self.state = json.loads(previous.read_text(encoding="utf-8")) if previous and previous.is_file() else {
            "binding":binding, "dependencies":{}}
        if self.state["binding"] != binding:
            raise ValueError("research knowledge differs from current source/runtime")
        for key, row in self.state["dependencies"].items():
            if key != self.identity(row["request"]):
                raise ValueError("research dependency identity changed")
            if row.get("resolution_digest") != self.resolution_digest(row):
                raise ValueError("research knowledge contents changed")
        self.save()

    @staticmethod
    def identity(request):
        canonical = {**request, "question":" ".join(request["question"].split()),
                     "scope":" ".join(request["scope"].split()), "artifacts":sorted(set(request["artifacts"]))}
        return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def resolution_digest(row):
        if "resolution" not in row:
            return None
        return hashlib.sha256(json.dumps([row["resolution"], row["source_handoff"]], sort_keys=True).encode()).hexdigest()

    def save(self):
        self.write(self.path, self.state)

    def request(self, request, consumer):
        key = self.identity(request)
        created = key not in self.state["dependencies"]
        row = self.state["dependencies"].setdefault(key, {"request":copy.deepcopy(request), "consumers":[], "status":"waiting"})
        if consumer not in row["consumers"]:
            row["consumers"].append(consumer)
        self.save()
        return key, created

    def resolve(self, key, note, source_handoff):
        row = self.state["dependencies"][key]
        row.update(status="resolved", resolution=copy.deepcopy(note), source_handoff=copy.deepcopy(source_handoff))
        row["resolution_digest"] = self.resolution_digest(row)
        self.save()

    def context(self, key):
        row = self.state["dependencies"][key]
        if row["status"] != "resolved":
            raise ValueError("cannot resume before dependency resolution")
        return {"dependency_id":key, "question":row["request"]["question"], "scope":row["request"]["scope"],
                "assertion":"source-backed model interpretation; verify applicability to this caller",
                **copy.deepcopy(row["resolution"])}


class BudgetExhausted(RuntimeError):
    pass


class SharedReviewBudget:
    """Reserve before dispatch; retries and different profiles share one ledger."""
    def __init__(self, path, policy, write, previous=None):
        self.path, self.policy, self.write = path, policy, write
        self.lock = threading.Lock()
        self.state = json.loads(previous.read_text(encoding="utf-8")) if previous and previous.is_file() else {
            "totals": {"model_calls": 0, "queries": 0, "bytes": 0}, "cases": {}, "run_seconds": 0}
        if self.state.get("active_since") is not None:
            self.state["run_seconds"] += max(0, time.time() - self.state["active_since"])
        for case in self.state["cases"].values():
            if case.pop("active_since", None) is not None:
                # Recovered active work has no reliable stop time after a crash.
                case["seconds"] += max(0, time.time() - case.pop("started_at"))
        self.prior_seconds = self.state["run_seconds"]
        self.started = time.monotonic()
        self.active = {}
        self._save()

    def _save(self):
        self.state.update(run_seconds=self.prior_seconds + time.monotonic() - self.started, active_since=time.time())
        self.write(self.path, self.state)

    def begin_case(self, identity):
        with self.lock:
            if identity in self.active:
                raise ValueError("a review case already has an active assessment")
            case = self.state["cases"].setdefault(identity,
                {"model_calls": 0, "queries": 0, "bytes": 0, "seconds": 0})
            self.active[identity] = time.monotonic()
            case.update(active_since=time.time(), started_at=time.time())
            self._save()

    def end_case(self, identity):
        with self.lock:
            if identity not in self.active:
                return
            case = self.state["cases"][identity]
            case["seconds"] += time.monotonic() - self.active.pop(identity)
            case.pop("active_since", None)
            case.pop("started_at", None)
            self._save()

    def remaining(self, identity, key):
        with self.lock:
            case = self.state["cases"][identity]
            if key == "timeout_seconds":
                return min(self.policy["run_limits"][key] - (self.prior_seconds + time.monotonic() - self.started),
                           self.policy["case_limits"][key] - case["seconds"] -
                           (time.monotonic() - self.active[identity] if identity in self.active else 0))
            return min(self.policy["run_limits"][key] - self.state["totals"][key],
                       self.policy["case_limits"][key] - case[key])

    def reserve(self, identity, key, amount):
        if type(amount) is not int or amount < 0:
            raise ValueError("invalid review budget reservation")
        with self.lock:
            case = self.state["cases"][identity]
            exceeded = any(current + amount > limits[key] for current, limits in (
                    (case[key], self.policy["case_limits"]),
                    (self.state["totals"][key], self.policy["run_limits"])))
            if exceeded and key != "bytes":
                raise BudgetExhausted("shared review " + key + " budget exhausted")
            case[key] += amount
            self.state["totals"][key] += amount
            self._save()
            if exceeded:
                # Bytes are observed after execution. Retain overspend so a
                # retry cannot erase an oversized already-received response.
                raise BudgetExhausted("shared review bytes budget exhausted")

    def close(self):
        with self.lock:
            self._save()
            self.state["active_since"] = None
            self.write(self.path, self.state)


def sampled(review_id, policy):
    digest = hashlib.sha256((policy["audit_seed"] + ":" + review_id).encode()).digest()
    return int.from_bytes(digest[:4], "big") % 100 < policy["audit_percent"]


def validate_routing(value, review_ids):
    if not isinstance(value, list) or len(value) > len(review_ids):
        raise ValueError("routing must name exact current review IDs and typed reasons")
    seen = set()
    for item in value:
        if (not isinstance(item, dict) or set(item) != {"review_id", "reason"}
                or item["review_id"] not in review_ids or item["reason"] not in ROUTING_REASONS
                or item["review_id"] in seen):
            raise ValueError("routing must name exact current review IDs and typed reasons")
        seen.add(item["review_id"])
    return value


def scoped_budget_routing(routing, stage_exhausted, shared_remaining):
    """A model's local stopping condition cannot declare a shared ledger spent."""
    result = copy.deepcopy(routing)
    for item in result:
        if item["reason"] not in {"budget_exhausted", "stage_budget_exhausted"}:
            continue
        if shared_remaining is None or any(value <= 0 for value in shared_remaining.values()):
            item["reason"] = "budget_exhausted"
        else:
            item["reason"] = "stage_budget_exhausted" if stage_exhausted else "reasoning_gap"
    return result


def source_handoff(stages, max_bytes):
    """Carry bounded actual query results, without prior verdicts or query intent."""
    facts, seen, omitted, size = [], set(), 0, 0
    for stage in reversed(stages):
        for row in reversed(stage.get("source_facts", [])):
            if row["result_id"] in seen:
                continue
            seen.add(row["result_id"])
            fact = {key:copy.deepcopy(row[key]) for key in
                    ("result_id", "origin_package_id", "origin_review_id", "query", "result")}
            fact["query"].pop("purpose", None)
            count = len(json.dumps(fact, ensure_ascii=False).encode("utf-8"))
            if size + count > max_bytes:
                omitted += 1
                continue
            facts.append(fact)
            size += count
    return {"facts":facts, "omitted_facts":omitted}


def needs_secondary(results, routing, policy, direct=False):
    reasons = {item["review_id"]: item["reason"] for item in routing}
    for result in results:
        decision, identity = result["decision"], result["review_id"]
        reason = reasons.get(identity)
        if decision == "issue":
            return True
        if not direct and reason in {"reasoning_gap", "control_applicability", "conflicting_evidence", "risky_dismissal", "stage_budget_exhausted"}:
            return True
        if decision == "not_issue" and sampled(identity, policy):
            return True
        if decision == "needs_review" and not direct and reason not in {"external_required", "human_required", "budget_exhausted"}:
            return True
    return False


def reconcile(primary, secondary, primary_profile, routing=()):
    """Compare source-validated assessments, never turn disagreement into safety."""
    other = {result["review_id"]: result for result in secondary["results"]}
    if set(other) != {result["review_id"] for result in primary["results"]}:
        raise ValueError("independent assessment differs from selected bundle coverage")
    result = copy.deepcopy(primary)
    unresolved = {item["review_id"] for item in routing}
    for index, first in enumerate(primary["results"]):
        second = other[first["review_id"]]
        chosen = copy.deepcopy(second if primary_profile == "routine" else first)
        if contrary(first["decision"], second["decision"]) or first["review_id"] in unresolved:
            chosen.update(decision="needs_review", confidence="low", diagnosis=None,
                          summary="Review leaves a decisive source question unresolved.")
            question = ("Resolve the contrary assessments for this exact operation using their decisive source evidence."
                        if contrary(first["decision"], second["decision"]) else
                        "Resolve the independent assessor's remaining question for this exact operation.")
            chosen["checks"] = list(dict.fromkeys([*first.get("checks", []), *second.get("checks", []), question]))
            chosen["investigation"]["blockers"] = list(dict.fromkeys([
                *first["investigation"].get("blockers", []), *second["investigation"].get("blockers", []), question]))
        chosen["investigation"]["journal_summary"] = None
        result["results"][index] = chosen
    return result


def adjudication_ids(stages):
    reasons = {item["review_id"]: item["reason"] for stage in stages for item in stage["routing"]
               if item["reason"] in UNAVAILABLE}
    left, right = ({r["review_id"]: r for r in stage["response"]["results"]} for stage in stages)
    routed = {item["review_id"] for stage in stages for item in stage["routing"] if item["reason"] == "conflicting_evidence"}
    return sorted(identity for identity in left if identity not in reasons and (
        contrary(left[identity]["decision"], right[identity]["decision"]) or identity in routed))


def contrary(left, right):
    """An open question is not an affirmative contrary security claim."""
    return {left, right} == {"issue", "not_issue"}


def validate_resolutions(values, ids, draft):
    if not isinstance(values, list) or {v.get("review_id") for v in values} != set(ids) or len(values) != len(ids):
        raise ValueError("adjudication must resolve exactly its assigned IDs")
    results = {r["review_id"]: r for r in draft["results"]}
    for value in values:
        if set(value) != {"review_id", "disputed_claim", "reason"} or any(
                not isinstance(value[key], str) or not 1 <= len(value[key].strip()) <= limit
                for key, limit in (("disputed_claim", 300), ("reason", 500))):
            raise ValueError("adjudication requires a bounded disputed claim and source reason")
        result = results[value["review_id"]]
        if not result.get("evidence"):
            raise ValueError("adjudication requires explicit source evidence")
        # Pin the explanation into the ordinary source-cited native assessment.
        result["reason"] = " ".join(value["reason"].split())
    return values


def apply_resolution(baseline, resolved, stages, ids):
    result = copy.deepcopy(baseline)
    by_id = {r["review_id"]: r for r in resolved["results"]}
    for index, prior in enumerate(result["results"]):
        identity = prior["review_id"]
        if identity not in ids:
            continue
        chosen = copy.deepcopy(by_id[identity])
        labels = {r["decision"] for stage in stages for r in stage["response"]["results"] if r["review_id"] == identity}
        if chosen["decision"] != "needs_review" and chosen["decision"] not in labels:
            chosen.update(decision="needs_review", confidence="low", diagnosis=None)
            question = "Independently assess the new verdict proposed during adjudication."
            chosen["checks"] = [question]
            chosen["investigation"]["blockers"] = [question]
        chosen["investigation"]["journal_summary"] = None
        result["results"][index] = chosen
    return result


def apply_qa(baseline, checked):
    result = copy.deepcopy(baseline)
    checked_by_id = {r["review_id"]: r for r in checked["results"]}
    if len(checked_by_id) != len(checked["results"]) or set(checked_by_id) != {r["review_id"] for r in baseline["results"]}:
        raise ValueError("final QA differs from assigned review coverage")
    for index, prior in enumerate(result["results"]):
        candidate = checked_by_id[prior["review_id"]]
        if candidate["decision"] not in (prior["decision"], "needs_review"):
            raise ValueError("final QA can only preserve a verdict or reopen its exact ID")
        if candidate["decision"] == "needs_review":
            chosen = copy.deepcopy(candidate)
            chosen["checks"] = list(dict.fromkeys([*prior.get("checks", []), *chosen.get("checks", [])]))
            chosen["investigation"]["blockers"] = list(dict.fromkeys([
                *prior["investigation"].get("blockers", []), *chosen["investigation"].get("blockers", [])]))
            chosen["investigation"]["journal_summary"] = None
            result["results"][index] = chosen
    return result


def revalidation_targets(stages, baseline, checked):
    """Revisit a new closed proposal or QA reopening, never an unavailable fact."""
    unavailable = {row["review_id"] for stage in stages for row in stage["routing"]
                   if row["reason"] in UNAVAILABLE}
    before = {r["review_id"]:r for r in baseline["results"]}
    proposed = {r["review_id"]:r for r in stages[-1]["response"]["results"]}
    adjudicated = stages[-1]["receipt"]["role"] == "adjudication"
    result = {}
    for row in checked["results"]:
        identity = row["review_id"]
        if identity in unavailable or row["decision"] != "needs_review":
            continue
        if before[identity]["decision"] != "needs_review":
            result[identity] = "quality_reopening"
        elif adjudicated and proposed[identity]["decision"] != "needs_review":
            result[identity] = "new_source_verdict"
    return result


def assessment_basis(assessments):
    decisions = [a["decision"] for a in assessments]
    if len(decisions) == 3:
        return decisions[-1] if decisions[-1] in decisions[:2] else "needs_review"
    if len(decisions) == 2:
        if contrary(*decisions):
            return "needs_review"
        expert = next((a for a in assessments if a.get("profile") == "expert"), None)
        if expert:
            return expert["decision"]
    return decisions[0] if len(set(decisions)) == 1 else "needs_review"


def quality_intent(draft, actions, baseline, assigned):
    """An explicit claim repair is pending even when its underlying label holds."""
    if (not isinstance(actions, list) or len(actions) != len(baseline["results"])
            or {a.get("review_id") for a in actions if isinstance(a, dict)} != {r["review_id"] for r in baseline["results"]}):
        raise ValueError("QA actions must cover exact assigned bundle IDs")
    result = copy.deepcopy(draft)
    rows = {r["review_id"]:r for r in result["results"]}
    before = {r["review_id"]:r for r in baseline["results"]}
    for action in actions:
        if (set(action) != {"review_id","action","claim"} or action["action"] not in ("keep","repair","reopen")
                or not isinstance(action["claim"], str) or len(action["claim"]) > 300):
            raise ValueError("QA action requires a bounded claim and typed intent")
        if action["action"] == "keep":
            if rows[action["review_id"]]["decision"] != before[action["review_id"]]["decision"]:
                raise ValueError("QA keep must preserve the baseline verdict")
            continue
        if action["review_id"] not in assigned or not action["claim"].strip():
            raise ValueError("QA repair/reopening requires an assigned claim")
        row = rows[action["review_id"]]
        row.update(decision="needs_review", diagnosis=None)
        row["checks"] = list(dict.fromkeys([*row.get("checks", []), action["claim"]]))
    return result


def apply_revalidation(baseline, first, second, proposals, routing=()):
    paired = reconcile(first, second, "routine", routing)
    first_by_id = {r["review_id"]:r for r in first["results"]}
    second_by_id = {r["review_id"]:r for r in second["results"]}
    result = copy.deepcopy(baseline)
    by_id = {r["review_id"]:r for r in paired["results"]}
    for index, row in enumerate(result["results"]):
        if row["review_id"] in proposals:
            chosen = by_id[row["review_id"]]
            if (first_by_id[row["review_id"]]["decision"] != second_by_id[row["review_id"]]["decision"]
                    or chosen["decision"] not in ("needs_review", proposals[row["review_id"]])):
                chosen.update(decision="needs_review", confidence="low", diagnosis=None)
                question = "Resolve the recovered-source proposal against the fresh assessments for this exact operation."
                chosen["checks"] = [*chosen.get("checks", []), question]
                chosen["investigation"]["blockers"] = [*chosen["investigation"].get("blockers", []), question]
            result["results"][index] = chosen
    return result


def index_peers(responses):
    """Index source relationships once; QA jobs need not rescan every artifact."""
    rows = {row["review_id"]:row for response in responses for row in response["results"]}
    paths, by_path = {}, {}
    for identity, row in rows.items():
        paths[identity] = {a["location"]["path"] for a in (row.get("investigation") or {}).get("decisive_artifacts", [])}
        for path in paths[identity]:
            by_path.setdefault(path, set()).add(identity)
    return rows, paths, by_path


def peer_context(index, assigned, limit):
    """Bound cross-bundle navigation by shared source files, not a run transcript."""
    rows, paths, by_path = index
    wanted = set().union(*(paths[identity] for identity in assigned))
    peers = sorted(set().union(*(by_path[path] for path in wanted)) - assigned)
    return {"related_reviews": [{"review_id":identity, "decision":rows[identity]["decision"],
        "summary":rows[identity]["summary"], "paths":sorted(paths[identity]), "diagnosis":rows[identity].get("diagnosis")}
        for identity in peers[:limit]], "omitted_related_reviews":max(0, len(peers) - limit),
        "scope":"Navigation only; each peer has its own QA job. No global completeness claim."}
