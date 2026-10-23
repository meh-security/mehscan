"""Bound review routing and shared reservations, independent of provider loops."""
import copy
import hashlib
import json
import threading
import time


ROUTING_REASONS = {"reasoning_gap", "control_applicability", "conflicting_evidence", "risky_dismissal",
                   "external_required", "human_required", "budget_exhausted"}
UNAVAILABLE = {"external_required", "human_required", "budget_exhausted"}


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


def needs_secondary(results, routing, policy, direct=False):
    reasons = {item["review_id"]: item["reason"] for item in routing}
    for result in results:
        decision, identity = result["decision"], result["review_id"]
        reason = reasons.get(identity)
        if decision == "issue":
            return True
        if reason in {"reasoning_gap", "control_applicability", "conflicting_evidence", "risky_dismissal"}:
            return True
        if decision == "not_issue" and (direct or sampled(identity, policy)):
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
        if first["decision"] != second["decision"] or first["review_id"] in unresolved:
            chosen.update(decision="needs_review", confidence="low", diagnosis=None,
                          summary="Independent review leaves a source question requiring adjudication.")
            question = ("Resolve the contrary assessments for this exact operation using their decisive source evidence."
                        if first["decision"] != second["decision"] else
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
    routed = {item["review_id"] for stage in stages for item in stage["routing"]}
    return sorted(identity for identity in left if identity not in reasons and (
        left[identity]["decision"] != right[identity]["decision"] or identity in routed))


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
