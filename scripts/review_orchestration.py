"""Bound review routing and shared reservations, independent of provider loops."""
import copy
import hashlib
import json
import threading
import time


ROUTING_REASONS = {"reasoning_gap", "control_applicability", "conflicting_evidence", "risky_dismissal",
                   "external_required", "human_required", "budget_exhausted"}


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
            chosen["checks"] = list(dict.fromkeys([*chosen.get("checks", []), question]))
            chosen["investigation"]["blockers"] = list(dict.fromkeys([
                *chosen["investigation"].get("blockers", []), question]))
        chosen["investigation"]["journal_summary"] = None
        result["results"][index] = chosen
    return result
