"""Source-bound, priority-ranked obligations and explicit review completion goals."""

from collections import Counter
import copy
import json
from pathlib import Path

import review_domains as domains
import review_questions
import review_fact_audit

HANDOFF_VERSION = "mehscanWorkHandoff/v1"


def audit_case_gaps(registry, rows):
    """Only required native obligations can reopen a fixed case target."""
    owners = {rid:item["id"] for item in registry["items"] for rid in item["verify_review_ids"]}
    return [{"case_id":owners[row["review_id"]], "review_id":row["review_id"], "outcome":row["outcome"]}
            for row in rows if row["outcome"] in ("corrected", "reopened") and row["review_id"] in owners]


def _handoff_budget_policy(budget):
    keys = ("max_calls", "input_limit", "reservation_per_call", "max_call_input_tokens", "deadline_epoch")
    cost_keys = ("currency", "limit_micros", "rates", "provider_rates", "output_reservation", "reservation_micros")
    cost = budget.get("cost")
    return {**{key:budget[key] for key in keys},
            "cost":{key:cost[key] for key in cost_keys if key in cost} if cost else None}


def freeze_handoff(stage, manifest_sha256, case_binding, worker):
    """Bind first-pass artifacts and immutable budget policy, never reset usage."""
    directory = Path(stage)
    files = ("summary.json", "work-plan.json", "case-state.sqlite", "work.json", "provider-metrics.jsonl")
    budget_path = Path(worker.read(directory / "summary.json")["budget_path"])
    budget = worker.read(budget_path)
    record = {"schema_version":HANDOFF_VERSION, "manifest_sha256":manifest_sha256,
        "case_binding":case_binding, "budget_path":str(budget_path),
        "files":{name:worker.digest_file(directory / name) for name in files},
        "budget_policy":_handoff_budget_policy(budget),
        "usage_floor":{"reserved_calls":budget["reserved_calls"], "observed_input_tokens":budget["observed_input_tokens"],
                      "cost_micros":budget.get("cost", {}).get("observed_micros", 0)},
        "fenced":budget["fenced"]}
    worker.write(directory / "work-handoff.json", record)
    return record


def read_handoff(attempt, root, worker):
    """Fail before inference on changed artifacts or a replacement allowance."""
    attempt = worker.outside(attempt, root)
    stage = attempt / "source-review"
    record = worker.read(stage / "work-handoff.json")
    expected = {"summary.json", "work-plan.json", "case-state.sqlite", "work.json", "provider-metrics.jsonl"}
    if record.get("schema_version") != HANDOFF_VERSION or set(record.get("files", {})) != expected:
        raise ValueError("unsupported work-plan handoff")
    for name, digest in record["files"].items():
        path = stage / name
        if path.is_symlink() or worker.digest_file(path) != digest:
            raise ValueError("work-plan handoff artifact changed: " + name)
    budget_path = Path(record.get("budget_path", stage / "budget.json"))
    if budget_path.is_symlink():
        raise ValueError("work-plan allowance cannot be redirected")
    budget_path = worker.outside(budget_path, root)
    budget = worker.read(budget_path)
    if _handoff_budget_policy(budget) != record["budget_policy"]:
        raise ValueError("work-plan continuation allowance changed")
    floor = record["usage_floor"]
    if (budget["reserved_calls"] < floor["reserved_calls"] or budget["observed_input_tokens"] < floor["observed_input_tokens"]
            or budget.get("cost", {}).get("observed_micros", 0) < floor["cost_micros"]
            or record["fenced"] and not budget["fenced"]):
        raise ValueError("work-plan continuation cannot reset prior usage or fences")
    summary = worker.read(stage / "summary.json")
    if Path(summary["budget_path"]).resolve() != budget_path.resolve():
        raise ValueError("work-plan handoff budget binding differs")
    return record, summary, str(budget_path)

VERSION = "mehscanWorkPlan/v1"
IMPACTS = ("critical", "high", "unknown", "medium", "low")
EXPOSURES = ("unauthenticated", "authenticated", "unknown", "privileged", "deployment")
STRENGTHS = ("strong", "moderate", "weak", "unknown")
CHECK_STATES = ("satisfied", "violated", "unresolved", "not_checked")
FOCUS_FIELDS = ("assignment_id", "owner_path", "start_line", "end_line", "question",
                "protected_effect", "area", "reason", "next_deciding_fact", "signal")


def freeze_resolution_handoff(stage, parent, worker, case_binding):
    stage, parent = Path(stage), Path(parent)
    inherited = parent / "source-review/resolution-handoff.json"
    native_parent = worker.read(stage / "resolution-plan.json").get("native_parent") or (worker.read(inherited)["native_parent"] if inherited.is_file() else str(parent))
    if not (Path(native_parent) / "source-review/work-handoff.json").is_file():
        return None  # Source interruption before native publication has no admitted baseline.
    files = ("case-state.sqlite", "work-ledger.json", "work-plan.json", "resolution-plan.json", "resolution-results.json", "provider-metrics.jsonl")
    record = {"schema_version":"mehscanResolutionHandoff/v1", "native_parent":native_parent, "case_binding":case_binding,
        "files":{name:worker.digest_file(stage / name) for name in files},
        "native_handoff_sha256":worker.digest_file(Path(native_parent) / "source-review/work-handoff.json")}
    worker.write(stage / "resolution-handoff.json", record)
    return record


def read_resolution_handoff(attempt, root, worker):
    attempt = worker.outside(attempt, root)
    stage = attempt / "source-review"
    record = worker.read(stage / "resolution-handoff.json")
    expected = {"case-state.sqlite", "work-ledger.json", "work-plan.json", "resolution-plan.json", "resolution-results.json", "provider-metrics.jsonl"}
    if record.get("schema_version") != "mehscanResolutionHandoff/v1" or set(record.get("files", {})) != expected:
        raise ValueError("invalid scoped correction handoff")
    for name, digest in record["files"].items():
        path = stage / name
        if path.is_symlink() or worker.digest_file(path) != digest:
            raise ValueError("scoped correction artifact changed")
    native_parent = worker.outside(record["native_parent"], root)
    if worker.digest_file(native_parent / "source-review/work-handoff.json") != record["native_handoff_sha256"]:
        raise ValueError("native correction baseline changed")
    _, source, budget_path = read_handoff(native_parent, root, worker)
    ledger = worker.read(stage / "work-ledger.json")
    if ledger["source_fingerprint"] != source["source_fingerprint"]:
        raise ValueError("correction source differs from native baseline")
    if _handoff_budget_policy(worker.read(budget_path)) != _handoff_budget_policy(ledger["budget"]):
        raise ValueError("correction allowance differs from native baseline")
    current = worker.read(budget_path)
    old = ledger["budget"]
    if (current["reserved_calls"] < old["reserved_calls"] or current["observed_input_tokens"] < old["observed_input_tokens"]
            or current.get("cost", {}).get("observed_micros", 0) < old.get("cost", {}).get("observed_micros", 0)
            or old["fenced"] and not current["fenced"]):
        raise ValueError("correction usage cannot be reset")
    return record, ledger, native_parent


def reconciled_resolution(attempt, handoff, audit, native_rows, budget, worker):
    """Project admitted native reconciliation alongside immutable source checks."""
    from review_case_state import CaseState
    stage = Path(attempt) / "source-review"
    state = CaseState(stage / "case-state.sqlite", handoff["case_binding"])
    results = state.results()
    admitted = {r["review_id"]:r for r in native_rows}
    settled = {r["review_id"] for r in audit["results"] if r["outcome"] in ("confirmed", "corrected")
        and r.get("proof_status") == "supported" and r.get("investigation_status") == "sufficient"
        and r["review_id"] in admitted and admitted[r["review_id"]]["decision"] != "needs_review"}
    for result in results:
        for rid in list(result.get("native_reconsideration", {})):
            if rid in settled:
                result["native_reconsideration"].pop(rid)
        if result.get("status") == "complete":
            result["draft"]["results"] = [copy.deepcopy(admitted.get(r["review_id"], r)) for r in result["draft"]["results"]]
    metrics = [json.loads(line) for line in (stage / "provider-metrics.jsonl").read_text(encoding="utf8").splitlines() if line.strip()]
    report = ledger(worker.read(stage / "work-plan.json"), results, budget=budget, metrics=metrics)
    report["native_reconciliation"] = {"settled_ids":sorted(settled), "outcomes":copy.deepcopy(audit["results"]),
        "authority":"Projection of source checks and admitted native reconciliation; parent artifacts remain historical."}
    return report


def text(value, label, maximum=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(label + " must be bounded nonempty text")
    return value


def priority(item):
    risk = item["priority"]
    return (IMPACTS.index(risk["impact"]), EXPOSURES.index(risk["exposure"]),
            STRENGTHS.index(risk["evidence"]), item.get("estimate", {}).get("calls", [0, 100_000_001])[1], item["ordinal"])


def validate(manifest, plan, native_ids, *, validate_selection, goal="budget", targets=None):
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != VERSION
            or manifest.get("source_plan_id") != plan["plan_id"]
            or manifest.get("source_fingerprint") != plan["source_fingerprint"]
            or set(manifest) - {"schema_version", "source_plan_id", "source_fingerprint", "items", "coverage_limits"}):
        raise ValueError("work plan differs from its source binding or schema")
    if len(json.dumps(manifest).encode("utf8")) > 4 * 1024 * 1024:
        raise ValueError("work plan exceeds four MiB")
    if goal not in ("budget", "coverage"):
        raise ValueError("unknown review goal")
    supplied = manifest.get("items")
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= 2000:
        raise ValueError("work plan requires one to 2000 grouped items")
    limits = manifest.get("coverage_limits", [])
    if not isinstance(limits, list) or len(limits) > 100:
        raise ValueError("coverage limits require a bounded list")
    limits = [text(value, "coverage limit") for value in limits]
    native_ids = list(native_ids)
    native_set = set(native_ids)
    if len(native_set) != len(native_ids):
        raise ValueError("duplicate native membership")
    assignments = {row["id"]: row for row in plan["assignments"]}
    items, seen, classified = [], set(), set()
    accounting = {rid: {"role": "unclassified", "status": "deferred", "reviewed": False,
                        "assessment_required": False, "item_id": None,
                        "case_id": None, "domain_id": None,
                        "reason": "Not classified by the work plan; importance remains unknown."} for rid in native_ids}
    for ordinal, raw in enumerate(supplied):
        allowed = set(FOCUS_FIELDS) | {"id", "priority", "actor", "conditions", "checks", "review_roles",
                                      "readiness", "blocked_reason", "estimate", "shared_facts", "case_kind"}
        if not isinstance(raw, dict) or set(raw) - allowed:
            raise ValueError("work item has unsupported fields")
        item_id = domains._name(raw.get("id"), "work item")
        if item_id in seen:
            raise ValueError("duplicate work item identifier")
        seen.add(item_id)
        source_case = {key: raw.get(key) for key in FOCUS_FIELDS}
        _, focus = validate_selection({"source_plan_id": plan["plan_id"],
            "source_fingerprint": plan["source_fingerprint"], "assignment_ids": [raw.get("assignment_id")],
            "assignments": [source_case]}, plan)
        risk = raw.get("priority")
        if (not isinstance(risk, dict) or set(risk) != {"impact", "exposure", "evidence", "basis"}
                or risk["impact"] not in IMPACTS or risk["exposure"] not in EXPOSURES
                or risk["evidence"] not in STRENGTHS):
            raise ValueError("priority requires potential impact, exposure, evidence strength and basis")
        text(risk["basis"], "priority basis")
        actor = text(raw.get("actor"), "actor")
        conditions = text(raw.get("conditions"), "conditions")
        readiness = raw.get("readiness", "ready")
        if readiness not in ("ready", "blocked", "deferred"):
            raise ValueError("unknown work readiness")
        blocked = raw.get("blocked_reason")
        if readiness != "ready":
            text(blocked, "blocked/deferred reason")
        checks = raw.get("checks")
        if not isinstance(checks, list) or not 1 <= len(checks) <= 16:
            raise ValueError("each item requires one to sixteen named checks")
        check_ids = set()
        for check in checks:
            if not isinstance(check, dict) or not {"id", "question"} <= set(check):
                raise ValueError("check requires id and question")
            check_id = domains._name(check["id"], "check")
            if check_id in check_ids:
                raise ValueError("duplicate check identifier")
            check_ids.add(check_id)
            text(check["question"], "check question")
            review_questions.validate_check(check)
        kind = raw.get("case_kind")
        if kind is not None and kind not in ("security", "factual"):
            raise ValueError("case_kind must be security or factual")
        if kind == "security" and not any(review_questions.validate_check(c) == "security_decision" for c in checks):
            raise ValueError("security cases require an explicit owner security check")
        estimate = raw.get("estimate", {})
        if not isinstance(estimate, dict) or set(estimate) - {"calls", "owner_calls", "input_tokens", "output_tokens"}:
            raise ValueError("unknown effort estimate")
        for key, bounds in estimate.items():
            if (not isinstance(bounds, list) or len(bounds) != 2 or any(type(n) is not int for n in bounds)
                    or not 0 <= bounds[0] <= bounds[1] <= 100_000_000):
                raise ValueError("effort estimates require ordered nonnegative integer bounds")
        local = assignments[raw["assignment_id"]]["review_ids"]
        roles = raw.get("review_roles", {})
        if not isinstance(roles, dict) or set(roles) - set(domains.ROLES):
            raise ValueError("unknown evidence role")
        normalized_roles = {}
        for role in domains.ROLES:
            members = roles.get(role, [])
            if (not isinstance(members, list) or any(not isinstance(rid, str) for rid in members)
                    or len(members) != len(set(members)) or not set(members) <= native_set.intersection(local)
                    or classified.intersection(members)):
                raise ValueError("native IDs require one item/role in their source assignment")
            classified.update(members)
            normalized_roles[role] = [rid for rid in local if rid in members]
            for rid in members:
                accounting[rid] = {"role": role, "status": "planned", "reviewed": False,
                    "assessment_required": role == "verify", "item_id": item_id,
                    "case_id": item_id, "domain_id": item_id, "reason": raw["reason"]}
        if kind == "factual" and (normalized_roles["verify"] or not all(
                review_questions.route_check(c)["effective_route"] == "prepare" for c in checks)):
            raise ValueError("factual cases require eligible factual checks and no Verify IDs")
        kind = kind or ("factual" if not normalized_roles["verify"] and all(
            review_questions.route_check(c)["effective_route"] == "prepare" for c in checks) else "security")
        facts = raw.get("shared_facts", [])
        if not isinstance(facts, list) or len(facts) > domains.MAX_SHARED_FACTS:
            raise ValueError("shared evidence exceeds the citation allowance")
        # Keep the backlog text-free. Deliver deciding signal excerpts outside
        # the primary packet as cited evidence only when this item starts.
        primary = assignments[raw["assignment_id"]]["windows"]
        facts = [*facts, *[cite for cite in raw["signal"]["evidence"] if not any(
            window["path"] == cite["path"] and window["start_line"] <= cite["start_line"] <= cite["end_line"] <= window["end_line"]
            for window in primary)]]
        metadata = {}
        for cite in facts:
            checked = domains._shared_fact(cite, plan)
            metadata[(checked["path"], checked["start_line"], checked["end_line"])] = {
                key: value for key, value in checked.items() if key != "quote"}
        compact_focus = focus[raw["assignment_id"]]
        for cite in compact_focus["signal"]["evidence"]:
            cite.pop("quote", None)
        items.append(dict(id=item_id, case_kind=kind, case_kind_basis="explicit" if "case_kind" in raw else "legacy_inference", assignment_id=raw["assignment_id"], focus=compact_focus,
            priority=copy.deepcopy(risk), actor=actor, conditions=conditions, checks=copy.deepcopy(checks),
            review_roles=normalized_roles, verify_review_ids=normalized_roles["verify"],
            readiness=readiness, blocked_reason=blocked, estimate=copy.deepcopy(estimate), ordinal=ordinal,
            shared_facts=list(metadata.values())))
    target_ids = list(targets) if targets is not None else [item["id"] for item in items]
    if (not target_ids or any(not isinstance(value, str) for value in target_ids)
            or len(target_ids) != len(set(target_ids)) or not set(target_ids) <= seen
            or (goal != "coverage" and targets is not None)):
        raise ValueError("coverage target must select distinct existing work items in coverage mode")
    target_set = set(target_ids)
    funded = sorted([item for item in items if item["readiness"] == "ready"
                     and (goal == "budget" or item["id"] in target_set)], key=priority)
    cases, groups = [], []
    for item in funded:
        case = {**item, "domain_id": item["id"], "work_item": True}
        cases.append(case)
        groups.append({"id": item["id"], "title": item["focus"]["question"],
                       "shared_facts": item["shared_facts"], "cases": [case]})
    funded_set = {item["id"] for item in funded}
    item_map = {item["id"]: item for item in items}
    for row in accounting.values():
        if row["item_id"] is not None and row["item_id"] not in funded_set:
            item = item_map[row["item_id"]]
            row["status"] = "outside_target" if goal == "coverage" and item["id"] not in target_set else item["readiness"]
    unnamed = []
    for assignment in plan["assignments"]:
        for window in assignment["windows"]:
            intervals = [(window["start_line"], window["end_line"])]
            for item in items:
                focus = item["focus"]
                if focus["owner_path"] != window["path"]:
                    continue
                start, end = focus["start_line"], focus["end_line"]
                intervals = [(a, b) for left, right in intervals for a, b in
                    ((left, min(right, start - 1)), (max(left, end + 1), right)) if a <= b]
            unnamed.extend(dict(path=window["path"], start_line=a, end_line=b) for a, b in intervals)
    source_scope = {"original_assignments": len(plan["assignments"]),
        "excluded_sources": [{key: row[key] for key in ("path", "reason", "review_ids", "source_sha256", "line_count") if key in row}
                             for row in plan.get("excluded_sources", [])],
        "owner_ranges": [{"item_id": item["id"], **{key: item["focus"][key] for key in
            ("owner_path", "start_line", "end_line")}} for item in items],
        "windows_without_named_owner": unnamed,
        "basis": "Owner ranges locate declared checks, not line coverage. Neighboring source and queried helpers do not acquire reviewed status."}
    return dict(schema_version=VERSION, source_plan_id=plan["plan_id"], source_fingerprint=plan["source_fingerprint"],
        goal=goal, target_ids=target_ids if goal == "coverage" else [], items=items, domains=groups, cases=cases,
        lead_accounting=accounting, coverage_limits=limits, source_scope=source_scope,
        coverage_plan={"goal": goal, "target_ids": target_ids if goal == "coverage" else []})


def check_results(required, rows, available_assertions=None, considered_assertions=None):
    """Validate closure claims before source-proof validation; no semantic verdict inference."""
    expected = {check["id"] for check in required}
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError("work result must answer every required check exactly once")
    seen = set()
    for row in rows:
        fields = {"check_id", "status", "summary", "evidence", "next_deciding_fact"}
        if (not isinstance(row, dict) or not fields <= set(row) or set(row) - fields - {"assertion_dependencies", "assertion_dispositions", "conditions", "limitations"}
                or row["check_id"] not in expected or row["check_id"] in seen or row["status"] not in CHECK_STATES):
            raise ValueError("work check identity, state or fields differ from the plan")
        for name in ("conditions", "limitations"):
            if name in row and (not isinstance(row[name], list) or len(row[name]) > 16):
                raise ValueError("check conditions and limitations require bounded lists")
            for value in row.get(name, []):
                text(value, name, 1000)
        dependencies = row.get("assertion_dependencies", [])
        if (available_assertions is not None and "assertion_dependencies" not in row
                or not isinstance(dependencies, list)):
            raise ValueError("owner checks must declare their assertion dependencies")
        offered = {(dep["assertion_id"], dep["version"]) for dep in (available_assertions or [])}
        seen_dependencies = set()
        for dep in dependencies:
            if (not isinstance(dep, dict) or set(dep) != {"assertion_id", "version"}
                    or not isinstance(dep["assertion_id"], str) or type(dep["version"]) is not int
                    or (dep["assertion_id"], dep["version"]) not in offered
                    or dep["assertion_id"] in seen_dependencies):
                raise ValueError("assertion dependency is foreign, duplicate or stale")
            seen_dependencies.add(dep["assertion_id"])
        if considered_assertions is not None and "assertion_dispositions" not in row:
            raise ValueError("owner must declare assertion dispositions")
        validate_dispositions(row, considered_assertions if considered_assertions is not None else available_assertions)
        seen.add(row["check_id"])
        text(row["summary"], "check conclusion")
        evidence = row["evidence"]
        if not isinstance(evidence, list) or len(evidence) > 8:
            raise ValueError("work check evidence must be bounded")
        if row["status"] in ("satisfied", "violated"):
            if not evidence or row["next_deciding_fact"] is not None:
                raise ValueError("closed check requires evidence and no unresolved fact")
        else:
            text(row["next_deciding_fact"], "unresolved deciding fact")


def validate_dispositions(row, offered=None):
    """Validate declared reliance without claiming to detect model influence."""
    dispositions = row.get("assertion_dispositions", [])
    if not isinstance(dispositions, list) or len(dispositions) > 16:
        raise ValueError("assertion dispositions require a bounded list")
    available = {(d["assertion_id"], d["version"]) for d in (offered or [])}
    dependencies = {(d["assertion_id"], d["version"]) for d in row.get("assertion_dependencies", [])}
    seen = set()
    for value in dispositions:
        if (not isinstance(value, dict) or set(value) != {"assertion_id", "version", "disposition", "reason", "conditions"}
                or not isinstance(value["assertion_id"], str) or type(value["version"]) is not int
                or value["version"] < 1 or value["disposition"] not in ("used", "qualified", "rejected")):
            raise ValueError("invalid assertion disposition")
        ref = (value["assertion_id"], value["version"])
        if ref in seen or offered is not None and ref not in available:
            raise ValueError("foreign or duplicate assertion disposition")
        seen.add(ref)
        text(value["reason"], "assertion disposition reason", 1000)
        conditions = value["conditions"]
        if not isinstance(conditions, list) or len(conditions) > 16:
            raise ValueError("assertion disposition requires bounded conditions")
        for condition in conditions:
            text(condition, "assertion condition", 1000)
        if value["disposition"] == "qualified" and not conditions:
            raise ValueError("qualified assertion requires its applicable conditions")
        if (value["disposition"] != "rejected") != (ref in dependencies):
            raise ValueError("assertion disposition conflicts with declared reliance")
    if "assertion_dispositions" in row and not dependencies <= seen:
        raise ValueError("every consumed assertion requires a disposition")


def ledger(registry, results=(), *, budget=None, metrics=()):
    results = list(results)
    by_case = {row["case_id"]: row for row in results if "case_id" in row}
    rows = []
    targets = set(registry["target_ids"])
    for item in sorted(registry["items"], key=priority):
        result = by_case.get(item["id"])
        check_rows = []
        state = item["readiness"] if item["readiness"] != "ready" else "unstarted"
        reason = item.get("blocked_reason") or "Not started; no reviewed conclusion."
        if registry["goal"] == "coverage" and item["id"] not in targets:
            state, reason = "outside_target", "Outside the fixed coverage target; not reviewed."
        if result:
            state, reason = result["status"], result.get("detail")
            if state == "complete":
                check_rows = copy.deepcopy(result["draft"]["work_checks"])
                for check in check_rows:
                    reason = result.get("reconsideration", {}).get(check["check_id"])
                    if reason:
                        check.update(status="not_checked", next_deciding_fact=reason)
                unresolved = any(row["status"] in ("unresolved", "not_checked") for row in check_rows)
                unresolved |= any(row["decision"] == "needs_review" for row in result["draft"]["results"])
                unresolved |= bool(result.get("native_reconsideration"))
                state = "investigated_unresolved" if unresolved else "closed"
                reason = "Evidence-backed check answers; source validation does not prove reasoning correct."
        outstanding = [row for row in check_rows if row["status"] in ("unresolved", "not_checked")]
        deciding = [row["next_deciding_fact"] for row in outstanding]
        if result:
            deciding.extend(result.get("native_reconsideration", {}).values())
        if result and result["status"] == "complete":
            deciding.extend(question for assessment in result["draft"]["results"] if assessment["decision"] == "needs_review"
                            for question in assessment.get("checks", []))
        deciding = list(dict.fromkeys(deciding))
        usage_rows = [row for row in metrics if row.get("work_item_id") == item["id"]]
        usage = {key: sum(row.get("usage", {}).get(key, 0) or 0 for row in usage_rows)
                 for key in ("input_tokens", "cached_input_tokens", "output_tokens")}
        rows.append({key: item[key] for key in ("id", "assignment_id", "priority", "actor", "conditions", "estimate")}
            | {"owner_path": item["focus"]["owner_path"], "question": item["focus"]["question"],
               "protected_effect": item["focus"]["protected_effect"], "review_roles": item["review_roles"],
               "case_kind": item.get("case_kind", "factual" if review_questions.fact_only(item) else "security"),
               "required": item["id"] in targets, "status": state, "reason": reason,
               "required_checks": item["checks"], "check_results": check_rows,
               "next_deciding_facts": deciding or ([item["focus"]["next_deciding_fact"]] if state != "closed" else []),
               "calls": result.get("calls", 0) if result else 0, "usage": usage,
               "partial_fact_checks": copy.deepcopy(result.get("partial_fact_checks", [])) if result else [],
               "question_work": copy.deepcopy(result.get("question_work", [])) if result else [],
               "factual_audits":review_fact_audit.with_usage(result.get("factual_audits", []), usage_rows, budget) if result else [],
               "routing": copy.deepcopy(result.get("routing", [])) if result else [],
               "completion_reservation": copy.deepcopy(result.get("completion_reservation")) if result else None,
               "provisional_fact_answers": copy.deepcopy(result.get("provisional_fact_answers", {})) if result else {},
               "reconsideration": copy.deepcopy(result.get("reconsideration", {})) if result else {},
               "native_reconsideration": copy.deepcopy(result.get("native_reconsideration", {})) if result else {},
               "job_directory": result.get("job_directory") if result else None,
               "usage_complete": bool(result and result["status"] == "complete" and len(usage_rows) == result.get("calls", 0)
                   and all(not set(metric.get("unknown_delta_counters", [])).intersection(
                       ("input_tokens", "cached_input_tokens", "output_tokens")) and all(
                       type(metric.get("usage", {}).get(key)) is int for key in
                       ("input_tokens", "cached_input_tokens", "output_tokens")) for metric in usage_rows))})
    required = [row for row in rows if row["required"]]
    complete = bool(required) and all(row["status"] == "closed" for row in required)
    residual = Counter(row["priority"]["impact"] for row in rows if row["status"] != "closed")
    remaining = [row for row in rows if row["status"] != "closed"]
    required_remaining = [row for row in remaining if row["required"]]

    def estimates(items):
        totals = {}
        for key in ("calls", "input_tokens", "output_tokens"):
            used = lambda row: row["calls"] if key == "calls" else row["usage"][key]
            missing = [row["id"] for row in items if key not in row["estimate"] or row["estimate"][key][1] <= used(row)]
            totals[key] = {"range": [sum(max(0, row["estimate"][key][i] - used(row)) for row in items
                if row["id"] not in missing) for i in (0, 1)], "unknown_items": missing,
                "complete": not missing,
                "basis": "Known-estimate subtotal minus observed work; missing items are additional unknown work. Not an enforced bound or completion guarantee."}
        cost = (budget or {}).get("cost")
        if cost and not totals["input_tokens"]["unknown_items"] and not totals["output_tokens"]["unknown_items"]:
            from decimal import Decimal
            rates = cost["rates"]
            input_rates = [Decimal(rates[key]) for key in ("input_per_million", "cached_input_per_million")]
            bounds = []
            for index, input_rate in enumerate((min(input_rates), max(input_rates))):
                amount = (Decimal(totals["input_tokens"]["range"][index]) * input_rate
                    + Decimal(totals["output_tokens"]["range"][index]) * Decimal(rates["output_per_million"])) / 1_000_000
                bounds.append(float(amount))
            totals["configured_rate_usd"] = bounds
        return totals

    additional = [{"item_id": result["case_id"], "key": proposal["key"], "question": proposal["question"],
        "anchor": proposal["anchor"], "decision": proposal["assessment"]["decision"],
        "severity": (proposal["assessment"].get("diagnosis") or {}).get("severity"),
        "remaining_checks": proposal["assessment"].get("checks", []), "required": False}
        for result in results if result.get("status") == "complete"
        for proposal in result.get("draft", {}).get("proposals", [])]
    return dict(schema_version="mehscanWorkLedger/v1", source_plan_id=registry["source_plan_id"],
        source_fingerprint=registry["source_fingerprint"], goal=registry["goal"], target_ids=registry["target_ids"],
        target_complete=complete if registry["goal"] == "coverage" else None,
        target_status=("complete" if complete else "incomplete") if registry["goal"] == "coverage" else "budgeted_review",
        summary=dict(by_case_kind={kind: dict(items=sum(r["case_kind"] == kind for r in rows),
                closed=sum(r["case_kind"] == kind and r["status"] == "closed" for r in rows))
                for kind in ("security", "factual")}, items=len(rows), closed=sum(row["status"] == "closed" for row in rows),
            remaining=len(remaining), by_status=dict(Counter(row["status"] for row in rows)),
            checks_total=sum(len(row["required_checks"]) for row in rows),
            checks_closed=sum(check["status"] in ("satisfied", "violated") for row in rows for check in row["check_results"]),
            routing=dict(declared_fact_checks=sum(check.get("route") == "source_fact" for row in rows for check in row["required_checks"]),
                effective_routes=dict(Counter(decision["effective_route"] for row in rows for decision in row["routing"])),
                declared_owner_checks=sum(check.get("route", "security_decision") == "security_decision" for row in rows for check in row["required_checks"]),
                question_worker_calls=sum(q["calls"] for row in rows for q in row["question_work"]),
                skipped_question_checks=sum(q["status"] == "skipped" for row in rows for q in row["question_work"]),
                owner_calls=sum(max(0, row["calls"] - sum(q["calls"] for q in row["question_work"])
                    - sum(audit["calls"] for audit in row["factual_audits"])) for row in rows),
                factual_audit_calls=sum(audit["calls"] for row in rows for audit in row["factual_audits"]),
                factual_audit_outcomes=dict(Counter(audit["outcome"] for row in rows for audit in row["factual_audits"])),
                provisional_answers=sum(q["status"] == "complete" for row in rows for q in row["question_work"])),
            required=len(required), required_closed=sum(row["status"] == "closed" for row in required),
            remaining_by_potential_impact=dict(residual),
            unclassified_native_ids=[rid for rid, row in registry["lead_accounting"].items() if row["role"] == "unclassified"]),
        coverage_limits=registry["coverage_limits"], source_scope=registry["source_scope"], items=rows, budget=budget,
        remaining_estimate=estimates(remaining), target_remaining_estimate=estimates(required_remaining),
        additional_source_proposals=additional,
        factual_audit_selection=copy.deepcopy(registry.get("factual_audit_plan")),
        authority="Potential impact is a host scheduling judgment, not a finding severity. Unclassified work has unknown importance. Completion applies only to declared checks, not whole-app safety.")


def markdown(report):
    lines = ["# Review work and remaining obligations", "", report["authority"], "",
             "Items: " + str(report["summary"]["closed"]) + " completed / " + str(report["summary"]["items"])
             + " declared; " + str(report["summary"]["remaining"]) + " remaining.", "",
             "Checks: " + str(report["summary"]["checks_closed"]) + " closed / "
             + str(report["summary"]["checks_total"]) + " declared. Completion can include a finding.", "",
             "Goal: " + report["goal"] + "; target status: " + report["target_status"] + ".", "",
             "| Item | Potential impact | State | Remaining deciding fact |", "| --- | --- | --- | --- |"]
    clean = lambda value: str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    for row in report["items"]:
        lines.append("| " + " | ".join(clean(value) for value in (row["id"], row["priority"]["impact"], row["status"],
            "; ".join(row["next_deciding_facts"]))) + " |")
    for kind, totals in report["summary"].get("by_case_kind", {}).items():
        lines += ["", kind.capitalize() + " items: " + str(totals["closed"]) + " settled / " + str(totals["items"]) + " declared."]
    unknown = len(report["summary"]["unclassified_native_ids"])
    lines += ["", str(unknown) + " native IDs remain unclassified; their importance is unknown.", ""]
    lines += [str(len(report["source_scope"]["windows_without_named_owner"]))
              + " source regions have no named checks in this plan. " + report["source_scope"]["basis"], ""]
    lines += [str(len(report["source_scope"]["excluded_sources"]))
              + " source entries have policy exclusions recorded separately; exclusions are not safety verdicts.", ""]
    lines += ["Remaining planned work by potential impact: " + json.dumps(report["summary"]["remaining_by_potential_impact"]), ""]
    estimate = report["target_remaining_estimate"] if report["goal"] == "coverage" else report["remaining_estimate"]
    lines += ["Known-estimate subtotal of remaining calls: " + str(estimate["calls"]["range"]) + "; "
              + str(len(estimate["calls"]["unknown_items"])) + " items lack call estimates.", ""]
    cost = (report.get("budget") or {}).get("cost")
    if cost:
        limit = ("; tracking only, no monetary cap" if cost["limit_micros"] is None else
                 " of $" + format(cost["limit_micros"] / 1_000_000, ".6f"))
        lines += ["Managed estimated spend: $" + format(cost["observed_micros"] / 1_000_000, ".6f")
                  + limit + ". " + cost["basis"], ""]
        if not cost["complete"]:
            lines += ["Cost counters are incomplete; the displayed estimate is a known subtotal.", ""]
    if "configured_rate_usd" in estimate:
        lines += ["Remaining configured-rate estimate: " + str(estimate["configured_rate_usd"]) + " USD; host estimates, not guaranteed charges.", ""]
    if report["additional_source_proposals"]:
        lines += ["Additional source proposals (do not expand the fixed target):", ""]
        lines.extend("- " + clean(row["question"]) + " — " + row["decision"]
                     for row in report["additional_source_proposals"])
    lines.extend("- " + clean(value) for value in report["coverage_limits"])
    if report.get("factual_audit_selection"):
        lines += ["", "Optional factual audits: " + str(report["summary"]["routing"]["factual_audit_calls"])
                  + " calls; outcomes: " + json.dumps(report["summary"]["routing"]["factual_audit_outcomes"])
                  + ". Selection or non-selection does not establish correctness or security coverage.", ""]
    return "\n".join(lines) + "\n"
