"""Source-bound, priority-ranked obligations and explicit review completion goals."""

from collections import Counter
import copy
import json

import review_domains as domains

VERSION = "mehscanWorkPlan/v1"
IMPACTS = ("critical", "high", "unknown", "medium", "low")
EXPOSURES = ("unauthenticated", "authenticated", "unknown", "privileged", "deployment")
STRENGTHS = ("strong", "moderate", "weak", "unknown")
CHECK_STATES = ("satisfied", "violated", "unresolved", "not_checked")
FOCUS_FIELDS = ("assignment_id", "owner_path", "start_line", "end_line", "question",
                "protected_effect", "area", "reason", "next_deciding_fact", "signal")


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
                                      "readiness", "blocked_reason", "estimate", "shared_facts"}
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
            if not isinstance(check, dict) or set(check) != {"id", "question"}:
                raise ValueError("check requires id and question")
            check_id = domains._name(check["id"], "check")
            if check_id in check_ids:
                raise ValueError("duplicate check identifier")
            check_ids.add(check_id)
            text(check["question"], "check question")
        estimate = raw.get("estimate", {})
        if not isinstance(estimate, dict) or set(estimate) - {"calls", "input_tokens", "output_tokens"}:
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
        items.append(dict(id=item_id, assignment_id=raw["assignment_id"], focus=compact_focus,
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
    owner_paths = {item["focus"]["owner_path"] for item in items}
    source_scope = {"original_assignments": len(plan["assignments"]),
        "excluded_sources": [{key: row[key] for key in ("path", "reason", "review_ids", "source_sha256", "line_count") if key in row}
                             for row in plan.get("excluded_sources", [])],
        "owner_ranges": [{"item_id": item["id"], **{key: item["focus"][key] for key in
            ("owner_path", "start_line", "end_line")}} for item in items],
        "windows_without_named_owner": [{key: window[key] for key in ("path", "start_line", "end_line")}
            for assignment in plan["assignments"] for window in assignment["windows"] if window["path"] not in owner_paths],
        "basis": "Owner ranges locate declared checks, not line coverage. Neighboring source and queried helpers do not acquire reviewed status."}
    return dict(schema_version=VERSION, source_plan_id=plan["plan_id"], source_fingerprint=plan["source_fingerprint"],
        goal=goal, target_ids=target_ids if goal == "coverage" else [], items=items, domains=groups, cases=cases,
        lead_accounting=accounting, coverage_limits=limits, source_scope=source_scope,
        coverage_plan={"goal": goal, "target_ids": target_ids if goal == "coverage" else []})


def check_results(required, rows):
    """Validate closure claims before source-proof validation; no semantic verdict inference."""
    expected = {check["id"] for check in required}
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError("work result must answer every required check exactly once")
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"check_id", "status", "summary", "evidence", "next_deciding_fact"}
                or row["check_id"] not in expected or row["check_id"] in seen or row["status"] not in CHECK_STATES):
            raise ValueError("work check identity, state or fields differ from the plan")
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
                check_rows = result["draft"]["work_checks"]
                unresolved = any(row["status"] in ("unresolved", "not_checked") for row in check_rows)
                unresolved |= any(row["decision"] == "needs_review" for row in result["draft"]["results"])
                state = "investigated_unresolved" if unresolved else "closed"
                reason = "Evidence-backed check answers; source validation does not prove reasoning correct."
        outstanding = [row for row in check_rows if row["status"] in ("unresolved", "not_checked")]
        deciding = [row["next_deciding_fact"] for row in outstanding]
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
               "required": item["id"] in targets, "status": state, "reason": reason,
               "required_checks": item["checks"], "check_results": check_rows,
               "next_deciding_facts": deciding or ([item["focus"]["next_deciding_fact"]] if state != "closed" else []),
               "calls": result.get("calls", 0) if result else 0, "usage": usage,
               "job_directory": result.get("job_directory") if result else None,
               "usage_complete": bool(result and result["status"] == "complete" and len(usage_rows) == result.get("calls", 0))})
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
        summary=dict(items=len(rows), closed=sum(row["status"] == "closed" for row in rows),
            required=len(required), required_closed=sum(row["status"] == "closed" for row in required),
            remaining_by_potential_impact=dict(residual),
            unclassified_native_ids=[rid for rid, row in registry["lead_accounting"].items() if row["role"] == "unclassified"]),
        coverage_limits=registry["coverage_limits"], source_scope=registry["source_scope"], items=rows, budget=budget,
        remaining_estimate=estimates(remaining), target_remaining_estimate=estimates(required_remaining),
        additional_source_proposals=additional,
        authority="Potential impact is a host scheduling judgment, not a finding severity. Unclassified work has unknown importance. Completion applies only to declared checks, not whole-app safety.")


def markdown(report):
    lines = ["# Review work and remaining obligations", "", report["authority"], "",
             "Goal: " + report["goal"] + "; target status: " + report["target_status"] + ".", "",
             "| Item | Potential impact | State | Remaining deciding fact |", "| --- | --- | --- | --- |"]
    clean = lambda value: str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    for row in report["items"]:
        lines.append("| " + " | ".join(clean(value) for value in (row["id"], row["priority"]["impact"], row["status"],
            "; ".join(row["next_deciding_facts"]))) + " |")
    unknown = len(report["summary"]["unclassified_native_ids"])
    lines += ["", str(unknown) + " native IDs remain unclassified; their importance is unknown.", ""]
    lines += [str(len(report["source_scope"]["windows_without_named_owner"]))
              + " original source windows have no named owner in this plan. " + report["source_scope"]["basis"], ""]
    lines += [str(len(report["source_scope"]["excluded_sources"]))
              + " source entries have policy exclusions recorded separately; exclusions are not safety verdicts.", ""]
    lines += ["Remaining planned work by potential impact: " + json.dumps(report["summary"]["remaining_by_potential_impact"]), ""]
    estimate = report["target_remaining_estimate"] if report["goal"] == "coverage" else report["remaining_estimate"]
    lines += ["Known-estimate subtotal of remaining calls: " + str(estimate["calls"]["range"]) + "; "
              + str(len(estimate["calls"]["unknown_items"])) + " items lack call estimates.", ""]
    cost = (report.get("budget") or {}).get("cost")
    if cost:
        lines += ["Managed estimated spend: $" + format(cost["observed_micros"] / 1_000_000, ".6f")
                  + " of $" + format(cost["limit_micros"] / 1_000_000, ".6f") + ". " + cost["basis"], ""]
    if "configured_rate_usd" in estimate:
        lines += ["Remaining configured-rate estimate: " + str(estimate["configured_rate_usd"]) + " USD; host estimates, not guaranteed charges.", ""]
    if report["additional_source_proposals"]:
        lines += ["Additional source proposals (do not expand the fixed target):", ""]
        lines.extend("- " + clean(row["question"]) + " — " + row["decision"]
                     for row in report["additional_source_proposals"])
    lines.extend("- " + clean(value) for value in report["coverage_limits"])
    return "\n".join(lines) + "\n"
