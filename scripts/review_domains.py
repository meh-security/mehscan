"""Source-bound cases and evidence roles for opt-in domain review."""

import json
import re


VERSION = "mehscanDomainPlan/v1"
ROLES = ("verify", "cover", "context")
MAX_DOMAINS = 8
MAX_CASES_PER_DOMAIN = 8
MAX_CASES = 32
MAX_SHARED_FACTS = 16
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_FACT_BYTES = 64 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
CASE_FIELDS = {"id", "assignment_id", "owner_path", "start_line", "end_line", "question",
               "protected_effect", "area", "reason", "next_deciding_fact", "signal", "review_roles"}


def _name(value, label):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError(label + " requires a bounded identifier")
    return value


def _shared_fact(cite, plan):
    if (not isinstance(cite, dict) or set(cite) != {"path", "start_line", "end_line"}
            or not isinstance(cite["path"], str) or not cite["path"]
            or type(cite["start_line"]) is not int or type(cite["end_line"]) is not int
            or not 1 <= cite["start_line"] <= cite["end_line"]
            or cite["end_line"] - cite["start_line"] >= 400):
        raise ValueError("shared facts require bounded original-source citation ranges")
    window = next((window for assignment in plan["assignments"] for window in assignment["windows"]
                   if window["path"] == cite["path"]
                   and window["start_line"] <= cite["start_line"] <= cite["end_line"] <= window["end_line"]), None)
    if window is None:
        raise ValueError("shared fact lies outside native source windows")
    source_hash = window.get("source_sha256")
    if not isinstance(source_hash, str) or not source_hash:
        raise ValueError("shared fact requires its native source hash")
    quote = "\n".join(window["text"].split("\n")[
        cite["start_line"] - window["start_line"]:cite["end_line"] - window["start_line"] + 1])
    if len(quote.encode("utf8")) > MAX_FACT_BYTES:
        raise ValueError("shared fact exceeds the source byte allowance")
    return {**cite, "source_sha256": source_hash, "quote": quote}


def validate(manifest, plan, native_ids, *, validate_selection):
    """Normalize a trusted plan without inferring safe verdicts or lead roles.

    The existing source-selection validator remains authoritative for case owner
    and signal citations. A case's reason is the explicit rationale for its role
    assignments. Unmentioned native IDs remain unclassified and deferred.
    """
    if (not isinstance(manifest, dict)
            or set(manifest) - {"schema_version", "source_plan_id", "source_fingerprint", "domains", "coverage_plan"}
            or manifest.get("schema_version", VERSION) != VERSION
            or manifest.get("source_plan_id") != plan["plan_id"]
            or manifest.get("source_fingerprint") != plan["source_fingerprint"]):
        raise ValueError("domain plan differs from the native source binding or schema")
    try:
        if len(json.dumps(manifest, ensure_ascii=False).encode("utf8")) > MAX_MANIFEST_BYTES:
            raise ValueError("domain plan exceeds one MiB")
    except (TypeError, UnicodeError) as error:
        raise ValueError("domain plan must contain JSON values") from error
    if "coverage_plan" in manifest and not isinstance(manifest["coverage_plan"], dict):
        raise ValueError("domain coverage plan must be an object")
    domains = manifest.get("domains")
    if not isinstance(domains, list) or not 1 <= len(domains) <= MAX_DOMAINS:
        raise ValueError("domain plan requires one to eight domains")
    if isinstance(native_ids, (str, bytes)):
        raise ValueError("native review IDs require a distinct identifier collection")
    try:
        native_ids = list(native_ids)
    except TypeError as error:
        raise ValueError("native review IDs require a distinct identifier collection") from error
    if (any(not isinstance(rid, str) or not rid for rid in native_ids)
            or len(native_ids) != len(set(native_ids))):
        raise ValueError("native review IDs require a distinct identifier collection")
    native_set = set(native_ids)
    assignments = {assignment["id"]: assignment for assignment in plan["assignments"]}
    accounting = {rid: {"role": "unclassified", "domain_id": None, "case_id": None,
                        "status": "deferred", "reviewed": False, "assessment_required": False,
                        "reason": "No evidence role or selected case supplied."} for rid in native_ids}
    seen_domains, seen_cases, seen_assignments, classified = set(), set(), set(), set()
    normalized_domains, cases = [], []
    for domain in domains:
        if not isinstance(domain, dict) or set(domain) - {"id", "title", "shared_facts", "cases"}:
            raise ValueError("domain requires an identifier, title and case queue")
        domain_id = _name(domain.get("id"), "domain")
        if domain_id in seen_domains:
            raise ValueError("domain identifiers must be unique")
        seen_domains.add(domain_id)
        title = domain.get("title")
        if not isinstance(title, str) or not title.strip() or len(title) > 1000:
            raise ValueError("domain title must be bounded and nonempty")
        supplied_facts = domain.get("shared_facts", [])
        if not isinstance(supplied_facts, list) or len(supplied_facts) > MAX_SHARED_FACTS:
            raise ValueError("domain shared facts exceed the citation allowance")
        shared_facts = [_shared_fact(cite, plan) for cite in supplied_facts]
        fact_ranges = [(cite["path"], cite["start_line"], cite["end_line"]) for cite in shared_facts]
        if len(fact_ranges) != len(set(fact_ranges)):
            raise ValueError("domain shared fact ranges must be unique")
        queue = domain.get("cases")
        if not isinstance(queue, list) or not 1 <= len(queue) <= MAX_CASES_PER_DOMAIN:
            raise ValueError("each domain requires one to eight cases")
        normalized_cases = []
        for case in queue:
            if not isinstance(case, dict) or set(case) - CASE_FIELDS:
                raise ValueError("domain case has unsupported fields")
            case_id = _name(case.get("id"), "case")
            if case_id in seen_cases:
                raise ValueError("case identifiers must be unique across the domain plan")
            seen_cases.add(case_id)
            if len(seen_cases) > MAX_CASES:
                raise ValueError("domain plan exceeds the case allowance")
            assignment_id = case.get("assignment_id")
            if not isinstance(assignment_id, str) or assignment_id not in assignments:
                raise ValueError("domain case requires a native source assignment")
            if assignment_id in seen_assignments:
                raise ValueError("a source assignment cannot be scheduled twice in a domain plan")
            seen_assignments.add(assignment_id)
            source_case = {key: value for key, value in case.items() if key not in ("id", "review_roles")}
            _, focus = validate_selection({"source_plan_id": plan["plan_id"],
                "source_fingerprint": plan["source_fingerprint"], "assignment_ids": [assignment_id],
                "assignments": [source_case]}, plan)
            supplied_roles = case.get("review_roles", {})
            if not isinstance(supplied_roles, dict) or set(supplied_roles) - set(ROLES):
                raise ValueError("domain case roles must be verify, cover or context")
            roles = {}
            local_ids = set(assignments[assignment_id]["review_ids"])
            for role in ROLES:
                members = supplied_roles.get(role, [])
                if (not isinstance(members, list) or any(not isinstance(rid, str) for rid in members)
                        or len(members) != len(set(members))
                        or not set(members) <= native_set or not set(members) <= local_ids):
                    raise ValueError("domain evidence roles must use native IDs from the selected assignment")
                if classified.intersection(members):
                    raise ValueError("a native review ID cannot have multiple case roles")
                classified.update(members)
                # Native source plans use canonical member order. Preserve case
                # priority, but do not make provider binding depend on how a
                # planner happened to order IDs inside one case.
                roles[role] = [rid for rid in assignments[assignment_id]["review_ids"] if rid in set(members)]
                for rid in members:
                    accounting[rid] = {"role": role, "domain_id": domain_id, "case_id": case_id,
                        "status": "queued" if role == "verify" else "planned" if role == "cover" else "available",
                        "reviewed": False, "assessment_required": role == "verify", "reason": case["reason"]}
            normalized = {"id": case_id, "domain_id": domain_id, "assignment_id": assignment_id,
                          "focus": focus[assignment_id], "review_roles": roles,
                          "verify_review_ids": roles["verify"]}
            normalized_cases.append(normalized)
            cases.append(normalized)
        normalized_domains.append({"id": domain_id, "title": title,
                                   "shared_facts": shared_facts, "cases": normalized_cases})
    return {"schema_version": VERSION, "source_plan_id": plan["plan_id"],
            "source_fingerprint": plan["source_fingerprint"], "domains": normalized_domains,
            "cases": cases, "lead_accounting": accounting,
            "coverage_plan": manifest.get("coverage_plan", {})}
