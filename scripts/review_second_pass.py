"""Opt-in source/trace review. Native finalization and state remain authoritative."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import json
import math
from pathlib import Path
import time

import review_context as context
import review_orchestration as orchestration
import review_trace

ROLES = ("second_pass_fast", "second_pass_compare")
FINAL_ONLY_ROLES = ("second_pass_compare",)
OUTCOMES = ("confirmed", "corrected", "reopened", "unresolved", "not_checked")
PROOFS = ("supported", "unsupported", "undetermined")
INVESTIGATIONS = ("sufficient", "missing_available_evidence", "external_blocker", "budget_limited", "execution_failed")
ERRORS = ("wrong_property", "relied_on_unread_guard", "caller_constraint_ignored", "invalid_counterexample",
          "unsupported_impact", "lost_adjacent_lead", "unnecessary_research")
FOLLOWUP_REASONS = ("conflicting_evidence", "control_applicability", "missing_local_evidence",
                    "external_required", "human_required")
FAST_MAX_CLAIMS = 20
FAST_FRACTION = 0.25
CLAIM_PROPERTIES = ("authorization", "output_encoding", "input_interpretation", "session_lifecycle",
                    "sensitive_storage", "transport", "resource_bounds", "configuration", "workflow_state", "other")


def validate_claim_context(value):
    fields = {"root", "property", "applicability", "basis", "kind", "impact", "conditions"}
    if (not isinstance(value, dict) or set(value) != fields
            or value["property"] not in CLAIM_PROPERTIES
            or value["applicability"] not in ("active", "supported_optional", "local_contract", "dormant", "unresolved")
            or value["kind"] not in ("application_path", "local_unsafe_construction", "security_contract", "configuration_exposure")
            or value["impact"] not in ("source_supported", "conditional", "unresolved")
            or any(not isinstance(value[k], str) or not value[k].strip() or len(value[k]) > limit
                   for k,limit in (("basis",300), ("conditions",500)))):
        raise ValueError("invalid claim applicability/repair context")
    root = value["root"]
    if (not isinstance(root,dict) or set(root) != {"path", "start_line", "end_line"}
            or not isinstance(root["path"],str) or not root["path"].strip()
            or any(type(root[k]) is not int for k in ("start_line","end_line"))
            or not 1 <= root["start_line"] <= root["end_line"] or root["end_line"]-root["start_line"] >= 20):
        raise ValueError("claim root needs a small cited source locator")
    return copy.deepcopy(value)


def take_claim_contexts(draft, *, errors=None):
    """Strip advisory metadata; its root must already be native-validated evidence."""
    values = []
    for row in draft.get("results", []):
        value = row.pop("claim_context", None)
        if value is None:
            continue
        try:
            value = validate_claim_context(value)
            root = value["root"]
            if not any(e.get("path") == root["path"] and e["start_line"] <= root["start_line"]
                       <= root["end_line"] <= e["end_line"] for e in row.get("evidence", [])):
                raise ValueError("claim root must be included in this assessment's inspected evidence")
        except (ValueError,KeyError,TypeError) as error:
            if errors is None:
                raise
            errors.append({"review_id":row["review_id"],"reason":str(error)})
            continue  # Invalid presentation metadata cannot discard source-valid review work.
        values.append({"review_id":row["review_id"], **value})
    return values


def claim_contexts(directory, ids):
    selected, values = set(ids), {}
    for _, job, _ in original_jobs(directory):
        if job.get("binding", {}).get("role", "investigator") != "investigator":
            continue
        bound = set(job.get("binding", {}).get("review_ids", []))
        for row in job.get("claim_contexts", []):
            rid = row.get("review_id")
            if rid not in bound:
                raise ValueError("claim context is outside its original job")
            if rid not in selected:
                continue
            value = {"review_id":rid, **validate_claim_context({k:v for k,v in row.items() if k != "review_id"})}
            if rid in values and values[rid] != value:
                raise ValueError("conflicting first-pass claim contexts")
            values[rid] = value
    return list(values.values())


def repair_key(value):
    root = value["root"]
    return (root["path"], root["start_line"], value["property"])


def group_claims(rows, contexts):
    """Proposed causal families; never discard claims or propagate a verdict."""
    by_id = {r["review_id"]:r for r in contexts}
    groups = {}
    for row in rows:
        rid, decision = row["review_id"], row["decision"]
        metadata = by_id.get(rid)
        key = ("cited", *repair_key(metadata), decision) if metadata else ("ungrouped", rid)
        identity = "claim-group-" + context.digest(key)[:16]
        group = groups.setdefault(identity, {"group_id":identity, "decision":decision,
            "basis":"cited_repair_locator" if metadata else "no_context_singleton",
            "root":metadata["root"] if metadata else None,
            "property":metadata["property"] if metadata else None, "members":[]})
        group["members"].append({"review_id":rid, "summary":row["summary"],
            "severity":(row.get("diagnosis") or {}).get("severity", "unknown"),
            "first_pass_context":metadata, "checks":row.get("checks", [])})
    return {"schema_version":"1", "authority":"proposed_presentation_groups",
        "context_stage":"first_pass; conditions may need revision after a later verdict/proof change",
        "claim_labels":dict(Counter(r["decision"] for r in rows)),
        "claim_count":len(rows), "group_count":len(groups), "groups":list(groups.values()),
        "limits":"Shared locator/property proposes a family, not a certified unique defect. Caller, branch and repair variants remain separate members. Missing context remains singleton; grouping changes no native decision."}


def write_groups(output, rows, contexts, write, *, annotation_errors=()):
    output = Path(output)
    grouped = group_claims(rows, contexts)
    grouped["annotation_errors"] = list(annotation_errors)
    write(output / "finding-groups.json", grouped)
    lines = ["# Proposed finding families", "", grouped["limits"], "",
        f"{grouped['claim_count']} claims in {grouped['group_count']} proposed groups. Raw labels: " +
        ", ".join(f"{k}={v}" for k,v in sorted(grouped["claim_labels"].items())) + ".", "",
        "Applicability and conditions below are first-pass annotations; inspect subsequent repairs before reusing them.", ""]
    if annotation_errors:
        lines += [f"{len(annotation_errors)} invalid annotations were omitted; native review results were retained. See annotation_errors in the JSON and bound job checkpoints.", ""]
    for group in grouped["groups"]:
        root = group["root"]
        label = f"{root['path']}:{root['start_line']} ({group['property']})" if root else "No shared repair locator"
        lines += [f"## {group['group_id']} — {group['decision']} — {label}", ""]
        for member in group["members"]:
            metadata = member["first_pass_context"]
            summary = " ".join(member["summary"].split())
            lines.append(f"- `{member['review_id']}`: {summary}")
            if metadata:
                lines.append("  " + " ".join(f"{metadata['applicability']}; {metadata['kind']}; impact={metadata['impact']}. "
                    f"{metadata['basis']} Conditions: {metadata['conditions']}".split()))
        lines.append("")
    (output / "finding-groups.md").write_text("\n".join(lines),encoding="utf-8")
    return grouped


def positive_audit_notes(row, value):
    """Proof-specific questions, not automatic false-positive labels."""
    if row["decision"] != "issue":
        return []
    root = value["root"]
    where = f"{root['path']}:{root['start_line']}"
    questions = []
    if value["kind"] == "application_path" and value["applicability"] in ("dormant", "unresolved", "local_contract"):
        questions.append(("conflicting_evidence" if value["applicability"] == "dormant" else "control_applicability",
            f"At {where}, does a compatible registered caller reach the claimed protected effect?"))
    if value["impact"] == "unresolved":
        questions.append(("conflicting_evidence", f"At {where}, which inspected actor-to-effect chain supports the claimed impact?"))
    if ((row.get("diagnosis") or {}).get("severity") in ("high", "critical")
            and (value["kind"] == "local_unsafe_construction" or
                 value["impact"] == "conditional" and value["applicability"] in ("supported_optional", "local_contract"))):
        questions.append(("control_applicability", f"At {where}, do the stated reaching conditions support this severity and protected effect?"))
    return [{"review_id":row["review_id"], "reason":reason, "question":question[:300]} for reason,question in questions]


def take_followups(draft):
    """Scheduling metadata never enters native verdicts or substitutes for proof."""
    notes = []
    for row in draft.get("results", []):
        note = row.pop("followup", None)
        if note is None:
            continue
        if (not isinstance(note, dict) or set(note) != {"reason", "question"}
                or note["reason"] not in FOLLOWUP_REASONS
                or not isinstance(note["question"], str) or not note["question"].strip() or len(note["question"]) > 300):
            raise ValueError("follow-up nomination needs a typed reason and bounded deciding question")
        if note["reason"] in ("external_required", "human_required") and row["decision"] != "needs_review":
            raise ValueError("unavailable follow-up requires a pending assessment")
        notes.append({"review_id":row["review_id"], **note})
    return notes


def followup_notes(directory, ids):
    selected = set(ids)
    notes = []
    for _, job, _ in original_jobs(directory):
        if job.get("binding", {}).get("role", "investigator") != "investigator":
            continue
        bound = set(job.get("binding", {}).get("review_ids", []))
        for note in job.get("followups", []):
            if note.get("review_id") not in bound:
                raise ValueError("follow-up nomination is outside its original job")
            if note["review_id"] not in selected:
                continue
            probe = {"review_id":note["review_id"], "decision":"needs_review",
                     "followup":{k:note[k] for k in ("reason", "question")}}
            notes.extend(take_followups({"results":[probe]}))
    return notes


def select_followups(rows, notes, *, scope=("issue", "not_issue", "needs_review"), max_claims=FAST_MAX_CLAIMS, contexts=()):
    """No inference: rank nominations/proof signals and expose all omissions."""
    if type(max_claims) is not int or not 1 <= max_claims <= FAST_MAX_CLAIMS:
        raise ValueError("Fast claim cap must be between 1 and 20; use Full for a broader audit")
    by_id = {r["review_id"]:r for r in rows}
    if len(by_id) != len(rows):
        raise ValueError("follow-up planning requires unique claim IDs")
    nominated = {}
    for note in notes:
        rid = note["review_id"]
        if rid not in by_id:
            raise ValueError("follow-up nomination is outside the selected first pass")
        # A later authorized quality stage may have resolved an original blocker.
        # Validate the note as scheduling data, then test its current applicability.
        validated = take_followups({"results":[{"review_id":rid, "decision":"needs_review",
            "followup":{k:note[k] for k in ("reason", "question")}}]})[0]
        if validated not in nominated.setdefault(rid, []):
            nominated[rid].append(validated)
    metadata = {r["review_id"]:r for r in contexts}
    if not set(metadata) <= set(by_id):
        raise ValueError("claim context is outside the selected first pass")
    audit = {}
    for rid,value in metadata.items():
        validate_claim_context({k:v for k,v in value.items() if k != "review_id"})
        audit[rid] = positive_audit_notes(by_id[rid], value)
    eligible = [r for r in rows if r["decision"] in scope]
    cap = min(max_claims, math.ceil(len(eligible) * FAST_FRACTION))
    ranks = {reason:i for i,reason in enumerate(FOLLOWUP_REASONS[:3])}
    severity = {s:i for i,s in enumerate(("critical", "high", "medium", "unknown", "low", "note"))}
    candidates, excluded = [], []
    for row in rows:
        rid = row["review_id"]
        own = nominated.get(rid, [])
        actionable = [n for n in own if n["reason"] in ranks]
        actionable += [n for n in audit.get(rid, []) if n not in actionable]
        unavailable = [n for n in own if n["reason"] not in ranks]
        if row["decision"] not in scope:
            reason = "outside_verdict_scope"
        elif unavailable:
            reason = "unavailable_deciding_fact" if row["decision"] == "needs_review" else "resolved_blocker_nomination"
        elif not actionable:
            reason = "no_actionable_nomination"
        else:
            candidates.append({"review_id":rid, "decision":row["decision"], "reasons":actionable,
                "selection_source":"positive_proof_signal" if audit.get(rid) else "first_pass_nomination"})
            continue
        excluded.append({"review_id":rid, "reason":reason, "notes":own})
    candidates.sort(key=lambda n:(0 if n["selection_source"] == "positive_proof_signal" else 1,
        min(ranks[r["reason"]] for r in n["reasons"]),
        severity.get((by_id[n["review_id"]].get("diagnosis") or {}).get("severity", "unknown"), 3), n["review_id"]))
    chosen, deferred, seen = [], [], set()
    for candidate in candidates:
        rid = candidate["review_id"]
        key = repair_key(metadata[rid]) if rid in metadata else ("claim",rid)
        reason = "shared_repair_point" if key in seen else "fast_cap"
        if key not in seen and len(chosen) < cap:
            chosen.append(candidate)
            seen.add(key)
        else:
            deferred.append({**candidate,"reason":reason})
    return {"schema_version":"1", "policy":"first-pass-evidence/v2", "authority":"scheduling_hypotheses",
        "scope":list(scope), "first_pass_claims":len(rows), "eligible_claims":len(eligible),
        "claim_labels":dict(Counter(r["decision"] for r in rows)),
        "limits":{"max_claims":max_claims, "fraction":FAST_FRACTION, "effective_cap":cap},
        "selected":chosen, "deferred":deferred,
        "excluded":excluded, "full_claims":len(eligible), "selection_model_calls":0}


def source_review_context(directory):
    """Locate first-pass coverage even when no scanner or AI claims exist."""
    directory = Path(directory)
    for name in ("source-review.json", "source-review/summary.json"):
        path = directory / name
        if not path.is_file():
            continue
        source = read(path)
        return {"origin":source.get("origin", "ai_source_review"),
            "native_selected_claims":source.get("native_selected_claims"),
            "ai_discovered_claims":source["source_questions"],
            "assignments":source["assignments"], "completed_assignments":source["completed_assignments"],
            "coverage_counts":dict(Counter(w["status"] for w in source["coverage"])),
            "coverage_report":str(path.resolve())}
    return None


def write_options(output, plan, rows, write, *, source_directory=None, contexts=()):
    """Prepare a reviewable first-pass checkpoint, without starting another stage."""
    output = Path(output)
    source = source_review_context(source_directory or output)
    leads = [lead for r in rows for lead in (r.get("investigation") or {}).get("reviewer_origin_leads", [])]
    grouped = write_groups(output, rows, contexts, write)
    options = {"schema_version":"1", "first_pass":plan["claim_labels"], "fast":plan,
        "review_origin":source["origin"] if source else "native_claims",
        "grouping":{"report":"finding-groups.json", "claims":len(rows), "proposed_groups":grouped["group_count"],
                    "authority":"presentation_hypotheses; native verdicts unchanged"},
        "full":{"claims":plan["full_claims"], "automatic_narrowing":False},
        "threat_model":{"execution":"agent_scoped_source_review", "leads":leads,
                        "source_context":source, "requires_claims":False,
                        "proposed_scopes":[{"lead":lead,"stop":"Settle this named invariant or retain its exact unavailable fact within remaining authorized budget."} for lead in leads[:3]],
                        "additional_leads":max(0,len(leads)-3), "automatic_execution":False,
                        "scope":"One identified flow/invariant and its deciding cross-file relationships."},
        "authorization":"Present results and next-step choices after the requested first pass. Execute only already requested follow-ups without another confirmation."}
    write(output / "review-options.json", options)
    lines = ["# First-pass results and next steps", "",
        "First pass: " + ("AI source review with no selected scanner claims." if source and source["origin"] == "ai_source_only" else
            "AI source review with scanner questions." if source else "Selected claim review."),
        "Claim labels: " + (", ".join(f"{k}={v}" for k,v in sorted(plan["claim_labels"].items())) or "none") + ".",
        "These counts are review decisions, not independent defect or ground-truth counts.", "",
        f"- Fast: {len(plan['selected'])} automatically selected claims; {len(plan['deferred'])} actionable claims deferred by cap/shared repair point.",
        f"- Full: audit all {plan['full_claims']} claims in the requested verdict scope, including dismissals and pending claims when scope is all.",
        "- Scoped threat review: examine an identified flow/invariant using cited facts and targeted cross-file reads.", "",
        "Fast uses first-pass nominations and explicit positive proof signals; selection makes no model call. Unselected claims retain their first results.",
        "Proposed causal families and per-caller applicability/impact conditions: finding-groups.md. Group counts are not unique vulnerability totals.",
        "First-pass coverage limits and unresolved facts remain in the findings/source reports.", "", "## Proposed Fast queue", ""]
    for item in plan["selected"]:
        for note in item["reasons"]:
            question = " ".join(note["question"].split())
            lines.append(f"- `{item['review_id']}` ({note['reason']}): {question}")
    if not plan["selected"]:
        lines.append("No actionable Fast nominations or positive proof signals. Do not broaden Fast to all claims as a fallback.")
    if source:
        lines += ["", f"AI source coverage: {source['completed_assignments']}/{source['assignments']} assignments completed; "
                  f"{source['ai_discovered_claims']} source-discovered claims.",
                  "Scoped threat review can start from the recorded source flows and coverage gaps even when there are no claims.",
                  "Read the source_context coverage report in review-options.json for the exact first-pass ranges and limits."]
    lines += ["", "Stop after the requested first-pass scope and present these choices unless a follow-up is already authorized.", ""]
    (output / "review-options.md").write_text("\n".join(lines), encoding="utf-8")


def review_scope(value):
    aliases = {"issues":"issue", "issue":"issue", "tp":"issue", "dismissals":"not_issue", "dismissed":"not_issue",
        "not_issue":"not_issue", "fp":"not_issue", "pending":"needs_review", "needs_review":"needs_review"}
    if value == "all":
        return ("issue", "not_issue", "needs_review")
    parts = value.split(",") if isinstance(value, str) else []
    if not parts or any(p.strip().lower() not in aliases for p in parts):
        raise ValueError("second-pass scope must be all or comma-separated issues,dismissals,pending")
    chosen = {aliases[p.strip().lower()] for p in parts}
    return tuple(v for v in ("issue", "not_issue", "needs_review") if v in chosen)


def validate_rates(value):
    if not isinstance(value, dict) or set(value) != {"models"} or not isinstance(value["models"], dict):
        raise ValueError("rates must contain a models mapping")
    for model, rate in value["models"].items():
        required = {"input_per_million", "cached_input_per_million", "output_per_million"}
        if not isinstance(model, str) or not model or not isinstance(rate, dict) or not required <= set(rate) or set(rate)-required-{"long_context"}:
            raise ValueError("invalid model token-rate fields")
        if any(type(rate[k]) not in (int, float) or not math.isfinite(rate[k]) or rate[k] < 0 for k in required):
            raise ValueError("token rates must be finite nonnegative numbers")
        if "long_context" in rate:
            long = rate["long_context"]
            if (not isinstance(long, dict) or set(long) != {"threshold_tokens", "input_multiplier", "output_multiplier"}
                    or type(long["threshold_tokens"]) is not int or long["threshold_tokens"] <= 0
                    or any(type(long[k]) not in (int, float) or not math.isfinite(long[k]) or long[k] <= 0 for k in ("input_multiplier", "output_multiplier"))):
                raise ValueError("invalid long-context rate basis")
    return value


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def checks(values, ids):
    """Validate semantic annotations structurally; this is not a truth checker."""
    if (not isinstance(values, list) or any(not isinstance(v, dict) for v in values)
            or Counter(v.get("review_id") for v in values) != Counter(ids)):
        raise ValueError("second-pass checks must cover exact assigned IDs once")
    for row in values:
        if (set(row) != {"review_id", "action", "claim", "proof_status", "investigation_status", "error_codes"}
                or row["action"] not in ("keep", "repair", "reopen", "insufficient")
                or row["proof_status"] not in PROOFS or row["investigation_status"] not in INVESTIGATIONS
                or not isinstance(row["claim"], str) or len(row["claim"]) > 300
                or not isinstance(row["error_codes"], list) or any(e not in ERRORS for e in row["error_codes"])):
            raise ValueError("invalid second-pass assessment")
        if row["action"] != "keep" and not row["claim"].strip():
            raise ValueError("second-pass objection needs an exact claim")
        if row["action"] == "keep" and (row["proof_status"] != "supported" or row["error_codes"]):
            raise ValueError("keeping a proof requires supported evidence without known errors")
        if row["action"] == "insufficient" and row["proof_status"] != "undetermined":
            raise ValueError("insufficient audit coverage cannot certify or refute a proof")
    # Error codes are tags, not ordered evidence. Preserve the raw response but
    # do not discard an otherwise valid bundle for a repeated allowed tag.
    return {r["review_id"]: {**r, "error_codes":list(dict.fromkeys(r["error_codes"]))} for r in values}


def brief(response):
    """Rebind inspected source to current bundle membership, preserving claims/leads."""
    values = []
    for row in response["results"]:
        investigation = row.get("investigation") or {}
        evidence = []
        for artifact in investigation.get("decisive_artifacts", []):
            loc = artifact["location"]
            end = loc["end"]["line"] - int(loc["end"]["column"] == 1 and loc["end"]["line"] > loc["start"]["line"])
            evidence.append({"path":loc["path"], "start_line":loc["start"]["line"], "end_line":end})
        value = {k:copy.deepcopy(row[k]) for k in ("review_id", "decision", "confidence", "summary", "checks", "diagnosis") if k in row}
        value.update(reason=" ".join(r["claim"] for r in investigation.get("reviewer_inferences", [])),
                     evidence=evidence, blockers=copy.deepcopy(investigation.get("blockers", [])))
        leads = []
        for lead in investigation.get("reviewer_origin_leads", []):
            loc = lead["location"]
            leads.append({k:copy.deepcopy(lead[k]) for k in ("question", "security_relevance", "distinct_from_review")})
            leads[-1]["evidence"] = {"path":loc["path"], "start_line":loc["start"]["line"],
                "end_line":loc["end"]["line"] - int(loc["end"]["column"] == 1 and loc["end"]["line"] > loc["start"]["line"])}
        if leads:
            value["source_leads"] = leads
        values.append(value)
    return {"results":values}


def reconcile(baseline, assessment, annotations, mode):
    """Install only explicit source-supported repairs; uncertainty remains pending."""
    original = {r["review_id"]:r for r in baseline["results"]}
    proposed = {r["review_id"]:r for r in assessment["results"]}
    if len(proposed) != len(assessment["results"]) or set(proposed) != set(original):
        raise ValueError("second assessment differs from selected coverage")
    notes = checks(annotations, list(original))
    result = copy.deepcopy(baseline)
    outcomes = []
    for index, old in enumerate(result["results"]):
        rid = old["review_id"]; note = notes[rid]; candidate = proposed[rid]
        action = note["action"]
        chosen = copy.deepcopy(old)
        if action == "keep":
            if candidate["decision"] != old["decision"]:
                raise ValueError("keep cannot approve a different verdict")
            outcome = "unresolved" if old["decision"] == "needs_review" else "confirmed"
        elif action == "insufficient":
            outcome = "not_checked"
        elif action == "repair" and note["proof_status"] == "supported":
            chosen = copy.deepcopy(candidate)
            if chosen["decision"] == "needs_review":
                outcome = "unresolved" if old["decision"] == "needs_review" else "reopened"
            else:
                outcome = "corrected"
            # A repair of prose/conditions is real even if the label is unchanged.
        else:
            chosen = copy.deepcopy(candidate if candidate["decision"] == "needs_review" else old)
            chosen.update(decision="needs_review", diagnosis=None)
            # A new pending draft owns its remaining questions. Replaying the
            # baseline's checks can resurrect gaps the recovery already settled.
            chosen["checks"] = list(dict.fromkeys([*chosen.get("checks", []), note["claim"]]))
            chosen.setdefault("investigation", {})["blockers"] = list(dict.fromkeys([
                *chosen.get("investigation", {}).get("blockers", []), note["claim"]]))
            outcome = "unresolved" if old["decision"] == "needs_review" else "reopened"
        result["results"][index] = chosen
        outcomes.append({"review_id":rid, "first_decision":old["decision"], "final_decision":chosen["decision"],
            "outcome":outcome, "claim":note["claim"], "proof_status":note["proof_status"],
            "investigation_status":note["investigation_status"], "error_codes":note["error_codes"]})
    return result, outcomes


def original_jobs(base):
    """Read the immutable first-attempt evidence once for all second-pass bundles."""
    if base is None:
        return []
    result = []
    for path in sorted((Path(base) / "jobs").glob("*.json")):
        job = read(path)
        if not str(job.get("binding", {}).get("assessment_cycle", "")).startswith("second_pass"):
            result.append((path, job, context.digest(job)))
    return result


def prior_material(base, ids, byte_limit, deciding_paths=None, *, jobs=None, related_paths=()):
    """Share original source results, never sibling verdicts or applicability claims."""
    facts, peer_facts, lookup_trace, fingerprints, job_ids = [], [], [], [], set()
    if base is None:
        return {"facts":[], "omitted_facts":0}, {"history":"unavailable", "queries":[], "flags":[]}, fingerprints
    base = Path(base)
    jobs = original_jobs(base) if jobs is None else jobs
    contributing = [item for item in jobs if set(item[1].get("binding", {}).get("review_ids", [])) & set(ids)]
    contributing_paths = {item[0] for item in contributing}
    peers = [item for item in jobs if item[0] not in contributing_paths] if related_paths else []
    # A relevant source file is an evidence reuse boundary, not permission to
    # merge claims/callers. Peer material cannot crowd out original evidence.
    peer_bytes, peer_limit = 0, min(65536, byte_limit // 4)
    for path, job, fingerprint in [*contributing, *peers]:
        own = path in contributing_paths
        selected = []
        for row in job.get("results", []):
            query = row.get("query", {})
            if own:
                if deciding_paths is not None and query.get("review_id") not in ids and query.get("arguments", {}).get("path") not in deciding_paths:
                    continue
            elif (query.get("tool") not in ("source", "definition", "references")
                    or query.get("arguments", {}).get("path") not in related_paths):
                continue
            fact = {k:copy.deepcopy(row[k]) for k in ("result_id", "origin_package_id", "origin_review_id", "query", "result") if k in row}
            if len(fact) != 5:
                continue
            fact["query"].pop("purpose", None)
            if not own:
                size = len(json.dumps(fact, ensure_ascii=False).encode("utf-8"))
                if peer_bytes + size > peer_limit:
                    continue
                peer_bytes += size
            selected.append((row, fact))
        if not selected:
            continue
        if own:
            job_ids.add(path.stem)  # Sibling progress/objections are not source facts.
        fingerprints.append([str(path), fingerprint])
        for row, fact in selected:
            # Only broker-returned evidence; checkpoint prose is deliberately not carried.
            (facts if own else peer_facts).append(fact)
            query = row.get("query", {}) if own else fact["query"]
            value = row.get("result", {})
            lookup_trace.append({"round":row.get("round"), "query":query,
                "result_id":row.get("result_id"), "operation":value.get("operation"),
                "source_complete":value.get("source_complete"), "truncated":value.get("truncated", False),
                "limit":value.get("limit"), "error":value.get("error"), "empty":value.get("results") == []})
    handoff = orchestration.source_handoff([{"source_facts":peer_facts}, {"source_facts":facts}], byte_limit)
    # Bound trace text separately; no unbounded event or source replay.
    selected, used = [], 0
    for row in lookup_trace:
        size = len(json.dumps(row, ensure_ascii=False).encode())
        if used + size > 65536:
            break
        selected.append(row); used += size
    flags = review_trace.query_flags([{"query":r["query"], "result":{"truncated":r["truncated"],
        "source_complete":r["source_complete"], **({"error":r["error"]} if r["error"] else {})}} for r in selected])
    events, torn = review_trace.jsonl(base / "review-trace.jsonl")
    for event in events:
        if event.get("job_id") not in job_ids:
            continue
        if event["event"] == "progress_changed" and event.get("dropped_open_edges"):
            flags.append({"kind":"open_relationship_disappeared", "round":event.get("round"),
                "edges":event["dropped_open_edges"], "interpretation":"Check whether resolved, rephrased or abandoned."})
        elif event["event"] in ("research_budget_deferred", "native_failed"):
            flags.append({"kind":event["event"], "round":event.get("round"), "operation":event.get("operation")})
    return handoff, {"history":"recorded" if (base / "review-trace.jsonl").is_file() else "legacy_reconstruction",
        "queries":selected, "omitted_queries":len(lookup_trace)-len(selected),
        "flags":flags[:100], "omitted_flags":max(0,len(flags)-100), "torn_trace_rows":torn}, fingerprints


def comparison_context(baseline, proposed, trace):
    sources = {}
    def compact(response):
        if response is None:
            return None
        rows = []
        for row in response["results"]:
            value = {k:copy.deepcopy(row[k]) for k in ("review_id", "decision", "confidence", "summary", "checks", "diagnosis") if k in row}
            investigation = row.get("investigation") or {}
            refs = []
            for artifact in investigation.get("decisive_artifacts", []):
                key = "source-" + context.digest([artifact["location"], artifact["excerpt"]])[:24]
                sources[key] = {"location":artifact["location"], "excerpt":artifact["excerpt"]}
                refs.append(key)
            value.update(evidence=refs, inferences=investigation.get("reviewer_inferences", []),
                blockers=investigation.get("blockers", []), source_leads=investigation.get("reviewer_origin_leads", []))
            rows.append(value)
        return {"results":rows}
    first, second = compact(baseline), compact(proposed)
    return {"baseline":first, "assessment":second, "decisive_source":sources, "lookup_trace":trace,
        "scope":"Exact assigned claims; trace is navigation, not semantic proof."}


def audit_checkpoint(draft, annotations, ids):
    """Capture provisional objections without admitting a proposed correction."""
    notes = checks(annotations, ids)
    rows = draft.get("results", [])
    if (Counter(r.get("review_id") for r in rows) != Counter(ids)
            or any(r.get("decision") not in ("issue", "not_issue", "needs_review") for r in rows)):
        raise ValueError("audit draft must cover exact assigned decisions once")
    affected = [r["review_id"] for r in rows if
        (notes[r["review_id"]]["action"] == "repair" and r["decision"] != "needs_review") or
        notes[r["review_id"]]["investigation_status"] in ("missing_available_evidence", "budget_limited") or
        (notes[r["review_id"]]["action"] in ("repair", "reopen") and
         notes[r["review_id"]]["investigation_status"] == "sufficient")]
    return {"review_ids":affected, "draft":copy.deepcopy(draft), "checks":list(notes.values()),
        "feedback":{"reason":"fast_audit_recovery", "review_ids":affected,
            "proposed_draft":copy.deepcopy(draft), "proposed_checks":list(notes.values()),
            "instruction":"Resolve these concrete audit objections against the original baseline and actual source. They are unverified hypotheses, not required verdicts. Reject inapplicable objections, retrieve only deciding available facts, and preserve active branches, prior guards and reaching conditions. Keep other IDs stable. Return all final review_checks against the original baseline; leave a precise gap only when it cannot be settled.",
            "authority":"Controller audit checkpoint, not source evidence or a certified verdict."}}


def retain_settled_audit(draft, annotations, checkpoint, ids):
    """Recovery cannot silently replace claims outside its objection scope."""
    notes = checks(annotations, ids)
    if Counter(r.get("review_id") for r in draft["results"]) != Counter(ids):
        raise ValueError("recovery draft must cover exact assigned decisions once")
    old = {r["review_id"]:r for r in checkpoint["draft"]["results"]}
    old_notes = {r["review_id"]:r for r in checkpoint["checks"]}
    affected = set(checkpoint["review_ids"])
    result = copy.deepcopy(draft)
    result["results"] = [r if r["review_id"] in affected else copy.deepcopy(old[r["review_id"]]) for r in result["results"]]
    return result, [notes[rid] if rid in affected else copy.deepcopy(old_notes[rid]) for rid in ids]


def defer_recovery(draft, annotations, ids, affected, obstacle, *, validation=False):
    proposed, notes = copy.deepcopy(draft), list(checks(annotations, ids).values())
    by_id = {r["review_id"]:r for r in notes}
    for row in proposed["results"]:
        if row["review_id"] in affected:
            note = by_id[row["review_id"]]
            if validation:
                # The source question may be answered. The remaining task is
                # validation of this proposed proof, not the old research gap.
                question = ("Counter-check the proposed correction against active guards, alternate producers and contrary source: "
                            + row["summary"][:180])
                questions = [question]
                note["claim"] = question
                summary = "Repair validation deferred: " + row["summary"][:450]
            else:
                questions = row.get("checks") or [note["claim"]]
                summary = "Review remains unresolved: " + questions[0][:450]
            row.update(decision="needs_review", diagnosis=None,
                summary=summary,
                checks=questions, blockers=list(dict.fromkeys([*row.get("blockers", []), obstacle])))
            # Keep the actual objection in the derived output as well as raw turns.
            note.update(action="reopen", proof_status="undetermined", investigation_status="budget_limited")
    return proposed, notes


def repair_countercheck(draft, annotations, ids):
    notes = checks(annotations, ids)
    affected = [r["review_id"] for r in draft["results"] if r["decision"] != "needs_review"
        and notes[r["review_id"]]["action"] == "repair" and notes[r["review_id"]]["proof_status"] == "supported"]
    if not affected:
        return None
    return {"reason":"fast_repair_countercheck", "review_ids":affected,
        "proposed_draft":copy.deepcopy(draft), "proposed_checks":copy.deepcopy(annotations),
        "instruction":"Check the proposed replacement proof against the actual active branches, earlier successful guards and contrary source. Comments, disabled alternatives and hypothetical prerequisites do not establish reachable behavior. Reuse inspected evidence; retrieve only a deciding missing fact. Confirm or repair the proposal, or leave the exact gap pending. Assess final actions against the original baseline, not the proposal; keep other IDs stable and return all final review_checks.",
        "authority":"Controller request to test a hypothesis, not source evidence or a verdict."}


def defer_unchecked_repairs(draft, annotations, ids):
    feedback = repair_countercheck(draft, annotations, ids)
    if feedback is None:
        return copy.deepcopy(draft), copy.deepcopy(annotations)
    return defer_recovery(draft, annotations, ids, feedback["review_ids"],
        "The proposed correction could not be counter-checked within the remaining audit allowance.", validation=True)


def fast_research_rounds(phase, rounds_remaining, countercheck_started=False):
    """Reserve one existing call for repair validation; never expand the allowance."""
    if phase == "audit":
        return 0
    return max(0, rounds_remaining - int(phase == "recovery" and not countercheck_started))


def run(*, mode, requests, baselines, first_directory, output, task_base, execute_stage,
        finalize, write, workers, byte_limit, outside_scope=(), scope=("issue", "not_issue", "needs_review"),
        selection=None, archive_baselines=True):
    """Independent bundle failures preserve baseline results and exact unchecked coverage."""
    started = time.monotonic(); output = Path(output); rows = []; failures = []
    (output / "first-pass").mkdir(exist_ok=True)
    write(output / "second-pass-status.json", {"mode":mode, "status":"running"})
    if archive_baselines:
        for filename, _, _ in requests:
            write(output / "first-pass" / filename, baselines[filename])
    jobs = original_jobs(first_directory) if requests else []
    def one(item):
        filename, request, data = item; ids = data["review_ids"]; baseline = baselines[filename]
        related_paths = {a["location"]["path"] for row in baseline["results"]
            for a in row.get("investigation", {}).get("decisive_artifacts", [])}
        deciding_paths = related_paths if selection is not None or tuple(scope) != review_scope("all") else None
        handoff, trace, frozen = prior_material(first_directory, ids, byte_limit, deciding_paths,
            jobs=jobs, related_paths=related_paths if mode == "fast" else ())
        task = {**task_base, "kind":"native_bundle", "bundle":str(request), "review_ids":ids,
            "review_playbooks":data.get("review_playbooks", {}), "profile":"routine",
            "second_pass":mode, "assessment_cycle":"second_pass_" + mode, "source_handoff":handoff}
        stages = []
        if mode == "full":
            fresh = {**task, "review_role":"verification"}
            stage = execute_stage(fresh); stages.append(stage)
            # Do not decide agreement from labels: proof/conditions can differ too.
            task["source_handoff"] = orchestration.source_handoff([stage], byte_limit)
            proposed = stage["response"]
        else:
            proposed = baseline
        task.update(review_role="second_pass_fast" if mode == "fast" else "second_pass_compare",
            assessment_cycle="second_pass_" + mode + "_check",
            stage_context=comparison_context(baseline, proposed if mode == "full" else None, trace))
        checked = execute_stage(task); stages.append(checked)
        for path, digest in frozen:
            if context.digest(read(path)) != digest:
                raise ValueError("first-pass evidence changed during second review")
        combined, outcomes = reconcile(baseline, checked["response"], checked["checks"], mode)
        finalize(combined, filename, request)
        checkpoint = checked.get("audit_checkpoint")
        audit_notes = {r["review_id"]:r for r in checkpoint["checks"]} if checkpoint else {}
        for row in outcomes:
            row.update(mode=mode, stages=[s["receipt"] for s in stages],
                source_handoff_omitted=handoff["omitted_facts"], trace_history=trace["history"],
                trace_queries_omitted=trace["omitted_queries"] if "omitted_queries" in trace else 0)
            if checkpoint:
                row["audit"] = {**audit_notes[row["review_id"]],
                    "recovery_requested":row["review_id"] in checkpoint["review_ids"],
                    "authority":"model_hypothesis"}
        return outcomes
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mehscan-second-pass") as pool:
        futures = {pool.submit(one, request):request for request in requests}
        for future in as_completed(futures):
            filename, request, data = futures[future]
            try:
                values = future.result()
            except Exception as error:
                failures.append({"bundle":filename, "error":type(error).__name__, "detail":str(error)[:500]})
                finalize(baselines[filename], filename, request)
                values = [{"review_id":r["review_id"], "first_decision":r["decision"], "final_decision":r["decision"],
                    "outcome":"not_checked", "mode":mode, "claim":"Second-pass execution did not complete.",
                    "proof_status":"undetermined", "investigation_status":"execution_failed", "error_codes":[], "stages":[]}
                    for r in baselines[filename]["results"]]
            rows.extend(values)
            write(output / "second-pass-progress.json", {"mode":mode, "results":rows, "failures":failures})
    targeted = len(rows)
    incomplete = sum(r["outcome"] == "not_checked" for r in rows)
    rows.extend({"review_id":r["review_id"], "first_decision":r["decision"], "final_decision":r["decision"],
        "outcome":"not_checked", "mode":mode, "claim":"Outside the requested second-pass scope.",
        "reason":"outside_scope", "proof_status":"undetermined", "investigation_status":None,
        "error_codes":[], "stages":[]} for r in outside_scope)
    counts = Counter(r["outcome"] for r in rows)
    summary = {"schema_version":"1", "mode":mode, "status":"partial" if incomplete else "complete",
        "scope":list(scope), "selected":len(rows), "targeted":targeted, "checked":targeted-incomplete,
        "outside_scope":len(outside_scope),
        "outcomes":{k:counts[k] for k in OUTCOMES}, "results":sorted(rows, key=lambda r:r["review_id"]),
        "failures":failures, "elapsed_seconds":time.monotonic()-started,
        "label_authority":"model_reviewed" if targeted-incomplete else "first_pass_only", "semantic_ground_truth":False}
    if selection is not None:
        summary["selection"] = selection
        excluded = {r["review_id"]:r["reason"] for r in [*selection["excluded"], *selection["deferred"]]}
        for row in summary["results"]:
            if row.get("reason") == "outside_scope":
                row["selection_reason"] = excluded[row["review_id"]]
    write(output / "second-pass.json", summary)
    write(output / "second-pass-status.json", {k:summary[k] for k in ("mode", "status", "selected", "targeted", "checked", "outside_scope")})
    return summary


def accounting(metrics, roles, rates=None, expected_calls=None):
    selected = [r for r in metrics if r.get("role", "investigator") in roles]
    names = ("input_tokens", "cached_input_tokens", "output_tokens")
    totals = {k:sum(r.get("usage", {}).get(k, 0) for r in selected) for k in names}
    expected_calls = len(selected) if expected_calls is None else expected_calls
    complete = expected_calls == len(selected) and all(all(k in r.get("usage", {}) for k in names)
        and not set(r.get("unknown_delta_counters", [])) & set(names) for r in selected)
    cost = 0.0 if rates is not None and complete else None
    if cost is not None:
        for row in selected:
            rate = rates.get("models", {}).get((row.get("provider") or {}).get("model"))
            if rate is None:
                cost = None; break
            u = row["usage"]; long = rate.get("long_context", {})
            large = u["input_tokens"] > long.get("threshold_tokens", float("inf"))
            factor = long.get("input_multiplier", 1) if large else 1
            out_factor = long.get("output_multiplier", 1) if large else 1
            cost += ((u["input_tokens"]-u["cached_input_tokens"])*rate["input_per_million"]*factor
                + u["cached_input_tokens"]*rate["cached_input_per_million"]*factor
                + u["output_tokens"]*rate["output_per_million"]*out_factor)/1e6
    return {"calls":expected_calls, "receipted_calls":len(selected), "usage":totals, "usage_complete":complete,
        "cached_fraction":totals["cached_input_tokens"]/totals["input_tokens"] if totals["input_tokens"] else None,
        "provider_seconds_sum":sum(r.get("elapsed_ms", 0) for r in selected)/1000,
        "cost":cost, "cost_basis":"configured_rates" if cost is not None else "unavailable"}


def export(output, metrics, write, rates=None, original_metrics=(), original_calls=None):
    """Derived labels retain source/provenance; no automatic training approval."""
    output = Path(output)
    path = output / "second-pass.json"
    if not path.is_file():
        return
    summary = read(path)
    # Metrics from verification use their conversation's captured stage task.
    stage_conversations = set()
    for p in (output / "training-turns").glob("*/*-input.json"):
        task = read(p)
        if task.get("second_pass"):
            stage_conversations.add(task["conversation_id"])
    second = [r for r in metrics if r.get("conversation_id") in stage_conversations or r.get("role") in ROLES]
    first = [*original_metrics, *[r for r in metrics if r not in second]]
    jobs = [read(p) for p in (output / "jobs").glob("*.json")]
    second_calls = sum(j["calls"] for j in jobs if str(j.get("binding", {}).get("assessment_cycle", "")).startswith("second_pass"))
    source_calls=read(output/"source-review.json").get("calls",0) if (output/"source-review.json").is_file() else 0
    first_calls = sum(j["calls"] for j in jobs)-second_calls+source_calls+(len(original_metrics) if original_calls is None else original_calls)
    all_roles = {r.get("role", "investigator") for r in [*first, *second]}
    summary["accounting"] = {"first_pass":accounting(first, all_roles, rates, first_calls),
        "second_pass":accounting(second, all_roles, rates, second_calls),
        "combined":accounting([*first, *second], all_roles, rates, first_calls+second_calls)}
    work = read(output / "work.json")["payload"]
    questions = {}
    for p in output.glob("context-*.json"):
        questions.update({r["review_id"]:r for r in read(p).get("native_questions", [])})
    final = read(output / "findings.json") if (output / "findings.json").is_file() else {}
    evidence = {r["response"]["review_id"]:r["response"].get("investigation", {}).get("decisive_artifacts", []) for r in final.get("decision_records", [])}
    labels = []
    for row in summary["results"]:
        labels.append({**{k:row[k] for k in ("review_id", "first_decision", "final_decision")},
            "second_pass":{k:row[k] for k in ("mode", "outcome", "proof_status", "investigation_status", "error_codes")},
            "label_authority":"model_reviewed" if row["outcome"] != "not_checked" else "first_pass_only",
            "training_status":"excluded" if row["outcome"] in ("not_checked", "reopened") or row["proof_status"] != "supported" else "candidate",
            "snapshot_id":work["snapshot_id"], "inventory_input_fingerprint":work["inventory_input_fingerprint"],
            "repository":work["repository"], "runtime":work["runtime"], "evidence_claim":row["claim"],
            "question":{k:questions.get(row["review_id"], {}).get(k) for k in ("rule_id", "capability", "path", "line")},
            "evidence_references":[{"artifact_id":r["artifact_id"], "location":r["location"]} for r in evidence.get(row["review_id"], [])],
            "stages":row["stages"], "trajectory_root":"training-turns/",
            "trajectory_ids":[s["trajectory_id"] for s in row["stages"] if s.get("trajectory_id")],
            "supervision":"actual_assistant_actions_only; source/controller tokens must be loss-masked"})
    write(output / "second-pass.json", summary)
    write(output / "training-labels.json", {"schema_version":"1", "auto_approved":False, "labels":labels})
    lines = ["# Second-pass review", "", f"Mode: {summary['mode']}. Status: {summary['status']}. Checked {summary['checked']}/{summary.get('targeted', summary['selected'])} targeted; {summary['selected']} first-pass claims, {summary.get('outside_scope', 0)} outside scope.",
        "", " · ".join(f"{key}: {value}" for key,value in summary["outcomes"].items()), "",
        "| Review ID | First | Final | Second pass | Detail |", "| --- | --- | --- | --- | --- |"]
    def cell(value):
        return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    for row in summary["results"]:
        lines.append("| " + " | ".join(cell(row[k]) for k in ("review_id", "first_decision", "final_decision", "outcome", "claim")) + " |")
    lines += ["", "Model-reviewed outcomes are not semantic ground truth; training labels require separate approval.", ""]
    for phase, values in summary["accounting"].items():
        lines.append(f"{phase}: {values['calls']} calls; input {values['usage']['input_tokens']}; cached {values['usage']['cached_input_tokens']}; output {values['usage']['output_tokens']}; cost {values['cost']} ({values['cost_basis']}).")
    (output / "second-pass.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
