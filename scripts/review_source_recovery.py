"""Source-phase checkpoints. Recorded responses never authorize a paid replay."""
import copy
from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3

import review_budget
import review_context as context
import review_work
from review_case_state import CaseState

VERSION = "mehscanSourceRecovery/v1"


def seal(stage, binding, budget_path, lineage_output, worker):
    budget = worker.read(budget_path)
    record = {"schema_version":VERSION, "binding":binding, "budget_path":str(budget_path),
        "lineage_output":str(lineage_output), "budget_policy":review_work._handoff_budget_policy(budget),
        "plans":{name:worker.digest_file(stage / name) for name in ("plan.json", "work-plan.json")},
        "usage_floor":usage_floor(budget)}
    if (stage / "resolution-plan.json").is_file():
        record["resolution_plan_sha256"] = worker.digest_file(stage / "resolution-plan.json")
    if (stage / "continuation.json").is_file():
        record["continuation_sha256"] = worker.digest_file(stage / "continuation.json")
    worker.write(stage / "source-recovery.json", record)
    return record


def usage_floor(budget):
    return {"reserved_calls":budget["reserved_calls"], "observed_input_tokens":budget["observed_input_tokens"],
            "cost_micros":budget.get("cost", {}).get("observed_micros", 0), "fenced":budget["fenced"]}


def check_floor(budget, floor):
    current = usage_floor(budget)
    if any(current[key] < floor[key] for key in current):
        raise ValueError("source recovery cannot reset prior usage or fences")


def restore(parent, stage, binding, root, worker):
    parent = worker.outside(parent, root)
    if stage.resolve().is_relative_to(parent) or parent.is_relative_to(stage.resolve()):
        raise ValueError("source recovery requires a separate sibling attempt")
    old = parent / "source-review"
    if (old / "continued-to.json").exists():
        raise ValueError("source attempt already continued; resume from the latest attempt instead")
    record = worker.read(old / "source-recovery.json")
    if record.get("schema_version") != VERSION or record["binding"] != binding:
        raise ValueError("source recovery source/work/provider/controller binding changed")
    if set(record.get("plans", {})) != {"plan.json", "work-plan.json"}:
        raise ValueError("source recovery requires both bound plans")
    if record.get("resolution_plan_sha256"):
        path = old / "resolution-plan.json"
        if path.is_symlink() or worker.digest_file(path) != record["resolution_plan_sha256"]:
            raise ValueError("scoped resolution plan changed")
        shutil.copyfile(path, stage / "resolution-plan.json")
    if record.get("continuation_sha256"):
        path = old / "continuation.json"
        if path.is_symlink() or worker.digest_file(path) != record["continuation_sha256"]:
            raise ValueError("Comprehensive continuation binding changed")
        shutil.copyfile(path, stage / path.name)
    for name, digest in record["plans"].items():
        if name not in ("plan.json", "work-plan.json") or worker.digest_file(old / name) != digest:
            raise ValueError("source recovery plan changed")
        if worker.digest_file(stage / name) != digest:
            raise ValueError("source recovery current plan differs")
    if Path(record["budget_path"]).is_symlink():
        raise ValueError("source recovery allowance cannot be redirected")
    budget_path = worker.outside(record["budget_path"], root)
    budget = worker.read(budget_path)
    if review_work._handoff_budget_policy(budget) != record["budget_policy"]:
        raise ValueError("source recovery cannot replace its original allowance")
    check_floor(budget, record["usage_floor"])
    copy_artifacts(old, stage, budget, worker)
    return record


def copy_artifacts(old, stage, budget, worker):
    if old.is_symlink() or (hasattr(old, "is_junction") and old.is_junction()):
        raise ValueError("source recovery state cannot be redirected")
    # The controller lock excludes another live controller. Copy bytes, not
    # filesystem metadata, and never follow links inside the old attempt.
    for directory in ("jobs", "preparation", "case-results"):
        source = old / directory
        if not source.exists():
            continue
        for path in [source, *source.rglob("*")]:
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise ValueError("source recovery artifacts cannot contain links")
            target = stage / path.relative_to(old)
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                if path.name == "recovery.json":
                    check_floor(budget, worker.read(path)["usage_floor"])
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
    for name in ("case-state.sqlite", "question-budget.json"):
        path = old / name
        if path.exists():
            if path.is_symlink():
                raise ValueError("source recovery state cannot be redirected")
            if name == "case-state.sqlite":
                # A killed transaction can leave a hot journal. SQLite recovers
                # committed state before backup; a bare file copy loses that journal.
                with closing(sqlite3.connect(path)) as source_db, closing(sqlite3.connect(stage / name)) as target_db:
                    source_db.backup(target_db)
            else:
                shutil.copyfile(path, stage / name)


def extend_scope(parent, stage, root, package, plan, registry, binding, worker):
    """Authorize a wider target from an admitted Value checkpoint, before dispatch."""
    parent = worker.outside(parent, root)
    audit = worker.read(parent / "worker.json").get("work_followup")
    if audit:
        parent = worker.outside(audit.get("correction_attempt") or audit["parent_attempt"], root)
    old = parent / "source-review"
    if stage.resolve().is_relative_to(parent) or parent.is_relative_to(stage.resolve()):
        raise ValueError("Comprehensive continuation requires a separate attempt directory")
    if (old / "continued-to.json").exists():
        raise ValueError("source attempt already continued; use its successor")
    correction = None
    native_parent = parent
    if (old / "resolution-handoff.json").is_file():
        correction, _, native_parent = review_work.read_resolution_handoff(parent, root, worker)
    handoff, summary, budget_path = review_work.read_handoff(native_parent, root, worker)
    finished = worker.read(native_parent / "worker.json")
    if not finished.get("native_admission"):
        raise ValueError("Comprehensive continuation requires a published Value attempt")
    previous = worker.read(native_parent / "source-review/work.json")["payload"]
    current = package["payload"]
    if previous["policy"] != "value" or current["policy"] != "comprehensive":
        raise ValueError("Comprehensive continuation requires Value followed by Comprehensive")
    if previous.get("impact_scope") is not None or current.get("impact_scope") is not None:
        raise ValueError("Comprehensive continuation requires a full-repository plan")
    if any(previous[key] != current[key] for key in ("snapshot_id", "inventory_input_fingerprint",
                                                     "repository", "assessment_context")):
        raise ValueError("Comprehensive continuation requires the same effective source inventory")
    record = worker.read(old / "source-recovery.json")
    if (old / "plan.json").is_symlink() or worker.digest_file(old / "plan.json") != record["plans"]["plan.json"]:
        raise ValueError("Value source plan changed")
    original = record["binding"]
    if any(original[key] != binding[key] for key in ("store", "stream", "scanner_sha256", "commands")):
        raise ValueError("Comprehensive continuation requires the original store, stream and reviewer")
    if original["options"]["include_supporting_source"] != binding["options"]["include_supporting_source"]:
        raise ValueError("Comprehensive continuation requires the original supporting-source scope")
    input_path = old / "input-work.json"
    if not input_path.is_file():
        frame = next((old / "jobs").glob("*/0-input.json"), None)
        if frame is None:
            raise ValueError("Value attempt lacks its original source work package")
        input_path = worker.outside(worker.read(frame)["work_package"], root)
    original_work = worker.read(input_path)
    if (original_work["package_id"] != summary["parent_work_package_id"]
            or context.digest(original_work) != original["package_digest"]):
        raise ValueError("Value source work package changed")
    original_payload = original_work["payload"]
    if {**original_payload["runtime"], "policy":"comprehensive"} != current["runtime"]:
        raise ValueError("Comprehensive continuation requires the original review runtime")
    old_registry = worker.read(old / "work-plan.json")
    if summary["source_fingerprint"] != plan["source_fingerprint"]:
        raise ValueError("Comprehensive continuation source changed")
    new_items = {item["id"]:item for item in registry["items"]}
    windows = {a["id"]:a["windows"] for a in plan["assignments"]}
    old_windows = {a["id"]:a["windows"] for a in worker.read(old / "plan.json")["assignments"]}
    ignored = {"ordinal", "assignment_id", "priority", "estimate", "readiness", "blocked_reason"}

    def scope(item):
        return {k:v for k,v in item.items() if k not in ignored}

    def premises(payload, item, window_map):
        paths = [w["path"] for w in window_map[item["assignment_id"]]]
        return [row for row in context.compact_work(payload, item["verify_review_ids"],
                source_paths=paths).get("knowledge", []) if row.get("author") != "mehscan:review"]

    case_binding = (correction or handoff)["case_binding"]
    case_state = CaseState(old / "case-state.sqlite", case_binding)
    saved = {row["case_id"]:row for row in case_state.results()}
    for item in old_registry["items"]:
        successor = new_items.get(item["id"])
        if successor is None or scope(item) != scope(successor):
            raise ValueError("Comprehensive work plan must keep prior case identities and questions")
        if item["id"] in saved and premises(original_payload, item, old_windows) != premises(current, successor, windows):
            raise ValueError("applicable Value knowledge changed; review the affected checks on current evidence")
    if not set(old_registry["coverage_limits"]) <= set(registry["coverage_limits"]):
        raise ValueError("Comprehensive work plan must retain prior coverage limits")
    parents = {row["decision_id"]:row for row in current["parent_decisions"]}
    heads, changed = {}, []
    for row in worker.read(native_parent / "findings.json").get("decision_records", []):
        rid = row["response"]["review_id"]
        if rid not in summary["assessments"]:
            raise ValueError("Value finding is outside its saved assessment scope")
        if rid not in current["planned_review_ids"]:
            continue  # The current native policy may exclude this exact question.
        expected = current["expected_parents"].get(rid, [])
        if (len(expected) != 1 or (head := parents.get(expected[0])) is None
                or head["inventory_input_fingerprint"] != current["inventory_input_fingerprint"]
                or head["response"]["review_id"] != rid):
            raise ValueError("Value native decision is missing, conflicting or from a different source")
        heads[rid] = expected[0]
        if heads[rid] != row["decision_id"]:
            changed.append(rid)
    if current.get("evidence_updates"):
        raise ValueError("Resolve new native evidence before continuing into Comprehensive")
    old_items = {item["id"] for item in old_registry["items"]}
    if any(set(item["verify_review_ids"]).intersection(heads) for item in registry["items"]
            if item["id"] not in old_items):
        raise ValueError("New Comprehensive cases must leave prior native decisions to the audit stage")
    budget = review_budget.snapshot(budget_path)
    if any(row["status"] == "reserved" for row in budget["leases"].values()):
        raise ValueError("Settle the Value allowance before continuing into Comprehensive")
    copy_artifacts(old, stage, budget, worker)
    question_cases = {rid:cases for rid, cases in summary.get("question_cases", {}).items() if rid in heads}
    continuation = {"parent":str(parent), "case_binding":case_binding,
        "cases":sorted(saved), "heads":heads, "reconsider_native_ids":sorted(changed),
        "spent_calls":budget["reserved_calls"],
        "case_assignments":{case:new_items[case]["assignment_id"] for case in saved},
        "question_cases":question_cases,
        "followups":[row for row in summary.get("followups", []) if row["review_id"] in heads and row["review_id"] not in changed],
        "claim_contexts":[row for row in summary.get("claim_contexts", []) if row["review_id"] in heads and row["review_id"] not in changed]}
    worker.write(stage / "continuation.json", continuation)
    return continuation, Path(budget_path)


def claim_successor(parent, stage, worker):
    """The stream lock serializes the claim before any replacement admission."""
    path = Path(parent) / "source-review/continued-to.json"
    if path.exists():
        raise ValueError("source attempt already continued; resume from the latest attempt instead")
    worker.write(path, {"output":str(stage.parent)})


def checkpoint(path, binding, worker):
    if not path.is_file():
        return None
    state = worker.read(path)
    if state.get("binding") != binding:
        raise ValueError("source job recovery binding changed")
    return state


def save(path, binding, phase, values, budget_path, worker):
    worker.write(path, {"binding":binding, "phase":phase, **copy.deepcopy(values),
                        "usage_floor":usage_floor(review_budget.snapshot(budget_path))})


def settle_interrupted(stage, budget_path, worker):
    """A known receipt settles once; an unattributed reserved turn fences admission."""
    by_lease = {}
    for path in (stage / "jobs").glob("*/recovery.json"):
        state = worker.read(path)
        if state.get("lease"):
            frame = worker.read(path.parent / (str(state["turn"]) + "-input.json"))
            receipt = worker.observed_turn(path.parent, frame["research"] | {
                "conversation_id":frame["conversation_id"]}, state["provider"], require_complete_usage=False)
            by_lease[state["lease"]] = receipt
    for lease, row in review_budget.snapshot(budget_path)["leases"].items():
        if row["status"] == "reserved":
            review_budget.finish(budget_path, lease, by_lease.get(lease))


def receipts(stage, worker):
    """Read original turn counters once, retaining case attribution."""
    rows = []
    seen = set()
    for directory in (stage / "jobs").iterdir() if (stage / "jobs").is_dir() else []:
        context = directory / "context.json"
        case_id = worker.read(context).get("work_item", {}).get("id") if context.is_file() else None
        for path in directory.glob("provider-metrics-*.jsonl"):
            for line in path.read_text(encoding="utf8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                key = (row.get("conversation_id"), row.get("round"))
                if key in seen:
                    raise ValueError("duplicate source recovery receipt")
                seen.add(key)
                if case_id:
                    row["work_item_id"] = case_id
                rows.append(row)
    return rows
