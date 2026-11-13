"""Source-phase checkpoints. Recorded responses never authorize a paid replay."""
import copy
from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3

import review_budget
import review_work

VERSION = "mehscanSourceRecovery/v1"


def seal(stage, binding, budget_path, lineage_output, worker):
    budget = worker.read(budget_path)
    record = {"schema_version":VERSION, "binding":binding, "budget_path":str(budget_path),
        "lineage_output":str(lineage_output), "budget_policy":review_work._handoff_budget_policy(budget),
        "plans":{name:worker.digest_file(stage / name) for name in ("plan.json", "work-plan.json")},
        "usage_floor":usage_floor(budget)}
    if (stage / "resolution-plan.json").is_file():
        record["resolution_plan_sha256"] = worker.digest_file(stage / "resolution-plan.json")
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
    return record


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
