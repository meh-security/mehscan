"""Bounded dispatch for independent native-candidate and AI-discovery queues."""

from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import review_budget


def deferred(job, reason):
    return {"assignment_id": job["id"], "status": "deferred",
            "review_ids": job.get("review_ids", []), "error": "BudgetExhausted",
            "detail": reason, "queries": 0, "bytes": 0, "calls": 0,
            "unknown_provider_calls": 0, "seconds": 0}


def run(queues, execute, *, workers, budget_path):
    """Yield (job, result), retaining untouched jobs as explicit zero-call deferrals.

    Each job owns its investigation and reserves every turn in its assigned lane.
    A queue is drained only when no pending or active jobs remain. Partial jobs
    are never retried if their lane's allocation later grows.
    """
    if set(queues) - {"native", "ai"} or type(workers) is not int or not 1 <= workers <= 16:
        raise ValueError("scheduler requires native/ai queues and one to sixteen workers")
    pending = {lane: deque(queues.get(lane, [])) for lane in ("native", "ai")}
    active = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while any(pending.values()) or active:
            for lane in pending:
                if not pending[lane] and not any(value[0] == lane for value in active.values()):
                    review_budget.complete_lane(budget_path, lane)
            while len(active) < workers:
                state = review_budget.snapshot(budget_path)
                available = [lane for lane in pending if pending[lane]
                             and review_budget.capacity(budget_path, lane) is None]
                if not available:
                    break
                def progress(lane):
                    allocation = state.get("lanes", {}).get(lane, {})
                    # Active jobs break ties before their first call is reserved.
                    weight = max(1, allocation.get("allocation", 1))
                    starting = sum(value[0] == lane for value in active.values())
                    return (allocation.get("reserved_calls", 0) + starting) / weight
                lane = min(available, key=progress)
                job = pending[lane].popleft()
                active[pool.submit(execute, job)] = (lane, job)
            if active:
                completed, _ = wait(active, return_when=FIRST_COMPLETED)
                for future in completed:
                    lane, job = active.pop(future)
                    result = future.result()
                    if not pending[lane] and not any(value[0] == lane for value in active.values()):
                        review_budget.complete_lane(budget_path, lane)
                    yield job, result
                continue
            # No live call can free reservation headroom or drain another queue.
            # Keep all remaining IDs visible; they are not reviewed safe.
            for lane, jobs in pending.items():
                reason = review_budget.capacity(budget_path, lane) or "review dispatch stopped"
                while jobs:
                    job = jobs.popleft()
                    yield job, deferred(job, reason)
            break
