"""Cross-process admission gate for a bounded review, using observed input usage."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import time
import uuid

MAX_CALLS = 40
MAX_INPUT = 1_500_000
RESERVATION = 100_000
ADMISSION_SECONDS = 20 * 60


class BudgetExhausted(ValueError):
    pass


def _lock(handle, acquire):
    handle.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB if acquire else fcntl.LOCK_UN)


@contextmanager
def locked(path):
    path = Path(path)
    lock = path.with_suffix(path.suffix + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or lock.is_symlink():
        raise ValueError("review budget requires regular files")
    with lock.open("a+b") as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"0")
            handle.flush()
        while True:
            try:
                _lock(handle, True)
                break
            except OSError:
                time.sleep(0.05)
        try:
            yield
        finally:
            _lock(handle, False)


def _write(path, state):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf8") as handle:
        json.dump(state, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def initialize(path):
    with locked(path):
        if Path(path).exists():
            raise ValueError("review budget already exists; never reset a live ledger")
        _write(path, {"schema_version": 1, "deadline_epoch": time.time() + ADMISSION_SECONDS,
                      "max_calls": MAX_CALLS, "input_limit": MAX_INPUT,
                      "reservation_per_call": RESERVATION, "reserved_calls": 0,
                      "observed_input_tokens": 0, "leases": {}, "fenced": False,
                      "limitations": "Observed input limit with in-flight reservation headroom; a provider call can exceed its reservation."})


def reserve(path, kind):
    with locked(path):
        state = json.loads(Path(path).read_text(encoding="utf8"))
        if state["fenced"]:
            raise BudgetExhausted("unknown usage or oversized prior call fenced the review")
        if time.time() >= state["deadline_epoch"]:
            raise BudgetExhausted("review new-call admission deadline reached")
        active = sum(entry["status"] == "reserved" for entry in state["leases"].values())
        if state["reserved_calls"] >= MAX_CALLS:
            raise BudgetExhausted("review provider-call limit reached")
        if state["observed_input_tokens"] + (active + 1) * RESERVATION > MAX_INPUT:
            raise BudgetExhausted("review observed input limit and in-flight headroom reached")
        lease = uuid.uuid4().hex
        state["reserved_calls"] += 1
        state["leases"][lease] = {"kind": kind, "status": "reserved", "reserved_at": time.time()}
        _write(path, state)
        return lease


def finish(path, lease, receipt):
    """Unknown/oversized input fences future admissions, but lets active calls drain."""
    receipt = receipt if isinstance(receipt, dict) else {}
    usage = receipt.get("usage")
    tokens = usage.get("input_tokens") if isinstance(usage, dict) else None
    unknown = receipt.get("unknown_delta_counters", [])
    known = type(tokens) is int and tokens >= 0 and isinstance(unknown, list) and "input_tokens" not in unknown
    with locked(path):
        state = json.loads(Path(path).read_text(encoding="utf8"))
        entry = state["leases"][lease]
        if entry["status"] != "reserved":
            raise ValueError("review budget lease already settled")
        entry.update(status="settled" if known else "unknown", settled_at=time.time())
        if known:
            entry["input_tokens"] = tokens
            state["observed_input_tokens"] += tokens
        if not known or tokens > RESERVATION or state["observed_input_tokens"] > MAX_INPUT:
            state["fenced"] = True
        _write(path, state)
    return known
