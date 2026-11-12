"""Cross-process admission gate for a bounded review, using observed input usage."""

from contextlib import contextmanager
import json
import math
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


def initialize(path, *, max_calls=MAX_CALLS, input_limit=MAX_INPUT,
               reservation_per_call=RESERVATION, admission_seconds=ADMISSION_SECONDS,
               native_percent=None):
    for name, value in (("max_calls", max_calls), ("input_limit", input_limit),
                        ("reservation_per_call", reservation_per_call)):
        if type(value) is not int or value < 1:
            raise ValueError(name + " must be a positive integer")
    if (type(admission_seconds) not in (int, float) or not math.isfinite(admission_seconds)
            or admission_seconds <= 0):
        raise ValueError("admission_seconds must be positive and finite")
    if native_percent is not None and (type(native_percent) not in (int, float)
            or not math.isfinite(native_percent) or not 0 <= native_percent <= 100):
        raise ValueError("native_percent must be between zero and one hundred")
    with locked(path):
        if Path(path).exists():
            raise ValueError("review budget already exists; never reset a live ledger")
        state = {"schema_version": 1, "deadline_epoch": time.time() + admission_seconds,
                      "max_calls": max_calls, "input_limit": input_limit,
                      "reservation_per_call": reservation_per_call, "reserved_calls": 0,
                      "observed_input_tokens": 0, "leases": {}, "fenced": False,
                      "limitations": "Observed input limit with in-flight reservation headroom; a provider call can exceed its reservation."}
        if native_percent is not None:
            native_calls = int(max_calls * native_percent / 100 + 0.5)
            state["native_percent"] = native_percent
            state["lanes"] = {
                "native": {"enabled": native_percent > 0, "allocation": native_calls,
                           "reserved_calls": 0, "complete": False},
                "ai": {"enabled": native_percent < 100, "allocation": max_calls - native_calls,
                       "reserved_calls": 0, "complete": False},
            }
        _write(path, state)


def snapshot(path):
    with locked(path):
        return json.loads(Path(path).read_text(encoding="utf8"))


def _admission_reason(state, lane=None):
    if state["fenced"]:
        return "unknown usage or oversized prior call fenced the review"
    if time.time() >= state["deadline_epoch"]:
        return "review new-call admission deadline reached"
    if state["reserved_calls"] >= state["max_calls"]:
        return "review provider-call limit reached"
    active = sum(entry["status"] == "reserved" for entry in state["leases"].values())
    reservation = state["reservation_per_call"]
    if state["observed_input_tokens"] + (active + 1) * reservation > state["input_limit"]:
        return "review observed input limit and in-flight headroom reached"
    if lane is not None and state.get("lanes"):
        if lane not in state["lanes"]:
            raise ValueError("unknown review budget lane")
        selected = state["lanes"][lane]
        if not selected["enabled"]:
            return lane + " queue is outside the requested allocation mode"
        if selected["complete"]:
            return lane + " queue was already completed"
        if selected["reserved_calls"] >= selected["allocation"]:
            return lane + " queue call allocation reached"
    return None


def capacity(path, lane=None):
    """A scheduling hint; reserve still performs the atomic admission check."""
    return _admission_reason(snapshot(path), lane)


def complete_lane(path, lane):
    """Transfer unused calls only after the scheduler drains a queue and its jobs."""
    with locked(path):
        state = json.loads(Path(path).read_text(encoding="utf8"))
        lanes = state.get("lanes", {})
        if lane not in lanes:
            return
        selected = lanes[lane]
        if selected["complete"]:
            return
        selected["complete"] = True
        other = lanes["ai" if lane == "native" else "native"]
        if other["enabled"] and not other["complete"]:
            unused = selected["allocation"] - selected["reserved_calls"]
            selected["allocation"] -= unused
            other["allocation"] += unused
        _write(path, state)


def reserve(path, kind, lane=None):
    with locked(path):
        state = json.loads(Path(path).read_text(encoding="utf8"))
        reason = _admission_reason(state, lane)
        if reason:
            raise BudgetExhausted(reason)
        lease = uuid.uuid4().hex
        state["reserved_calls"] += 1
        state["leases"][lease] = {"kind": kind, "status": "reserved", "reserved_at": time.time()}
        if lane is not None:
            state["leases"][lease]["lane"] = lane
            if state.get("lanes"):
                state["lanes"][lane]["reserved_calls"] += 1
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
        if (not known or tokens > state["reservation_per_call"]
                or state["observed_input_tokens"] > state["input_limit"]):
            state["fenced"] = True
        _write(path, state)
    return known
