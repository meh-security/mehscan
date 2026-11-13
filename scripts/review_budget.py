"""Cross-process admission gate for a bounded review, using observed input usage."""

from contextlib import contextmanager
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import json
import math
import os
from pathlib import Path
import time
import uuid

MAX_CALLS = 40
MAX_INPUT = 1_500_000
RESERVATION = 100_000
MAX_CALL_INPUT = 250_000
ADMISSION_SECONDS = 20 * 60


def decimal(value, label):
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        raise ValueError(label + " must be a finite nonnegative number") from None
    if isinstance(value, bool) or not result.is_finite() or result < 0:
        raise ValueError(label + " must be a finite nonnegative number")
    return result


def cost_policy(limit, rates, output_reservation=16000):
    keys = {"input_per_million", "cached_input_per_million", "output_per_million"}
    if not isinstance(rates, dict) or set(rates) != keys:
        raise ValueError("cost rates require ordinary input, cached input and output rates")
    normalized = {key: str(decimal(rates[key], key)) for key in keys}
    amount = decimal(limit, "cost allowance")
    if amount <= 0 or type(output_reservation) is not int or output_reservation < 1:
        raise ValueError("cost allowance and output reservation must be positive")
    micros = lambda value: int(value.to_integral_value(rounding=ROUND_CEILING))
    return {"currency": "USD", "limit_micros": micros(amount * 1_000_000), "rates": normalized,
            "output_reservation": output_reservation,
            "reservation_micros": micros(Decimal(MAX_CALL_INPUT) * max(Decimal(normalized[key]) for key in
                ("input_per_million", "cached_input_per_million")) + Decimal(output_reservation) * Decimal(normalized["output_per_million"])),
            "observed_micros": 0, "complete": True,
            "basis": "Configured-rate estimate, not an invoice. Unreported cache writes and host work are excluded; reservations and observed fences are not hard currency caps."}


def estimate_cost(usage, rates):
    values = [usage.get(key) for key in ("input_tokens", "cached_input_tokens", "output_tokens")]
    if any(type(value) is not int or value < 0 for value in values) or values[1] > values[0]:
        return None
    ordinary, cached, output = values[0] - values[1], values[1], values[2]
    total = (ordinary * Decimal(rates["input_per_million"]) + cached * Decimal(rates["cached_input_per_million"])
             + output * Decimal(rates["output_per_million"]))
    return int(total.to_integral_value(rounding=ROUND_CEILING))


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
               native_percent=None, max_call_input_tokens=MAX_CALL_INPUT, cost=None, started_at=None):
    for name, value in (("max_calls", max_calls), ("input_limit", input_limit),
                        ("reservation_per_call", reservation_per_call),
                        ("max_call_input_tokens", max_call_input_tokens)):
        if type(value) is not int or value < 1:
            raise ValueError(name + " must be a positive integer")
    if (type(admission_seconds) not in (int, float) or not math.isfinite(admission_seconds)
            or admission_seconds <= 0):
        raise ValueError("admission_seconds must be positive and finite")
    if native_percent is not None and (type(native_percent) not in (int, float)
            or not math.isfinite(native_percent) or not 0 <= native_percent <= 100):
        raise ValueError("native_percent must be between zero and one hundred")
    if started_at is not None and (type(started_at) not in (int, float) or not math.isfinite(started_at) or started_at <= 0):
        raise ValueError("review start time must be positive and finite")
    with locked(path):
        if Path(path).exists():
            raise ValueError("review budget already exists; never reset a live ledger")
        state = {"schema_version": 1, "deadline_epoch": (time.time() if started_at is None else started_at) + admission_seconds,
                      "max_calls": max_calls, "input_limit": input_limit,
                      "reservation_per_call": reservation_per_call, "reserved_calls": 0,
                      "max_call_input_tokens": max_call_input_tokens,
                      "observed_input_tokens": 0, "leases": {}, "fenced": False,
                      "limitations": "Observed input limit with in-flight reservation headroom; a provider call can exceed its reservation."}
        if cost is not None:
            state["cost"] = cost
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
        return state.get("fence_reason", "unknown usage or oversized prior call fenced the review")
    if time.time() >= state["deadline_epoch"]:
        return "review new-call admission deadline reached"
    if state["reserved_calls"] >= state["max_calls"]:
        return "review provider-call limit reached"
    active = sum(entry["status"] == "reserved" for entry in state["leases"].values())
    cost = state.get("cost")
    if cost and cost["observed_micros"] + (active + 1) * cost["reservation_micros"] > cost["limit_micros"]:
        return "review estimated cost allowance and in-flight reservation reached"
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
        cost = state.get("cost")
        if cost:
            cost_known = isinstance(usage, dict) and isinstance(unknown, list) and not set(unknown).intersection(
                ("input_tokens", "cached_input_tokens", "output_tokens"))
            amount = estimate_cost(usage, cost["rates"]) if cost_known else None
            entry["estimated_cost_micros"] = amount
            if amount is None:
                cost["complete"] = False
                state["fenced"] = True
                state["fence_reason"] = "provider cost counters unknown; estimated allowance fenced"
            else:
                cost["observed_micros"] += amount
                if (cost["observed_micros"] > cost["limit_micros"]
                        or usage["output_tokens"] > cost["output_reservation"]):
                    state["fenced"] = True
                    state["fence_reason"] = ("observed estimated cost allowance exceeded" if cost["observed_micros"] > cost["limit_micros"]
                        else "provider output exceeded the cost reservation; new calls fenced")
        # Reservation estimates concurrent headroom; it is not the per-call fence.
        # Existing ledgers retain the threshold with which they were initialized.
        call_limit = state.get("max_call_input_tokens", state["reservation_per_call"])
        if (not known or tokens > call_limit
                or state["observed_input_tokens"] > state["input_limit"]):
            state["fenced"] = True
        _write(path, state)
    return known
