#!/usr/bin/env python3
"""Bound Codex review adapter. Model research is returned to the native broker."""
import argparse
import hashlib
import json
import errno
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import time
import uuid

from codex_launcher import Launcher, cancel, file_digest, load_config, provider_contract
from codex_protocol import build_prompt, build_schema, envelope


def read(path):
    if Path(path).stat().st_size > 8 * 1024 * 1024:
        raise ValueError("provider input exceeds bounded intake")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, value):
    pending = path.with_suffix(".tmp")
    pending.write_text(json.dumps(value, indent=2), encoding="utf-8")
    pending.replace(path)


CODE_MODE_DISABLED_NOTICE = (
    "Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; "
    "enable `features.code_mode_host` and install `codex-code-mode-host`."
)


def parse_events(raw, old_thread=None):
    thread, usage, completed, started = old_thread, None, False, False
    for line in raw.splitlines():
        event = json.loads(line)
        kind = event.get("type")
        if kind == "thread.started":
            candidate = str(uuid.UUID(event["thread_id"]))
            if old_thread and candidate != old_thread:
                raise ValueError("provider resumed a different thread")
            thread = candidate
        elif kind in ("item.started", "item.updated", "item.completed"):
            # Current clients label this intentional disabled-tool startup notice
            # as an error item. It is not a model action or a failed turn.
            if (kind == "item.completed" and not started and not completed and thread
                    and event["item"]["type"] == "error"
                    and event["item"].get("message") == CODE_MODE_DISABLED_NOTICE):
                continue
            if event["item"]["type"] not in ("agent_message", "reasoning"):
                raise ValueError("provider attempted a tool outside the native broker")
        elif kind == "turn.completed":
            completed = True
            usage = {key: value for key, value in event.get("usage", {}).items()
                     if key in ("input_tokens", "cached_input_tokens", "output_tokens")
                     and type(value) is int and 0 <= value <= 2**63 - 1}
        elif kind in ("turn.failed", "error"):
            raise RuntimeError("provider turn failed")
        elif kind == "turn.started":
            started = True
        else:
            raise ValueError("unsupported provider event")
    if not thread or not completed:
        raise ValueError("provider did not finish an exact conversation")
    return thread, usage


def usage_delta(current, previous, resumed):
    """Codex completion counters accumulate across the exact resumed thread."""
    delta, unknown = {}, []
    for key, total in (current or {}).items():
        if not resumed:
            delta[key] = total
        elif key not in (previous or {}) or total < previous[key]:
            # Missing baseline or a counter reset cannot establish this turn's cost.
            unknown.append(key)
        else:
            delta[key] = total - previous[key]
    return delta, unknown


def initialize_store(private, expected):
    """Publish the initialized directory atomically for parallel first jobs."""
    marker = private / "mehscan-provider.json"
    if not private.exists():
        private.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix="." + private.name + "-", dir=private.parent))
        try:
            staging.chmod(0o700)
            save(staging / marker.name, expected)
            try:
                os.rename(staging, private)
            except OSError as error:
                if error.errno not in (errno.EEXIST, errno.ENOTEMPTY) and not isinstance(error, FileExistsError):
                    raise
        finally:
            if staging.exists():
                import shutil
                shutil.rmtree(staging)
    if not marker.is_file() or read(marker) != expected:
        raise ValueError("private provider directory is not an initialized compatible store")
    private.chmod(0o700)


def run(config, task, launcher_factory=Launcher):
    started = time.monotonic()
    packet, facts_file = read(task["evidence_packet"]), read(task["shared_facts"])
    facts = facts_file["facts"]
    expected = provider_contract(config)
    runtime = packet["work"]["runtime"]
    profile = task.get("profile", "routine")
    role = task.get("review_role", "investigator")
    quality = (runtime.get("orchestration") or {}).get("quality") or {}
    if role not in ("investigator", "verification", "adjudication", "final_qa") or (
            role in ("adjudication", "final_qa") and (profile != "expert" or not quality.get(
                "adjudicate_disagreements" if role == "adjudication" else "final_qa"))):
        raise ValueError("review role is not enabled by the native runtime")
    allowed = runtime.get("provider") if profile == "routine" else (runtime.get("orchestration") or {}).get("expert") if profile == "expert" else None
    if allowed != expected:
        raise ValueError("provider configuration differs from the native work binding")
    if runtime.get("orchestration") and packet.get("job_binding") != {
            "profile": profile, "role": task.get("review_role", "investigator"), "provider": expected}:
        raise ValueError("job provider/role differs from its native runtime profile")
    root = Path(task["source_root"]).resolve(strict=True)
    public = Path(task["evidence_packet"]).resolve(strict=True).parent
    artifact_root = Path(task.get("artifact_root", public)).resolve(strict=True)
    private = Path(config["private_directory"]).resolve()
    if private.is_relative_to(root) or private.is_relative_to(artifact_root):
        raise ValueError("provider sessions/auth must stay outside source and exported artifacts")
    for path in (config["auth_file"], config["executable"]):
        if Path(path).resolve(strict=True).is_relative_to(root):
            raise ValueError("provider code/auth cannot come from target source")
    if Path(config["auth_file"]).resolve(strict=True).is_relative_to(artifact_root):
        raise ValueError("provider authentication cannot be an exported artifact")
    conversation = task["conversation_id"]
    if not isinstance(conversation, str) or not re.fullmatch(r"[0-9a-f]{64}", conversation):
        raise ValueError("invalid native conversation identity")
    initialize_store(private, expected)
    metrics_path = Path(task.get("provider_metrics", public / "provider-metrics.jsonl")).resolve()
    if not metrics_path.is_relative_to(public) or metrics_path.parent != public:
        raise ValueError("provider metrics must stay in the public conversation artifact directory")
    session = private / conversation
    session.mkdir(exist_ok=True)
    session.chmod(0o700)
    state_path = session / "conversation.json"
    state = read(state_path) if state_path.exists() else None
    packet_hash = file_digest(task["evidence_packet"])
    schema = build_schema(task)
    round_index = task["research"]["round"]
    if type(round_index) is not int or not 0 <= round_index <= 10:
        raise ValueError("invalid native research round")
    # Source/query handles grow as the native broker returns inspected facts.
    # Pin the protocol and exact question IDs; constrain each turn's output to
    # its current handles without treating new evidence as a new conversation.
    binding = {"packet_sha256": packet_hash, "provider": expected, "schema": build_schema(task, bound_handles=False)}
    if state:
        if state["binding"] != binding or round_index != state["round"] + 1:
            raise ValueError("provider continuation is stale or incompatible")
        uuid.UUID(state["thread_id"])
    elif round_index != 0:
        raise ValueError("cannot silently restart a missing provider continuation")
    log = session / ("round-" + str(round_index))
    log.mkdir(exist_ok=False)
    prompt = build_prompt(task, packet, facts, state)
    (log / "prompt.txt").write_text(prompt, encoding="utf-8")
    launcher = launcher_factory(config, session)
    response, events, stderr = launcher.review(prompt, schema, (state or {}).get("thread_id"), timeout=task["research"].get("seconds_remaining", 600))
    (log / "events.jsonl").write_text(events, encoding="utf-8")
    (log / "stderr.txt").write_text(stderr, encoding="utf-8")
    thread, usage = parse_events(events, (state or {}).get("thread_id"))
    result = envelope(response)
    delta, unknown = usage_delta(usage, state["reported_conversation_usage"] if state else None, state is not None)
    save(state_path, {"binding": binding, "round": round_index, "thread_id": thread,
                      "sent_facts": [fact["result_id"] for fact in facts], "sent_results": len(task["research"]["results"]),
                      "reported_conversation_usage":usage})
    metric = {"schema_version": "1", "provider": expected, "conversation_id": conversation, "round": round_index,
              "profile":profile, "role":task.get("review_role", "investigator"),
              "resumed": state is not None, "elapsed_ms": round((time.monotonic()-started)*1000),
              "prompt_bytes": len(prompt.encode()), "usage":delta, "usage_basis":"conversation_delta",
              "reported_conversation_usage":usage, "unknown_delta_counters":unknown}
    with metrics_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(metric) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--contract", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    if args.contract:
        print(json.dumps(provider_contract(config)))
    else:
        print(json.dumps(run(config, json.load(sys.stdin))))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGTERM, cancel)
    try:
        main()
    except Exception as error:
        print("BYOK Codex reviewer failed (" + type(error).__name__ + ").", file=sys.stderr)
        sys.exit(2)
