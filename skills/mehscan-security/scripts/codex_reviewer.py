#!/usr/bin/env python3
"""Bound Codex review adapter. Model research is returned to the native broker."""
import argparse
import copy
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

from codex_launcher import Launcher, ProviderExecutionError, cancel, file_digest, load_config, provider_contract
from codex_protocol import build_prompt, build_schema, envelope, source_presentation_mode
from boundary_review import review_envelope
import workspace_protocol


def read(path):
    if Path(path).stat().st_size > 8 * 1024 * 1024:
        raise ValueError("provider input exceeds bounded intake")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, value):
    pending = path.with_suffix(".tmp")
    pending.write_text(json.dumps(value, indent=2), encoding="utf-8")
    pending.replace(path)


def json_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def inspect_candidate(config, request):
    """Read-only independent decision inspection. Never instantiate a launcher."""
    expected_keys = {"directory","session_id","round","candidate_sha256","packet_sha256","task_file_sha256","usage"}
    if not isinstance(request,dict) or set(request)!=expected_keys:
        raise ValueError("invalid candidate inspection request")
    sid, turn = request["session_id"],request["round"]
    if not isinstance(sid,str) or not re.fullmatch(r"[0-9a-f]{64}",sid) or type(turn) is not int or turn not in (0,1):
        raise ValueError("invalid candidate turn")
    directory = Path(request["directory"]).resolve(strict=True)
    manifest_path = directory / ("reply-candidate-"+sid+"-"+str(turn)+".json")
    if file_digest(manifest_path)!=request["candidate_sha256"]:
        raise ValueError("candidate rejection record changed")
    manifest = read(manifest_path)
    keys = {"schema_version","conversation_id","round","provider","task_sha256","task_file_sha256",
            "packet_sha256","facts_sha256","response_sha256","metric_sha256","diagnostic_sha256"}
    if (set(manifest)!=keys or manifest["schema_version"]!="mehscanRejectedCandidate/v1"
            or manifest["conversation_id"]!=sid or manifest["round"]!=turn or manifest["provider"]!=provider_contract(config)):
        raise ValueError("candidate binding differs")
    log = Path(config["private_directory"]) / sid / ("round-"+str(turn))
    if file_digest(log/"response.json")!=manifest["response_sha256"] or file_digest(log/"dispatched-task.json")!=manifest["task_file_sha256"]:
        raise ValueError("returned candidate or dispatched task changed")
    task,response = read(log/"dispatched-task.json"),read(log/"response.json")
    if json_digest(task)!=manifest["task_sha256"]:
        raise ValueError("dispatched task digest differs")
    if file_digest(directory/"task.json")!=request["task_file_sha256"] or file_digest(directory/"context.json")!=request["packet_sha256"]:
        raise ValueError("prepared candidate context changed")
    prepared = read(directory/"task.json")
    if {k:v for k,v in task.items() if k!="research"}!={k:v for k,v in prepared.items() if k!="research"}:
        raise ValueError("dispatched candidate assignment differs")
    runtime_fields = {"round","seconds_remaining","rounds_remaining","queries_remaining","bytes_remaining","workspace_budget","feedback"}
    if ({k:v for k,v in task["research"].items() if k not in runtime_fields} !=
            {k:v for k,v in prepared["research"].items() if k not in runtime_fields}):
        raise ValueError("dispatched candidate source handles differ")
    if task["conversation_id"]!=sid or task["research"]["round"]!=turn or Path(task["provider_metrics"]).resolve()!=directory/"provider-metrics.jsonl":
        raise ValueError("candidate task turn differs")
    for name,key in (("evidence_packet","packet_sha256"),("shared_facts","facts_sha256")):
        expected_file = directory / ("context.json" if name=="evidence_packet" else "facts.json")
        if Path(task[name]).resolve()!=expected_file or file_digest(expected_file)!=manifest[key]:
            raise ValueError("candidate packet/facts binding differs")
    diag_path = directory / ("reply-validation-"+sid+"-"+str(turn)+".json")
    if file_digest(diag_path)!=manifest["diagnostic_sha256"]:
        raise ValueError("candidate validation diagnostic changed")
    diagnostic = read(diag_path)
    if (diagnostic.get("kind")!="local_response_validation" or diagnostic.get("repairable_proof_references") is not True
            or diagnostic.get("task_sha256")!=manifest["task_sha256"] or diagnostic.get("conversation_id")!=sid
            or diagnostic.get("round")!=turn or diagnostic.get("artifact_handles")!=list(task["research"]["artifact_handles"])
            or diagnostic.get("source_artifact_handles")!=task["research"].get("source_artifact_handles",[])):
        raise ValueError("not an exact auxiliary-proof rejection")
    path = directory/"provider-metrics.jsonl"
    if path.stat().st_size>8*1024*1024:raise ValueError("candidate metrics exceed bounded intake")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows = [r for r in rows if r.get("conversation_id")==sid and r.get("round")==turn]
    if len(rows)!=1 or json_digest(rows[0])!=manifest["metric_sha256"] or rows[0].get("provider")!=manifest["provider"]:
        raise ValueError("candidate requires one unchanged usage receipt")
    row = rows[0]
    for key in ("input_tokens","cached_input_tokens","output_tokens","elapsed_ms"):
        value = row.get("elapsed_ms") if key=="elapsed_ms" else row.get("usage",{}).get(key)
        if type(value) is not int or value<0 or value!=request["usage"].get(key) or key in row.get("unknown_delta_counters",[]):
            raise ValueError("candidate provider usage is missing or differs")
    if row["usage"]["cached_input_tokens"]>row["usage"]["input_tokens"]:
        raise ValueError("invalid candidate cache counters")
    packet = read(directory/"context.json")
    if not workspace_protocol.enabled(task,packet):raise ValueError("candidate preview requires workspace actions")
    from jsonschema import Draft202012Validator
    validator = Draft202012Validator(workspace_protocol.schema(task))
    if not proof_reference_failure(response,validator,task) or not response.get("decisions"):
        raise ValueError("rejected response has no independently eligible decisions")
    decisions = response["decisions"]
    ids = [r["review_id"] for r in decisions]
    if len(ids)!=len(set(ids)) or not set(ids)<=set(task["review_ids"]):
        raise ValueError("candidate names duplicate or unassigned claims")
    requested = {rid for lookup in response["lookups"] for rid in lookup["review_ids"]}
    if set(ids)&requested:raise ValueError("candidate requests more deciding evidence for the same claim")
    for result in decisions:
        for citation in result["evidence"]:
            if not any(not window.get("clipped") and window["path"]==citation["path"]
                       and window["start_line"]<=citation["start_line"]<=citation["end_line"]<=window["end_line"]
                       for window in packet["primary"]["windows"]):
                raise ValueError("candidate cites unseen or clipped source")
    return {"decisions":decisions,"binding":manifest,"auxiliary_actions_accepted":False,"native_admission":False}


def review_intent(response):
    """Only proof references in auxiliary tables may change during correction."""
    intent = copy.deepcopy(response)
    def remove_artifacts(value):
        if isinstance(value,list):
            return [remove_artifacts(v) for v in value]
        if isinstance(value,dict):
            return {k:remove_artifacts(v) for k,v in value.items() if k!="artifacts"}
        return value
    if isinstance(intent,dict):
        for key in ("progress","boundary_checks"):
            if key in intent:intent[key] = remove_artifacts(intent[key])
        if isinstance(intent.get("updates"),list):
            intent["updates"] = [{k:v for k,v in u.items() if k!="evidence"} if isinstance(u,dict) else u for u in intent["updates"]]
    return hashlib.sha256(json.dumps(intent,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def proof_reference_failure(response, validator, task):
    """Classify with a disposable schema probe; never admit the probe as evidence."""
    candidate = copy.deepcopy(response); changed = False
    def probe(value, key, handles):
        nonlocal changed
        if isinstance(value,list):
            for v in value:probe(v,key,handles)
        elif isinstance(value,dict):
            if isinstance(value.get(key),list) and handles:
                for i,handle in enumerate(value[key]):
                    if isinstance(handle,str) and handle not in handles:
                        value[key][i] = handles[0];changed = True
            for k,v in value.items():
                if k!=key:probe(v,key,handles)
    if not isinstance(candidate,dict):return False
    probe(candidate.get("progress"),"artifacts",list(task["research"]["artifact_handles"]))
    source_handles = task["research"].get("source_artifact_handles",[])
    probe(candidate.get("boundary_checks"),"artifacts",source_handles)
    updates = candidate.get("updates",[])
    if not isinstance(updates,list):return False
    for update in updates:
        if isinstance(update,dict):probe(update,"evidence",source_handles)
    return changed and validator.is_valid(candidate)


def proof_correction_matches(original, corrected, task):
    """Only originally invalid reference slots may change, with no removals."""
    candidate = copy.deepcopy(original)
    def replace(value, other, key, handles):
        if isinstance(value,list) and isinstance(other,list) and len(value)==len(other):
            for a,b in zip(value,other):replace(a,b,key,handles)
        elif isinstance(value,dict) and isinstance(other,dict):
            refs = value.get(key)
            proposed = other.get(key)
            if isinstance(refs,list) and isinstance(proposed,list) and len(refs)==len(proposed):
                for i,old in enumerate(refs):
                    if isinstance(old,str) and old not in handles and proposed[i] in handles:
                        refs[i] = proposed[i]
            for k,v in value.items():
                if k!=key and k in other:replace(v,other[k],key,handles)
    for field,key,handles in (("progress","artifacts",list(task["research"]["artifact_handles"])),
                              ("boundary_checks","artifacts",task["research"].get("source_artifact_handles",[])),
                              ("updates","evidence",task["research"].get("source_artifact_handles",[]))):
        if field in candidate:replace(candidate[field],corrected.get(field),key,handles)
    return candidate == corrected


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
            names = {"input_tokens":"input_tokens", "cached_input_tokens":"cached_input_tokens",
                     "output_tokens":"output_tokens", "cache_write_input_tokens":"cache_write_tokens",
                     "reasoning_output_tokens":"reasoning_output_tokens"}
            usage = {names[key]: value for key, value in event.get("usage", {}).items()
                     if key in names
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
    presentation = source_presentation_mode(config)
    packet, facts_file = read(task["evidence_packet"]), read(task["shared_facts"])
    facts = facts_file["facts"]
    expected = provider_contract(config)
    runtime = packet["work"]["runtime"]
    profile = task.get("profile", "routine")
    role = task.get("review_role", "investigator")
    quality = (runtime.get("orchestration") or {}).get("quality") or {}
    if role not in ("investigator", "verification", "adjudication", "final_qa", "research", "collection") or (
            role == "collection" and (profile not in ("routine", "expert") or not runtime.get("orchestration"))) or (
            role == "research" and (profile != "expert" or not runtime.get("orchestration"))) or (
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
    workspace_mode = workspace_protocol.enabled(task, packet)
    schema_builder = workspace_protocol.schema if workspace_mode else build_schema
    local_schema = schema_builder(task)
    stable_schema = config.get("schema_mode", "dynamic") == "stable"
    validator = None
    if stable_schema:
        try:
            from jsonschema import Draft202012Validator
        except ImportError as error:
            raise ValueError("stable schema mode requires the adapter requirements.txt dependencies") from error
        validator = Draft202012Validator(local_schema)
    schema = schema_builder(task, bound_handles=False) if stable_schema else local_schema
    round_index = task["research"]["round"]
    if type(round_index) is not int or not 0 <= round_index <= 10:
        raise ValueError("invalid native research round")
    # Source/query handles grow as the native broker returns inspected facts.
    # Pin the protocol and exact question IDs; constrain each turn's output to
    # its current handles without treating new evidence as a new conversation.
    binding = {"packet_sha256": packet_hash, "provider": expected, "schema": schema_builder(task, bound_handles=False)}
    if stable_schema:
        binding["schema_mode"] = "stable"
    if presentation != "raw":binding["source_presentation"] = presentation
    if state:
        if state["binding"] != binding or round_index != state["round"] + 1:
            raise ValueError("provider continuation is stale or incompatible")
        if state.get("rejected_intent_sha256") and task["research"].get("feedback",{}).get("kind") != "local_response_validation":
            raise ValueError("rejected proof references require an explicit bound correction")
        uuid.UUID(state["thread_id"])
    elif round_index != 0:
        raise ValueError("cannot silently restart a missing provider continuation")
    log = session / ("round-" + str(round_index))
    log.mkdir(exist_ok=False)
    prompt = (workspace_protocol.prompt if workspace_mode else build_prompt)(task, packet, facts, state, source_presentation=presentation)
    save(log / "dispatched-task.json", task)
    (log / "prompt.txt").write_text(prompt, encoding="utf-8")
    launcher = launcher_factory(config, session)
    try:
        response, events, stderr = launcher.review(prompt, schema, (state or {}).get("thread_id"), timeout=task["research"].get("seconds_remaining", 600))
    except ProviderExecutionError as error:
        (log / "events.jsonl").write_text(error.events, encoding="utf-8")
        (log / "stderr.txt").write_text(error.stderr, encoding="utf-8")
        raise
    (log / "events.jsonl").write_text(events, encoding="utf-8")
    (log / "stderr.txt").write_text(stderr, encoding="utf-8")
    # Keep each exact paid reply privately even when local validation rejects it;
    # the launcher's answer.json is overwritten by the next continuation.
    save(log / "response.json", response)
    thread, usage = parse_events(events, (state or {}).get("thread_id"))
    delta, unknown = usage_delta(usage, state["reported_conversation_usage"] if state else None, state is not None)
    next_state = {"binding": binding, "round": round_index, "thread_id": thread,
                      "sent_facts": [fact["result_id"] for fact in facts], "sent_results": len(task["research"]["results"]),
                      "reported_conversation_usage":usage}
    if state and state.get("rejected_intent_sha256"):
        next_state["rejected_intent_sha256"] = state["rejected_intent_sha256"]
        next_state["rejected_response_round"] = state["rejected_response_round"]
    save(state_path, next_state)
    metric = {"schema_version": "1", "provider": expected, "conversation_id": conversation, "round": round_index,
              "profile":profile, "role":task.get("review_role", "investigator"),
              "resumed": state is not None, "elapsed_ms": round((time.monotonic()-started)*1000),
              "source_presentation":presentation,
              "prompt_bytes": len(prompt.encode()), "usage":delta, "usage_basis":"conversation_delta",
              "reported_conversation_usage":usage, "unknown_delta_counters":unknown}
    with metrics_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(metric) + "\n")
    if state and state.get("rejected_intent_sha256") and review_intent(response)!=state["rejected_intent_sha256"]:
        raise ValueError("proof-reference correction changed protected review intent")
    if state and state.get("rejected_intent_sha256"):
        original = read(session / ("round-" + str(state["rejected_response_round"])) / "response.json")
        if not proof_correction_matches(original,response,task):
            raise ValueError("proof-reference correction changed protected review intent or reference structure")
    if validator is not None:
        errors = list(validator.iter_errors(response))
        diagnostic = {"conversation_id":conversation, "round":round_index,
                      "schema_mode":"stable", "valid":not errors,
                      "wire_schema_sha256":hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest(),
                      "local_schema_sha256":hashlib.sha256(json.dumps(local_schema, sort_keys=True).encode()).hexdigest(),
                      "error_paths":[list(e.absolute_path) for e in errors]}
        with metrics_path.with_name("schema-validation-" + conversation + ".jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(diagnostic) + "\n")
        if errors:
            repairable = proof_reference_failure(response,validator,task)
            if repairable:
                saved = read(state_path)
                saved.setdefault("rejected_intent_sha256",review_intent(response))
                saved.setdefault("rejected_response_round",round_index)
                save(state_path,saved)
            save(metrics_path.with_name("reply-validation-" + conversation + "-" + str(round_index) + ".json"), {
                "schema_version":"1", "kind":"local_response_validation", "conversation_id":conversation,
                "round":round_index, "task_sha256":hashlib.sha256(json.dumps(task, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
                "error_paths":diagnostic["error_paths"][:20],
                "repairable_proof_references":repairable,
                "artifact_handles":list(task["research"]["artifact_handles"]),
                "source_artifact_handles":task["research"].get("source_artifact_handles", [])})
            if repairable and workspace_mode and response.get("decisions"):
                diagnostic_path = metrics_path.with_name("reply-validation-"+conversation+"-"+str(round_index)+".json")
                save(metrics_path.with_name("reply-candidate-"+conversation+"-"+str(round_index)+".json"), {
                    "schema_version":"mehscanRejectedCandidate/v1", "conversation_id":conversation,"round":round_index,
                    "provider":expected,"task_sha256":json_digest(task),"task_file_sha256":file_digest(log/"dispatched-task.json"),
                    "packet_sha256":packet_hash,"facts_sha256":file_digest(task["shared_facts"]),
                    "response_sha256":file_digest(log/"response.json"),"metric_sha256":json_digest(metric),
                    "diagnostic_sha256":file_digest(diagnostic_path)})
            raise ValueError("current-turn schema rejected response: " + str(diagnostic["error_paths"]))
    # A completed provider turn costs tokens even when its reply is rejected.
    # Persist counters/continuation before admission; never admit the bad draft.
    accepted = workspace_protocol.envelope(response,task,packet) if workspace_mode else review_envelope(response, task, packet, envelope)
    if "rejected_intent_sha256" in next_state:
        del next_state["rejected_intent_sha256"]
        del next_state["rejected_response_round"]
        save(state_path,next_state)
    return accepted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--contract", action="store_true")
    parser.add_argument("--inspect-candidate", action="store_true",help="inspect a rejected paid decision without inference")
    args = parser.parse_args()
    config = load_config(args.config)
    if args.contract and args.inspect_candidate:
        parser.error("contract and candidate inspection are separate operations")
    if args.contract:
        print(json.dumps(provider_contract(config)))
    elif args.inspect_candidate:
        print(json.dumps(inspect_candidate(config,json.load(sys.stdin))))
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
