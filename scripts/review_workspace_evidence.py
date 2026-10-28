"""Controller-only, question-linked shared source and local dependency receipts.

No network/package execution, dependency resolution or security interpretation.
"""
import hashlib
import json
import re
from pathlib import Path

from review_workspace import identity, label, shape, source, MAX_CONTEXT_BYTES

VERSION = "mehscanDecidingEvidence/experimental-v1"
LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


def file_receipt(root, relative):
    """Check one explicit path, including missing ancestors, without following links."""
    root = Path(root).resolve(strict=True)
    parts = relative.split("/")
    if any(p in ("", ".", "..") for p in parts) or "\\" in relative or ":" in relative:
        raise ValueError("expected a relative dependency path")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
            raise ValueError("dependency links are not supported")
    if not current.exists():
        return {"path":relative, "status":"missing"}
    if not current.is_file():
        raise ValueError("dependency metadata path is not a file")
    data = source(root, relative)
    return {"path":relative, "status":"present", "sha256":hashlib.sha256(data).hexdigest()}


def dependency(root, package):
    """Root-local observations only; lock presence does not identify deployed resolution."""
    if not isinstance(package, str) or not re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9][a-z0-9_.-]*", package):
        raise ValueError("invalid bounded package name")
    if len(package) > 214:
        raise ValueError("package name exceeds limit")
    paths = ["package.json", *LOCKS, "node_modules/" + package + "/package.json"]
    receipts = [file_receipt(root, p) for p in paths]
    manifests = {}
    for receipt in (receipts[0], receipts[-1]):
        if receipt["status"] == "present":
            data = source(Path(root), receipt["path"])
            if hashlib.sha256(data).hexdigest() != receipt["sha256"]:
                raise ValueError("dependency metadata changed during observation")
            manifests[receipt["path"]] = json.loads(data.decode("utf-8-sig"))
            if not isinstance(manifests[receipt["path"]], dict):
                raise ValueError("dependency manifest must be an object")
    declared = {}
    manifest = manifests.get("package.json", {})
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        entries = manifest.get(section, {})
        if not isinstance(entries, dict):
            raise ValueError("dependency declarations must be objects")
        if package in entries:
            value = entries[package]
            if not isinstance(value, str) or len(value) > 1000:
                raise ValueError("invalid dependency declaration")
            declared[section] = value
    installed = manifests.get(paths[-1])
    version = None if installed is None else installed.get("version")
    if version is not None and (not isinstance(version, str) or len(version) > 1000):
        raise ValueError("invalid installed package version")
    return {"version":VERSION, "package":package, "declarations":declared,
            "root_installed_manifest_version":version, "files":receipts,
            "limits":"Only listed root-local paths checked. No workspace, nested, PnP, global, "
                     "deployment or runtime resolution performed. Lockfile contents not interpreted. "
                     "Missing metadata does not prove a package or its source is unavailable everywhere. "
                     "No dependency effect contract or security verdict established."}


def prepare(workspace, request, operation_key):
    """Caller holds native guard. One atomic action, bounded views, no model updates."""
    shape(request, ("version", "targets"))
    if request["version"] != VERSION:
        raise ValueError("unsupported deciding evidence request")
    action = {"kind":"prepare_evidence", "targets":request["targets"]}
    previous = workspace.operation(operation_key)
    if previous:
        if previous["request"]["action"] != action:
            raise ValueError("evidence retry changed")
        # Revalidate source and local availability before returning an old receipt.
        for target in request["targets"]:
            workspace.view(target["work_id"], MAX_CONTEXT_BYTES)
        return workspace.apply(operation_key, previous["request"]["revision"], action)
    return workspace.apply(operation_key, workspace.snapshot()["revision"], action)


def apply(state, workspace, action, operation_key):
    shape(action, ("kind", "targets"))
    targets = action["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 16:
        raise ValueError("expected one to sixteen evidence targets")
    root = Path(state["source_root"])
    records = state.setdefault("deciding_evidence", {})
    shared = state.setdefault("dependency_observations", {})
    observed = {}
    created = []
    for target in targets:
        shape(target, ("work_id", "question", "windows", "packages"))
        wid = target["work_id"]
        work = state["work"][wid]
        if not work["claims"]:
            raise ValueError("evidence target requires selected claims")
        label(target["question"])
        if not isinstance(target["windows"], list) or len(target["windows"]) > 8:
            raise ValueError("expected at most eight source windows")
        if (not isinstance(target["packages"], list) or len(target["packages"]) > 4
                or any(not isinstance(p, str) for p in target["packages"])
                or len(set(target["packages"])) != len(target["packages"])):
            raise ValueError("expected at most four distinct packages")
        if not target["windows"] and not target["packages"]:
            raise ValueError("evidence target is empty")
        evidence = []
        for window in target["windows"]:
            shape(window, ("path", "start_line", "end_line", "file_sha256"))
            eid = workspace._action(state, {"kind":"source", "review_id":work["claims"][0],
                **{k:window[k] for k in ("path", "start_line", "end_line")}}, operation_key)["evidence_id"]
            if state["evidence"][eid]["file_sha256"] != window["file_sha256"]:
                raise ValueError("shared source window is stale")
            evidence.append(eid)
        observations = []
        for name in target["packages"]:
            if name not in observed:
                observed[name] = dependency(root, name)
            observation = observed[name]
            observation_id = identity(observation)
            shared[observation_id] = observation
            observations.append(observation_id)
        record = {"question":target["question"], "evidence_ids":sorted(set(evidence)),
                  "dependency_ids":observations,
                  "authority":"Controller observations and source only; question remains open. "
                              "Establish caller applicability and check-to-effect relationship separately."}
        key = identity(record)
        bucket = records.setdefault(wid, {})
        if len(bucket) >= 8 and key not in bucket:
            raise ValueError("work deciding evidence limit exceeded")
        bucket[key] = record
        work["evidence_ids"] = sorted(set(work["evidence_ids"]) | set(evidence))
        created.append({"work_id":wid, "receipt_id":key})
    for target in targets:
        workspace._view(state, target["work_id"], MAX_CONTEXT_BYTES)
    return {"receipts":created, "native_query_count":0, "native_admission":False}


def visible(state, work_id):
    records = state.get("deciding_evidence", {}).get(work_id, {})
    shared = state.get("dependency_observations", {})
    selected = {key for record in records.values() for key in record["dependency_ids"]}
    for key in selected:
        observation = shared[key]
        if dependency(Path(state["source_root"]), observation["package"]) != observation:
            raise ValueError("dependency observation is stale; create newly bound state")
    result = {}
    for key, record in records.items():
        result[key] = {**record, "dependencies":[shared[k] for k in record["dependency_ids"]]}
    return result
