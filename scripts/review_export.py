"""Advisory artifact packaging; native CLI owns findings, identity and flow evidence."""
import hashlib
import json
from pathlib import Path


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def usage(path, runtime):
    rows = []
    if path.exists():
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("provider metrics exceed export limits")
        seen = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if (not isinstance(row, dict) or not isinstance(row.get("conversation_id"), str)
                    or not row["conversation_id"] or type(row.get("round")) is not int
                    or row["round"] < 0 or not isinstance(row.get("usage", {}), dict)):
                raise ValueError("invalid provider metrics record")
            identity = (row["conversation_id"], row["round"])
            if (row["schema_version"] != "1" or row["provider"] != runtime.get("provider") or identity in seen
                    or row.get("usage_basis") != "conversation_delta"):
                raise ValueError("provider metrics are incompatible or duplicated")
            seen.add(identity)
            rows.append(row)
    def counter(values, key):
        numbers = [value[key] for value in values if key in value]
        if any(type(number) is not int or number < 0 for number in numbers):
            raise ValueError("invalid provider usage counter")
        return sum(numbers) if numbers else None, len(numbers)
    counters = {}
    reporting = {}
    for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
        counters[key], reporting[key] = counter([row.get("usage", {}) for row in rows], key)
    elapsed, _ = counter(rows, "elapsed_ms")
    prompt, _ = counter(rows, "prompt_bytes")
    return {"schema_version":"1", "provider":runtime.get("provider"), "policy":runtime["policy"],
        "research_limits":runtime["limits"], "round_count":len(rows), "token_accounting":"reported_conversation_deltas",
        "reported_token_sums":counters, "counter_reporting_rounds":reporting,
        "provider_elapsed_ms":elapsed, "prompt_bytes":prompt,
        "usage_available":bool(rows), "cost":None}


def export_review(plan, directory, record, reviewer, execute, env):
    directory = Path(directory)
    root = Path(plan["checkout"]) / plan["scan_root"]
    worker = json.loads((directory / "review/worker.json").read_text(encoding="utf-8"))
    if worker["status"] != "admitted" or worker["runtime"] != plan["review"]["runtime"]:
        raise ValueError("only native-admitted review work can be exported")
    files = ["usage.json", "completion.json"]
    run = directory / "review/run"
    native_export = "rendered"
    if not run.exists():
        # An empty inventory still needs a real native manifest, not fabricated SARIF.
        if record["native_inventory"]["review_count"] == 0:
            run = directory / "empty-report-run"
            execute([plan["scanner"], "investigate", "review-bundles", str(root),
                "--inventory", str(directory / "inventory"), "--review-ids", "", "--output", str(run)], env=env)
        else:
            native_export = "unavailable_no_selected_native_work"
    if native_export == "rendered":
        kind = "pr" if plan["endpoints"]["kind"] == "pull_request" else "release"
        category = "mehscan/triaged/" + kind + "/root-" + hashlib.sha256(plan["scan_root"].encode()).hexdigest()[:16]
        attempt = "gh-" + plan["run_id"] + "-" + plan["run_attempt"] + "-" + record["snapshot_id"][:16]
        args = [plan["scanner"], "report", "--run", str(run), "--source-root", str(root),
            "--reviewer", reviewer, "--revision", plan["endpoints"]["target_commit"],
            "--sarif-category", category, "--sarif-run-id", attempt]
        canonical = json.loads(execute([*args, "--format", "json"], env=env))
        sarif = json.loads(execute([*args, "--format", "sarif"], env=env))
        if sarif["version"] != "2.1.0" or len(sarif["runs"]) != 1:
            raise ValueError("native SARIF export is invalid")
        # Annotation only: never replace native matching/flow/completion fields.
        sarif["runs"][0]["properties"]["mehscanAction"] = {
            "snapshot_id":record["snapshot_id"], "endpoints":plan["endpoints"],
            "native_completion":record["completion"], "publication":"artifact_only"}
        write(directory / "findings.json", canonical)
        write(directory / "findings.sarif", sarif)
        files += ["findings.json", "findings.sarif"]
    write(directory / "usage.json", usage(directory / "review/provider-metrics.jsonl", plan["review"]["runtime"]))
    return {"schema_version":"1", "snapshot_id":record["snapshot_id"], "native_findings":native_export,
        "scan_root":plan["scan_root"], "files":files,
        "publication":"artifact_only"}


def manifest(directory, exports):
    values = []
    for name in exports["files"]:
        path = directory / name
        data = path.read_bytes()
        values.append({"path":name, "bytes":len(data), "sha256":hashlib.sha256(data).hexdigest()})
    write(directory / "artifacts.json", {**exports, "files":values, "execution_record":"run.json"})
