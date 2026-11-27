"""Exercise the extracted package's Changed worker and skill, without inference."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import unquote, urlsplit


def validate_document_links(package, files):
    """Check inline file links against the extracted release's declared payload."""
    package = package.resolve()
    included = set(files)
    for name in sorted(included):
        if not name.endswith('.md'):
            continue
        document = package / name
        lines, fence = [], None
        for line in document.read_text(encoding='utf-8-sig').splitlines():
            marker = re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$', line)
            if fence:
                if (marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence)
                        and not marker[2].strip()):
                    fence = None
            elif marker:
                fence = marker[1]
            else:
                lines.append(line)
        text = re.sub(r'(`+).*?\1', '', '\n'.join(lines))
        for match in re.finditer(r'\]\(\s*(<[^>]+>|[^\s)]+)', text):
            link = match[1].strip('<>')
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = (document.parent / unquote(parsed.path)).resolve()
            if (not target.is_relative_to(package) or not target.is_file()
                    or target.relative_to(package).as_posix() not in included):
                raise ValueError(f'Packaged document {name} links outside its payload: {link}')


def check_installed_transports(skill):
    # Stop at the launcher boundary so release validation needs no credentials or network.
    probe = """import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import codex_reviewer
for transport, module, name in (
    ("codex-cli", "codex_launcher", "Launcher"),
    ("openai-responses", "openai_responses", "ResponsesLauncher"),
):
    with patch.object(codex_reviewer, "run_bound") as dispatch:
        codex_reviewer.run({"transport": transport}, {})
        launcher = dispatch.call_args.args[2]
        assert (launcher.__module__, launcher.__name__) == (module, name)
        assert Path(sys.modules[module].__file__).resolve().parent == Path(sys.argv[1])
"""
    subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(skill / "scripts")],
                   check=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    package = parser.parse_args().package.resolve()
    manifest = json.loads((package / 'release-manifest.json').read_text(encoding='utf-8-sig'))
    validate_document_links(package, manifest['files'])
    scanner = package / ("mehscan.exe" if os.name == "nt" else "mehscan")
    skill = package / "skills/mehscan-security"
    check_installed_transports(skill)
    base = package / "_installed-review-smoke"
    base.mkdir()
    source = base / "source"
    source.mkdir()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", MEHSCAN_STATE_HOME=str(base / "state"))
    def call(*args, cwd=None, failure_record=None):
        result = subprocess.run([str(value) for value in args], cwd=cwd, env=env,
            capture_output=True, text=True, encoding="utf-8", timeout=120)
        if result.returncode:
            diagnostic = result.stdout[-1000:] + result.stderr[-1000:]
            if failure_record is not None and failure_record.is_file():
                diagnostic += "\n" + failure_record.read_text(encoding="utf-8")[-4000:]
            raise RuntimeError(Path(str(args[0])).name + " failed: " + diagnostic)
        return result.stdout
    def native(*args):
        return json.loads(call(scanner, *args))
    def save(path, value):
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    def git(*args):
        return call("git", "-c", "core.hooksPath=", "-c", "commit.gpgsign=false", *args, cwd=source).strip()
    git("init", "--quiet")
    git("config", "user.name", "Installed package smoke")
    git("config", "user.email", "smoke@example.invalid")
    git("config", "core.autocrlf", "false")
    (source / "app.js").write_text("const previous = true;\n", encoding="utf-8")
    git("add", "app.js")
    git("commit", "--quiet", "-m", "base")
    previous = git("rev-parse", "HEAD")
    (source / "app.js").write_text("function handle(request) { eval(request.query.code); }\n", encoding="utf-8")
    git("add", "app.js")
    git("commit", "--quiet", "-m", "target")
    target = git("rev-parse", "HEAD")
    inventory = base / "inventory"
    call(scanner, "investigate", "review-inventory", source, "--changed-from", previous, "--target", target,
         "--diff-mode", "files", "--repository-key", "test:installed-package", "--output", inventory)
    memory = base / "memory.turso"
    project = native("project", "bind", "--source-root", source, "--inventory", inventory,
                     "--stream", "package-smoke", "--memory-store", memory)["project_run"]
    claim_file = base / "claim.json"
    save(claim_file, native("state", "claim", "--project-run", project, "--attempt-id", "installed",
                            "--expected-generation", "0", "--operation-key", "claim"))
    common = ["--project-run", project, "--claim", claim_file, "--skill-root", skill]
    plan = native("state", "plan-template", "--project-run", project, "--skill-root", skill,
                  "--policy", "value", "--selection", "policy")
    assert plan["runtime"]["limits"] == {"rounds":5, "queries":24, "bytes":524288, "timeout_seconds":900}
    assert plan["selected_review_ids"], "Changed inventory has no seeded native question"
    plan_file = base / "plan.json"
    save(plan_file, plan)
    call(scanner, "state", "plan", *common, "--input", plan_file, "--operation-key", "plan")
    reviewer = base / "reviewer.py"
    reviewer.write_text('''import json, sys
from pathlib import Path

task = json.load(sys.stdin)
with Path(task["provider_metrics"]).open("a", encoding="utf-8") as receipt:
    receipt.write(json.dumps({"conversation_id": task["conversation_id"], "round": task["research"]["round"],
        "provider": None, "elapsed_ms": 1,
        "usage": {"input_tokens": 100, "cached_input_tokens": 0, "output_tokens": 10}}) + "\\n")
if task["kind"] == "change_pass":
    ids = json.load(open(task["work_package"], encoding="utf-8"))["payload"]["review_ids"]
    result = {"change_pass":[{"path":"app.js", "status":"reviewed", "summary":"Compared the supplied old and current operation.",
        "questions":[], "native_review_ids":ids, "evidence":[{"side":"base", "path":"app.js", "start_line":1, "end_line":1},
        {"side":"current", "path":"app.js", "start_line":1, "end_line":1}]}]}
elif task["kind"] == "source_review":
    packet = json.load(open(task["evidence_packet"], encoding="utf-8"))
    windows = packet["primary"]["windows"]
    result = {"draft":{"results":[{"review_id":row["review_id"], "decision":"needs_review", "confidence":"low",
        "summary":"Installed package smoke retains an unresolved caller question.",
        "reason":"The operation evaluates the supplied request code.",
        "evidence":[{"path":row["path"], "start_line":row["line"], "end_line":row["line"]}],
        "checks":["Confirm whether an untrusted caller reaches this operation."], "blockers":[],
        "followup":{"reason":"control_applicability", "question":"Does the registered caller constrain request code?"}}
        for row in packet["native_questions"]], "proposals":[], "coverage":[{
        **{key:window[key] for key in ("path","start_line","end_line")},
        "status":"examined", "summary":"Examined the assigned original source."} for window in windows]}}
else:
    result = {"results":[{"review_id":value, "decision":"needs_review", "confidence":"low",
        "summary":"Installed package smoke retains an unresolved caller question.", "reason":"The operation evaluates the supplied request code.",
        "evidence":[{"path":"app.js", "start_line":1, "end_line":1}],
        "checks":["Confirm whether an untrusted caller reaches this operation."], "blockers":[]} for value in task["review_ids"]]}
    if task.get("review_role") == "second_pass_fast":
        assert task["fast_phase"] == "audit"
        assert task["research"]["queries_remaining"] == 0
        result = {"draft":result, "working_chain":"", "progress":[], "review_checks":[{
            "review_id":value, "action":"keep", "claim":"", "proof_status":"supported",
            "investigation_status":"external_blocker", "error_codes":[]} for value in task["review_ids"]]}
print(json.dumps(result))
''', encoding="utf-8")
    command = base / "reviewer-command.json"
    save(command, [sys.executable, "-B", str(reviewer)])
    source_plan = native("investigate", "source-review-plan", source, "--inventory", inventory,
                         "--review-ids", ",".join(plan["selected_review_ids"]))
    selection = base / "source-selection.json"
    save(selection, {"source_plan_id": source_plan["plan_id"], "source_fingerprint": source_plan["source_fingerprint"],
                     "assignment_ids": [], "assignments": []})
    attempt = base / "attempt"
    worker = [sys.executable, "-B", package / "scripts/review_worker.py", "--scanner", scanner,
              "--skill-root", skill, "--reviewer-command", command, "--reviewer-label", "package-smoke/deterministic"]
    def close(result, key):
        assert result["status"] == "admitted", result
        receipt = native("state", "end", "--project-run", result["project_run"], "--claim", result["private_claim"],
                         "--status", "finished", "--operation-key", key)
        assert receipt["admitted_report"]["generation"] == result["generation"]
        assert receipt["memory"]["status"] == "retained", receipt
        path = base / (key + ".json")
        save(path, receipt)
        return path
    first = json.loads(call(*worker, "--project-run", project, "--claim", claim_file,
                            "--output", attempt, "--source-selection", selection,
                            failure_record=attempt / "worker.json"))
    record = json.loads((attempt / "worker.json").read_text(encoding="utf-8"))
    assert record["completion"]["pending_review_ids"]
    assert record["completion"]["security_resolution"] == "not_established"
    reviewed = record["source_review"]
    assert reviewed["completed_assignments"] == reviewed["assignments"] > 0
    assert reviewed["calls"] > 0 and record["unknown_provider_calls"] == 0
    first_receipt = close(first, "close-value")
    if sys.platform == "linux":
        # A Linux executable can carry trailing bytes, so this tests a distinct
        # build identity using the same behavior and version as the scanner.
        other_build = base / "other-build"
        shutil.copy2(scanner, other_build)
        with other_build.open("ab") as binary:
            binary.write(b"release smoke: different executable digest")
        journal = Path(json.loads(Path(first["project_run"]).read_text(encoding="utf-8"))["state_store"]) / "transactions.jsonl"
        original = journal.read_bytes()
        refused = subprocess.run([other_build, "state", "claim", "--close-receipt", first_receipt,
                                  "--attempt-id", "audit", "--operation-key", "claim-audit"],
                                 env=env, capture_output=True, text=True, timeout=30)
        assert refused.returncode and "cannot claim a follow-up from this close receipt" in refused.stderr, refused.stderr
        assert journal.read_bytes() == original, "incompatible receipt claim appended a transaction"
    second = base / "second-pass"
    audit_claim = base / "audit-claim.json"
    save(audit_claim, native("state", "claim", "--close-receipt", first_receipt,
                             "--attempt-id", "audit", "--operation-key", "claim-audit"))
    audit = json.loads(call(*worker, "--close-receipt", first_receipt, "--claim", audit_claim, "--output", second,
                            "--second-pass", "fast", "--second-pass-scope", "pending", "--supersede",
                            failure_record=second / "worker.json"))
    assert audit["generation"] == first["generation"] + 1
    audit_receipt = close(audit, "close-audit")
    checked = json.loads((second / "second-pass.json").read_text(encoding="utf-8"))
    labels = json.loads((second / "training-labels.json").read_text(encoding="utf-8"))
    assert checked["status"] == "complete" and checked["checked"] == len(plan["selected_review_ids"])
    assert checked["outcomes"]["unresolved"] == checked["checked"]
    assert not labels["auto_approved"] and labels["labels"]
    assert all(row["label_authority"] == "model_reviewed" for row in labels["labels"])
    report_args = ("report", "--close-receipt", first_receipt)
    exports = native(*report_args, "--format", "json-sarif")
    assert exports["sarif"] == native(*report_args, "--format", "sarif")
    assert exports["report"] == native(*report_args, "--format", "json")
    assert exports["sarif"]["version"] == "2.1.0" and exports["sarif"]["runs"][0]["results"] == []
    # This checks imports from the archive, without credentials or a client launch.
    call(sys.executable, "-B", skill / "scripts/codex_reviewer.py", "--help")
    assert native("report", "--close-receipt", audit_receipt) == json.loads((second / "findings.json").read_text(encoding="utf-8"))
    effective = native("project", "resolve", "--project-run", audit["project_run"])
    closed = json.loads(audit_receipt.read_text(encoding="utf-8"))
    exported = native("memory", "export", "--close-receipt", audit_receipt)
    assert exported == native("memory", "export", "--store", memory, "--source-root", source,
                              "--inventory", effective["inventory"], "--stream", effective["stream"],
                              "--batch", closed["memory"]["batch"])
    original = json.loads(first_receipt.read_text(encoding="utf-8"))
    assert native("memory", "export", "--close-receipt", first_receipt)["batch"] == original["memory"]["batch"]
    forged = base / "wrong-batch.json"
    save(forged, {**closed, "memory": original["memory"]})
    try:
        native("memory", "export", "--close-receipt", forged)
    except RuntimeError as error:
        assert "retained batch differs from the journal close" in str(error), error
    else:
        raise AssertionError("export accepted another generation's batch")
    manual_inventory = base / "manual-inventory"
    shutil.copytree(effective["inventory"], manual_inventory)
    manual_store = base / "manual-state"
    manual_store.mkdir()
    if os.name != "nt":
        alias = base / "manual-state-link"
        alias.symlink_to(manual_store, target_is_directory=True)
        manual_store = alias
    manual_project = native("project", "bind", "--source-root", source, "--inventory", manual_inventory,
                            "--stream", "manual", "--store", manual_store, "--memory-store", memory)["project_run"]
    manual_claim = base / "manual-claim.json"
    save(manual_claim, native("state", "claim", "--project-run", manual_project, "--expected-generation", "0",
                              "--attempt-id", "manual", "--operation-key", "claim-manual"))
    lane = ["--project-run", manual_project, "--claim", manual_claim, "--skill-root", skill]
    manual_plan = base / "manual-plan.json"
    save(manual_plan, native("state", "plan-template", "--project-run", manual_project, "--skill-root", skill,
                             "--policy", "value", "--selection", "policy"))
    native("state", "plan", *lane, "--input", manual_plan, "--operation-key", "manual-plan")
    manual_work = base / "manual-work.json"
    save(manual_work, native("state", "work", *lane))
    record_args = ["state", "record", *lane, "--work-package", manual_work, "--run", second / "run",
                   "--reviewer", "manual-reviewer", "--operation-key", "manual-record"]
    manual = native(*record_args)
    assert native(*record_args)["project_run"] == manual["project_run"]
    manual_receipt = base / "manual-close.json"
    save(manual_receipt, native("state", "end", "--project-run", manual["project_run"], "--claim", manual_claim,
                                "--status", "finished", "--operation-key", "manual-close"))
    manual_findings = native("report", "--close-receipt", manual_receipt)
    assert manual_findings["decision_records"] and manual_findings["triage"]["reviewer"] == "manual-reviewer"
    assert native("memory", "export", "--close-receipt", manual_receipt)["stream"] == "manual"
    manual_audit_claim = base / "manual-audit-claim.json"
    save(manual_audit_claim, native("state", "claim", "--close-receipt", manual_receipt,
                                    "--attempt-id", "manual-audit", "--operation-key", "manual-audit"))
    manual_audit = base / "manual-audit"
    checked_manual = json.loads(call(*worker, "--close-receipt", manual_receipt, "--claim", manual_audit_claim,
                                     "--output", manual_audit, "--second-pass", "fast", "--supersede",
                                     failure_record=manual_audit / "worker.json"))
    assert checked_manual["status"] == "admitted", checked_manual
    saved = native("memory", "assessments", "--store", memory, "--source-root", source,
                   "--inventory", effective["inventory"], "--stream", effective["stream"])
    retained = saved["batches"][0]["assessments"]
    assert retained and all(row["verdict"] == "needs_review" for row in retained), saved
    print(json.dumps({"status":"passed", "native_admission":"passed", "pending_preserved":True,
                      "installed_worker":True, "source_review":"passed", "second_pass":"passed", "scoped_pending":True,
                      "training_labels":"not_auto_approved", "document_links":"passed", "local_memory":"passed",
                      "inference":False}))


if __name__ == "__main__":
    main()
