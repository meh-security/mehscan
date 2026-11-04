"""Exercise the extracted package's Changed worker and skill, without inference."""
import argparse
import json
import os
from pathlib import Path
import re
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    package = parser.parse_args().package.resolve()
    manifest = json.loads((package / 'release-manifest.json').read_text(encoding='utf-8-sig'))
    validate_document_links(package, manifest['files'])
    scanner = package / ("mehscan.exe" if os.name == "nt" else "mehscan")
    skill = package / "skills/mehscan-security"
    base = package / "_installed-review-smoke"
    base.mkdir()
    source = base / "source"
    source.mkdir()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    def call(*args, cwd=None):
        result = subprocess.run([str(value) for value in args], cwd=cwd, env=env,
            capture_output=True, text=True, encoding="utf-8", timeout=120)
        if result.returncode:
            raise RuntimeError(Path(str(args[0])).name + " failed: " + result.stdout[-1000:] + result.stderr[-1000:])
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
    inventory, store, bundles = base / "inventory", base / "state", base / "bundles"
    call(scanner, "investigate", "review-inventory", source, "--changed-from", previous, "--target", target,
         "--diff-mode", "files", "--repository-key", "test:installed-package", "--output", inventory)
    claim = native("state", "claim", "--store", store, "--stream", "package-smoke", "--inventory", inventory,
                   "--source-root", source, "--attempt-id", "installed", "--expected-generation", "0", "--operation-key", "claim")
    common = ["--store", store, "--stream", "package-smoke", "--inventory", inventory, "--source-root", source,
              "--generation", "1", "--owner", claim["result"]["owner"]]
    claim_file, work_file = base / "claim.json", base / "work.json"
    save(claim_file, claim)
    plan = native("state", "plan-template", "--skill-root", skill, "--inventory", inventory,
                  "--source-root", source, "--policy", "value", "--selection", "policy")
    assert plan["runtime"]["limits"] == {"rounds":5, "queries":24, "bytes":524288, "timeout_seconds":900}
    assert plan["selected_review_ids"], "Changed inventory has no seeded native question"
    plan_file = base / "plan.json"
    save(plan_file, plan)
    call(scanner, "state", "plan", *common, "--skill-root", skill, "--input", plan_file, "--operation-key", "plan")
    call(scanner, "investigate", "review-bundles", source, "--inventory", inventory,
         "--review-ids", ",".join(plan["selected_review_ids"]), "--output", bundles)
    save(work_file, native("state", "work", *common, "--skill-root", skill))
    reviewer = base / "reviewer.py"
    reviewer.write_text('''import json, sys
task = json.load(sys.stdin)
if task["kind"] == "change_pass":
    ids = json.load(open(task["work_package"], encoding="utf-8"))["payload"]["review_ids"]
    result = {"change_pass":[{"path":"app.js", "status":"reviewed", "summary":"Compared the supplied old and current operation.",
        "questions":[], "native_review_ids":ids, "evidence":[{"side":"base", "path":"app.js", "start_line":1, "end_line":1},
        {"side":"current", "path":"app.js", "start_line":1, "end_line":1}]}]}
else:
    result = {"results":[{"review_id":value, "decision":"needs_review", "confidence":"low",
        "summary":"Installed package smoke retains an unresolved caller question.", "reason":"The operation evaluates the supplied request code.",
        "evidence":[{"path":"app.js", "start_line":1, "end_line":1}],
        "checks":["Confirm whether an untrusted caller reaches this operation."], "blockers":[]} for value in task["review_ids"]]}
print(json.dumps(result))
''', encoding="utf-8")
    command = base / "reviewer-command.json"
    save(command, [sys.executable, "-B", str(reviewer)])
    attempt = base / "attempt"
    call(sys.executable, "-B", package / "scripts/review_worker.py", "--scanner", scanner,
         "--source-root", source, "--inventory", inventory, "--store", store, "--stream", "package-smoke",
         "--claim", claim_file, "--work-package", work_file, "--reviewer-command", command,
         "--reviewer-label", "package-smoke/deterministic", "--run", bundles, "--output", attempt, "--skill-root", skill)
    record = json.loads((attempt / "worker.json").read_text(encoding="utf-8"))
    assert record["status"] == "admitted"
    assert record["completion"]["pending_review_ids"]
    assert record["completion"]["security_resolution"] == "not_established"
    sarif = native("report", "--run", attempt / "run", "--source-root", source,
                   "--reviewer", "package-smoke/deterministic", "--format", "sarif")
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"] == []
    # This checks imports from the archive, without credentials or a client launch.
    call(sys.executable, "-B", skill / "scripts/codex_reviewer.py", "--help")
    call(scanner, "state", "end", "--store", store, "--stream", "package-smoke", "--repository-key", "test:installed-package",
         "--generation", "1", "--owner", claim["result"]["owner"], "--status", "finished", "--operation-key", "end")
    print(json.dumps({"status":"passed", "native_admission":"passed", "pending_preserved":True,
                      "installed_worker":True, "document_links":"passed", "inference":False}))


if __name__ == "__main__":
    main()
