#!/usr/bin/env python3
"""Read-only GitHub adapter for native Changed inventory; never a merge gate."""
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = "1"
POLICY = {"native_scope": "changed_files", "include_review_material": False, "ai_review": "not_run", "change_pass": "not_run",
          "integration_review": "not_run", "alert_disposition": "not_established"}
SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_cancelled = False


class CancelledRun(Exception):
    pass


class StaleRun(Exception):
    pass


def is_cancelled():
    return _cancelled


def cancel(signum, frame):
    global _cancelled
    _cancelled = True


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError("GitHub endpoint must be a full lowercase commit SHA")
    return value


def repository(value):
    name, identifier = value["full_name"], value["id"]
    if not isinstance(name, str) or not REPOSITORY.fullmatch(name) or any(part in (".", "..") for part in name.split("/")):
        raise ValueError("invalid GitHub repository name")
    if type(identifier) is not int or identifier <= 0:
        raise ValueError("GitHub repository identity is unavailable")
    return {"name": name, "id": identifier}


def server_url(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("GitHub server URL must be an HTTPS origin")
    return value.rstrip("/")


class GitHub:
    def __init__(self, api_url, token):
        parsed = urllib.parse.urlsplit(api_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("invalid GitHub API URL")
        self.url, self.token = api_url.rstrip("/"), token

    def get(self, endpoint):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "mehscan-advisory", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.url + endpoint, headers=headers)
        # Redirects must not forward the read token to another origin.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            return json.load(response)


def resolve_pr(get, repo_name, number, forge):
    if not REPOSITORY.fullmatch(repo_name) or type(number) is not int or number <= 0:
        raise ValueError("a repository and positive PR number are required")
    pr = get(f"/repos/{repo_name}/pulls/{number}")
    base = repository(pr["base"]["repo"])
    if base["name"].lower() != repo_name.lower() or pr["number"] != number:
        raise ValueError("PR does not belong to the requested base repository")
    if pr["state"] not in ("open", "closed") or type(pr["draft"]) is not bool:
        raise ValueError("invalid PR lifecycle state")
    head = repository(pr["head"]["repo"]) if pr["head"]["repo"] is not None else None
    if pr["state"] == "open" and head is None:
        raise ValueError("open PR source repository is unavailable")
    base_ref = pr["base"]["ref"]
    if not isinstance(base_ref, str) or not base_ref:
        raise ValueError("PR base branch is unavailable")
    # Read the actual branch tip, including base-only pushes with unchanged head.
    base_commit = sha(pr["base"]["sha"]) if pr["state"] == "closed" else sha(get(
        f"/repos/{base['name']}/git/ref/heads/{urllib.parse.quote(base_ref, safe='/')}"
    )["object"]["sha"])
    return {"kind": "pull_request", "forge": forge, "base_repository": base,
            "source_repository": head, "pull_request": number, "base_ref": base_ref,
            "base_commit": base_commit, "target_commit": sha(pr["head"]["sha"]), "source_ref": pr["head"]["ref"],
            "state": pr["state"], "draft": bool(pr["draft"]), "merged": bool(pr.get("merged", False))}


def resolve_release(get, repo_name, base_ref, target_ref, forge):
    if not REPOSITORY.fullmatch(repo_name) or not base_ref or not target_ref:
        raise ValueError("release comparison requires repository, base and target refs")
    info = repository(get(f"/repos/{repo_name}"))
    if info["name"].lower() != repo_name.lower():
        raise ValueError("release repository does not match")
    def resolve(ref):
        if not isinstance(ref, str) or len(ref) > 512 or any(ord(char) < 32 for char in ref):
            raise ValueError("invalid release ref")
        return sha(get(f"/repos/{repo_name}/commits/{urllib.parse.quote(ref, safe='')}")["sha"])
    return {"kind": "release_delta", "forge": forge, "base_repository": info,
            "source_repository": info, "base_ref": base_ref, "target_ref": target_ref,
            "base_commit": resolve(base_ref), "target_commit": resolve(target_ref)}


def route(event_name, event, explicit_pr, base_ref, target_ref):
    if event_name in ("pull_request_target", "issue_comment", "merge_group", "push"):
        raise ValueError("unsupported advisory event; use pull_request or explicit workflow_dispatch")
    if event_name == "pull_request":
        if explicit_pr or base_ref or target_ref:
            raise ValueError("pull_request inputs cannot override event identity")
        number = event.get("number")
        if type(number) is not int or number <= 0:
            raise ValueError("event is missing its PR number")
        action = event.get("action")
        if action not in ("opened", "reopened", "synchronize", "ready_for_review", "converted_to_draft", "edited", "closed"):
            raise ValueError("unsupported pull_request activity")
        skip_edit = action == "edited" and not event.get("changes", {}).get("base")
        return "pr", number, "metadata_only_edit" if skip_edit else None
    if event_name != "workflow_dispatch":
        raise ValueError("unsupported advisory event")
    if explicit_pr:
        if base_ref or target_ref or not re.fullmatch(r"[1-9][0-9]*", explicit_pr):
            raise ValueError("manual PR and release inputs are mutually exclusive")
        return "pr", int(explicit_pr), None
    if not base_ref or not target_ref:
        raise ValueError("manual release comparison needs both base and target")
    return "release", None, None


def policy(plan):
    if not plan.get("review"):
        return POLICY
    return {**POLICY, "include_review_material": True, "review_policy": plan["review"]["policy"],
            "ai_review": "requested", "change_pass": "required"}


def contract(plan, comparison=None, inventory=None):
    result = {"schema_version": SCHEMA, "endpoints": plan["endpoints"], "policy": policy(plan),
              "scan_root": plan["scan_root"], "scanner_sha256": plan["scanner_sha256"],
              "adapter_sha256": plan["adapter_sha256"]}
    if plan.get("review"):
        result["review_runtime"] = {key: value for key, value in plan["review"].items() if key not in ("skill_root", "provider_contract")}
    if comparison is not None:
        result["comparison"] = comparison
    if inventory is not None:
        result["inventory_inputs"] = inventory
    return result


def is_current(expected, observed):
    return expected == observed and (expected["kind"] != "pull_request" or expected["state"] == "open")


def run_command(args, cwd=None, env=None, cancellable=True):
    if cancellable and is_cancelled():
        raise CancelledRun()
    process = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace")
    deadline = time.monotonic() + 900
    try:
        while True:
            if cancellable and is_cancelled():
                raise CancelledRun()
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(args[0], 900)
            try:
                output, _ = process.communicate(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
    if process.returncode:
        # Keep untrusted command output and filenames out of Actions annotations.
        raise RuntimeError(f"{Path(args[0]).name} command failed with exit code {process.returncode}")
    return output


def outputs(values):
    filename = os.environ.get("GITHUB_OUTPUT")
    if filename:
        with open(filename, "a", encoding="utf-8") as handle:
            for key, value in values.items():
                value = str(value)
                if "\n" in value or "\r" in value:
                    raise ValueError("multiline Action output is not allowed")
                handle.write(f"{key}={value}\n")


def load_options():
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    source_path = os.environ.get("MEHSCAN_SOURCE_PATH", "mehscan-source")
    scan_root = os.environ.get("MEHSCAN_SCAN_ROOT", ".")
    for value in (source_path, scan_root):
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value or "\n" in value or "\r" in value:
            raise ValueError("source path and scan root must be relative paths without parent traversal")
    checkout = (workspace / source_path).resolve()
    if checkout == workspace or not checkout.is_relative_to(workspace):
        raise ValueError("source checkout must be a dedicated directory inside the workspace")
    scanner = Path(os.environ["MEHSCAN_SCANNER_PATH"]).resolve(strict=True)
    if not scanner.is_file() or scanner.is_relative_to(checkout) or Path(__file__).resolve().is_relative_to(checkout):
        raise ValueError("trusted scanner and Action adapter must stay outside target source")
    return checkout, scan_root, scanner


def state_options():
    value = os.environ.get("MEHSCAN_STATE_STORE", "")
    retry = os.environ.get("MEHSCAN_STATE_RETRY", "false")
    if retry not in ("true", "false") or (retry == "true" and not value):
        raise ValueError("state retry requires a configured store and true/false value")
    if not value:
        return None
    if not Path(value).is_absolute():
        raise ValueError("persistent state store must be an absolute operator-provisioned directory")
    store = Path(value).resolve(strict=True)
    if not store.is_dir() or any(store.is_relative_to(Path(os.environ[name]).resolve())
                                  for name in ("GITHUB_WORKSPACE", "RUNNER_TEMP")):
        raise ValueError("persistent state store must stay outside workspace and runner temporary directories")
    return {"directory": str(store), "retry": retry == "true"}


def model_options(mode, endpoints):
    path = os.environ.get("MEHSCAN_PROVIDER_CONFIG", "")
    allow_fork = os.environ.get("MEHSCAN_ALLOW_FORK_REVIEW", "false")
    if allow_fork not in ("true", "false"):
        raise ValueError("allow-fork-review must be true or false")
    if allow_fork == "true" and os.environ["GITHUB_EVENT_NAME"] != "workflow_dispatch":
        raise ValueError("fork model review requires explicit workflow_dispatch authorization")
    if path and mode == "native":
        raise ValueError("provider-config requires value or comprehensive review-mode")
    if path and endpoints["kind"] == "pull_request" and endpoints["source_repository"] and endpoints["source_repository"]["id"] != endpoints["base_repository"]["id"] and allow_fork != "true":
        return "native", None, "fork_model_review_not_authorized"
    return mode, path or None, None


def configure_model(path, skill, control, checkout, directory):
    config_path = Path(path).resolve(strict=True)
    if not Path(path).is_absolute() or config_path.is_relative_to(checkout) or config_path.is_relative_to(directory):
        raise ValueError("provider configuration must be an absolute trusted private path")
    # This installed helper uses only stdlib; target source never supplies it.
    spec = importlib.util.spec_from_file_location("mehscan_action_codex_config", skill / "scripts/codex_launcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = module.load_config(config_path)
    for name in ("auth_file", "executable", "private_directory"):
        actual = Path(config[name]).resolve()
        if actual.is_relative_to(checkout) or actual.is_relative_to(directory):
            raise ValueError("provider code/auth/sessions must stay outside source and artifacts")
    descriptor = control / "provider.json"
    write_json(descriptor, module.provider_contract(config))
    command = control / "reviewer-command.json"
    write_json(command, [sys.executable, str(skill / "scripts/codex_reviewer.py"), "--config", str(config_path)])
    descriptor.chmod(0o600)
    command.chmod(0o600)
    return str(descriptor), {"config":str(config_path), "config_sha256":file_digest(config_path),
        "command":str(command), "command_sha256":file_digest(command),
        "label":"codex-cli/" + config["model"] + "/" + config["reasoning_effort"]}


def native_environment():
    return review_environment()


def resolve_delivery(get=None):
    """Read current authoritative endpoints without source/config/credential setup."""
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    kind, number, skip = route(os.environ["GITHUB_EVENT_NAME"], event,
                               os.environ.get("MEHSCAN_PR", ""), os.environ.get("MEHSCAN_BASE", ""), os.environ.get("MEHSCAN_TARGET", ""))
    forge = server_url(os.environ.get("GITHUB_SERVER_URL", "https://github.com"))
    get = get or GitHub(os.environ.get("GITHUB_API_URL", "https://api.github.com"), os.environ.get("GH_TOKEN", "")).get
    repo_name = os.environ["GITHUB_REPOSITORY"]
    endpoints = resolve_pr(get, repo_name, number, forge) if kind == "pr" else resolve_release(get, repo_name, os.environ["MEHSCAN_BASE"], os.environ["MEHSCAN_TARGET"], forge)
    expected_id = os.environ.get("GITHUB_REPOSITORY_ID")
    if expected_id and str(endpoints["base_repository"]["id"]) != expected_id:
        raise ValueError("base repository ID differs from the workflow repository")
    return endpoints, skip


def model_lane(get=None):
    endpoints, skip = resolve_delivery(get)
    mode = os.environ.get("MEHSCAN_REVIEW_MODE", "native")
    if mode not in ("native", "value", "comprehensive"):
        raise ValueError("invalid review mode")
    mode, config, reason = model_options(mode, endpoints)
    if endpoints["kind"] == "pull_request":
        skip = skip or ("closed" if endpoints["state"] != "open" else "draft" if endpoints["draft"] else None)
    allowed = not skip and mode != "native" and config is not None
    return {"allowed":bool(allowed), "reason":reason or skip or ("model_setup_allowed" if allowed else "native_only")}


def prepare(get=None, execute=run_command):
    checkout, scan_root, scanner = load_options()
    mode = os.environ.get("MEHSCAN_REVIEW_MODE", "native")
    if mode not in ("native", "value", "comprehensive"):
        raise ValueError("review mode must be native, value or comprehensive")
    if mode != "native" and os.environ.get("MEHSCAN_STATE_STORE", ""):
        raise ValueError("review handoff currently requires fresh one-run state; persistent review is unsupported")
    endpoints, skip = resolve_delivery(get)
    mode, model_config, ai_skip = model_options(mode, endpoints)
    run_id, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    if not run_id.isdigit() or not attempt.isdigit():
        raise ValueError("invalid Actions execution identity")
    temporary_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if temporary_root.is_relative_to(checkout):
        raise ValueError("artifacts must stay outside target checkout")
    directory = Path(tempfile.mkdtemp(prefix=f"mehscan-native-{run_id}-{attempt}-", dir=temporary_root))
    plan = {"schema_version": SCHEMA, "endpoints": endpoints, "scan_root": scan_root,
            "checkout": str(checkout), "scanner": str(scanner), "run_id": run_id, "run_attempt": attempt,
            "scanner_sha256": file_digest(scanner),
            "adapter_sha256": file_digest(__file__)}
    plan["state"] = state_options()
    if ai_skip:
        plan["ai_skip_reason"] = ai_skip
    if mode != "native":
        skill = Path(os.environ.get("MEHSCAN_SKILL_ROOT") or Path(__file__).resolve().parents[1] / "skills/mehscan-security").resolve(strict=True)
        if skill.is_relative_to(checkout):
            raise ValueError("review skill must stay outside source")
        provider_path = os.environ.get("MEHSCAN_PROVIDER_CONTRACT", "")
        control = Path(tempfile.mkdtemp(prefix="mehscan-review-control-", dir=temporary_root))
        control.chmod(0o700)
        plan["review_control"] = str(control)
        if model_config and skip is None and (endpoints["kind"] != "pull_request" or endpoints["state"] == "open"):
            if provider_path:
                raise ValueError("provider-config generates its descriptor; do not also supply provider-contract")
            provider_path, plan["model"] = configure_model(model_config, skill, control, checkout, directory)
        provider_args = []
        if provider_path:
            provider_path = str(Path(provider_path).resolve(strict=True))
            if Path(provider_path).is_relative_to(checkout):
                raise ValueError("provider contract must stay outside source")
            provider_args = ["--provider-contract", provider_path]
        runtime = json.loads(execute([str(scanner), "state", "runtime-template", "--skill-root", str(skill), "--policy", mode, *provider_args], env=native_environment()))
        if runtime["engine_sha256"] != plan["scanner_sha256"] or runtime["policy"] != mode:
            raise ValueError("native runtime differs from requested scanner/profile")
        plan["review"] = {"policy": mode, "skill_root": str(skill), "runtime": runtime,
                          "controller_sha256": file_digest(Path(__file__).with_name("review_worker.py")),
                          "context_sha256": file_digest(Path(__file__).with_name("review_context.py")),
                          "source_profile_sha256": file_digest(Path(__file__).with_name("review_source_profile.py")),
                          "exporter_sha256": file_digest(Path(__file__).with_name("review_export.py")),
                          "orchestrator_sha256": file_digest(Path(__file__).with_name("review_orchestration.py"))}
        if provider_path:
            plan["review"]["provider_contract"] = provider_path

    reason = "closed_pull_request" if endpoints["kind"] == "pull_request" and endpoints["state"] != "open" else skip
    plan["should_scan"] = reason is None
    plan["skip_reason"] = reason
    write_json(directory / "plan.json", plan)
    write_json(directory / "run.json", {"schema_version": SCHEMA, "status": "prepared" if plan["should_scan"] else "skipped",
               "reason": reason, "snapshot_id": digest(contract(plan)), "run_id": run_id,
               "run_attempt": attempt, "contract": contract(plan), "policy": policy(plan)})
    outputs({"directory": directory, "plan": directory / "plan.json", "should-scan": str(plan["should_scan"]).lower(),
             "source-repository": endpoints["source_repository"]["name"] if endpoints["source_repository"] else "", "target-commit": endpoints["target_commit"],
             "source-path": os.environ.get("MEHSCAN_SOURCE_PATH", "mehscan-source"), "artifact-name": directory.name})
    return directory


def fetch_base(plan, execute=run_command):
    endpoints = plan["endpoints"]
    env = dict(os.environ)
    # No persisted credentials, target-controlled helpers, recursive submodules,
    # hooks or tag discovery. Only the pinned base object/history is fetched.
    url = endpoints["forge"] + "/" + endpoints["base_repository"]["name"] + ".git"
    token = env.get("GH_TOKEN", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_COUNT"] = "1" if token else "0"
    if token:
        env["GIT_CONFIG_KEY_0"] = f"http.{url}.extraheader"
        auth = base64.b64encode(("x-access-token:" + token).encode()).decode()
        env["GIT_CONFIG_VALUE_0"] = "AUTHORIZATION: basic " + auth
    execute(["git", "-c", "credential.helper=", "-c", "core.hooksPath=", "-c", "http.followRedirects=false", "fetch", "--no-tags", "--no-recurse-submodules", url, endpoints["base_commit"]], cwd=plan["checkout"], env=env)


def scan(plan, directory, execute=run_command):
    checkout = Path(plan["checkout"]).resolve(strict=True)
    root = (checkout / plan["scan_root"]).resolve(strict=True)
    if not root.is_relative_to(checkout) or not root.is_dir():
        raise ValueError("scan root must be a directory within pinned checkout")
    scanner = Path(plan["scanner"]).resolve(strict=True)
    if scanner.is_relative_to(checkout) or file_digest(scanner) != plan["scanner_sha256"]:
        raise ValueError("trusted scanner binding changed")
    endpoints = plan["endpoints"]
    head = execute(["git", "rev-parse", "HEAD"], cwd=checkout).strip()
    if head != endpoints["target_commit"]:
        raise ValueError("checkout HEAD does not equal the pinned source endpoint")
    fetch_base(plan, execute)
    child_env = native_environment()
    help_text = execute([str(scanner), "investigate", "--help"], env=child_env)
    if "--target" not in help_text or "--merge-base" not in help_text:
        raise ValueError("scanner lacks V11 Changed support; released 0.8.0 is insufficient")
    command = [str(scanner), "investigate", "review-inventory", str(root), "--changed-from", endpoints["base_commit"],
               "--target", endpoints["target_commit"], "--diff-mode", "files", "--repository-key",
               endpoints["forge"].split("://", 1)[1] + "/repositories/" + str(endpoints["base_repository"]["id"]),
               "--source-repository-key", endpoints["forge"].split("://", 1)[1] + "/repositories/" + str(endpoints["source_repository"]["id"]),
               "--output", str(directory / "inventory")]
    if endpoints["kind"] == "pull_request":
        command.append("--merge-base")
    # The scanner gets no GitHub token or header environment; it never fetches.
    execute(command, cwd=checkout, env=child_env)
    overview = json.loads((directory / "inventory" / "overview.json").read_text(encoding="utf-8"))
    if execute(["git", "rev-parse", "HEAD"], cwd=checkout).strip() != endpoints["target_commit"] or execute(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], cwd=checkout
    ):
        raise ValueError("source checkout changed during native preparation")
    comparison = overview["impact_scope"]["comparison"]
    if overview["impact_scope"]["result_policy"] != "changed_files" or overview["impact_scope"]["full_scan"]:
        raise ValueError("native inventory widened or filtered the changed-file policy")
    if comparison["base_commit"] != endpoints["base_commit"] or comparison["target_commit"] != endpoints["target_commit"] or comparison["working_tree"]:
        raise ValueError("native inventory does not match pinned comparison")
    if (endpoints["kind"] == "pull_request") != bool(comparison.get("merge_base_commit")):
        raise ValueError("native comparison kind differs from the requested workflow")
    namespace = endpoints["forge"].split("://", 1)[1] + "/repositories/"
    identities = overview["native_identity"]["repository"]
    if identities["repository_key"] != namespace + str(endpoints["base_repository"]["id"]) or identities["source_repository_key"] != namespace + str(endpoints["source_repository"]["id"]):
        raise ValueError("native repository namespace differs from the source contract")
    inputs = {key: overview[key] for key in ("schema_version", "source_fingerprint", "input_fingerprint")}
    inputs["changed_snapshot"] = overview["impact_scope"]["snapshot_fingerprint"]
    return comparison, inputs, overview


def observe(plan, get):
    endpoints = plan["endpoints"]
    if endpoints["kind"] == "pull_request":
        return resolve_pr(get, endpoints["base_repository"]["name"], endpoints["pull_request"], endpoints["forge"])
    return resolve_release(get, endpoints["base_repository"]["name"], endpoints["base_ref"], endpoints["target_ref"], endpoints["forge"])


@contextmanager
def coordinator_lock(path, cancelled):
    """One trusted host; API selection and native CAS share this worker lock."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("coordinator lock must not be a symlink")
    with path.open("a+b") as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"0")
            handle.flush()
        deadline, locked = time.monotonic() + 60, False
        try:
            while not locked:
                if cancelled():
                    raise CancelledRun()
                handle.seek(0)
                try:
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except OSError as error:
                    if error.errno not in (11, 13, 35):
                        raise
                    if time.monotonic() >= deadline:
                        raise TimeoutError("coordinator is busy") from error
                    time.sleep(0.05)
            yield
        finally:
            if locked:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def state_layout(plan):
    endpoints = plan["endpoints"]
    key = endpoints["forge"].split("://", 1)[1] + "/repositories/" + str(endpoints["base_repository"]["id"])
    stream = (f"pr:{endpoints['pull_request']}" if endpoints["kind"] == "pull_request" else
              "release:" + digest({"base_ref": endpoints["base_ref"], "target_ref": endpoints["target_ref"]}))
    stream += "/root:" + plan["scan_root"]
    lane = digest({"repository_key": key, "stream": stream})
    parent = Path(plan["state"]["directory"]).resolve(strict=True)
    if not parent.is_dir() or any(parent.is_relative_to(Path(os.environ[name]).resolve())
                                  for name in ("GITHUB_WORKSPACE", "RUNNER_TEMP")):
        raise ValueError("persistent state directory changed or became ephemeral")
    return parent / ("mehscan-action-" + lane), parent / ("coordinator-" + lane + ".lock"), key, stream


def state_json(plan, execute, operation, args, cleanup=False):
    if file_digest(plan["scanner"]) != plan["scanner_sha256"] or file_digest(__file__) != plan["adapter_sha256"]:
        raise ValueError("trusted tool binding changed before state access")
    kwargs = {"env": native_environment()}
    if cleanup:
        kwargs["cancellable"] = False
    result = json.loads(execute([plan["scanner"], "state", operation, *args], **kwargs))
    if not isinstance(result, dict):
        raise ValueError("native state returned an invalid receipt")
    return result


def export_module():
    spec = importlib.util.spec_from_file_location("mehscan_advisory_export", Path(__file__).with_name("review_export.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save_result(directory, record):
    write_json(directory / "run.json", record)
    if "completion" in record:
        write_json(directory / "completion.json", {"schema_version":"1", "snapshot_id":record["snapshot_id"],
            "endpoints":record["contract"]["endpoints"], "execution_status":record["status"], "completion":record["completion"]})
    if "exports" in record:
        export_module().manifest(directory, record["exports"])
    summary(directory, record)
    return record


def coordinate(plan, directory, record, get, execute, cancelled):
    store, lock, key, stream = state_layout(plan)
    common = ["--store", str(store), "--stream", stream]
    read_args = [*common, "--repository-key", key]
    info = {"mode": "persistent_local", "stream": stream, "state": "not_claimed"}
    record["coordination"] = info
    with coordinator_lock(lock, cancelled):
        # Never promote a delayed plan using just the currently available number.
        if not is_current(plan["endpoints"], observe(plan, get)):
            record.update(status="stale", reason="endpoints_changed_before_claim")
            return save_result(directory, record)
        previous = state_json(plan, execute, "status", read_args) if (store / "transactions.jsonl").exists() else None
        expected = previous["generation"] if previous else 0
        claim = state_json(plan, execute, "claim", [*common, "--inventory", str(directory / "inventory"),
                           "--source-root", str(Path(plan["checkout"]) / plan["scan_root"]),
                           "--attempt-id", directory.name, "--expected-generation", str(expected),
                           "--operation-key", "claim:" + directory.name,
                           "--coordination-key", "mehscanAction/v1:" + record["snapshot_id"],
                           "--retry", str(plan["state"]["retry"]).lower()])
        receipt = claim["result"]
        generation, owner = receipt["generation"], receipt.get("owner")
        if receipt["status"] not in ("claimed", "coalesced") or (owner and not claim["currently_owned"]):
            raise ValueError("claim did not grant current coordination authority")
        info.update(generation=generation, native_snapshot_id=receipt["snapshot_id"],
                    state="owned" if owner else "coalesced")
        try:
            if cancelled():
                record.update(status="cancelled", reason="attempt_cancelled")
            elif not is_current(plan["endpoints"], observe(plan, get)):
                record.update(status="stale", reason="endpoints_changed_after_claim")
            else:
                record.update(status="native_only", reason=plan.get("ai_skip_reason", "ai_and_change_pass_not_run"))
        except Exception:
            record.update(status="cancelled" if cancelled() else "incomplete", reason="coordination_interrupted")
            raise
        finally:
            if owner:
                terminal = "finished" if record["status"] == "native_only" else ("cancelled" if cancelled() else "incomplete")
                state_json(plan, execute, "end", [*read_args, "--generation", str(generation), "--owner", owner,
                           "--status", terminal, "--operation-key", "end:" + directory.name], cleanup=True)
                info["state"] = "owned_" + terminal
        current = state_json(plan, execute, "status", read_args, cleanup=True)
        if current["generation"] != generation or current["snapshot_id"] != receipt["snapshot_id"]:
            info["state"] = "superseded"
            record.update(status="stale", reason="generation_changed_before_artifact")
        elif not owner:
            info["state"] = "coalesced_" + current["attempt_status"]
        if cancelled():
            record.update(status="cancelled", reason="attempt_cancelled")
        elif not is_current(plan["endpoints"], observe(plan, get)):
            record.update(status="stale", reason="endpoints_changed_before_artifact")
        checkout = Path(plan["checkout"])
        if execute(["git", "rev-parse", "HEAD"], cwd=checkout, env=native_environment()).strip() != plan["endpoints"]["target_commit"] or execute(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], cwd=checkout, env=native_environment()
        ):
            record.update(status="stale", reason="source_changed_before_artifact")
        info["freshness"] = "checked_at_artifact_write"
        # The advisory artifact is emitted under the same coordinator lock.
        # Later GitHub upload is historical and cannot be atomic with a push.
        return save_result(directory, record)


def provider_arguments(plan):
    path = plan.get("review", {}).get("provider_contract")
    return ["--provider-contract", path] if path else []


def review_tools(plan, execute):
    if model := plan.get("model"):
        if file_digest(model["command"]) != model["command_sha256"] or file_digest(model["config"]) != model["config_sha256"]:
            raise ValueError("configured BYOK reviewer changed after preparation")
    config = plan["review"]
    for name, key in (("review_worker.py", "controller_sha256"), ("review_context.py", "context_sha256"),
                      ("review_source_profile.py", "source_profile_sha256"),
                      ("review_export.py", "exporter_sha256"), ("review_orchestration.py", "orchestrator_sha256")):
        if file_digest(Path(__file__).with_name(name)) != config[key]:
            raise ValueError("trusted review controller changed")
    runtime = state_json(plan, execute, "runtime-template", ["--skill-root", config["skill_root"], "--policy", config["policy"], *provider_arguments(plan)])
    if runtime != config["runtime"]:
        raise ValueError("review runtime changed before handoff")


def review_source(plan, execute):
    checkout = Path(plan["checkout"])
    env = native_environment()
    if execute(["git", "rev-parse", "HEAD"], cwd=checkout, env=env).strip() != plan["endpoints"]["target_commit"] or execute(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], cwd=checkout, env=env
    ):
        raise ValueError("source changed before review handoff/result")


def review_lane(plan, directory):
    control = Path(plan["review_control"]).resolve(strict=True)
    if not control.is_dir() or control.is_relative_to(Path(plan["checkout"]).resolve()) or control.is_relative_to(directory.resolve()):
        raise ValueError("private review control must stay outside source and artifacts")
    key = plan["endpoints"]["forge"].split("://", 1)[1] + "/repositories/" + str(plan["endpoints"]["base_repository"]["id"])
    stream = "action-review:" + directory.name
    return control, ["--store", str(control / "state"), "--stream", stream], key


def end_review(plan, execute, common, key, receipt, status):
    return state_json(plan, execute, "end", [*common, "--repository-key", key,
        "--generation", str(receipt["generation"]), "--owner", receipt["owner"],
        "--status", status, "--operation-key", "review-end:" + status], cleanup=True)


def prepare_review(plan, directory, record, get, execute, cancelled):
    control, common, key = review_lane(plan, directory)
    receipt, ready = None, False
    info = {"mode": "ephemeral_review", "state": "not_claimed"}
    record["coordination"] = info
    try:
        review_tools(plan, execute)
        review_source(plan, execute)
        if not is_current(plan["endpoints"], observe(plan, get)):
            record.update(status="stale", reason="endpoints_changed_before_review_claim")
            return save_result(directory, record)
        root = str(Path(plan["checkout"]) / plan["scan_root"])
        source_args = ["--inventory", str(directory / "inventory"), "--source-root", root]
        claim = state_json(plan, execute, "claim", [*common, *source_args, "--attempt-id", directory.name,
            "--expected-generation", "0", "--operation-key", "review-claim:" + directory.name,
            "--coordination-key", "mehscanAction/v1:" + record["snapshot_id"]])
        receipt = claim["result"]
        if receipt["status"] != "claimed" or not receipt.get("owner") or not claim["currently_owned"]:
            raise ValueError("fresh review claim did not grant current ownership")
        info.update(state="owned_running", generation=receipt["generation"], native_snapshot_id=receipt["snapshot_id"])
        if cancelled():
            raise CancelledRun()
        owned = [*common, *source_args, "--generation", str(receipt["generation"]), "--owner", receipt["owner"],
                 "--skill-root", plan["review"]["skill_root"], *provider_arguments(plan)]
        draft = state_json(plan, execute, "plan-template", [*source_args, "--policy", plan["review"]["policy"],
            "--skill-root", plan["review"]["skill_root"], *provider_arguments(plan)])
        if draft["runtime"] != plan["review"]["runtime"]:
            raise ValueError("review template differs from pinned runtime")
        write_json(directory / "review-plan.json", draft)
        state_json(plan, execute, "plan", [*owned, "--input", str(directory / "review-plan.json"), "--operation-key", "review-plan"])
        package = state_json(plan, execute, "work", owned)
        write_json(directory / "work.json", package)
        # A zero queue needs a change pass but no native bundle run.
        if package["payload"]["review_ids"]:
            execute([plan["scanner"], "investigate", "review-bundles", root, "--inventory", str(directory / "inventory"),
                "--review-ids", ",".join(package["payload"]["review_ids"]), "--output", str(directory / "bundles")], env=native_environment())
        review_tools(plan, execute)
        review_source(plan, execute)
        if cancelled():
            raise CancelledRun()
        if not is_current(plan["endpoints"], observe(plan, get)):
            record.update(status="stale", reason="endpoints_changed_before_review_handoff")
            raise StaleRun()
        write_json(control / "claim.json", claim)
        (control / "claim.json").chmod(0o600)
        handoff = {"schema_version": "1", "plan": str(directory / "plan.json"),
                   "plan_sha256": file_digest(directory / "plan.json"), "snapshot_id": record["snapshot_id"],
                   "work_package_id": package["package_id"], "claim_sha256": file_digest(control / "claim.json")}
        write_json(control / "handoff.json", handoff)
        (control / "handoff.json").chmod(0o600)
        record.update(status="review_ready", reason="active_review_handoff", review_handoff=str(control / "handoff.json"))
        ready = True
    finally:
        if receipt and receipt.get("owner") and not ready:
            terminal = "cancelled" if cancelled() else "incomplete"
            end_review(plan, execute, common, key, receipt, terminal)
            info["state"] = "owned_" + terminal
    return save_result(directory, record)


def review_environment():
    # Provider authentication is supplied explicitly by the BYOK adapter, not by
    # copying a workflow's environment into the investigator process.
    allowed = {"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR",
               "HOME", "USERPROFILE", "LANG", "LC_ALL", "LC_CTYPE"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0", PYTHONIOENCODING="utf-8")
    return env


def run_model(plan_path, get=None, execute=run_command, cancelled=is_cancelled):
    plan_path = Path(plan_path).resolve(strict=True)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    model = plan.get("model")
    if not model:
        raise ValueError("this plan has no configured BYOK model step")
    record = json.loads((plan_path.parent / "run.json").read_text(encoding="utf-8"))
    if record["status"] != "review_ready":
        raise ValueError("configured model review is not pending; start a fresh attempt")
    return review(record["review_handoff"], model["command"], model["label"], get, execute, cancelled)


def review(handoff_path, reviewer_command, reviewer_label, get=None, execute=run_command, cancelled=is_cancelled):
    handoff = json.loads(Path(handoff_path).read_text(encoding="utf-8"))
    plan_path = Path(handoff["plan"]).resolve(strict=True)
    if file_digest(plan_path) != handoff["plan_sha256"]:
        raise ValueError("review plan changed after handoff")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    control, _, _ = review_lane(plan, plan_path.parent)
    with coordinator_lock(control / "consumer.lock", cancelled):
        return consume_review(handoff_path, reviewer_command, reviewer_label, get, execute, cancelled)


def consume_review(handoff_path, reviewer_command, reviewer_label, get=None, execute=run_command, cancelled=is_cancelled):
    handoff_path = Path(handoff_path).resolve(strict=True)
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if handoff["schema_version"] != "1":
        raise ValueError("unsupported review handoff")
    plan_path = Path(handoff["plan"]).resolve(strict=True)
    if file_digest(plan_path) != handoff["plan_sha256"]:
        raise ValueError("review plan changed after handoff")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    directory = plan_path.parent
    control, common, key = review_lane(plan, directory)
    if handoff_path != control / "handoff.json" or file_digest(control / "claim.json") != handoff["claim_sha256"]:
        raise ValueError("review ownership handoff changed")
    claim = json.loads((control / "claim.json").read_text(encoding="utf-8"))
    receipt = claim["result"]
    record = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    if record["status"] != "review_ready" or record["snapshot_id"] != handoff["snapshot_id"] or digest(record["contract"]) != handoff["snapshot_id"]:
        raise ValueError("review handoff is not pending for this snapshot")
    get = get or GitHub(os.environ.get("GITHUB_API_URL", "https://api.github.com"), os.environ.get("GH_TOKEN", "")).get
    terminal = "incomplete"
    try:
        if cancelled():
            raise CancelledRun()
        if model := plan.get("model"):
            if Path(reviewer_command).resolve(strict=True) != Path(model["command"]).resolve(strict=True):
                raise ValueError("configured BYOK review requires its prepared command")
        review_tools(plan, execute)
        review_source(plan, execute)
        if not is_current(plan["endpoints"], observe(plan, get)):
            record.update(status="stale", reason="endpoints_changed_before_review")
        else:
            source_args = ["--inventory", str(directory / "inventory"), "--source-root", str(Path(plan["checkout"]) / plan["scan_root"])]
            work = state_json(plan, execute, "work", [*common, *source_args, "--generation", str(receipt["generation"]),
                "--owner", receipt["owner"], "--skill-root", plan["review"]["skill_root"], *provider_arguments(plan)])
            if work["package_id"] != handoff["work_package_id"] or work != json.loads((directory / "work.json").read_text(encoding="utf-8")):
                raise ValueError("review work changed after handoff")
            argv = [sys.executable, str(Path(__file__).with_name("review_worker.py")), "--scanner", plan["scanner"],
                *source_args, *common, "--claim", str(control / "claim.json"), "--work-package", str(directory / "work.json"),
                "--skill-root", plan["review"]["skill_root"], "--reviewer-command", str(Path(reviewer_command).resolve(strict=True)),
                "--reviewer-label", reviewer_label, "--output", str(directory / "review"),
                "--artifact-root", str(directory), *provider_arguments(plan)]
            if (directory / "bundles").exists():
                argv += ["--run", str(directory / "bundles")]
            # The native worker owns finalization/report validation and admission.
            execute(argv, cwd=control, env=review_environment())
            worker_record = json.loads((directory / "review/worker.json").read_text(encoding="utf-8"))
            if worker_record["status"] != "admitted":
                raise ValueError("review worker did not admit a result")
            record["review_execution"] = "admitted"
            review_tools(plan, execute)
            review_source(plan, execute)
            current = state_json(plan, execute, "status", [*common, "--repository-key", key])
            if current["generation"] != receipt["generation"] or current["snapshot_id"] != receipt["snapshot_id"]:
                raise ValueError("review generation changed before result")
            record["completion"] = current["completion"]
            if cancelled():
                raise CancelledRun()
            if not is_current(plan["endpoints"], observe(plan, get)):
                record.update(status="stale", reason="endpoints_changed_during_review")
            else:
                record.update(status="reviewed", reason="advisory_review_finished")
                terminal = "finished"
            record["exports"] = export_module().export_review(plan, directory, record, reviewer_label, execute, native_environment())
            review_tools(plan, execute)
            review_source(plan, execute)
            if cancelled():
                raise CancelledRun()
            if not is_current(plan["endpoints"], observe(plan, get)):
                record.update(status="stale", reason="endpoints_changed_during_export")
                terminal = "incomplete"
    except CancelledRun:
        record.update(status="cancelled", reason="attempt_cancelled")
        terminal = "cancelled"
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, urllib.error.URLError) as error:
        record.update(status="cancelled" if cancelled() else "incomplete", reason=type(error).__name__)
        terminal = "cancelled" if cancelled() else "incomplete"
    finally:
        record.pop("review_handoff", None)
        try:
            end_review(plan, execute, common, key, receipt, terminal)
            record["coordination"]["state"] = "owned_" + terminal
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
            record.update(status="incomplete", reason="review_end_failed")
            record["coordination"]["state"] = "incomplete"
        save_result(directory, record)
    return record


def finish(plan_path, get=None, execute=run_command, cancelled=is_cancelled):
    directory = Path(plan_path).resolve().parent
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    record = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    if not plan["should_scan"]:
        summary(directory, record)
        return record
    get = get or GitHub(os.environ.get("GITHUB_API_URL", "https://api.github.com"), os.environ.get("GH_TOKEN", "")).get
    try:
        if file_digest(__file__) != plan["adapter_sha256"]:
            raise ValueError("trusted adapter binding changed")
        if cancelled():
            record.update(status="cancelled", reason="attempt_cancelled")
        elif not is_current(plan["endpoints"], observe(plan, get)):
            record.update(status="stale", reason="endpoints_changed_before_scan")
        else:
            comparison, inputs, overview = scan(plan, directory, execute)
            record["contract"] = contract(plan, comparison, inputs)
            record["snapshot_id"] = digest(record["contract"])
            record["native_inventory"] = {"review_count": overview["review_count"], "coverage": overview["coverage"], "impact_scope": overview["impact_scope"]}
            if cancelled():
                record.update(status="cancelled", reason="attempt_cancelled")
            elif plan.get("review"):
                return prepare_review(plan, directory, record, get, execute, cancelled)
            elif plan.get("state"):
                return coordinate(plan, directory, record, get, execute, cancelled)
            elif is_current(plan["endpoints"], observe(plan, get)):
                record.update(status="native_only", reason=plan.get("ai_skip_reason", "ai_and_change_pass_not_run"))
            else:
                record.update(status="stale", reason="endpoints_changed_during_scan")
    except StaleRun:
        pass
    except CancelledRun:
        record.update(status="cancelled", reason="attempt_cancelled")
        if "coordination" in record:
            record["coordination"]["state"] = "cancelled"
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, urllib.error.URLError) as error:
        # Error type only: API/server/target text cannot inject Actions commands
        # or expose credentials in job summaries. Original artifacts stay bound.
        record.update(status="incomplete", reason=type(error).__name__)
        if "coordination" in record:
            record["coordination"]["state"] = "incomplete"
    record.setdefault("coordination", {"mode": "none", "state": "disabled"})
    return save_result(directory, record)


def summary(directory, record):
    endpoints = record["contract"]["endpoints"]
    text = ("# Mehscan advisory review\n\n"
            f"Status: **{record['status']}**. Snapshot: `{record['snapshot_id']}`.\n\n"
            f"Base: `{endpoints['base_commit']}`. Source: `{endpoints['target_commit']}`.\n\n"
            "AI review, reviewer change pass and merge-integration review were not run. "
            "This artifact establishes no safety verdict, alert closure or merge approval.\n")
    if plan_review := record["contract"].get("review_runtime"):
        text = ("# Mehscan advisory review\n\n"
                f"Status: **{record['status']}**. Snapshot: `{record['snapshot_id']}`.\n\n"
                f"Base: `{endpoints['base_commit']}`. Source: `{endpoints['target_commit']}`.\n\n"
                f"Review profile: **{plan_review['policy']}**. ")
        text += ("Reviewer decisions were admitted for this pinned snapshot.\n" if record.get("review_execution") == "admitted" else
                 "Review is pending or did not finish; native preparation is not an AI review.\n")
        text += "This advisory result is not a merge approval or alert closure.\n"
        if "completion" in record:
            text += f"\nReview work complete: `{str(record['completion']['review_work_complete']).lower()}`. Security resolution: `{record['completion']['security_resolution']}`.\n"
    if record.get("reason"):
        text += f"\nReason: `{record['reason']}`.\n"
    if "native_inventory" in record:
        text += f"\nNative questions admitted: {record['native_inventory']['review_count']}.\n"
    coordination = record.get("coordination", {"mode": "none", "state": "disabled"})
    text += f"\nWorker coordination: `{coordination['state']}`. This is execution state, not review completion.\n"
    (directory / "summary.md").write_text(text, encoding="utf-8")
    filename = os.environ.get("GITHUB_STEP_SUMMARY")
    if filename:
        with open(filename, "a", encoding="utf-8") as handle:
            handle.write(text)
    completion = record.get("completion", {})
    counts = {"issue-count":len(completion.get("issue_review_ids", [])),
              "pending-review-count":len(completion.get("pending_review_ids", [])),
              "pending-effect-count":len(completion.get("pending_changed_effects", [])),
              "deferred-count":len(completion.get("deferred_review_ids", {})),
              "missing-review-count":len(completion.get("missing_or_conflicting_review_ids", []))}
    if completion:
        labels = {"issue-count":"Issues", "pending-review-count":"Pending native reviews",
                  "pending-effect-count":"Pending changed effects", "deferred-count":"Deferred reviews",
                  "missing-review-count":"Missing/conflicting reviews"}
        text_counts = "\n" + ". ".join(f"{labels[key]}: {value}" for key,value in counts.items()) + ".\n"
        with (directory / "summary.md").open("a", encoding="utf-8") as handle:
            handle.write(text_counts)
        if filename:
            with open(filename, "a", encoding="utf-8") as handle:
                handle.write(text_counts)
    outputs({key:value if completion else "" for key,value in counts.items()})
    outputs({"review-work-complete":str(completion["review_work_complete"]).lower() if completion else ""})
    outputs({"status": record["status"], "snapshot-id": record["snapshot_id"],
             "coordination-status": coordination["state"], "generation": coordination.get("generation", ""),
             "review-handoff": record.get("review_handoff", "")})


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    try:
        if sys.argv[1:] == ["prepare"]:
            prepare()
        elif sys.argv[1:] == ["model-lane"]:
            lane = model_lane()
            outputs({"model-allowed":str(lane["allowed"]).lower(), "model-setup-reason":lane["reason"]})
            print(json.dumps(lane))
        elif len(sys.argv) == 3 and sys.argv[1] == "finish":
            finish(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "run-model":
            result = run_model(sys.argv[2])
            if result["status"] != "reviewed":
                sys.exit(2)
        elif len(sys.argv) == 7 and sys.argv[1] == "review" and sys.argv[3] == "--reviewer-command" and sys.argv[5] == "--reviewer-label":
            result = review(sys.argv[2], sys.argv[4], sys.argv[6])
            if result["status"] != "reviewed":
                sys.exit(2)
        else:
            raise ValueError("expected prepare, finish PLAN, run-model PLAN or review HANDOFF --reviewer-command FILE --reviewer-label LABEL")
    except Exception as error:
        print(f"Mehscan advisory adapter could not prepare artifacts ({type(error).__name__}).", file=sys.stderr)
        sys.exit(2)
