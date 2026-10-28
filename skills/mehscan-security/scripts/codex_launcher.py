"""BYOK Codex execution using upstream tool controls, not a Mehscan sandbox."""
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time

# Disable specific research/execution surfaces, not every unknown client feature.
REQUIRED_FEATURES = {"shell_tool", "multi_agent", "apps", "plugins", "hooks", "view_image"}
OPTIONAL_TOOL_FEATURES = {"browser_use", "computer_use", "artifact", "code_mode", "code_mode_host", "shell_snapshot", "unified_exec"}
REVIEWER_INSTRUCTIONS = Path(__file__).resolve().parent.parent / "references" / "reviewer-base.md"


def file_digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def load_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = {"schema_version", "executable", "executable_version", "model", "reasoning_effort",
                "auth_file", "private_directory"}
    if (not isinstance(config, dict) or set(config)-{"source_presentation"} != expected or config["schema_version"] != "1"
            or config.get("source_presentation","raw") not in ("raw","line-addressed-v1")):
        raise ValueError("unsupported Codex BYOK configuration")
    for key in ("executable", "auth_file", "private_directory"):
        if not isinstance(config[key], str) or not Path(config[key]).is_absolute():
            raise ValueError("provider paths must be absolute trusted paths")
    for key in ("executable_version", "model"):
        value = config[key]
        if not isinstance(value, str) or not value or not value[0].isascii() or not value[0].isalnum() or len(value) > 128 or any(not (c.isascii() and (c.isalnum() or c in "-_.:/")) for c in value):
            raise ValueError("invalid provider version or model")
    if config["reasoning_effort"] not in ("low", "medium", "high", "xhigh", "max", "ultra"):
        raise ValueError("invalid reasoning effort")
    if not Path(config["executable"]).is_file():
        raise ValueError("configured Codex executable is missing")
    return config


def provider_contract(config):
    return {"schema_version": "1", "provider": "codex-cli",
            **{key: config[key] for key in ("executable_version", "model", "reasoning_effort")}}


def process_environment(home=None):
    # Explicit auth.json supplies the selected model credential. Do not inherit
    # workflow keys, GitHub tokens or arbitrary provider configuration.
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL") if key in os.environ}
    if home is not None:
        env.update({"HOME": str(home), "USERPROFILE": str(home), "CODEX_HOME": str(home)})
    return env


def run_process(command, prompt=None, timeout=600, *, cwd=None, env=None):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise ValueError("provider deadline must be finite and bounded")
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", start_new_session=True,
        cwd=cwd, env=env if env is not None else process_environment())
    deadline, supplied = time.monotonic() + timeout, False
    try:
        while True:
            if CANCELLED or time.monotonic() >= deadline:
                raise TimeoutError("provider cancelled or timed out")
            try:
                stdout, stderr = process.communicate(input=prompt if not supplied else None, timeout=0.25)
                if len(stdout) + len(stderr) > 16 * 1024 * 1024:
                    raise ValueError("provider diagnostics exceed bounded intake")
                return process.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                supplied = True
    finally:
        if process.poll() is None:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.communicate()


CANCELLED = False


def cancel(signum, frame):
    global CANCELLED
    CANCELLED = True


class Launcher:
    def __init__(self, config, session):
        self.config, self.session = config, Path(session).resolve()
        self.work, self.home = self.session / "work", self.session / "home"
        for directory in (self.session, self.work, self.home):
            directory.mkdir(exist_ok=True)
            directory.chmod(0o700)
        self.executable = Path(config["executable"]).resolve(strict=True)
        auth_path = self.home / "auth.json"
        raw = auth_path.read_bytes() if auth_path.exists() else Path(config["auth_file"]).read_bytes()
        if len(raw) > 64 * 1024 or not isinstance(json.loads(raw), dict):
            raise ValueError("invalid explicit provider authentication file")
        # Copy only explicit authentication. Preserve refreshed auth on resume.
        auth_path.write_bytes(raw)
        auth_path.chmod(0o600)
        code, version, _ = self.call(["--version"], timeout=30)
        if code or version.strip().removeprefix("codex-cli ") != config["executable_version"]:
            raise ValueError("provider version differs from the native binding")
        for operation in (["exec", "--help"], ["exec", "resume", "--help"]):
            code, help_text, _ = self.call(operation, timeout=30)
            if code or not all(flag in help_text for flag in ("--ignore-user-config", "--ignore-rules", "--strict-config", "--output-schema", "--json")):
                raise ValueError("Codex lacks required structured continuation options")
        code, features, _ = self.call(["features", "list"], timeout=30)
        self.features = {line.split()[0] for line in features.splitlines() if line.split()}
        if code or not REQUIRED_FEATURES.issubset(self.features):
            raise ValueError("Codex lacks required analysis-only tool controls")

    def call(self, arguments, prompt=None, timeout=600):
        return run_process([str(self.executable), *arguments], prompt, timeout,
            cwd=self.work, env=process_environment(self.home))

    def options(self):
        options = ["--ignore-user-config", "--ignore-rules", "--strict-config", "--skip-git-repo-check", "--json",
            "--output-schema", str(self.work / "schema.json"), "--output-last-message", str(self.work / "answer.json"),
            "-m", self.config["model"]]
        for feature in sorted(REQUIRED_FEATURES | (OPTIONAL_TOOL_FEATURES & self.features)):
            options += ["--disable", feature]
        if "skip_host_skill_discovery" in self.features:
            options += ["--enable", "skip_host_skill_discovery"]
        # Upstream permissions prohibit generated writes/network. The client
        # still needs inference networking and writes its private session state.
        filesystem = {":root": "deny", ":minimal": "read", str(self.work): "read", str(self.home): "deny"}
        for value in ('approval_policy="never"', 'default_permissions="mehscan_review"',
                'permissions.mehscan_review.filesystem={' + ', '.join(json.dumps(key) + '=' + json.dumps(value) for key, value in filesystem.items()) + '}',
                'permissions.mehscan_review.network.enabled=false', 'web_search="disabled"',
                'project_doc_max_bytes=0', 'cli_auth_credentials_store="file"',
                'model_instructions_file=' + json.dumps(str(REVIEWER_INSTRUCTIONS)),
                'suppress_unstable_features_warning=true',
                'model_reasoning_effort=' + json.dumps(self.config["reasoning_effort"])):
            options += ["-c", value]
        return options

    def review(self, prompt, schema, thread_id=None, timeout=600):
        (self.work / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
        answer = self.work / "answer.json"
        if answer.exists():
            answer.unlink()
        arguments = ["exec", *self.options(), "-C", str(self.work), "-"] if thread_id is None else ["exec", "resume", *self.options(), thread_id, "-"]
        code, events, stderr = self.call(arguments, prompt, timeout)
        if code or not answer.exists():
            raise RuntimeError("BYOK provider execution failed")
        return json.loads(answer.read_text(encoding="utf-8")), events, stderr
