"""Install a pinned Linux x64 Codex client and private config for the BYOK example."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import tarfile
import urllib.request


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(256 * 1024 * 1024 + 1)
    if len(data) > 256 * 1024 * 1024:
        raise ValueError("trusted client package exceeds setup limit")
    return data


def setup(root, version, model, auth_json, retrieve=fetch):
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError("this example installs the Linux x64 client")
    if not root.is_absolute() or not re.fullmatch(r"[0-9][0-9A-Za-z.-]{0,127}", version):
        raise ValueError("absolute private setup root and pinned client version required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", model):
        raise ValueError("invalid selected model")
    if not auth_json or len(auth_json.encode()) > 64 * 1024:
        raise ValueError("explicit authentication JSON is missing or oversized")
    auth = json.loads(auth_json)
    if not isinstance(auth, dict) or not auth:
        raise ValueError("explicit authentication must be a nonempty JSON object")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    metadata = json.loads(retrieve("https://registry.npmjs.org/@openai/codex/" + version + "-linux-x64"))
    url = metadata["dist"]["tarball"]
    if not isinstance(url, str) or not url.startswith("https://registry.npmjs.org/@openai/codex/-/"):
        raise ValueError("unexpected trusted package URL")
    archive = retrieve(url)
    actual = "sha512-" + base64.b64encode(hashlib.sha512(archive).digest()).decode()
    if metadata["dist"]["integrity"] != actual:
        raise ValueError("client package integrity mismatch")
    client = root / "client"
    with tarfile.open(fileobj=io.BytesIO(archive)) as package:
        package.extractall(client, filter="data")
    executable = client / "package/vendor/x86_64-unknown-linux-musl/bin/codex"
    if not executable.is_file():
        raise ValueError("pinned package lacks the expected client")
    executable.chmod(0o755)
    auth_file = root / "auth.json"
    auth_file.write_text(json.dumps(auth), encoding="utf-8")
    auth_file.chmod(0o600)
    config = {"schema_version":"1", "executable":str(executable), "executable_version":version,
              "model":model, "reasoning_effort":"medium", "auth_file":str(auth_file),
              "private_directory":str(root / "sessions"),
              "schema_mode":"stable", "source_presentation":"line-addressed-v1"}
    path = root / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    path.chmod(0o600)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--version", default="0.162.0-alpha.17.2")
    parser.add_argument("--model", default="gpt-6.1-terra")
    args = parser.parse_args()
    try:
        path = setup(args.private_root, args.version, args.model, os.environ.get("MEHSCAN_CODEX_AUTH_JSON", ""))
        print(json.dumps({"status":"configured", "config":str(path)}))
    except Exception as error:
        # Authentication values and raw provider responses never become logs.
        print(json.dumps({"status":"incomplete", "reason":type(error).__name__}))
        raise SystemExit(2)
