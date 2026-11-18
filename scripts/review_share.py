"""Link a checkout, read shared review history, or submit an approved publication."""

import argparse
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import urllib.parse

from review_share_storage import (
    MAX_DOCUMENT, EventStore, ShareError, canonical, digest, parse_document, request_json, sql_database,
)


def endpoint(value):
    url = urllib.parse.urlsplit(value)
    if (not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment
            or any(ord(char) < 33 or char == "\\" for char in value)
            or not (url.scheme == "https" or url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost"))):
        raise ShareError(400, "sharing service requires HTTPS or HTTP on loopback")
    return value.rstrip("/")


def app_credential(oidc_audience):
    token = os.environ.get("MEHSCAN_SHARE_TOKEN")
    if token:
        return token
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    parsed = urllib.parse.urlsplit(request_url)
    if (not request_token or not oidc_audience or parsed.scheme != "https"
            or not parsed.hostname or not parsed.hostname.endswith(".actions.githubusercontent.com")
            or parsed.username or parsed.password or parsed.fragment):
        raise ShareError(401, "provide a Mehscan token or an approved GitHub Actions identity")
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query["audience"] = oidc_audience
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    result = request_json(url, token=request_token)
    return result["value"]


def send(link, operation, submission=None):
    document = {key: link[key] for key in ("repository_id", "audience")}
    if submission is not None:
        document["submission"] = submission
    return request_json(endpoint(link["host"]) + "/v1/" + operation, "POST",
                        app_credential(link.get("oidc_audience")), document, api_status=True)


def read_json(filename, limit=MAX_DOCUMENT):
    with open(filename, "rb") as file:
        contents = file.read(limit + 1)
    if len(contents) > limit:
        raise ShareError(413, "sharing file exceeds the size limit")
    return parse_document(contents)


def outside(path, root):
    resolved = Path(path).resolve()
    if resolved.is_relative_to(root):
        raise ShareError(400, "sharing control and output files must stay outside the source root")
    return resolved


def child_env():
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith(("GIT_", "MEHSCAN_TURSO_", "MEHSCAN_SHARE_", "ACTIONS_ID_TOKEN_", "MEHSCAN_GITHUB_"))
            and key.upper() not in ("GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY")}


def git_state(root, env):
    git = ["git", "-c", "core.fsmonitor=false", "-C", str(root)]
    sha = subprocess.check_output([*git, "rev-parse", "--verify", "HEAD"], env=env, text=True, timeout=20).strip()
    changes = subprocess.check_output([*git, "status", "--porcelain=v1", "--untracked-files=all",
                                       "--ignore-submodules=none"], env=env, timeout=30)
    if changes or not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ShareError(409, "publication requires a clean checkout pinned to a Git commit")
    return sha


def publish(args, link):
    root = args.source_root.resolve(strict=True)
    scanner = outside(args.scanner, root)
    inventory = outside(args.inventory, root)
    outside(args.link, root)
    env = child_env()
    commit = git_state(root, env)
    number = getattr(args, "pull_request", None)
    if number is None and commit != os.environ.get("GITHUB_SHA"):
        raise ShareError(409, "checkout commit differs from the protected job source commit")
    if number is not None and args.stream != f"pr:{number}":
        raise ShareError(409, "pull request publication requires its approved PR stream")
    command = [str(scanner), "memory", "export", "--source-root", str(root), "--inventory", str(inventory),
               "--stream", args.stream, "--batch", args.batch]
    if args.store:
        command += ["--store", str(outside(args.store, root))]
    completed = subprocess.run(command, check=True, capture_output=True, env=env, timeout=300)
    if len(completed.stdout) > MAX_DOCUMENT:
        raise ShareError(413, "retained batch exceeds the publication limit")
    if git_state(root, env) != commit:
        raise ShareError(409, "checkout changed while exporting the retained batch")
    batch = parse_document(completed.stdout)
    if batch["repository"]["repository_key"] != link["repository_key"]:
        raise ShareError(403, "inventory does not belong to the linked repository")
    submission = {"commit": commit, "batch": batch, "run_id": os.environ.get("GITHUB_RUN_ID"),
                  "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT")}
    if number is not None:
        submission["pull_request"] = number
    return send(link, "publish", submission)


def read_store(link):
    session = send(link, "read-token")
    if any(session[key] != link[key] for key in ("audience", "enrollment", "repository_key")):
        raise ShareError(403, "read credential does not match the linked enrollment")
    store = EventStore(sql_database(session["remote"], session["token"]), link["enrollment"])
    store.database_id = session.get("database_id")
    store.check_binding()
    return store


def sync_facts(args, link):
    root = args.source_root.resolve(strict=True)
    scanner = outside(args.scanner, root)
    inventory = outside(args.inventory, root)
    link_path = outside(args.link, root)
    cache_id = digest([endpoint(link["host"]), link["enrollment"]])
    home = outside(link_path.parent / ("review-state-" + cache_id), root)
    store = read_store(link)
    sharing = {"enrollment": store.enrollment, "database_id": store.database_id}
    if not isinstance(store.database_id, str) or not store.database_id:
        raise ShareError(409, "the sharing service must identify the enrolled database before syncing facts")
    env = {**child_env(), "MEHSCAN_STATE_HOME": str(home)}

    def native(operation, *options):
        result = subprocess.run([str(scanner), "memory", operation, "--source-root", str(root),
                                 "--inventory", str(inventory), *options],
                                capture_output=True, env=env, timeout=300)
        if result.returncode:
            raise ShareError(409, "native memory refused the shared fact cache or revision page")
        if len(result.stdout) > 64 * 1024:
            raise ShareError(502, "native memory returned an invalid fact sync receipt")
        return parse_document(result.stdout)

    state = native("shared-facts")
    if state["sharing"] not in (None, sharing):
        raise ShareError(409, "local memory is linked to a different sharing enrollment")
    locations = native("location")
    head = store.fact_head()
    imported, retries = 0, 0
    with TemporaryDirectory(dir=home, prefix="fact-sync-") as directory:
        page = Path(directory) / "page.json"
        while True:
            after = state["cursor"]["after"]
            if after:
                checkpoint = store.get(state["cursor"]["event_id"])
                if not checkpoint or checkpoint["kind"] != "fact" or checkpoint["seq"] != after:
                    raise ShareError(409, "upstream fact history no longer contains the local checkpoint")
            if state["sharing"] and after >= head:
                break
            facts = store.facts(after, head)
            if after < head and not facts:
                raise ShareError(409, "upstream did not return the announced shared fact revisions")
            page.write_text(canonical({"sharing": sharing, "after": after, "facts": facts}), encoding="utf-8")
            state = native("shared-facts", "--input", str(page))
            if state["status"] == "cursor_changed":
                retries += 1
                if retries > 8:
                    raise ShareError(409, "another client is updating the shared fact cache")
                continue
            imported += state["imported"]
    return {"status": "synced", "sharing": sharing, "imported": imported, "cursor": state["cursor"],
            "state_home": str(home), **locations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    connect = commands.add_parser("link")
    for option in ("host", "repository-id", "audience"):
        connect.add_argument("--" + option, required=True)
    connect.add_argument("--oidc-audience")
    connect.add_argument("--source-root", type=Path, required=True)
    connect.add_argument("--output", type=Path, required=True)
    for name in ("list", "get", "sync", "publish", "fact", "grant", "workflow", "approve-pr", "pr-target"):
        command = commands.add_parser(name)
        command.add_argument("--link", type=Path, required=True)
        if name == "list":
            command.add_argument("--after", type=int, default=0)
        elif name == "get":
            command.add_argument("--id", required=True)
        elif name in ("publish", "sync"):
            for option in ("source-root", "inventory", "scanner"):
                command.add_argument("--" + option, required=True, type=Path)
        if name == "publish":
            command.add_argument("--store", type=Path)
            command.add_argument("--stream", required=True)
            command.add_argument("--batch", required=True)
            command.add_argument("--pull-request", type=int)
        if name == "pr-target":
            command.add_argument("--pull-request", type=int, required=True)
        if name in ("fact", "grant", "workflow", "approve-pr"):
            command.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "link":
            output = outside(args.output, args.source_root.resolve(strict=True))
            link = {"host": endpoint(args.host), "repository_id": args.repository_id,
                    "audience": args.audience, "oidc_audience": args.oidc_audience}
            result = send(link, "link")
            link.update({key: result[key] for key in ("enrollment", "repository_key")})
            with output.open("x", encoding="utf-8") as file:
                file.write(canonical(link) + "\n")
            result["link_file"] = str(output)
        else:
            link = read_json(args.link, 16 * 1024)
            if args.command == "publish":
                result = publish(args, link)
            elif args.command == "sync":
                result = sync_facts(args, link)
            elif args.command == "pr-target":
                result = send(link, "pr-target", {"pull_request": args.pull_request})
            elif args.command == "list":
                if not 0 <= args.after < 2**63:
                    raise ShareError(400, "invalid sharing cursor")
                events = read_store(link).list(args.after)
                result = {"events": events, "next": events[-1]["seq"] if events else args.after}
            elif args.command == "get":
                if not re.fullmatch(r"[a-f0-9]{64}", args.id):
                    raise ShareError(400, "invalid sharing event ID")
                result = read_store(link).get(args.id)
                if result is None:
                    raise ShareError(404, "sharing event does not exist")
            else:
                result = send(link, args.command, read_json(args.input, 32 * 1024))
        print(canonical(result))
    except ShareError as error:
        parser.exit(2, f"{error}\n")
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        parser.exit(2, "sharing command could not read its inputs or complete the requested operation\n")


if __name__ == "__main__":
    main()
