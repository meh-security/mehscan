"""Repository enrollment and authenticated publication for hosted review memory."""

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

from github_action import resolve_pr
from review_share_storage import (
    MAX_DOCUMENT, ShareError, canonical, cloud_database, cloud_reader, cloud_store, digest, parse_document,
    request_json,
)


ISSUER = "https://token.actions.githubusercontent.com"
PR_EVENTS = {"workflow_dispatch", "pull_request_target"}
EVENTS = PR_EVENTS | {"push", "schedule"}
CLAIMS = ("sub", "repository_id", "sha", "workflow_ref", "workflow_sha", "ref",
          "environment", "event_name", "run_id", "run_attempt")
REGISTRY = """
    CREATE TABLE IF NOT EXISTS enrollments (
        id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, audience TEXT NOT NULL,
        organization TEXT NOT NULL, database_name TEXT NOT NULL, writer_env TEXT NOT NULL,
        database_id TEXT NOT NULL UNIQUE, remote TEXT NOT NULL UNIQUE,
        active INTEGER NOT NULL DEFAULT 1,
        UNIQUE (repository_id, audience), UNIQUE (organization, database_name)
    );
    CREATE TABLE IF NOT EXISTS identities (actor TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS tokens (
        digest TEXT PRIMARY KEY, actor TEXT NOT NULL REFERENCES identities(actor),
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS grants (
        enrollment TEXT NOT NULL REFERENCES enrollments(id),
        actor TEXT NOT NULL REFERENCES identities(actor), role TEXT NOT NULL,
        PRIMARY KEY (enrollment, actor)
    );
    CREATE TABLE IF NOT EXISTS workflows (
        enrollment TEXT PRIMARY KEY REFERENCES enrollments(id),
        policy TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pull_request_runs (
        enrollment TEXT NOT NULL REFERENCES enrollments(id),
        run_id TEXT NOT NULL,
        run_attempt TEXT NOT NULL,
        binding TEXT NOT NULL,
        PRIMARY KEY (enrollment, run_id, run_attempt)
    );
"""


def fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() <= set(required) | set(optional):
        raise ShareError(400, "invalid sharing document fields")
    return value


def bounded(value, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\0" in value:
        raise ShareError(400, "invalid sharing text field")
    return value


def matching(value, pattern):
    if not isinstance(value, str) or not re.fullmatch(pattern, value, re.ASCII):
        raise ShareError(400, "invalid sharing identifier")
    return value


def sequence(value, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise ShareError(400, "invalid sharing list")
    return value


def fingerprint(value):
    return matching(value, r"(?:[A-Za-z][A-Za-z0-9_-]{0,70}/v[0-9]+:)?[a-f0-9]{64}")


def path(value):
    bounded(value, 1024)
    if any(part in ("", ".", "..") for part in value.split("/")) or "\\" in value or ":" in value:
        raise ShareError(400, "sharing references require repository-relative paths")
    return value


def repository_key(repo):
    return "github.com/repositories/" + matching(repo, r"[1-9][0-9]{0,19}")


def enrollment_id(repo, audience):
    return repository_key(repo) + "/" + matching(audience, r"[a-z0-9][a-z0-9-]{0,62}")


def human(name):
    return "user:" + matching(name, r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,95}")


def stream_name(value):
    return matching(value, r"[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,127}")


def workflow_run(value):
    return tuple(matching(value[key], r"[1-9][0-9]{0,19}") for key in ("run_id", "run_attempt"))


def pull_number(value):
    if type(value) is not int or not 1 <= value < 2**31:
        raise ShareError(400, "a positive GitHub pull request number is required")
    return value


def commit_sha(value):
    return matching(value, r"[a-f0-9]{40}")


def github_pull_request(repository, number):
    token = os.environ.get("MEHSCAN_GITHUB_READ_TOKEN")
    def get(resource):
        return request_json("https://api.github.com" + resource, token=token)
    try:
        return resolve_pr(get, repository, number, "https://github.com")
    except (TypeError, KeyError, ValueError):
        raise ShareError(502, "GitHub returned an invalid pull request binding") from None


def verify_batch(batch, repo, stream):
    fields(batch, ("schema_version", "batch", "repository", "repository_id", "snapshot_id", "source_fingerprint",
                   "inventory_fingerprint", "stream", "attempt_status", "assessments", "file_dependencies"),
           ("sharing", "comparison"))
    if type(batch["schema_version"]) is not int or batch["schema_version"] != 1:
        raise ShareError(400, "unsupported retained batch schema")
    identity = fields(batch["repository"], ("repository_key", "path_prefix"), ("source_repository_key",))
    if (identity["repository_key"] != repository_key(repo)
            or identity.get("source_repository_key", identity["repository_key"]) != identity["repository_key"]
            or batch["stream"] != stream or batch["attempt_status"] not in ("finished", "incomplete")):
        raise ShareError(403, "retained batch does not match the enrolled repository and stream")
    if identity["path_prefix"]:
        path(identity["path_prefix"])
    elif identity["path_prefix"] != "":
        raise ShareError(400, "invalid retained batch path prefix")
    for name in ("batch", "repository_id", "snapshot_id", "inventory_fingerprint"):
        fingerprint(batch[name])
    matching(batch["source_fingerprint"], r"review-sources-v1-[a-f0-9]{64}")
    decisions = set()
    for row in sequence(batch["assessments"], 4096):
        fields(row, ("decision_id", "review_id", "subject_key", "basis_fingerprint", "response_fingerprint",
                     "verdict", "confidence", "summary", "questions", "evidence"))
        for name in ("decision_id", "subject_key", "basis_fingerprint", "response_fingerprint"):
            fingerprint(row[name])
        bounded(row["review_id"], 256)
        if (row["decision_id"] in decisions or row["verdict"] not in ("issue", "not_issue", "needs_review")
                or row["confidence"] not in ("low", "medium", "high")):
            raise ShareError(400, "invalid retained decision")
        decisions.add(row["decision_id"])
        bounded(row["summary"], 8192)
        for question in sequence(row["questions"], 256):
            fields(question, ("kind", "text"))
            if question["kind"] not in ("check", "blocker"):
                raise ShareError(400, "invalid retained question")
            bounded(question["text"], 4096)
        for evidence in sequence(row["evidence"], 256):
            fields(evidence, ("kind", "reference", "path", "start_line", "end_line", "start_byte",
                              "end_byte", "excerpt_sha256"))
            if evidence["kind"] not in ("primary", "retrieved"):
                raise ShareError(400, "invalid retained source evidence")
            bounded(evidence["reference"], 512)
            path(evidence["path"])
            for start, end in (("start_line", "end_line"), ("start_byte", "end_byte")):
                if any(type(evidence[key]) is not int for key in (start, end)) or not 0 <= evidence[start] <= evidence[end]:
                    raise ShareError(400, "invalid retained source coordinates")
            if evidence["excerpt_sha256"] is not None:
                fingerprint(evidence["excerpt_sha256"])
    for dependency in sequence(batch["file_dependencies"], 32768):
        fields(dependency, ("decision_id", "role", "path", "sha256"))
        if not isinstance(dependency["decision_id"], str) or dependency["decision_id"] not in decisions:
            raise ShareError(400, "file dependency refers to an absent retained decision")
        bounded(dependency["role"], 64)
        path(dependency["path"])
        if dependency["sha256"] is not None:
            fingerprint(dependency["sha256"])
    if "comparison" in batch:
        comparison = fields(batch["comparison"], ("requested_base", "base_commit", "head_commit",
                            "target_commit", "working_tree"), ("requested_target", "merge_base_commit"))
        for name in ("base_commit", "head_commit", "target_commit"):
            commit_sha(comparison[name])
        bounded(comparison["requested_base"], 512)
        if "requested_target" in comparison:
            bounded(comparison["requested_target"], 512)
        if "merge_base_commit" in comparison:
            commit_sha(comparison["merge_base_commit"])
        if type(comparison["working_tree"]) is not bool:
            raise ShareError(400, "invalid retained Git comparison")


def verify_fact(value, at):
    fields(value, ("statement", "origin"), ("scope", "evidence", "source_sha256", "observed_at", "expires_at"))
    bounded(value["statement"], 2048)
    origin = value["origin"]
    if origin not in ("assertion", "inference", "source_observation"):
        raise ShareError(400, "invalid fact origin")
    scope = fields(value.get("scope", {}), (), ("path", "subject_key", "environment"))
    if "path" in scope:
        path(scope["path"])
    if "subject_key" in scope:
        fingerprint(scope["subject_key"])
    if "environment" in scope:
        bounded(scope["environment"], 128)
    hashes = value.get("source_sha256", {})
    if not isinstance(hashes, dict) or len(hashes) > 8 or (origin == "source_observation" and not hashes):
        raise ShareError(400, "source observations require source hashes")
    for filename, sha in hashes.items():
        path(filename)
        matching(sha, r"[a-f0-9]{64}")
    observed, expiry = value.get("observed_at"), value.get("expires_at")
    if (observed is None and ("environment" in scope or expiry is not None)
            or observed is not None and (type(observed) is not int or not 0 <= observed <= at)
            or expiry is not None and (type(expiry) is not int or expiry <= observed)):
        raise ShareError(400, "invalid fact observation or expiry time")
    evidence = sorted({bounded(item, 512) for item in sequence(value.get("evidence", []), 8)})
    return {"statement": value["statement"], "origin": origin, "scope": scope,
            "source_sha256": hashes, "evidence": evidence, "observed_at": observed, "expires_at": expiry}


class Registry:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not self.path.exists():
            try:
                with os.fdopen(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"):
                    pass
            except FileExistsError:
                pass
        with self.connect() as db:
            db.executescript(REGISTRY)
            if db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'approved_pull_requests'").fetchone():
                db.execute("INSERT OR IGNORE INTO pull_request_runs SELECT * FROM approved_pull_requests")

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            with db:
                if write:
                    db.execute("BEGIN IMMEDIATE")
                yield db
        finally:
            db.close()

    def enroll(self, repo, audience, organization, database, writer_env, initial_manager,
               storage=cloud_store, lookup=cloud_database):
        identifier = enrollment_id(repo, audience)
        actor = human(initial_manager)
        matching(writer_env, r"MEHSCAN_TURSO_WRITE_TOKEN_[A-Z0-9_]{1,64}")
        database_id, remote = lookup(organization, database)
        row = {"id": identifier, "repository_id": repo, "audience": audience, "organization": organization,
               "database_name": database, "writer_env": writer_env, "database_id": database_id, "remote": remote}
        with self.connect(write=True) as db:
            db.execute("INSERT INTO enrollments (id,repository_id,audience,organization,database_name,writer_env,database_id,remote) "
                       "VALUES (:id,:repository_id,:audience,:organization,:database_name,:writer_env,:database_id,:remote)", row)
            db.execute("INSERT INTO identities VALUES (?) ON CONFLICT DO NOTHING", (actor,))
            db.execute("INSERT INTO grants VALUES (?, ?, 'Manager')", (identifier, actor))
            storage(row).initialize()
        return row

    def issue(self, name, hours):
        actor = human(name)
        if not 1 <= hours <= 24 * 30:
            raise ShareError(400, "application token lifetime must be between one hour and thirty days")
        token = "msk_" + secrets.token_urlsafe(32)
        expiry = int(time.time()) + hours * 3600
        with self.connect(write=True) as db:
            db.execute("INSERT INTO identities VALUES (?) ON CONFLICT DO NOTHING", (actor,))
            db.execute("INSERT INTO tokens VALUES (?, ?, ?)", (digest(token), actor, expiry))
        return {"actor": actor, "token": token, "expires_at": expiry}

    def revoke(self, name):
        with self.connect(write=True) as db:
            changed = db.execute("DELETE FROM tokens WHERE actor = ?", (human(name),)).rowcount
        return {"revoked": changed}


def github_verifier(audience):
    import jwt

    keys = jwt.PyJWKClient(ISSUER + "/.well-known/jwks", timeout=10, lifespan=300)

    def verify(token):
        try:
            if jwt.get_unverified_header(token).get("alg") != "RS256":
                raise jwt.InvalidTokenError()
            claims = jwt.decode(token, keys.get_signing_key_from_jwt(token).key, algorithms=["RS256"],
                                issuer=ISSUER, audience=audience, leeway=15,
                                options={"require": ["iss", "aud", "iat", "nbf", "exp", *CLAIMS], "strict_aud": True})
            if not 0 < claims["exp"] - claims["iat"] <= 600 or claims["iat"] < time.time() - 600:
                raise jwt.InvalidTokenError()
            if any(not isinstance(claims[key], str) for key in CLAIMS):
                raise jwt.InvalidTokenError()
            return claims
        except (jwt.PyJWTError, TypeError, ValueError):
            raise ShareError(401, "GitHub Actions credential is invalid or expired") from None

    return verify


def workflow_policy(policy):
    fields(policy, ("workflow_ref", "ref", "environment", "stream", "events"))
    ref = matching(policy["ref"], r"refs/heads/[a-zA-Z0-9._/-]{1,160}")
    workflow = matching(policy["workflow_ref"],
                        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@refs/heads/[a-zA-Z0-9._/-]+")
    if not workflow.endswith("@" + ref):
        raise ShareError(400, "workflow and protected branch must match")
    matching(policy["environment"], r"[a-zA-Z0-9_.-]{1,80}")
    stream_name(policy["stream"])
    events = sequence(policy["events"], len(EVENTS))
    if not events or any(not isinstance(event, str) or event not in EVENTS for event in events):
        raise ShareError(400, "workflow events must be approved branch runs")
    return policy


def enrolled_policy(db, enrollment):
    row = db.execute("SELECT policy FROM workflows WHERE enrollment = ?", (enrollment,)).fetchone()
    return parse_document(row["policy"]) if row else None


def saved_binding(db, enrollment, run):
    row = db.execute("SELECT binding FROM pull_request_runs WHERE enrollment = ? AND run_id = ? AND run_attempt = ?",
                     (enrollment, *run)).fetchone()
    return parse_document(row["binding"]) if row else None


def validate_binding(binding, policy, claims, number):
    if (not binding or binding["pull_request"] != number or binding["policy"] != digest(policy)
            or claims["event_name"] != binding.get("event", "workflow_dispatch")
            or claims["workflow_sha"] != binding.get("workflow_sha", claims["workflow_sha"])):
        raise ShareError(403, "bind this protected workflow run to the pull request before publishing")


def authorize(db, enrolled, token, verified):
    enrollment = enrolled["id"]
    if verified is None:
        row = db.execute("""SELECT tokens.actor, grants.role FROM tokens JOIN grants ON grants.actor = tokens.actor
                          WHERE digest = ? AND expires_at > ? AND enrollment = ?""",
                         (digest(token), int(time.time()), enrollment)).fetchone()
        if not row:
            raise ShareError(403, "active sharing grant required")
        return row["actor"], row["role"], None
    policy = enrolled_policy(db, enrollment)
    if (not policy or verified["repository_id"] != enrolled["repository_id"]
            or any(verified[key] != policy[key] for key in ("workflow_ref", "ref", "environment"))
            or verified["event_name"] not in policy["events"]
            or verified["workflow_sha"] != verified["sha"]
            or verified.get("job_workflow_ref", verified["workflow_ref"]) != verified["workflow_ref"]
            or verified.get("job_workflow_sha", verified["workflow_sha"]) != verified["workflow_sha"]):
        raise ShareError(403, "GitHub Actions run does not match the enrolled protected workflow")
    return "actions:" + verified["workflow_ref"], "Scanner", policy


class Service:
    def __init__(self, registry, verify_actions, reader=cloud_reader, storage=cloud_store,
                 pull_request=github_pull_request):
        self.registry, self.verify_actions, self.reader, self.storage = registry, verify_actions, reader, storage
        self.pull_request = pull_request

    def dispatch(self, route, token, data):
        if not token or len(token) > 16000 or any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise ShareError(401, "sharing credential required")
        fields(data, ("repository_id", "audience"), ("submission",))
        repo, audience = data["repository_id"], data["audience"]
        identifier = enrollment_id(repo, audience)
        verified = None if token.startswith("msk_") else self.verify_actions(token)
        with self.registry.connect(write=route in ("/v1/grant", "/v1/workflow", "/v1/pr-target", "/v1/publish", "/v1/fact")) as db:
            enrollment = db.execute("SELECT * FROM enrollments WHERE id = ? AND active = 1", (identifier,)).fetchone()
            if not enrollment:
                raise ShareError(403, "active sharing grant required")
            actor, role, policy = authorize(db, enrollment, token, verified)
            link = {"enrollment": identifier, "repository_key": repository_key(repo),
                    "audience": audience, "actor": actor, "role": role}
            if route == "/v1/link":
                return link
            if route == "/v1/read-token":
                return {**link, **self.reader(enrollment)}
            body = data.get("submission")
            if route == "/v1/pr-current":
                return self.pr_current(enrollment, enrolled_policy(db, identifier), body)
            if route in ("/v1/grant", "/v1/workflow"):
                if role != "Manager":
                    raise ShareError(403, "Manager grant required")
                if route == "/v1/workflow":
                    if body is None:
                        db.execute("DELETE FROM workflows WHERE enrollment = ?", (identifier,))
                        return {"workflow": None}
                    db.execute("INSERT INTO workflows VALUES (?, ?) ON CONFLICT(enrollment) DO UPDATE SET policy=excluded.policy",
                               (identifier, canonical(workflow_policy(body))))
                    return {"workflow": body["workflow_ref"], "stream": body["stream"]}
                return self.grant(db, identifier, actor, body)
            if route in ("/v1/publish", "/v1/pr-target"):
                if role != "Scanner" or verified is None:
                    raise ShareError(403, "enrolled GitHub Actions Scanner required")
                binding = saved_binding(db, identifier, workflow_run(verified))
                if route == "/v1/pr-target":
                    return self.bind_pr(db, enrollment, policy, verified, body, binding)
                return self.publish(enrollment, actor, policy, verified, body, binding)
            if route == "/v1/fact":
                if role not in ("Contributor", "Manager"):
                    raise ShareError(403, "Contributor or Manager grant required")
                return self.fact(enrollment, actor, body)
            raise ShareError(404, "unknown sharing endpoint")

    @staticmethod
    def grant(db, enrollment, manager, body):
        fields(body, ("name", "role"))
        actor = human(body["name"])
        role = body["role"]
        if actor == manager:
            raise ShareError(403, "a Manager cannot change their own grant")
        if role is None:
            db.execute("DELETE FROM grants WHERE enrollment = ? AND actor = ?", (enrollment, actor))
        else:
            if role not in ("Viewer", "Contributor", "Manager"):
                raise ShareError(400, "set Scanner grants through the protected workflow policy")
            if not db.execute("SELECT 1 FROM identities WHERE actor = ?", (actor,)).fetchone():
                raise ShareError(400, "issue a credential for this identity first")
            db.execute("INSERT INTO grants VALUES (?, ?, ?) ON CONFLICT(enrollment,actor) DO UPDATE SET role=excluded.role",
                       (enrollment, actor, role))
        return {"actor": actor, "role": role}

    def enrolled_pr(self, enrollment, policy, number):
        repo = policy["workflow_ref"].split("/.github/workflows/", 1)[0]
        pr = self.pull_request(repo, number)
        repositories = (pr["base_repository"], pr["source_repository"])
        if (pr["pull_request"] != number or "refs/heads/" + pr["base_ref"] != policy["ref"]
                or any(not entry or str(entry["id"]) != enrollment["repository_id"] for entry in repositories)):
            raise ShareError(403, "pull request must target the protected branch of the enrolled repository")
        return pr

    @staticmethod
    def pr_scope(body):
        scope = body.get("path_prefix", "")
        return path(scope) if scope != "" else scope

    def bind_pr(self, db, enrollment, policy, claims, body, previous):
        fields(body, ("pull_request",), ("event_head_sha", "path_prefix"))
        number, scope = pull_number(body["pull_request"]), self.pr_scope(body)
        event = claims["event_name"]
        if event not in PR_EVENTS:
            raise ShareError(403, "pull request binding requires an enrolled PR trigger or manual dispatch")
        automatic = event == "pull_request_target"
        event_head = commit_sha(body.get("event_head_sha")) if automatic else None
        if previous:
            if (previous["pull_request"] != number or scope != previous.get("path_prefix", "")
                    or (automatic and event_head != previous["head_sha"])):
                raise ShareError(409, "workflow run is already bound to a different pull request snapshot")
            validate_binding(previous, policy, claims, number)
            return previous
        pr = self.enrolled_pr(enrollment, policy, number)
        if pr["state"] != "open" or pr["draft"]:
            raise ShareError(409, "pull request must be open and ready for review")
        base, head = commit_sha(pr["base_commit"]), commit_sha(pr["target_commit"])
        if automatic:
            for claim, ref in (("base_ref", pr["base_ref"]), ("head_ref", pr["source_ref"])):
                if claims.get(claim) not in (ref, "refs/heads/" + ref):
                    raise ShareError(403, "run refs do not match the pull request")
            if head != event_head:
                raise ShareError(409, "a newer pull request head superseded this event before review")
        run = workflow_run(claims)
        binding = {"pull_request": number, "base_sha": base, "head_sha": head, "path_prefix": scope,
                   "bound_at": int(time.time()), "run_id": run[0], "run_attempt": run[1], "stream": f"pr:{number}",
                   "policy": digest(policy), "event": event, "workflow_sha": claims["workflow_sha"]}
        if automatic:
            store = self.storage(enrollment)
            store.check_binding()
            compatible = {"base": base, "policy": binding["policy"], "workflow_sha": binding["workflow_sha"]}
            if run[1] == "1" and (existing := store.latest_pr(binding["stream"], scope, head=head, **compatible)):
                return {"status": "already_reviewed", "result": existing}
            prior = store.latest_pr(binding["stream"], scope, **compatible)
            if prior and prior["commit_sha"] != head:
                binding["previous_head_sha"] = prior["commit_sha"]
        db.execute("INSERT INTO pull_request_runs VALUES (?, ?, ?, ?)",
                   (enrollment["id"], *run, canonical(binding)))
        return binding

    def pr_current(self, enrollment, policy, body):
        fields(body, ("pull_request",), ("path_prefix",))
        number, scope = pull_number(body["pull_request"]), self.pr_scope(body)
        stream = f"pr:{number}"
        store = self.storage(enrollment)
        store.check_binding()
        latest = store.latest_pr(stream, scope)
        try:
            pr = self.enrolled_pr(enrollment, policy, number) if policy else None
        except ShareError as error:
            return {"status": "historical" if error.status == 403 else "unconfirmed", "result": latest}
        if not pr:
            return {"status": "unconfirmed", "result": latest}
        if pr["state"] != "open" or pr["draft"]:
            return {"status": "historical" if latest else "pending", "result": latest}
        base, head = commit_sha(pr["base_commit"]), commit_sha(pr["target_commit"])
        current = store.latest_pr(stream, scope, base=base, head=head)
        return {"status": "current" if current else "historical" if latest else "pending",
                "head_sha": head, "base_sha": base, "result": current or latest}

    def publish(self, enrollment, actor, policy, claims, body, binding):
        fields(body, ("commit", "run_id", "run_attempt", "batch"), ("pull_request",))
        commit = commit_sha(body["commit"])
        if workflow_run(body) != workflow_run(claims):
            raise ShareError(403, "retained review must bind the authenticated run and source commit")
        pull_request = "pull_request" in body
        if pull_request:
            validate_binding(binding, policy, claims, pull_number(body["pull_request"]))
            if commit != binding["head_sha"]:
                raise ShareError(403, "retained review does not match the pinned pull request head")
            stream = binding["stream"]
        else:
            if binding or claims["event_name"] == "pull_request_target" or commit != claims["sha"]:
                raise ShareError(403, "retained review must bind the authenticated branch run and source commit")
            stream = policy["stream"]
        verify_batch(body["batch"], enrollment["repository_id"], stream)
        comparison = body["batch"].get("comparison")
        if comparison and (comparison["target_commit"] != commit or comparison["head_commit"] != commit):
            raise ShareError(403, "retained Git comparison must bind the pinned checkout commit")
        if pull_request and "path_prefix" in binding and body["batch"]["repository"]["path_prefix"] != binding["path_prefix"]:
            raise ShareError(403, "retained review does not match the pinned scan root")
        if pull_request and (not comparison or comparison["working_tree"] or comparison["base_commit"] != binding["base_sha"]
                or comparison["requested_base"] != binding["base_sha"] or comparison.get("requested_target") != commit
                or comparison.get("merge_base_commit") is None):
            raise ShareError(403, "pull request publication requires the pinned Git comparison and merge base")
        if "sharing" in body["batch"] and body["batch"]["sharing"] != {
                "enrollment": enrollment["id"], "database_id": enrollment["database_id"]}:
            raise ShareError(403, "retained review belongs to a different sharing audience")
        event_id = digest(["review", enrollment["id"], actor, body["run_id"], body["run_attempt"], body["batch"]["batch"]])
        store = self.storage(enrollment)
        store.check_binding()
        payload = {"authority": "advisory", "run_id": body["run_id"], "run_attempt": body["run_attempt"],
                   "workflow_ref": claims["workflow_ref"], "ref": claims["ref"], "batch": body["batch"]}
        if pull_request:
            payload["pull_request"] = binding
            payload["workflow_sha"] = claims["workflow_sha"]
        return receipt(store.append(event_id=event_id, request_digest=digest(payload), kind="review",
                                    actor=actor, stream=stream, commit=commit, payload=payload))

    def fact(self, enrollment, actor, body):
        fields(body, ("key", "operation", "parent_revision", "fact"))
        if len(canonical(body)) > 32 * 1024:
            raise ShareError(413, "shared fact exceeds the size limit")
        key = bounded(body["key"], 256)
        matching(body["operation"], r"[a-zA-Z0-9][a-zA-Z0-9:._-]{0,127}")
        parent = body["parent_revision"]
        if parent is not None:
            matching(parent, r"[a-f0-9]{64}")
        item_id = digest(["fact", enrollment["id"], actor, key])
        event_id = digest(["fact-revision", item_id, body["operation"]])
        request_digest = digest(body)
        store = self.storage(enrollment)
        store.check_binding()
        saved = store.get(event_id)
        if saved:
            if saved["digest"] != request_digest:
                raise ShareError(409, "sharing operation ID was already used for a different submission")
            return receipt(saved)
        previous = store.get(parent) if parent else None
        if parent and (not previous or previous["kind"] != "fact" or previous["payload"]["item_id"] != item_id):
            raise ShareError(409, "fact revision does not belong to this author and key")
        withdrawn = body["fact"] is None
        if withdrawn and (not previous or previous["payload"]["withdrawn"]):
            raise ShareError(409, "withdrawal requires a current authored fact")
        if withdrawn:
            values = {key: previous["payload"][key] for key in (
                "statement", "origin", "scope", "source_sha256", "evidence", "observed_at", "expires_at")}
        else:
            values = verify_fact(body["fact"], int(time.time()))
        payload = {**values, "author": actor, "key": key, "item_id": item_id, "revision_id": event_id,
                   "parent_revision": parent, "withdrawn": withdrawn}
        return receipt(store.append(event_id=event_id, request_digest=request_digest, kind="fact",
                                    actor=actor, stream=None, commit=None, item_id=item_id,
                                    parent=parent or "", payload=payload))


def receipt(row):
    return {key: row[key] for key in ("seq", "id", "kind", "actor", "stream", "commit_sha", "created_at")}


def http_server(service, address):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(20)

        def log_message(self, *_):
            pass

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_DOCUMENT:
                    raise ShareError(413, "invalid sharing request size")
                scheme, _, token = self.headers.get("Authorization", "").partition(" ")
                if scheme != "Bearer":
                    raise ShareError(401, "sharing credential required")
                reply = service.dispatch(self.path, token, parse_document(self.rfile.read(size)))
                status = 200
            except ShareError as error:
                reply, status = {"error": str(error)}, error.status
            except (ValueError, TypeError, KeyError, RecursionError):
                reply, status = {"error": "invalid sharing document"}, 400
            except (sqlite3.Error, OSError):
                reply, status = {"error": "sharing service is unavailable"}, 503
            data = canonical(reply).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    return ThreadingHTTPServer(address, Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll")
    for option in ("repository-id", "audience", "organization", "database", "writer-env", "manager"):
        enroll.add_argument("--" + option, required=True)
    issue = commands.add_parser("issue")
    issue.add_argument("--name", required=True)
    issue.add_argument("--hours", type=int, default=168)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--name", required=True)
    disable = commands.add_parser("disable")
    disable.add_argument("--repository-id", required=True)
    disable.add_argument("--audience", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8281)
    serve.add_argument("--oidc-audience", required=True)
    args = parser.parse_args()
    try:
        registry = Registry(args.registry)
        if args.command == "serve":
            service = Service(registry, github_verifier(bounded(args.oidc_audience, 256)))
            with http_server(service, ("127.0.0.1", args.port)) as server:
                server.serve_forever()
            return
        if args.command == "enroll":
            result = registry.enroll(args.repository_id, args.audience, args.organization, args.database,
                                     args.writer_env, args.manager)
        elif args.command == "issue":
            result = registry.issue(args.name, args.hours)
        elif args.command == "revoke":
            result = registry.revoke(args.name)
        else:
            with registry.connect(write=True) as db:
                changed = db.execute("UPDATE enrollments SET active = 0 WHERE id = ? AND active = 1",
                                     (enrollment_id(args.repository_id, args.audience),)).rowcount
            result = {"disabled": bool(changed)}
        print(json.dumps(result))
    except (ShareError, sqlite3.IntegrityError, ImportError) as error:
        parser.exit(2, f"{error}\n")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
