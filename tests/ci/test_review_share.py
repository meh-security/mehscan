"""Enrollment, publication, and readback through the hosted review API."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import copy
import os
import sqlite3
import subprocess
import sys
import tempfile
from threading import Thread
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_host as host
import review_share as client
import review_share_storage as storage


REPO = "123"
AUDIENCE = "team"
WORKFLOW = "owner/repo/.github/workflows/review.yml@refs/heads/main"
REF = "refs/heads/main"
COMMIT = "a" * 40
SHA = "b" * 64
POLICY = {"workflow_ref": WORKFLOW, "ref": REF, "environment": "Review", "stream": "main",
          "events": ["push", "schedule", "workflow_dispatch"]}
CLAIMS = {"sub": "repo:owner/repo:environment:Review", "repository_id": REPO,
          "workflow_ref": WORKFLOW, "workflow_sha": COMMIT, "sha": COMMIT, "ref": REF,
          "environment": "Review", "event_name": "push", "run_id": "45", "run_attempt": "1"}


def sqlite_execute(path, read_only=False):
    def execute(sql, *args):
        uri = Path(path).as_uri() + "?mode=ro" if read_only else str(path)
        with closing(sqlite3.connect(uri, uri=read_only)) as db, db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(sql, args)]
    return execute


def batch():
    return {"schema_version": 1, "batch": SHA, "repository": {"repository_key": host.repository_key(REPO), "path_prefix": ""},
            "repository_id": SHA, "snapshot_id": SHA, "source_fingerprint": "review-sources-v1-" + SHA,
            "inventory_fingerprint": SHA, "stream": "main", "attempt_status": "incomplete",
            "assessments": [{"decision_id": "mehscanDecision/v1:" + SHA, "review_id": "review:1",
                "subject_key": "mehscanSubject/v1:" + SHA, "basis_fingerprint": SHA,
                "response_fingerprint": SHA, "verdict": "needs_review", "confidence": "medium",
                "summary": "Check the trusted entry conditions.",
                "questions": [{"kind": "check", "text": "What paths reach the operation?"}],
                "evidence": [{"kind": "primary", "reference": "anchor", "path": "src/app.js",
                    "start_line": 1, "end_line": 1, "start_byte": 0, "end_byte": 15, "excerpt_sha256": None}]}],
            "file_dependencies": [{"decision_id": "mehscanDecision/v1:" + SHA,
                                   "role": "primary", "path": "src/app.js", "sha256": SHA}]}


def save_fixture_responses(run, decision):
    manifest = storage.parse_document((run / "manifest.json").read_bytes())
    for bundle in manifest["bundles"]:
        name = bundle["filename"]
        request = storage.parse_document((run / "requests" / name).read_bytes())
        results = []
        for review in request["reviews"]:
            if request["review_kind"] == "security_path":
                anchor = review["candidate"]["sink"]["id"]
            else:
                offered = [item for item in review["evidence"] if item["id"] in review["anchor_evidence_ids"]]
                anchor = next(item["id"] for kind in ("sink", "sensitive_operation", "security_configuration")
                              for item in offered if item["kind"] == kind)
            results.append({"review_id": review["id"], "selected_anchor_id": anchor, "decision": decision,
                "confidence": "medium", "summary": "Retained finding context for the sharing test.",
                "checks": ["Confirm which caller reaches the entry point."] if decision == "needs_review" else [],
                "investigation": {"decisive_artifacts": [], "journal_summary": None,
                    "citations": [{"artifact_id": anchor, "claim": "Native operation."}],
                    "reviewer_inferences": [], "reviewer_origin_leads": [], "blockers": []}})
        (run / "responses" / name).write_text(storage.canonical({"schema_version": "1.3",
            "bundle_fingerprint": request["bundle_fingerprint"], "results": results}), encoding="utf-8")


class ReviewSharing(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.registry = host.Registry(self.base / "registry.sqlite")
        self.enroll(AUDIENCE, "publications")
        self.enroll("restricted", "restricted-publications")
        self.manager = self.registry.issue("ana", 1)["token"]
        self.viewer = self.registry.issue("vic", 1)["token"]
        self.contributor = self.registry.issue("cam", 1)["token"]
        self.claims = CLAIMS.copy()
        self.leases = []
        service = host.Service(self.registry, self.verify, reader=self.reader, storage=self.storage)
        self.server = host.http_server(service, ("127.0.0.1", 0))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.post("grant", self.manager, {"name": "vic", "role": "Viewer"})
        self.post("grant", self.manager, {"name": "cam", "role": "Contributor"})
        self.post("workflow", self.manager, POLICY)

    def enroll(self, audience, database):
        return self.registry.enroll(REPO, audience, "test-org", database, "MEHSCAN_TURSO_WRITE_TOKEN_TEST", "ana",
                                    storage=self.storage, lookup=lambda org, name: ("id:" + name, "https://" + name + ".turso.io"))

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def storage(self, enrollment, read_only=False):
        db = self.base / (enrollment["database_name"] + ".sqlite")
        return storage.EventStore(sqlite_execute(db, read_only), enrollment["id"])

    def reader(self, enrollment):
        token = f"test-read-{len(self.leases)}"
        self.leases.append((token, dict(enrollment)))
        return {"remote": enrollment["remote"], "token": token,
                "database_id": enrollment["database_id"], "expires_in_seconds": 900}

    def read_with_lease(self, remote, token):
        matched = next(row for issued, row in self.leases if issued == token)
        self.assertEqual(matched["remote"], remote)
        return self.storage(matched, read_only=True).execute

    def verify(self, token):
        if token != "test-actions-jwt":
            raise storage.ShareError(401, "invalid test identity")
        return self.claims.copy()

    def post(self, route, token, body=None, audience=AUDIENCE, repo=REPO):
        request = {"repository_id": repo, "audience": audience}
        if body is not None:
            request["submission"] = body
        return storage.request_json(self.url + "/v1/" + route, "POST", token, request, api_status=True)

    def rejected(self, status, route, token, body=None, **scope):
        with self.assertRaises(storage.ShareError) as issue:
            self.post(route, token, body, **scope)
        self.assertEqual(issue.exception.status, status)

    def test_roles_revoke_and_isolated_read_credentials(self):
        self.assertEqual(self.post("link", self.viewer)["role"], "Viewer")
        self.assertEqual(self.post("link", self.contributor)["role"], "Contributor")
        self.rejected(403, "link", self.viewer, audience="restricted")
        self.rejected(403, "read-token", self.viewer, repo="999")
        self.rejected(403, "fact", self.viewer, {})
        self.rejected(403, "workflow", self.contributor, POLICY)
        self.rejected(403, "publish", self.manager, {})
        self.rejected(403, "grant", self.manager, {"name": "ana", "role": None})
        first = self.post("read-token", self.viewer)
        self.assertEqual(first["expires_in_seconds"], 900)
        self.assertNotEqual(first["token"], self.post("read-token", self.viewer)["token"])
        self.post("grant", self.manager, {"name": "vic", "role": None})
        self.rejected(403, "read-token", self.viewer)
        self.registry.revoke("cam")
        self.rejected(403, "link", self.contributor)
        with self.registry.connect(write=True) as db:
            db.execute("UPDATE tokens SET expires_at = 0 WHERE actor = 'user:ana'")
        self.rejected(403, "read-token", self.manager)
        with self.assertRaises(sqlite3.IntegrityError):
            self.enroll("third-audience", "publications")

    def test_pinned_workload_publication_and_second_client_readback(self):
        submission = {"commit": COMMIT, "run_id": "45", "run_attempt": "1", "batch": batch()}
        for claim, changed in {"repository_id": "999", "environment": "Other", "ref": "refs/heads/topic",
                               "event_name": "pull_request", "workflow_ref": WORKFLOW.replace(".yml", "2.yml"),
                               "workflow_sha": "c" * 40, "run_attempt": "2", "sha": "c" * 40,
                               "job_workflow_ref": "owner/repo/other"}.items():
            with self.subTest(claim=claim):
                self.claims = {**CLAIMS, claim: changed}
                self.rejected(403, "publish", "test-actions-jwt", submission)
        self.claims = CLAIMS.copy()
        self.rejected(403, "publish", "test-actions-jwt", submission, audience="restricted")
        altered = copy.deepcopy(submission)
        altered["batch"]["stream"] = "other-stream"
        self.rejected(403, "publish", "test-actions-jwt", altered)
        altered["batch"]["stream"] = "main"
        altered["batch"]["repository"]["source_repository_key"] = host.repository_key("999")
        self.rejected(403, "publish", "test-actions-jwt", altered)
        altered = copy.deepcopy(submission)
        altered["batch"]["sharing"] = {"enrollment": host.enrollment_id(REPO, "restricted"),
                                       "database_id": "id:restricted-publications"}
        self.rejected(403, "publish", "test-actions-jwt", altered)

        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(pool.map(lambda _: self.post("publish", "test-actions-jwt", submission), range(2)))
        self.assertEqual(receipts[0], receipts[1])
        receipt = receipts[0]
        self.assertEqual((receipt["actor"], receipt["commit_sha"]), ("actions:" + WORKFLOW, COMMIT))
        altered = copy.deepcopy(submission)
        altered["batch"]["assessments"][0]["summary"] = "Conflicting retry."
        self.rejected(409, "publish", "test-actions-jwt", altered)

        linked = {**self.post("link", self.viewer), "host": self.url, "repository_id": REPO}

        with patch.dict(os.environ, {"MEHSCAN_SHARE_TOKEN": self.viewer}), patch.object(client, "sql_database", self.read_with_lease):
            reader = client.read_store(linked)
            self.assertEqual(reader.list(0), [receipt])
            self.assertEqual(reader.list(receipt["seq"]), [])
            item = reader.get(receipt["id"])
            self.assertEqual(item["payload"]["batch"], submission["batch"])
            self.assertEqual(item["payload"]["authority"], "advisory")
            with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                reader.execute("UPDATE mehscan_shared_events SET stream = 'other'")
        self.post("workflow", self.manager)
        self.rejected(403, "publish", "test-actions-jwt", submission)

    def test_shared_revisions_reach_normal_review_and_reopen_only_affected_work(self):
        project = Path(__file__).resolve().parents[2]
        scanner = Path(os.environ.get("MEHSCAN_TEST_SCANNER", project / "target/debug"
                                     / ("mehscan.exe" if os.name == "nt" else "mehscan")))
        if not scanner.is_file():
            self.skipTest("build the native CLI to exercise linked review preparation")
        first_root, second_root = (self.base / label for label in ("author-checkout", "review-checkout"))
        first_root.mkdir()
        for filename in ("app.js", "other.js"):
            (first_root / filename).write_text("function handle(request) { eval(request.query.code); }\n", encoding="utf-8")
        git = ["git", "-C", str(first_root)]
        subprocess.run([*git, "init", "--quiet"], check=True, timeout=20)
        subprocess.run([*git, "add", "."], check=True, timeout=20)
        subprocess.run([*git, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "--quiet", "-m", "source"], check=True, timeout=20)
        subprocess.run(["git", "clone", "--quiet", str(first_root), str(second_root)], check=True, timeout=30)

        def native(*args, home=None, reject=None):
            environment = client.child_env()
            if home:
                environment["MEHSCAN_STATE_HOME"] = str(home)
            result = subprocess.run([str(scanner), *map(str, args)], capture_output=True, text=True,
                                    env=environment, timeout=60)
            if reject:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reject, result.stderr)
                return None
            self.assertEqual(result.returncode, 0, result.stderr)
            return storage.parse_document(result.stdout)

        def linked(root, directory, *, token=self.viewer, audience=AUDIENCE):
            directory = self.base / directory
            directory.mkdir()
            inventory = directory / "inventory"
            native("investigate", "review-inventory", root, "--repository-key", host.repository_key(REPO),
                   "--source-repository-key", host.repository_key(REPO), "--output", inventory)
            link = {**self.post("link", token, audience=audience), "host": self.url, "repository_id": REPO}
            path = directory / "link.json"
            path.write_text(storage.canonical(link), encoding="utf-8")
            return SimpleNamespace(scanner=scanner, source_root=root, inventory=inventory, link=path), link

        def sync(pair, token=self.viewer):
            with patch.dict(os.environ, {"MEHSCAN_SHARE_TOKEN": token}), \
                    patch.object(client, "sql_database", self.read_with_lease):
                return client.sync_facts(*pair)

        draft = {"key": "entry-context", "operation": "add", "parent_revision": None,
                 "fact": {"statement": "Confirm the caller scope for this operation.",
                          "origin": "assertion", "scope": {"path": "app.js"}}}
        received = self.post("fact", self.contributor, draft)
        stale_source = self.post("fact", self.contributor, {
            "key": "other-entry", "operation": "add", "parent_revision": None,
            "fact": {"statement": "Locate the entry point in other.js.", "origin": "source_observation",
                     "scope": {"path": "other.js"}, "source_sha256": {"other.js": "0" * 64}},
        })
        first, second = linked(first_root, "author-control"), linked(second_root, "review-control")
        with patch.object(storage, "FACT_PAGE_SIZE", 1):
            snapshot = sync(second)
        self.assertEqual(sync(first)["sharing"], snapshot["sharing"])
        self.assertEqual(snapshot["imported"], 2)
        self.assertEqual(sync(second)["imported"], 0)
        self.assertNotEqual(sync(first)["memory_store"], snapshot["memory_store"])
        args = second[0]
        home = snapshot["state_home"]
        journal = snapshot["state_store"]
        source_args = ["--source-root", args.source_root, "--inventory", args.inventory]
        entries = storage.parse_document((args.inventory / "inventory.json").read_bytes())["entries"]
        ids = {row["path"]: row["review_id"] for row in entries}
        self.assertEqual(set(ids), {"app.js", "other.js"})
        affected, unaffected = ids["app.js"], ids["other.js"]
        skill = args.link.parent / "skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("Trusted fixture review instructions.", encoding="utf-8")
        plan = args.link.parent / "plan.json"
        work = args.link.parent / "work.json"

        def plan_generation(generation):
            previous = generation - 1
            claim = native("state", "claim", "--store", journal, "--stream", "main", *source_args,
                           "--attempt-id", str(generation), "--expected-generation", str(previous),
                           "--retry", "true" if previous else "false", "--operation-key", f"claim-{generation}", home=home)
            scope = ["--stream", "main", *source_args, "--generation", str(generation), "--owner", claim["result"]["owner"]]
            state = ["--store", journal, *scope]
            draft = native("state", "plan-template", *source_args, "--policy", "value", "--skill-root", skill, home=home)
            plan.write_text(storage.canonical(draft), encoding="utf-8")
            native("state", "plan", *state, "--input", plan, "--skill-root", skill, "--operation-key", f"plan-{generation}", home=home)
            return scope, state

        scope, state = plan_generation(1)
        initial = native("state", "work", *state, "--skill-root", skill, home=home)
        initial_knowledge = initial["payload"]["knowledge"]
        self.assertEqual(initial_knowledge["sharing"], snapshot["sharing"])
        self.assertEqual(initial_knowledge["by_review"], {affected: [received["id"]]})
        self.assertNotIn(stale_source["id"], storage.canonical(initial))
        work.write_text(storage.canonical(initial), encoding="utf-8")
        run = args.link.parent / "bundles"
        native("investigate", "review-bundles", args.source_root, "--inventory", args.inventory,
               "--review-ids", ",".join(ids.values()), "--output", run, home=home)
        save_fixture_responses(run, "not_issue")
        native("state", "record", *state, "--run", run, "--work-package", work, "--skill-root", skill,
               "--operation-key", "baseline", home=home)
        closed = native("state", "end", *state, "--status", "finished", "--operation-key", "end", home=home)
        self.assertEqual(closed["memory"]["status"], "retained")
        exported = native("memory", "export", *source_args, "--stream", "main", "--batch",
                          closed["memory"]["batch"], home=home)
        self.assertEqual(exported["sharing"], snapshot["sharing"])

        changed = self.post("fact", self.contributor, {**draft, "operation": "change", "parent_revision": received["id"],
                            "fact": {**draft["fact"], "statement": "Check the new caller evidence."}})
        database = self.storage({"database_name": "publications", "id": snapshot["sharing"]["enrollment"]})
        valid = database.get(changed["id"])
        event = {key: valid[key] for key in ("seq", "id", "actor", "payload")}
        bad = {**event, "seq": event["seq"] + 1, "id": "f" * 64,
               "payload": {**event["payload"], "revision_id": "f" * 64, "parent_revision": None}}
        page = args.link.parent / "rejected-page.json"
        page.write_text(storage.canonical({"sharing": snapshot["sharing"], "after": snapshot["cursor"]["after"],
                                           "facts": [event, bad]}), encoding="utf-8")
        native("memory", "shared-facts", *source_args, "--input", page, home=home,
               reject="does not extend the current revision")
        self.assertEqual(native("memory", "shared-facts", *source_args, home=home)["cursor"], snapshot["cursor"])
        self.assertEqual(sync(second)["imported"], 1)
        scope, state = plan_generation(2)
        prepare = ["memory", "prepare", "--state-store", journal, *scope, "--skill-root", skill]
        fresh = native(*prepare, home=home)
        self.assertEqual(fresh["memory"]["reused_review_ids"], [unaffected])
        package = fresh["work_package"]
        self.assertEqual(package["payload"]["review_ids"], [affected])
        self.assertEqual(package["payload"]["knowledge"]["by_review"], {affected: [changed["id"]]})
        work.write_text(storage.canonical(package), encoding="utf-8")
        withdrawal = self.post("fact", self.contributor, {**draft, "operation": "withdraw",
                               "parent_revision": changed["id"], "fact": None})
        self.assertEqual(sync(second)["cursor"]["event_id"], withdrawal["id"])
        native("state", "record", *state, "--run", run, "--work-package", work, "--skill-root", skill,
               "--operation-key", "stale", home=home, reject="applicable knowledge changed")
        refreshed = native(*prepare, home=home)["work_package"]
        self.assertEqual(refreshed["payload"]["review_ids"], [affected])
        self.assertEqual(refreshed["payload"]["knowledge"]["by_review"], {})
        history = native("memory", "knowledge-list", *source_args, "--history", "true", home=home)
        self.assertTrue(any(row["revision"]["withdrawn"] for row in history["items"]))
        restricted = linked(second_root, "restricted-control", token=self.manager, audience="restricted")
        other_store = sync(restricted, self.manager)["memory_store"]
        native("state", "work", *state, "--skill-root", skill, "--memory-store", other_store,
               home=home, reject="different sharing audience")

        database.execute("DELETE FROM mehscan_shared_events WHERE id = ?", withdrawal["id"])
        with self.assertRaisesRegex(storage.ShareError, "no longer contains the local checkpoint"):
            sync(second)

    def test_attributed_fact_history_conflicts_and_retries(self):
        draft = {"key": "route", "operation": "first", "parent_revision": None,
                 "fact": {"statement": "Review the registered route.", "origin": "assertion",
                          "evidence": ["TICKET-18"]}}
        first = self.post("fact", self.contributor, draft)
        self.assertEqual(first["actor"], "user:cam")
        self.assertEqual(first, self.post("fact", self.contributor, draft))
        incompatible = {**draft, "operation": "duplicate-claim"}
        self.rejected(409, "fact", self.contributor, incompatible)
        change = {**draft, "parent_revision": first["id"], "operation": "correction",
                  "fact": {"statement": "Check the production route table.", "origin": "inference"}}
        self.rejected(409, "fact", self.manager, change)
        self.assertNotEqual(self.post("fact", self.manager, draft)["actor"], first["actor"])
        second = self.post("fact", self.contributor, change)
        self.rejected(409, "fact", self.contributor, {**change, "operation": "stale"})
        withdrawal = {**change, "fact": None, "parent_revision": second["id"], "operation": "withdraw"}
        third = self.post("fact", self.contributor, withdrawal)
        self.assertEqual(third, self.post("fact", self.contributor, withdrawal))
        event_db = self.storage({"database_name": "publications", "id": host.enrollment_id(REPO, AUDIENCE)})
        old = event_db.get(first["id"])["payload"]
        new = event_db.get(third["id"])["payload"]
        self.assertEqual(new["item_id"], old["item_id"])
        self.assertFalse(old["withdrawn"])
        self.assertTrue(new["withdrawn"])
        self.assertEqual(new["parent_revision"], second["id"])
        self.assertEqual(len(event_db.list(0)), 4)

    def test_native_retention_publishes_through_client_without_sharing_credentials(self):
        project = Path(__file__).resolve().parents[2]
        scanner = Path(os.environ.get("MEHSCAN_TEST_SCANNER", project / "target/debug"
                                     / ("mehscan.exe" if os.name == "nt" else "mehscan")))
        if not scanner.is_file():
            self.skipTest("build the native CLI to exercise actual retained batches")
        root = self.base / "checkout"
        root.mkdir()
        (root / "app.js").write_text("function handle(request) { eval(request.query.code); }\n", encoding="utf-8")

        def git(*args):
            return subprocess.check_output(["git", "-C", str(root), *args], text=True, timeout=20).strip()

        def native(*args):
            result = subprocess.run([str(scanner), *map(str, args)], capture_output=True, text=True,
                                    env=client.child_env(), timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            return storage.parse_document(result.stdout)

        git("init", "--quiet")
        git("add", "app.js")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "source")
        commit = git("rev-parse", "HEAD")
        self.claims.update(sha=commit, workflow_sha=commit)
        inventory, run, journal, memory = [self.base / name for name in ("inventory", "run", "journal", "memory.turso")]
        native("investigate", "review-inventory", root, "--repository-key", host.repository_key(REPO),
               "--source-repository-key", host.repository_key(REPO), "--output", inventory)
        source = ["--source-root", root, "--inventory", inventory]
        state = ["--store", journal, "--stream", "main", *source]
        claim = native("state", "claim", *state, "--attempt-id", "first", "--expected-generation", "0", "--operation-key", "claim")
        owner = ["--owner", claim["result"]["owner"], "--generation", "1"]
        entries = storage.parse_document((inventory / "inventory.json").read_bytes())["entries"]
        self.assertTrue(entries)
        native("investigate", "review-bundles", root, "--inventory", inventory,
               "--review-ids", ",".join(row["review_id"] for row in entries), "--output", run)
        save_fixture_responses(run, "needs_review")
        native("state", "record", *state, *owner, "--run", run, "--operation-key", "record",
               "--memory-store", memory)
        retained = native("state", "end", *state, *owner, "--status", "incomplete", "--operation-key", "end",
                          "--memory-store", memory)["memory"]
        self.assertEqual(retained["status"], "retained")
        link = {**self.post("link", self.viewer), "host": self.url, "repository_id": REPO}
        args = SimpleNamespace(scanner=scanner, source_root=root, inventory=inventory,
                               store=memory, stream="main", batch=retained["batch"], link=self.base / "link.json")
        environment = {"GITHUB_SHA": commit, "GITHUB_RUN_ID": "45", "GITHUB_RUN_ATTEMPT": "1",
                       "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fixture", "MEHSCAN_TURSO_WRITE_TOKEN_TEST": "fixture"}
        with patch.dict(os.environ, environment), patch.object(client, "app_credential", return_value="test-actions-jwt"):
            self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", client.child_env())
            self.assertNotIn("MEHSCAN_TURSO_WRITE_TOKEN_TEST", client.child_env())
            result = client.publish(args, link)
            self.assertEqual(client.publish(args, link), result)
            (root / "app.js").write_text("// changed\n", encoding="utf-8")
            with self.assertRaisesRegex(storage.ShareError, "clean checkout"):
                client.publish(args, link)
        database = self.storage({"database_name": "publications", "id": link["enrollment"]})
        saved = database.get(result["id"])["payload"]["batch"]
        self.assertEqual(saved["batch"], retained["batch"])
        self.assertEqual(saved["attempt_status"], "incomplete")
        self.assertTrue(saved["assessments"])
        self.assertEqual(saved["assessments"][0]["verdict"], "needs_review")

    def test_stale_or_non_dedicated_database_is_refused(self):
        database = self.base / "extra.sqlite"
        store = storage.EventStore(sqlite_execute(database), host.enrollment_id(REPO, "other"))
        store.execute("CREATE TABLE other_application (secret TEXT)")
        with self.assertRaisesRegex(storage.ShareError, "dedicated"):
            store.initialize()
        first = self.storage({"database_name": "publications", "id": host.enrollment_id(REPO, "unrelated")})
        with self.assertRaisesRegex(storage.ShareError, "another sharing enrollment"):
            first.initialize()


class CredentialAdapters(unittest.TestCase):
    def test_turso_mint_uses_pinned_database_id_and_read_only_lease(self):
        calls = []
        enrollment = {"organization": "org", "database_name": "db", "database_id": "id:db",
                      "remote": "https://db.org.turso.io"}

        def request(url, method="GET", token=None):
            calls.append((url, method, token))
            return {"database": {"DbId": "id:db", "Hostname": "db.org.turso.io"}} if method == "GET" else {"jwt": "db-read-token"}

        with patch.dict(os.environ, {"MEHSCAN_TURSO_PLATFORM_TOKEN": "fixture-platform-token"}), \
                patch.object(storage, "request_json", request), patch.object(storage, "cloud_store") as writer:
            session = storage.cloud_reader(enrollment)
            self.assertEqual(session["token"], "db-read-token")
            self.assertEqual(session["expires_in_seconds"], 900)
            writer.return_value.check_binding.assert_called_once()
            self.assertEqual(calls[1], ("https://api.turso.tech/v1/organizations/org/databases/db/auth/tokens"
                                       "?expiration=15m&authorization=read-only", "POST", "fixture-platform-token"))
            with self.assertRaisesRegex(storage.ShareError, "identity changed"):
                storage.cloud_reader({**enrollment, "database_id": "replaced"})
            self.assertEqual(len(calls), 3)

    def test_actions_credentials_require_signature_issuer_audience_and_expiration(self):
        try:
            import jwt
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            self.skipTest("install the hosted service requirements to exercise real token signatures")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        at = int(time.time())
        values = {**CLAIMS, "iss": host.ISSUER, "aud": "test-mehscan", "iat": at, "nbf": at - 5, "exp": at + 60}

        def token(claims, signer=key):
            return jwt.encode(claims, signer, algorithm="RS256", headers={"kid": "test-key"})

        with patch.object(jwt.PyJWKClient, "get_signing_key_from_jwt", return_value=SimpleNamespace(key=key.public_key())):
            verify = host.github_verifier("test-mehscan")
            self.assertEqual(verify(token(values))["sha"], COMMIT)
            for invalid in (token(values, other), token({**values, "iss": "https://other.invalid"}),
                            token({**values, "aud": "other"}), token({**values, "aud": ["test-mehscan"]}),
                            token({**values, "iat": at - 60, "nbf": at - 60, "exp": at - 30})):
                with self.assertRaises(storage.ShareError) as issue:
                    verify(invalid)
                self.assertEqual(issue.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
