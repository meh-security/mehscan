"""Credential-lane authorization and pinned client setup; no network or inference."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import test_advisory as fixtures

spec = importlib.util.spec_from_file_location("provider_setup", fixtures.ROOT / "scripts/setup-action-provider.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class CredentialLane(fixtures.FixtureBase):
    def setUp(self):
        super().setUp()
        os.environ.update(MEHSCAN_REVIEW_MODE="value", MEHSCAN_PROVIDER_CONFIG="absent-config-not-opened")

    def test_authoritative_same_repo_allows_setup_without_opening_config(self):
        self.assertTrue(fixtures.adapter.model_lane(self.delivery.get)["allowed"])
        os.environ["GITHUB_REPOSITORY_ID"] = "999"
        with self.assertRaises(ValueError): fixtures.adapter.model_lane(self.delivery.get)

    def test_forks_require_manual_explicit_authorization(self):
        self.delivery.pr["head"]["repo"] = {"id":777,"full_name":"fork/project"}
        self.assertFalse(fixtures.adapter.model_lane(self.delivery.get)["allowed"])
        os.environ["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        os.environ["MEHSCAN_PR"] = "24"
        self.assertFalse(fixtures.adapter.model_lane(self.delivery.get)["allowed"])
        os.environ["MEHSCAN_ALLOW_FORK_REVIEW"] = "true"
        self.assertTrue(fixtures.adapter.model_lane(self.delivery.get)["allowed"])
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        os.environ["MEHSCAN_PR"] = ""
        with self.assertRaisesRegex(ValueError, "workflow_dispatch"):
            fixtures.adapter.model_lane(self.delivery.get)

    def test_drafts_closed_and_metadata_only_edits_do_not_load_credentials(self):
        self.delivery.pr["draft"] = True
        self.assertFalse(fixtures.adapter.model_lane(self.delivery.get)["allowed"])
        self.delivery.pr.update(draft=False,state="closed")
        self.assertFalse(fixtures.adapter.model_lane(self.delivery.get)["allowed"])
        self.delivery.pr["state"] = "open"
        self.event.write_text(json.dumps({"number":24,"action":"edited"}))
        self.assertFalse(fixtures.adapter.model_lane(self.delivery.get)["allowed"])

    def test_release_lane_and_native_mode(self):
        os.environ.update(GITHUB_EVENT_NAME="workflow_dispatch",MEHSCAN_BASE="old",MEHSCAN_TARGET="new")
        self.assertTrue(fixtures.adapter.model_lane(self.delivery.get)["allowed"])
        os.environ.update(MEHSCAN_REVIEW_MODE="native",MEHSCAN_PROVIDER_CONFIG="")
        self.assertFalse(fixtures.adapter.model_lane(self.delivery.get)["allowed"])


class PinnedSetup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "private"
        self.addCleanup(patch.stopall)
        patch.object(setup.platform,"system",return_value="Linux").start()
        patch.object(setup.platform,"machine",return_value="x86_64").start()
        data = io.BytesIO()
        with tarfile.open(fileobj=data,mode="w:gz") as archive:
            entry = tarfile.TarInfo("package/vendor/x86_64-unknown-linux-musl/bin/codex")
            content = b"trusted-client-fixture"
            entry.size = len(content)
            archive.addfile(entry,io.BytesIO(content))
        self.archive = data.getvalue()
        self.metadata = {"dist":{"tarball":"https://registry.npmjs.org/@openai/codex/-/fixture.tgz",
            "integrity":"sha512-"+base64.b64encode(hashlib.sha512(self.archive).digest()).decode()}}
        self.calls = []

    def fetch(self,url):
        self.calls.append(url)
        return self.archive if url.endswith(".tgz") else json.dumps(self.metadata).encode()

    def test_config_auth_and_sessions_are_private_without_inference(self):
        path = setup.setup(self.root,"0.162.0-alpha.17.2","gpt-6-luna",'{"fixture":"private-fixture"}',self.fetch)
        config = json.loads(path.read_text())
        self.assertEqual(config["reasoning_effort"],"medium")
        self.assertEqual(config["model"],"gpt-6-luna")  # Explicit model override survives.
        self.assertEqual(config["schema_mode"],"stable")
        self.assertEqual(config["source_presentation"],"line-addressed-v1")
        self.assertTrue(Path(config["executable"]).is_file())
        self.assertFalse(Path(config["private_directory"]).exists())
        self.assertEqual(json.loads(Path(config["auth_file"]).read_text()),{"fixture":"private-fixture"})
        with self.assertRaises(FileExistsError): setup.setup(self.root,"0.162.0-alpha.17.2","gpt-6-luna",'{"fixture":"key"}',self.fetch)

    def test_missing_auth_bad_version_and_integrity_fail_before_credentials_written(self):
        for version, auth in (("--unsafe",'{"key":"test"}'),("0.162.0",""),("0.162.0","[]")):
            with self.assertRaises(ValueError): setup.setup(self.root,version,"gpt-6-luna",auth,self.fetch)
        self.assertFalse(self.calls)
        self.metadata["dist"]["integrity"] = "sha512-incorrect"
        with self.assertRaises(ValueError): setup.setup(self.root,"0.162.0","gpt-6-luna",'{"key":"test"}',self.fetch)
        self.assertFalse((self.root / "auth.json").exists())

    def test_caller_only_exposes_auth_to_authorized_setup(self):
        import yaml
        value = yaml.safe_load((fixtures.ROOT / "docs/examples/mehscan-byok-advisory.yml").read_text(encoding="utf-8"))
        self.assertEqual(value["permissions"],{"contents":"read","pull-requests":"read"})
        job = value["jobs"]["byok-artifact"]
        secret_steps = [step for step in job["steps"] if "secrets." in json.dumps(step)]
        self.assertEqual(len(secret_steps),1)
        self.assertEqual(secret_steps[0]["if"],"steps.lane.outputs.model-allowed == 'true'")
        action = next(step for step in job["steps"] if step.get("uses")=="./.mehscan-tool")
        self.assertIn("|| 'native'",action["with"]["review-mode"])
        upload = next(step for step in job["steps"] if step.get("uses","").startswith("actions/upload-artifact@"))
        self.assertEqual(upload["with"]["path"],"${{ steps.mehscan.outputs.artifact-directory }}")


if __name__ == "__main__":
    unittest.main()
