"""Domain plan role, membership and source-binding regressions."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import review_domains
import review_source


class DomainPlan(unittest.TestCase):
    def setUp(self):
        self.plan = {"plan_id": "native-plan", "source_fingerprint": "source", "assignments": [
            {"id": "first", "review_ids": ["failure", "marker", "fact", "unknown"], "windows": [
                {"path": "first.py", "start_line": 1, "end_line": 3,
                 "source_sha256": "first-hash", "text": "read()\ncheck()\nwrite()"}]},
            {"id": "second", "review_ids": ["second-marker"], "windows": [
                {"path": "second.py", "start_line": 1, "end_line": 2,
                 "source_sha256": "second-hash", "text": "check()\nwrite()"}]}]}
        self.ids = ["failure", "marker", "fact", "unknown", "second-marker"]
        self.manifest = {"source_plan_id": "native-plan", "source_fingerprint": "source", "domains": [{
            "id": "records", "title": "Record mutation and shared ownership checks",
            "shared_facts": [{"path": "first.py", "start_line": 2, "end_line": 2}],
            "cases": [self.case("update", "first", "first.py", 3)]}]}
        self.manifest["domains"][0]["cases"][0]["review_roles"] = {
            "verify": ["failure"], "cover": ["marker"], "context": ["fact"]}

    def case(self, case_id, assignment_id, path, end):
        return {"id": case_id, "assignment_id": assignment_id, "owner_path": path,
                "start_line": 1, "end_line": end, "question": "Can this actor update the selected record?",
                "protected_effect": "Record mutation", "area": "record authority",
                "reason": "The implementation reads an actor-selected key before the protected write.",
                "next_deciding_fact": "Whether the ownership check binds that actor and record.",
                "signal": {"kind": "source_relationship", "evidence": [
                    {"path": path, "start_line": 1, "end_line": 2}]}}

    def validate(self, manifest=None):
        return review_domains.validate(manifest or self.manifest, self.plan, self.ids,
                                       validate_selection=review_source.validate_selection)

    def test_roles_preserve_every_native_id_without_inventing_verdicts(self):
        result = self.validate()
        self.assertEqual(set(result["lead_accounting"]), set(self.ids))
        self.assertEqual(result["cases"][0]["verify_review_ids"], ["failure"])
        self.assertEqual(result["lead_accounting"]["failure"]["status"], "queued")
        self.assertEqual(result["lead_accounting"]["marker"]["status"], "planned")
        self.assertEqual(result["lead_accounting"]["fact"]["status"], "available")
        for rid in ("unknown", "second-marker"):
            self.assertEqual(result["lead_accounting"][rid]["role"], "unclassified")
            self.assertEqual(result["lead_accounting"][rid]["status"], "deferred")
        self.assertTrue(all(not row["reviewed"] and "decision" not in row
                            for row in result["lead_accounting"].values()))
        self.assertEqual(result["domains"][0]["shared_facts"], [{"path": "first.py", "start_line": 2,
            "end_line": 2, "source_sha256": "first-hash", "quote": "check()"}])

    def test_ordered_cases_share_a_domain_without_sharing_membership(self):
        case = self.case("other-update", "second", "second.py", 2)
        case["review_roles"] = {"cover": ["second-marker"]}
        self.manifest["domains"][0]["cases"].append(case)
        result = self.validate()
        self.assertEqual([case["id"] for case in result["domains"][0]["cases"]], ["update", "other-update"])
        self.assertEqual(result["cases"][1]["verify_review_ids"], [])
        self.assertEqual(result["lead_accounting"]["second-marker"]["case_id"], "other-update")

    def test_ai_only_case_has_no_native_obligation(self):
        self.manifest["domains"][0]["cases"][0].pop("review_roles")
        result = self.validate()
        self.assertEqual(result["cases"][0]["review_roles"], {"verify": [], "cover": [], "context": []})
        self.assertTrue(all(row["status"] == "deferred" for row in result["lead_accounting"].values()))

    def test_invalid_bindings_and_source_citations_reject_before_execution(self):
        changes = [lambda value: value.update(source_fingerprint="stale"),
                   lambda value: value.update(source_plan_id="stale"),
                   lambda value: value["domains"][0]["cases"][0].update(start_line=0),
                   lambda value: value["domains"][0]["cases"][0].update(end_line=4),
                   lambda value: value["domains"][0]["shared_facts"][0].update(path="missing.py"),
                   lambda value: value["domains"][0]["shared_facts"][0].update(end_line=4),
                   lambda value: value["domains"][0]["shared_facts"][0].update(quote="invented")]
        for change in changes:
            value = copy.deepcopy(self.manifest)
            change(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(value)

    def test_role_membership_cannot_cross_callers_or_claim_safe(self):
        for roles in ({"verify": ["second-marker"]}, {"cover": ["missing"]},
                      {"verify": ["failure"], "context": ["failure"]},
                      {"safe": ["marker"]}, {"verify": ["failure", "failure"]}):
            value = copy.deepcopy(self.manifest)
            value["domains"][0]["cases"][0]["review_roles"] = roles
            with self.subTest(roles=roles), self.assertRaises(ValueError):
                self.validate(value)

    def test_duplicate_cases_assignments_and_domains_are_rejected(self):
        for kind in ("case", "assignment", "domain"):
            value = copy.deepcopy(self.manifest)
            if kind == "domain":
                value["domains"].append(copy.deepcopy(value["domains"][0]))
            else:
                other = copy.deepcopy(value["domains"][0]["cases"][0])
                if kind == "assignment":
                    other["id"] = "another"
                value["domains"][0]["cases"].append(other)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(value)

    def test_context_fact_requires_a_source_operation_not_a_standalone_fact_job(self):
        value = copy.deepcopy(self.manifest)
        value["domains"][0]["cases"][0]["review_roles"] = {"context": ["fact"]}
        value["domains"][0]["cases"][0]["question"] = ""
        with self.assertRaises(ValueError):
            self.validate(value)


if __name__ == "__main__":
    unittest.main()
