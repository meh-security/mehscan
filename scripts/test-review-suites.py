"""Classify and time deterministic worker tests; all tiers run unless selected."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
RESEARCH_DIR = ROOT / "research"

# Run these product checks on Intel macOS PR runners. Linux and Windows run the
# full product tier. Keep POSIX-specific behavior and the native CLI boundary.
SMOKE_TESTS = {
    "test_context.Context.test_source_root_alias_accepts_contained_files_and_rejects_escape",
    "test_worker.Worker.test_research_rejects_symlink_escape_and_boolean_ranges",
    "test_worker.Worker.test_native_worker_records_its_local_assignment",
    "test_worker.Worker.test_tiered_local_assignment_enforces_its_reserved_provider_calls",
    "test_worker.Worker.test_change_pass_native_finalization_and_state_admission_share_one_bound_workflow",
    "test_worker.Worker.test_native_admission_and_pending_crashes_resume_without_more_model_calls",
    "test_worker.Worker.test_native_runtime_matches_python_package_and_rejects_worker_override",
    "test_work_review.WorkReview.test_native_fast_reconciles_scoped_correction_under_original_allowance",
    "test_worker.Worker.test_source_changed_during_query_is_rejected_before_receipt_or_admission",
    "test_source_review.SourceReview.test_native_admission_rejects_unseen_fabricated_and_altered_plans",
}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def inventory(include_research_dir):
    loader = unittest.TestLoader()
    directories = [ROOT / "tests/review_worker"]
    if include_research_dir:
        directories.append(RESEARCH_DIR)
    tests = []
    for directory in directories:
        tests.extend(flatten(loader.discover(str(directory), top_level_dir=str(directory))))
    counts = Counter(test.id() for test in tests)
    if any(count != 1 for count in counts.values()):
        raise ValueError("duplicate discovered test IDs")
    if loader.errors:
        raise ValueError("test discovery failed; run unittest discovery for the import diagnostic")
    return tests


def tier(test):
    module = test.__class__.__module__
    return "research" if Path(sys.modules[module].__file__).parent == RESEARCH_DIR else "product"


def select(tests, selection):
    if selection == "all":
        return tests
    if selection == "smoke":
        selected = [test for test in tests if tier(test) == "product" and test.id() in SMOKE_TESTS]
        missing = SMOKE_TESTS - {test.id() for test in selected}
        if missing:
            raise ValueError(f"missing product smoke tests: {', '.join(sorted(missing))}")
        return selected
    return [test for test in tests if tier(test) == selection]


class TimedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def startTest(self, test):
        self.started = time.perf_counter()
        self.outcome = "passed"
        super().startTest(test)

    def addError(self, test, err):
        self.outcome = "error"
        super().addError(test, err)

    def addFailure(self, test, err):
        self.outcome = "failed"
        super().addFailure(test, err)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.outcome = "failed"
        super().addSubTest(test, subtest, err)

    def addSkip(self, test, reason):
        self.outcome = "skipped"
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self.outcome = "expected_failure"
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self.outcome = "unexpected_success"
        super().addUnexpectedSuccess(test)

    def stopTest(self, test):
        self.records.append({"id":test.id(), "tier":tier(test), "status":self.outcome,
                             "seconds":round(time.perf_counter() - self.started, 6)})
        super().stopTest(test)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("all", "product", "research", "smoke"), default="all")
    parser.add_argument("--list", action="store_true", help="collect/classify without executing")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    tests = inventory(include_research_dir=args.list or args.tier in {"all", "research"})
    selected = select(tests, args.tier)
    report = {"schema_version":1, "selection":args.tier,
              "inventory":[{"id":test.id(), "tier":tier(test), "selected":test in selected} for test in tests],
              "results":[], "status":"listed" if args.list else "interrupted"}
    result = None
    try:
        if not args.list:
            result = unittest.TextTestRunner(verbosity=2, resultclass=TimedResult).run(unittest.TestSuite(selected))
            report.update(results=result.records, status="passed" if result.wasSuccessful() else "failed")
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if args.list or result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
