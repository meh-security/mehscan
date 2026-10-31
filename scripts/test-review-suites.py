"""Classify and time deterministic worker tests; all tiers run unless selected."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
# Standalone, unshipped experiment drivers. Everything else stays product
# coverage, including evidence/accounting regressions inside pilot tests.
RESEARCH_MODULES = {
    "test_work_formation_experiment", "test_review_routing", "test_review_hybrid",
    "test_workspace_batch", "test_workspace_planner",
}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def inventory():
    loader = unittest.TestLoader()
    tests = list(flatten(loader.discover(str(ROOT / "tests/review_worker"))))
    counts = Counter(test.id() for test in tests)
    if any(count != 1 for count in counts.values()):
        raise ValueError("duplicate discovered test IDs")
    if loader.errors:
        raise ValueError("test discovery failed; run unittest discovery for the import diagnostic")
    modules = {test.__class__.__module__ for test in tests}
    if RESEARCH_MODULES - modules:
        raise ValueError("research classification references missing modules")
    return tests


def tier(test):
    return "research" if test.__class__.__module__ in RESEARCH_MODULES else "product"


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
    parser.add_argument("--tier", choices=("all", "product", "research"), default="all")
    parser.add_argument("--list", action="store_true", help="collect/classify without executing")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    tests = inventory()
    selected = [test for test in tests if args.tier == "all" or tier(test) == args.tier]
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
