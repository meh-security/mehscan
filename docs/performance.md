# Scanner, review and test measurements

Measured on Linux x86-64 against PR 48 at `46f7ec5`. Both scanner builds used Rust 1.88, locked dependencies, release optimization and LTO disabled. Times below are local medians. They include process startup.

| Workload | PR 48 | Updated | Output check |
| --- | ---: | ---: | --- |
| One JavaScript file, full scan | 66.8 ms | 23.7 ms | Byte-identical scan JSON |
| 26 files across six languages, full scan | 125.9 ms | 108.8 ms | Byte-identical scan JSON, including the existing parse failure |
| Render JSON and triaged SARIF from one retained attempt | 30.5 ms | 15.7 ms | Both documents equal the standalone renders |

The scan comparison ran `scan PATH --jobs 1 --include-tests --timings --format json` against the same directory with both executables. It used one warm-up and seven alternating measured pairs. The small input exported a single greeting function. The six-language input combined the repository fixtures `java-review-convergence`, `csharp-filesystem-operands`, `frontend-review-packets`, `kotlin-files` and `angular-review-packets`.

Compiling structural rules for the languages actually analyzed reduced median rule compilation on the JavaScript input from 42.4 ms to 2.5 ms. Razor-generated C# is included when its frontend is enabled. The full catalog is still compiled by the engine tests.

The report comparison used the installed Changed-review smoke attempt, one warm-up and nine alternating pairs on the updated executable. The first path runs the original two report commands. The second uses `report --format json-sarif` to validate once. The GitHub Action also runs a help probe so it can recognize older scanners.

## Test build footprint

The 15 Go integration targets built 1,412,550,064 bytes of test executables. The combined target built 108,519,680 bytes with the same Rust test profile and debug info disabled. These totals count the executables in Cargo's build messages. They exclude shared dependencies and build intermediates.

Cargo now discovers 312 engine integration targets, down from 326. Run `cargo test -p mehscan-engine --test go` or add a module or test name as the filter. The grouped target has 28 active cases and one optional corpus case. All 21 historical scan-schema goldens retain their own named test. Python's research tier also owns the frozen pilot-arm comparison and its source-parity check.

## Journal replay

With one JavaScript input and a single journal stream, a native claim followed by an incomplete close produced two journal transactions per generation. Seven warm `state status` calls per measurement gave the following medians.

| Generations | Journal bytes | Status latency |
| ---: | ---: | ---: |
| 1 | 1,603 | 2.25 ms |
| 25 | 42,408 | 2.46 ms |
| 100 | 170,237 | 3.71 ms |
| 250 | 427,037 | 6.53 ms |

This sample covers lightweight claims and closes. A production-sized journal with evidence-heavy decisions and concurrent writers would establish whether replay time or lock contention warrants a storage change. Likewise, a saved run with a large publication history would provide a basis for optimizing the per-publication assessment reads.
