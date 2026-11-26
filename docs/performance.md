# Scanner, review and test measurements

Measured on Linux x86-64 against PR 48 at `46f7ec5`. Both scanner builds used Rust 1.88, locked dependencies, release optimization and LTO disabled. Times below are local medians. They include process startup.

| Workload | PR 48 | Updated | Output check |
| --- | ---: | ---: | --- |
| One JavaScript file, full scan | 83.3 ms | 35.3 ms | Byte-identical scan JSON |
| 26 files across six languages, full scan | 144.9 ms | 127.8 ms | Byte-identical scan JSON, including the existing parse failure |
| Prepare a native inventory for the JavaScript file | 94.2 ms | 27.8 ms | Byte-identical overview, inventory and scan cache |
| Render JSON and triaged SARIF from one retained attempt | 33.6 ms | 15.8 ms | Both documents equal the standalone renders |

The scan comparison ran `scan PATH --jobs 1 --include-tests --timings --format json` against the same directory with both executables. It used one warm-up and seven alternating measured pairs. The small input exported a single greeting function. The six-language input combined the repository fixtures `java-review-convergence`, `csharp-filesystem-operands`, `frontend-review-packets`, `kotlin-files` and `angular-review-packets`.

The inventory comparison used `investigate review-inventory` against the same JavaScript file with a fixed repository key, the same output path and seven measured pairs. Preparation also reuses the computed inventory fingerprint when writing the overview and inventory.

Compiling structural rules for the languages actually analyzed reduced median rule compilation on the JavaScript input from 55.8 ms to 3.8 ms. Razor-generated C# is included when its frontend is enabled. The full catalog is still compiled by the engine tests. Seventeen native-owned rules declare their capture roles directly in the catalog. Existing declarative YAML uses `match.any` as before. Rust callers constructing `MatchSpec` literals for structural rules supply an empty `native_captures` vector.

The report comparison used the installed Changed-review smoke attempt, one warm-up and nine alternating pairs on the updated executable. The first path runs the original two report commands. The second uses `report --format json-sarif` to validate once. The GitHub Action also runs a help probe so it can recognize older scanners.

Repeated calls to `scan_path_profiled` in one process share validated embedded rules and relations. On the same JavaScript fixture, median warm catalog loading fell from 14.7 ms to below the profiler’s one-microsecond resolution. Total warm scan time fell from 18.1 ms to 3.3 ms. Each version ran in three fresh processes with the first scan excluded and 11 subsequent scans measured per process. Source contents, ignore rules, file discovery and per-scan language selection are evaluated on each call.

## Test build footprint

The 15 Go integration targets built 1,412,550,064 bytes of test executables. The combined target built 108,519,680 bytes with the same Rust test profile and debug info disabled. These totals count the executables in Cargo's build messages. They exclude shared dependencies and build intermediates.

After the Go pilot, the same grouping was applied to Java, Kotlin, C#, Node, Python, PHP and Rust. Cargo now discovers **139 engine integration targets**, down from 326. The 195 original modules are compiled in eight suites, with 389 active cases and 11 optional cases. Their test bodies match PR 48. The documented standalone Roslyn targets retain their names.

Use `cargo test -p mehscan-engine --test LANGUAGE` with one of `go`, `java`, `kotlin`, `csharp`, `node`, `python`, `php` or `rust`. Add the old target name as a module filter to select a specific group. For example, `cargo test -p mehscan-engine --test go v2_go_g4::` runs the former Go G4 target.

All 21 historical scan-schema goldens retain their own named test. Python's research tier also owns the frozen pilot-arm comparison and its source-parity check.

## Journal replay

With one JavaScript input and a single journal stream, a native claim followed by an incomplete close produced two journal transactions per generation. Seven warm `state status` calls per measurement gave the following medians.

| Generations | Journal bytes | Status latency |
| ---: | ---: | ---: |
| 1 | 1,603 | 2.25 ms |
| 25 | 42,408 | 2.46 ms |
| 100 | 170,237 | 3.71 ms |
| 250 | 427,037 | 6.53 ms |

This sample covers lightweight claims and closes. A production-sized journal with evidence-heavy decisions and concurrent writers would establish whether replay time or lock contention warrants a storage change. Likewise, a saved run with a large publication history would provide a basis for optimizing the per-publication assessment reads.
