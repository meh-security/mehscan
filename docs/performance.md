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

A second release-build measurement admitted 16 cited decisions per generation. The benchmark created eight more streams from each baseline, each using claim, plan, record, and close. Each writer ran a separate CLI process against the same journal. All eight closes succeeded in every run.

| Baseline generations | Journal bytes | Median record, one writer | Median record, four writers | Elapsed for eight streams, one / four writers |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 82,392 | 15.2 ms | 28.6 ms | 0.39 / 0.25 s |
| 16 | 1,319,728 | 30.9 ms | 99.0 ms | 0.91 / 0.83 s |
| 33 | 2,722,142 | 64.4 ms | 192.2 ms | 2.13 / 2.08 s |

At 2.7 MB, four writers gave almost identical total throughput and tripled median record latency. The timings include native validation and process startup. Replaying the journal under an exclusive lock is a candidate for a verified checkpoint keyed to journal sequence and chain digest. Benchmark replay and lock duration separately before changing the storage format. The existing journal has a 512 MiB ceiling.

The Rust engine retains its opt-in literal-secret detector. The CLI disables it, the engine crate is unpublished, and a public GitHub code search found no external Cargo manifests referencing `mehscan-engine`. Private and unindexed path dependencies are outside that search.

## Retained and published assessment reads

Reading a nonempty batch now takes three assessment-content queries regardless of its size. One loads the assessments in review order, one loads their questions, and one loads their evidence. Previously, each assessment added two queries. A 1,024-assessment batch went from 2,049 queries to three. Empty batches still take one query.

| CLI workflow | Assessments in batch | Before (`c4d51e9`) | Batched reads |
| --- | ---: | ---: | ---: |
| `memory assessments` | 0 | 18.03 ms | 18.96 ms |
| `memory assessments` | 1 | 17.56 ms | 18.70 ms |
| `memory assessments` | 128 | 26.80 ms | 23.68 ms |
| `memory assessments` | 1,024 | 98.33 ms | 54.04 ms |
| `memory sync context` on a pulled replica | 1,024 | 130.38 ms | 82.80 ms |

These end-to-end medians include process startup, inventory validation and JSON output. Each release binary ran once to warm up, then five times in alternating order. The local fixtures included 2,048 additional assessments outside the selected batch and varied the number of questions and evidence records per assessment. The replica measurement used the same 1,024-assessment batch after staging, pushing to a local Turso sync server and pulling into a separate reader. Sync transport time is excluded.

The complete JSON output matched byte for byte in every comparison, including the published context and its resolution projection. The larger local batch took 45% less time and the published context took 36% less time. Empty and single-assessment reads were about 1 ms slower in this sample.

### Histories with many small publications

For each nonempty publication, `memory sync context` executes four queries to load assessments, questions, evidence and file dependencies. Turso now reuses the compiled statements on the same connection. Each execution binds the selected batch ID and reads the current rows.

| Selected publications | Assessments per publication | Before (`bc496c0`) | With statement reuse |
| ---: | ---: | ---: | ---: |
| 0 | — | 21.61 ms | 20.18 ms |
| 1 | 1 | 20.95 ms | 20.22 ms |
| 32 | 1 | 28.90 ms | 23.12 ms |
| 256 | 1 | 98.19 ms | 40.56 ms |
| 1,024 | 1 | 310.69 ms | 105.03 ms |
| 1 | 1,024 | 83.80 ms | 80.09 ms |

The small-publication fixtures used disposable copies of the pulled replica described above. Each selected publication had one assessment and one file dependency. Sixty-four additional publications belonged to a different stream. The final row used the original large publication as a control.

Both release binaries ran `memory sync context` offline against the same replica and inventory for each fixture. Times are end-to-end medians from five alternating pairs after one warm-up per binary. Complete JSON matched byte for byte across all six fixtures. For 1,024 small publications, elapsed time fell by 66% while returning the same 3.35 MB of context.
