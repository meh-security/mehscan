# Export navigation through the review broker — 2026-10-30, CY

The [CX native navigation primitive](review-export-navigation-2026-10-30.md)
is now available through the normal typed review API. This completes the broker
integration milestone, not the remaining review-quality or live-provider gates.
No live model was called and no provider spend was added.

## Implementation

The shared tool catalog exposes `import-targets(path)` and
`export-target(path, name)` at one query unit each. Their strict wire schemas and
generated API reference use that catalog. Both require `purpose` describing the
deciding question. Export names must be simple ASCII identifiers or `default`;
directories, escaping paths, foreign claim IDs and unsupported arguments fail
before execution. The broker only adds a discovery limit to tools that declare
one, so these commands receive their actual native argument shapes.

This reuses the existing broker rather than adding another fact store. Cache keys
bind the scanner, source snapshot, inventory fingerprint and effective arguments.
Identical reads can share a result across claims, while each request retains its
own ID and question and points back to the original producer. Query and byte
budgets still charge every recipient. A post-query freshness check also applies
to cache hits before facts reach a reviewer or a recoverable fact file.

Navigation results are available as navigation artifacts, not source-body proof
handles. A separate `definition`/`source` read supplies the implementation body.
The new API retains CX's ambiguity, traversal and package/build limits. Exact
missing-file and unsupported import-language errors become explicit non-source
results, allowing independent successful lookups to proceed. Unrelated execution
errors remain errors; no failure becomes evidence of safety or absent controls.

Only the tool catalog, schema compilation, command reference and broker validation
changed. Main review prose and category guidance did not grow. Existing bound
conversations cannot silently acquire the new API: the changed skill bundle needs
a freshly bound work package. Stable-schema behavior within a conversation remains
covered by the adapter regression suite. The automatic source-profile builder is
unchanged and does not recursively preload export chains.

## Validation

59 tests pass, with one existing POSIX-only adapter test skipped on Windows:
four new broker tests, ten existing lookup/controller regressions and the
46-case adapter suite (45 pass, one skip). The generated reference check and skill
validator also pass. Real worker tests cover cross-claim reuse, separate questions,
body retrieval after navigation, missing/unsupported lookups in a successful batch,
query accounting and journaling. Changing a transitive helper during the query
rejects the batch before research receipts or reusable facts reach the reviewer.

The frozen application replay selects these existing Docmost claims:

| Claim suffix | Navigation exercised |
| --- | --- |
| `c643d062f6f03cdf` | Exact export-service import, `getPageTitle` target, then its body |
| `fea800db655648db` | Card caller's sanitizer claim |
| `ce7edba3da8cbbbf` | Link caller's sanitizer claim |

**Attribution correction during release closure:** the original CY fixture swapped
these two caller labels and initial import-query paths. Its transport/cache counts
remain recorded, but it is not evidence of correct caller-specific investigation.
The corrected replay derives/asserts the mapping from the native inventory; see
the [study closure and release fixes](review-release-closure-2026-10-30.md). Original
CY artifacts remain unchanged.

The explicit editor source paths are saved source-audit leads, not inferred
fallbacks for failed package resolution. The barrel remains bounded/incomplete;
both package imports remain unresolved. The sanitizer leaf can still be inspected
without promoting that local observation into a complete caller/build conclusion.

The normal worker completes `--validate-only --phase native` with status
`source_validated`: **11 lookup requests, 14 reserved query units, eight unique
facts, three research-cache hits and ten native CLI executions**. There are four
deterministic reviewer invocations and **zero provider calls**. The worker takes
**5.507 seconds**; this excludes preparation and later audit. All **4,796 pinned
source hashes** verify, and native history confirms no admitted decisions.

These cache hits are local research reuse, not provider prompt-cache hits. The
synthetic final records explicitly retain uncertainty and make no fresh semantic
assessment. This proves transport, attribution, freshness and completion wiring;
it does not establish model precision, better review decisions or API savings.

Artifacts are under `C:/dmitry/scan-runs/export-broker-20261030-cy`: frozen runtime,
skill binding, exact requests/results, native journals, source facts, worker
receipt, empty decision history and `summary.json`. The initial harness completed
the worker but failed its final history check because it read a repository key
from the wrong metadata object. The original error is retained; the post-check
was corrected against the saved work package without rerunning the worker.

## Next milestone and stop

Freeze further navigation/preparation expansion. Use the saved 13-case scope
corpus to evaluate whether final review packages preserve a supported local fact
while retaining a distinct unresolved downstream effect. Start with exact source
and conclusion scope; do not add universal caller discovery, a new global priority
rule or a mandatory second reviewer merely because this API exists.

The scope-aware finalization change is still undecided/unimplemented. The recurring
provider-403 diagnostic gate and unknown historical charges also remain open.
Keep native first for complete local constructions and selective workspace for
shared relationships. No paid expansion is queued until the specific remaining
gates and a named quality/price test are ready.
