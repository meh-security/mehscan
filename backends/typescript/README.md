# Optional TypeScript / JavaScript evidence

Experimental source-only TypeScript Compiler API backend for selected SQL,
filesystem, process and HTML operands in TS, TSX and supported JS files. It
resolves import aliases, symbols/types and source declarations, and locates small
source helper returns with call arguments. Types supply navigation. An explicit
Node reference also permits a narrow traversal closure for complete literal/const
path operands and literal-only standard Node path calls. It does not close other
filesystem effects or assign a whole-operation safety verdict. `any`, missing implementations,
mutated contents and project errors retain explicit checks.

Requests and browser navigation also receive destination/producer navigation.
Declare `runtime: "browser"` on a project only with source/build evidence of its
browser execution. DOM-bound ordinary fetch GET/HEAD operations without other
options leave both review queues when they are standalone occurrences without
represented input relationships. Raw context remains available to admitted work.
This is not destination trust or an operation-safety verdict. Credentials,
headers/body, mutation methods, unknown options, replaced/custom fetch and
Node/SSR scope remain active. Browser declarations alone do not establish runtime.

The adapter pins TypeScript 5.9.3. Install its own dependency with
`pnpm install --ignore-scripts` in this directory; Node must be on PATH. It never
installs scanned-project dependencies, emits application code, runs plugins,
executes target modules or invokes a target build. Existing dependencies and
compiler libraries provide metadata. The adapter itself is trusted local tooling.

Supply a context outside the scanned tree:

```json
{
  "typescript_path": "/absolute/path/to/typescript/lib/typescript.js",
  "node_types": "/absolute/path/to/@types/node",
  "projects": [{
    "id": "web",
    "tsconfig": "tsconfig.json",
    "sources": ["src/app.ts", "src/helpers.ts", "src/component.tsx"],
    "compiler_options": {
      "target": "ES2022", "module": "commonjs", "jsx": "react-jsx",
      "allowJs": true, "strict": true
    }
  }],
  "context_files": ["/absolute/path/to/tsconfig.json", "/absolute/path/to/package-lock.json"]
}
```

`tsconfig` is optional: TypeScript reads JSONC and inherited configuration with
config-relative aliases/options, and binds every configuration read. `sources`
remains the explicit scope; include/exclude globs do not broaden it. Optional
`compiler_options` uses tsconfig JSON names and explicitly overrides loaded options.
No project-reference build or bundler-plugin evaluation; referenced projects
currently require explicit options and separate source contexts. Separate conflicting project
contexts; overlapping operations have their facts withheld. `.d.ts` declarations
can guide research but do not establish a runtime implementation. Type annotations
do not validate external input. Only inspectable source function returns receive
return navigation; no general effect summary or arbitrary call-chain traversal.

`node_types` is optional and explicit. Use a compatible existing `@types/node`
package, or the adapter's pinned 26.0.1 metadata when appropriate for the target.
The adapter loads declarations, not the application. It does not silently add
framework types to every scan. Supplied Node package/declaration reads are bound.
Fixed-path closure requires actual Node imports and source-proven values; matching
type annotations, unknown arguments, replaced APIs and escaped module objects do
not qualify. Independent fixed-path proofs can survive unrelated compiler errors;
ordinary unresolved semantic facts retain partial-context checks.

```sh
mehscan investigate review-inventory ROOT --output inventory --typescript-context context.json --typescript-backend /absolute/path/to/backend.mjs
mehscan investigate review-bundles ROOT --inventory inventory --review-ids IDS --output review
```

Collection scans once and launches the helper once. Cached inventory facts serve
selected review chunks without a compiler process. C# and TS inputs can coexist.
Source, compiler/dependency reads, optional context files and module-resolution
existence/directory probes are bound; changes require regeneration. Probes also
invalidate when a previously absent module appears. Keep the scan cache and its
input binding with saved inventories/chunks. Contexts/snapshots contain local
absolute input paths and are not portable between machines.

For a separately saved snapshot, use `investigate typescript-semantic ROOT
--context FILE --backend SCRIPT --output FILE`, then import it with
`--typescript-semantic FILE --typescript-context FILE` on `scan` or
`investigate review-inventory`. Without an inventory, separate commands each scan the root. Snapshot
import requires full scan context; reduced `--diff-mode impact` is unsupported.

Directed follow-ups can reuse a bound inventory without a Rust rescan:

```sh
mehscan investigate typescript-semantic ROOT --inventory inventory --evidence-ids ID,ID --context context.json --backend SCRIPT --output selected-semantic.json
```

Use scanner evidence IDs from the review card's `anchor.id`. Unknown, empty or
unsupported selections fail. The compiler retains supplied project sources,
imports and caller scope; only requested operands change. Keep this snapshot
as scoped follow-up evidence, not a replacement for the full enriched inventory.
Selected collection returns compact `selected_observations` on stdout; input
binding metadata stays in the saved snapshot.
Absent observations do not establish safety or unreachability.

The helper is bounded to 60 seconds, 8 MiB output, 2 MiB per compiler source read
and 8 KiB source helper declarations. Narrow large projects to relevant contexts.
Compiler errors are counted with compact diagnostics. Raw evidence/security paths
remain intact. Only complete fixed-path CWE-22 questions can leave the admitted
queue; exact closure facts remain in the admission audit. No broad cost-savings
claim or general type-derived sanitizer catalog.

Complete static paths can also propagate through compiler-bound direct source
functions with a single expression return and exact positional arguments. Nested
helpers are bounded; branches, assignments, recursion, async/default/rest
parameters and replaced bindings do not qualify. This closes only path selection.

Projects without queried operands skip semantic analysis after the Program has
followed imports. Their sources/config/resolution inputs remain bound. Snapshot
projects mark `semantic_analysis: "not_requested"`; a zero error count there is
not a clean-compilation claim. Queries in imported sources still receive analysis.
This avoids unneeded semantic work; it does not automatically narrow root sources.

Build/vendor/generated scoping is compiler-independent. Use `investigate provenance`
for compact candidates and the security skill to confirm lanes and exact IDs.

For a queried operand that is a function parameter, `local_call_argument` facts
marked `observed_signature_argument` locate arguments at compiler-resolved local
calls, including import aliases and instance methods. The caller index is built
once per queried project and returns at most eight calls per implementation.
Source argument text is limited to 1,024 characters. Missing arguments,
default/rest/spread mappings, oversized arguments and overload signatures without
an implementation binding remain incomplete. The index stops at 200,000 syntax
nodes or 20,000 calls and reports truncation on the parameter boundary.

These edges cover only supplied project sources/imports, not all runtime callers.
Reassignments, virtual dispatch, callbacks, reflection and external callers still
need research. Empty caller lists never establish unreachability. Facts retain
exact source locations and existing cache bindings; no review ID is closed or
conditionally deferred solely because of incoming-argument navigation.
