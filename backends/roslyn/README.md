# Optional Roslyn evidence

Experimental source/reference-only C# backend. It adds compact compiler symbol,
local producer/stop and source helper declaration facts to selected SQL operands.
It preserves review IDs, admission and Value selection. Facts guide research;
they do not prove input control, safe binding, escaping or runtime dispatch.

## Build

Build this helper with the .NET 10 SDK. The helper uses pinned Roslyn 5.0.0;
the scanned application's target framework is independent of the helper runtime.

```sh
dotnet build backends/roslyn/Mehscan.Roslyn.csproj
```

The apphost is `backends/roslyn/bin/Debug/net10.0/Mehscan.Roslyn` (`.exe` on
Windows). It needs the .NET 10 runtime. Neither scanning nor ordinary Mehscan
investigation requires this backend.

## Supply context

Create a JSON file outside the scanned source tree, for example:

```json
{
  "projects": [{
    "id": "app-net8",
    "target_framework": "net8.0",
    "language_version": "12.0",
    "sources": ["App.cs", "Helpers.cs"],
    "references": [],
    "reference_directories": ["/absolute/path/to/Microsoft.NETCore.App.Ref/8.0.x/ref/net8.0"],
    "defines": [],
    "allow_unsafe": false,
    "nullable": true
  }]
}
```

`output_kind` can be `library` (default), `console` or `windows`. Choose the
application's actual output kind; top-level programs need `console` or `windows`.

Use actual target reference assemblies and dependency metadata; host runtime
assemblies are not a substitute. Supply absolute reference paths/directories,
and root-relative UTF-8 C# source paths. All listed array fields are required.
Reference directories contribute their immediate `.dll` files. ASP.NET Core,
System.Web, Dapper/EF and proprietary APIs need their corresponding references.
The target label describes the supplied context; the backend does not discover
or certify its references from the label. Keep multi-target contexts separate.

## Use existing package metadata

When a project already has `obj/project.assets.json`, add these fields to each
project in a context seed:

```json
"assets_file": "/absolute/path/to/obj/project.assets.json",
"assets_target": "net8.0",
"package_roots": ["/absolute/path/to/local/nuget/packages"]
```

Run `mehscan investigate csharp-context ROOT --context SEED --output CONTEXT`.
It resolves only the selected target's exact `compile` DLL paths. Package roots
are optional and default to the assets file's cache locations; explicit roots
allow a relocated cache with the same package/version/asset paths. It never
substitutes runtime assets, newer packages, project output placeholders or
executes package build/analyzer/generator assets. Missing entries are recorded
in the prepared context and summary; they do not stop unrelated valid bindings.

Target keys must use modern short names matching `target_framework` (`net8.0`,
`net10.0`, optionally with an explicit RID). Older long NuGet target keys and
`packages.config` remain explicit-reference workflows. Framework reference
directories, sources and compiler options remain supplied by the caller. Include
existing generated global-using files in `sources` when needed; no files are
generated automatically. Project references need explicit source or metadata.

Optional top-level `context_files` lists absolute project/props/lock filenames
whose changes should invalidate this context. The prepared context binds their
hashes, the original seed and assets file; imports reject subsequent changes.
This does not certify that an old assets file matches today's project options.
Use a known applicable restore graph and prepare again after changing inputs.
Use the original seed for regeneration and a separate output path.

A restore graph can contain duplicate framework/package assembly names. The
backend withholds that project's facts and reports the conflicting names; supply
an explicit resolved reference set. It does not guess SDK conflict resolution.

## Collect and reuse

```sh
mehscan investigate csharp-semantic ROOT --context context.json --backend BACKEND_EXE --output semantic.json
mehscan investigate review-inventory ROOT --output inventory --csharp-semantic semantic.json --csharp-context context.json
mehscan investigate review-bundles ROOT --inventory inventory --review-ids IDS --output review
```

`scan ROOT --format json --csharp-semantic semantic.json --csharp-context
context.json` also imports the facts. The inventory saves them in its normal
scan cache; selected bundles use that cache without launching Roslyn again.
Snapshot imports require full scan context; changed-line filtering can use
`--diff-mode full`, but the reduced `impact` context is not supported yet.

Collection launches the explicitly supplied helper once; it does not build the
target, restore dependencies, evaluate MSBuild, run generators or load analyzers.
Source files are limited to 2 MiB each; helper output to 8 MiB and execution to
60 seconds. Snapshot import verifies SHA-256 of the context, all supplied source
files and reference metadata. Local snapshots contain reference paths and are
not portable between machines; final facts use repository-relative locations.
Regenerate after a source/reference/option change. Saved inventories retain the
native input binding and revalidate it before materializing a selected chunk.
Native chunk identities also bind these inputs. Keep `input-binding.json` with
the manifest and requests when copying a run. Review ledgers bind the current
inventory, every chunk's source/semantic inputs, request contents and review
contract, and check decisive source against the checkout. Rebuild old inventories
and ledger files. Inventory and ledger schema 2 reject previous files, including
native inventories that did not retain reference/context bindings.

Missing dependencies leave precise unresolved bindings. Unrelated compiler errors
do not discard valid identities, but facts carry `partial_semantic_context`.
When multiple project/target contexts cover one operation, import withholds its
facts and emits a diagnostic. A declaration location does not establish runtime
implementation or trust. For an immutable string local in a selected method,
Roslyn CFG facts can locate up to eight possible source producers across resets,
branches and appends. Joins retain alternatives; completed resets drop earlier
parts; appends and self-dependent writes retain their inputs. These are possible
producers, not feasible paths, concatenation order, global taint or a safe verdict.
The bound is 64 blocks and a 32,768-character method. Captures, ref/out handoffs,
deconstruction, unsupported writes, try/catch/finally and exceeded bounds stop
this analysis and retain source navigation. Reads of an uncaptured immutable
string do not imply replacement. A source-bound static helper with one return
expression supplies that exact expression and call identity; argument mapping,
side effects and interpretation still require review. Review cards prefer the
captured operand over receiver navigation; captured terms need not exhaust the
complete SQL operand.
For SQL construction, `query_value` facts give compiler types at up to sixteen
exact inserted-value locations. A fallback local capture navigates observed
writes from a top-level reset. This is source navigation, not a complete reaching
query: conditional writes, earlier execution, format/culture and all remaining
terms still require inspection. Scalar types do not automatically establish
safe SQL. Error types are withheld; an exceeded window stays explicit.
Razor, generated source, implicit project imports/options and full DI/reflection
resolution remain outside the explicit context unless already supplied as source.

For compiler-bound `DbCommand` receivers, the helper locates one initialized
local and its exact source uses in the same callable. `receiver_reference`
includes member assignments and calls; an alias, replacement, capture or handoff
ends navigation at an explicit boundary. There are at most eight reference
windows of 256 characters, a 2,048-character initializer and a 32,768-character
callable. Parameters and fields gain exact compiler declaration locations,
while their runtime lifecycle remains open. `IDbCommand` is supported as an
interface identity, without assuming its runtime implementation. Constructor
or factory identities retain their actual metadata identity and target.

These are source navigation facts: branches, API contracts, reaching state and
effective execution still require review. Absence of a connection assignment
is not a safety verdict. A connection passed to a constructor, a later write,
a different local connection and a handoff must be distinguished using source
and the applicable API contract. Native facts do not change admission or Value
selection. The independent source scanner recognizes bounded direct command/
connection aliases; inferred factories still require a later execution site.

## Native integration checks

Build the helper, then set `MEHSCAN_ROSLYN_BACKEND` to its executable,
`MEHSCAN_ROSLYN_NET8_REFS` to the .NET 8 reference directory, and
`MEHSCAN_ROSLYN_NET48_REFS` to the Framework 4.8 reference directory. Also set
`MEHSCAN_ROSLYN_NET10_REFS` and `MEHSCAN_ROSLYN_STANDARD20_REFS` to the .NET 10 and
Standard 2.0 reference directories. Ensure the
helper's .NET runtime is discoverable (`DOTNET_ROOT` for a private SDK).
The receiver test additionally needs `MEHSCAN_ROSLYN_SQLCLIENT_REF` pointing to
the real Microsoft.Data.SqlClient 5.2.1 `ref/net8.0` assembly.

```sh
cargo test -p mehscan-engine --test csharp_semantic_backend -- --ignored
cargo test -p mehscan-cli --test csharp_semantic_cli -- --ignored
```

These opt-in checks use real metadata, including stale inputs, partial binding,
source lookalikes, Unicode positions, conflicting contexts, branch/loop/reset
contrasts, mixed operands, helper returns and saved chunk/ledger bindings.
The validated target baselines are .NET 8/C# 12, Framework 4.8/C# 7.3,
.NET 10/C# 14 and Standard 2.0/C# 7.3. The helper itself uses .NET 10;
the target framework does not have to run. Other explicit versions may work
when matching references and language options are supplied; they are not
certified by this baseline. Existing deterministic C# rules work without .NET.
Optional semantic queries currently enrich admitted SQL operands only.
The asset-selection checks run without .NET:

```sh
cargo test -p mehscan-engine --test csharp_context
```

NuGet background: [dependency graphs](https://learn.microsoft.com/en-us/nuget/concepts/dependency-resolution)
and [compile/runtime asset selection](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files).
