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

Use actual target reference assemblies and dependency metadata; host runtime
assemblies are not a substitute. Supply absolute reference paths/directories,
and root-relative UTF-8 C# source paths. All listed array fields are required.
Reference directories contribute their immediate `.dll` files. ASP.NET Core,
System.Web, Dapper/EF and proprietary APIs need their corresponding references.
The target label describes the supplied context; the backend does not discover
or certify its references from the label. Keep multi-target contexts separate.

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
Regenerate after a source/reference/option change. Discard old inventories after
changing their semantic context; historical verdict reuse remains a separate gate.

Missing dependencies leave precise unresolved bindings. Unrelated compiler errors
do not discard valid identities, but facts carry `partial_semantic_context`.
When multiple project/target contexts cover one operation, import withholds its
facts and emits a diagnostic. A declaration location does not establish runtime
implementation, helper return behavior or trust. Intervening local references
stop initializer reuse; this increment supplies no CFG/reaching-write proof.
Razor, generated source, implicit project imports/options and full DI/reflection
resolution remain outside the explicit context unless already supplied as source.

## Native integration checks

Build the helper, then set `MEHSCAN_ROSLYN_BACKEND` to its executable,
`MEHSCAN_ROSLYN_NET8_REFS` to the .NET 8 reference directory, and
`MEHSCAN_ROSLYN_NET48_REFS` to the Framework 4.8 reference directory. Ensure the
helper's .NET runtime is discoverable (`DOTNET_ROOT` for a private SDK).

```sh
cargo test -p mehscan-engine --test csharp_semantic_backend -- --ignored
cargo test -p mehscan-cli --test csharp_semantic_cli -- --ignored
```

These opt-in checks use real metadata, including stale inputs, partial binding,
source lookalikes, Unicode positions, conflicting contexts and saved bundles.
