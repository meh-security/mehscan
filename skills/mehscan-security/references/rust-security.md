# Rust security review

<!-- runtime:routing -->
For Rust source, use `guidance(name="rust-security")` for the pattern index when
needed. Load `rust-memory` for unsafe invariants, lifetimes, panic cleanup,
thread sharing or pinning; load `rust-boundaries` for parser/resource limits,
archives, protocol transitions and credentials. Load only the relevant guide.
Use `rust-attack-surfaces` when selecting scenarios for an application or when
a candidate's impact depends on its caller. Start from the actual entry point,
actor or safe caller, then trace the deciding guard and effect. Apply this
also to source assignments with zero native questions.

Establish the concrete type/API, safe caller boundary and effective configuration.
Inspect imports, aliases, impl bounds and helpers rather than assigning standard
library semantics to a method name. Follow relevant Cargo features, `cfg`, target
width, panic and overflow settings; unknown applicability stays explicit.
For unsoundness, show that a safe caller satisfying the public API can violate an
unsafe invariant. An explicit unsafe function needs its caller obligations checked.
Bounds-checked panics, resource exhaustion and memory UB are different effects.
Advisory metadata and secure-coding recommendations guide investigation; neither
establishes a defect in the assigned source. Informational unsoundness deserves
review; unmaintained status alone does not prove an exploitable vulnerability.

These references do not authorize execution. Source-bound workers keep their
existing broker-only contract. Suggested witnesses are verification plans unless
an authorized operator actually runs them; report that distinction.
<!-- /runtime:routing -->

## Pattern index

Use the violated invariant from an advisory, not its package name as a detection
signature. The examples below are historical mechanisms, not current affected
version advice. Check the current advisory and actual lockfile for version claims.
Use [Rust attack scenarios](rust-attack-surfaces.md) to connect a mechanism to
the actual application boundary and choose a verification control.

| Relationship | Deciding evidence | Guide / advisory example |
| --- | --- | --- |
| Extent arithmetic -> allocation or unsafe access | Same value, conversion, overflow policy, physical extent and consuming operation | `rust-memory`; [bytes overflow](https://rustsec.org/advisories/RUSTSEC-2026-0007.html) |
| Initialized prefix -> published bytes | Successful writes, decoder back-references, `set_len`/raw-slice exposure and reused storage | `rust-memory`; [lz4_flex disclosure](https://rustsec.org/advisories/RUSTSEC-2026-0041.html) |
| Panic -> cleanup or reuse | Callback/Drop can unwind while ownership metadata is inconsistent | `rust-memory`; [circular-buffer cleanup](https://rustsec.org/advisories/RUSTSEC-2026-0256.html) |
| Captured state -> concurrent invocation | Actual sharing behavior and generic Send/Sync requirements | `rust-memory`; [PyO3 closure bounds](https://rustsec.org/advisories/RUSTSEC-2026-0177.html) |
| Input -> disproportionate work | Limit before allocation, cumulative budget, progress and recursion/expansion bound | `rust-boundaries`; [codeq length prefix](https://rustsec.org/advisories/RUSTSEC-2026-0432.html), [calamine chain/parser](https://rustsec.org/advisories/RUSTSEC-2026-0436.html) |
| Optional parser behavior -> repeated scanning | Enabled option, repeated range, input growth and actual work | `rust-boundaries`; [pulldown-cmark wikilinks](https://rustsec.org/advisories/RUSTSEC-2026-0433.html) |
| Archive entry -> filesystem mutation | Entry provenance, path resolution, link policy and the actual write | `rust-boundaries`; [ant-releases extraction](https://rustsec.org/advisories/RUSTSEC-2026-0434.html) |
| Protocol state -> forwarding authority | Peer interpretations, mode transition and bytes accepted before agreement | `rust-boundaries`; [Pingora premature upgrade](https://rustsec.org/advisories/RUSTSEC-2026-0033.html) |
| FFI/pinning/cancellation -> lifetime | Allocation owner, retaining consumer, movement/drop and callback completion | `rust-memory`; [ANSSI FFI guidance](https://anssi-fr.github.io/rust-guide/unsafe/ffi.html), [Pin contract](https://doc.rust-lang.org/std/pin/index.html) |

## Applicability and reporting

Inspect Cargo.toml and Cargo.lock when relevant: package aliases, optional
dependencies, workspace feature unification and target-specific dependencies can
change which implementation is used. A Cargo feature and a runtime parser option
are separate conditions. Macro definitions and generated code need source mapping;
missing expansion or unresolved trait dispatch is a gap, not a safe result.

Keep dependency matches separate from source findings. A lockfile match records
version/metadata applicability, not affected-function reachability. Preserve
withdrawal, architecture/OS/function qualifiers and informational kinds. A library
may have a soundness defect without a demonstrated remote exploit; name the safe
caller and invariant instead of inventing deployment impact.

Use [Rust Reference UB rules](https://doc.rust-lang.org/reference/behavior-considered-undefined.html)
for language obligations and the linked API's Safety section for exact preconditions.
[ANSSI Secure Rust Guidelines](https://anssi-fr.github.io/rust-guide/) provide
practical review prompts, not automatic finding criteria; their current scope
does not cover async Rust. Prefer direct std/async-library contracts there.
