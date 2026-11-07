# Rust security review coverage

Mehscan prepares bounded security questions from Rust source without building the
target. A question identifies an operation and the deciding source evidence;
it is not a confirmed vulnerability. Default AI review can discover additional
relationships beyond these native models.

| Area | Selected relationships |
| --- | --- |
| Allocation and size arithmetic | Caller-influenced vector capacity, typed reserve/resize, identifier-count repeat macros, and selected arithmetic reaching allocation or view capacity publication. Growth receivers can follow named fields, explicit free-helper returns and aliases through source-owned modules, including selected cross-file imports and reexports. Capacity reuse review ties an unchecked offset addition to the same backing vector and the metadata update. |
| Archives | Typed tar/zip extraction, selected ZIP entry names reaching writes, and tar entries from loops or `if let Some(entry) = entries.next()` reaching writes or per-entry extraction. Review `unpack` as an explicit destination and `unpack_in` as a library-managed root. |
| Unsafe memory | Selected vector reconstruction/ownership, raw slices and copies, unchecked indexing on witnessed buffers, length publication, typed pointer offsets, MaybeUninit assertions and standard transmute operations in safe functions. |
| Thread safety | Unsafe standard Send/Sync assertions connected to the same local struct's generic or recognized interior-mutability storage, with actual bounds retained. |
| Panic cleanup | Raw element destruction connected to the same owner's scalar metadata and local Drop implementation. Also follows local drop guards in helpers and bounded same-owner callers that update live-element metadata after the helper returns. Metadata-before-drop and nonpanicking elements can be controls. |
| Parser availability | Input-backed byte-slice indexing and selected get(...).unwrap operations. Short-input panic is distinct from memory unsafety or deployed service denial. |
| Decoder history | Selected byte-decoded offsets that are clamped or saturated before copying from the same output buffer. Review the initialized prefix, usable dictionary, zero distance and overlap. |
| HTTP framing | Content-Length and Transfer-Encoding reads from one typed header source together with raw input forwarding to a typed TCP stream. Actual peer disagreement and input association need assessment. |
| Credentials | Authentication-like default headers in recognized reqwest builders, signature-disabled Validation objects consumed by jsonwebtoken decode, and generated tokens passed directly to selected output macros. |

Source checks retain typed declarations, enclosing definitions, guard ordering
and exact selected operations. Cross-file allocation questions preserve the
Cargo target and module declarations used to bind receiver types, including
conventional modules and supported literal `#[path]` file modules. Ambiguous
inclusions, transformed or conditional paths, and routes beyond analysis limits
remain unresolved. Receiver declarations do not establish helper value semantics,
trait dispatch, generic substitution or custom dereferencing. Async return types,
cross-function data flow and arbitrary macros remain bounded. Iterator adapters,
recursive/expansion resource analysis, complete lifetime proofs and general
cryptographic correctness are not established by this coverage. For an explicit
unsafe function, its caller contract requires separate review from safe-boundary
admission. Review limits can defer additional native questions to later pages.

Rust memory reviews use Rust-specific soundness guidance. Parser panic questions
use resource guidance so the review can account for caller guards and panic
configuration. Regenerate existing Rust inventories to pick up the updated
review routes and detection rules.

## Offline RustSec metadata

Match an existing Cargo.lock against a supplied RustSec advisory-db checkout:

```sh
mehscan investigate rust-advisories . --database /path/to/advisory-db --output rust-advisories.json
```

The command reads the lockfile and advisory metadata. It does not fetch a database,
run Cargo, build packages or infer whether affected functions are reached.
Informational records are included by default; `--include-informational false`
excludes informational records while retaining malicious-package records.

The JSON separates vulnerability, unsound, unmaintained, notice and malicious
records. Patched and unaffected version ranges are applied to stable crates.io
registry versions. Withdrawn records are skipped. Git, local and other registry
sources are listed as excluded; prereleases and malformed relevant records make
version matching incomplete instead of becoming clean results.

Kinds follow explicit metadata. An uncategorized record retains its title and
generic vulnerability kind; the command does not invent a malicious category
from a package name or prose alone.

Affected architectures, operating systems, functions and aliases remain report
metadata for applicability review. Input hashes identify the lockfile and
inspected advisory files; they do not certify database freshness. An empty match
list is not a safety verdict. Offline dependency matches remain separate from
source findings and their review/export lifecycle.

## Rust review guidance

The security skill includes an on-demand [Rust pattern index](../skills/mehscan-security/references/rust-security.md),
[memory and lifecycle patterns](../skills/mehscan-security/references/rust-memory.md)
and [input and authority patterns](../skills/mehscan-security/references/rust-boundaries.md).
They connect RustSec mechanisms and Rust/ANSSI contracts to small examples,
deciding evidence and repaired controls. Rust source and Cargo manifest/lockfile
assignments receive a short router even when native scanning produces no candidates; full guides remain
available through the worker's allowlisted guidance API. Guidance does not extend
the native detection guarantees listed above or establish a finding by itself.
Use the [attack scenario guide](../skills/mehscan-security/references/rust-attack-surfaces.md)
to select a scenario from the application's actual entry point and verify the
caller, guard and consequence against source.
