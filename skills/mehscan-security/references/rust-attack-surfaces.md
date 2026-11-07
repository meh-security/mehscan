# Rust attack scenarios

Use this guide when reviewing a Rust application boundary or when a native
question's exposure depends on its caller. Start from the actual crate target,
entry point and enabled feature. A workspace can include a server, a CLI, a
reusable library and build tooling with different trust boundaries.

## Select a scenario from source

Identify what crosses the boundary and who controls it. Follow the selected
input, state or capability through the actual caller and guard to an observable
effect. Bind each step to the same object, buffer, request, principal or task.
Carry relevant conditions such as authentication, target OS, Cargo features,
runtime options, buffer reuse, panic strategy and process isolation.
Start with the few rows that match the code.

| Surface | Scenario to look for | Evidence and a discriminating control |
| --- | --- | --- |
| Network service, proxy or protocol peer | A request or peer controls a length, compressed body, framing decision or protocol transition. One layer accepts bytes that another interprets differently, or decoding spends resources before an effective limit. | Trace the listener or handler, transport mode, both peer interpretations or the first expensive operation. Compare a request rejected before expansion or bytes forwarded after both sides agree on the transition. [Actix compressed bodies](https://rustsec.org/advisories/RUSTSEC-2026-0447.html), [Pingora upgrade](https://rustsec.org/advisories/RUSTSEC-2026-0033.html) |
| File upload, importer, decoder or library called on external data | Malformed structure drives a cycle, excessive work or an out-of-prefix copy. Reused output may carry data from an earlier operation. | Follow bytes from the file or request to the consuming loop or copy and the error or returned bytes. Check progress, cumulative budgets, written extent and dictionary selection. Compare a tiny malformed case, an early rejecting control and a valid small input. [Calamine CFB parser](https://rustsec.org/advisories/RUSTSEC-2026-0436.html), [LZ4 decoder history](https://rustsec.org/advisories/RUSTSEC-2026-0041.html) |
| Archive extractor, installer, updater or privileged file service | An archive entry, upload name, link or path selects a write or read beyond the intended root. An update may replace an executable or configuration used later. | Bind the original entry to the filesystem operation. Check platform path semantics, existing links and the actual root guarantee. Compare the same entry with an effective confinement control. For an update, inspect signature verification, staging and activation separately. [Release archive extraction](https://rustsec.org/advisories/RUSTSEC-2026-0434.html) |
| Authenticated API, credential consumer or data service | A lower-privilege caller reaches another tenant's record, a state transition, an interpreter or a credential consumer through an incorrect binding or skipped check. | Compare two principals or credential purposes. Bind verified claims and the selected object to the protected operation. Follow values into SQL, markup or command grammar only when the actual interpreter consumes them. Compare a valid caller and a rejected cross-boundary caller. [PAM authentication result](https://rustsec.org/advisories/RUSTSEC-2025-0173.html) |
| Outbound client, webhook or fetcher | A caller influences the destination, a redirect changes the effective target, or credentials travel across an unintended boundary. A network peer can take advantage of weakened identity or trust checks. | Verify the dispatched URL, scheme, redirect policy and credential attachment, or the concrete TLS identity policy and peer. Compare a fixed destination or correctly rejected peer. [Webpage URL validation](https://rustsec.org/advisories/RUSTSEC-2026-0407.html), [NATS TLS validation](https://rustsec.org/advisories/RUSTSEC-2023-0029.html) |
| CLI, developer tool, desktop integration or CI | A checkout, project configuration, plugin, IPC peer or downloaded file supplies a path, executable or argument that runs with developer or CI authority. A browser can also reach a local development service. | Find discovery and execution separately. Compare explicitly trusted operator configuration with automatic discovery from a lower-trust checkout. Check Host, Origin and authentication for browser-accessible local endpoints. Trace the executable, arguments and privilege. [Rojo development server](https://rustsec.org/advisories/RUSTSEC-2026-0279.html), [Nextest recordings](https://rustsec.org/advisories/RUSTSEC-2026-0412.html) |
| Reusable safe API, FFI, async or shared runtime | A safe caller, callback, task cancellation or concurrent use violates initialization, ownership, lifetime, Send/Sync or pinning. For FFI, inspect obligations on both sides of the bridge. | Bind the public call sequence, valid input, owner and first invalid operation. Track Drop or callback completion and the actual thread or executor. Compare corrected metadata, bounds, ownership or synchronization with the same caller. [Circular buffer unwind](https://rustsec.org/advisories/RUSTSEC-2026-0256.html), [PyO3 closure bounds](https://rustsec.org/advisories/RUSTSEC-2026-0177.html) |
| Cryptographic operation or protocol trust | A peer can skip verification or observe a secret-dependent operation through a usable channel. | Identify the protected key or value, exact verification decision or secret-dependent operand, attacker observations and relevant target. Compare explicit rejection or the corrected primitive. A timing claim needs a measurement design and controls for noise. [Curve25519 scalar timing](https://rustsec.org/advisories/RUSTSEC-2024-0344.html) |

Dependency advisories run alongside these scenarios. Record resolved version,
target, enabled features and affected API separately from reachability. A
malicious dependency may run through a build script, proc macro or runtime
entry point. Unmaintained and general notices belong in dependency reporting.
An informational unsoundness advisory can still support a source finding when
a safe caller and violated invariant are established. [RustSec reporting criteria](https://rustsec.org/contributing.html), [Malicious build dependency example](https://rustsec.org/advisories/RUSTSEC-2026-0266.html)

## Verify the candidate

1. Start with the candidate's exact operation and question. Write a short
   scenario with the actor or safe caller, controlled input or valid API
   sequence, deciding guard, activation conditions and expected effect.
2. Inspect the next source edge that could change the verdict. A weak marker
   such as slice indexing or allocation becomes more useful when the caller
   delivers untrusted bytes before rejection. A concrete safe-API invariant
   violation can stand on its own even when deployment impact is unknown.
3. Compare the failing case with a repaired or inapplicable control and a
   valid case. For resource issues, distinguish panic from bounded error and
   record where work or allocation occurs. For stale bytes, a small
   preinitialized marker can distinguish reuse from uninitialized memory.
   For UB, plan a reduced Miri case when supported. Source-bound workers
   verify with broker-delivered source and record any runtime test as proposed.
   An authorized operator can use a reduced local fixture and report observed
   results separately. [Rust Reference on undefined behavior](https://doc.rust-lang.org/reference/behavior-considered-undefined.html)
4. Decide the assigned ID on its own evidence. Use `issue` for a demonstrated
   source weakness with its actual impact, `not_issue` when an inspected
   control closes the claim and `needs_review` when a specific deciding edge
   remains unavailable. Keep additional mechanisms separate. When no native
   ID exists, use the source proposal workflow only for a distinct,
   consequential relationship anchored in the assigned source.

For review planning, keep a concrete unsafe invariant, authority bypass or
input-to-effect chain in Value. Use Comprehensive for a plausible material
effect with a named unresolved caller, guard or configuration edge. Once
source establishes an ordinary operation such as an operator-selected startup
file, keep it as supporting evidence for that scenario. Review priority and
severity are separate decisions.

**Example.** A decoder's saturated subtraction gives a useful library
question when the distance and copy are bound to the same output buffer.
For a service exposure claim, follow the upload handler's selected decoder
and feature, pooled buffer reuse, and the bytes actually returned or logged.
If the output goes only to an isolated parser and is discarded on error,
inspect that exact control before assigning disclosure. A small matching
buffer witness would settle the copy behavior separately from network impact.
