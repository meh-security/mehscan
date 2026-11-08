# Rust input, resource and authority patterns

Use with [Rust review](rust-security.md). Memory-safe Rust can still consume
unbounded resources, write outside an intended root or lose an authority boundary.
Keep these claims separate from unsafe-code soundness.

## Length headers and cumulative work

Bind the decoded length to the reservation/resize/repeat/collection operation.
Check units, conversions and a limit before the effect. For record counts,
offsets and strides, follow intermediate arithmetic to the exact value used by
the guard and the allocation, slice or copy. Check whether narrowing, wrapping
or saturation changes that value. `try_reserve` reports some
allocation failures but does not impose a workload budget; a limit after allocation
is too late. Growing only as bytes arrive avoids trusting an absent payload but
still needs an overall limit for genuinely large streams. This distinction is
illustrated by [codeq RUSTSEC-2026-0432](https://rustsec.org/advisories/RUSTSEC-2026-0432.html).

When the length comes from a local header buffer, trace the successful read into
that buffer and the bytes the decoder consumes. Identify who supplies the reader,
any intervening writes and what the bound measures. A remaining-input check can
exclude allocation for a missing payload while leaving a separate question about
the cost of a large payload that is actually present.

When a decoder reads a scalar through a reader field, follow the field type,
trait bounds and imported extension trait to establish that the value comes
from input. For signed lengths, check which negative values can reach the
conversion to `usize`. Follow each reachable format or compatibility branch to
its own allocation. A limit in a shared string decoder covers only branches
that call it. Check whether callers can disable the limit or select a legacy
branch, and distinguish those configurations from the default path.

When a decoder reuses a buffer field for the header and payload, follow the
header resize, successful read or awaited read, decode and payload resize in
order. Check the bound on both client replies and server requests. For an IPC
stream, identify who can select the endpoint or connect to the listener, and
whether allocation precedes message-level authorization. A generic stream or
listener leaves endpoint exposure to its caller. [russh agent framing advisory](https://github.com/Eugeny/russh/security/advisories/GHSA-g9f8-wqj9-fjw5)

```rust
pub fn bad_frame(input: &[u8]) -> Option<Vec<u8>> {
    let n = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let mut body = vec![0; n]; // effect precedes payload availability check
    body.copy_from_slice(input.get(4..4usize.checked_add(n)?)?);
    Some(body)
}
pub fn bounded_frame(input: &[u8]) -> Option<Vec<u8>> {
    let n = usize::try_from(u32::from_be_bytes(input.get(..4)?.try_into().ok()?)).ok()?;
    if n > 1024 { return None; }
    Some(input.get(4..4usize.checked_add(n)?)?.to_vec())
}
```

Witness: a small declared body with no payload demonstrates ordering without a
large allocation; use allocator instrumentation for the attempted size. Test the
repair with an oversized header, exact-limit payload and short ordinary input.
For loops, require cumulative bytes/items, progress or cycle detection as
appropriate. A per-entry cap does not bound an archive's total output, and a
compressed-input cap does not bound decompressed output, recursion or CPU work.
[calamine RUSTSEC-2026-0436](https://rustsec.org/advisories/RUSTSEC-2026-0436.html)
includes a malformed chain that grows storage without a useful iteration bound.

For queues, compare what each accepted item charges with what the receiver
retains. A payload-byte window can leave empty frames free even when each
creates a queue entry. Trace the insertion, the consumer's dequeue, and any
separate item or overhead budget. Check whether a discard preserves terminal
signals and whether discarded work and delivered items return the same credit.
[h2 empty DATA frames](https://rustsec.org/advisories/RUSTSEC-2026-0258.html)

## Compressed request bodies

Trace the enabled codec from content-encoding selection to the first output
buffer and the consumer's limit. Identify which bytes each limit counts and
where it rejects. A wire-size check, a decoded chunk-size bound, and a total
decoded-byte budget cover different effects. For a writer-backed decoder, check
the budget before each output append, across buffer drains and at stream finish.
For a pull-based decoder, check the size of the output buffer passed to each read.
[Actix Web extractor limits](https://rustsec.org/advisories/RUSTSEC-2026-0447.html)

Check codec workspace separately. A limit on emitted bytes can leave an
input-selected window or dictionary allocation inside the codec. Verify the
actual decoder options and the supported codec branches before closing that
question. [Actix HTTP Brotli workspace](https://rustsec.org/advisories/RUSTSEC-2026-0455.html)

## Parser panic and algorithmic amplification

```rust
pub fn bad_tag(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}
pub fn checked_tag(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?))
}
```

Empty and one-byte inputs distinguish panic from rejection; include a valid input
control. Check caller guarantees and the actual failure boundary: panic may abort
the process, unwind a worker or be caught. Bounds-checked indexing does not establish
memory corruption. [ANSSI error guidance](https://anssi-fr.github.io/rust-guide/errors.html)
helps locate fallible paths; a policy preference for Result is not sufficient to
report DoS.

Trace an `unwrap` or `expect` back to the exact failed operation, such as a
checked multiply returning `None`. Check whether an earlier bound rules out
that failure on the same value. For a propagated error, inspect the caller's
response and any allocation or mutation that already happened.

For repeated scanning, recursion or decompression, identify the repeated range and
the measure that should decrease. A geometric input series and operation counts
can demonstrate superlinear work without a service attack. Retain the enabled
options: [pulldown-cmark RUSTSEC-2026-0433](https://rustsec.org/advisories/RUSTSEC-2026-0433.html)
depends on wikilink parsing, including when enabled through `Options::all()`.
Small output does not establish small parsing cost. Bounded input and disabled
features are distinct controls; neither fixes the enabled implementation itself.
When a parser invokes a callback or populates internal state before returning an
event, inspect that helper before crediting limits applied by the event consumer.
Track which counter or budget is shared across recursion or iterations and when it
is checked, reset or overridden.

## Archive names and actual writes

`root.join(entry.name())` does not establish containment. Track the selected entry
through normalization, path checks and every file/directory/link creation.
[ant-releases RUSTSEC-2026-0434](https://rustsec.org/advisories/RUSTSEC-2026-0434.html)
provides this mechanism in release extraction. A harmless `../marker` entry in a
temporary tree is a small witness for an authorized operator.

Use the actual version's ZIP enclosed-path or tar root-aware extraction contract
as applicable; inspect rejection handling and the selected operation. Lexical
containment does not by itself resolve existing symlinks, archive-created links,
check/write races, Windows drive/UNC paths or platform-specific normalization.
A repaired control must address the claimed property and filesystem assumptions.
Load `path-selection` and `file-network` for the specific containment relationship.

For `OpenOptions`, follow the builder returned by the helper through the caller's
setters to the exact `open`, including retry closures and target-specific branches.
Record known access flags separately from unknown flags and from the path policy.
Protection on the final path component leaves the parent components to verify.
For recursive deletion, trace the same selected path and the condition that enables
overwrite or cleanup, even when extraction has a separate guard.

## CLI argument interpretation

Follow checkout, archive or IPC data to the actual launched program. Use
[process review](categories/process-code.md) to distinguish executable selection,
shell text and argument operands. For a direct `Command::arg`, inspect the
callee's option or path grammar and confirm whether its operand separator
applies at that position. On Windows, check the selected program's argument
decoding, especially `cmd.exe` and batch files. [Rust Command](https://doc.rust-lang.org/std/process/struct.Command.html#method.arg)

## Async request and stream lifetimes

For a slow operation, bind attacker-controlled work to the executor that runs
it and the requests that share that executor. For work offloaded to a blocking
pool, inspect admission and queue limits and what happens after the caller
times out. For a held lock, identify its type, where the guard drops and which
other task needs that lock to make progress. [Tokio blocking tasks](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html) ·
[Tokio mutexes](https://docs.rs/tokio/latest/tokio/sync/struct.Mutex.html)

For a timeout, disconnect or losing `select!` branch, identify which future
is dropped and what survives. Check partially read protocol state, queued work
and committed effects before retry. A complete control restores the invariant
or safely resumes the same operation. [Tokio cancellation safety](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety)

## Protocol transitions and credentials

Bind raw bytes, parsed headers, framing decisions and forwarding to the same
request/connection. CL/TE header reads alone do not establish request smuggling.
A valid claim identifies two peers' different interpretations or an early mode
transition. [Pingora RUSTSEC-2026-0033](https://rustsec.org/advisories/RUSTSEC-2026-0033.html)
forwarded upgraded bytes before the backend agreed with a 101 response. Local
peers with marker requests can verify ordering without an external target.

For reqwest redirects/default headers, determine header sensitivity and the
effective version-specific redirect policy for the actual client. A custom header
is not automatically leaked. Two loopback origins with a harmless marker can
settle destination and propagation when execution is authorized.

For JWT verification, bind the configured Validation instance, key/algorithm and
decoded token to the acceptance/privileged action. For generated-token logging,
show that the emitted value is a usable credential and who can read the output.
Distinguish diagnostic identifiers/redaction from accepted tokens. Use `token-review`
and `credential-lifecycle` for issuer/audience, expiry, purpose and revocation.
Avoid reproducing real secrets in evidence.
