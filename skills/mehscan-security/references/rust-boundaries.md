# Rust input, resource and authority patterns

Use with [Rust review](rust-security.md). Memory-safe Rust can still consume
unbounded resources, write outside an intended root or lose an authority boundary.
Keep these claims separate from unsafe-code soundness.

## Length headers and cumulative work

Bind the decoded length to the reservation/resize/repeat/collection operation.
Check units, conversions and a limit before the effect. `try_reserve` reports some
allocation failures but does not impose a workload budget; a limit after allocation
is too late. Growing only as bytes arrive avoids trusting an absent payload but
still needs an overall limit for genuinely large streams. This distinction is
illustrated by [codeq RUSTSEC-2026-0432](https://rustsec.org/advisories/RUSTSEC-2026-0432.html).

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

For repeated scanning, recursion or decompression, identify the repeated range and
the measure that should decrease. A geometric input series and operation counts
can demonstrate superlinear work without a service attack. Retain the enabled
options: [pulldown-cmark RUSTSEC-2026-0433](https://rustsec.org/advisories/RUSTSEC-2026-0433.html)
depends on wikilink parsing, including when enabled through `Options::all()`.
Small output does not establish small parsing cost. Bounded input and disabled
features are distinct controls; neither fixes the enabled implementation itself.

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
