# Rust memory and lifecycle patterns

Use with [Rust review](rust-security.md). These are original reduced examples,
not copies of affected packages. A suspicious primitive needs its violated
precondition and caller. Correct uses of unsafe, raw pointers and custom marker
traits are ordinary Rust implementation techniques.

## Extents and initialized storage

Track element count versus byte count, signed/narrowing casts, `size_of::<T>()`,
offset, capacity and initialized length separately. A mathematical check after
an overflowing expression cannot repair the earlier value. Checked arithmetic
must reject failure; saturating arithmetic is not generally a valid substitute
for a buffer extent. Record effective overflow checks and target pointer width.
[bytes RUSTSEC-2026-0007](https://rustsec.org/advisories/RUSTSEC-2026-0007.html)
shows wrapped extent arithmetic corrupting trusted buffer metadata.
[ANSSI integer guidance](https://anssi-fr.github.io/rust-guide/integer.html)
explains why build-profile overflow behavior matters.

Original reduction: the bad total can wrap under the applicable overflow policy.
The repaired total rejects overflow and an excessive result before any allocation.

```rust
pub fn bad_total(count: usize, width: usize, prefix: usize) -> usize {
    count * width + prefix
}
pub fn bounded_total(count: usize, width: usize, prefix: usize) -> Option<usize> {
    let total = count.checked_mul(width)?.checked_add(prefix)?;
    (total <= 4096).then_some(total)
}
```

Witness: `usize::MAX, 2, 0` distinguishes wrapping/panic from rejection without
allocating huge memory; also check an ordinary small input and the exact limit.
Arithmetic alone is not memory corruption: inspect the allocation/access that
trusts the result.

Capacity is not initialized length. For `set_len`, `assume_init`, raw slices and
copies, bind the exposed range to successfully initialized elements of the same
allocation, including partial reads, errors and panics. Check alignment, validity,
overlap requirements, allocation provenance and ownership for the exact API.

```rust
pub fn bad_bytes(n: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(n);
    unsafe { bytes.set_len(n); } // exposes storage with no preceding writes
    bytes
}
pub fn initialized_bytes(n: usize) -> Vec<u8> {
    vec![0; n]
}
```

The repair settles initialization only; a hostile `n` still needs a resource
budget. A small Miri witness consuming `bad_bytes(1)[0]` can test invalid exposure;
ordinary execution is not a reliable UB demonstration. For stale-data disclosure,
use an initialized marker in reused storage and prove it reaches returned output.
That is distinct from reading truly uninitialized bytes. The decoder mechanism
in [lz4_flex RUSTSEC-2026-0041](https://rustsec.org/advisories/RUSTSEC-2026-0041.html)
requires checking back-reference offsets against the initialized prefix/dictionary.

## Cleanup during unwinding

Treat caller-controlled Drop, Clone, comparisons, iterators and callbacks as
potential unwind points. Follow cleanup and later reuse, not just the success
path. A safe API cannot leave raw ownership metadata authorizing repeated drop.
[circular-buffer RUSTSEC-2026-0256](https://rustsec.org/advisories/RUSTSEC-2026-0256.html)
records this as informational unsoundness with a safe-call memory-safety witness.

```rust
pub fn bad_remove_last<T>(items: &mut Vec<T>) {
    let n = items.len();
    if n == 0 { return; }
    unsafe {
        std::ptr::drop_in_place(items.as_mut_ptr().add(n - 1));
        items.set_len(n - 1); // skipped if T::drop panics
    }
}
pub fn remove_last<T>(items: &mut Vec<T>) {
    drop(items.pop()); // ownership is removed before invoking T::drop
}
```

Witness plan: one element owns a Box and panics once during Drop; catch the unwind,
then drop the container under Miri. Compare the repaired path and an independent
nonpanicking type. `AssertUnwindSafe` does not restore ownership. Account for
`panic=abort` applicability. The [Rustonomicon exception-safety discussion](https://doc.rust-lang.org/nomicon/exception-safety.html)
also covers partially initialized data and user code invoked in temporary states.

## Thread transfer and sharing

Inspect the storage, generic bounds, method receiver and callback dispatch
together. `Send` permits transfer; `Sync` permits shared access. A closure being
Send does not establish concurrent-call safety. PyO3's
[missing Sync bound advisory](https://rustsec.org/advisories/RUSTSEC-2026-0177.html)
illustrates why the eventual invocation contract matters.

```rust
pub struct Forced<T>(pub T);
unsafe impl<T> Send for Forced<T> {} // unjustified for arbitrary T
unsafe impl<T> Sync for Forced<T> {}
pub struct Derived<T>(pub T); // compiler propagates T's auto-trait requirements
```

A compile witness can assert that `Forced<Rc<Cell<u8>>>` is Send/Sync; the same
assertions must reject `Derived<Rc<Cell<u8>>>`. This reveals an erased restriction,
not a race by itself. Inspect safe methods permitting concurrent access, thread
affinity, synchronization and destruction before stating the effect. Explicit
unsafe impls can be valid with sufficient invariants; do not mechanically add
`T: Sync` to every Send implementation. See the
[Rustonomicon Send/Sync contracts](https://doc.rust-lang.org/nomicon/send-and-sync.html).

## FFI lifetime and ownership

Bind a raw pointer to its actual owner and every retaining consumer. A pointer
copied out of a temporary does not keep that allocation alive.

```rust
pub fn dangling_name() -> *const std::ffi::c_char {
    std::ffi::CString::new("review-marker").unwrap().as_ptr()
}
pub fn owned_name() -> std::ffi::CString {
    std::ffi::CString::new("review-marker").unwrap()
}
```

Returning a dangling raw pointer does not itself dereference it. Establish a later
read/callback while the owner is gone; a synchronous consumer with a live owner is
a control. The repaired caller must retain `owned_name()` for the consumer's entire
use, including deferred callbacks. Check allocator/release pairing, length changes,
null/enum validity, ABI/layout and unwinding at the boundary. `CString::from_raw`
cannot generically reclaim a foreign allocation. Sources:
[CString ownership contracts](https://doc.rust-lang.org/std/ffi/struct.CString.html),
[ANSSI FFI guidance](https://anssi-fr.github.io/rust-guide/unsafe/ffi.html).

## Pinning, async cancellation and reentrancy

For `Pin::new_unchecked`, unchecked projection, lifetime erasure or manual Unpin,
show what address-sensitive value can move or become invalid and which safe
operation permits it. Pinning a Box does not automatically pin every reachable
allocation. Check structural projection and Drop obligations against the
[std Pin contract](https://doc.rust-lang.org/std/pin/index.html).

For an in-flight future or registered callback, trace ownership through Pending,
drop/cancellation, completion and reentrant calls. A pending foreign operation
retaining a pointer needs completion/unregistration before storage dies. A future
being dropped is normal; a vulnerability needs a concrete remaining consumer or
broken state/authority invariant. Treat async-library semantics as version-specific.

Use [Miri](https://github.com/rust-lang/miri) for supported small memory/race
witnesses when execution is separately authorized. A passing run covers that
execution, not all lifetimes, schedules, targets or foreign code.
