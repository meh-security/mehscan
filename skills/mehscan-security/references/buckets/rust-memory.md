# Rust memory and soundness

For Rust unchecked indexing, validate each endpoint against initialized length,
not capacity. Creating an out-of-range reference is already invalid. set_len
requires valid initialized elements and sufficient capacity; shrinking can be a
valid control. For MaybeUninit, identify actual writes and destination validity;
zeroing does not create a valid value for every type. Pointer offsets require
same-allocation and arithmetic proofs; one-past pointers differ from accesses.
Equal-sized transmute types can still violate representation, lifetime or aliasing.

For source-bound Send/Sync assertions, inspect the actual generic storage and
bounds, interior mutability and synchronization before constructing a safe
caller. The unsafe assertion is not itself a vulnerability. For panic cleanup,
trace metadata at the moment an element destructor can unwind, then the same
owner's later Drop. Compare metadata-before-drop controls and nonpanicking
concrete elements without assuming all generic destructors are nonpanicking.

Rust `raw_operation_definition` and the captured parameter/owner identify the
selected operation. Review each invariant separately: vector metadata uses
element counts and initialized length no greater than capacity; ownership must
transfer the same live allocation exactly once; retyping must preserve allocation
size/alignment and valid initialized representation. A byte pointer's apparent
alignment does not establish the allocation layout required at deallocation.
`Copy` does not exclude padding, and a plain-data bound alone does not guarantee
that changing the allocation's element alignment is valid. A repair for metadata
or padding is not closure for another invariant. See the
[vector reconstruction contract](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.from_raw_parts).

For raw slices and copies exposed through safe APIs, check every relevant pointer,
extent, alignment, mutability and lifetime condition. A non-null check does not
validate arbitrary non-null addresses or lengths. For slice-derived pointers,
compare the count with the exact source/destination bounds before the operation;
account for element size and overlap. `copy` permits overlap;
`copy_nonoverlapping` does not. Bitwise copying owning values also needs an
ownership transfer: inspect the actual source suppression and destination Drop,
including custom element Drop and unwind paths. Follow the original binding
through moves and shadowing; forgetting a replacement owner does not release the
original one. An opaque helper leaves its precise effect unresolved. See
[raw-copy requirements](https://doc.rust-lang.org/std/ptr/fn.copy_nonoverlapping.html).

Distinguish consuming the owner from forgetting a reference or derived pointer:
the latter does not disable the backing container's destructor. After drop is
disabled, trace actual reallocations, additional owners and handoffs of that
allocation before reconstruction. A `ManuallyDrop` constructor does not prove
the captured allocation remains live after a later helper or mutation.

`rust_context_*` captures provide bounded typed definitions, import/re-export
bindings and macro bodies as source context. They do not prove trait dispatch,
macro expansion, active features, caller authority or a transaction's coverage.
Use the exact bound implementation when established; identify the unresolved
binding/configuration when it decides the result. Optional context is separate
from the selected operation's applicability.

For Rust raw slices, use `null_pointer`, `safe_constructor`, `field_transfer`
and `safe_accessor` to check that a possible null state belongs to the same
object field. A raw slice requires a non-null pointer even for zero length.
Returning an empty slice before construction can settle this invariant;
alignment, initialized extent, single-allocation range, lifetime and aliasing
remain separate. A generic `unsafe` block or FFI declaration alone establishes
no such relationship. See the [raw-slice safety requirements](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html#safety).

For initialized-prefix questions, distinguish allocation capacity, initialized
length and output position. Follow the same mutable buffer from safe construction
through the carrier and publisher; inspect the supplied standard-vector effect
and any initializing write. A source-bound trait implementation is a concrete
witness, not proof about every implementation. Helper names do not establish
effects. A safe library API can expose a real invariant violation for valid
caller arguments without an HTTP entry point.

Before `Vec::set_len`, the newly exposed elements must already be initialized.
An FFI writer starting at a nonzero position may leave an earlier gap untouched.
Zero filling settles that gap only when its exact pointer, starting offset,
count, branch and order cover the range before publication. Partial writes,
unknown helper effects or initialization after exposure do not establish that
coverage. Preserve a complete earlier initialization as a negative control;
otherwise identify the precise missing effect or dispatch fact. Keep null,
alignment, capacity, lifetime and initialization claims separate. See
[the vector length contract](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.set_len).
