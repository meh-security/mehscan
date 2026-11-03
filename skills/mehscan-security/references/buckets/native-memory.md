# Native memory and parser state

Match the exact operation to its authoritative extent, object and branch.
Attacker-controlled input is not required for every memory defect.

`native_operand_declaration` locates the scalar's declared type; inspect typedefs,
promotions and the value at the operation before deciding its arithmetic domain.
`local_call_argument` locates one direct file-local helper argument. Check its
conversion and the helper's guards; it does not prove runtime reachability or
all caller preconditions. A boundary names the unresolved binding or caller.

| Question | Inspect |
| --- | --- |
| Allocation/copy overflow | Operand widths and a pre-computation division bound for every product or sum. A later check cannot undo overflow. |
| Buffer write/read | Destination capacity, offset, count and every relevant axis before the operation. |
| Parser remaining input | Cursor bound and `length <= total - cursor` before the read; `cursor + length` may wrap. |
| Fixed-layout blob | Reported source length against the exact copy extent. Allocation size is a different invariant. |
| Subtracted copy count | The original integer's lower bound before subtraction, its promotions and conversion into the actual copy-count parameter. |
| Rust raw slice | A concrete pointer state, the same owned field and a rejecting non-null boundary before construction, including zero length. |
| Initialized buffer prefix | The initialized element range before a stored position becomes logical length, including any gap skipped by an FFI writer. Capacity is separate. |
| Ownership/lifetime | Same allocation, pointer, release family and reachable path. A failed-allocation return is not a post-allocation leak. |
| Format string | Whether the complete format is compile-time fixed; runtime text should be a data argument or constrained as a whole format. |

A nearby check protects the operation only if it covers the same value before
use and its rejection terminates. Do not infer typedef widths, macro effects,
custom deleters or caller preconditions from names. `native-call-sites` and
`structural` are syntax navigation, not call graphs or new scan evidence;
use them only for an exact unresolved syntax question.

For a defined helper or constructor, use `definition`, `defined_copy` and
`binding_*` captures to check the qualified implementation and source/count
positions. A braced return can invoke a copying constructor. Its name alone
does not establish the effect. A rejecting helper's body can establish that
normal return implies its predicate; it need not prove termination.

A protected subtraction path settles that arithmetic invariant. It does not
prove source accessibility, allocation success, destination capacity or every
conversion inside the helper. `member_initializers` and an unresolved-effect
tag identify remaining applicability questions. Check those definitions when
they could change the verdict. Also distinguish a negative count passed to a
generic `std::copy_n` from a negative value converted into an unsigned count
before that call; their effects differ. See the [standard copy-count semantics](https://eel.is/c++draft/alg.copy#lib:copy_n).

For persistent-vector borrows, follow `container_binding`, `persistent_storage`,
`mutation_*`, `borrow_*` and `outward_call_*` through the supplied operation.
A pointer passed outward is not proof that the callee retains or later uses it;
resolve that storage/use question when it decides the verdict. Repeated loop
iterations can revisit the same keyed vector. Resize or growth can invalidate
its existing element pointers even when the borrow appears later in one iteration.
Check duplicate-entry and capacity guards on that same vector before mutation.
An empty-vector guard that rejects populated entries can prevent a second
mutation of storage already lending elements. Do not require exhaustive caller
discovery once the selected relationship is settled. Keep capacity, allocation
failure and unrelated lifetime claims separate. See [vector invalidation](https://eel.is/c++draft/vector.capacity).

For `loop-carried-reference-publication`, `back()` or `front()` passes an element
reference outward; `outward_storage_*` supplies a local receiver declaration when
available. Inspect the actual stored type and conversion: an owning string copy
differs from a copied view containing a pointer and length. A reference argument
does not prove retained borrowing. For views into string data, vector relocation
does not necessarily invalidate a moved heap buffer; establish the relevant
element move/copy behavior and possible inline or short-string storage. Trace a
retained view to its later read or comparison after growth. An opaque storage
implementation leaves that exact retention/use question unresolved.

For pending collection ownership, follow `collection_binding`, `allocation_*`,
`collection_insert_*` and `exceptional_exit` through the complete operation.
A throw early in an iteration can abandon allocations from prior iterations.
Check cleanup before the selected throw, enclosing handlers or scope guards,
and when the successful path actually transfers those same allocations.
Destroying a standard raw-pointer vector releases its slots, not its pointees.
Borrowed entries and independently owned allocations can coexist; settle the
selected allocation's cleanup without treating every entry as newly owned.
Deleting with a different allocation family or an opaque cleanup helper does
not establish correct cleanup. Keep unrelated throw sites, failed insertion,
double deletion and other lifetime claims separate from the selected exit.

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
