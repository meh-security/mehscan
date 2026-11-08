# C/C++ memory and parser state

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
| Ownership/lifetime | Same allocation, pointer, release family and reachable path. A failed-allocation return is not a post-allocation leak. |
| Format string | Whether the complete format is compile-time fixed; runtime text should be a data argument or constrained as a whole format. |

A nearby check protects the operation only if it covers the same value before
use and its rejection terminates. Do not infer typedef widths, macro effects,
custom deleters or caller preconditions from names. `native-call-sites` and
`structural` are syntax navigation, not call graphs or new scan evidence;
use them only for an exact unresolved syntax question. If `structural` reports
`parse_recovered_files`, use returned matches as source anchors and check any
missing edge with an exact source read.

When a parser reuses decoder state across phases, trace the saved buffer,
remaining count and owner together. On an early exit, follow the cleanup
implementation through return or buffer replacement. Clearing an owner flag
alone may leave a live count with a dangling pointer. Check whether the next
public operation reinitializes the state or resumes from it. Use a caller that
initializes the next phase first as a control, and verify that the configured
feature and call sequence can reach the stale read before reporting it.

When an object stores a product for an allocation, resolve the operands at the
calculation even if the result field has a wider type. Follow field declarations,
getters and base/derived implementations into the array allocation and compare
its extent with the stride or bounds used by the writer. An axis limit protects
the product only when the maximum admitted combination fits the arithmetic
type. Verify a repair at the multiplication and carry any separate allocation or
indexing concern as its own question.

For a split copy from a circular buffer, trace the actual source allocation
size and check both segment lengths. The first segment ends at the ring boundary.
The wrapped remainder starts at the source base and still needs its own bound.
A single-wrap implementation can use a total count bounded by the ring size.
Check that any earlier rejection covers the decoded or cached count before it is
stored for later use. A destination capacity or signedness check covers a
different invariant. Verify destination advancement separately and use a
non-wrapping or explicitly source-bounded path as a control.

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
