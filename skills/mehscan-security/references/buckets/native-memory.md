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
