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
| Ownership/lifetime | Same allocation, pointer, release family and reachable path. A failed-allocation return is not a post-allocation leak. |
| Format string | Whether the complete format is compile-time fixed; runtime text should be a data argument or constrained as a whole format. |

A nearby check protects the operation only if it covers the same value before
use and its rejection terminates. Do not infer typedef widths, macro effects,
custom deleters or caller preconditions from names. `native-call-sites` and
`structural` are syntax navigation, not call graphs or new scan evidence;
use them only for an exact unresolved syntax question.
