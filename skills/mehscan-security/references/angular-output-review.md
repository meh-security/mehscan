# Angular output evidence

Use with the HTML output guide when selected IDs contain Angular trust bypasses.
Mehscan supplies exact source navigation; you determine the effective value,
context, control and trust boundary. No supplied relationship is a runtime proof.

## Read the chain

- Component/template and host facts identify explicit metadata and a candidate
  consumer. Confirm the selected field or method reaches that binding. Distinguish
  HTML (`innerHTML`, `srcdoc`) from escaped text, URL and resource URL contexts.
  A matching property name or text-only consumer does not establish XSS.
- Pipe facts include a registered implementation and observed template use.
  Check imports or NgModule declarations/exports, `transform` arguments and the
  complete expression in order. Names alone do not establish registration or
  escaping. Inspect another chained pipe or input transform if it changes the
  result. Different registrations of the same name can have different behavior.
- Input/handoff facts pair a parent binding with a decorator, signal or metadata
  input, including aliases. Follow object members, collection items and template
  aliases separately; `description` evidence does not prove anything about `image`.
  Verify setters, transforms, reassignment and the actual child renderer when
  relevant. Signals must be called to read their value.
- Value handoffs show local assignment or object-key renames. A library's
  `args` field does not prove its template item has the same contents. Verify the
  actual library contract or implementation if that edge is decisive.
- Material dialog facts identify an imported `MatDialog.open` call, injected
  `MAT_DIALOG_DATA` and a target template. Check the passed `data` object and
  selected member; verify the opener is on the relevant path. Other dialog
  libraries need their own contract rather than assumed Material behavior.

`bypassSecurityTrust*` marks a value trusted; it does not sanitize it. Verified
normal Angular binding plus its documented public API can establish that bypass
without an installed dependency tree. Research exact versions or overrides only
when they would change the decision. An intentional trusted author/seed path,
escaped pipe before trust marking, or text-only output can refute the selected
property; a lower-trust input and HTML interpretation can establish an issue.

## Request the missing edge

Reuse supplied source. Use journaled `source`, file-scoped `symbol`, or scoped
`references --summary true` as described in the HTML guide. Start at the declared
template, actual input/pipe implementation, module or producer that is missing.
Packets stop at bounded depth/count/size. Missing consumers, dynamic metadata,
barrel aliases, inheritance and external registrations remain research directions;
they do not mean no consumer exists. Expand a clipped method only if needed.

Stop with the HTML guide's per-ID decision and finalization. State a specific
unavailable fact when blocked; do not require whole-app taint or hypothetical
deployment research to settle a source-visible relationship.
