# Parsers, deserialization and resource effects

Bind the exact parser/import, version/options and downstream consumer before
classifying the effect. Parsing untrusted input is a review entrypoint, not an
automatic code-execution or denial-of-service finding.

Distinguish executable types/hooks, external-resource access, expansion, deep
recursion and ordinary data decoding. A safe-type schema can close executable
deserialization while leaving a separately supported resource effect open.
Likewise, a parser default may be safe unless the application enables a loader,
filesystem provider, entity substitution or custom construction hook.

For expansion, inspect what materializes the result. Shared references may remain
compact until a later stringify, traversal or render duplicates the data. Check
the actual input exposure and enforced size/depth/time/memory boundary. Small
wire size alone does not bound expanded work, but a generic large-input argument
without a disproportionate effect is weak evidence.

For XML/external entities, inspect both entity/DTD behavior and registered resource
providers. For archives, include extraction paths and expansion controls relevant
to the selected question. Rejected HTTP responses do not undo parsing or writes
that already occurred.

Use established matching API semantics where applicable. Custom loaders and
unknown decisive contracts need targeted evidence; absent vendored dependencies
alone are not a mandatory blocker. Repository fixtures/tests can support the
mechanism without being described as executed. Keep impact limited to the shown
effect: exhaustion does not establish arbitrary code execution.
