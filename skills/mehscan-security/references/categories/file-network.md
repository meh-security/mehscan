# Files, network destinations and redirects

Use the resource-boundary guide for operand facts; this guide frames the complete
operation when producers, consumers or alternate paths matter.

For files, compare the final selected path and actual read/write root. Normalizing
a path is not containment; containment checked after the effect is not enforcement.
Check relevant platform separators/rooted paths and symlinks only when supported
execution conditions make them material. A fixed temporary cleanup path does not
inherit an adjacent archive extraction weakness.

For archives, bind each member's target and extraction write. Distinguish escape
from the upload root, escape from the repository root, overwrite and later code/HTML
interpretation. A writer-to-consumer link needs matching paths and reaching
conditions; do not infer it merely because both use uploaded files.

For network calls, first establish execution authority: server, browser, desktop
or intentional operator tool. Then inspect the final scheme/host/port, rewrites,
redirect handling and relevant private destination constraints. Do not call a
browser request SSRF solely because a URL is controlled. A fixed public endpoint
does not authorize forwarding a credential to a caller-selected alternate host.

For redirects and browser URLs, verify the emitted destination and relevant
consumer semantics. A string-concatenation concern needs an actual destination
change. A claimed unusual-path exploit also needs the application handler to be
reachable at that path; configuration ambiguity remains a named limitation.

Template options can select files independently of a fixed view name. Bind the
registered view engine and actual option; use established API semantics or inspect
the deciding contract. Separate disclosure from subsequent interpretation.
