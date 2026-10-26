# Process and code interpretation

Identify what actually executes: binary, shell script, interpreter option, dynamic
code body or merely a builder. Follow a consequential builder to launch before
claiming execution. Separate input control from permission to invoke the feature.

For process calls, inspect executable selection, argv construction, shell mode,
environment and working directory only where they can change the selected effect.
Separate argv prevents shell parsing of those values; it does not prevent unsafe
program options, an attacker-selected binary or an explicit interpreter argument.
Quoting must match the actual shell and platform. Do not treat an intentional
operator command runner as remote command injection without a less-trusted caller.

For evaluators, locate the exact code operand and any template, stored field or
file that supplies it. A numeric expression with a closed operator alphabet can
be clean even though eval is present. A sandbox label does not establish isolation;
inspect the exposed authority only when sandbox escape is the selected claim.

The interpreted-input unsafe-construction policy distinguishes source-supported
shell/code construction from proven remote exploitation. State unresolved caller
or activation conditions explicitly. Do not attribute a prior eval effect to a later
template API merely because both occur in the same handler.

Finish once executable/code control, relevant interpretation and the same-path
restriction or weakness are established. Retain a distinct privileged automation
or workflow bypass separately instead of transferring its verdict to every launch.
