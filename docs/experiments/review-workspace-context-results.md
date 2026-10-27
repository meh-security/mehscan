# Context comparison and requested Terra 6.1 medium run

Status: **both bounded studies stopped on rejected lookup requests**. Terra really
ran as `gpt-6.1-terra`, medium: seven observed calls and two native-source-validated
dispositions before a YAML lookup failed. Sol workspace stopped after three calls
with no dispositions. No controller/skill change, paid repair, retry or silent
resume occurred. All **20 paid attempts** have observed usage. This is not a completed
six-case workflow comparison and establishes no whole-package speed or quality win.

The run also exposed a material **SAML oracle/claim-scope ambiguity**. The frozen
expected credential-revocation finding was attached to an authorization marker
whose native relationship highlights SAML request construction. Matching that
expected verdict cannot by itself establish that native Sol was more correct than
Terra. Original expectations are preserved; this correction does not create a
post-hoc pass.

## Frozen conditions and what executed

The [plan](review-workspace-context-plan.md) selected six native claims across
Directus, Juice Shop and existing contract controls: paired logout callers, default
YAML, owned address deletion, an unsafe sanitizer hook and an unknown external
sanitizer. Model settings/availability were checked in the local registry; actual
provider contracts and metrics bind the exact model and medium effort. CLI stayed
`0.164.0-alpha.11.1`; runtime code remained the context/publication implementation
from `360529a`. Documentation commits did not alter that runtime.

Study V: `C:/dmitry/scan-runs/workspace-context-20261027-v`. Sol native/workspace
and Terra workspace preparations had independent state, identical initial source
and native bundle membership, with default maximum 20. Four bundles contain
2 / 1 / 1 / 2 claims. Six calls, 24 query units, 512 KiB received JSON and 900 seconds
per bundle; each dataset/arm has 1,800 seconds. Execution is serial, and stopping
on any controller/tool failure or unknown usage was frozen before dispatch.

V completed native Sol's three Directus claims. The subsequent Sol workspace arm
failed, so V closed with thirteen calls. Terra and the remaining datasets were not
dispatched. V's unused allowance/states were not reused.

To fulfil the user's explicitly requested additional model run, study VT was
separately prepared and frozen at
`C:/dmitry/scan-runs/workspace-context-terra-20261027-vt`. It uses fresh stores,
Terra 6.1 medium, the same six cases and same per-bundle limits, with a 24-call
ceiling. Exact controller/skill/scanner/provider descriptor and initial-source
equality with V's unused Terra preparations were checked before inference. Thus
this is an independent additional model run, not a repaired Sol run. VT finalized
the two-claim logout bundle, then failed on its second YAML turn and closed.
Neither Juice Shop nor HTML controls received live review in either study.

Native completion admitted only into V's fresh private study store. Workspace used
native finalization without admission. No application/shared production state or
remote publication changed. The earlier R/S/T/U and main/reserved datasets remain
unchanged and closed/unreviewed as applicable.

## Actual cost, including incomplete work

| Observed slice | Calls | Input | Cached input | Output | Review-call time | Active execution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Sol native / Directus, three dispositions | 10 | 311,227 | 0 | 7,083 | 249.856 s | 269.712 s |
| Sol workspace / Directus, no dispositions | 3 | 56,861 | 0 | 1,340 | 41.671 s | 54.812 s |
| Terra workspace / Directus, two dispositions | 7 | 136,442 | 6,528 | 3,469 | 77.709 s | 116.968 s |
| Total | 20 | 504,530 | 6,528 | 11,892 | 369.236 s | 441.492 s |

These slices complete different amounts of review. Do not turn their time/token
ratios into savings or model rankings. Preparation totals 89.471 seconds for V,
including unused datasets, and 41.319 seconds for VT; retain both costs. These
measured intervals exclude implementation/evaluator labor and are not end-to-end
wall-time claims. No input-percentage gate applies.

Workspace state/work validation still costs 9.651 seconds / 19 checks for Sol and
28.111 seconds / 55 checks for Terra. The earlier offline publication improvement
remains valid within its fixed pattern, but it did not eliminate controller overhead.

## Why execution stopped

Sol's third response requested:
`symbol(name="logout", path="api/src/auth")`. The symbol tool's optional `path`
filters a file, so the directory is rejected. The complete requested lookup batch
was validated before native lookup, leaving its other requests unexecuted. The
three paid calls and six previously consumed query units/five completed receipts
remain recorded; no judgment was fabricated.

Terra finalized the logout pair in five calls. Its second YAML response requested
`references(symbol="readFileUploadBody", path="api")` to discover YAML callers and
size options. That tool supports directory scope through `path_prefix`, but the
returned `path` was a directory. The same controller check rejected the batch;
seven total Terra calls remain observed, with no YAML disposition.

These are model lookup errors safely rejected by the controller, not target-source
or ownership failures. Treating an ordinary filter error as fatal makes the review
package brittle. The error text also recommends `path_prefix` generically although
the offered symbol tool does not support that argument. A future feedback path
must describe the actual tool's allowed alternatives instead of inducing another
invalid request. No runtime change or normalization was applied to these studies.

## Source audit and the SAML scope conflict

Sol native returns a conditional SAML finding, canonical-logout scoped negative
and default-parser scoped negative. Its source trace inspects JWT/session issuance,
the selected cookie argument, raw-token lookup/delete and the accepting middleware/
session verifier. The **local revocation mechanism is supported**: in the relevant
SAML session/cookie path, signed wrapper J is passed where the database session key
R is expected. Clearing the cookie does not revoke R; replay claims retain JWT and
session validity conditions. Native source validation alone does not decide whether
that finding belongs to this selected review ID.

Terra correctly inspects the shared logout service and the canonical caller's mode
normalization before returning its scoped negative. For SAML it retains uncertainty
about the identity-provider request's subject/authorization contract and saves a
**separate unreviewed local-revocation lead**. It does not call SAML safe, and that
lead is not a classified finding. Terra does not inspect the full issuance/acceptance
chain needed to turn its conditional lead into the stronger source-supported result.

The exact SAML native ID is `observation-review-77b1f507d66d7e7b`, capability
`authorization`, relationship `bounded_action_resource_authorization_review`, with
`related_handler_1=createLogoutRequest`. Its card explicitly asks what that helper
enforces for the affected subject/action/resource or credential transition. The
frozen oracle instead required the local credential-revocation result (CWE-613).
The marker spans the POST handler containing both statements, so this is a real
scope ambiguity to resolve, not merely a requirement to match candidate CWE hints.
Candidate CWEs remain leads; the issue is the security relationship being adjudicated.

Consequently, do not label Terra a proven authorization false negative from its
`needs_review`, or treat native Sol's matching `issue` as proof of better claim
alignment. Conversely, do not promote Terra's unreviewed lead into a supported
classified finding or declare whole-package coverage complete. Both the selected
claim and coverage of the distinct revocation mechanism need honest status.
No wrong safe dismissal was identified in the completed dispositions. The YAML
and remaining controls are not completed model-quality data.

`oracle-scope-erratum.json` records the post-run conflict separately; original
frozen expectations and the recorded execution failure stay unchanged. The earlier
dependency-policy trial's SAML verdict agreement is also not safe ground truth for
this claim relationship without that same scope qualification. Its source mechanism
and paid costs remain evidence; no historical trial is silently rescored here.

The new state path was exercised live: after canonical logout retired, Terra's next
packet retained the answered shared service question, latest conclusion and cited
source while the SAML question remained open. This verifies transport/partial reuse,
not semantic correctness of every shared interpretation or a quality recovery.

## Corrected next work

1. **Make routine lookup mistakes recoverable within the original limits.** Return
   bounded controller feedback for invalid file/directory filters; retain the exact
   requested fact and query, executed scope, paid usage and applicable query/byte
   costs. A directory-to-prefix conversion is permissible only where that tool
   actually offers it and preserves scope. Other cases require explicit feedback.
   Never broaden a search silently, treat an API error as absence evidence, refund
   paid calls, or recover source/owner/runtime failures through this mechanism.
   Test valid mixed batches, malformed filters, unknown usage, stale source and
   replay, then use a fresh freeze. More prompt warnings are not the demonstrated fix.
2. **Re-audit claim-to-mechanism alignment before the next quality gate.** Select an
   unambiguous native positive for the requested property. Keep the IdP authorization
   question separate from local revocation coverage; preserve unmapped mechanisms
   honestly without forcing them into another scanner claim. Do not add a large new
   finding subsystem merely to repair this oracle. Compare supported mechanisms,
   scoped verdicts and actionable uncertainty as separate package outcomes.

Then run a fresh bounded comparison, retaining the requested Terra medium variant
alongside the primary same-model workflow comparison. Do not resume V/VT or use
their unused ceiling for repairs. The sixteen mixed main/eight reserved claims and
full application review remain outside scope. There is no basis yet for a model
ranking, full-app efficiency claim or wider workspace promotion.
