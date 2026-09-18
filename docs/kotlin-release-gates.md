# Kotlin release readiness

The current partial Kotlin JVM profile is approved for release as-is on
2026-09-18. The remaining coverage categories below are future improvements,
not requirements for this release. This records the user-approved release scope;
it does not claim compiler completeness or coverage of all Kotlin platforms.

| Release check | Result |
| --- | --- |
| Vulnerable and safe source controls | 269 selected cases; Luna and Terra agree on every predefined label. Changed inputs were freshly reviewed; identical validated requests reused accepted responses. |
| Report quality | All selected reports have engineer-ready audit evidence, including the corrected Exposed batch. Earlier failures remain retained. |
| Report projections | 72 primary JSON/SARIF/Markdown sets reconcile; both corrected Exposed projections pass. |
| Build and tests | 1,013 workspace tests pass; 41 optional tests ignored. Formatting, strict workspace lint and CLI acceptance pass. |

## Future improvements

- Broader JVM deserialization, class/filter policy and XML resolver/lifecycle effects.
- TLS caching, concurrency and additional trust bindings; JWT SDK and lifecycle coverage beyond the tested Auth0 profile.
- Additional JDBC/persistence APIs and complete branch/binding effects.
- Wider Ktor/Spring routing, model-property, authentication and authorization effects.
- Additional process, filesystem, network, proxy and custom-handler effects.
- Compiler value/call semantics, helper effects, coroutines and mixed Java/Kotlin relationships.
- Compiler-backed identities, inheritance/overload resolution, dependency metadata and custom Gradle source sets.
- Android, Kotlin/JS and Kotlin/Native platform-owned boundaries.

See the [coverage profile](kotlin-coverage.md) and
[quality checkpoint](kotlin-quality-results.json) for the supported scope and evidence.

The historical verification notes below retain earlier failures and gate states;
the release decision above supersedes their pending-release wording.

## Local verification progress

The Auth0 JWT follow-up adds canonical decoding and verification boundaries.
Six original helpers produce eight admitted policy reviews: unverified admin
claims, metadata display, HMAC verification, unsigned algorithm acceptance,
swallowed verification exceptions and same-token verification before instance
decoding. Twenty-four direct SDK assertions pass with Auth0 java-jwt 4.6.1 on
Kotlin 2.4.10/JDK17, using owned valid, forged-signature and unsigned credentials
plus invalid issuer, audience and expiry controls. Operational server keys are
private harness dependencies, not request-selected values.

The focused integration test initially compared the fact's exact-operation
header with the function body rather than ordering operations within the body;
that test failure is retained and its source-order assertion now inspects the
actual containing function. Catalog validation caught the newly supported
Kotlin CWE-347 language count; the declaration and per-CWE expectations now agree.
The corrected integration suite, all 22 Kotlin tests and catalog validation pass.
An export made with the pre-build CLI is retained as stale and excluded from
reviews. After terminal build success, all eight fresh policy facts are verified
before independent model calls. Eight predefined source labels are frozen before
fresh Luna/Terra/Sol review. All three models match 8/8 labels, all three quality
audits mark their reports engineer-ready with nonblocking wording/grouping
warnings, and all three projection checks pass. An overbroad argument filter
initially risked excluding opaque String aliases; it now rejects enumerated
known incompatible Kotlin types without asserting unknown aliases' compiler
types. Its regression also covers primitive verify input, SDK shadows, foreign
builder methods and mutable aliases. The rebuilt export preserves all eight
accepted request payloads byte-for-byte; this is equivalence evidence, not a new
security run. The engine unit suite passes 169 tests and strict lint passes.

JWT dismissals now identify their source helper. A first regenerated handoff
passes all three quality audits and projection checks, but still mixes unsigned
algorithm and swallowed-failure mechanisms in shared impact text. That audited
round is retained. The next regeneration preserves each operation-specific
validated summary and uses only the common unauthenticated-credential impact,
with explicit after-remediation regression expectations. All three fresh quality
audits mark that final handoff ready: two passes and one nonblocking warning about
naming the ignored documentation file. All three final projection checks pass;
canonical verdicts have not been hand-edited. This regenerated text audit is not
a new source-security run.
The current catalog contains 38 Kotlin rules and 355 built-in rules. Issuance,
lifecycle policy, Nimbus/JJWT and broader resolver/helper effects remain open;
Auth0 syntax recognition does not close general JWT parity.

The hostname-default follow-up adds exact canonical static global TLS setters
and bounded containing-function context. The SDK contract distinguishes
construction-time HttpsURLConnection inheritance from existing instances and
explicit instance overrides; SSLContext defaults do not automatically replace
cached client factories. Four original hostname helpers produce thirteen
admitted review boundaries: nine global setters and four lazy URL constructors.
Eight connection, four restoration and one peer-counter assertions pass against
one owned HTTPS service with a trusted localhost certificate. The permissive
inherited verifier accepts a hostname mismatch; restoration before construction,
a preexisting rejecting instance and a subsequent instance override reject it.
All four helpers restore the prior global verifier. Runtime controls use fresh
connections with HTTP keep-alive disabled, so reused-connection behavior is not
established. There is no mapped request-input producer; integer fixture ports
identify the owned service.

The initial independent run matches 12/13 labels for each model: all three
incorrectly attribute the earlier permissive installation to the final
restoration anchor. Terra's quality audit rejects that mismatched narrative;
Luna and Sol accept it with warnings. That run is retained as a failed gate.
A focused integration check also caught missing context for single-call finally
blocks: an overlapping statement range was selected before the call node. The
lookup now requires an exact call-expression range, and both TLS integration
checks pass. Exact-anchor guidance distinguishes the installed policy at this
setter from an earlier different setter's effect; a fresh thirteen-boundary
model and quality repeat verified all nine function facts before model review.
Terra and Sol match 13/13 labels; Luna still misattributes the restoration anchor
and matches 12/13. Only two of three quality audits mark that repeat ready, so it
also remains a failed gate. A separate exact-setter fact now records the actual
policy argument and location without borrowing neighboring callbacks. The
restoration regression requires that its matched policy is `saved` and its exact
fact contains no accept-all callback. The rebuilt export verifies all nine exact
policy facts before fresh model review. That third complete run matches 13/13
labels across all three models; all three quality audits are engineer-ready and
all three projection checks pass. Nonblocking warnings concern the broad TLS
title/verification text, explicit fixture labeling and the sample-distribution
warning. Narrative repairs now derive the exact SDK method from the matched AST
range and clarify that dominant decisions alone do not establish model error.
All three regenerated hostname handoffs pass fresh quality audits outright and
all three projection checks pass. The passing security decisions remain
unchanged; these text-only audits are not new security runs. A regression verifies
that neighboring calls and a misleading argument name cannot change the exact
SDK-method presentation.
The engine unit suite passes 168 tests, all 22 Kotlin integration
tests and catalog validation pass, and strict core/engine lint passes. The
catalog contains 36 Kotlin rules and 353 built-in rules.
Four additional original factory-default helpers produce sixteen boundaries:
four SSLContext initializations, eight global setters and four lazy URL
constructors. Eight connection assertions, sixteen global-restoration assertions
and two peer counters pass against two owned HTTPS services with distinct
localhost certificates. New inherited socket factories and explicitly consumed
SSLContext defaults accept the untrusted certificate when their server check is
empty; preexisting connections and captured validating factories reject it.
Hostname verification remains enabled. Focused TLS/Kotlin/catalog tests and
strict lint pass. Fresh Luna, Terra and Sol reviews match all sixteen predefined
source labels. Initial quality audits mark all three reports ready. Regeneration
for the general narrative repairs produces two ready audits and one rejected
handoff: the isolated response/rejection counts are not mapped to operations.
Both rounds are retained. The next regeneration explicitly records both peers'
outcomes for each original helper. All three fresh quality audits mark that mapped
handoff ready: two passes and one nonblocking warning result about grouping
related anchors and distinguishing explicit default-context consumption from
construction-time inheritance. Canonical decisions remain unchanged. All three
final mapped JSON/Markdown/SARIF projection checks pass. These regenerated report
audits do not constitute new security runs.
Implicit factory-cache effects, concurrency, unrelated client uptake and JWT
remain open; recognizing their setter syntax alone does not close those gates.

The current TLS trust follow-up adds canonical SSLContext initialization review
boundaries and exact containing-function context. Ten initialization anchors in
eight original functions include provider defaults, actual provider validation,
unused contexts, reinitialization, manager ordering and swallowed certificate
errors. Sixteen isolated connection assertions and two peer-counter assertions
pass against two owned HTTPS services with distinct localhost certificates:
eight trusted responses, three untrusted responses and five certificate-chain
rejections. Hostname verification remains enabled.

The first fresh independent run matches 9/10 labels for Luna and 10/10 for
Terra and Sol. Luna incorrectly dismisses the permissive-first manager because
it considers selection unresolved. All three report-quality audits accept their
respective bounded handoffs, but this does not repair that security disagreement.
The failed security run is retained. Review material now includes the documented
first-manager contract and standard JDK17 SunJSSE X509 manager selection. A fresh
complete ten-anchor repeat matches all ten labels across Luna, Terra and Sol.
All three fresh quality audits mark the reports engineer-ready: one pass and
two passes with nonblocking instance-label, remediation-specificity and repeated
dismissal warnings. All three JSON/Markdown/SARIF projection checks pass.
No canonical decisions were hand-edited.
The affected engine suite passes 166 tests, all 22 Kotlin integration tests and
catalog validation pass, and strict core/engine lint passes. Global TLS defaults,
JWT, wider client bindings and the final complete-corpus/workspace gates remain
open. The current catalog contains 35 Kotlin rules and 352 built-in rules.

The current unpushed changes add trailing-lambda hostname verifier recognition,
same-stream deserialization policy context, JDK/OkHttp client factories,
ProcessBuilder fluent command capture, exact OkHttp execution context, Ktor
client construction and bounded request-builder review context. Kotlin
conventional platform test source sets are classified separately from production
source sets; custom Gradle layouts remain unresolved.

Fresh independent Luna, Terra and Sol reviews agree with the predefined source
oracle on 11 object/TLS cases, eight reviewable client/process cases, and four
Ktor builder cases. A ninth client/process source case is excluded by the
existing fixed-executable policy and remains a negative source control.
The quality skill accepts all 12 resulting reports; canonical decisions,
counts and SARIF locations reconcile in all 12 report projections.
Earlier model disagreements and failed quality audits remain in the private
evaluation evidence; they are not included as passing final reviews.

Direct isolated controls pass seven object policy assertions, four TLS
assertions, eight client/process assertions and four Ktor builder assertions.
These controls use original fixtures and owned resources. They do not establish
coverage of the broader open categories above. In particular, hostname policy
does not validate general trust-manager policy, and request-builder source
context does not prove native final-URL propagation.

Scope-lambda source context passes five predefined source cases across all three
independent models and all three quality audits. Its facts state lexical
candidate identity, rather than compiler identity; application member shadowing
is excluded for known non-string receiver types. The new scope fixture compiles
with Kotlin 2.4.10/JDK 17, and the Kotlin integration suite passes 22 tests.
All eight canonical Ktor client request verbs retain builder context in a
separate integration check covering 16 request shapes plus an excluded foreign
member. Builder replacements do not acquire native initial-URL paths.
Final complete-corpus agreement, final report audits and the workspace release
sweep remain pending after all implementation gates close.

The File-overload follow-up adds charset-bearing reads/writes and append
operations. Eight direct-call assertions pass against owned temporary files.
A focused integration check caught incorrect content capture for reordered named
arguments; that failure is retained. The capture now resolves the Kotlin
parameter value by name, while Java named arguments remain excluded. The
corrected fixture has six admitted review cases, including fixed-write and
allowlisted-read negative controls. All three fresh models match six of six
labels. After fixing append impact wording and a stale evaluation heading, all
three fresh quality audits accept the regenerated reports (two passes and one
non-blocking presentation warning). Earlier audits and incorrect captures are
retained as historical evidence. A regression verifies impact selection uses
the exact matched operation, excluding neighboring calls and string literals.
The engine unit suite now passes 159 tests; strict lint and final workspace
checks remain separate gates.

The JDBC follow-up validates constructed JdbcTemplate receivers, canonical
pooled/XA factories and three/four-argument preparation. Eight original source
cases match Luna, Terra and Sol after clarifying the same-statement execution
invariant; the earlier unused-preparation disagreement is retained. Seventeen
owned-H2 assertions include an instrumented connection confirming one unused
prepare call and zero execute calls. The original factory fixture is preserved;
new controls live in `kotlin-jdbc-policy-factories`.

One Luna narrative called a Statement operation JdbcTemplate. A fresh independent
response repaired that case, preserving all decisions; seven other Luna
responses were retained. Three fresh quality auditors accept that repaired
handoff, and the existing Terra/Sol handoffs pass. All three canonical report
sets reconcile in projection checks. This targeted narrative repair is not
counted as a fresh full-corpus repeat.

Exposed v1 JDBC raw SQL now has an embedded rule and bounded transaction
ownership. Six original compiled source cases match all three independent
models; twelve owned-H2 direct-call assertions pass against Exposed 1.5.0.
All three regenerated handoffs pass quality review and projection checks.
Five lambda cases remain source reviews and the declared receiver admits one
local scalar path. Legacy Exposed, R2DBC, statement building and wider JDBC
effects remain open; this evidence does not close the entire persistence gate.

The preceding persistence checkpoint passes 160 engine unit tests, 22 Kotlin integration tests,
the JDBC/Exposed focused integration tests, embedded-catalog validation and strict
engine lint. Rule inventory is 30 Kotlin rules and 347 globally, with each
Kotlin rule exercised by the original fixture selections including Exposed.
These are affected checks at that checkpoint, not a completed workspace release sweep.

The next local follow-up adds declared Spring JDBC interfaces, canonical
NamedParameterJdbcTemplate constructors and execution callbacks. Six original
source cases match all three independent models; twelve owned-H2 assertions
distinguish interpolation from map and SqlParameterSource binding. Four callable
statement cases also match all three models; ten owned-H2 assertions include
one unused preparation, one close and zero executions for the lazy case only.
Fresh quality audits accept all six regenerated report sets without warnings,
and their canonical counts, decisions and SARIF locations reconcile.

Those audits exposed a Markdown presentation bug: underscores inside code spans
were escaped as prose. The renderer now preserves code identifiers while escaping
surrounding prose. Core tests and strict core/engine lint passed before the WebFlux
follow-up; this correction does not change canonical security decisions.

WebFlux functional request inventory now includes exact ServerRequest query,
path and String-body sources. Optional/Mono consumers receive bounded containing
function context instead of claimed native reactive flow. Ten isolated checks
pass through an actual Spring functional router against owned loopback marker
services at the first checkpoint. An additional three owned-loopback assertions
demonstrate that user-info syntax in the unvalidated path String changes the
parsed host despite its literal loopback prefix. The complete runtime fixture
passes thirteen assertions. The earlier source-oracle rationale and quality
warnings incorrectly narrowed this authority interpolation to port selection;
those historical artifacts are retained and fresh reviews use corrected source
semantics. The new fixture exercises five URL review boundaries; focused
integration and catalog checks pass, bringing the embedded inventory to 33 Kotlin
rules and 350 globally. All three fresh models match five of five predefined
labels at the corrected authority checkpoint. Regenerated handoffs preserve
their canonical decisions; fresh quality audits accept all three (one pass,
two nonblocking warnings about shared titles and per-instance follow-up).
All three handoffs reconcile canonical counts, decisions and SARIF locations.
The engine suite passes 161 unit tests and strict core/engine lint; the later
remediation-only change also builds the CLI. Final workspace checks await
implementation closure. WebClient, DTO decoding, reactive response surfaces and access
policy coverage remain open, along with the other gates above.

The next local WebClient follow-up adds URI-spec review boundaries with
enumerated client factories/builders and HTTP-method spec aliases. String,
absolute URI, template/map and URI-builder syntax are admitted; numeric URI
lookalikes and foreign clients are excluded. A regression initially exposed
missing declared generic URI-spec identity; the corrected resolver recognizes
the canonical outer spec type without claiming generic overload dispatch.

Ten original URI boundaries retain exact containing-function context for
subscription and same-spec replacement. A bounded direct same-file helper
candidate supplies the explicit non-network ExchangeFunction body; overloaded,
shadowed and unrelated helper calls are excluded. Twenty-one SDK assertions
pass: six instrumented request exchanges, four actual HTTP exchanges to an
owned loopback marker service, unused-publisher zero-execution checks, encoded
path authority preservation, replacement and non-network exchange controls.
No external-host access or deployed Spring dispatch is claimed. All three fresh
models match ten of ten predefined source labels (five issue and five negative
boundaries), including the non-network exchange and both replaced URI setters.
All three regenerated handoffs are engineer-ready (one pass and two nonblocking
warnings about shared instance labels and repeated narrative). Canonical
decisions, counts and SARIF locations reconcile in all three projections.
The report's generic scope text now distinguishes isolated checks from deployed
activation and external exploitation; core tests and strict core/engine lint
pass after that correction. The engine suite passes 163 unit tests; 22 native
Kotlin tests, focused WebFlux/WebClient tests and catalog checks pass. Embedded
inventory is now 34 Kotlin rules and 351 globally. Default-request,
filter and custom URI-factory effects remain wider obligations.

The subsequent policy fixture adds nine original helper boundaries for
default-request timing, forwarded and discarded filter replacements, ordered
rewrites, removed filters and overload-specific factory overrides. Twenty-one
assertions pass through eighteen actual HTTP exchanges to two owned loopback
marker services. One initial Kotlin override used the wrong nullable vararg
signature; that compiler failure is retained and the corrected fixture compiles.

The initial independent models matched eight/nine, nine/nine and nine/nine;
Luna incorrectly treated an expand override as protection for String uri.
That disagreement and its reports remain historical. Anchor-specific argument
representation facts now state the verified default SDK entry point, distinguishing
String uriString/build from direct URI installation and URI-function callbacks;
they do not claim compiler dispatch or generalized callback effects. Fresh
complete nine-case agreement and quality audits are pending.

Builder ownership also admits the remaining enumerated Builder entry points,
including clone/apply, strategy and version configuration, default status handlers
and empty-value header/cookie varargs. Nine additional assertions cover eight
instrumented exchanges without network I/O. An initial default-version test failed
before exchange because no version inserter was configured; the corrected control
supplies the required inserter. This SDK precondition is retained as a separate
execution lesson, not counted as a successful outbound request.

After adding overload facts, all three fresh models match nine of nine policy
labels. The quality skill accepts the three reports, but one audit identifies
misleading initial-URI metadata for a later filter rewrite. The canonical
WebClient finding now names the captured literal field initial_uri_argument
and labels the matched URI setter as initial syntax. Owned ClientRequest URL
mutations receive separate source-context locations; candidate mutations do
not assert forwarding or final-destination proof. Raw matched evidence remains
unchanged. The affected regression, engine suite and strict lint pass before
the last metadata test; final regenerated policy agreement and handoffs are
pending at this checkpoint. Earlier passing audits and the metadata warning
remain retained evidence, not a substitute for the corrected handoff.

The next fresh metadata run matches eight/nine, nine/nine and nine/nine; Luna
misses the shown rewrite-after-approval because it treats direct forwarding as
unresolved. The truth labels remain unchanged. A separate exact AST argument
fact now records when a constructed request containing the mutation is passed
directly to an enclosing exchange call. That relationship is source evidence,
not compiler dispatch or deployed/runtime proof. A wrong-request regression
confirms that constructing an ignored replacement produces no such forwarding
fact. The final complete policy rerun remains pending; this second model miss
is retained and does not close the release gate.

A diagnostic rerun exported stale requests because Windows blocked replacement
of the scanner executable while it was in use. Its missing forwarding fact was
detected before acceptance; that evaluation was stopped and retained. The CLI
was rebuilt successfully after its processes stopped, and the next exported
request was checked for the new forwarding fact before fresh model calls.
Affected checks now pass 165 engine unit tests, the Kotlin integration controls
and strict core/engine lint. The final verified-export model and quality run is
in progress; no further push has occurred.

The verified-export rerun now matches nine of nine predefined policy labels
across all three models. All three final report sets are engineer-ready (one
pass and two nonblocking warnings about instance subtitles and repeated shared
guidance); the initial-versus-effective metadata warning is resolved. All
three canonical JSON/Markdown/SARIF projections reconcile. Earlier SDK misses,
compiler/runtime failures and the stopped stale-binary evaluation are retained.
These bounded policy controls do not close general compiler callback effects,
external client configuration, unrelated framework APIs or platform coverage.

### Local Auth0 lifetime follow-up (gate still pending)

Seven original helpers add fourteen issuance/verification review boundaries.
Twenty-eight isolated SDK assertions pass: four credentials with missing or
replaced expiry remain accepted after ten minutes despite a five-minute contract;
two effective expiry controls reject them, and an independently bounded consumer
rejects late replay and a forged owned signing key without an exp claim.
The first fresh model run matches Luna 12/14, Terra 14/14 and Sol 13/14. Its quality
checks mark only one report ready. The required lifetime was outside the supplied
function context. Making that existing contract explicit inside each helper
improves Sol to 14/14, while Luna remains 12/14 and only two reports are ready.
Both failed rounds remain recorded. No canonical verdicts are manually changed.

The issuance invariant is now narrowed to lifetime enforcement under CWE-613;
shared report wording no longer implies an unestablished signing-policy defect.
Generic guidance recognizes an explicitly supplied credential-lifetime contract
without demanding deployed compromise. These latest changes still require a
verified executable, a fresh complete fourteen-boundary model run, report-quality
checks and projection reconciliation. The final test build encountered a Windows
executable lock from an overlapping earlier filtered run; its failed log is
retained and the rebuild will run sequentially. All changes remain local.
The prior eight-request JWT equivalence check describes its historical checkpoint:
the newly expanded lifecycle context changes those request facts, so it does not
establish equivalence at the current source revision. Broader JWT SDKs, lifecycle
and other release gates remain open.

### Verified lifetime checkpoint

After terminal completion of the earlier filtered run, the precise final targets
pass: 169 engine unit tests, both JWT integration tests and catalog validation.
Strict core/engine lint and the rebuilt CLI pass. The narrowed issuance invariant
reviews lifetime under CWE-613 and explicitly recognizes source-declared lifetime
requirements. Fresh Luna/Terra/Sol each match all 14 predefined labels. All three
quality-skill audits are engineer-ready (one pass, two nonblocking warnings), and
all three JSON/SARIF/Markdown projection checks pass. Earlier failed rounds and
the Windows executable-lock build are retained. The unrelated zero-match test
launches in the earlier filtered run were cancelled after the requested ownership
test passed; that log is not a complete integration-suite result.

The final source snapshot includes 242 selected review boundaries: 221 in the
main release corpus and 21 existing XML/object/hostname controls, including two
new validating TLS-context observations in the owned probe. Predefined source
labels are frozen before changed-input reviews. Exact-byte-identical request
responses are reused only with unchanged fingerprints and complete validation;
changed inputs receive fresh independent Luna/Terra review. The current public
oracle records 219 original-fixture labels and the fixed-command exclusion.
Pinned application cases remain separate. Final broad model agreement, quality
handoffs and workspace checks are still pending. A concurrent workspace linker
run exhausted memory; its failed log is retained and the retry uses two build
jobs. No push has occurred.

### Current selected-corpus gates

The corrected current inventory matches all 242 source labels for both primary
models. All 65 current reports are quality-skill ready and pass projection
reconciliation. Historical failures remain in their original artifacts. Full
workspace completion, the final changed JWT fixture check and the broader coverage
gate audit remain pending; these results do not close unsupported capability
categories or authorize a push. See kotlin-quality.md for the current checkpoint.

### Peer-profile audit

The current Java/Kotlin rule-inventory audit identifies uploads, cookie flags,
method authorization and dynamic script evaluation as concrete remaining
counterpart gaps. An absent control-only capability ID is not automatically a
missing feature: path operations, SQL binding, process arguments, parser filters
and URI policy already have bounded Kotlin facts and executable controls.
The peer-profile review must distinguish those facts from genuinely absent
surfaces. Compiler-backed analysis and all-platform APIs remain unsupported;
selected-case quality does not justify claiming them implemented. The remaining
work should target the established Java counterpart surfaces, not an expanding
list of unrelated SDK/platform features. No push is authorized by the passing
selected corpus while required counterpart gaps remain.

### Servlet cookie progress

The bounded Servlet cookie counterpart is verified: 16 predefined labels match
all three fresh independent models, 23 SDK/response-spy assertions pass, three
quality audits are ready and three projection checks pass. Current catalog: 41
Kotlin/358 total rules. Uploads, method authorization and script evaluation remain
concrete peer gaps; broad baseline equivalence and final workspace checks remain
open. The pre-cookie workspace tests pass 1008/41 ignored; its lint is superseded
by corrected affected lint because it observed a temporary cookie compile error.

### Remaining counterpart verification

The four concrete Java counterpart categories now have bounded Kotlin inventory:
Servlet cookies, Spring method-authorization annotations, Servlet multipart APIs
and ScriptEngine evaluation. Authorization is context-only and has no standalone
vulnerability verdict. Multipart/script source labels match all three models;
their corrected report-quality handoff and final current-source checks are pending.
Unsupported categories in the gate table remain open; these selected controls do
not establish compiler-backed analysis or Android/JS/Native support.
