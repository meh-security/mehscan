# Value and Comprehensive admission policy

Use when choosing repository scope or reconsidering a noisy review family.
The scanner assigns initial queues; source research can change priority.
This policy is maintained from real application snippets and regression controls.
It describes intended membership and known implementation gaps below; a current
queue entry is not proof that it deserves its assigned priority.

## Two review queues

| Queue | Include when | Rationale |
| --- | --- | --- |
| **Value** | A shown unsafe construction, meaningful protection bypass, consequential input/effect relationship, dangerous security configuration, or specific high-value lead makes investigation worthwhile. A clearly justified fix can qualify before exposure is proved. | Spend the first review budget on likely useful findings and conclusions. Useful medium issues can qualify; default severity alone does not decide. |
| **Comprehensive** | A plausible medium-or-higher consequence has a concrete unresolved edge: a producer, writer, interpreter/control, selected resource, actor or sensitive effect. State the next fact that could settle it. | Research credible relationships whose evidence is weaker or whose expected impact is lower. Includes Value. |
| **Neither** | Ordinary API use, setup, syntax, positive controls, duplicates or weak occurrences lack a practical consequence. Requiring several hypothetical conditions to invent a boundary is insufficient. | Avoid mandatory investigations of normal application behavior. An exclusion is not an AI safe verdict. |

Unknown attacker control does not automatically discard a dangerous construction.
An unknown caller does not automatically make every filesystem or output API
worth investigating either. Judge the concrete operation and likely boundary.
Keep conditional activation/exposure in the verdict and confidence.

## Conditions by security family

| Family | Value | Comprehensive-only research | Exclude ordinary work |
| --- | --- | --- | --- |
| SQL, commands and code interpreters | Variable-built interpreter grammar, a dangerous execution target, or an actual input/execution relationship. Inspect wrappers/callers; a raw API alone is not a confirmed injection. | A consequential interpreter/loader relationship whose input, authority or protection remains unresolved. | Fixed grammar with data binding; unused builders; parsing/compilation without execution, unless another sensitive effect is shown. |
| HTML and templates | Shown raw lower-trust output, an encoding/autoescape bypass, unsafe interpreted construction, or a promising writer-to-renderer relationship. Check the actual context. | Bound stored/helper producers, active script/style/event/unquoted contexts and consequential raw rendering with a specific writer/control gap. | Ordinary escaped output; numeric-only output with a supported complete proof; unbound generic output without an actual producer/context lead. A transport writer is not automatically browser HTML. |
| Files, uploads and archives | Attacker-selected content reads, overwrite/deletion, upload/archive entry paths, writable-code paths or a useful containment gap. | Real content/destructive effects with unresolved resource authority; shared roots/producers whose independent effects still need checks. | Directory setup, simple names-only listing, existence/stat checks and closed path selectors. A fixed selector closes traversal only, not authorization or writable content. |
| Network destinations | Server/privileged fetch with a consequential destination producer, executable download or credential/data disclosure. | A credible destination/authority gap with an actual sensitive effect. | URI construction without dispatch; ordinary browser GETs without a separate privileged or sensitive consequence. Unknown URLs do not turn client requests into server SSRF. |
| Authorization, credentials and state | An actual sensitive action with an ownership, policy, credential-lifecycle, authoritative-value or integrity question. | A concrete medium-impact state boundary or unresolved protection attachment. | Bare route names, handler attributes and policy words without a sensitive action; absence of a local guard alone is not a bypass. |
| Configuration and cryptography | A dangerous effective option or a security-purpose weakness: disabled certificate validation, unsafe polymorphism, weak password/integrity handling. | Concrete medium-impact cookie/CORS/CSRF/redirect/logging relationships; promote a consequential chain. | Positive secure settings, nonsecurity hashes, expiry metadata, public-route names, generic listener/deployment speculation and ordinary log formatting. |
| Native memory and unsafe APIs | A represented size/lifetime/ownership/format relationship or concrete dangerous use. | A plausible memory/resource effect with a named unresolved operand or ownership edge. | The presence of `unsafe`, interop or a buffer API alone; unrelated API inventories. |
| Deserialization | Executable/object-instantiating behavior with an unsafe type/policy/input relationship. | A concrete type/policy/resource question capable of medium impact. | Ordinary JSON/Serde/data decoding. Input co-location alone does not establish gadget execution or significant denial of service. |

Co-occurrence is navigation, not propagation. It may retain research when the
effect is worthwhile; it does not override an ordinary/low-effect exclusion.
Do not require theoretical format, environment or plugin attacks to keep a case.
Reopen when source or repository knowledge supplies the missing practical edge.

A decision-critical producer question does not itself promote an ordinary
medium-impact redirect into Value. Keep its exact Comprehensive ID and origin
question; promote when evidence shows a consequential credential/effect chain.

## Ordinary patterns excluded from both queues

These belong in **Neither**, rather than becoming permanent Comprehensive work.
An ordinary occurrence is not an AI safe verdict for every possible caller.

| Pattern | Why exclude it | Keep review work when |
| --- | --- | --- |
| Intrinsic `a`/`area` href merely forwards an unchanged parameter, without a represented input or producer relationship | Normal link presentation does not supply an unsafe construction or a concrete lower-trust writer to investigate. Unknown callers alone are insufficient. | URL construction/default/reassignment, input relationships, bound incoming arguments/origins, resource contexts or a consequential writer supply a real lead. |
| DOM-bound GET/HEAD in an explicit browser context, without other options or an input relationship | The operation is an ordinary client request and supplies no server-side SSRF question. | Credentials/headers/body, mutations, unknown options, input relationships, privileged effects or Node/SSR/unknown runtime make the destination consequential. |
| Django-style non-authority lookup used exclusively as a predicate to refine a supplied queryset | Ordinary query construction should not get a separate verdict just for using a record key, when there is no represented protected-resource selection or sensitive consumer. | Request-selected owner/tenant/account boundaries, selected fields/records escaping, metadata in errors, wrappers/aliases, non-ID projections or terminal read/destructive consumers supply a practical edge. |
| Owned trusted-markup call containing only fixed whitespace/nonbreaking-space padding | Variable repetition changes padding quantity, without a dynamic HTML producer or interpreted construction. | Dynamic text, formatting, interpolation, escaped bytes or other markup remain in the operand. |

Directory setup, names-only listing, positive security controls and effect-free
builders follow the same principle in the family table above. Keep supporting
extraction only when an admitted relationship or compiler fact actually consumes
it; text search does not require ordinary review IDs. Broader timestamp,
routing-metadata or parent-inheritance exclusions need consumer facts, not method
or field-name allowlists copied from one application's verdicts.

Queryset refinement alone does not prove authorization. For example, a request
choosing a tenant and returning `qs.filter(tenant=tenant)` can select protected
resources if `qs` was not scoped to the actor. Keep that concrete authority
question; do not classify it as ordinary just because evaluation happens later.
The current Python exclusion checks local uses and terminal consumers, but does
not establish caller permissions or fully propagate request/authority facts.
Treat guarding those connected selections as an implementation gap, not as a
safe verdict or a reason to retain every ordinary query-builder occurrence.

## Language and backend differences

The impact test is shared. Differences below concern facts the scanner can
establish, not different standards for what constitutes a useful issue.

| Language | Practical facts and current treatment | Remaining limits |
| --- | --- | --- |
| **C / C++** | Keep represented buffer extent, allocation size, arithmetic, format, lifetime and ownership relationships. Unlinked native API inventories are excluded. A dangerous sink need not have an HTTP source. | No whole-program ownership or full CFG. Source-visible aliases, exceptional paths and platform behavior can need research. |
| **C#** | Optional Roslyn supplies actual SDK identity, scalar/Guid/date normalization, closed selectors, helper/property/argument origins and actual HTTP dispatch. Shared filesystem/destination questions defer repetitions, preserving exact Comprehensive IDs. URI setters and directory setup are context. | Facts require a bound compiler context; missing facts do not prove custom calls safe. A record key is not the path string stored in its selected record. Check response destinations before assigning HTML; optional backend facts are not required for the base workflow. |
| **Java** | Inspect query text separately from prepared-statement bindings. Actual `send` is an effect; an HTTP builder alone is context. Ordinary Jackson reading is excluded unless project-visible unsafe polymorphic/default-typing policy warrants research. | A policy elsewhere is a lead until tied to the mapper. Framework guards, wrappers and annotations still need exact binding. |
| **Kotlin** | Apply the same JVM interpreter, mapper and filesystem distinctions. Kotlin unsafe Jackson policy syntax can retain research even without a dedicated policy emitter. Owned ordinary directory setup is excluded. | Java/Kotlin API interoperability does not establish identical framework coverage. Do not infer absent policy from a missing Java-only detector. |
| **JavaScript / TypeScript / TSX** | Preserve raw DOM/trusted HTML and real process/filesystem effects. Proven build/vendor/generated ownership can remove ordinary application Value work. Proven fixed `pg` query objects with separate values leave both queues for injection. Owned `js-yaml` v4 default data schemas are ordinary decoding; custom/unknown policies retain their question. Standalone DOM GET/HEAD in an explicit browser context leaves both queues when options show no sensitive effect. Unconnected intrinsic `a`/`area` hrefs merely forwarding an unchanged parameter with no observed producer leave both queues. Custom component href props are not direct browser sinks. Optional TypeScript facts improve identity, producers and literal selectors. | Ordinary-link exclusion is a scope decision, not scheme/authority proof. Constructed, defaulted or reassigned operands, observed input relationships or producer facts, resource hrefs and raw HTML remain active. Credentials, request mutations, unknown options and Node/SSR/unknown runtime prevent the browser-request cut. Template/custom renderer controls and alternate writers need source checks. |
| **Python** | Executable pickle/unsafe loader behavior differs from normal data parsing. Supported autoescaped Django responses close the exact output property. Owned trusted-markup calls containing only fixed whitespace/`&nbsp;` repetition do not create an XSS review. A Django-style lookup assigned locally and used exclusively as a keyword filter predicate on a supplied queryset does not create an authorization sink. Marshal inventory is excluded without a connection and is otherwise research, not automatic code execution. `compile` alone is context. | Queryset narrowing does not establish caller authorization. Returning records, reading fields, errors, mutations, aliases, wrappers or other consumers prevent that cut. Fixed padding does not close arbitrary `mark_safe`, formatting or dynamic text. HTML attribute escaping does not establish safe attribute names/event handlers/URL semantics. Shell behavior depends on actual options/interpreter/platform. Custom serializers, autoescape settings and dynamic template inputs need exact evidence. |
| **PHP** | Value keeps shown raw request-to-output/code-selection constructs. Comprehensive retains represented flows/co-occurrences, bound local stored/helper reads, runtime-selected loaders, matched write/load targets and active interpreted output contexts. Ordinary unbound output/constant-shaped includes leave both queues. Complete native numeric output closes its own output property. | Producer navigation is bounded and mostly same-file/native-reader based. Framework and cross-file property/writer chains can be missed. Known important renderers/loaders may warrant a category sweep; queue exhaustion is not complete XSS/include coverage. |
| **Go** | Use owned API identities and concrete effects. Ordinary mkdir and effect-free resource filters are excluded. Unconnected gob inventory is excluded; connected gob is research unless a real impact qualifies it. | No optional Go compiler backend is assumed. Imports/helpers and data decoding do not by themselves prove destination authority or significant impact. |
| **Rust** | Keep concrete command/filesystem/trusted-output and represented unsafe effects. Ordinary directory setup/listing and Serde data decoding are excluded. Syntax-only unsafe/interop rules were retired. | Direct process launch is not shell injection. CLI command authority and custom data consumers may need research. No Rust compiler backend or full borrow/CFG analysis is assumed. |

Ordinary C#/Java/Node/Go directory cuts require owned API identity, not a suffix
match. PHP rejects native-function lookalikes. Missing ownership can preserve an
uncertain candidate; investigate repeated ambiguity before widening exclusions.

Several families still default too broadly to Value when no deferral applies,
especially unknown filesystem selectors, generic response output and browser
operations. Treat those assignments as implementation gaps to test, not reasons
to weaken this policy. Changes should follow actual snippets and protective
controls rather than a language-wide blanket cut.

## Database exclusions and remaining cleanup

Judge **query grammar** and **resource authority** separately. Closing injection
does not prove access rights; a possible access question does not reopen fixed
SQL as injection. Do not create an authorization review for every ordinary query.

| Pattern | Intended queue / reason | Evidence that retains work |
| --- | --- | --- |
| Fixed SQL, including a complete immutable query object with separate values | Neither for injection: runtime values remain data. Request values in the binding array are ordinary, not a reason for another SQL verdict. | Replaced query methods, object mutation/escape/overrides, unknown driver identity, dynamic SQL text or identifiers. Independently selected protected records keep their own authority question. |
| Query text or document assembled without a consuming operation | Supporting context, not a standalone injection verdict. Attach useful construction/binding facts to the consumer. | An observed executable consumer, escaped query handle with a concrete execution lead, or unsafe construction used by a real application operation. Missing local execution facts alone do not prove unused code. |
| SDK equality predicates, fixed operators and separately bound expression values | Neither for grammar when the owned API keeps these values in data positions. | Raw operator-capable documents, computed/spread keys, executable predicates, raw expression text or unknown construction. A fixed key with `req.body.id` is not proof of a scalar value. |
| Exact authenticated owner predicate that survives through the selected operation | Neither for that ownership property once the control is established. Keep its supporting control fact. | Alternate callers/routes, missing authentication, predicate overrides, later selector writes or a different sensitive property/effect. A column named `owner` or an `owner_scoped` hint alone is insufficient. |
| Reload of an already selected resource during an authorized operation | Review the operation's authority once; an identity-preserving reload is not a new actor/resource boundary. | A changed key, independent selected instance, exposed fields, broader query scope or an effect outside the inspected permission contract. |
| Fixed/configuration-owned identifiers quoted by an owned dialect | Neither for injection after checking the complete identifier construction and quoting contract. | Untrusted names reaching raw identifiers, grammar-bearing fragments, unverified helper behavior or a runtime SQL template whose values are rendered into syntax. Parameter binding does not cover identifiers. |

Implemented closures: complete local `pg` fixed-text objects with separate
binding arrays leave both queues, including request-bound data. Unchanged local
C/C++ char pointers or `auto` aliases initialized solely by literal strings also
leave both queues. Prior uses, writes, escapes, globals, conditional declarations
and uncertain initializers veto the native cut. This is not general C/C++
constant folding; source/origin facts remain available.

Node owner hints now reject duplicate, spread, computed and escaped keys.
They remain hints: middleware text alone does not establish every control path
or intervening write, so no blanket owner-flag cut is added. Python's exclusive
queryset narrowing retains directly observed request selectors and bounded local
aliases; unknown cross-file callers still require separate authority research.
Java/Kotlin MongoDB document construction and C# BSON/JSON filter construction
are supporting facts, not injection sinks. JS/TS/TSX DynamoDB Query/Scan/PartiQL
command construction and PHP MongoDB driver `Query` construction follow the same
rule. Unused parser/constructor rows leave
both queues and the scan evidence. Inline construction and bounded local
uses attach their origin to the actual database operation; used construction
rows remain context without their own review ID. Opaque helper consumers remain
reviewable: missing construction facts do not establish safe operators or input
types. This attachment is file-local and does not follow arbitrary helpers or
cross-file producers. Raw SQL constructors and other query-builder families
still need separate consumer coverage checks before the same cleanup.

JS/TS/TSX reviews anchor to `send` on an owned SDK v3 DynamoDB client with an
observed query-command producer. Recognize inline commands, local bindings and a
single directly returned constructor from an unshadowed local helper. One direct
local alias preserves a lead without transferring fixed facts. Helper
input binding remains a question. Reused, mutated or escaped local commands keep
the unresolved command operand; do not copy fixed expression facts through an
uncertain use. Computed/spread/duplicate/escaped object keys keep the whole input.
Unrelated AWS commands do not become NoSQL injection reviews. External helper
producers, longer alias chains, properties and CommonJS v3 construction are beyond
this bounded producer resolution; absence of a review does not certify them.
Source/category research can still inspect them. Existing SDK v2 query/scan
operations remain separate, with expression syntax distinct from bound values.

PHP reviews anchor to `executeQuery` on an owned MongoDB `Manager`/`Server`.
Inline/local query objects attach their filter; opaque query/helper operands
remain reviewable. Preserve identity gates for imports, typed receivers,
reassignments and includes, and do not guess named/unpacked argument positions.
Python, Go, Rust and C/C++ NoSQL rules already represent collection/table calls;
there is no standalone document-constructor review to retire in those profiles.
Keep their actual filter/pipeline consumers. This NoSQL slice does not close
operator injection or independently settle resource authority.

Modern EF Core `SqlQuery<T>(FormattableString)` parameterizes interpolation;
legacy EF string overloads and `SqlQueryRaw` differ. The current native emitter
does not reliably separate them. Bind the SDK/overload before excluding the
modern form, rather than transferring safety from the method name alone.

Apply the same distinctions to ADO.NET/Dapper/EF, JDBC/JPA/Hibernate/Exposed,
Node drivers/query builders, DB-API/Django/SQLAlchemy, PDO/mysqli/Laravel,
database/sql/GORM/pgx/sqlx, Rust drivers and native database APIs. Preserve exact
SDK identities, argument roles and language-specific construction facts; do not
transfer one driver's binding, quoting or equality contract to another by name.

## Supporting evidence is not a third review queue

`source`, `symbol` and `references` read repository text. They do not require
ordinary findings to be persisted for search. Do not create extra preparation or
review work merely to make exclusions searchable.

Extract/retain a supporting fact when it serves a concrete consumer: building an
input/producer/effect relationship, resolving an admitted operation's ownership
or control, establishing an exact closure, or validating an existing bound review.
Routine setup may be relevant when it actually establishes an admitted file
operation's root. It does not need its own verdict.

The current inventory cache still contains the full scan and rebuilds selected
jobs/history from it. That is an implementation dependency, not a promise to keep
every ordinary fact forever. Remove unused extraction/context and compact cache
data when consumer checks demonstrate it is unnecessary. Preserve required path
steps, controls, context, admission accounting and optional compiler collection
inputs; do not silently turn a scope exclusion into a safety proof.

## Improve from real applications

For each concentrated or surprising lane, inspect a small mix of Value,
Comprehensive-only and excluded snippets with the normal bundle skill. Include a
useful counterexample, not just examples expected to be ordinary. Record:

- application/revision, exact operation and original queue;
- practical consequence and the one missing fact, if any;
- keep/promote/demote/exclude, with concise rationale;
- whether the repeated fact can be established cheaply by the scanner;
- measured preparation/lookups/reviewer effort when available.

Update this policy and scanner admission together when a repeated pattern is
supported. Preserve a meaningful dangerous control and avoid app-name allowlists.
If the change is still a hypothesis, label it and state which apps/languages have
been checked. Do not extrapolate a small sample to vulnerability recall.
Use existing plans/reports for this evidence; no additional AI routing pass,
per-occurrence classification run or coverage quota is needed.

## Current calibration from real snippets

The first bounded sample used WordPress, Juice Shop and LANCommander. These are
policy decisions for the inspected mechanisms, not application allowlists or a
full recall assessment. The scanner does not yet establish every fact below.

| Observed pattern | Target bucket | Decision-changing fact |
| --- | --- | --- |
| Fixed local startup copy or fixed application-root file read | Neither for traversal/SSRF | Actual owned file API and closed source/destination selectors; retain a separately shown writable-code or disclosure relationship. |
| Private file reader fed by a fixed path table | Neither for traversal | All relevant producers select complete literal paths; a table key is not arbitrary path text. |
| Template helper returns a canonical target checked beneath a canonical root | Neither for traversal | Separator-aware containment covers the returned path and later helpers preserve it. This does not settle template-content trust. |
| Generic file-reader wrapper with no represented caller boundary | Comprehensive shared research at most | Check the actual caller/selector once. Mere existence of `get_contents(file)` is insufficient for Value or a separate review of every caller. Remove the lane if no practical medium-impact boundary emerges. |
| Stream writer of ZIP scripts or serialized manifests | Neither for HTML output | Destination is an archive entry or private memory buffer, not an HTML renderer. Preserve independently shown script-execution effects. Receiver type alone is insufficient: a StreamWriter can wrap a response. |
| Request-selected file content returned without canonical containment | Value | Request path controls the resource; combining/trimming paths does not establish containment. |
| Request text interpolated into executed SQL | Value | The inserted value can change grammar; a length bound does not bind it. |
| Auth-cookie HttpOnly omission / bound arbitrary-origin credentialed CORS | Comprehensive, unless a consequential chain promotes it | Cookie omission can be directly resolved; CORS needs applicable browser credentials and a sensitive response. |
| Runtime plugin/code loader with validation whose selection contract is unresolved | Comprehensive | Verify target validation and selection authority as one implementation question; variable inclusion alone is not a finding. |

Next admission refinements should establish the first five patterns generically,
starting with actual output receivers and closed path producers. Do not add an
extra model pass to classify ordinary operations. Prefer dropping a wrong sink
classification over deferring it to Comprehensive.

### Wagtail calibration (2026-10-09)

A source-only scan of Wagtail at `e5117ba8` produced 154 Value/154 Comprehensive
IDs. The generic changes above produce **103 Value/153 Comprehensive**: 34
redirect questions and 16 unchanged link parameters defer; one fixed-padding
candidate leaves both queues. No compiler backend or application/path allowlist
was used. This first calibration used inventory schema 5; the follow-up below
supersedes its ordinary-link deferral.

Skill review covered 23 selected IDs, not the whole application: two guarded
redirects, fixed padding, a narrowing locale lookup and sixteen links sharing the
same default story URL were resolved as not issues in that scope. Three questions
remain: image attribute-writer authority, RawHTMLBlock publishing authority and
metadata exposure on denied parent selection. Those meaningful questions remain
in Value. The story result does not certify arbitrary overridden URL arguments.

The 62 ORM resource-access IDs remain the largest lane. A scalar selector used
only to narrow an existing queryset can be ordinary; a request-selected record
whose metadata or effect crosses authority is worthwhile. The scanner does not
yet prove the former downstream-use restriction, so this calibration does not
add a blanket `.get()`/record-key exclusion. Next test that effect distinction
against real caller uses, retaining invalid-form and error-response disclosures.

#### Follow-up: ordinary work can leave Comprehensive too

Do not keep an ordinary occurrence solely to assign it a future verdict. Bare
unchanged anchor parameters without a bound producer/input lead and ordinary
DOM GET/HEAD without consequential options leave both queues. Their raw facts
remain evidence for actual consumers; their exclusion does not certify all
possible URL writers or callers. Strengthen source facts or explicitly scope a
category sweep when a project exposes a consequential URL writer.

Exclusive queryset narrowing now avoids extracting an unused ORM authorization
sink. The selected value must have no field read, return, error output, mutation,
alias or wrapped consumer; all uses are filter predicates on supplied querysets.
The filter returns a queryset or reassigns that same parameter. Chained terminal
reads/deletes and other observed terminal uses of that parameter veto the cut.
Projected values must be a single flat `pk`/`id`; other columns remain data
relationships, even if their value is later used as a predicate.
Broader bookkeeping/metadata patterns remain source-review decisions until a
cheap generic fact supports exclusion. Unknown dynamic redirects remain credible
medium-impact research. Do not discard those merely because two inspected
destinations were guarded. Regenerate inventory and ledgers with schema 6.

The follow-up release inventory is **101 Value/135 Comprehensive**, down from
103/153: sixteen ordinary link occurrences and two narrowing-only lookups leave
both queues. All remaining IDs and priorities are unchanged. Eight focused ORM
source reviews resolved seven cases and retained the denied-parent title question;
that is a scoped calibration, not a whole-application vulnerability assessment.
