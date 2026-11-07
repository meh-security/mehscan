use super::*;
mod csharp_boundaries;
mod javascript_boundaries;
mod python_credentials;
mod rust_allocation;
mod rust_archive;
mod rust_buffer_initialization;
mod rust_configuration;
mod rust_credential_renewal;
mod rust_dependencies;
mod rust_extent_arithmetic;
mod rust_memory_boundaries;
mod rust_module_bindings;
mod rust_panic_cleanup;
mod rust_parser_resource;
mod rust_protocol_credentials;
mod rust_raw_memory;
mod rust_receiver_types;
mod rust_shared_state;
mod rust_thread_safety;

const AUTHORIZATION_REVIEW_MARKER_RULE_ID: &str = "framework-authorization-review-marker";
const CREDENTIAL_LIFECYCLE_REVIEW_MARKER_RULE_ID: &str =
    "framework-credential-lifecycle-review-marker";
const MAX_REVIEW_ADMISSION_MARKERS: usize = 48;
const MAX_REVIEW_ADMISSION_MARKERS_PER_FAMILY: usize = 48;
const MAX_REVIEW_ADMISSION_MARKERS_PER_FILE: usize = 8;
const MUTATION_NAME_MARKERS: &[&str] = &[
    "update", "delete", "remove", "destroy", "save", "persist", "assign", "invite", "revoke",
    "cancel", "edit", "create", "approve", "publish", "archive", "enable", "disable", "transfer",
    "reset",
];

struct ServerMutationMarker {
    start_index: usize,
    end_index: usize,
    symbol: String,
    effect: String,
    related_handlers: Vec<String>,
    credential_effect: Option<(std::ops::Range<usize>, &'static str)>,
}

struct ReviewAdmissionDescriptor {
    rule_id: &'static str,
    capability: Capability,
    cwe_candidates: Vec<String>,
    tags: Vec<String>,
}

pub(super) struct OperationReviewContract {
    pub(super) relationship: &'static str,
    pub(super) security_question: &'static str,
    pub(super) title: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperationReviewFamily {
    Authorization,
    CredentialLifecycle,
    ObjectBinding,
    RequestIntegrity,
    FailOpen,
    AuthoritativeValue,
    StateTransition,
    SharedStateLimit,
}

/// Admit bounded review work for sensitive server mutations even when no
/// ordinary sink rule expresses the relevant authorization or credential-
/// lifecycle invariant. A marker never claims that its invariant is violated.
fn server_mutation_review_marker_groups(
    sources: &RepositorySources,
    existing_evidence: &[Evidence],
    scope: Option<&mehscan_core::ImpactScanScope>,
    page: usize,
    include_review_material: bool,
    configurations: &BTreeMap<String, mehscan_core::SourceConfiguration>,
) -> (Vec<ObservationGroup>, mehscan_core::ReviewMarkerAdmission) {
    let selection =
        rust_configuration::Selection::build(sources, configurations, include_review_material);
    let parsed = rust_dependencies::RustSources::build(sources, &selection);
    let models = rust_shared_state::ModelBindings::build(sources, &selection, &parsed);
    let dependencies = rust_dependencies::Dependencies::build(sources, &selection, &parsed);
    let allocation_groups = rust_allocation::groups(sources, scope, &selection, &parsed);
    let mut groups = rust_shared_state::configured_groups_with_context(
        sources,
        existing_evidence,
        scope,
        include_review_material,
        &selection,
        &parsed,
        &models,
    );
    groups.extend(allocation_groups);
    groups.extend(rust_archive::groups(sources, scope, &selection, &parsed));
    groups.extend(rust_protocol_credentials::groups(
        sources, scope, &selection, &parsed,
    ));
    groups.extend(rust_extent_arithmetic::groups(
        sources, scope, &selection, &parsed,
    ));
    groups.extend(rust_parser_resource::groups(
        sources, scope, &selection, &parsed,
    ));
    groups.extend(rust_panic_cleanup::groups(
        sources, scope, &selection, &parsed,
    ));
    groups.extend(rust_thread_safety::groups(
        sources, scope, &selection, &parsed,
    ));
    groups.extend(rust_memory_boundaries::groups(
        sources, scope, &selection, &parsed,
    ));
    groups.extend(rust_credential_renewal::configured_groups_with_context(
        sources,
        existing_evidence,
        scope,
        include_review_material,
        &selection,
        &parsed,
        &models,
    ));
    groups.extend(rust_buffer_initialization::groups(
        sources,
        existing_evidence,
        scope,
        include_review_material,
        &selection,
        &parsed,
    ));
    groups.extend(rust_raw_memory::groups(
        sources,
        scope,
        include_review_material,
        &selection,
        &parsed,
        &dependencies,
    ));
    let mut seen = BTreeSet::new();
    for file in sources.files.values() {
        if selection.excluded_file(&file.path) {
            continue;
        }
        if !include_review_material && is_review_material_path(&file.path) {
            continue;
        }
        if scope.is_some_and(|scope| match scope.result_policy.as_str() {
            "changed_files" | "impact_scope" => !scope
                .included_files
                .iter()
                .any(|item| item.path == file.path),
            "changed_locations" => !scope
                .changed_files
                .iter()
                .any(|item| item.path == file.path),
            _ => false,
        }) {
            continue;
        }
        if file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
            continue;
        }
        let Some(language) = file.language else {
            continue;
        };
        if !matches!(
            language,
            Language::Csharp
                | Language::Java
                | Language::Kotlin
                | Language::Javascript
                | Language::Typescript
                | Language::Tsx
                | Language::Python
                | Language::Php
                | Language::Go
                | Language::Rust
        ) {
            continue;
        }
        let spans = line_spans(&file.source);
        let mut csharp_boundaries = csharp_boundaries::inspect(file, &spans);
        let mut javascript_boundaries = javascript_boundaries::inspect(file, &spans);
        let mut python_credentials = python_credentials::inspect(file, &spans);
        let comment_ranges = javascript_boundaries
            .as_ref()
            .map(|index| index.comments.clone())
            .unwrap_or_else(|| {
                file.source
                    .contains("/*")
                    .then(|| StrDoc::try_new(&file.source, parser_language(language)).ok())
                    .flatten()
                    .map(|document| {
                        let ast = AstGrep::doc(document);
                        let root = ast.root();
                        root.dfs()
                            .filter(|node| node.kind().as_ref().contains("comment"))
                            .map(|node| node.range())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            });
        for line_index in 0..spans.len() {
            let (line_start, line_end) = spans[line_index];
            let first_content = line_start + file.source[line_start..line_end].len()
                - file.source[line_start..line_end].trim_start().len();
            if comment_ranges
                .iter()
                .any(|range| range.start <= first_content && first_content < range.end)
            {
                continue;
            }
            let line = file.source[line_start..line_end].trim();
            let marker = if file.language == Some(Language::Csharp) {
                csharp_boundaries.remove(&line_index)
            } else if let Some(marker) = python_credentials.remove(&line_index) {
                Some(marker)
            } else if let Some(index) = javascript_boundaries.as_mut() {
                if ["@Post(", "@Put(", "@Patch(", "@Delete(", "@Mutation("]
                    .iter()
                    .any(|s| line.starts_with(s))
                {
                    index.decorated.remove(&line_index)
                } else {
                    server_mutation_review_marker(
                        file,
                        &spans,
                        line_index,
                        Some(index.mutation_members.contains(&line_index)),
                        Some(index.route_invocations.get(&line_index).copied().unwrap_or(
                            javascript_boundaries::RouteInvocation {
                                possible_route: false,
                                end_line: line_index,
                            },
                        )),
                    )
                }
            } else {
                server_mutation_review_marker(file, &spans, line_index, None, None)
            };
            let Some(marker) = marker else {
                continue;
            };
            // Prefer the AST-backed credential effect to the surrounding Python
            // decorator marker; the same implementation is one review question.
            if marker.credential_effect.is_none()
                && file.language == Some(Language::Python)
                && (marker.start_index..=marker.end_index)
                    .find(|index| {
                        let (start, end) = spans[*index];
                        authorization_definition_identifier(&file.source[start..end]).as_deref()
                            == Some(marker.symbol.as_str())
                    })
                    .is_some_and(|index| python_credentials.contains_key(&index))
            {
                continue;
            }
            let start = spans[marker.start_index].0;
            let end = spans[marker.end_index].1;
            if !seen.insert((file.path.clone(), start, end)) {
                continue;
            }
            let location = location_from_offsets(&file.path, &file.source, start, end);
            if scope.is_some_and(|scope| {
                scope.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &scope.changed_files)
            }) {
                continue;
            }
            let excerpt = &file.source[start..end];
            let descriptor = review_admission_descriptor(&marker, excerpt);
            if marker_covered_by_existing_evidence(
                existing_evidence,
                &file.path,
                start,
                end,
                &descriptor,
            ) {
                continue;
            }
            let mut captures = BTreeMap::new();
            captures.insert(
                "operation".to_string(),
                Capture {
                    text: marker.symbol.clone(),
                    location: location.clone(),
                },
            );
            captures.insert(
                "effect".to_string(),
                Capture {
                    text: marker.credential_effect.as_ref().map_or_else(
                        || marker.effect.clone(),
                        |(range, _)| file.source[range.clone()].to_string(),
                    ),
                    location: marker.credential_effect.as_ref().map_or_else(
                        || location.clone(),
                        |(range, _)| {
                            location_from_offsets(&file.path, &file.source, range.start, range.end)
                        },
                    ),
                },
            );
            if let Some((_, basis)) = &marker.credential_effect {
                captures.insert(
                    "effect_basis".to_string(),
                    Capture {
                        text: (*basis).to_string(),
                        location: location.clone(),
                    },
                );
            }
            for (index, handler) in marker.related_handlers.iter().enumerate() {
                captures.insert(
                    format!("related_handler_{}", index + 1),
                    Capture {
                        text: handler.clone(),
                        location: location.clone(),
                    },
                );
            }
            let id = review_admission_marker_id(&file.path, descriptor.rule_id, start, end);
            let evidence = Evidence {
                id: id.clone(),
                kind: EvidenceKind::SensitiveOperation,
                capability: descriptor.capability,
                location,
                enclosing_symbol: Some(marker.symbol.clone()),
                captures,
                cwe_candidates: descriptor.cwe_candidates,
                tags: descriptor.tags,
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: if marker.credential_effect.is_some() {
                        Resolution::Ast
                    } else {
                        Resolution::Textual
                    },
                    engine: if marker.credential_effect.is_some() {
                        "bounded Python credential effect classifier"
                    } else {
                        "bounded server mutation classifier"
                    }
                    .to_string(),
                    rule_version: 1,
                },
                context: EvidenceContext::default(),
                symbol_resolution: None,
                rule_id: descriptor.rule_id.to_string(),
                related_evidence: Vec::new(),
            };
            groups.push(ObservationGroup {
                review_material: is_review_material_path(&file.path),
                path: file.path.clone(),
                symbol: marker.symbol,
                evidence: vec![evidence],
                anchor_evidence_ids: vec![id],
                priority: 1,
            });
        }
    }
    dependencies.enrich(&mut groups);
    for group in &mut groups {
        for fact in &mut group.evidence {
            selection.annotate(fact);
        }
    }
    groups.retain(|group| {
        group.evidence.iter().all(|fact| {
            !fact
                .context
                .availability
                .as_ref()
                .is_some_and(|availability| {
                    availability.state == mehscan_core::AvailabilityState::Excluded
                })
        })
    });
    let recognized = groups.len();
    let mut previously_admitted = 0;
    let mut selected = Vec::new();
    for current_page in 0..=page {
        let mut files = BTreeMap::new();
        let mut families = BTreeMap::new();
        let eligible = groups
            .iter()
            .filter(|group| {
                let file = files.entry(group.path.as_str()).or_insert(0usize);
                let family = families
                    .entry(group.evidence[0].rule_id.as_str())
                    .or_insert(0usize);
                if *file >= MAX_REVIEW_ADMISSION_MARKERS_PER_FILE
                    || *family >= MAX_REVIEW_ADMISSION_MARKERS_PER_FAMILY
                {
                    return false;
                }
                *file += 1;
                *family += 1;
                true
            })
            .cloned()
            .collect();
        selected = fair_marker_limit(eligible, MAX_REVIEW_ADMISSION_MARKERS);
        if current_page == page || selected.is_empty() {
            break;
        }
        let ids = selected
            .iter()
            .map(|g| g.anchor_evidence_ids[0].clone())
            .collect::<BTreeSet<_>>();
        previously_admitted += selected.len();
        groups.retain(|g| !ids.contains(&g.anchor_evidence_ids[0]));
    }
    let accounting = mehscan_core::ReviewMarkerAdmission {
        page,
        recognized,
        previously_admitted,
        admitted: selected.len(),
        budget_deferred: recognized - previously_admitted - selected.len(),
    };
    let mut groups = selected;
    // Presentation must not affect marker classification, coverage checks or
    // bounded selection. An adjacent middleware name is not an inline handler.
    for group in &mut groups {
        let Some(file) = sources.files.get(&group.path) else {
            continue;
        };
        if !matches!(
            file.language,
            Some(Language::Javascript | Language::Typescript | Language::Tsx)
        ) {
            continue;
        }
        let Some(evidence) = group.evidence.first_mut() else {
            continue;
        };
        let Some(excerpt) = file
            .source
            .get(evidence.location.start.byte_offset..evidence.location.end.byte_offset)
        else {
            continue;
        };
        if let Some(label) = inline_route_label(excerpt) {
            group.symbol = label.clone();
            evidence.enclosing_symbol = Some(label.clone());
            if let Some(operation) = evidence.captures.get_mut("operation") {
                operation.text = label;
            }
        }
    }
    (groups, accounting)
}

fn inline_route_label(excerpt: &str) -> Option<String> {
    let prefix = excerpt.lines().take(12).collect::<Vec<_>>().join("\n");
    (prefix.contains("=>") || prefix.contains("function"))
        .then(|| http_mutation_symbol(prefix.lines().next().unwrap_or_default()))
        .flatten()
}

fn fair_marker_limit(groups: Vec<ObservationGroup>, limit: usize) -> Vec<ObservationGroup> {
    let mut by_family: BTreeMap<String, Vec<ObservationGroup>> = BTreeMap::new();
    for group in groups {
        let family = group
            .evidence
            .first()
            .map(|evidence| evidence.rule_id.clone())
            .unwrap_or_default();
        by_family.entry(family).or_default().push(group);
    }
    for groups in by_family.values_mut() {
        groups.sort_by(|left, right| {
            left.review_material
                .cmp(&right.review_material)
                .then_with(|| left.path.cmp(&right.path))
                .then_with(|| left.symbol.cmp(&right.symbol))
        });
        groups.reverse();
    }
    let mut selected = Vec::new();
    while selected.len() < limit {
        let mut added = false;
        for groups in by_family.values_mut() {
            if let Some(group) = groups.pop() {
                selected.push(group);
                added = true;
                if selected.len() == limit {
                    break;
                }
            }
        }
        if !added {
            break;
        }
    }
    selected
}

#[cfg(test)]
pub(super) fn marker_groups(
    sources: &RepositorySources,
    existing_evidence: &[Evidence],
) -> Vec<ObservationGroup> {
    // Marker families share the admission contract but keep separate, narrow
    // deterministic predicates. Add a new family here only when the engine can
    // establish its boundary and dangerous effect without AI inference.
    scoped_marker_groups(sources, existing_evidence, None)
}

#[cfg(test)]
pub(super) fn scoped_marker_groups(
    sources: &RepositorySources,
    existing_evidence: &[Evidence],
    scope: Option<&mehscan_core::ImpactScanScope>,
) -> Vec<ObservationGroup> {
    marker_page(sources, existing_evidence, scope, 0, true, &BTreeMap::new()).0
}

pub(super) fn marker_page(
    sources: &RepositorySources,
    existing_evidence: &[Evidence],
    scope: Option<&mehscan_core::ImpactScanScope>,
    page: usize,
    include_review_material: bool,
    configurations: &BTreeMap<String, mehscan_core::SourceConfiguration>,
) -> (Vec<ObservationGroup>, mehscan_core::ReviewMarkerAdmission) {
    server_mutation_review_marker_groups(
        sources,
        existing_evidence,
        scope,
        page,
        include_review_material,
        configurations,
    )
}

fn marker_covered_by_existing_evidence(
    evidence: &[Evidence],
    path: &str,
    start: usize,
    end: usize,
    descriptor: &ReviewAdmissionDescriptor,
) -> bool {
    evidence.iter().any(|item| {
        // A source-gated lookup is not coverage of the surrounding mutation's
        // policy question, even when it remains available as raw evidence.
        !item
            .tags
            .iter()
            .any(|tag| tag == "review:source-flow-required")
            && item.location.path == path
            && item.location.start.byte_offset < end
            && item.location.end.byte_offset > start
            && matches!(
                item.kind,
                EvidenceKind::Sink
                    | EvidenceKind::SensitiveOperation
                    | EvidenceKind::SecurityConfiguration
            )
            && item
                .cwe_candidates
                .iter()
                .any(|cwe| descriptor.cwe_candidates.contains(cwe))
    })
}

fn review_admission_descriptor(
    marker: &ServerMutationMarker,
    excerpt: &str,
) -> ReviewAdmissionDescriptor {
    let mut operation = marker.symbol.to_ascii_lowercase();
    for handler in &marker.related_handlers {
        operation.push(' ');
        operation.push_str(&handler.to_ascii_lowercase());
    }
    let credential_lifecycle = marker.credential_effect.is_some()
        || [
            "password",
            "passwd",
            "passcode",
            "credential",
            "mfa",
            "totp",
            "authenticator",
            "recoverycode",
            "recovery_code",
            "apikey",
            "api_key",
        ]
        .iter()
        .any(|marker| operation.contains(marker));
    if credential_lifecycle {
        let recovery = operation.contains("reset")
            || operation.contains("recover")
            || excerpt.to_ascii_lowercase().contains("forgot password");
        return ReviewAdmissionDescriptor {
            rule_id: CREDENTIAL_LIFECYCLE_REVIEW_MARKER_RULE_ID,
            capability: Capability::Authentication,
            cwe_candidates: vec![if recovery { "CWE-640" } else { "CWE-620" }.to_string()],
            tags: vec![
                "review-admission-marker".to_string(),
                "review-invariant:credential-lifecycle".to_string(),
                "credential-lifecycle-review-marker".to_string(),
                "server-trust-state-change".to_string(),
                "verify-subject-proof-and-transition".to_string(),
            ],
        };
    }
    ReviewAdmissionDescriptor {
        rule_id: AUTHORIZATION_REVIEW_MARKER_RULE_ID,
        capability: Capability::Authorization,
        cwe_candidates: vec!["CWE-862".to_string(), "CWE-639".to_string()],
        tags: vec![
            "review-admission-marker".to_string(),
            "review-invariant:action-resource-authorization".to_string(),
            "authorization-review-marker".to_string(),
            "server-mutation".to_string(),
            "verify-action-resource-policy".to_string(),
        ],
    }
}

pub(super) fn is_marker(evidence: &Evidence) -> bool {
    evidence
        .tags
        .iter()
        .any(|tag| tag == "review-admission-marker")
}

pub(super) fn review_contract(evidence: &[Evidence]) -> Option<OperationReviewContract> {
    if let Some(e) = evidence.iter().find(|e| {
        e.tags
            .iter()
            .any(|t| t == "rust-protocol-credential-obligation")
    }) {
        let (relationship, title, question) = match e.rule_id.as_str() {
            "rust-http-framing-forward-review" => (
                "bounded_rust_http_framing_review",
                "Review HTTP framing before forwarding",
                "Do the same request headers and forwarded bytes have one unambiguous message boundary at every peer? Inspect captured Content-Length/Transfer-Encoding handling, raw byte provenance, conflicting/duplicate values, rejection before forwarding, connection reuse and actual downstream parsing. Reading both headers is not a smuggling finding. A strict rejection or single canonical reserialization can be a clean control; demonstrate a bounded peer disagreement before claiming request smuggling.",
            ),
            "rust-default-credential-header-review" => (
                "bounded_rust_credential_header_policy_review",
                "Review default credential header destinations",
                "Can these default authentication-like headers reach an unintended origin through the configured client, redirects or reused requests? Inspect actual credential meaning, destination authority, redirect policy and version-specific header stripping. Standard Authorization and custom API-key headers can behave differently. A disabled redirect policy or fixed authorized origin can be a control; builder configuration alone does not prove delivery or exposure.",
            ),
            "rust-jwt-verification-policy-review" => (
                "bounded_rust_jwt_verification_policy_review",
                "Review consumed token verification policy",
                "Can an untrusted token reach this decode with signature checking disabled on the same Validation object? Trace the captured policy mutation and consuming call, key/algorithm and claims checks, later rejection and actual authentication/authorization use. Parsing a token for non-authoritative display can differ from trusting it. A secure verifier on the deciding path can be a control; signature-disabled syntax alone does not establish an account takeover.",
            ),
            _ => (
                "bounded_rust_credential_output_review",
                "Review generated credential output",
                "Does this output actually expose a usable generated token to an unintended reader? Trace the exact token producer, direct formatter argument, log visibility, redaction, token validity and lifetime. A length/digest, test-only dummy or authorized intentional display is a different effect. Source linkage does not establish log deployment or severity, and this review does not enable generic literal-secret scanning.",
            ),
        };
        return Some(OperationReviewContract {
            relationship,
            title,
            security_question: question,
        });
    }
    if evidence
        .iter()
        .any(|e| e.rule_id == "rust-allocation-extent-arithmetic-review")
    {
        return Some(OperationReviewContract {
            relationship: "bounded_rust_extent_arithmetic_review",
            title: "Review allocation extent arithmetic",
            security_question: "Can caller-influenced size arithmetic wrap, narrow or produce a mismatched extent before allocation? Inspect operand types, element counts versus bytes, arithmetic order, checked/saturating/wrapping behavior and guards before computation. Debug overflow panic and release wrapping differ; allocation failure or a later bounds check does not repair prior arithmetic. Checked arithmetic with a rejecting error path and valid small extents are controls. Establish consequential use and caller constraints before claiming memory corruption or denial of service.",
        });
    }
    if evidence
        .iter()
        .any(|e| e.capability == Capability::RustParserResourceReview)
    {
        return Some(OperationReviewContract {
            relationship: "bounded_rust_input_parser_resource_review",
            title: "Review input-backed parser panic boundary",
            security_question: "Can an allowed short or malformed byte input reach this indexing or get(...).unwrap operation without an effective rejecting bound? Check every endpoint, arithmetic before the check, exact input length and the parser's caller contract. Distinguish an ordinary panic/precondition from a remotely consequential abort or service denial; inspect catch_unwind, panic profile and isolation before assigning availability impact. Guarded access or fallible get/Result conversion can be clean controls. This is not a memory-unsafety claim and does not prove arbitrary recursion or expansion behavior.",
        });
    }
    if evidence
        .iter()
        .any(|e| e.tags.iter().any(|t| t == "rust-panic-cleanup-obligation"))
    {
        return Some(OperationReviewContract {
            relationship: "bounded_rust_panic_cleanup_review",
            title: "Review metadata across element destruction",
            security_question: "If this element destructor panics, does the same owner's live-element metadata already exclude the destroyed value before later cleanup? Trace the captured raw drop, metadata assignments, actual owner Drop and generic destructor behavior. Preserve control flow, partial initialization and guards. Updating metadata before destruction can be a repaired control; a nonpanicking concrete element or unwind guard can change applicability. Establish the safe catch_unwind/callback path and repeated destruction rather than calling every raw drop a double free.",
        });
    }
    if evidence
        .iter()
        .any(|e| e.tags.iter().any(|t| t == "rust-thread-safety-obligation"))
    {
        return Some(OperationReviewContract {
            relationship: "bounded_rust_thread_safety_review",
            title: "Review unsafe thread-transfer contract",
            security_question: "Does this unsafe Send/Sync implementation preserve the same stored values' thread-transfer/sharing requirements? Inspect captured fields, generic bounds, interior mutability, synchronization, ownership, PhantomData and type-erased callbacks/futures. A mutex or bound must cover the exact storage and operation. Establish a safe caller that transfers or shares forbidden state, or retain the unresolved contract. Unsafe impl syntax alone is not a defect; complete bounds and valid synchronized storage can be clean controls.",
        });
    }
    if evidence
        .iter()
        .any(|e| e.capability == Capability::RustArchiveExtractionReview)
    {
        return Some(OperationReviewContract {
            relationship: "bounded_rust_archive_extraction_review",
            title: "Review archive extraction boundary",
            security_question: "Can archive-controlled names, link targets or metadata escape the intended extraction boundary or cause an unauthorized overwrite? Trace archive provenance, exact library implementation/version/options, destination and platform path/symlink semantics. For entry-path writes inspect containment BEFORE the write, for the same resolved destination. Distinguish tar Entry::unpack's explicit destination from Entry::unpack_in's root and library containment behavior, using the captured method. For library extraction inspect its actual guarantees; using unpack/extract alone is not a vulnerability. Keep resource limits, permissions and overwrite policy distinct. A documented local API boundary can be assessed without inventing a remote caller; deployment impact needs its real caller binding.",
        });
    }
    if evidence
        .iter()
        .any(|e| e.capability == Capability::RustAllocationReview)
    {
        return Some(OperationReviewContract {
            relationship: "bounded_rust_allocation_extent_review",
            title: "Review caller-influenced allocation extent",
            security_question: "Can untrusted callers control this allocation extent, directly or through decoded lengths? Establish the actual input boundary, element size, arithmetic/casts, available payload and effective rejecting limits BEFORE allocation. A public parameter alone does not prove attacker control. Receiver support captures witness selected fields, aliases and helper return declarations, including the source-owned module/target route when crossing files. Check applicable configuration; declarations do not prove helper value semantics, trait dispatch, generic substitution or custom dereferencing. Distinguish bounded allocation, capacity overflow, allocation-error abort, resident memory growth and recoverable errors; catch_unwind does not catch allocation-error abort. Keep guards and embedding quotas in scope; this marker proves neither missing limits nor denial of service.",
        });
    }
    if let Some(e) = evidence
        .iter()
        .find(|e| e.capability == Capability::RustRawMemoryReview)
    {
        let (question, title) = match e.rule_id.as_str() {
            "rust-unchecked-index-review" => (
                "Can a safe caller select an index or range outside this exact slice/vector's initialized length? Check all range endpoints, overflow, same-object bounds, rejecting guards and mutable aliasing before get_unchecked/get_unchecked_mut. Forming an invalid reference is UB even without a later dereference. A guard retained in source may establish a valid control; admission is not a missing-check verdict.",
                "Review unchecked indexing boundary",
            ),
            "rust-vector-length-publication-review" => (
                "Are all elements exposed by this set_len initialized and valid, and is the new length no greater than the same allocation's capacity? Capacity is not initialized length. Trace writes, their order, element representation, length units, caller preconditions and panic paths. Shrinking length can be valid but changes drop behavior; do not infer uninitialized exposure from the call alone.",
                "Review vector length publication",
            ),
            "rust-pointer-offset-review" => (
                "Does pointer arithmetic stay within the same live allocation or its permitted one-past boundary, without arithmetic overflow? Establish offset units, element size, provenance and subsequent access. Non-null does not establish allocation membership; add/sub/offset and wrapping variants have different contracts. Safe-call reachability alone does not establish that the pointer is dereferenced.",
                "Review raw pointer offset",
            ),
            "rust-assume-initialized-review" => (
                "Has the exact MaybeUninit value been fully initialized with a valid representation before assume_init/read/ref/mut/drop? Inspect writes, padding versus value validity, initialized-prefix accounting and duplicate owning reads. zeroed is invalid for some types; a new(initialized_value) control can be valid. Do not assume a write occurred from capacity or field names.",
                "Review initialization assertion",
            ),
            "rust-transmute-representation-review" => (
                "Does the source value establish the destination representation, alignment, lifetime and aliasing invariants for this transmute/transmute_copy? Equal size is insufficient; pointer/integer provenance, invalid enum/bool/reference values and duplicated owners are separate obligations. Inspect actual generic types and safe caller values rather than treating all retyping as a defect.",
                "Review representation conversion",
            ),
            "rust-vector-metadata-review" => (
                "Do the reconstructed vector's length and capacity operands represent the correct element counts, with initialized length no greater than its actual capacity? Trace their source and arithmetic. Ownership and allocation layout are separate obligations.",
                "Review reconstructed vector metadata",
            ),
            "rust-vector-ownership-review" => (
                "Does reconstruction transfer this live vector allocation exactly once, without a remaining owner or earlier destruction? Check consuming raw-parts APIs, ManuallyDrop, forget, rebinding and possible unwinding before ownership is disabled. Metadata and allocation layout are separate obligations.",
                "Review vector ownership handoff",
            ),
            "rust-vector-layout-review" => (
                "Does the reconstructed element type preserve the original allocation size and alignment, and are the exposed bytes initialized and valid for the new representation? Copy alone does not exclude padding. Check actual trait guarantees and deallocation layout; metadata ordering and owner handoff are separate.",
                "Review raw vector allocation layout",
            ),
            "rust-raw-copy-range-review" => (
                "Do the effective source and destination ranges cover this copy count in elements, with valid alignment and initialized storage as required? Establish the same objects and rejecting checks before the copy. copy_nonoverlapping additionally requires disjoint ranges; copy permits overlap.",
                "Review raw copy ranges",
            ),
            "rust-owned-buffer-copy-review" => (
                "Does this bitwise copy leave live source-owned values duplicated in storage that will also destroy them? Trace the actual copy helper, destination ownership/drop, source suppression and generic element bounds. Distinguish Copy bytes, transfer, opaque effects, copy bounds and panic paths.",
                "Review bitwise ownership transfer",
            ),
            _ => (
                "Can a safe caller supply a pointer or extent that violates this raw memory operation's validity, alignment, initialized range or ownership contract? Establish the actual public/FFI boundary and effective checks; a null or zero-length check alone does not validate arbitrary non-null memory.",
                "Review safe raw-memory boundary",
            ),
        };
        return Some(OperationReviewContract {
            relationship: "bounded_rust_raw_memory_invariant_review",
            security_question: question,
            title,
        });
    }
    if evidence
        .iter()
        .any(|e| e.capability == Capability::ExceptionalOwnershipCleanup)
    {
        return Some(OperationReviewContract {
            relationship: "bounded_pending_collection_cleanup_review",
            security_question: "Can allocations stored in this local raw-pointer collection survive a prior iteration and remain unowned at the selected throw? Establish pending ownership, applicable cleanup/handlers and successful-path transfer. Destroying a vector of raw pointers does not destroy its pointees; distinguish borrowed entries and the selected allocation family.",
            title: "Review pending ownership at exceptional exit",
        });
    }
    if evidence.iter().any(|e| {
        e.tags
            .iter()
            .any(|t| t == "loop-carried-reference-publication")
    }) {
        return Some(OperationReviewContract {
            relationship: "bounded_vector_element_publication_review",
            security_question: "Does the outward call retain a reference or view into this vector element, or make an independent owning copy? Establish the actual stored type/conversion and later use, then whether a later iteration's same-vector mutation invalidates the referenced storage. Check short-string and move behavior, capacity, duplicate and exit guards; a reference argument alone does not prove retained borrowing.",
            title: "Review vector element publication lifetime",
        });
    }
    if evidence
        .iter()
        .any(|e| e.capability == Capability::ContainerBorrowLifetime)
    {
        return Some(OperationReviewContract {
            relationship: "bounded_container_borrow_lifetime_review",
            security_question: "Can this outward element pointer survive a later mutation of the same persistent vector, including repeated keys or iterations? Establish the callee's storage effect and subsequent pointer use; evaluate entry, capacity and duplicate guards for that exact object.",
            title: "Review persistent vector element lifetime",
        });
    }
    if evidence
        .iter()
        .any(|e| e.capability == Capability::BufferLengthPublication)
    {
        return Some(OperationReviewContract {
            relationship: "bounded_initialized_prefix_publication_review",
            security_question: "Does the stored buffer position reach publication as vector length before every byte in that prefix has been initialized? Establish the same buffer and range through the supplied implementation and transfer.",
            title: "Review initialized buffer length publication",
        });
    }
    // A renewal marker selects renewal validity, not only initial sign-in proof.
    // Review procedure and token semantics remain in the routed skill guides.
    if evidence
        .iter()
        .any(|e| e.tags.iter().any(|t| t == "credential-renewal"))
    {
        return Some(OperationReviewContract {
            relationship: "bounded_credential_renewal_review",
            security_question: "Which presented credential does this exchange accept, which subject and authority does it issue, and do applicable expiry, rotation, revocation and security-state changes invalidate that same renewal proof before further authority is issued?",
            title: "Review credential renewal validity",
        });
    }
    match operation_review_family(evidence)? {
        OperationReviewFamily::Authorization => Some(OperationReviewContract {
            relationship: "bounded_action_resource_authorization_review",
            security_question: "Does this action actually select, mutate, disclose, or issue authority over a protected resource? Trace its real effect and effective application/inherited policy; a logged action name or success-shaped response alone does not establish a protected mutation. Does authorization reject the exact unauthorized action before that effect?",
            title: "Review action and resource authorization",
        }),
        OperationReviewFamily::CredentialLifecycle => Some(OperationReviewContract {
            relationship: "bounded_credential_lifecycle_review",
            security_question: "Is there an actual credential transition or an authority-bearing token with account binding and a validating consumer? A random token or success message alone proves neither. For the shown effect, is required subject proof, recovery authority, current credential, or step-up authentication enforced before mutation or authority issuance?",
            title: "Review credential lifecycle state transition",
        }),
        OperationReviewFamily::ObjectBinding => Some(OperationReviewContract {
            relationship: "bounded_object_binding_review",
            security_question: "Which request-controlled fields can this exact binding or copy operation persist, and do explicit allowlists, exclusions, DTO boundaries, or field-level authorization prevent security-sensitive assignment?",
            title: "Review persisted object binding",
        }),
        OperationReviewFamily::RequestIntegrity => Some(OperationReviewContract {
            relationship: "bounded_request_integrity_review",
            security_question: "Can a cross-site request invoke this exact state-changing operation with victim authority, or does an applicable request-bound token or strict origin control reject it first?",
            title: "Review request integrity for state change",
        }),
        OperationReviewFamily::FailOpen => Some(OperationReviewContract {
            relationship: "bounded_fail_open_policy_review",
            security_question: "Does the shown failed security or validation decision terminate the protected operation, or can execution continue to the sensitive effect?",
            title: "Review non-enforcing security decision",
        }),
        OperationReviewFamily::AuthoritativeValue => Some(OperationReviewContract {
            relationship: "bounded_authoritative_value_binding_review",
            security_question: "Does this financial effect use the applicable server-authoritative value for the selected resource and version, rather than a caller-supplied amount?",
            title: "Review authoritative financial value binding",
        }),
        OperationReviewFamily::StateTransition => Some(OperationReviewContract {
            relationship: "bounded_state_transition_enforcement_review",
            security_question: "Does this exact resource state change enforce an allowed transition from the persisted current state to the requested next state, with rejection before mutation?",
            title: "Review resource state transition",
        }),
        OperationReviewFamily::SharedStateLimit => Some(OperationReviewContract {
            relationship: "bounded_shared_state_limit_enforcement_review",
            security_question: "Are the shown shared-state limit check and resulting write enforced atomically for the same persisted value, and does the check implement the applicable business limit?",
            title: "Review shared-state limit enforcement",
        }),
    }
}

fn operation_review_family(evidence: &[Evidence]) -> Option<OperationReviewFamily> {
    let invariant = evidence
        .iter()
        .flat_map(|item| item.tags.iter())
        .find_map(|tag| tag.strip_prefix("review-invariant:"));
    if invariant == Some("authoritative-value-binding") {
        return Some(OperationReviewFamily::AuthoritativeValue);
    }
    if invariant == Some("state-transition-enforcement") {
        return Some(OperationReviewFamily::StateTransition);
    }
    if invariant == Some("shared-state-limit-enforcement") {
        return Some(OperationReviewFamily::SharedStateLimit);
    }
    if invariant == Some("action-resource-authorization")
        || evidence.iter().any(|item| {
            item.cwe_candidates.iter().any(|cwe| cwe == "CWE-862")
                && (item.rule_id.contains("generated-crud-review")
                    || item.tags.iter().any(|tag| {
                        matches!(
                            tag.as_str(),
                            "allow-anonymous"
                                | "needs-verification"
                                | "verify-public-intent-and-operation-authorization"
                                | "verify-field-authority"
                        )
                    }))
        })
    {
        return Some(OperationReviewFamily::Authorization);
    }
    if invariant == Some("credential-lifecycle") {
        return Some(OperationReviewFamily::CredentialLifecycle);
    }
    if evidence.iter().any(|item| {
        matches!(
            item.kind,
            EvidenceKind::Sink | EvidenceKind::SensitiveOperation
        ) && item.cwe_candidates.iter().any(|cwe| cwe == "CWE-915")
            && item.tags.iter().any(|tag| tag == "mass-assignment")
    }) {
        return Some(OperationReviewFamily::ObjectBinding);
    }
    if evidence.iter().any(|item| {
        matches!(
            item.kind,
            EvidenceKind::Sink
                | EvidenceKind::SensitiveOperation
                | EvidenceKind::SecurityConfiguration
        ) && item.cwe_candidates.iter().any(|cwe| cwe == "CWE-352")
            && item.tags.iter().any(|tag| tag == "csrf")
    }) {
        return Some(OperationReviewFamily::RequestIntegrity);
    }
    if evidence.iter().any(|item| {
        item.tags.iter().any(|tag| {
            matches!(
                tag.as_str(),
                "rejection-response-falls-through" | "mismatch-not-rejected"
            )
        })
    }) {
        return Some(OperationReviewFamily::FailOpen);
    }
    None
}

pub(super) fn decision_questions(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> Vec<String> {
    if evidence
        .iter()
        .any(|e| e.tags.iter().any(|t| t == "credential-renewal"))
    {
        return vec!["Does the accepting record invalidate the same presented renewal proof under applicable expiry, rotation, revocation and security-state changes before further authority is issued, and is this exchange exposed by the registered application?".into()];
    }
    match operation_review_family(evidence) {
        Some(OperationReviewFamily::Authorization | OperationReviewFamily::CredentialLifecycle)
            if evidence.iter().any(is_marker) =>
        {
            let missing_helpers = evidence
                .iter()
                .flat_map(|item| item.captures.iter())
                .filter(|(name, _)| name.starts_with("related_handler_"))
                .map(|(_, capture)| capture.text.as_str())
                .filter(|handler| {
                    !facts
                        .iter()
                        .any(|fact| fact_supplies_mutation_helper(fact, handler))
                })
                .collect::<BTreeSet<_>>();
            if missing_helpers.is_empty() {
                Vec::new()
            } else {
                vec![format!(
                    "What do the exact referenced mutation helpers {} enforce for this operation, including rejection behavior and the affected subject, action, resource, or credential transition?",
                    missing_helpers
                        .into_iter()
                        .map(|handler| format!("`{handler}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )]
            }
        }
        Some(OperationReviewFamily::ObjectBinding)
            if !evidence.iter().any(|item| {
                item.tags
                    .iter()
                    .any(|tag| tag.starts_with("sensitive-fields:"))
            }) =>
        {
            let input_type = preferred_capture(evidence, &["input_type", "model", "entity"]);
            vec![match input_type {
                Some(input_type) => format!(
                    "Which persisted fields can request-bound `{input_type}` supply through this exact binding operation, which are security-sensitive, and does an applicable executable allowlist, exclusion, DTO mapping, or field-level authorization prevent them from being written?"
                ),
                None => "Which persisted fields can the request-bound object supply through this exact binding operation, which are security-sensitive, and does an applicable executable allowlist, exclusion, DTO mapping, or field-level authorization prevent them from being written?".to_string(),
            }]
        }
        Some(OperationReviewFamily::AuthoritativeValue) => {
            let helper = preferred_capture(evidence, &["authority_helper"]);
            let Some(helper) = helper else {
                return Vec::new();
            };
            if facts.iter().any(|fact| {
                matches!(
                    fact.role.as_str(),
                    "helper_definition_context"
                        | "captured_definition_context"
                        | "imported_member_definition_context"
                ) && fact.symbol == helper
            }) {
                Vec::new()
            } else {
                vec![format!(
                    "Does exact helper `{helper}` produce the applicable server-authoritative price, quote, order amount, or catalog value for this financial effect, and where is the caller-supplied value compared and rejected before persistence?"
                )]
            }
        }
        Some(OperationReviewFamily::StateTransition) => {
            let helper = preferred_capture(evidence, &["transition_helper"]);
            let Some(helper) = helper else {
                return Vec::new();
            };
            vec![format!(
                "What exact current-to-next transitions does helper `{helper}` allow for this resource, and how does it reject a disallowed edge before persistence?"
            )]
        }
        Some(OperationReviewFamily::SharedStateLimit) => {
            let helper = preferred_capture(evidence, &["persistence_helper"]);
            let Some(helper) = helper else {
                return Vec::new();
            };
            if facts.iter().any(|fact| {
                matches!(
                    fact.role.as_str(),
                    "helper_definition_context"
                        | "captured_definition_context"
                        | "imported_member_definition_context"
                ) && fact.symbol == helper
            }) {
                Vec::new()
            } else {
                vec![format!(
                    "What database operation does exact helper `{helper}` execute, and does it combine the limit predicate and state change in one conditional write, locked transaction, or other adapter-established atomic operation?"
                )]
            }
        }
        _ => Vec::new(),
    }
}

fn fact_supplies_mutation_helper(fact: &ReviewNeighborhoodFact, handler: &str) -> bool {
    if fact.symbol != handler {
        return false;
    }
    // Both helper producers cap excerpts at this budget. Reaching the cap can
    // mean that the rejection or affected-resource logic was omitted, so only
    // a definition that clearly fits inside the bound satisfies the question.
    let supplied_lines = fact
        .location
        .end
        .line
        .saturating_sub(fact.location.start.line)
        .saturating_add(1);
    matches!(
        fact.role.as_str(),
        "review_admission_helper_context"
            | "helper_definition_context"
            | "imported_member_definition_context"
    ) && !fact.excerpt.trim().is_empty()
        && supplied_lines < MAX_REVIEW_HELPER_LINES
}

pub(super) fn preferred_lookup_symbol(evidence: &[Evidence]) -> Option<String> {
    preferred_capture(
        evidence,
        &[
            "authority_helper",
            "transition_helper",
            "persistence_helper",
            "input_type",
            "model",
            "entity",
            "related_handler_1",
        ],
    )
    .or_else(|| {
        evidence
            .iter()
            .flat_map(|item| item.tags.iter())
            .find_map(|tag| {
                ["model:", "entity:", "resource:"]
                    .iter()
                    .find_map(|prefix| tag.strip_prefix(prefix))
            })
            .filter(|symbol| is_helpful_reference_identifier(symbol))
            .map(str::to_string)
    })
}

fn preferred_capture(evidence: &[Evidence], names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        evidence
            .iter()
            .filter_map(|item| item.captures.get(*name))
            .map(|capture| capture.text.trim())
            .find(|value| is_helpful_reference_identifier(value))
            .map(str::to_string)
    })
}

fn server_mutation_review_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    javascript_mutation_member: Option<bool>,
    javascript_route_invocation: Option<javascript_boundaries::RouteInvocation>,
) -> Option<ServerMutationMarker> {
    let (start, end) = spans[line_index];
    let line = file.source[start..end].trim();
    if line.is_empty()
        || line.starts_with(['/', '*'])
        || (line.starts_with('#') && !line.starts_with("#["))
    {
        return None;
    }
    match file.language? {
        Language::Java | Language::Python => {
            attributed_server_mutation_marker(file, spans, line_index, line)
        }
        Language::Kotlin => kotlin_server_mutation_marker(file, spans, line_index, line),
        Language::Javascript | Language::Typescript | Language::Tsx => {
            javascript_server_mutation_marker(
                file,
                spans,
                line_index,
                line,
                javascript_mutation_member,
                javascript_route_invocation,
            )
        }
        Language::Php => php_server_mutation_marker(file, spans, line_index, line),
        Language::Go => go_server_mutation_marker(file, spans, line_index, line),
        Language::Rust => rust_server_mutation_marker(file, spans, line_index, line),
        _ => None,
    }
}

fn attributed_server_mutation_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    line: &str,
) -> Option<ServerMutationMarker> {
    let is_boundary = match file.language? {
        Language::Java => [
            "@PostMapping",
            "@PutMapping",
            "@PatchMapping",
            "@DeleteMapping",
            "@POST",
            "@PUT",
            "@PATCH",
            "@DELETE",
            "@MutationMapping",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix)),
        Language::Python => {
            (line.starts_with('@')
                && [
                    ".post(",
                    ".put(",
                    ".patch(",
                    ".delete(",
                    "methods=[",
                    "methods = [",
                ]
                .iter()
                .any(|needle| line.to_ascii_lowercase().contains(needle)))
                || ([
                    "def create(",
                    "def update(",
                    "def destroy(",
                    "def partial_update(",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
                    && file.source.contains("rest_framework"))
        }
        _ => false,
    };
    if !is_boundary {
        return None;
    }
    if file.language == Some(Language::Python)
        && authorization_definition_identifier(line).is_some()
    {
        return marker_from_definition(file, spans, line_index, line_index);
    }
    marker_after_boundary(file, spans, line_index, 8)
}

fn kotlin_server_mutation_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    line: &str,
) -> Option<ServerMutationMarker> {
    if [
        "@PostMapping",
        "@PutMapping",
        "@PatchMapping",
        "@DeleteMapping",
        "@MutationMapping",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
    {
        return marker_after_boundary(file, spans, line_index, 8);
    }
    if ![
        "post<", "put<", "patch<", "delete<", "post(", "put(", "patch(", "delete(",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
    {
        return None;
    }
    marker_from_inline_boundary(file, spans, line_index, "ktor-route")
}

fn javascript_server_mutation_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    line: &str,
    mutation_member: Option<bool>,
    route_invocation: Option<javascript_boundaries::RouteInvocation>,
) -> Option<ServerMutationMarker> {
    if ["@Post(", "@Put(", "@Patch(", "@Delete(", "@Mutation("]
        .iter()
        .any(|prefix| line.starts_with(prefix))
    {
        return marker_after_boundary(file, spans, line_index, 8);
    }

    let chained_mutation_route = if line.contains(".route(") {
        let end = (line_index + 12).min(spans.len().saturating_sub(1));
        let excerpt = &file.source[spans[line_index].0..spans[end].1];
        let route_open = excerpt.find(".route(").map(|start| start + ".route".len());
        route_open
            .and_then(|open| super::balanced_javascript_call_end(excerpt, open))
            .is_some_and(|close| {
                let tail = excerpt[close + 1..].trim_start().to_ascii_lowercase();
                [".post(", ".put(", ".patch(", ".delete("]
                    .iter()
                    .any(|verb| tail.starts_with(verb))
            })
    } else {
        false
    };
    if (javascript_http_mutation_route(line) || chained_mutation_route)
        && route_invocation.is_none_or(|call| call.possible_route)
    {
        let symbol =
            http_mutation_symbol(line).unwrap_or_else(|| "HTTP mutation route".to_string());
        return marker_from_inline_boundary_through(
            file,
            spans,
            line_index,
            &symbol,
            route_invocation.map(|call| call.end_line),
        );
    }

    if (line.contains("validatedActionWithUser(")
        || line.contains("withTeam(")
        || (line.starts_with("export async function ") && mutation_effect(line).is_some()))
        && (file.source.contains("'use server'") || file.source.contains("\"use server\""))
    {
        return marker_from_inline_boundary(file, spans, line_index, "server-action");
    }

    if line.contains(": async")
        && mutation_member.unwrap_or_else(|| {
            javascript_inside_mutation_object(&file.source, start_of(spans, line_index))
        })
    {
        return marker_from_inline_boundary(file, spans, line_index, "graphql-mutation");
    }
    None
}

fn php_server_mutation_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    line: &str,
) -> Option<ServerMutationMarker> {
    let lower = line.to_ascii_lowercase();
    if line.starts_with("#[Route")
        || (line.contains("Route::")
            && ["post", "put", "patch", "delete", "resource"]
                .iter()
                .any(|method| lower.contains(method)))
    {
        let definition_index =
            ((line_index + 1)..(line_index + 10).min(spans.len())).find(|index| {
                let (start, end) = spans[*index];
                authorization_definition_identifier(&file.source[start..end]).is_some()
            })?;
        if line.starts_with("#[Route") {
            let definition_line =
                &file.source[spans[definition_index].0..spans[definition_index].1];
            let definition = authorization_definition_identifier(definition_line)?;
            let mutation_method = ["'post'", "'put'", "'patch'", "'delete'"]
                .iter()
                .any(|method| lower.contains(method));
            let get_only = lower.contains("methods:") && !mutation_method;
            if get_only || (!lower.contains("methods:") && !mutation_effect(&definition).is_some())
            {
                return None;
            }
        }
        return marker_from_definition(file, spans, line_index, definition_index);
    }
    None
}

fn go_server_mutation_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    line: &str,
) -> Option<ServerMutationMarker> {
    if [".POST(", ".PUT(", ".PATCH(", ".DELETE("]
        .iter()
        .any(|needle| line.contains(needle))
    {
        return marker_from_inline_boundary(file, spans, line_index, "go-http-mutation");
    }
    None
}

fn rust_server_mutation_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    line: &str,
) -> Option<ServerMutationMarker> {
    let lower = line.to_ascii_lowercase();
    if line.contains(".route(")
        && ["post(", "delete(", "patch(", "put("]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        return marker_from_inline_boundary(file, spans, line_index, "rust-http-mutation");
    }
    None
}

fn marker_from_definition(
    file: &SourceFile,
    spans: &[(usize, usize)],
    boundary_index: usize,
    definition_index: usize,
) -> Option<ServerMutationMarker> {
    let (definition_start, definition_end) = spans[definition_index];
    let symbol =
        authorization_definition_identifier(&file.source[definition_start..definition_end])?;
    if is_authorization_bootstrap_operation(&symbol) {
        return None;
    }
    let end_index = textual_definition_end_with_limit(&file.source, spans, definition_index, 120);
    let excerpt = &file.source[spans[boundary_index].0..spans[end_index].1];
    let effect = mutation_effect(excerpt)?;
    Some(ServerMutationMarker {
        start_index: boundary_index,
        end_index,
        effect,
        related_handlers: terminal_call_identifiers(excerpt, &symbol),
        credential_effect: None,
        symbol,
    })
}

fn marker_after_boundary(
    file: &SourceFile,
    spans: &[(usize, usize)],
    boundary_index: usize,
    lookahead: usize,
) -> Option<ServerMutationMarker> {
    let definition_index = ((boundary_index + 1)..(boundary_index + lookahead).min(spans.len()))
        .find(|index| {
            let (start, end) = spans[*index];
            authorization_definition_identifier(&file.source[start..end]).is_some()
        })?;
    marker_from_definition(file, spans, boundary_index, definition_index)
}

fn marker_from_inline_boundary(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    fallback_symbol: &str,
) -> Option<ServerMutationMarker> {
    marker_from_inline_boundary_through(file, spans, line_index, fallback_symbol, None)
}

fn marker_from_inline_boundary_through(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
    fallback_symbol: &str,
    call_end_line: Option<usize>,
) -> Option<ServerMutationMarker> {
    let mut end_index = textual_definition_end_with_limit(&file.source, spans, line_index, 120);
    if let Some(call_end_line) = call_end_line {
        // A multiline route chain can continue after the first balanced call.
        // Extend through its invocation without widening the source budget.
        end_index = end_index.max(call_end_line.min(line_index + 119).min(spans.len() - 1));
    }
    let excerpt = &file.source[spans[line_index].0..spans[end_index].1];
    let mut handlers = terminal_call_identifiers(excerpt, "");
    let boundary_line = &file.source[spans[line_index].0..spans[line_index].1];
    let route_excerpt = excerpt.lines().take(12).collect::<Vec<_>>().join("\n");
    let route_handlers = terminal_route_handlers(&route_excerpt);
    let route_handler = route_handlers.last().cloned();
    for handler in route_handlers.into_iter().rev() {
        if !handlers.contains(&handler) {
            handlers.insert(0, handler);
        }
    }
    let declared = authorization_definition_identifier(boundary_line);
    let prefer_declared = boundary_line.trim_start().starts_with("export ")
        || boundary_line.contains(" = validatedAction")
        || boundary_line.contains(" = withTeam")
        || boundary_line.contains(": async");
    let symbol = if prefer_declared {
        declared.or_else(|| handlers.first().cloned())
    } else {
        route_handler
    }
    .unwrap_or_else(|| fallback_symbol.to_string());
    if is_authorization_bootstrap_operation(&symbol)
        || is_authorization_bootstrap_excerpt(excerpt)
        || handlers
            .iter()
            .any(|handler| is_authorization_bootstrap_operation(handler))
    {
        return None;
    }
    let effect = mutation_effect(excerpt)?;
    Some(ServerMutationMarker {
        start_index: line_index,
        end_index,
        symbol,
        effect,
        related_handlers: handlers,
        credential_effect: None,
    })
}

fn mutation_effect(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    [
        (
            "delete",
            ["delete", "destroy", "remove", "delete from"].as_slice(),
        ),
        (
            "authorization-change",
            ["permission", "invitation", "member", "grant", "revoke"].as_slice(),
        ),
        (
            "update",
            [
                "update", "save", "persist", "flush", "insert", "create", "approve", "publish",
                "archive", "enable", "disable", "transfer", "cancel", "reset",
            ]
            .as_slice(),
        ),
    ]
    .into_iter()
    .find_map(|(effect, needles)| {
        needles
            .iter()
            .any(|needle| lower.contains(needle))
            .then(|| effect.to_string())
    })
}

fn terminal_call_identifiers(text: &str, enclosing: &str) -> Vec<String> {
    let mut called = BTreeSet::new();
    for prefix in text.split('(').take(64) {
        let token = prefix
            .trim_end()
            .rsplit(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$' | '.'))
            })
            .next()
            .unwrap_or_default()
            .rsplit('.')
            .next()
            .unwrap_or_default();
        let lower = token.to_ascii_lowercase();
        if token != enclosing
            && !matches!(
                lower.as_str(),
                "post" | "put" | "patch" | "delete" | "route" | "action" | "mutation"
            )
            && !is_generic_mutation_reference(&lower)
            && is_helpful_reference_identifier(token)
            && mutation_name(&lower)
            && is_mutation_helper_identifier(token)
        {
            called.insert(token.to_string());
        }
    }
    called.into_iter().take(6).collect()
}

fn is_mutation_helper_identifier(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    token
        .chars()
        .next()
        .is_some_and(|character| !character.is_ascii_uppercase())
        && !matches!(
            lower.as_str(),
            "createform"
                | "createformbuilder"
                | "createquerybuilder"
                | "createvalidator"
                | "createview"
        )
        && !lower.contains("schema")
}

fn authorization_definition_identifier(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with(['@', '#', '/', '*']) || trimmed.contains(" class ") {
        return None;
    }
    if let Some(identifier) = textual_definition_identifier(trimmed) {
        return Some(identifier);
    }
    let prefix = trimmed.split_once('(')?.0.trim_end();
    let identifier = prefix
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        })
        .rfind(|token| !token.is_empty())?;
    mutation_name(&identifier.to_ascii_lowercase()).then(|| identifier.to_string())
}

fn mutation_name(lower: &str) -> bool {
    MUTATION_NAME_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn is_generic_mutation_reference(lower: &str) -> bool {
    matches!(
        lower,
        "create"
            | "created"
            | "update"
            | "updated"
            | "delete"
            | "deleted"
            | "remove"
            | "removed"
            | "save"
            | "saved"
            | "persist"
            | "edit"
            | "edited"
            | "destroy"
            | "destroyed"
    )
}

fn terminal_route_handlers(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let (open, chained) = [".post(", ".put(", ".patch(", ".delete("]
        .iter()
        .filter_map(|verb| {
            lower
                .find(verb)
                .map(|start| (start + verb.len() - 1, lower[..start].contains(".route(")))
        })
        .min_by_key(|(start, _)| *start)
        .unwrap_or((0, false));
    if open == 0 || line.as_bytes().get(open) != Some(&b'(') {
        return Vec::new();
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut argument_start = open + 1;
    let mut arguments = Vec::new();
    for (offset, byte) in line.as_bytes().iter().enumerate().skip(open) {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == delimiter {
                quote = None;
            }
            continue;
        }
        match *byte {
            b'\'' | b'"' | b'`' => quote = Some(*byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    arguments.push(&line[argument_start..offset]);
                    break;
                }
            }
            b',' if depth == 1 => {
                arguments.push(&line[argument_start..offset]);
                argument_start = offset + 1;
            }
            _ => {}
        }
    }
    arguments
        .into_iter()
        .skip(usize::from(!chained))
        .filter(|argument| {
            !argument.contains("=>") && !argument.trim_start().starts_with("function")
        })
        .filter_map(|argument| {
            let last_call = argument
                .split('(')
                .filter_map(|prefix| {
                    prefix
                        .trim_end()
                        .rsplit(|character: char| {
                            !(character.is_ascii_alphanumeric()
                                || matches!(character, '_' | '$' | '.'))
                        })
                        .next()?
                        .rsplit('.')
                        .next()
                })
                .filter(|token| {
                    is_helpful_reference_identifier(token)
                        && !matches!(
                            token.to_ascii_lowercase().as_str(),
                            "async" | "function" | "asynchandler" | "request" | "reply"
                        )
                })
                .last();
            last_call.map(str::to_string)
        })
        .take(6)
        .collect()
}

#[cfg(test)]
mod route_handler_tests {
    use super::terminal_route_handlers;

    #[test]
    fn inline_route_label_does_not_claim_a_middleware_identity() {
        assert_eq!(
            super::inline_route_label(
                "router.patch(\n '/:collection',\n collectionExists,\n asyncHandler(async (req) => {\n service.update(req.body);"
            ),
            Some("PATCH route".into())
        );
        assert_eq!(
            super::inline_route_label("app.post('/items', authenticate, updateItem)"),
            None
        );
    }

    #[test]
    fn uses_invoked_handler_instead_of_module_or_wrapper() {
        assert_eq!(
            terminal_route_handlers("app.delete('/api/Products/:id', security.denyAll())")
                .last()
                .cloned(),
            Some("denyAll".to_string())
        );
        assert_eq!(
            terminal_route_handlers(
                "app.put('/api/BasketItems/:id', utils.asyncHandler(basketItems.quantityCheckBeforeBasketItemUpdate()))"
            )
            .last()
            .cloned(),
            Some("quantityCheckBeforeBasketItemUpdate".to_string())
        );
    }

    #[test]
    fn retains_ordered_route_middleware_and_chained_handlers() {
        assert_eq!(
            terminal_route_handlers(
                "app.post('/benefits', isLoggedIn, isAdmin, benefitsHandler.updateBenefits)"
            ),
            vec!["isLoggedIn", "isAdmin", "updateBenefits"]
        );
        assert_eq!(
            terminal_route_handlers("router.route('/items/:id').put(security.denyAll())"),
            vec!["denyAll"]
        );
        assert_eq!(
            terminal_route_handlers(
                "app.put('/api/BasketItems/:id', security.appendUserId(), utils.asyncHandler(basketItems.quantityCheckBeforeBasketItemUpdate()))"
            ),
            vec!["appendUserId", "quantityCheckBeforeBasketItemUpdate"]
        );
        assert!(terminal_route_handlers("fastify.patch('/tasks/:id', async (request) => { return tasks.update(request.body) })").is_empty());
        assert_eq!(
            terminal_route_handlers(
                "router.route('/items/:id')\n  .put(\n    authenticateToken,\n    handlers.updateItem\n  )"
            ),
            vec!["authenticateToken", "updateItem"]
        );
    }
}

fn javascript_http_mutation_route(line: &str) -> bool {
    if !line.contains('.') || !line.contains('(') {
        return false;
    }
    let compact = line
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    ["fastify", "router", "app", "server"]
        .iter()
        .any(|receiver| {
            ["post", "put", "patch", "delete"]
                .iter()
                .any(|verb| compact.contains(&format!("{receiver}.{verb}(")))
        })
}

fn http_mutation_symbol(line: &str) -> Option<String> {
    let compact = line.split_whitespace().collect::<String>();
    let lower = compact.to_ascii_lowercase();
    ["post", "put", "patch", "delete"]
        .into_iter()
        .find(|verb| lower.contains(&format!(".{verb}(")))
        .map(|verb| format!("{} route", verb.to_ascii_uppercase()))
}

fn is_authorization_bootstrap_operation(symbol: &str) -> bool {
    matches!(
        symbol
            .to_ascii_lowercase()
            .replace(['_', '-', '$'], "")
            .as_str(),
        "login"
            | "signin"
            | "signup"
            | "register"
            | "registration"
            | "logout"
            | "signout"
            | "registeruser"
            | "loginuser"
    )
}

fn is_authorization_bootstrap_excerpt(excerpt: &str) -> bool {
    let compact = excerpt
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    [
        "'/login'",
        "\"/login\"",
        "'/signin'",
        "\"/signin\"",
        "'/signup'",
        "\"/signup\"",
        "registeruser(",
        "loginuser(",
        "login:async",
    ]
    .iter()
    .any(|marker| compact.contains(marker))
}

fn javascript_inside_mutation_object(source: &str, offset: usize) -> bool {
    let mut prefix_start = offset.saturating_sub(4096);
    while !source.is_char_boundary(prefix_start) {
        prefix_start += 1;
    }
    let prefix = &source[prefix_start..offset];
    prefix
        .rfind("Mutation")
        .is_some_and(|mutation| !prefix[mutation..].contains("Query:"))
}

fn start_of(spans: &[(usize, usize)], line_index: usize) -> usize {
    spans[line_index].0
}

fn review_admission_marker_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

#[cfg(test)]
mod effect_cases {
    use super::*;

    #[test]
    fn csharp_http_attributes_keep_the_owning_handler_and_review_family() {
        let source = r#"
using Microsoft.AspNetCore.Mvc;
class AccountController {
    [HttpPost]
    [ActionName("ResetPassword")]
    [Route(
        "account/recover",
        Name = nameof(ResetPassword)
    )]
    [ValidateAntiForgeryToken]
    public IActionResult ResetPassword(string token, string next) {
        users.ResetPassword(token, next);
        return Ok();
    }
    [HttpPut, Route("settings")]
    public IActionResult UpdateSettings(string next) {
        settings.Save(next);
        return Ok();
    }
    public void Helper() {
        var example = "[HttpPost]";
        settings.Save(example);
    }
    [Example.HttpPost]
    public void SaveUnrelatedAttribute() { settings.Save(); }
    [HttpPost, ActionName("Index")]
    [FormValueRequired("Filter")]
    public IActionResult Filter() {
        editor.UpdateEditor();
        return RedirectToAction("Index");
    }
}
[HttpPost]
class NotAHandler {
    public void SaveHelper() { settings.Save(); }
}
"#;
        let sources = RepositorySources {
            node_modules: Default::default(),
            root: ".".into(),
            files: BTreeMap::from([(
                "Account.cs".into(),
                SourceFile {
                    path: "Account.cs".into(),
                    language: Some(Language::Csharp),
                    source: source.into(),
                },
            )]),
        };
        let groups =
            server_mutation_review_marker_groups(&sources, &[], None, 0, true, &BTreeMap::new()).0;
        assert_eq!(groups.len(), 2);
        for (symbol, capability, family, call) in [
            (
                "ResetPassword",
                Capability::Authentication,
                "review-invariant:credential-lifecycle",
                "users.ResetPassword(token, next)",
            ),
            (
                "UpdateSettings",
                Capability::Authorization,
                "review-invariant:action-resource-authorization",
                "settings.Save(next)",
            ),
        ] {
            let group = groups.iter().find(|group| group.symbol == symbol).unwrap();
            let marker = &group.evidence[0];
            assert_eq!(marker.capability, capability);
            assert!(marker.tags.iter().any(|tag| tag == family));
            let excerpt =
                &source[marker.location.start.byte_offset..marker.location.end.byte_offset];
            assert!(excerpt.contains(call));
            assert!(excerpt.contains("return Ok()"));
            assert!(!excerpt.contains("public void Helper"));
        }
    }

    #[test]
    fn simulated_and_actual_transitions_keep_separate_source_bound_questions() {
        let source = include_str!("../../../../tests/fixtures/v11-review-effects/Actions.cs");
        let sources = RepositorySources {
            node_modules: Default::default(),
            root: ".".into(),
            files: BTreeMap::from([(
                "Actions.cs".into(),
                SourceFile {
                    path: "Actions.cs".into(),
                    language: Some(Language::Csharp),
                    source: source.into(),
                },
            )]),
        };
        let groups =
            server_mutation_review_marker_groups(&sources, &[], None, 0, true, &BTreeMap::new()).0;
        assert_eq!(groups.len(), 3);
        let mut identities = BTreeSet::new();
        for symbol in ["ResetPasswordDemo", "ResetPassword", "DeleteUser"] {
            let group = groups.iter().find(|group| group.symbol == symbol).unwrap();
            let marker = &group.evidence[0];
            assert_eq!(marker.kind, EvidenceKind::SensitiveOperation);
            assert!(identities.insert(marker.id.clone()));
            let location = &marker.location;
            let text = &source[location.start.byte_offset..location.end.byte_offset];
            assert!(text.contains("return Ok"));
            assert_eq!(text.contains("password = next"), symbol == "ResetPassword");
            // Admission retains questions for both. It must not classify a
            // response-shaped action as a proven state transition or safe code.
            assert!(review_contract(&group.evidence).is_some());
        }
    }
}
