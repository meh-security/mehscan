use super::*;

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
}

/// Admit bounded review work for sensitive server mutations even when no
/// ordinary sink rule expresses the relevant authorization or credential-
/// lifecycle invariant. A marker never claims that its invariant is violated.
fn server_mutation_review_marker_groups(
    sources: &RepositorySources,
    existing_evidence: &[Evidence],
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    let mut seen = BTreeSet::new();
    let mut family_counts = BTreeMap::new();
    for file in sources.files.values() {
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
        let mut file_count = 0;
        for line_index in 0..spans.len() {
            if file_count >= MAX_REVIEW_ADMISSION_MARKERS_PER_FILE {
                break;
            }
            let Some(marker) = server_mutation_review_marker(file, &spans, line_index) else {
                continue;
            };
            let start = spans[marker.start_index].0;
            let end = spans[marker.end_index].1;
            if !seen.insert((file.path.clone(), start, end)) {
                continue;
            }
            let location = location_from_offsets(&file.path, &file.source, start, end);
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
            let family_count = family_counts.entry(descriptor.rule_id).or_insert(0usize);
            if *family_count >= MAX_REVIEW_ADMISSION_MARKERS_PER_FAMILY {
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
                    text: marker.effect,
                    location: location.clone(),
                },
            );
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
                    resolution: Resolution::Textual,
                    engine: "bounded server mutation classifier".to_string(),
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
            *family_count += 1;
            file_count += 1;
        }
    }
    fair_marker_limit(groups, MAX_REVIEW_ADMISSION_MARKERS)
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

pub(super) fn marker_groups(
    sources: &RepositorySources,
    existing_evidence: &[Evidence],
) -> Vec<ObservationGroup> {
    // Marker families share the admission contract but keep separate, narrow
    // deterministic predicates. Add a new family here only when the engine can
    // establish its boundary and dangerous effect without AI inference.
    server_mutation_review_marker_groups(sources, existing_evidence)
}

fn marker_covered_by_existing_evidence(
    evidence: &[Evidence],
    path: &str,
    start: usize,
    end: usize,
    descriptor: &ReviewAdmissionDescriptor,
) -> bool {
    evidence.iter().any(|item| {
        item.location.path == path
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
    let credential_lifecycle = [
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
    match operation_review_family(evidence)? {
        OperationReviewFamily::Authorization => Some(OperationReviewContract {
            relationship: "bounded_action_resource_authorization_review",
            security_question: "Does the supplied operation, subject, selected resource, and applicable policy establish effective authorization for this exact action?",
            title: "Review action and resource authorization",
        }),
        OperationReviewFamily::CredentialLifecycle => Some(OperationReviewContract {
            relationship: "bounded_credential_lifecycle_review",
            security_question: "Does the supplied credential or authenticator transition enforce the required subject proof, recovery authority, current credential, or step-up authentication?",
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
                    !facts.iter().any(|fact| {
                        fact.role == "review_admission_helper_context" && fact.symbol == *handler
                    })
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
                    "helper_definition_context" | "captured_definition_context"
                ) && fact.symbol == helper
            }) {
                Vec::new()
            } else {
                vec![format!(
                    "Does exact helper `{helper}` produce the applicable server-authoritative price, quote, order amount, or catalog value for this financial effect, and where is the caller-supplied value compared and rejected before persistence?"
                )]
            }
        }
        _ => Vec::new(),
    }
}

pub(super) fn preferred_lookup_symbol(evidence: &[Evidence]) -> Option<String> {
    preferred_capture(
        evidence,
        &[
            "authority_helper",
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

pub(super) fn helper_facts(
    sources: &RepositorySources,
    group: &ObservationGroup,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if !group.evidence.iter().any(is_marker) {
        return (Vec::new(), false);
    }
    let Ok(anchor_file) = sources.file(&group.path) else {
        return (Vec::new(), false);
    };
    let handlers = group
        .evidence
        .iter()
        .flat_map(|item| item.captures.iter())
        .filter(|(name, _)| name.starts_with("related_handler_"))
        .map(|(_, capture)| capture.text.as_str())
        .collect::<BTreeSet<_>>();
    let mut facts = Vec::new();
    for handler in handlers {
        for file in sources
            .files
            .values()
            .filter(|file| file.language == anchor_file.language)
            .filter(|file| !is_generic_mutation_reference(&handler) || file.path == group.path)
            .filter(|file| file.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES)
        {
            let spans = line_spans(&file.source);
            for (line_index, (start, end)) in spans.iter().copied().enumerate() {
                if authorization_definition_identifier(&file.source[start..end]).as_deref()
                    != Some(handler)
                {
                    continue;
                }
                let end_index = textual_definition_end_with_limit(
                    &file.source,
                    &spans,
                    line_index,
                    MAX_REVIEW_HELPER_LINES,
                );
                let location =
                    location_from_offsets(&file.path, &file.source, start, spans[end_index].1);
                if facts_cover_location(existing, &location)
                    || facts_cover_location(&facts, &location)
                {
                    continue;
                }
                if facts.len() == limit {
                    return (facts, true);
                }
                facts.push(ReviewNeighborhoodFact {
                    role: "review_admission_helper_context".to_string(),
                    symbol: handler.to_string(),
                    location,
                    excerpt: file.source[start..spans[end_index].1].to_string(),
                    evidence_id: group.anchor_evidence_ids.first().cloned(),
                    provenance: textual_provenance(
                        "bounded exact review-admission helper definition, lexical non-flow 1",
                    ),
                });
            }
        }
    }
    (facts, false)
}

fn server_mutation_review_marker(
    file: &SourceFile,
    spans: &[(usize, usize)],
    line_index: usize,
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
        Language::Csharp | Language::Java | Language::Python => {
            attributed_server_mutation_marker(file, spans, line_index, line)
        }
        Language::Kotlin => kotlin_server_mutation_marker(file, spans, line_index, line),
        Language::Javascript | Language::Typescript | Language::Tsx => {
            javascript_server_mutation_marker(file, spans, line_index, line)
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
        Language::Csharp => ["[HttpPost", "[HttpPut", "[HttpPatch", "[HttpDelete"]
            .iter()
            .any(|prefix| line.starts_with(prefix)),
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
                || (file.source.contains("rest_framework")
                    && [
                        "def create(",
                        "def update(",
                        "def destroy(",
                        "def partial_update(",
                    ]
                    .iter()
                    .any(|prefix| line.starts_with(prefix)))
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
) -> Option<ServerMutationMarker> {
    if ["@Post(", "@Put(", "@Patch(", "@Delete(", "@Mutation("]
        .iter()
        .any(|prefix| line.starts_with(prefix))
    {
        return marker_after_boundary(file, spans, line_index, 8);
    }

    if javascript_http_mutation_route(line) {
        let symbol =
            http_mutation_symbol(line).unwrap_or_else(|| "HTTP mutation route".to_string());
        return marker_from_inline_boundary(file, spans, line_index, &symbol);
    }

    if (file.source.contains("'use server'") || file.source.contains("\"use server\""))
        && (line.contains("validatedActionWithUser(")
            || line.contains("withTeam(")
            || (line.starts_with("export async function ") && mutation_effect(line).is_some()))
    {
        return marker_from_inline_boundary(file, spans, line_index, "server-action");
    }

    if line.contains(": async")
        && javascript_inside_mutation_object(&file.source, start_of(spans, line_index))
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
    let end_index = textual_definition_end_with_limit(&file.source, spans, line_index, 120);
    let excerpt = &file.source[spans[line_index].0..spans[end_index].1];
    let mut handlers = terminal_call_identifiers(excerpt, "");
    let boundary_line = &file.source[spans[line_index].0..spans[line_index].1];
    let route_handler = terminal_route_handler(boundary_line);
    if let Some(handler) = route_handler.as_ref()
        && !handlers.contains(handler)
    {
        handlers.insert(0, handler.clone());
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

fn terminal_route_handler(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if lower.contains(".route(") {
        for verb in ["post(", "put(", "patch(", "delete("] {
            let Some(start) = lower.rfind(verb).map(|start| start + verb.len()) else {
                continue;
            };
            let candidate = line[start..]
                .split(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
                })
                .find(|token| is_helpful_reference_identifier(token));
            if let Some(candidate) = candidate {
                return Some(candidate.to_string());
            }
        }
    }
    let tail = line.rsplit_once(',')?.1;
    let candidate = tail
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        })
        .find(|token| {
            is_helpful_reference_identifier(token)
                && !matches!(
                    token.to_ascii_lowercase().as_str(),
                    "post"
                        | "put"
                        | "patch"
                        | "delete"
                        | "request"
                        | "reply"
                        | "async"
                        | "function"
                )
        })?;
    Some(candidate.to_string())
}

fn javascript_http_mutation_route(line: &str) -> bool {
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
