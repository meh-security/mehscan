use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceKind, FixedOutputFormat,
    Language, Location, Position, ProtectionApplication, ReachabilityState, RelationContract,
    RelationStrategy, RuntimeEnvironment, SecurityPath, SecurityPathProvenance, SecurityPathState,
    SecurityPathStep, SecurityPathStepKind,
};

use super::csharp_handoff::FORWARDED_PARAMETER_RULE_ID;
use super::csharp_ingress::{CONTROLLER_RULE_ID, MINIMAL_RULE_ID};
use super::csharp_rpc::{GRPC_RULE_ID, SIGNALR_RULE_ID, WCF_RULE_ID};
use super::java_context::FORWARDED_PARAMETER_RULE_ID as JAVA_FORWARDED_PARAMETER_RULE_ID;
use super::java_ingress::{SPRING_MULTIPART_RULE_ID, SPRING_PARAMETER_RULE_ID};
use super::symbols::FileSymbolEnvironment;

const MAX_PROPAGATION_DEPTH: usize = 4;

#[derive(Clone)]
struct Assignment<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    left: String,
    right: Node<'tree, StrDoc<SupportLang>>,
    in_control_flow: bool,
}

#[derive(Clone)]
struct TrackedValue {
    depth: usize,
    steps: Vec<SecurityPathStep>,
}

pub(crate) fn build_security_paths(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    evidence: &[Evidence],
    symbols: &FileSymbolEnvironment,
    relations: &[RelationContract],
) -> Vec<SecurityPath> {
    let mut paths = Vec::new();
    for relation in relations {
        match relation.strategy {
            RelationStrategy::BoundedLocalValue => paths.extend(build_family_paths(
                path, root, language, evidence, symbols, relation,
            )),
            RelationStrategy::StoredSubtitleFile => paths.extend(build_stored_subtitle_html_paths(
                path, root, language, evidence, relation,
            )),
        }
    }
    let mut deduplicated: Vec<SecurityPath> = Vec::new();
    for candidate in paths {
        let duplicate = deduplicated.iter().position(|existing| {
            existing.state == candidate.state
                && existing.sink_evidence_id == candidate.sink_evidence_id
                && existing.capability == candidate.capability
                && existing.cwe_candidates == candidate.cwe_candidates
                && nested_source_locations(existing, &candidate)
        });
        if let Some(index) = duplicate {
            if source_location_width(&candidate) > source_location_width(&deduplicated[index]) {
                deduplicated[index] = candidate;
            }
        } else {
            deduplicated.push(candidate);
        }
    }
    deduplicated.sort_by(|left, right| left.id.cmp(&right.id));
    deduplicated
}

fn nested_source_locations(left: &SecurityPath, right: &SecurityPath) -> bool {
    let Some(left) = left.steps.first().map(|step| &step.location) else {
        return false;
    };
    let Some(right) = right.steps.first().map(|step| &step.location) else {
        return false;
    };
    left.path == right.path
        && (contains_range(location_range(left), location_range(right))
            || contains_range(location_range(right), location_range(left)))
}

fn source_location_width(path: &SecurityPath) -> usize {
    path.steps.first().map_or(0, |step| {
        step.location.end.byte_offset - step.location.start.byte_offset
    })
}

fn build_stored_subtitle_html_paths(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    evidence: &[Evidence],
    relation: &RelationContract,
) -> Vec<SecurityPath> {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        return Vec::new();
    }
    let sources = evidence.iter().filter(|item| {
        item.kind == EvidenceKind::Source
            && relation.source.accepts(item.capability)
            && item
                .provenance
                .engine
                .ends_with("local-subtitle-file-source")
            && !is_definitely_unreachable(item)
    });
    let sinks = evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == relation.sink.capability
                && !is_definitely_unreachable(item)
        })
        .collect::<Vec<_>>();
    let mut paths = Vec::new();
    for source in sources {
        let Some(source_node) = smallest_node_containing(root, location_range(&source.location))
        else {
            continue;
        };
        for sink in &sinks {
            let Some(content) = sink.captures.get("content") else {
                continue;
            };
            let Some(target_node) =
                smallest_node_containing(root, location_range(&content.location))
            else {
                continue;
            };
            let scope = scope_range(&target_node, root);
            if scope_range(&source_node, root) != scope {
                continue;
            }
            let Some(path_steps) = stored_subtitle_html_steps(
                path,
                root,
                language,
                source,
                &source_node,
                &target_node,
                &scope,
            ) else {
                continue;
            };
            let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
            steps.extend(path_steps);
            steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
            push_path(
                &mut paths,
                source,
                sink,
                SecurityPathState::Unknown,
                steps,
                &[],
                relation,
            );
            if let Some(path) = paths.last_mut() {
                path.uncertainty_reasons
                    .push("stored_file_to_html_flow_is_syntactic".to_string());
            }
        }
    }
    paths
}

#[allow(clippy::too_many_arguments)]
fn stored_subtitle_html_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source: &Evidence,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    target_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    if source.related_evidence.len() != 1 {
        return None;
    }
    let assignments = assignments_in_scope(root, language, scope);
    let source_assignment = assignments.iter().find(|assignment| {
        contains_range(assignment.right.range(), source_node.range())
            && assignment.node.range().end <= target_node.range().start
    })?;
    let target_text = target_node.text();
    let target_binding = simple_identifier(target_text.trim())?;
    let injection = assignments.iter().find(|assignment| {
        if assignment.left != target_binding
            || assignment.node.range().start <= source_assignment.node.range().end
            || assignment.node.range().end > target_node.range().start
            || !identifiers(&assignment.right).contains(&source_assignment.left)
        {
            return false;
        }
        let right = assignment.right.text();
        let compact = right
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        compact.starts_with(&format!("{target_binding}.replace("))
            && right.contains("<script id=\"subtitle\"></script>")
            && right.contains("type=\"text/vtt\"")
            && right.contains("data-label=\"English\"")
            && right.contains("</script>")
    })?;
    if assignments.iter().any(|assignment| {
        assignment.left == source_assignment.left
            && assignment.node.range().start > source_assignment.node.range().end
            && assignment.node.range().start < injection.node.range().start
    }) || assignments.iter().any(|assignment| {
        assignment.left == target_binding
            && assignment.node.range().start > injection.node.range().end
            && assignment.node.range().start < target_node.range().start
    }) || !lexical_if_try_path_is_prefix(&source_assignment.node, &injection.node, scope)
        || !lexical_if_try_path_is_prefix(&injection.node, target_node, scope)
    {
        return None;
    }
    Some(vec![
        SecurityPathStep {
            kind: SecurityPathStepKind::Assignment,
            location: node_location(path, &source_assignment.node),
            evidence_id: None,
            symbol: Some(source_assignment.left.clone()),
        },
        SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: node_location(path, &injection.node),
            evidence_id: None,
            symbol: Some(format!("{target_binding} via subtitle script replacement")),
        },
    ])
}

fn build_family_paths(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    evidence: &[Evidence],
    symbols: &FileSymbolEnvironment,
    family: &RelationContract,
) -> Vec<SecurityPath> {
    let sources = evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Source
                && family.source.accepts(item.capability)
                && !is_definitely_unreachable(item)
        })
        .collect::<Vec<_>>();
    let sinks = evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == family.sink.capability
                && (!is_identity_boundary_relation(family)
                    || item
                        .provenance
                        .engine
                        .ends_with("bounded-node-identity-boundary")
                    || item.rule_id == "go-cookie-authenticated-state-change-review"
                    || is_csharp_crypto_policy(item))
                && !(family.sink.capability == Capability::OutboundNetworkRequest
                    && item.context.runtime_environment == Some(RuntimeEnvironment::Browser))
                && !is_definitely_unreachable(item)
        })
        .collect::<Vec<_>>();
    let protections = family
        .protection
        .as_ref()
        .map(|protection| {
            evidence
                .iter()
                .filter(|item| {
                    matches!(
                        item.kind,
                        EvidenceKind::Sanitizer | EvidenceKind::Validation
                    ) && !is_definitely_unreachable(item)
                        // These PHP APIs retain useful control evidence but do
                        // not establish output-context safety or containment.
                        && !matches!(item.rule_id.as_str(), "php-html-encoding" | "php-path-canonicalization")
                        && (item.capability == protection.capability
                            || (family.sink.capability == Capability::Redirect
                                && item.capability == Capability::RedirectDestinationValidation)
                            || (matches!(
                                family.sink.capability,
                                Capability::FilesystemRead | Capability::FilesystemWrite
                            ) && item.capability == Capability::PathContainmentCheck))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut paths = Vec::new();
    for sink in sinks {
        if family.id.starts_with("cwe-79-")
            && sink.tags.iter().any(|tag| tag == "pug-output:escaped")
        {
            continue;
        }
        if family.sink.capability == Capability::ResourceAccess
            && sink.context.resource_policy.as_ref().is_some_and(|policy| {
                matches!(
                    policy.state,
                    mehscan_core::ResourcePolicyState::OwnerScoped
                        | mehscan_core::ResourcePolicyState::PublicCatalog
                        | mehscan_core::ResourcePolicyState::SharedResource
                )
            })
        {
            continue;
        }
        let target_nodes = family
            .sink
            .input_roles
            .iter()
            .filter_map(|name| {
                let capture = sink.captures.get(name)?;
                let node = smallest_node_containing(root, location_range(&capture.location))?;
                Some((capture, node))
            })
            .collect::<Vec<_>>();
        let Some((_, first_target)) = target_nodes.first() else {
            continue;
        };
        // Native PHP controls may preserve a reviewed input, but an arbitrary
        // helper's return value needs a summary. Keep its sink as an observation.
        if language == Language::Php
            && target_nodes.iter().any(|(_, target)| {
                target.dfs().any(|call| {
                    matches!(
                        call.kind().as_ref(),
                        "function_call_expression" | "member_call_expression"
                    ) && !evidence.iter().any(|item| {
                        matches!(
                            item.kind,
                            EvidenceKind::Sanitizer | EvidenceKind::Validation
                        ) && location_range(&item.location) == call.range()
                    })
                })
            })
        {
            continue;
        }
        let sink_scope = scope_range(first_target, root);
        let sink_in_control_flow = target_nodes
            .iter()
            .any(|(_, node)| has_control_flow_ancestor(node, &sink_scope));
        let attached_protections = protections
            .iter()
            .copied()
            .filter(|protection| protection_belongs_to_sink(root, protection, sink, family))
            .collect::<Vec<_>>();

        for source in &sources {
            if family.id == "cwe-79-browser-input-to-html-output"
                && !sink.rule_id.contains("browser-dom-html-output")
                && !sink.rule_id.contains("react-dangerous-html-output")
                && !sink.rule_id.contains("url-attribute-output")
                && !sink.rule_id.contains("angular-html-trust-bypass")
            {
                continue;
            }
            if family.id == "cwe-79-stored-content-to-html-output"
                && !source
                    .provenance
                    .engine
                    .ends_with("bounded-angular-rxjs-summary")
                && !source
                    .provenance
                    .engine
                    .ends_with("bounded-mongo-callback-result-summary")
                && source.rule_id != "go-ldap-result-value-source"
            {
                continue;
            }
            if source
                .provenance
                .engine
                .ends_with("bounded-node-identity-boundary")
                && !sink
                    .provenance
                    .engine
                    .ends_with("bounded-node-identity-boundary")
            {
                continue;
            }
            if is_csharp_crypto_policy(source) && !is_csharp_crypto_policy(sink) {
                continue;
            }
            if sink
                .provenance
                .engine
                .ends_with("bounded-node-object-input")
                && sink.related_evidence.as_slice() != [source.id.as_str()]
            {
                continue;
            }
            if sink
                .provenance
                .engine
                .ends_with("bounded-password-lifecycle")
                && sink.related_evidence.as_slice() != [source.id.as_str()]
            {
                continue;
            }
            if sink
                .provenance
                .engine
                .ends_with("bounded-node-identity-boundary")
                && (sink.related_evidence.as_slice() != [source.id.as_str()]
                    || sink.cwe_candidates != family.cwe_candidates)
            {
                continue;
            }
            if is_csharp_crypto_policy(sink)
                && (sink.related_evidence.as_slice() != [source.id.as_str()]
                    || sink.cwe_candidates != family.cwe_candidates)
            {
                continue;
            }
            if sink
                .provenance
                .engine
                .ends_with("dynamic-sensitive-response-field")
                && sink.related_evidence.as_slice() != [source.id.as_str()]
            {
                continue;
            }
            if sink.provenance.engine.ends_with("bounded-node-file-roles")
                && sink.related_evidence.as_slice() != [source.id.as_str()]
            {
                continue;
            }
            if sink.provenance.engine.ends_with("bounded-node-policy")
                && sink.related_evidence.as_slice() != [source.id.as_str()]
            {
                continue;
            }
            if sink.rule_id == "go-cookie-authenticated-state-change-review"
                && sink.related_evidence.as_slice() != [source.id.as_str()]
            {
                continue;
            }
            let source_range = location_range(&source.location);
            let Some(source_node) = smallest_node_containing(root, source_range.clone()) else {
                continue;
            };
            let source_scope = scope_range(&source_node, root);
            if sink.rule_id.ends_with("postgres-query")
                && sink.captures.get("query").is_some_and(|query| {
                    contains_range(location_range(&query.location), source_range.clone())
                })
            {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(
                    attached_protections
                        .iter()
                        .map(|item| evidence_step(SecurityPathStepKind::Protection, item)),
                );
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    if attached_protections.is_empty() {
                        SecurityPathState::Direct
                    } else {
                        SecurityPathState::Protected
                    },
                    steps,
                    &attached_protections,
                    family,
                );
                continue;
            }
            if source_scope != sink_scope {
                let closure_steps = (matches!(
                    language,
                    Language::Javascript | Language::Typescript | Language::Tsx
                ) && family.sink.capability == Capability::DatabaseQuery
                    && contains_range(source_scope.clone(), sink_scope.clone()))
                .then(|| {
                    target_nodes.iter().find_map(|(_, target)| {
                        value_preserving_sql_steps(
                            path,
                            root,
                            language,
                            &source_node,
                            target,
                            &source_scope,
                        )
                    })
                })
                .flatten();
                if let Some(path_steps) = closure_steps {
                    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                    steps.extend(path_steps);
                    steps.extend(
                        attached_protections
                            .iter()
                            .map(|item| evidence_step(SecurityPathStepKind::Protection, item)),
                    );
                    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                    push_path(
                        &mut paths,
                        source,
                        sink,
                        if attached_protections.is_empty() {
                            SecurityPathState::Propagated
                        } else {
                            SecurityPathState::Protected
                        },
                        steps,
                        &attached_protections,
                        family,
                    );
                    if let Some(path) = paths.last_mut() {
                        path.uncertainty_reasons
                            .push("node_lexical_closure_capture_is_syntactic".to_string());
                    }
                }
                continue;
            }
            if let Some(path_steps) =
                go_text_template_steps(path, root, language, &source_node, sink, &sink_scope)
            {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Propagated,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("go_text_template_model_binding_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) = object_input_steps(source, sink) {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("node_object_input_relationship_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) = go_formatted_html_steps(source, sink) {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("go_fmt_trusted_html_summary_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) = password_lifecycle_steps(source, sink) {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("password_lifecycle_relationship_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) = identity_boundary_steps(source, sink) {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("node_identity_boundary_relationship_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) = csharp_privilege_assignment_steps(source, sink) {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("csharp_privilege_assignment_relationship_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) = file_role_steps(source, sink) {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("node_file_role_relationship_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) = node_policy_steps(source, sink) {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("node_policy_relationship_is_syntactic".to_string());
                }
                continue;
            }
            if let Some(path_steps) =
                java_stored_process_steps(path, root, source, &source_node, sink, &sink_scope)
            {
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(path_steps);
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    SecurityPathState::Unknown,
                    steps,
                    &[],
                    family,
                );
                if let Some(path) = paths.last_mut() {
                    path.uncertainty_reasons
                        .push("java_stored_property_origin_is_syntactic".to_string());
                    path.uncertainty_reasons
                        .push("shell_helper_summary_is_project_local".to_string());
                }
                continue;
            }
            if has_fixed_format_sql_barrier(source, sink, family, evidence) {
                continue;
            }

            let source_in_control_flow = has_control_flow_ancestor(&source_node, &sink_scope);
            if source_in_control_flow || sink_in_control_flow {
                if sink.rule_id == "go-cookie-authenticated-state-change-review"
                    && sink.related_evidence.as_slice() == [source.id.as_str()]
                {
                    let steps = vec![
                        evidence_step(SecurityPathStepKind::Source, source),
                        evidence_step(SecurityPathStepKind::Sink, sink),
                    ];
                    push_path(
                        &mut paths,
                        source,
                        sink,
                        SecurityPathState::Unknown,
                        steps,
                        &[],
                        family,
                    );
                    if let Some(path) = paths.last_mut() {
                        path.uncertainty_reasons
                            .push("control_flow_context_not_modeled".to_string());
                    }
                    continue;
                }
                let specialized_direct = (family.source.accepts(Capability::ArchiveEntryPath)
                    || family.source.accepts(Capability::BrowserInput)
                    || family.sink.capability == Capability::ProcessExecution
                    || family.sink.capability == Capability::FileUpload
                    || (source
                        .provenance
                        .engine
                        .ends_with("bounded-serverless-boundary")
                        && matches!(
                            family.sink.capability,
                            Capability::OutboundNetworkRequest
                                | Capability::Redirect
                                | Capability::HtmlOutput
                        ))
                    || (sink.rule_id == "go-fprintf-http-html-output"
                        && matches!(
                            source.rule_id.as_str(),
                            "go-ldap-result-value-source"
                                | "go-http-form-map-value-source"
                                | "go-http-form-indexed-value-source"
                        )))
                    && target_nodes.iter().any(|(capture, _)| {
                        contains_range(location_range(&capture.location), source_range.clone())
                    });
                if specialized_direct {
                    let state = if attached_protections.is_empty() {
                        SecurityPathState::Direct
                    } else {
                        SecurityPathState::Protected
                    };
                    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                    steps.extend(
                        attached_protections
                            .iter()
                            .map(|item| evidence_step(SecurityPathStepKind::Protection, item)),
                    );
                    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                    push_path(
                        &mut paths,
                        source,
                        sink,
                        state,
                        steps,
                        &attached_protections,
                        family,
                    );
                    continue;
                }
                let lexical_path = angular_direct_steps(source, sink, &target_nodes)
                    .or_else(|| {
                        (language == Language::Php
                            && !source_is_conditional_predicate(&source_node))
                        .then(|| {
                            target_nodes.iter().find_map(|(_, target)| {
                                propagated_steps_with_options(
                                    path,
                                    root,
                                    language,
                                    &source_node,
                                    target,
                                    &sink_scope,
                                    false,
                                    true,
                                    false,
                                )
                            })
                        })
                        .flatten()
                    })
                    .or_else(|| dynamic_response_field_steps(source, sink))
                    .or_else(|| duplicate_key_resource_steps(source, sink))
                    .or_else(|| {
                        target_nodes
                            .iter()
                            .find_map(|(_, target_node)| {
                                bound_parameter_steps(
                                    path,
                                    root,
                                    language,
                                    source,
                                    target_node,
                                    &sink_scope,
                                    true,
                                )
                                .or_else(|| {
                                    express_pug_layout_steps(
                                        source,
                                        &source_node,
                                        sink,
                                        target_node,
                                        &sink_scope,
                                    )
                                })
                            })
                            .or_else(|| {
                                (matches!(
                                    family.sink.capability,
                                    Capability::OutboundNetworkRequest
                                        | Capability::Redirect
                                        | Capability::ResourceAccess
                                        | Capability::XmlParsing
                                ) || (language == Language::Python
                                    && matches!(
                                        family.sink.capability,
                                        Capability::DatabaseQuery
                                            | Capability::FilesystemRead
                                            | Capability::FilesystemWrite
                                            | Capability::ProcessExecution
                                            | Capability::DynamicCodeExecution
                                            | Capability::TemplateEvaluation
                                            | Capability::Deserialization
                                            | Capability::HtmlOutput
                                    ))
                                    || (family.sink.capability == Capability::HtmlOutput
                                        && matches!(
                                            sink.rule_id.as_str(),
                                            "go-request-fmt-to-trusted-html"
                                                | "go-fprintf-http-html-output"
                                        ))
                                    || (family.sink.capability == Capability::LdapQuery
                                        && sink.rule_id == "go-ldap-filter-query-summary")
                                    || (family.sink.capability == Capability::DatabaseQuery
                                        && sink.rule_id == "go-sql-parameter-query-summary")
                                    || (language == Language::Rust
                                        && family.sink.capability == Capability::DatabaseQuery)
                                    || (family.source.accepts(Capability::ArchiveEntryPath)
                                        && family.sink.capability == Capability::FilesystemWrite))
                                    .then(|| {
                                        target_nodes.iter().find_map(|(_, target_node)| {
                                            if language == Language::Go
                                                && matches!(
                                                    sink.rule_id.as_str(),
                                                    "go-fprintf-http-html-output"
                                                        | "go-ldap-filter-query-summary"
                                                )
                                            {
                                                go_uncertain_control_flow_steps(
                                                    path,
                                                    root,
                                                    language,
                                                    &source_node,
                                                    target_node,
                                                    &sink_scope,
                                                )
                                            } else {
                                                lexical_control_flow_steps(
                                                    path,
                                                    root,
                                                    language,
                                                    &source_node,
                                                    target_node,
                                                    &sink_scope,
                                                )
                                            }
                                        })
                                    })
                                    .flatten()
                            })
                            .or_else(|| {
                                (source.rule_id.contains("angular-route-data")
                                    && sink.rule_id.contains("angular-html-trust-bypass"))
                                .then(|| {
                                    target_nodes.iter().find_map(|(_, target_node)| {
                                        client_html_control_flow_steps(
                                            path,
                                            root,
                                            language,
                                            &source_node,
                                            target_node,
                                            &sink_scope,
                                        )
                                    })
                                })
                                .flatten()
                            })
                    });
                let (path_steps, embedded_program_resolution) = if let Some(steps) = lexical_path {
                    (Some(steps), false)
                } else {
                    (
                        stored_dynamic_code_steps(
                            path,
                            root,
                            language,
                            source,
                            &source_node,
                            sink,
                            &sink_scope,
                        )
                        .or_else(|| {
                            embedded_evaluator_steps(
                                path,
                                root,
                                language,
                                symbols,
                                &source_node,
                                sink,
                                &sink_scope,
                            )
                        })
                        .or_else(|| {
                            embedded_deserialization_steps(
                                path,
                                root,
                                language,
                                symbols,
                                &source_node,
                                sink,
                                &sink_scope,
                            )
                        }),
                        source.capability != Capability::StoredUserContent,
                    )
                };
                if let Some(path_steps) = path_steps {
                    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                    steps.extend(path_steps);
                    steps.extend(
                        attached_protections
                            .iter()
                            .map(|item| evidence_step(SecurityPathStepKind::Protection, item)),
                    );
                    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                    let state = if attached_protections.is_empty() {
                        SecurityPathState::Unknown
                    } else {
                        SecurityPathState::Protected
                    };
                    push_path(
                        &mut paths,
                        source,
                        sink,
                        state,
                        steps,
                        &attached_protections,
                        family,
                    );
                    if let Some(path) = paths.last_mut() {
                        let uncertainty = if attached_protections.is_empty() {
                            "control_flow_context_not_modeled"
                        } else if family.sink.capability == Capability::Redirect {
                            "redirect_validation_guard_is_syntactic"
                        } else {
                            "value_transform_protection_is_syntactic"
                        };
                        path.uncertainty_reasons.push(uncertainty.to_string());
                        if embedded_program_resolution {
                            path.uncertainty_reasons
                                .push("embedded_program_resolution_is_syntactic".to_string());
                        }
                        if sink
                            .provenance
                            .engine
                            .ends_with("duplicate-key-object-mutation")
                        {
                            path.uncertainty_reasons
                                .push("duplicate_key_object_mutation_is_syntactic".to_string());
                        }
                        if sink
                            .provenance
                            .engine
                            .ends_with("dynamic-sensitive-response-field")
                        {
                            path.uncertainty_reasons
                                .push("dynamic_response_field_exposure_is_syntactic".to_string());
                        }
                    }
                }
                continue;
            }

            let applicable_protections = if family.sink.capability == Capability::Redirect {
                let mut applicable = protections
                    .iter()
                    .copied()
                    .filter(|protection| {
                        protection.capability == Capability::UrlParsing
                            && (contains_range(
                                location_range(&protection.location),
                                source_range.clone(),
                            ) || protection_contains_bound_parameter(
                                root, source, protection, family,
                            ))
                    })
                    .collect::<Vec<_>>();
                applicable.extend(attached_protections.iter().copied());
                applicable.sort_by(|left, right| left.id.cmp(&right.id));
                applicable.dedup_by(|left, right| left.id == right.id);
                applicable
            } else if family.protection.as_ref().is_some_and(|protection| {
                protection.application == ProtectionApplication::ValueTransform
            }) {
                protections
                    .iter()
                    .copied()
                    .filter(|protection| {
                        contains_range(location_range(&protection.location), source_range.clone())
                            || protection_contains_bound_parameter(root, source, protection, family)
                            || (language == Language::Python
                                && python_protection_follows_source(
                                    path,
                                    root,
                                    &source_node,
                                    protection,
                                    family,
                                    &sink_scope,
                                ))
                            || (language == Language::Rust
                                && family.protection.as_ref().is_some_and(|contract| {
                                    contract.value_roles.iter().any(|role| {
                                        protection.captures.get(role).is_some_and(|value| {
                                            rust_protection_follows_source(
                                                path,
                                                root,
                                                &source_node,
                                                value,
                                                &sink_scope,
                                            )
                                        })
                                    })
                                }))
                    })
                    .collect::<Vec<_>>()
            } else {
                attached_protections.clone()
            };
            let direct = target_nodes.iter().any(|(capture, _)| {
                contains_range(location_range(&capture.location), source_range.clone())
            });
            let protected_parameter = applicable_protections.iter().any(|protection| {
                family.protection.as_ref().is_some_and(|contract| {
                    contract.value_roles.iter().any(|capture| {
                        protection.captures.get(capture).is_some_and(|value| {
                            contains_range(location_range(&value.location), source_range.clone())
                                || capture_contains_bound_parameter(root, source, value)
                                || (language == Language::Rust
                                    && rust_protection_follows_source(
                                        path,
                                        root,
                                        &source_node,
                                        value,
                                        &sink_scope,
                                    ))
                        })
                    })
                })
            });
            if direct || protected_parameter {
                let state = if applicable_protections.is_empty() {
                    SecurityPathState::Direct
                } else {
                    SecurityPathState::Protected
                };
                let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
                steps.extend(
                    applicable_protections
                        .iter()
                        .map(|item| evidence_step(SecurityPathStepKind::Protection, item)),
                );
                steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
                push_path(
                    &mut paths,
                    source,
                    sink,
                    state,
                    steps,
                    &applicable_protections,
                    family,
                );
                continue;
            }

            let path_steps = target_nodes
                .iter()
                .find_map(|(_, target_node)| {
                    propagated_steps(path, root, language, &source_node, target_node, &sink_scope)
                        .or_else(|| {
                            (source.rule_id.contains("angular-route-data")
                                && sink.rule_id.contains("angular-html-trust-bypass"))
                            .then(|| {
                                client_html_control_flow_steps(
                                    path,
                                    root,
                                    language,
                                    &source_node,
                                    target_node,
                                    &sink_scope,
                                )
                            })
                            .flatten()
                        })
                        .or_else(|| {
                            (family.sink.capability == Capability::DatabaseQuery)
                                .then(|| {
                                    value_preserving_sql_steps(
                                        path,
                                        root,
                                        language,
                                        &source_node,
                                        target_node,
                                        &sink_scope,
                                    )
                                })
                                .flatten()
                        })
                        .or_else(|| {
                            bound_parameter_steps(
                                path,
                                root,
                                language,
                                source,
                                target_node,
                                &sink_scope,
                                false,
                            )
                        })
                })
                .or_else(|| {
                    stored_dynamic_code_steps(
                        path,
                        root,
                        language,
                        source,
                        &source_node,
                        sink,
                        &sink_scope,
                    )
                    .or_else(|| {
                        embedded_evaluator_steps(
                            path,
                            root,
                            language,
                            symbols,
                            &source_node,
                            sink,
                            &sink_scope,
                        )
                    })
                    .or_else(|| {
                        embedded_deserialization_steps(
                            path,
                            root,
                            language,
                            symbols,
                            &source_node,
                            sink,
                            &sink_scope,
                        )
                    })
                });
            let Some(path_steps) = path_steps else {
                continue;
            };
            let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
            steps.extend(path_steps);
            steps.extend(
                applicable_protections
                    .iter()
                    .map(|item| evidence_step(SecurityPathStepKind::Protection, item)),
            );
            steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
            let state = if applicable_protections.is_empty() {
                SecurityPathState::Propagated
            } else {
                SecurityPathState::Protected
            };
            push_path(
                &mut paths,
                source,
                sink,
                state,
                steps,
                &applicable_protections,
                family,
            );
        }
    }
    paths
}

fn rust_protection_follows_source(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    value: &Capture,
    scope: &Range<usize>,
) -> bool {
    smallest_node_containing(root, location_range(&value.location)).is_some_and(|target| {
        propagated_steps_with_options(
            path,
            root,
            Language::Rust,
            source_node,
            &target,
            scope,
            false,
            false,
            false,
        )
        .is_some()
    })
}

fn go_text_template_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    if language != Language::Go || sink.rule_id != "go-text-template-html-output" {
        return None;
    }
    let content = sink.captures.get("content")?.text.trim();
    let content = simple_identifier(content)?;
    let assignments = assignments_in_scope(root, language, scope);
    let source_assignment = assignments.iter().find(|assignment| {
        contains_range(assignment.right.range(), source_node.range())
            && assignment.node.range().end <= sink.location.start.byte_offset
    })?;
    let model_assignment = assignments.iter().find(|assignment| {
        assignment.left == content
            && assignment.node.range().start >= source_assignment.node.range().end
            && assignment.node.range().end <= sink.location.start.byte_offset
            && identifiers(&assignment.right).contains(&source_assignment.left)
    })?;
    Some(vec![
        SecurityPathStep {
            kind: SecurityPathStepKind::Assignment,
            location: node_location(path, &source_assignment.node),
            evidence_id: None,
            symbol: Some(source_assignment.left.clone()),
        },
        SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: node_location(path, &model_assignment.node),
            evidence_id: None,
            symbol: Some(format!("{content} text/template model")),
        },
    ])
}

fn go_formatted_html_steps(source: &Evidence, sink: &Evidence) -> Option<Vec<SecurityPathStep>> {
    if sink.rule_id != "go-request-fmt-to-trusted-html"
        || sink.capability != Capability::HtmlOutput
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    let formatted = sink.captures.get("formatted_output")?;
    Some(vec![SecurityPathStep {
        kind: SecurityPathStepKind::Alias,
        location: formatted.location.clone(),
        evidence_id: None,
        symbol: Some("request value formatted into trusted HTML".to_string()),
    }])
}

fn java_stored_process_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    source: &Evidence,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    if source.rule_id != "java-persisted-user-command-construction-source"
        || sink.rule_id != "java-proved-shell-helper-invocation"
        || source.related_evidence.is_empty()
        || source.provenance.engine != sink.provenance.engine
    {
        return None;
    }
    let command = sink.captures.get("command")?;
    let target = smallest_node_containing(root, location_range(&command.location))?;
    let target_text = target.text();
    let target_name = simple_identifier(target_text.trim())?;
    let assignment = source_node.ancestors().find(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node.range().start >= scope.start
            && node.range().end <= scope.end
            && node.range().end < target.range().start
            && node
                .field("name")
                .is_some_and(|name| name.text().as_ref() == target_name)
            && node
                .field("value")
                .is_some_and(|value| contains_range(value.range(), source_node.range()))
    })?;
    Some(vec![SecurityPathStep {
        kind: SecurityPathStepKind::Assignment,
        location: node_location(path, &assignment),
        evidence_id: None,
        symbol: Some(format!(
            "{target_name} from persisted user-controlled properties"
        )),
    }])
}

fn is_identity_boundary_relation(relation: &RelationContract) -> bool {
    matches!(
        relation.id.as_str(),
        "cwe-321-credential-to-hardcoded-jwt-signing"
            | "cwe-613-credential-to-session-lifecycle"
            | "cwe-613-credential-to-token-without-expiry"
            | "cwe-345-request-token-to-unverified-identity"
            | "cwe-347-request-token-to-jwt-verification"
            | "cwe-614-credential-to-cookie-transport"
            | "cwe-1004-credential-to-script-readable-cookie"
            | "cwe-352-cookie-request-to-state-change"
            | "cwe-942-origin-to-cors-policy"
            | "cwe-307-forwarded-address-to-rate-limit"
            | "cwe-640-reset-token-lifecycle"
    )
}

fn duplicate_key_resource_steps(
    source: &Evidence,
    sink: &Evidence,
) -> Option<Vec<SecurityPathStep>> {
    if sink.capability != Capability::ResourceAccess
        || !sink
            .provenance
            .engine
            .ends_with("duplicate-key-object-mutation")
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    let validated = sink.captures.get("validated_value")?;
    let persisted = sink.captures.get("persisted_value")?;
    Some(vec![
        SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: validated.location.clone(),
            evidence_id: None,
            symbol: Some("first duplicate-key value used by ownership check".to_string()),
        },
        SecurityPathStep {
            kind: SecurityPathStepKind::Assignment,
            location: persisted.location.clone(),
            evidence_id: None,
            symbol: Some("last duplicate-key value persisted".to_string()),
        },
    ])
}

fn file_role_steps(source: &Evidence, sink: &Evidence) -> Option<Vec<SecurityPathStep>> {
    if !sink.provenance.engine.ends_with("bounded-node-file-roles")
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    if sink.rule_id.contains("archive-raw-path-write") {
        let assignment = sink.captures.get("entry_assignment")?;
        let resolved = sink.captures.get("resolved_target")?;
        let containment = sink.captures.get("containment_check")?;
        let write = sink.captures.get("write_path")?;
        return Some(vec![
            contextual_step(
                SecurityPathStepKind::Assignment,
                assignment,
                "archive entry path assigned to local filename",
            ),
            contextual_step(
                SecurityPathStepKind::Alias,
                resolved,
                "canonical target computed but not used for the write",
            ),
            contextual_step(
                SecurityPathStepKind::IneffectiveProtection,
                containment,
                "substring containment check does not establish path containment",
            ),
            contextual_step(
                SecurityPathStepKind::Alias,
                write,
                "raw archive entry path selected as filesystem write target",
            ),
        ]);
    }
    if sink.rule_id.contains("poison-null-byte-send-file") {
        let suffix = sink.captures.get("suffix_check")?;
        let transform = sink.captures.get("null_byte_transform")?;
        let served = sink.captures.get("served_path")?;
        return Some(vec![
            contextual_step(
                SecurityPathStepKind::IneffectiveProtection,
                suffix,
                "file suffix checked before subsequent path transformation",
            ),
            contextual_step(
                SecurityPathStepKind::Alias,
                transform,
                "poison null byte removed after allowlist decision",
            ),
            contextual_step(
                SecurityPathStepKind::Alias,
                served,
                "post-transformation filename selected for sendFile",
            ),
        ]);
    }
    None
}

fn csharp_privilege_assignment_steps(
    source: &Evidence,
    sink: &Evidence,
) -> Option<Vec<SecurityPathStep>> {
    if !sink
        .provenance
        .engine
        .ends_with("bounded privilege assignment 1")
        || sink.rule_id != "csharp-request-controlled-role-assignment"
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    let decision = sink.captures.get("assigned_fields")?;
    let role = sink.captures.get("role")?;
    let mut steps = Vec::new();
    if let Some(client_guard) = sink.captures.get("client_authorization_guard") {
        steps.push(contextual_step(
            SecurityPathStepKind::IneffectiveProtection,
            client_guard,
            "request-bound model property cannot establish caller privilege",
        ));
    }
    steps.push(if let Some(assignment) = sink.captures.get("assignment") {
        contextual_step(
            SecurityPathStepKind::Assignment,
            assignment,
            "request-bound privilege value assigned to a persisted identity property",
        )
    } else {
        contextual_step(
            SecurityPathStepKind::Alias,
            decision,
            "request-bound decision controls administrative role assignment",
        )
    });
    steps.push(contextual_step(
        SecurityPathStepKind::Alias,
        role,
        "role selected for identity assignment",
    ));
    Some(steps)
}

fn node_policy_steps(source: &Evidence, sink: &Evidence) -> Option<Vec<SecurityPathStep>> {
    if !sink.provenance.engine.ends_with("bounded-node-policy")
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    if sink.rule_id.contains("plaintext-totp-storage") {
        let field = sink.captures.get("field")?;
        let persistence = sink.captures.get("persistence")?;
        return Some(vec![
            contextual_step(
                SecurityPathStepKind::Assignment,
                field,
                "TOTP secret assigned directly to persistent model field",
            ),
            contextual_step(
                SecurityPathStepKind::Alias,
                persistence,
                "model saved without an observed encryption transform",
            ),
        ]);
    }
    if sink.rule_id.contains("unbounded-coupon-operation") {
        let policy = sink.captures.get("prose_limit")?;
        let operation = sink.captures.get("operation")?;
        return Some(vec![
            contextual_step(
                SecurityPathStepKind::IneffectiveProtection,
                policy,
                "numeric limit exists in schema prose but not executable validation",
            ),
            contextual_step(
                SecurityPathStepKind::Alias,
                operation,
                "unbounded model tool argument reaches coupon generation",
            ),
        ]);
    }
    if sink.rule_id.contains("unencoded-log-message") {
        let message = sink.captures.get("message")?;
        return Some(vec![contextual_step(
            SecurityPathStepKind::Alias,
            message,
            "request-derived value reaches a rendered log argument without observed line-break encoding",
        )]);
    }
    None
}

fn contextual_step(
    kind: SecurityPathStepKind,
    capture: &Capture,
    symbol: &str,
) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: capture.location.clone(),
        evidence_id: None,
        symbol: Some(symbol.to_string()),
    }
}

fn angular_direct_steps(
    source: &Evidence,
    sink: &Evidence,
    target_nodes: &[(&Capture, Node<'_, StrDoc<SupportLang>>)],
) -> Option<Vec<SecurityPathStep>> {
    if !source
        .provenance
        .engine
        .ends_with("bounded-angular-rxjs-summary")
        || !sink.rule_id.contains("angular-html-trust-bypass")
    {
        return None;
    }
    let source_range = location_range(&source.location);
    target_nodes
        .iter()
        .any(|(capture, _)| contains_range(location_range(&capture.location), source_range.clone()))
        .then_some(Vec::new())
}

fn dynamic_response_field_steps(
    source: &Evidence,
    sink: &Evidence,
) -> Option<Vec<SecurityPathStep>> {
    if sink.capability != Capability::ResourceAccess
        || !sink
            .provenance
            .engine
            .ends_with("dynamic-sensitive-response-field")
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    let selected = sink.captures.get("selected_value")?;
    let response_assignment = sink.captures.get("response_assignment")?;
    let response = sink.captures.get("response")?;
    Some(vec![
        SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: selected.location.clone(),
            evidence_id: None,
            symbol: Some("request-selected authenticated-user field".to_string()),
        },
        SecurityPathStep {
            kind: SecurityPathStepKind::Assignment,
            location: response_assignment.location.clone(),
            evidence_id: None,
            symbol: Some("selected field added to response object".to_string()),
        },
        SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: response.location.clone(),
            evidence_id: None,
            symbol: Some("response object reaches Express JSON output".to_string()),
        },
    ])
}

fn password_lifecycle_steps(source: &Evidence, sink: &Evidence) -> Option<Vec<SecurityPathStep>> {
    if !sink
        .provenance
        .engine
        .ends_with("bounded-password-lifecycle")
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    let (capture, symbol) = match sink.capability {
        Capability::Authentication => (
            sink.captures.get("password_change")?,
            "password update accepted without a mandatory reauthentication control",
        ),
        Capability::CryptographicHash => (
            sink.captures.get("storage")?,
            "password reaches a weak or unresolved storage transform",
        ),
        _ => return None,
    };
    Some(vec![SecurityPathStep {
        kind: SecurityPathStepKind::Alias,
        location: capture.location.clone(),
        evidence_id: None,
        symbol: Some(symbol.to_string()),
    }])
}

fn identity_boundary_steps(source: &Evidence, sink: &Evidence) -> Option<Vec<SecurityPathStep>> {
    if !(sink
        .provenance
        .engine
        .ends_with("bounded-node-identity-boundary")
        || is_csharp_crypto_policy(sink))
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    let symbol = match sink.cwe_candidates.as_slice() {
        [cwe] if cwe == "CWE-321" => "hardcoded key reaches JWT signing",
        [cwe]
            if cwe == "CWE-345"
                && sink.rule_id == "csharp-unverified-sso-cookie-token-issuance" =>
        {
            "unsigned SSO cookie identity selects an account and reaches token issuance"
        }
        [cwe] if cwe == "CWE-345" => {
            "decoded JWT claims establish identity without signature verification"
        }
        [cwe] if cwe == "CWE-347" => {
            "request token reaches JWT verification without an explicit algorithm allowlist"
        }
        [cwe] if cwe == "CWE-613" => {
            "session or token lifecycle lacks a bounded expiry or invalidation control"
        }
        [cwe] if cwe == "CWE-614" => "authentication material reaches a cookie without Secure",
        [cwe] if cwe == "CWE-1004" => "authentication material reaches a cookie without HttpOnly",
        [cwe] if cwe == "CWE-352" => {
            "cookie-authenticated request reaches a state-changing operation without a recognized CSRF control"
        }
        [cwe] if cwe == "CWE-942" => "an untrusted request origin reaches a permissive CORS policy",
        [cwe] if cwe == "CWE-307" => {
            "attacker-controlled forwarded address selects the authentication rate-limit bucket"
        }
        [cwe] if cwe == "CWE-640" => {
            "a verified reset token reaches password reset without a recognized one-time consumption step"
        }
        _ => return None,
    };
    Some(vec![SecurityPathStep {
        kind: SecurityPathStepKind::Alias,
        location: sink.location.clone(),
        evidence_id: None,
        symbol: Some(symbol.to_string()),
    }])
}

fn object_input_steps(source: &Evidence, sink: &Evidence) -> Option<Vec<SecurityPathStep>> {
    if !sink
        .provenance
        .engine
        .ends_with("bounded-node-object-input")
        || sink.related_evidence.as_slice() != [source.id.as_str()]
    {
        return None;
    }
    let symbol = match sink.cwe_candidates.as_slice() {
        [cwe] if cwe == "CWE-943" => "request value reaches a NoSQL selector",
        [cwe] if cwe == "CWE-915" => {
            "request object reaches a model with security-sensitive writable fields"
        }
        [cwe] if cwe == "CWE-1321" => {
            "request-controlled key reaches a prototype-bearing dynamic write"
        }
        _ => return None,
    };
    let operation = sink.captures.get("operation")?;
    Some(vec![SecurityPathStep {
        kind: SecurityPathStepKind::Alias,
        location: operation.location.clone(),
        evidence_id: None,
        symbol: Some(symbol.to_string()),
    }])
}

fn has_fixed_format_sql_barrier(
    source: &Evidence,
    sink: &Evidence,
    family: &RelationContract,
    evidence: &[Evidence],
) -> bool {
    if family.sink.capability != Capability::DatabaseQuery {
        return false;
    }
    let source_range = location_range(&source.location);
    evidence.iter().any(|transform| {
        transform.kind == EvidenceKind::Sanitizer
            && transform.capability == Capability::FixedFormatTransform
            && transform.confidence == Confidence::High
            && transform
                .context
                .value_transform
                .as_ref()
                .is_some_and(|summary| {
                    summary.output_format == FixedOutputFormat::LowercaseHexadecimal
                        && summary.exact_length > 0
                })
            && transform.captures.get("value").is_some_and(|value| {
                contains_range(location_range(&value.location), source_range.clone())
            })
            && family.sink.input_roles.iter().any(|capture| {
                sink.captures.get(capture).is_some_and(|target| {
                    contains_range(
                        location_range(&target.location),
                        location_range(&transform.location),
                    )
                })
            })
    })
}

fn propagated_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    query_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    propagated_steps_with_options(
        path,
        root,
        language,
        source_node,
        query_node,
        scope,
        false,
        false,
        false,
    )
}

fn value_preserving_sql_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    query_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    if is_node_non_runtime_example_path(path) || source_is_conditional_predicate(source_node) {
        return None;
    }
    matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    )
    .then(|| {
        propagated_steps_with_options(
            path,
            root,
            language,
            source_node,
            query_node,
            scope,
            false,
            false,
            true,
        )
    })
    .flatten()
}

fn source_is_conditional_predicate(source_node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    source_node.ancestors().any(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "conditional_expression" | "ternary_expression"
        ) && ancestor
            .field("condition")
            .is_some_and(|condition| contains_range(condition.range(), source_node.range()))
    })
}

fn is_node_non_runtime_example_path(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.contains("/data/static/codefixes/") || path.starts_with("data/static/codefixes/")
}

fn bound_parameter_name(source: &Evidence) -> Option<&str> {
    matches!(
        source.rule_id.as_str(),
        CONTROLLER_RULE_ID
            | MINIMAL_RULE_ID
            | GRPC_RULE_ID
            | SIGNALR_RULE_ID
            | WCF_RULE_ID
            | FORWARDED_PARAMETER_RULE_ID
            | SPRING_PARAMETER_RULE_ID
            | SPRING_MULTIPART_RULE_ID
            | JAVA_FORWARDED_PARAMETER_RULE_ID
            | "typescript-nestjs-request-parameter"
            | "tsx-nestjs-request-parameter"
            | "typescript-express-request-binding-source"
            | "tsx-express-request-binding-source"
            | "rust-axum-request-extractor"
            | super::rust_context::RUST_WARP_PARAMETER_RULE_ID
            | super::rust_context::RUST_FORWARDED_PARAMETER_RULE_ID
            | super::rust_project::ACTIX_PARAMETER_RULE_ID
            | super::rust_project::ACTIX_FORWARDED_RULE_ID
            | super::native_drogon::DROGON_PARAMETER_RULE_ID
    )
    .then(|| source.captures.get("parameter"))
    .flatten()
    .map(|capture| capture.text.trim())
    .filter(|name| simple_identifier(name).is_some())
}

fn capture_contains_bound_parameter(
    root: &Node<'_, StrDoc<SupportLang>>,
    source: &Evidence,
    capture: &Capture,
) -> bool {
    let Some(name) = bound_parameter_name(source) else {
        return false;
    };
    smallest_node_containing(root, location_range(&capture.location))
        .is_some_and(|node| semantic_identifiers(&node).contains(name))
}

fn protection_contains_bound_parameter(
    root: &Node<'_, StrDoc<SupportLang>>,
    source: &Evidence,
    protection: &Evidence,
    family: &RelationContract,
) -> bool {
    if source
        .enclosing_symbol
        .as_ref()
        .zip(protection.enclosing_symbol.as_ref())
        .is_some_and(|(source_symbol, protection_symbol)| source_symbol != protection_symbol)
    {
        return false;
    }
    family.protection.as_ref().is_some_and(|contract| {
        contract.value_roles.iter().any(|role| {
            protection
                .captures
                .get(role)
                .is_some_and(|capture| capture_contains_bound_parameter(root, source, capture))
        })
    })
}

fn python_protection_follows_source(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    protection: &Evidence,
    family: &RelationContract,
    scope: &Range<usize>,
) -> bool {
    if family
        .protection
        .as_ref()
        .is_none_or(|contract| contract.capability != Capability::HtmlEncoding)
    {
        return false;
    }
    family.protection.as_ref().is_some_and(|contract| {
        contract.value_roles.iter().any(|role| {
            protection.captures.get(role).is_some_and(|capture| {
                smallest_node_containing(root, location_range(&capture.location)).is_some_and(
                    |target| {
                        propagated_steps_with_options(
                            path,
                            root,
                            Language::Python,
                            source_node,
                            &target,
                            scope,
                            false,
                            true,
                            false,
                        )
                        .is_some()
                    },
                )
            })
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn bound_parameter_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source: &Evidence,
    target_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    allow_lexical_control_flow: bool,
) -> Option<Vec<SecurityPathStep>> {
    let supported_parameter =
        matches!(language, Language::Csharp | Language::Java | Language::Rust)
            || (language == Language::Cpp
                && source.rule_id == super::native_drogon::DROGON_PARAMETER_RULE_ID)
            || (matches!(language, Language::Typescript | Language::Tsx)
                && matches!(
                    source.rule_id.as_str(),
                    "typescript-nestjs-request-parameter"
                        | "tsx-nestjs-request-parameter"
                        | "typescript-express-request-binding-source"
                        | "tsx-express-request-binding-source"
                ));
    if !supported_parameter || source.location.end.byte_offset > target_node.range().start {
        return None;
    }
    let parameter = bound_parameter_name(source)?.to_string();
    let initial_steps = if matches!(
        source.rule_id.as_str(),
        FORWARDED_PARAMETER_RULE_ID
            | JAVA_FORWARDED_PARAMETER_RULE_ID
            | super::rust_context::RUST_FORWARDED_PARAMETER_RULE_ID
            | super::rust_project::ACTIX_FORWARDED_RULE_ID
    ) {
        let call = source.captures.get("controller_call")?;
        vec![
            SecurityPathStep {
                kind: SecurityPathStepKind::Alias,
                location: call.location.clone(),
                evidence_id: None,
                symbol: Some(format!("controller call into {parameter}")),
            },
            SecurityPathStep {
                kind: SecurityPathStepKind::Assignment,
                location: source.location.clone(),
                evidence_id: None,
                symbol: Some(format!("unique callee parameter {parameter}")),
            },
        ]
    } else {
        Vec::new()
    };
    let mut tracked = BTreeMap::from([(
        parameter.clone(),
        TrackedValue {
            depth: 0,
            steps: initial_steps,
        },
    )]);

    for assignment in assignments_in_scope(root, language, scope)
        .iter()
        .filter(|assignment| {
            assignment.node.range().start >= source.location.end.byte_offset
                && assignment.node.range().end <= target_node.range().start
        })
    {
        if assignment.in_control_flow && !allow_lexical_control_flow && language != Language::Rust {
            continue;
        }
        let origin = projection_origin(&assignment.right, &tracked).or_else(|| {
            if language != Language::Rust {
                return None;
            }
            rust_assignment_origin(&assignment.right, &tracked).map(|(value, _)| value)
        });
        tracked.remove(&assignment.left);
        let Some(origin) = origin else {
            continue;
        };
        if origin.depth >= MAX_PROPAGATION_DEPTH {
            continue;
        }
        let mut steps = origin.steps;
        steps.push(SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: node_location(path, &assignment.node),
            evidence_id: None,
            symbol: Some(assignment.left.clone()),
        });
        tracked.insert(
            assignment.left.clone(),
            TrackedValue {
                depth: origin.depth + 1,
                steps,
            },
        );
    }

    let semantic_match = semantic_identifier_nodes(target_node)
        .into_iter()
        .filter_map(|identifier| {
            let name = identifier.text();
            tracked.get(name.trim()).map(|value| (value, identifier))
        })
        .min_by_key(|(value, identifier)| {
            (value.depth, value.steps.len(), identifier.range().start)
        })
        .map(|(value, identifier)| {
            let mut steps = value.steps.clone();
            if let Some(presence_check) =
                ineffective_redirect_presence_step(path, target_node, scope)
            {
                steps.push(presence_check);
            }
            steps.push(SecurityPathStep {
                kind: SecurityPathStepKind::Alias,
                location: node_location(path, &identifier),
                evidence_id: None,
                symbol: Some(format!(
                    "{}-bound parameter {parameter}",
                    if language == Language::Java {
                        "Spring MVC"
                    } else if matches!(language, Language::Typescript | Language::Tsx) {
                        "NestJS"
                    } else if language == Language::Rust {
                        "Rust HTTP extractor"
                    } else {
                        "ASP.NET"
                    }
                )),
            });
            steps
        });
    semantic_match.or_else(|| {
        let text = target_node.text();
        let compact = compact_expression(&text);
        if language != Language::Rust
            || !compact.starts_with("format!(")
            || !semantic_identifier_text(&text).contains(&parameter)
        {
            return None;
        }
        let value = tracked.get(&parameter)?;
        let mut steps = value.steps.clone();
        steps.push(SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: node_location(path, target_node),
            evidence_id: None,
            symbol: Some(format!("Rust format input {parameter}")),
        });
        Some(steps)
    })
}

fn ineffective_redirect_presence_step(
    path: &str,
    target: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<SecurityPathStep> {
    let invocation = target
        .ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
        .find(|ancestor| {
            if ancestor.kind().as_ref() != "invocation_expression" {
                return false;
            }
            let compact = compact_expression(ancestor.text().as_ref());
            compact.starts_with("Redirect(") || compact.contains(".Redirect(")
        })?;
    let target_text = compact_expression(target.text().as_ref());
    if target_text.is_empty() {
        return None;
    }
    let guard = invocation
        .ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
        .find(|ancestor| {
            ancestor.kind().as_ref() == "if_statement"
                && ancestor
                    .field("consequence")
                    .is_some_and(|branch| contains_range(branch.range(), invocation.range()))
        })?;
    let condition = guard.field("condition")?;
    let condition_text = compact_expression(condition.text().as_ref());
    let condition_text = condition_text.trim_start_matches('(').trim_end_matches(')');
    let presence_only = [
        format!("{target_text}!=null"),
        format!("null!={target_text}"),
        format!("{target_text}isnotnull"),
        format!("!string.IsNullOrEmpty({target_text})"),
        format!("!string.IsNullOrWhiteSpace({target_text})"),
    ]
    .iter()
    .any(|shape| condition_text == shape);
    presence_only.then(|| SecurityPathStep {
        kind: SecurityPathStepKind::IneffectiveProtection,
        location: node_location(path, &condition),
        evidence_id: None,
        symbol: Some("presence check does not constrain redirect destination".to_string()),
    })
}

fn projection_origin(
    expression: &Node<'_, StrDoc<SupportLang>>,
    tracked: &BTreeMap<String, TrackedValue>,
) -> Option<TrackedValue> {
    if expression.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "invocation_expression"
                | "object_creation_expression"
                | "binary_expression"
                | "conditional_expression"
                | "lambda_expression"
                | "assignment_expression"
        )
    }) {
        return None;
    }
    if !matches!(
        expression.kind().as_ref(),
        "identifier"
            | "member_access_expression"
            | "element_access_expression"
            | "conditional_access_expression"
    ) {
        return None;
    }
    semantic_identifiers(expression)
        .into_iter()
        .filter_map(|identifier| tracked.get(&identifier))
        .min_by_key(|value| (value.depth, value.steps.len()))
        .cloned()
}

fn lexical_control_flow_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    query_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    propagated_steps_with_options(
        path,
        root,
        language,
        source_node,
        query_node,
        scope,
        false,
        true,
        false,
    )
}

fn go_uncertain_control_flow_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    query_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    propagated_steps_with_options(
        path,
        root,
        language,
        source_node,
        query_node,
        scope,
        true,
        true,
        false,
    )
}

fn client_html_control_flow_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    query_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    propagated_steps_with_options(
        path,
        root,
        language,
        source_node,
        query_node,
        scope,
        true,
        true,
        false,
    )
}

fn express_pug_layout_steps(
    source: &Evidence,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    target_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    if sink.capability != Capability::FilesystemRead
        || !sink
            .provenance
            .engine
            .ends_with("express-pug-layout-options")
        || !sink
            .related_evidence
            .iter()
            .any(|evidence_id| evidence_id == &source.id)
        || !lexical_if_try_path_is_prefix(source_node, target_node, scope)
    {
        return None;
    }
    let request_body = sink.captures.get("path")?;
    Some(vec![SecurityPathStep {
        kind: SecurityPathStepKind::Alias,
        location: request_body.location.clone(),
        evidence_id: None,
        symbol: Some("req.body spread into render layout options".to_string()),
    }])
}

fn stored_dynamic_code_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source: &Evidence,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    let supported_pair = (matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) && sink.capability == Capability::DynamicCodeExecution)
        || (language == Language::Java && sink.capability == Capability::ProcessExecution);
    if source.capability != Capability::StoredUserContent || !supported_pair {
        return None;
    }
    let code = sink.captures.get("code")?;
    let query_node = smallest_node_containing(root, location_range(&code.location))?;
    propagated_steps_with_options(
        path,
        root,
        language,
        source_node,
        &query_node,
        scope,
        true,
        false,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn propagated_steps_with_options(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    query_node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    allow_controlled_string_extraction: bool,
    allow_lexical_control_flow: bool,
    allow_bounded_string_choice: bool,
) -> Option<Vec<SecurityPathStep>> {
    let assignments = assignments_in_scope(root, language, scope);
    let source_assignment = assignments.iter().find(|assignment| {
        contains_range(assignment.right.range(), source_node.range())
            && assignment.node.range().end <= query_node.range().start
            && (!assignment.in_control_flow
                || allow_controlled_string_extraction
                || (allow_lexical_control_flow
                    && lexical_path_is_prefix_for_language(
                        language,
                        &assignment.node,
                        query_node,
                        scope,
                    )))
    })?;
    let source_end = source_assignment.node.range().end;
    let mut php_context = None;
    if language == Language::Php {
        if source_assignment.node.kind().as_ref() == "augmented_assignment_expression"
            && source_assignment
                .node
                .field("operator")
                .is_none_or(|op| op.text() != ".=")
        {
            return None;
        }
        if source_assignment.right.dfs().any(|call| {
            matches!(
                call.kind().as_ref(),
                "function_call_expression" | "member_call_expression"
            ) && contains_range(call.range(), source_node.range())
                && !["htmlspecialchars", "htmlentities", "escapeshellarg"]
                    .iter()
                    .any(|name| {
                        php_context
                            .get_or_insert_with(|| super::php::PhpContext::build(root))
                            .exact_function(&call, name)
                    })
        }) {
            return None;
        }
    }
    let mut tracked = BTreeMap::from([(
        source_assignment.left.clone(),
        TrackedValue {
            depth: 0,
            steps: vec![SecurityPathStep {
                kind: SecurityPathStepKind::Assignment,
                location: node_location(path, &source_assignment.node),
                evidence_id: None,
                symbol: Some(source_assignment.left.clone()),
            }],
        },
    )]);

    for assignment in assignments.iter().filter(|assignment| {
        assignment.node.range().start >= source_end
            && assignment.node.range().end <= query_node.range().start
    }) {
        if language == Language::Php
            && assignment.in_control_flow
            && !lexical_path_is_prefix_for_language(language, &assignment.node, query_node, scope)
            && tracked.contains_key(&assignment.left)
        {
            // No join solver: a branch write may replace this value before the
            // sink even when its lexical arm differs. Do not retain stale data.
            return None;
        }
        if assignment.in_control_flow
            && allow_lexical_control_flow
            && !allow_controlled_string_extraction
            && !lexical_path_is_prefix_for_language(language, &assignment.node, query_node, scope)
            && !(language == Language::Python
                && python_conditional_join_may_reach(&assignment.node, query_node, scope))
        {
            continue;
        }
        let right = assignment.right.text();
        let right = right.trim();
        let (alias_origin, extraction) = if let Some(name) = simple_identifier(right) {
            (tracked.get(name).cloned(), None)
        } else if matches!(
            language,
            Language::Javascript | Language::Typescript | Language::Tsx
        ) && matches!(
            assignment.right.kind().as_ref(),
            "binary_expression" | "template_string"
        ) {
            (
                semantic_identifiers(&assignment.right)
                    .into_iter()
                    .filter_map(|identifier| tracked.get(&identifier))
                    .min_by_key(|value| (value.depth, value.steps.len()))
                    .cloned(),
                Some(("value".to_string(), "JavaScript string composition")),
            )
        } else if language == Language::Php
            && assignment.right.kind().as_ref() == "conditional_expression"
        {
            let identifiers = [
                assignment.right.field("body"),
                assignment.right.field("alternative"),
            ]
            .into_iter()
            .flatten()
            .filter(|branch| {
                !branch.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "function_call_expression"
                            | "member_call_expression"
                            | "assignment_expression"
                    )
                })
            })
            .flat_map(|branch| semantic_identifiers(&branch))
            .collect::<BTreeSet<_>>();
            (
                identifiers
                    .into_iter()
                    .filter_map(|name| tracked.get(&name))
                    .min_by_key(|value| (value.depth, value.steps.len()))
                    .cloned(),
                Some((
                    "value".to_string(),
                    "PHP raw conditional value arm; other-arm controls remain contextual",
                )),
            )
        } else if language == Language::Php
            && matches!(
                assignment.right.kind().as_ref(),
                "binary_expression" | "encapsed_string"
            )
            && !assignment.right.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "function_call_expression" | "member_call_expression" | "assignment_expression"
                )
            })
        {
            (
                semantic_identifiers(&assignment.right)
                    .into_iter()
                    .filter_map(|identifier| tracked.get(&identifier))
                    .min_by_key(|value| (value.depth, value.steps.len()))
                    .cloned(),
                Some(("value".to_string(), "PHP string composition")),
            )
        } else if matches!(
            language,
            Language::Javascript | Language::Typescript | Language::Tsx
        ) && assignment.right.kind().as_ref() == "call_expression"
            && compact_expression(assignment.right.text().as_ref()).starts_with("path.join(")
        {
            (
                semantic_identifiers(&assignment.right)
                    .into_iter()
                    .filter_map(|identifier| tracked.get(&identifier))
                    .min_by_key(|value| (value.depth, value.steps.len()))
                    .cloned(),
                Some(("value".to_string(), "Node path.join composition")),
            )
        } else if language == Language::Python {
            if let Some((origin, transform)) =
                python_value_preserving_origin(&assignment.right, &tracked)
            {
                (Some(origin), Some(("value".to_string(), transform)))
            } else if allow_controlled_string_extraction {
                simple_string_extraction(right).map_or((None, None), |(receiver, method)| {
                    (tracked.get(&receiver).cloned(), Some((receiver, method)))
                })
            } else if allow_bounded_string_choice {
                bounded_string_choice_receiver(right).map_or((None, None), |receiver| {
                    (
                        tracked.get(&receiver).cloned(),
                        Some((receiver, "bounded length/truncation choice")),
                    )
                })
            } else {
                (None, None)
            }
        } else if language == Language::Go && right.starts_with("fmt.Sprintf(") {
            (
                semantic_identifiers(&assignment.right)
                    .into_iter()
                    .filter_map(|identifier| tracked.get(&identifier))
                    .min_by_key(|value| (value.depth, value.steps.len()))
                    .cloned(),
                Some(("value".to_string(), "fmt.Sprintf")),
            )
        } else if language == Language::Go
            && (right.starts_with("strings.Replace(") || right.starts_with("strings.ReplaceAll("))
        {
            (
                semantic_identifiers(&assignment.right)
                    .into_iter()
                    .filter_map(|identifier| tracked.get(&identifier))
                    .min_by_key(|tracked| (tracked.depth, tracked.steps.len()))
                    .cloned(),
                Some(("value".to_string(), "strings.Replace")),
            )
        } else if language == Language::Go
            && assignment.right.kind().as_ref() == "composite_literal"
        {
            (
                semantic_identifiers(&assignment.right)
                    .into_iter()
                    .filter_map(|identifier| tracked.get(&identifier))
                    .min_by_key(|value| (value.depth, value.steps.len()))
                    .cloned(),
                Some(("value".to_string(), "Go composite literal")),
            )
        } else if language == Language::Rust
            && rust_assignment_origin(&assignment.right, &tracked).is_some()
        {
            let (origin, transform) = rust_assignment_origin(&assignment.right, &tracked)
                .expect("guarded Rust value-preserving expression");
            (Some(origin), Some(("value".to_string(), transform)))
        } else if allow_controlled_string_extraction {
            simple_string_extraction(right).map_or((None, None), |(receiver, method)| {
                (tracked.get(&receiver).cloned(), Some((receiver, method)))
            })
        } else if allow_bounded_string_choice {
            bounded_string_choice_receiver(right).map_or((None, None), |receiver| {
                (
                    tracked.get(&receiver).cloned(),
                    Some((receiver, "bounded length/truncation choice")),
                )
            })
        } else {
            (None, None)
        };
        let alias_origin = if language == Language::Php
            && assignment.node.kind().as_ref() == "augmented_assignment_expression"
        {
            if assignment
                .node
                .field("operator")
                .is_some_and(|op| op.text() == ".=")
            {
                alias_origin.or_else(|| tracked.get(&assignment.left).cloned())
            } else {
                None
            }
        } else {
            alias_origin
        };
        let overwrite_is_on_source_path = !assignment.in_control_flow
            || (!allow_controlled_string_extraction && !allow_lexical_control_flow)
            || lexical_path_is_prefix_for_language(language, &assignment.node, query_node, scope);
        if overwrite_is_on_source_path {
            tracked.remove(&assignment.left);
        }
        let Some(origin) = alias_origin else {
            continue;
        };
        if (assignment.in_control_flow
            && !allow_controlled_string_extraction
            && !allow_lexical_control_flow)
            || origin.depth >= MAX_PROPAGATION_DEPTH
        {
            continue;
        }
        let mut steps = origin.steps;
        let symbol = extraction.map_or_else(
            || assignment.left.clone(),
            |(receiver, method)| format!("{} via {receiver}.{method}", assignment.left),
        );
        steps.push(SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: node_location(path, &assignment.node),
            evidence_id: None,
            symbol: Some(symbol),
        });
        tracked.insert(
            assignment.left.clone(),
            TrackedValue {
                depth: origin.depth + 1,
                steps,
            },
        );
    }

    if language == Language::Php
        && !semantic_identifiers(query_node)
            .iter()
            .any(|name| tracked.contains_key(name))
    {
        return None;
    }
    if language == Language::Php
        && root.dfs().any(|node| {
            node.range().start >= source_end
                && node.range().end <= query_node.range().start
                && matches!(
                    node.kind().as_ref(),
                    "include_expression"
                        | "include_once_expression"
                        | "require_expression"
                        | "require_once_expression"
                        | "function_call_expression"
                        | "member_call_expression"
                        | "reference_assignment_expression"
                        | "unset_statement"
                        | "update_expression"
                )
                && match node.kind().as_ref() {
                    "include_expression"
                    | "include_once_expression"
                    | "require_expression"
                    | "require_once_expression" => scope_range(&node, root) == *scope,
                    "function_call_expression" | "member_call_expression" => {
                        if node.field("arguments").is_none_or(|args| {
                            !semantic_identifiers(&args)
                                .iter()
                                .any(|name| tracked.contains_key(name))
                        }) {
                            return false;
                        }
                        if scope_range(&node, root) != *scope {
                            return false;
                        }
                        let context =
                            php_context.get_or_insert_with(|| super::php::PhpContext::build(root));
                        ![
                            "htmlspecialchars",
                            "htmlentities",
                            "escapeshellarg",
                            "escapeshellcmd",
                            "parse_url",
                            "mysqli_execute_query",
                            "empty",
                            "is_null",
                            "is_array",
                            "is_object",
                            "is_string",
                        ]
                        .iter()
                        .any(|name| context.exact_function(&node, name))
                            && !(context.exact_function(&node, "preg_match")
                                && node.field("arguments").is_some_and(|args| {
                                    args.children().filter(|arg| arg.is_named()).count() == 2
                                }))
                    }
                    "reference_assignment_expression" | "unset_statement" | "update_expression" => {
                        semantic_identifiers(&node)
                            .iter()
                            .any(|name| tracked.contains_key(name))
                            && scope_range(&node, root) == *scope
                    }
                    _ => false,
                }
        })
    {
        return None;
    }
    let semantic = semantic_identifiers(query_node)
        .into_iter()
        .filter_map(|identifier| tracked.get(&identifier))
        .min_by_key(|value| (value.depth, value.steps.len()))
        .map(|value| value.steps.clone());
    semantic.or_else(|| {
        (language == Language::Rust && query_node.text().trim_start().starts_with("format!("))
            .then(|| {
                semantic_identifier_text(query_node.text().as_ref())
                    .into_iter()
                    .filter_map(|identifier| tracked.get(&identifier))
                    .min_by_key(|value| (value.depth, value.steps.len()))
                    .map(|value| value.steps.clone())
            })
            .flatten()
    })
}

fn rust_value_preserving_expression(node: &Node<'_, StrDoc<SupportLang>>) -> Option<&'static str> {
    let text = compact_expression(node.text().as_ref());
    if text.starts_with("format!(") {
        Some("Rust format!")
    } else if node.kind().as_ref() == "binary_expression" {
        Some("Rust concatenation")
    } else if text.ends_with(".into_inner()") {
        Some("Rust extractor unwrap")
    } else if text.ends_with(".clone()") || text.ends_with(".to_owned()") {
        Some("Rust owned-value copy")
    } else if text.ends_with(".to_string()") {
        Some("Rust string conversion")
    } else if text.ends_with(".as_bytes()") {
        Some("Rust byte view")
    } else if text.contains(".replace(") {
        Some("Rust string replacement")
    } else {
        None
    }
}

fn rust_assignment_origin(
    node: &Node<'_, StrDoc<SupportLang>>,
    tracked: &BTreeMap<String, TrackedValue>,
) -> Option<(TrackedValue, &'static str)> {
    let (candidates, transform) = if node.kind().as_ref() == "if_expression" {
        let candidates = [node.field("consequence"), node.field("alternative")]
            .into_iter()
            .flatten()
            .flat_map(|branch| semantic_identifiers(&branch))
            .collect::<BTreeSet<_>>();
        (candidates, "Rust conditional value")
    } else {
        (
            semantic_identifiers(node),
            rust_value_preserving_expression(node)?,
        )
    };
    candidates
        .into_iter()
        .filter_map(|identifier| tracked.get(&identifier))
        .min_by_key(|value| (value.depth, value.steps.len()))
        .cloned()
        .map(|value| (value, transform))
}

/// Follows only Python operations that preserve attacker-controlled content.
///
/// This is intentionally an allow-list, not a general expression evaluator. A
/// dictionary/attribute projection, string concatenation, URL decoding, and
/// path composition/canonicalization all retain influence from their input.
/// Calls outside this small set terminate propagation.
fn python_value_preserving_origin(
    expression: &Node<'_, StrDoc<SupportLang>>,
    tracked: &BTreeMap<String, TrackedValue>,
) -> Option<(TrackedValue, &'static str)> {
    let kind = expression.kind();
    let kind = kind.as_ref();
    let mut preferred_receiver = None;
    let transform = match kind {
        "attribute" | "subscript" => "Python projection",
        "binary_operator" => "Python expression",
        "call" => {
            let function = expression.field("function")?;
            let callee = compact_expression(function.text().as_ref());
            match callee.as_str() {
                "unquote" | "urllib.parse.unquote" => "URL decode",
                "base64.b64decode"
                | "base64.urlsafe_b64decode"
                | "b64decode"
                | "urlsafe_b64decode" => "base64 decode",
                "re.sub" => "regular-expression replacement",
                "os.path.join" => "path join",
                "os.path.abspath" | "os.path.realpath" | "os.path.normpath" => {
                    "path canonicalization"
                }
                _ if callee.ends_with(".format") => "string formatting",
                _ if callee.ends_with(".strip") => {
                    preferred_receiver = callee.split('.').next().map(str::to_string);
                    "string trimming"
                }
                _ if callee.ends_with(".replace") => {
                    preferred_receiver = callee.split('.').next().map(str::to_string);
                    "string replacement"
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    preferred_receiver
        .as_ref()
        .and_then(|receiver| tracked.get(receiver))
        .cloned()
        .or_else(|| {
            semantic_identifiers(expression)
                .into_iter()
                .filter_map(|identifier| tracked.get(&identifier))
                .min_by_key(|value| (value.depth, value.steps.len()))
                .cloned()
        })
        .map(|origin| (origin, transform))
}

fn simple_string_extraction(text: &str) -> Option<(String, &'static str)> {
    let compact = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let call = compact.strip_suffix(')')?;
    for (marker, method) in [
        ("?.substring(", "substring"),
        (".substring(", "substring"),
        ("?.slice(", "slice"),
        (".slice(", "slice"),
        ("?.trim(", "trim"),
        (".trim(", "trim"),
    ] {
        let Some((receiver, arguments)) = call.split_once(marker) else {
            continue;
        };
        if simple_identifier(receiver).is_some() && !arguments.contains(['(', ')', ';']) {
            return Some((receiver.to_string(), method));
        }
    }
    None
}

fn bounded_string_choice_receiver(text: &str) -> Option<String> {
    let compact = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let (condition, branches) = compact.split_once('?')?;
    let condition = condition
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(condition);
    let (consequence, alternative) = branches.rsplit_once(':')?;
    let (receiver, method) =
        simple_string_extraction(alternative).or_else(|| simple_string_extraction(consequence))?;
    let unchanged = if consequence == receiver {
        alternative
    } else if alternative == receiver {
        consequence
    } else {
        return None;
    };
    let (extraction_receiver, extraction_method) = simple_string_extraction(unchanged)?;
    if extraction_receiver != receiver || !matches!(extraction_method, "substring" | "slice") {
        return None;
    }
    let length_prefix = format!("{receiver}.length<=");
    let bound = condition.strip_prefix(&length_prefix)?;
    if method != extraction_method
        || bound.is_empty()
        || !bound.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(receiver)
}

/// Resolves one deliberately narrow JavaScript/TypeScript pattern:
///
/// `const context = { evaluator, requestValue };`
/// `vm.runInContext('evaluator(requestValue)', context);`
///
/// The evaluator must resolve to `notevil.eval`, the embedded program must be a
/// single literal call, and both context properties must be simple bindings.
/// This is syntax-bounded object flow, not arbitrary string interpretation.
fn embedded_evaluator_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    symbols: &FileSymbolEnvironment,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) || sink.capability != Capability::DynamicCodeExecution
        || !matches!(
            sink.symbol_resolution.as_ref()?.canonical.as_str(),
            "vm.runInContext" | "vm.runInNewContext"
        )
    {
        return None;
    }
    let code_capture = sink.captures.get("code")?;
    let program = simple_string_literal(code_capture.text.trim())?;
    let (evaluator_property, argument_property) = simple_embedded_call(program)?;
    embedded_context_property_steps(
        path,
        root,
        language,
        symbols,
        source_node,
        sink,
        scope,
        evaluator_property,
        argument_property,
        "",
        "notevil.eval",
        &code_capture.location,
        &format!("{evaluator_property}({argument_property})"),
    )
}

fn embedded_deserialization_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    symbols: &FileSymbolEnvironment,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    scope: &Range<usize>,
) -> Option<Vec<SecurityPathStep>> {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) || sink.capability != Capability::Deserialization
        || !sink.provenance.engine.ends_with("constant-vm-wrapper")
    {
        return None;
    }
    let loader = sink.captures.get("loader")?;
    let payload = sink.captures.get("payload")?;
    embedded_context_property_steps(
        path,
        root,
        language,
        symbols,
        source_node,
        sink,
        scope,
        loader.text.trim(),
        payload.text.trim(),
        ".load",
        "js-yaml.load",
        &payload.location,
        &format!("{}.load({})", loader.text.trim(), payload.text.trim()),
    )
}

#[allow(clippy::too_many_arguments)]
fn embedded_context_property_steps(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    symbols: &FileSymbolEnvironment,
    source_node: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    scope: &Range<usize>,
    callable_property: &str,
    argument_property: &str,
    callable_suffix: &str,
    callable_canonical: &str,
    program_location: &Location,
    program_step_symbol: &str,
) -> Option<Vec<SecurityPathStep>> {
    let sink_node = call_node_containing(root, location_range(&sink.location))?;
    let context_name = call_argument_identifier(&sink_node, 1)?;
    let assignments = assignments_in_scope(root, language, scope);
    let source_assignment = assignments.iter().find(|assignment| {
        contains_range(assignment.right.range(), source_node.range())
            && assignment.node.range().end <= sink_node.range().start
    })?;
    let source_end = source_assignment.node.range().end;
    let mut tracked = BTreeMap::from([(
        source_assignment.left.clone(),
        TrackedValue {
            depth: 0,
            steps: vec![SecurityPathStep {
                kind: SecurityPathStepKind::Assignment,
                location: node_location(path, &source_assignment.node),
                evidence_id: None,
                symbol: Some(source_assignment.left.clone()),
            }],
        },
    )]);

    for assignment in assignments.iter().filter(|assignment| {
        assignment.node.range().start >= source_end
            && assignment.node.range().end <= sink_node.range().start
    }) {
        if assignment.left == context_name {
            let properties = simple_object_bindings(assignment.right.text().trim())?;
            let callable_binding = properties.get(callable_property)?;
            let argument_binding = properties.get(argument_property)?;
            symbols.resolve(
                &format!("{callable_binding}{callable_suffix}"),
                callable_canonical,
            )?;
            let origin = tracked.get(argument_binding)?;
            if origin.depth + 2 > MAX_PROPAGATION_DEPTH
                || has_member_mutation(
                    root,
                    &context_name,
                    assignment.node.range().end..sink_node.range().start,
                    scope,
                )
            {
                return None;
            }
            let mut steps = origin.steps.clone();
            steps.push(SecurityPathStep {
                kind: SecurityPathStepKind::Alias,
                location: node_location(path, &assignment.node),
                evidence_id: None,
                symbol: Some(format!("{context_name}.{argument_property}")),
            });
            steps.push(SecurityPathStep {
                kind: SecurityPathStepKind::Alias,
                location: program_location.clone(),
                evidence_id: None,
                symbol: Some(program_step_symbol.to_string()),
            });
            return Some(steps);
        }

        let alias_origin = simple_identifier(assignment.right.text().trim())
            .and_then(|name| tracked.get(name).cloned());
        tracked.remove(&assignment.left);
        let Some(origin) = alias_origin else {
            continue;
        };
        if origin.depth >= MAX_PROPAGATION_DEPTH {
            continue;
        }
        let mut steps = origin.steps;
        steps.push(SecurityPathStep {
            kind: SecurityPathStepKind::Alias,
            location: node_location(path, &assignment.node),
            evidence_id: None,
            symbol: Some(assignment.left.clone()),
        });
        tracked.insert(
            assignment.left.clone(),
            TrackedValue {
                depth: origin.depth + 1,
                steps,
            },
        );
    }
    None
}

fn call_node_containing<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    range: Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "call_expression" | "invocation_expression"
            ) && (contains_range(node.range(), range.clone())
                || contains_range(range.clone(), node.range()))
        })
        .min_by_key(|node| node.range().end - node.range().start)
}

fn call_argument_identifier(call: &Node<'_, StrDoc<SupportLang>>, index: usize) -> Option<String> {
    let arguments = call.field("arguments")?;
    let argument = arguments
        .children()
        .filter(|child| child.is_named())
        .nth(index)?;
    simple_identifier(argument.text().trim()).map(str::to_string)
}

fn simple_string_literal(text: &str) -> Option<&str> {
    let text = text.trim();
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"')
        || text.as_bytes().last().copied() != Some(quote)
        || text.len() < 2
        || text[1..text.len() - 1].contains('\\')
    {
        return None;
    }
    Some(&text[1..text.len() - 1])
}

fn simple_embedded_call(program: &str) -> Option<(&str, &str)> {
    let program = program.trim().trim_end_matches(';').trim();
    let (callee, argument) = program.split_once('(')?;
    let argument = argument.strip_suffix(')')?.trim();
    let callee = simple_identifier(callee.trim())?;
    let argument = simple_identifier(argument)?;
    (!program[..program.len() - 1].contains(')') && !argument.contains(','))
        .then_some((callee, argument))
}

fn simple_object_bindings(text: &str) -> Option<BTreeMap<String, String>> {
    let body = text.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    let mut bindings = BTreeMap::new();
    for entry in body.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (property, value) = entry
            .split_once(':')
            .map_or((entry, entry), |(property, value)| {
                (property.trim(), value.trim())
            });
        let property = simple_identifier(property)?;
        let value = simple_identifier(value)?;
        if bindings
            .insert(property.to_string(), value.to_string())
            .is_some()
        {
            return None;
        }
    }
    (!bindings.is_empty()).then_some(bindings)
}

fn has_member_mutation(
    root: &Node<'_, StrDoc<SupportLang>>,
    object: &str,
    range: Range<usize>,
    scope: &Range<usize>,
) -> bool {
    root.dfs()
        .filter(|node| {
            range.start <= node.range().start
                && node.range().end <= range.end
                && scope_range(node, root) == *scope
                && matches!(
                    node.kind().as_ref(),
                    "assignment" | "assignment_expression" | "augmented_assignment"
                )
        })
        .filter_map(|node| node.field("left"))
        .any(|left| {
            let text = left.text();
            let text = text.trim();
            text.starts_with(&format!("{object}.")) || text.starts_with(&format!("{object}["))
        })
}

fn assignments_in_scope<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    scope: &Range<usize>,
) -> Vec<Assignment<'tree>> {
    let mut assignments = root
        .dfs()
        .filter(|node| scope.start <= node.range().start && node.range().end <= scope.end)
        .filter_map(|node| assignment_parts(node, language, scope))
        .filter(|assignment| scope_range(&assignment.node, root) == *scope)
        .collect::<Vec<_>>();
    assignments
        .sort_by_key(|assignment| (assignment.node.range().start, assignment.node.range().end));
    assignments
}

fn assignment_parts<'tree>(
    node: Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    scope: &Range<usize>,
) -> Option<Assignment<'tree>> {
    let kind = node.kind();
    let kind = kind.as_ref();
    let (left, right) = if matches!(
        kind,
        "variable_declarator" | "init_declarator" | "var_spec" | "const_spec" | "let_declaration"
    ) {
        let left = node
            .field("name")
            .or_else(|| node.field("pattern"))
            .or_else(|| node.field("declarator"))?;
        let right = node
            .field("value")
            .or_else(|| node.field("initializer"))
            .or_else(|| {
                (language == Language::Csharp).then(|| {
                    let left_range = left.range();
                    node.children()
                        .filter(|child| child.is_named() && child.range() != left_range)
                        .last()
                })?
            })?;
        (left, unwrap_initializer(right))
    } else if matches!(
        kind,
        "assignment"
            | "assignment_expression"
            | "assignment_statement"
            | "short_var_declaration"
            | "augmented_assignment"
            | "augmented_assignment_expression"
    ) {
        (node.field("left")?, node.field("right")?)
    } else {
        return None;
    };
    if language != Language::Php && kind == "augmented_assignment_expression" {
        return None;
    }
    let left = assignment_identifier(&left, language)?;
    Some(Assignment {
        in_control_flow: has_control_flow_ancestor(&node, scope),
        node,
        left,
        right,
    })
}

fn assignment_identifier(
    left: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
) -> Option<String> {
    simple_identifier(left.text().trim())
        .map(str::to_string)
        .or_else(|| {
            matches!(language, Language::C | Language::Cpp)
                .then(|| {
                    left.dfs()
                        .filter(|node| node.kind().as_ref() == "identifier")
                        .last()
                        .and_then(|node| simple_identifier(node.text().trim()).map(str::to_string))
                })
                .flatten()
        })
        .or_else(|| {
            (language == Language::Go && left.kind().as_ref() == "expression_list")
                .then(|| {
                    left.children()
                        .find(|child| child.kind().as_ref() == "identifier")
                        .and_then(|child| {
                            simple_identifier(child.text().trim()).map(str::to_string)
                        })
                })
                .flatten()
        })
}

fn unwrap_initializer(node: Node<'_, StrDoc<SupportLang>>) -> Node<'_, StrDoc<SupportLang>> {
    if matches!(
        node.kind().as_ref(),
        "equals_value_clause" | "expression_list"
    ) {
        let children = node
            .children()
            .filter(|child| child.is_named())
            .collect::<Vec<_>>();
        if children.len() == 1 {
            return children[0].clone();
        }
    }
    node
}

fn smallest_node_containing<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    range: Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if !contains_range(root.range(), range.clone()) {
        return None;
    }
    let mut current = root.clone();
    loop {
        let next = current
            .children()
            .filter(|child| contains_range(child.range(), range.clone()))
            .min_by_key(|child| child.range().end - child.range().start);
        let Some(next) = next else {
            return Some(current);
        };
        current = next;
    }
}

fn scope_range(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> Range<usize> {
    node.ancestors()
        .find(|ancestor| is_function_scope(ancestor.kind().as_ref()))
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn is_function_scope(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_definition"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
            | "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
            | "function_literal"
            | "function_item"
            | "anonymous_function"
    )
}

fn has_control_flow_ancestor(node: &Node<'_, StrDoc<SupportLang>>, scope: &Range<usize>) -> bool {
    node.ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
        .any(|ancestor| is_control_flow(ancestor.kind().as_ref()))
}

fn lexical_if_try_path_is_prefix(
    source: &Node<'_, StrDoc<SupportLang>>,
    target: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> bool {
    let Some(source_path) = lexical_if_try_path(source, scope) else {
        return false;
    };
    let Some(target_path) = lexical_if_try_path(target, scope) else {
        return false;
    };
    source_path.len() <= target_path.len()
        && source_path
            .iter()
            .zip(target_path.iter())
            .all(|(source_frame, target_frame)| source_frame == target_frame)
}

fn lexical_path_is_prefix_for_language(
    language: Language,
    source: &Node<'_, StrDoc<SupportLang>>,
    target: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> bool {
    if language != Language::Python {
        return lexical_if_try_path_is_prefix(source, target, scope);
    }
    let Some(source_path) = lexical_python_path(source, scope) else {
        return false;
    };
    let Some(target_path) = lexical_python_path(target, scope) else {
        return false;
    };
    source_path.len() <= target_path.len()
        && source_path
            .iter()
            .zip(target_path.iter())
            .all(|(source_frame, target_frame)| source_frame == target_frame)
}

/// Allows a Python value assigned in one arm of a completed `if` statement to
/// reach a later statement. The result remains an unknown/may-flow path: this
/// does not claim that the arm executes or that all arms define the value.
fn python_conditional_join_may_reach(
    source: &Node<'_, StrDoc<SupportLang>>,
    target: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> bool {
    if source.range().end >= target.range().start {
        return false;
    }
    let source_controls = source
        .ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
        .filter(|ancestor| is_control_flow(ancestor.kind().as_ref()))
        .collect::<Vec<_>>();
    let target_control_ranges = target
        .ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
        .filter(|ancestor| is_control_flow(ancestor.kind().as_ref()))
        .map(|ancestor| (ancestor.range().start, ancestor.range().end))
        .collect::<BTreeSet<_>>();
    let source_only = source_controls
        .iter()
        .filter(|ancestor| {
            !target_control_ranges.contains(&(ancestor.range().start, ancestor.range().end))
        })
        .collect::<Vec<_>>();
    !source_only.is_empty()
        && source_only.iter().all(|ancestor| {
            ancestor.kind().as_ref() == "if_statement"
                && ancestor.range().end <= target.range().start
        })
}

fn lexical_python_path(
    node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<(Range<usize>, Range<usize>)>> {
    let mut path = Vec::new();
    let mut descendant = node.clone();
    for ancestor in node
        .ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
    {
        if is_control_flow(ancestor.kind().as_ref()) {
            path.push((ancestor.range(), descendant.range()));
        }
        descendant = ancestor;
    }
    path.reverse();
    Some(path)
}

fn lexical_if_try_path(
    node: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> Option<Vec<(Range<usize>, Range<usize>)>> {
    let mut path = Vec::new();
    let mut descendant = node.clone();
    for ancestor in node
        .ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
    {
        let kind = ancestor.kind();
        let kind = kind.as_ref();
        if is_control_flow(kind) {
            if !is_lexical_if_try_control(kind) {
                return None;
            }
            path.push((ancestor.range(), descendant.range()));
        }
        descendant = ancestor;
    }
    path.reverse();
    Some(path)
}

fn is_lexical_if_try_control(kind: &str) -> bool {
    kind.contains("if_")
        || kind == "if_statement"
        || matches!(kind, "try_statement" | "catch_clause")
}

fn is_control_flow(kind: &str) -> bool {
    kind.contains("if_")
        || kind == "if_statement"
        || kind == "conditional_expression"
        || kind.contains("for_")
        || kind.contains("while_")
        || matches!(
            kind,
            "for_statement"
                | "for_in_statement"
                | "enhanced_for_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
                | "switch_expression"
                | "match_statement"
                | "try_statement"
                | "catch_clause"
        )
}

fn protection_belongs_to_sink(
    root: &Node<'_, StrDoc<SupportLang>>,
    protection: &Evidence,
    sink: &Evidence,
    family: &RelationContract,
) -> bool {
    let Some(contract) = &family.protection else {
        return false;
    };
    if contract.application == ProtectionApplication::ValueTransform
        && protection
            .enclosing_symbol
            .as_ref()
            .zip(sink.enclosing_symbol.as_ref())
            .is_some_and(|(protection_symbol, sink_symbol)| protection_symbol != sink_symbol)
    {
        return false;
    }
    same_range(&protection.location, &sink.location)
        || protection.related_evidence.contains(&sink.id)
        || (contract.application == ProtectionApplication::ValueTransform
            && family.sink.input_roles.iter().any(|capture| {
                sink.captures.get(capture).is_some_and(|target| {
                    contains_range(
                        location_range(&target.location),
                        location_range(&protection.location),
                    )
                })
            }))
        || (contract.application == ProtectionApplication::ValueTransform
            && value_transform_assignment_guards_sink(root, protection, sink, family))
        || protection
            .captures
            .get(&contract.relation_role)
            .is_some_and(|protected_target| {
                sink.captures
                    .get(&contract.relation_role)
                    .is_some_and(|sink_target| {
                        same_range(&protected_target.location, &sink_target.location)
                    })
            })
        || (family.sink.capability == Capability::BrowserCredentialedRequest
            && protection.capability == Capability::Authorization
            && protection
                .rule_id
                .contains("browser-message-origin-validation")
            && protection.location.start.byte_offset < sink.location.start.byte_offset
            && smallest_node_containing(root, location_range(&protection.location))
                .zip(smallest_node_containing(
                    root,
                    location_range(&sink.location),
                ))
                .is_some_and(|(protection_node, sink_node)| {
                    scope_range(&protection_node, root) == scope_range(&sink_node, root)
                }))
        || (matches!(
            family.sink.capability,
            Capability::FilesystemRead | Capability::FilesystemWrite
        ) && protection.capability == Capability::PathContainmentCheck
            && archive_containment_guards_sink(root, protection, sink, family))
        || (family.sink.capability == Capability::Redirect
            && protection.capability == Capability::RedirectDestinationValidation
            && redirect_validation_guards_sink(root, protection, sink, family))
}

fn value_transform_assignment_guards_sink(
    root: &Node<'_, StrDoc<SupportLang>>,
    protection: &Evidence,
    sink: &Evidence,
    family: &RelationContract,
) -> bool {
    let Some(protection_node) =
        smallest_node_containing(root, location_range(&protection.location))
    else {
        return false;
    };
    let Some(assignment) = protection_node.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "assignment_expression"
                | "assignment_statement"
                | "short_var_declaration"
                | "variable_declarator"
                | "local_variable_declaration"
                | "let_declaration"
        ) && ancestor
            .field("right")
            .or_else(|| ancestor.field("value"))
            .or_else(|| ancestor.field("initializer"))
            .is_some_and(|right| contains_range(right.range(), protection_node.range()))
    }) else {
        return false;
    };
    let Some(left) = assignment
        .field("left")
        .or_else(|| assignment.field("name"))
        .or_else(|| assignment.field("pattern"))
    else {
        return false;
    };
    let left_text = left.text();
    let binding = simple_identifier(left_text.trim())
        .map(str::to_string)
        .or_else(|| {
            let identifiers = left
                .children()
                .filter(|child| child.kind().as_ref() == "identifier")
                .collect::<Vec<_>>();
            (identifiers.len() == 1).then(|| identifiers[0].text().into_owned())
        });
    let Some(binding) = binding else {
        return false;
    };
    family.sink.input_roles.iter().any(|role| {
        sink.captures.get(role).is_some_and(|target| {
            assignment.range().end <= target.location.start.byte_offset
                && semantic_identifier_text(&target.text)
                    .iter()
                    .any(|identifier| identifier == &binding)
        })
    })
}

fn semantic_identifier_text(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|part| simple_identifier(part).is_some())
        .map(str::to_string)
        .collect()
}

fn archive_containment_guards_sink(
    root: &Node<'_, StrDoc<SupportLang>>,
    protection: &Evidence,
    sink: &Evidence,
    family: &RelationContract,
) -> bool {
    let Some(protected) = protection.captures.get("path") else {
        return false;
    };
    let Some(target) = family
        .sink
        .input_roles
        .iter()
        .find_map(|role| sink.captures.get(role))
    else {
        return false;
    };
    if compact_expression(&protected.text) != compact_expression(&target.text) {
        return false;
    }
    let Some(protection_node) =
        smallest_node_containing(root, location_range(&protection.location))
    else {
        return false;
    };
    let Some(target_node) = smallest_node_containing(root, location_range(&target.location)) else {
        return false;
    };
    let Some(guard) = protection_node.ancestors().find(|ancestor| {
        ancestor.kind().as_ref() == "if_statement"
            && ancestor
                .field("condition")
                .is_some_and(|condition| contains_range(condition.range(), protection_node.range()))
    }) else {
        return false;
    };
    let Some(condition) = guard.field("condition") else {
        return false;
    };
    let negated = compact_expression(condition.text().as_ref())
        .trim_start_matches('(')
        .starts_with('!');
    if !negated
        && guard
            .field("consequence")
            .is_some_and(|branch| contains_range(branch.range(), target_node.range()))
    {
        return true;
    }
    if !negated
        || !guard
            .field("consequence")
            .is_some_and(|branch| syntactically_terminates(&branch))
        || guard.range().end >= target_node.range().start
    {
        return false;
    }
    let Some(block) = guard.parent() else {
        return false;
    };
    block.kind().as_ref() == "block"
        && target_node
            .ancestors()
            .any(|ancestor| ancestor.range() == block.range())
        && !block.dfs().any(|node| {
            node.kind().as_ref() == "assignment_expression"
                && guard.range().end <= node.range().start
                && node.range().end <= target_node.range().start
                && node.field("left").is_some_and(|left| {
                    compact_expression(left.text().as_ref()) == compact_expression(&target.text)
                })
        })
}

fn redirect_validation_guards_sink(
    root: &Node<'_, StrDoc<SupportLang>>,
    protection: &Evidence,
    sink: &Evidence,
    family: &RelationContract,
) -> bool {
    let Some(protected) = protection.captures.get("location") else {
        return false;
    };
    let Some(target) = family
        .sink
        .input_roles
        .iter()
        .find_map(|role| sink.captures.get(role))
    else {
        return false;
    };
    if compact_expression(&protected.text) != compact_expression(&target.text) {
        return false;
    }
    let Some(protection_node) =
        smallest_node_containing(root, location_range(&protection.location))
    else {
        return false;
    };
    let Some(target_node) = smallest_node_containing(root, location_range(&target.location)) else {
        return false;
    };
    let Some(guard) = protection_node.ancestors().find(|ancestor| {
        ancestor.kind().as_ref() == "if_statement"
            && ancestor
                .field("condition")
                .is_some_and(|condition| contains_range(condition.range(), protection_node.range()))
    }) else {
        return false;
    };
    if guard
        .field("consequence")
        .is_some_and(|branch| contains_range(branch.range(), target_node.range()))
    {
        return true;
    }
    let Some(condition) = guard.field("condition") else {
        return false;
    };
    if !compact_expression(condition.text().as_ref())
        .trim_start_matches('(')
        .starts_with('!')
        || !guard
            .field("consequence")
            .is_some_and(|branch| syntactically_terminates(&branch))
        || guard.range().end >= target_node.range().start
    {
        return false;
    }
    let Some(block) = guard.parent() else {
        return false;
    };
    if block.kind().as_ref() != "block"
        || !target_node
            .ancestors()
            .any(|ancestor| ancestor.range() == block.range())
    {
        return false;
    }
    !block.dfs().any(|node| {
        node.kind().as_ref() == "assignment_expression"
            && guard.range().end <= node.range().start
            && node.range().end <= target_node.range().start
            && node.field("left").is_some_and(|left| {
                compact_expression(left.text().as_ref()) == compact_expression(&target.text)
            })
    })
}

fn syntactically_terminates(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    match node.kind().as_ref() {
        "return_statement" | "throw_statement" => true,
        "block" => node
            .children()
            .filter(|child| child.is_named())
            .last()
            .is_some_and(|last| syntactically_terminates(&last)),
        "if_statement" => {
            node.field("consequence")
                .is_some_and(|branch| syntactically_terminates(&branch))
                && node
                    .field("alternative")
                    .is_some_and(|branch| syntactically_terminates(&branch))
        }
        _ => false,
    }
}

fn compact_expression(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn identifiers(node: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    node.dfs()
        .filter(|candidate| {
            matches!(
                candidate.kind().as_ref(),
                "identifier"
                    | "variable_name"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            )
        })
        .filter_map(|candidate| simple_identifier(candidate.text().trim()).map(str::to_string))
        .collect()
}

fn semantic_identifiers(node: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    semantic_identifier_nodes(node)
        .into_iter()
        .map(|identifier| identifier.text().into_owned())
        .collect()
}

fn semantic_identifier_nodes<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.dfs()
        .filter(|candidate| {
            matches!(
                candidate.kind().as_ref(),
                "identifier"
                    | "variable_name"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) && !is_member_name(candidate)
        })
        .filter(|candidate| simple_identifier(candidate.text().trim()).is_some())
        .collect()
}

fn is_member_name(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind().as_ref(),
            "member_access_expression" | "conditional_access_expression"
        ) && parent
            .field("name")
            .is_some_and(|name| name.range() == node.range())
    })
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.strip_prefix('$').unwrap_or(text).chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_alphabetic())
        || !characters.all(|character| character == '_' || character.is_alphanumeric())
    {
        return None;
    }
    Some(text)
}

fn push_path(
    paths: &mut Vec<SecurityPath>,
    source: &Evidence,
    sink: &Evidence,
    state: SecurityPathState,
    steps: Vec<SecurityPathStep>,
    protections: &[&Evidence],
    family: &RelationContract,
) {
    let bounded_string_choice = steps.iter().any(|step| {
        step.symbol
            .as_deref()
            .is_some_and(|symbol| symbol.contains("bounded length/truncation choice"))
    });
    let protection_evidence_ids = protections
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let mut uncertainty_reasons = (source.confidence != Confidence::High)
        .then(|| "source_observation_not_high_confidence".to_string())
        .into_iter()
        .collect::<Vec<_>>();
    if source.capability == Capability::StoredUserContent {
        uncertainty_reasons.push(
            if source
                .provenance
                .engine
                .ends_with("bounded-angular-rxjs-summary")
            {
                "angular_service_response_origin_is_syntactic"
            } else if source
                .provenance
                .engine
                .ends_with("local-subtitle-file-source")
            {
                "stored_file_origin_is_syntactic"
            } else if source
                .provenance
                .engine
                .ends_with("bounded-mongo-callback-result-summary")
            {
                "mongo_callback_result_origin_is_syntactic"
            } else {
                "stored_model_origin_is_syntactic"
            }
            .to_string(),
        );
    }
    if source
        .provenance
        .engine
        .ends_with("bounded-parameter-return-summary")
    {
        uncertainty_reasons.push("node_parameter_return_summary_is_syntactic".to_string());
    }
    if source
        .provenance
        .engine
        .ends_with("bounded-async-continuation-summary")
    {
        uncertainty_reasons.push("node_async_continuation_summary_is_syntactic".to_string());
    }
    if sink
        .provenance
        .engine
        .ends_with("bounded-parameter-sink-summary")
    {
        uncertainty_reasons.push("node_parameter_sink_summary_is_syntactic".to_string());
    }
    if sink
        .provenance
        .engine
        .ends_with("bounded-libxml2-xxe-summary")
    {
        uncertainty_reasons.push("node_libxml2_xxe_summary_is_syntactic".to_string());
    }
    if source
        .provenance
        .engine
        .ends_with("bounded-angular-rxjs-summary")
    {
        uncertainty_reasons.push("angular_rxjs_source_summary_is_syntactic".to_string());
    }
    if source.capability == Capability::BrowserInput {
        uncertainty_reasons.push("browser_input_boundary_is_syntactic".to_string());
        if source.rule_id.contains("socket-message-source") {
            uncertainty_reasons.push("socket_message_producer_validation_unverified".to_string());
        } else if source.rule_id.contains("message-source") {
            uncertainty_reasons.push("message_event_origin_validation_unverified".to_string());
        } else if source.rule_id.contains("storage-source") {
            uncertainty_reasons.push("browser_storage_writer_origin_unverified".to_string());
        }
    }
    if bounded_string_choice {
        uncertainty_reasons.push("node_value_preserving_reassignment_is_syntactic".to_string());
    }
    if matches!(
        source.rule_id.as_str(),
        CONTROLLER_RULE_ID | MINIMAL_RULE_ID
    ) {
        uncertainty_reasons.push("aspnet_parameter_binding_is_syntactic".to_string());
    } else if source.rule_id == GRPC_RULE_ID
        || source.rule_id == super::go_grpc::GO_GRPC_REQUEST_RULE_ID
    {
        uncertainty_reasons.push("grpc_parameter_binding_is_syntactic".to_string());
    } else if source.rule_id == SIGNALR_RULE_ID {
        uncertainty_reasons.push("signalr_parameter_binding_is_syntactic".to_string());
    } else if source.rule_id == WCF_RULE_ID {
        uncertainty_reasons.push("wcf_contract_implementation_binding_is_syntactic".to_string());
    } else if source.rule_id == FORWARDED_PARAMETER_RULE_ID {
        uncertainty_reasons.push("aspnet_parameter_binding_is_syntactic".to_string());
        uncertainty_reasons.push("controller_service_parameter_summary_is_syntactic".to_string());
        uncertainty_reasons.push("runtime_dispatch_unverified".to_string());
        uncertainty_reasons.push("single_formal_parameter_hop".to_string());
    }
    let id = path_id(source, sink, state, &steps);
    paths.push(SecurityPath {
        id,
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: sink.capability,
        cwe_candidates: family.cwe_candidates.clone(),
        state,
        steps,
        protection_evidence_ids,
        uncertainty_reasons,
        provenance: SecurityPathProvenance {
            engine: "mehscan bounded-local-flow 1".to_string(),
            maximum_propagation_depth: MAX_PROPAGATION_DEPTH,
        },
    });
}

fn path_id(
    source: &Evidence,
    sink: &Evidence,
    state: SecurityPathState,
    steps: &[SecurityPathStep],
) -> String {
    let mut input = format!("{}\0{}\0{state:?}", source.id, sink.id);
    for step in steps {
        input.push_str(&format!(
            "\0{:?}\0{}\0{}",
            step.kind, step.location.start.byte_offset, step.location.end.byte_offset
        ));
    }
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("path-{hash:016x}")
}

fn evidence_step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: if kind == SecurityPathStepKind::Source
            && evidence.rule_id == FORWARDED_PARAMETER_RULE_ID
        {
            evidence
                .captures
                .get("controller_source")
                .map(|capture| capture.location.clone())
                .unwrap_or_else(|| evidence.location.clone())
        } else {
            evidence.location.clone()
        },
        evidence_id: Some(evidence.id.clone()),
        symbol: None,
    }
}

fn node_location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}

fn location_range(location: &Location) -> Range<usize> {
    location.start.byte_offset..location.end.byte_offset
}

fn contains_range(container: Range<usize>, contained: Range<usize>) -> bool {
    container.start <= contained.start && container.end >= contained.end
}

fn same_range(left: &Location, right: &Location) -> bool {
    left.path == right.path
        && left.start.byte_offset == right.start.byte_offset
        && left.end.byte_offset == right.end.byte_offset
}

fn is_definitely_unreachable(evidence: &Evidence) -> bool {
    evidence
        .context
        .reachability
        .as_ref()
        .is_some_and(|reachability| reachability.state == ReachabilityState::Unreachable)
        || evidence
            .context
            .availability
            .as_ref()
            .is_some_and(|availability| availability.state == AvailabilityState::Excluded)
}

fn is_csharp_crypto_policy(evidence: &Evidence) -> bool {
    evidence
        .provenance
        .engine
        .starts_with("mehscan csharp-crypto-policy ")
}
