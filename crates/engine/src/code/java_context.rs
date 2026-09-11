use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, ResourcePolicyContext, ResourcePolicyState,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::java_ingress::{
    is_bound_spring_parameter, is_spring_multipart_parameter, spring_multipart_evidence_id,
    spring_parameter_evidence_id,
};
use super::literals::LiteralEnvironment;
use super::reachability;

pub(crate) const FORWARDED_PARAMETER_RULE_ID: &str =
    "java-spring-controller-service-parameter-source";
pub(crate) const FORWARDED_MULTIPART_RULE_ID: &str =
    "java-spring-controller-service-multipart-source";
const HANDOFF_ENGINE: &str = "mehscan java-controller-service-summary 1";
const REPOSITORY_ENGINE: &str = "mehscan java-spring-data-resource-summary 1";

#[derive(Clone, Debug)]
struct TypeRecord {
    name: String,
    bases: BTreeSet<String>,
    interface: bool,
}

#[derive(Clone, Debug)]
struct ParameterRecord {
    name: String,
    location: Location,
}

#[derive(Clone, Debug)]
struct MethodRecord {
    owner: String,
    name: String,
    parameters: Vec<ParameterRecord>,
    path: String,
}

#[derive(Clone, Debug)]
struct PendingCall {
    receiver_type: String,
    method_name: String,
    argument_count: usize,
    parameter_index: usize,
    controller_parameter: String,
    controller_source: Location,
    controller_call: Location,
    controller_symbol: String,
    multipart: bool,
}

#[derive(Clone, Debug)]
struct ParameterHandoff {
    target_path: String,
    target_parameter: String,
    target_location: Location,
    controller_parameter: String,
    controller_source: Location,
    controller_call: Location,
    controller_symbol: String,
    target_symbol: String,
    multipart: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct JavaProjectContext {
    handoffs: Vec<ParameterHandoff>,
    repositories: BTreeMap<String, String>,
    shell_helpers: BTreeSet<(String, String)>,
}

impl JavaProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let mut types = Vec::new();
        let mut methods = Vec::new();
        let mut calls = Vec::new();
        let mut repositories = BTreeMap::new();
        let mut shell_helpers = BTreeSet::new();
        for (path, language, source) in sources {
            if language != Language::Java {
                continue;
            }
            let Ok(document) = StrDoc::try_new(source, SupportLang::Java) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            if root.dfs().any(|node| node.is_error() || node.is_missing()) {
                continue;
            }
            catalog_types_methods_and_repositories(
                path,
                &root,
                &mut types,
                &mut methods,
                &mut repositories,
                &mut shell_helpers,
            );
            catalog_controller_calls(path, &root, &mut calls);
        }
        let mut handoffs = calls
            .into_iter()
            .filter_map(|call| resolve_call(call, &types, &methods))
            .collect::<Vec<_>>();
        handoffs.sort_by(|left, right| {
            left.target_path
                .cmp(&right.target_path)
                .then_with(|| {
                    left.target_location
                        .start
                        .byte_offset
                        .cmp(&right.target_location.start.byte_offset)
                })
                .then_with(|| {
                    left.controller_source
                        .path
                        .cmp(&right.controller_source.path)
                })
        });
        handoffs.dedup_by(|left, right| {
            left.target_path == right.target_path
                && left.target_location == right.target_location
                && left.controller_source == right.controller_source
        });
        Self {
            handoffs,
            repositories,
            shell_helpers,
        }
    }

    pub(crate) fn is_shell_helper(&self, owner: &str, method: &str) -> bool {
        self.shell_helpers
            .contains(&(owner.to_string(), method.to_string()))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_project_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project: &JavaProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }
    add_forwarded_parameter_sources(
        path,
        root,
        comments,
        conditional,
        literals,
        project,
        evidence,
    );
    add_repository_observations(
        path,
        root,
        comments,
        conditional,
        literals,
        project,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_forwarded_parameter_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project: &JavaProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    for handoff in project
        .handoffs
        .iter()
        .filter(|handoff| handoff.target_path == path)
    {
        let Some(parameter_node) = root.dfs().find(|node| {
            node.range().start == handoff.target_location.start.byte_offset
                && node.range().end == handoff.target_location.end.byte_offset
        }) else {
            continue;
        };
        let rule_id = if handoff.multipart {
            FORWARDED_MULTIPART_RULE_ID
        } else {
            FORWARDED_PARAMETER_RULE_ID
        };
        let id = format!(
            "{}:{}:{}:{}:{}",
            path,
            parameter_node.range().start,
            parameter_node.range().end,
            rule_id,
            handoff.controller_source.start.byte_offset
        );
        evidence.push(Evidence {
            id,
            kind: EvidenceKind::Source,
            capability: if handoff.multipart {
                Capability::UploadedFileContent
            } else {
                Capability::HttpRequestData
            },
            location: handoff.target_location.clone(),
            enclosing_symbol: Some(handoff.target_symbol.clone()),
            captures: BTreeMap::from([
                (
                    "parameter".to_string(),
                    Capture {
                        text: handoff.target_parameter.clone(),
                        location: handoff.target_location.clone(),
                    },
                ),
                (
                    "controller_source".to_string(),
                    Capture {
                        text: handoff.controller_parameter.clone(),
                        location: handoff.controller_source.clone(),
                    },
                ),
                (
                    "controller_call".to_string(),
                    Capture {
                        text: handoff.target_symbol.clone(),
                        location: handoff.controller_call.clone(),
                    },
                ),
            ]),
            cwe_candidates: vec![
                if handoff.multipart {
                    "CWE-434"
                } else {
                    "CWE-20"
                }
                .to_string(),
            ],
            tags: vec![
                "http".to_string(),
                "spring-mvc".to_string(),
                "controller-service-handoff".to_string(),
                "single-hop".to_string(),
                "unique-syntactic-target".to_string(),
                if handoff.multipart {
                    "multipart-content"
                } else {
                    "request-data"
                }
                .to_string(),
                format!("controller:{}", handoff.controller_symbol),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: HANDOFF_ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(parameter_node.range()),
                reachability: Some(reachability::classify(&parameter_node, literals)),
                availability: Some(conditional.availability_for(parameter_node.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: vec![if handoff.multipart {
                spring_multipart_evidence_id(
                    &handoff.controller_source.path,
                    handoff.controller_source.start.byte_offset,
                    handoff.controller_source.end.byte_offset,
                )
            } else {
                spring_parameter_evidence_id(
                    &handoff.controller_source.path,
                    handoff.controller_source.start.byte_offset,
                    handoff.controller_source.end.byte_offset,
                )
            }],
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_repository_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project: &JavaProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    let receiver_types = receiver_types(root);
    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        let (Some(object), Some(name), Some(arguments)) = (
            invocation.field("object"),
            invocation.field("name"),
            invocation.field("arguments"),
        ) else {
            continue;
        };
        let Some(receiver_type) = receiver_types.get(object.text().trim()) else {
            continue;
        };
        let Some(entity) = project.repositories.get(receiver_type) else {
            continue;
        };
        if !is_security_resource_entity(entity) {
            continue;
        }
        let operation = name.text();
        if !(operation.starts_with("findBy")
            || operation.as_ref() == "getById"
            || operation.as_ref() == "getReferenceById"
            || operation.as_ref() == "deleteById"
            || operation.as_ref() == "delete")
        {
            continue;
        }
        let Some(filter) = arguments.children().find(|child| child.is_named()) else {
            continue;
        };
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let owner_scoped =
            is_authenticated_owner_filter(root, &invocation, operation.as_ref(), &filter);
        let rule_id = if owner_scoped {
            "java-spring-data-owner-scoped-resource-control"
        } else {
            "java-spring-data-resource-access"
        };
        let sink_location = location(path, &invocation);
        evidence.push(Evidence {
            id: format!(
                "{}:{}:{}:{}",
                path,
                invocation.range().start,
                invocation.range().end,
                rule_id
            ),
            kind: if owner_scoped {
                EvidenceKind::Validation
            } else {
                EvidenceKind::Sink
            },
            capability: Capability::ResourceAccess,
            location: sink_location,
            enclosing_symbol: enclosing_symbol(&invocation),
            captures: BTreeMap::from([(
                "filter".to_string(),
                Capture {
                    text: filter.text().into_owned(),
                    location: location(path, &filter),
                },
            )]),
            cwe_candidates: vec!["CWE-639".to_string()],
            tags: vec![
                "spring-data".to_string(),
                "resource-access".to_string(),
                format!("repository:{receiver_type}"),
                format!("entity:{entity}"),
                format!("operation:{operation}"),
                if owner_scoped {
                    "authenticated-owner-scoped"
                } else {
                    "verify-owner-or-tenant-policy"
                }
                .to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: REPOSITORY_ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&invocation, literals)),
                availability: Some(conditional.availability_for(invocation.range())),
                literals: BTreeMap::from([("filter".to_string(), literals.evaluate(&filter))]),
                resource_policy: Some(ResourcePolicyContext {
                    state: if owner_scoped {
                        ResourcePolicyState::OwnerScoped
                    } else {
                        ResourcePolicyState::Unknown
                    },
                    basis: if owner_scoped {
                        "repository filter uses an identity obtained from the authenticated request"
                            .to_string()
                    } else {
                        "repository key lacks a proved owner or tenant predicate; verify service or global policy"
                            .to_string()
                    },
                }),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn catalog_types_methods_and_repositories(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    types: &mut Vec<TypeRecord>,
    methods: &mut Vec<MethodRecord>,
    repositories: &mut BTreeMap<String, String>,
    shell_helpers: &mut BTreeSet<(String, String)>,
) {
    let spring_data_imported = imports_spring_data_repository(root);
    for declaration in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "interface_declaration" | "record_declaration"
        )
    }) {
        let Some(name) = declaration
            .field("name")
            .and_then(|node| simple_identifier(node.text().as_ref()))
        else {
            continue;
        };
        let header = declaration
            .text()
            .split('{')
            .next()
            .unwrap_or_default()
            .to_string();
        let bases = declared_bases(&header);
        let interface = declaration.kind().as_ref() == "interface_declaration";
        if interface
            && (spring_data_imported
                || header.contains("org.springframework.data.jpa.repository.JpaRepository")
                || header.contains("org.springframework.data.repository.CrudRepository")
                || header
                    .contains("org.springframework.data.repository.PagingAndSortingRepository"))
            && bases.iter().any(|base| {
                matches!(
                    base.as_str(),
                    "JpaRepository" | "CrudRepository" | "PagingAndSortingRepository"
                )
            })
            && let Some(entity) = repository_entity(&header)
        {
            repositories.insert(name.clone(), entity);
        }
        types.push(TypeRecord {
            name: name.clone(),
            bases,
            interface,
        });
        for method in declaration
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_declaration")
            .filter(|method| immediate_owner(method).as_deref() == Some(name.as_str()))
        {
            let Some(method_name) = method
                .field("name")
                .and_then(|node| simple_identifier(node.text().as_ref()))
            else {
                continue;
            };
            methods.push(MethodRecord {
                owner: name.clone(),
                name: method_name.clone(),
                parameters: method_parameters(path, &method),
                path: path.to_string(),
            });
            if is_shell_helper_method(root, &method) {
                shell_helpers.insert((name.clone(), method_name));
            }
        }
    }
}

fn imports_spring_data_repository(root: &Node<'_, StrDoc<SupportLang>>) -> bool {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .any(|import| {
            matches!(
                import.text().trim(),
                "import org.springframework.data.jpa.repository.JpaRepository;"
                    | "import org.springframework.data.repository.CrudRepository;"
                    | "import org.springframework.data.repository.PagingAndSortingRepository;"
            )
        })
}

fn catalog_controller_calls(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    calls: &mut Vec<PendingCall>,
) {
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let source_parameters = method_parameter_nodes(&method)
            .into_iter()
            .filter(|parameter| is_bound_spring_parameter(root, &method, parameter))
            .filter_map(|parameter| {
                let name = parameter.field("name")?;
                Some((
                    name.text().into_owned(),
                    (
                        location(path, &name),
                        is_spring_multipart_parameter(root, &method, &parameter),
                    ),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        if source_parameters.is_empty() {
            continue;
        }
        let Some(controller_symbol) = method.field("name").map(|name| name.text().into_owned())
        else {
            continue;
        };
        let receivers = receiver_types_for_method(&method);
        for invocation in method
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_invocation")
            .filter(|node| {
                nearest_method(node).is_some_and(|owner| owner.range() == method.range())
            })
        {
            let (Some(object), Some(name), Some(arguments)) = (
                invocation.field("object"),
                invocation.field("name"),
                invocation.field("arguments"),
            ) else {
                continue;
            };
            let Some(receiver_type) = receivers.get(object.text().trim()) else {
                continue;
            };
            if !receiver_type.ends_with("Service") {
                continue;
            }
            let arguments = arguments
                .children()
                .filter(|child| child.is_named())
                .collect::<Vec<_>>();
            for (parameter_index, argument) in arguments.iter().enumerate() {
                let Some((controller_source, multipart)) =
                    source_parameters.get(argument.text().trim())
                else {
                    continue;
                };
                calls.push(PendingCall {
                    receiver_type: receiver_type.clone(),
                    method_name: name.text().into_owned(),
                    argument_count: arguments.len(),
                    parameter_index,
                    controller_parameter: argument.text().into_owned(),
                    controller_source: controller_source.clone(),
                    controller_call: location(path, &invocation),
                    controller_symbol: controller_symbol.clone(),
                    multipart: *multipart,
                });
            }
        }
    }
}

fn resolve_call(
    call: PendingCall,
    types: &[TypeRecord],
    methods: &[MethodRecord],
) -> Option<ParameterHandoff> {
    let implementors = types
        .iter()
        .filter(|kind| !kind.interface && kind.bases.contains(&call.receiver_type))
        .map(|kind| kind.name.clone())
        .collect::<BTreeSet<_>>();
    let owners = if implementors.is_empty() {
        BTreeSet::from([call.receiver_type.clone()])
    } else {
        implementors
    };
    let candidates = methods
        .iter()
        .filter(|method| owners.contains(&method.owner))
        .filter(|method| {
            method.name == call.method_name && method.parameters.len() == call.argument_count
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return None;
    }
    let target = candidates[0];
    let parameter = target.parameters.get(call.parameter_index)?;
    Some(ParameterHandoff {
        target_path: target.path.clone(),
        target_parameter: parameter.name.clone(),
        target_location: parameter.location.clone(),
        controller_parameter: call.controller_parameter,
        controller_source: call.controller_source,
        controller_call: call.controller_call,
        controller_symbol: call.controller_symbol,
        target_symbol: target.name.clone(),
        multipart: call.multipart,
    })
}

fn is_shell_helper_method(
    root: &Node<'_, StrDoc<SupportLang>>,
    method: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    if root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "interface_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().as_ref() == "Runtime")
    }) {
        return false;
    }
    let Some(parameters) = method.field("parameters") else {
        return false;
    };
    let names = parameters
        .children()
        .filter(|node| node.kind().as_ref() == "formal_parameter")
        .filter_map(|parameter| parameter.field("name"))
        .map(|name| name.text().into_owned())
        .collect::<Vec<_>>();
    if names.len() != 1 {
        return false;
    }
    let text = method.text();
    text.contains("Runtime.getRuntime()")
        && text.contains(".exec(")
        && text.contains("\"bash\"")
        && text.contains("\"-c\"")
        && text.contains(&names[0])
}

fn receiver_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for declaration in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "field_declaration" | "local_variable_declaration"
        )
    }) {
        add_declared_receivers(&declaration, &mut result);
    }
    result
}

fn receiver_types_for_method(method: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    if let Some(owner) = method.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "class_declaration" | "record_declaration"
        )
    }) {
        for field in owner
            .dfs()
            .filter(|node| node.kind().as_ref() == "field_declaration")
            .filter(|field| immediate_owner(field) == immediate_owner(method))
        {
            add_declared_receivers(&field, &mut result);
        }
    }
    for local in method
        .dfs()
        .filter(|node| node.kind().as_ref() == "local_variable_declaration")
    {
        add_declared_receivers(&local, &mut result);
    }
    result
}

fn add_declared_receivers(
    declaration: &Node<'_, StrDoc<SupportLang>>,
    result: &mut BTreeMap<String, String>,
) {
    let Some(kind) = declaration
        .field("type")
        .and_then(|kind| type_name(kind.text().as_ref()))
    else {
        return;
    };
    for variable in declaration
        .children()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        if let Some(name) = variable.field("name") {
            result.insert(name.text().into_owned(), kind.clone());
        }
    }
}

fn is_authenticated_owner_filter(
    root: &Node<'_, StrDoc<SupportLang>>,
    invocation: &Node<'_, StrDoc<SupportLang>>,
    operation: &str,
    filter: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    if !["owner", "user", "tenant", "account"]
        .iter()
        .any(|part| operation.to_ascii_lowercase().contains(part))
    {
        return false;
    }
    let filter_text = filter.text();
    let Some(subject) = filter_text.split('.').next().and_then(simple_identifier) else {
        return false;
    };
    let scope = invocation
        .ancestors()
        .find(|node| node.kind().as_ref() == "method_declaration")
        .map(|node| node.range())
        .unwrap_or_else(|| root.range());
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "variable_declarator" | "assignment_expression"
            )
        })
        .filter(|node| {
            scope.start <= node.range().start && node.range().end < invocation.range().start
        })
        .any(|variable| {
            variable
                .field("name")
                .or_else(|| variable.field("left"))
                .is_some_and(|name| name.text().as_ref() == subject)
                && variable
                    .field("value")
                    .or_else(|| variable.field("right"))
                    .is_some_and(|value| {
                        let text = value.text();
                        text.contains("getUserFromToken(")
                            || text.contains("getPrincipal(")
                            || text.contains("SecurityContextHolder")
                    })
        })
}

fn repository_entity(header: &str) -> Option<String> {
    [
        "JpaRepository<",
        "CrudRepository<",
        "PagingAndSortingRepository<",
    ]
    .iter()
    .find_map(|marker| {
        let rest = header.split_once(marker)?.1;
        type_name(rest.split([',', '>']).next()?.trim())
    })
}

fn is_security_resource_entity(entity: &str) -> bool {
    !matches!(
        entity,
        "User" | "Otp" | "ChangeEmailRequest" | "ChangePhoneRequest"
    )
}

fn declared_bases(header: &str) -> BTreeSet<String> {
    header
        .split_whitespace()
        .skip_while(|part| *part != "extends" && *part != "implements")
        .skip(1)
        .flat_map(|part| part.split(','))
        .filter_map(type_name)
        .collect()
}

fn method_parameters(path: &str, method: &Node<'_, StrDoc<SupportLang>>) -> Vec<ParameterRecord> {
    method_parameter_nodes(method)
        .into_iter()
        .filter_map(|parameter| {
            let name = parameter.field("name")?;
            Some(ParameterRecord {
                name: name.text().into_owned(),
                location: location(path, &name),
            })
        })
        .collect()
}

fn method_parameter_nodes<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    method
        .field("parameters")
        .map(|parameters| {
            parameters
                .children()
                .filter(|node| node.kind().as_ref() == "formal_parameter")
                .collect()
        })
        .unwrap_or_default()
}

fn immediate_owner(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "class_declaration" | "interface_declaration" | "record_declaration"
            )
        })?
        .field("name")
        .map(|name| name.text().into_owned())
}

fn nearest_method<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
}

fn simple_identifier(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()
        && text.chars().enumerate().all(|(index, ch)| {
            ch == '_' || ch == '$' || ch.is_alphanumeric() && (index > 0 || !ch.is_numeric())
        }))
    .then(|| text.to_string())
}

fn type_name(text: &str) -> Option<String> {
    let text = text.trim().split('<').next()?.trim();
    let text = text.rsplit('.').next()?.trim();
    simple_identifier(text)
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let range = node.range();
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: range.start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: range.end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}
