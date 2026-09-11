use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, ResourcePolicyContext, ResourcePolicyState,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "ast-grep 0.45.1 + bounded-node-object-input";

#[derive(Clone, Debug, Default)]
pub(crate) struct ObjectInputProjectContext {
    sensitive_model_fields: BTreeMap<String, BTreeSet<String>>,
    has_mongodb_driver: bool,
}

impl ObjectInputProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let mut context = Self::default();
        for (_, language, source) in sources {
            if !is_node_language(language) {
                continue;
            }
            context.has_mongodb_driver |= source.contains("require('mongodb')")
                || source.contains("require(\"mongodb\")")
                || source.contains("from 'mongodb'")
                || source.contains("from \"mongodb\"");
            collect_sensitive_model_fields(source, &mut context.sensitive_model_fields);
        }
        context
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        source: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) || is_non_runtime_example_path(path) {
            return;
        }
        let source_lower = source.to_ascii_lowercase();
        if source_lower.contains("collection.") || source_lower.contains(".collection(") {
            add_nosql_observations(
                path,
                root,
                language,
                comments,
                conditional,
                literals,
                self.has_mongodb_driver,
                evidence,
            );
        }
        if contains_request_body(&source_lower)
            && [".create(", ".build(", ".update("]
                .iter()
                .any(|operation| source_lower.contains(operation))
        {
            self.add_direct_mass_assignment(
                path,
                root,
                language,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if source_lower.contains("...req.body") || source_lower.contains("...request.body") {
            self.add_typed_object_mass_assignment(
                path,
                root,
                language,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if source_lower.contains("finale.resource") {
            self.add_generated_mass_assignment(
                path,
                source,
                root,
                language,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if contains_request_member(&source_lower) && source_lower.contains(".find(") {
            self.add_in_memory_resource_access(
                path,
                root,
                language,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if contains_request_member(&source_lower)
            && (source_lower.contains('[')
                || source_lower.contains(".set(")
                || source_lower.contains(".merge("))
        {
            add_prototype_pollution_observations(
                path,
                root,
                language,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_typed_object_mass_assignment<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        for declaration in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "variable_declarator")
        {
            let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
            else {
                continue;
            };
            let Some(request) = direct_body_or_spread(&value) else {
                continue;
            };
            let declaration_text = declaration.text();
            let Some(model) = declared_type_name(declaration_text.as_ref()) else {
                continue;
            };
            let Some(fields) = self.sensitive_model_fields.get(model) else {
                continue;
            };
            let scope = function_scope(&declaration, root);
            let persisted = root.dfs().filter_map(call_site).any(|call| {
                call.node.range().start > declaration.range().end
                    && call.node.range().end <= scope.end
                    && matches!(terminal_symbol(&call.callee), "push" | "save" | "insert")
                    && call
                        .arguments
                        .iter()
                        .any(|argument| argument.text().trim() == name.text().trim())
            });
            if !persisted {
                continue;
            }
            push_object_input_pair(
                path,
                language,
                "mass-assignment-request-body",
                "mass-assignment-sensitive-model",
                &request,
                &request,
                &value,
                "assigned_fields",
                Capability::ResourceAccess,
                "CWE-915",
                vec![
                    "mass-assignment".to_string(),
                    "typed-object-spread".to_string(),
                    "bounded-persistence-use".to_string(),
                    format!("model:{model}"),
                    format!("sensitive-fields:{}", join_fields(fields)),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_in_memory_resource_access<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        for call in root.dfs().filter_map(call_site) {
            let Some(receiver) = call.callee.strip_suffix(".find") else {
                continue;
            };
            if simple_identifier(receiver).is_none()
                || call.arguments.len() != 1
                || comments.is_in_comment(call.node.range())
            {
                continue;
            }
            let Some(model) = typed_array_model(root.text().as_ref(), receiver) else {
                continue;
            };
            if !self.sensitive_model_fields.contains_key(&model) {
                continue;
            }
            let filter = &call.arguments[0];
            let scope = function_scope(&call.node, root);
            let Some(request) =
                request_use_in(root, filter, &scope, call.node.range().start, false)
            else {
                continue;
            };
            if !request_transport_is_scalar(&request.origin)
                || !compact(filter.text().as_ref())
                    .to_ascii_lowercase()
                    .contains(".id")
            {
                continue;
            }
            let owner_scoped = has_authenticated_owner_constraint(filter.text().as_ref());
            push_object_input_pair(
                path,
                language,
                "in-memory-resource-id",
                "in-memory-resource-access",
                &request.use_node,
                &request.origin,
                &call.node,
                "filter",
                Capability::ResourceAccess,
                "CWE-639",
                vec![
                    "authorization".to_string(),
                    "idor".to_string(),
                    "in-memory-collection".to_string(),
                    format!("model:{model}"),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
            if owner_scoped {
                let sink_rule = language_rule(language, "in-memory-resource-access");
                if let Some(item) = evidence.iter_mut().find(|item| {
                    item.rule_id == sink_rule
                        && item.location.start.byte_offset == call.node.range().start
                }) {
                    item.context.resource_policy = Some(ResourcePolicyContext {
                        state: ResourcePolicyState::OwnerScoped,
                        basis: "authenticated owner or tenant constraint is present in the in-memory filter"
                            .to_string(),
                    });
                    item.tags.push("owner-scoped".to_string());
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_direct_mass_assignment<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            let operation = terminal_symbol(&call.callee);
            if !matches!(operation, "create" | "build" | "update")
                || call.arguments.is_empty()
                || comments.is_in_comment(call.node.range())
            {
                continue;
            }
            let Some(receiver) = call.callee.strip_suffix(&format!(".{operation}")) else {
                continue;
            };
            let Some(model) = model_name(receiver) else {
                continue;
            };
            let Some(fields) = self.sensitive_model_fields.get(&model) else {
                continue;
            };
            let assigned = &call.arguments[0];
            let Some(request) = direct_body_or_spread(assigned) else {
                continue;
            };
            push_object_input_pair(
                path,
                language,
                "mass-assignment-request-body",
                "mass-assignment-sensitive-model",
                &request,
                &request,
                &call.node,
                "assigned_fields",
                Capability::ResourceAccess,
                "CWE-915",
                vec![
                    "mass-assignment".to_string(),
                    "model-write".to_string(),
                    format!("model:{model}"),
                    format!("sensitive-fields:{}", join_fields(fields)),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_generated_mass_assignment<'tree>(
        &self,
        path: &str,
        source: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        let Some(fields) = self.sensitive_model_fields.get("User") else {
            return;
        };
        let Some(excluded) = generated_user_resource_exclusions(source) else {
            return;
        };
        let exposed = fields
            .iter()
            .filter(|field| !excluded.contains(normalize_name(field).as_str()))
            .cloned()
            .collect::<BTreeSet<_>>();
        if exposed.is_empty()
            || !source.contains("app.post('/api/Users'")
            || source.contains("app.post('/api/Users', security.denyAll())")
        {
            return;
        }
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            if call.callee != "finale.resource"
                || call.arguments.len() != 1
                || comments.is_in_comment(call.node.range())
            {
                continue;
            }
            let configuration = &call.arguments[0];
            let compact_configuration = compact(configuration.text().as_ref());
            if !compact_configuration.contains("model,")
                || !compact_configuration.contains("endpoints:")
                || !compact_configuration.contains("/api/${name}s")
            {
                continue;
            }
            let endpoint = configuration
                .dfs()
                .filter(|candidate| candidate.is_named())
                .find(|candidate| candidate.text().contains("/api/${name}s"))
                .unwrap_or_else(|| configuration.clone());
            push_object_input_pair(
                path,
                language,
                "generated-resource-request-body",
                "generated-resource-mass-assignment",
                &endpoint,
                &endpoint,
                &call.node,
                "assigned_fields",
                Capability::ResourceAccess,
                "CWE-915",
                vec![
                    "mass-assignment".to_string(),
                    "generated-rest-resource".to_string(),
                    "model:User".to_string(),
                    format!("sensitive-fields:{}", join_fields(&exposed)),
                    "route:POST /api/Users".to_string(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_nosql_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    has_dedicated_mongodb_observations: bool,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        let operation = terminal_symbol(&call.callee);
        if !matches!(
            operation,
            "find" | "findOne" | "update" | "remove" | "delete"
        ) || call.arguments.is_empty()
            || !is_collection_receiver(&call.callee, operation)
            || comments.is_in_comment(call.node.range())
        {
            continue;
        }
        let selector = &call.arguments[0];
        if !matches!(selector.kind().as_ref(), "object" | "object_expression") {
            continue;
        }
        let has_where = object_has_key(selector, "$where");
        if has_where && has_dedicated_mongodb_observations {
            continue;
        }
        let scope = function_scope(&call.node, root);
        let Some(request) =
            request_use_in(root, selector, &scope, selector.range().start, has_where)
        else {
            continue;
        };
        if request.definitely_scalar
            || (!has_where && request_transport_is_scalar(&request.origin))
            || has_rejecting_string_guard(
                root,
                &call.node,
                &scope,
                &request.use_node,
                &request.origin,
                literals,
            )
        {
            continue;
        }
        let mut tags = vec![
            "nosql".to_string(),
            "query-selector".to_string(),
            format!("operation:{operation}"),
        ];
        tags.push(if has_where {
            "javascript-predicate".to_string()
        } else {
            "operator-capable-value".to_string()
        });
        push_object_input_pair(
            path,
            language,
            "nosql-request-value",
            "nosql-query-selector",
            &request.use_node,
            &request.origin,
            &call.node,
            "nosql_query",
            Capability::DatabaseQuery,
            "CWE-943",
            tags,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_prototype_pollution_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs() {
        let candidate = if node.kind().as_ref() == "assignment_expression" {
            dynamic_property_assignment(root, &node)
        } else {
            deep_set_call(root, node)
        };
        let Some(candidate) = candidate else {
            continue;
        };
        if comments.is_in_comment(candidate.sink.range()) {
            continue;
        }
        let Some(request) = request_use_in(
            root,
            &candidate.key,
            &candidate.scope,
            candidate.sink.range().start,
            false,
        ) else {
            continue;
        };
        if null_prototype_target(
            root,
            &candidate.target,
            candidate.sink.range().start,
            &candidate.scope,
        ) || rejects_prototype_keys(
            root,
            &candidate.sink,
            &candidate.scope,
            &candidate.key,
            literals,
        ) {
            continue;
        }
        push_object_input_pair(
            path,
            language,
            "prototype-key-request-value",
            "prototype-pollution-dynamic-write",
            &request.use_node,
            &request.origin,
            &candidate.sink,
            "property_key",
            Capability::ResourceAccess,
            "CWE-1321",
            vec![
                "prototype-pollution".to_string(),
                "dynamic-property-write".to_string(),
                format!("target:{}", candidate.target),
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    add_lodash_merge_observations(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_lodash_merge_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        if terminal_symbol(&call.callee) != "merge"
            || call.arguments.len() < 2
            || comments.is_in_comment(call.node.range())
        {
            continue;
        }
        let Some(binding) = call.callee.strip_suffix(".merge") else {
            continue;
        };
        if !is_lodash_binding(root.text().as_ref(), binding) {
            continue;
        }
        let scope = function_scope(&call.node, root);
        let source_value = &call.arguments[1];
        let Some(request) =
            request_use_in(root, source_value, &scope, call.node.range().start, false)
        else {
            continue;
        };
        push_object_input_pair(
            path,
            language,
            "prototype-key-request-value",
            "prototype-pollution-dynamic-write",
            &request.use_node,
            &request.origin,
            &call.node,
            "property_key",
            Capability::ResourceAccess,
            "CWE-1321",
            vec![
                "prototype-pollution".to_string(),
                "lodash-merge".to_string(),
                "request-controlled-source-object".to_string(),
                "dependency-version-sensitive".to_string(),
                "affected-before-lodash-4.17.11".to_string(),
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn is_lodash_binding(source: &str, binding: &str) -> bool {
    [
        format!("import * as {binding} from 'lodash'"),
        format!("import * as {binding} from \"lodash\""),
        format!("import {binding} from 'lodash'"),
        format!("import {binding} from \"lodash\""),
        format!("const {binding} = require('lodash')"),
        format!("const {binding} = require(\"lodash\")"),
    ]
    .iter()
    .any(|import| source.contains(import))
}

struct PrototypeCandidate<'tree> {
    sink: Node<'tree, StrDoc<SupportLang>>,
    key: Node<'tree, StrDoc<SupportLang>>,
    target: String,
    scope: Range<usize>,
}

fn dynamic_property_assignment<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    assignment: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<PrototypeCandidate<'tree>> {
    let left = assignment.field("left")?;
    if left.kind().as_ref() != "subscript_expression" {
        return None;
    }
    let target = left.field("object")?.text().trim().to_string();
    simple_identifier(&target)?;
    let key = left.field("index")?;
    if !may_reference_request_key(assignment, &key, root) {
        return None;
    }
    Some(PrototypeCandidate {
        sink: assignment.clone(),
        key,
        target,
        scope: function_scope(assignment, root),
    })
}

fn deep_set_call<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    node: Node<'tree, StrDoc<SupportLang>>,
) -> Option<PrototypeCandidate<'tree>> {
    let call = call_site(node)?;
    if terminal_symbol(&call.callee) != "set"
        || call.arguments.len() < 3
        || !(call.callee.starts_with("_.")
            || call.callee.starts_with("lodash.")
            || call.callee == "set")
    {
        return None;
    }
    let target = call.arguments[0].text().trim().to_string();
    simple_identifier(&target)?;
    let key = call.arguments[1].clone();
    if !may_reference_request_key(&call.node, &key, root) {
        return None;
    }
    Some(PrototypeCandidate {
        sink: call.node.clone(),
        key,
        target,
        scope: function_scope(&call.node, root),
    })
}

fn may_reference_request_key<'tree>(
    sink: &Node<'tree, StrDoc<SupportLang>>,
    key: &Node<'tree, StrDoc<SupportLang>>,
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> bool {
    if direct_request_expression(key) {
        return true;
    }
    if simple_identifier(key.text().trim()).is_none() {
        return false;
    }
    let scope = sink
        .ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        })
        .unwrap_or_else(|| root.clone());
    let text = scope.text();
    [
        "req.body",
        "req.query",
        "req.params",
        "request.body",
        "request.query",
        "request.params",
    ]
    .iter()
    .any(|request| text.contains(request))
}

struct RequestUse<'tree> {
    use_node: Node<'tree, StrDoc<SupportLang>>,
    origin: Node<'tree, StrDoc<SupportLang>>,
    definitely_scalar: bool,
}

fn request_use_in<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    expression: &Node<'tree, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    before: usize,
    string_interpolation: bool,
) -> Option<RequestUse<'tree>> {
    let mut candidates = expression
        .dfs()
        .filter(|node| node.is_named())
        .collect::<Vec<_>>();
    candidates.sort_by_key(|node| node.range().end - node.range().start);
    for use_node in candidates {
        if direct_request_expression(&use_node) {
            return Some(RequestUse {
                use_node: use_node.clone(),
                origin: use_node,
                definitely_scalar: false,
            });
        }
        if use_node.kind().as_ref() != "identifier" || is_member_property(&use_node) {
            continue;
        }
        let name = use_node.text();
        let name = name.trim();
        let Some(value) = latest_assigned_value(root, name, before, scope) else {
            continue;
        };
        let Some((origin, definitely_scalar)) = trace_request_origin(
            root,
            &value,
            scope,
            value.range().start,
            0,
            string_interpolation,
        ) else {
            continue;
        };
        return Some(RequestUse {
            use_node,
            origin,
            definitely_scalar,
        });
    }
    None
}

fn trace_request_origin<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    before: usize,
    depth: usize,
    string_interpolation: bool,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, bool)> {
    if depth > 4 {
        return None;
    }
    if direct_request_expression(value) || is_request_body(value.text().trim()) {
        return Some((value.clone(), false));
    }
    let compact_value = compact(value.text().as_ref());
    let direct_scalar = !string_interpolation
        && (compact_value.starts_with("Number(")
            || compact_value.starts_with("parseInt(")
            || compact_value.starts_with("parseFloat("));
    for node in value.dfs().filter(|node| node.is_named()) {
        if direct_request_expression(&node) {
            return Some((node, direct_scalar));
        }
    }
    for identifier in value
        .dfs()
        .filter(|node| node.kind().as_ref() == "identifier" && !is_member_property(node))
    {
        let name = identifier.text();
        let Some(assigned) = latest_assigned_value(root, name.trim(), before, scope) else {
            continue;
        };
        if let Some((origin, scalar)) = trace_request_origin(
            root,
            &assigned,
            scope,
            assigned.range().start,
            depth + 1,
            string_interpolation,
        ) {
            return Some((origin, direct_scalar || scalar));
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn push_object_input_pair<'tree>(
    path: &str,
    language: Language,
    source_suffix: &str,
    sink_suffix: &str,
    source_node: &Node<'tree, StrDoc<SupportLang>>,
    origin: &Node<'tree, StrDoc<SupportLang>>,
    sink_node: &Node<'tree, StrDoc<SupportLang>>,
    sink_role: &str,
    capability: Capability,
    cwe: &str,
    tags: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let source_rule = language_rule(language, source_suffix);
    let sink_rule = language_rule(language, sink_suffix);
    let source_id = evidence_id(
        path,
        source_rule,
        source_node.range().start,
        source_node.range().end,
    );
    if !evidence.iter().any(|item| item.id == source_id) {
        let mut captures = BTreeMap::new();
        captures.insert("name".to_string(), capture(path, source_node));
        captures.insert("origin".to_string(), capture(path, origin));
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location(path, source_node),
            enclosing_symbol: enclosing_symbol(sink_node),
            captures,
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "http".to_string(),
                "request".to_string(),
                "bounded-object-input".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(source_node, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule.to_string(),
            related_evidence: Vec::new(),
        });
    }
    let sink_id = evidence_id(
        path,
        sink_rule,
        sink_node.range().start,
        sink_node.range().end,
    );
    if evidence.iter().any(|item| item.id == sink_id) {
        return;
    }
    let mut captures = BTreeMap::new();
    captures.insert(sink_role.to_string(), capture(path, source_node));
    captures.insert("operation".to_string(), capture(path, sink_node));
    evidence.push(Evidence {
        id: sink_id,
        kind: EvidenceKind::Sink,
        capability,
        location: location(path, sink_node),
        enclosing_symbol: enclosing_symbol(sink_node),
        captures,
        cwe_candidates: vec![cwe.to_string()],
        tags,
        confidence: Confidence::Medium,
        provenance: provenance(),
        context: evidence_context(sink_node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: sink_rule.to_string(),
        related_evidence: vec![source_id],
    });
}

fn collect_sensitive_model_fields(source: &str, models: &mut BTreeMap<String, BTreeSet<String>>) {
    collect_sensitive_interface_fields(source, models);
    let mut cursor = 0;
    while let Some(relative_init) = source[cursor..].find(".init(") {
        let init = cursor + relative_init;
        let receiver_start = source[..init]
            .char_indices()
            .rev()
            .take_while(|(_, character)| character.is_ascii_alphanumeric() || *character == '_')
            .last()
            .map(|(index, _)| index)
            .unwrap_or(init);
        let receiver = &source[receiver_start..init];
        let Some(model) = model_name(receiver) else {
            cursor = init + ".init(".len();
            continue;
        };
        let arguments_start = init + ".init(".len();
        let Some(relative_object) = source[arguments_start..].find('{') else {
            cursor = arguments_start;
            continue;
        };
        let object_start = arguments_start + relative_object;
        let Some(object_end) = matching_brace(source, object_start) else {
            cursor = arguments_start;
            continue;
        };
        let fields = top_level_sensitive_keys(&source[object_start..=object_end]);
        if !fields.is_empty() {
            models.entry(model).or_default().extend(fields);
        }
        cursor = object_end + 1;
    }
}

fn collect_sensitive_interface_fields(
    source: &str,
    models: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let mut cursor = 0;
    while let Some(relative_interface) = source[cursor..].find("interface ") {
        let start = cursor + relative_interface + "interface ".len();
        let name = source[start..]
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .next()
            .unwrap_or_default();
        let Some(relative_object) = source[start + name.len()..].find('{') else {
            break;
        };
        let object_start = start + name.len() + relative_object;
        let Some(object_end) = matching_brace(source, object_start) else {
            break;
        };
        let fields = top_level_sensitive_keys(&source[object_start..=object_end]);
        if !name.is_empty() && !fields.is_empty() {
            models.entry(name.to_string()).or_default().extend(fields);
        }
        cursor = object_end + 1;
    }
}

fn declared_type_name(declaration: &str) -> Option<&str> {
    let left = declaration.split_once('=')?.0;
    let type_name = left.split_once(':')?.1.trim();
    simple_identifier(type_name)
}

fn typed_array_model(source: &str, receiver: &str) -> Option<String> {
    let compact_source = compact(source);
    for declaration in ["const", "let", "var"] {
        let marker = format!("{declaration}{receiver}:");
        let Some(after) = compact_source.split_once(&marker).map(|(_, after)| after) else {
            continue;
        };
        let Some((model, _)) = after.split_once("[]") else {
            continue;
        };
        return simple_identifier(model).map(str::to_string);
    }
    None
}

fn has_authenticated_owner_constraint(filter: &str) -> bool {
    let compact_filter = compact(filter).to_ascii_lowercase().replace("?.", ".");
    [
        "ownerid",
        "userid",
        "accountid",
        "tenantid",
        "organizationid",
    ]
    .iter()
    .any(|field| compact_filter.contains(&format!(".{field}===req.user.")))
}

fn matching_brace(source: &str, start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (relative, character) in source[start..].char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '{' => depth += 1,
            '}' if depth == 1 => return Some(start + relative),
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn top_level_sensitive_keys(object: &str) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    let mut depth = 0usize;
    for line in object.lines() {
        if depth == 1 {
            let candidate = line
                .trim_start()
                .split_once(':')
                .map(|(key, _)| key.trim().trim_matches(['\'', '"']));
            if let Some(field) = candidate.filter(|field| is_mass_assignment_sensitive(field)) {
                fields.insert(field.to_string());
            }
        }
        depth = brace_depth_after_line(line, depth);
    }
    fields
}

fn brace_depth_after_line(line: &str, mut depth: usize) -> usize {
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

fn generated_user_resource_exclusions(source: &str) -> Option<BTreeSet<String>> {
    let line = source.lines().find(|line| {
        let line = compact(line);
        line.contains("name:'User'") && line.contains("model:UserModel")
    })?;
    let compact_line = compact(line);
    let excluded = compact_line.split_once("exclude:[")?.1.split_once(']')?.0;
    Some(
        excluded
            .split(',')
            .filter_map(|field| exact_quoted(field).map(normalize_name))
            .collect(),
    )
}

fn direct_body_or_spread<'tree>(
    value: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if is_request_body(value.text().trim()) {
        return Some(value.clone());
    }
    if !matches!(value.kind().as_ref(), "object" | "object_expression") {
        return None;
    }
    value
        .children()
        .filter(|child| child.kind().as_ref() == "spread_element")
        .find_map(|spread| {
            spread
                .children()
                .find(|child| child.is_named() && is_request_body(child.text().trim()))
        })
}

fn has_rejecting_string_guard<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    sink: &Node<'tree, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    use_node: &Node<'tree, StrDoc<SupportLang>>,
    origin: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> bool {
    let names = [
        compact(use_node.text().as_ref()),
        compact(origin.text().as_ref()),
    ];
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "if_statement"
                && scope.start <= node.range().start
                && node.range().end <= sink.range().start
                && function_scope(node, root) == *scope
        })
        .any(|statement| {
            let (Some(condition), Some(consequence)) =
                (statement.field("condition"), statement.field("consequence"))
            else {
                return false;
            };
            if !reachability::always_terminates(&consequence, literals) {
                return false;
            }
            let condition = compact(condition.text().as_ref());
            names.iter().any(|name| {
                condition.contains(&format!("typeof{name}!=='string'"))
                    || condition.contains(&format!("typeof{name}!=\"string\""))
                    || condition.contains(&format!("typeof{name}!==\"string\""))
                    || condition.contains(&format!("typeof{name}!='string'"))
            })
        })
}

fn rejects_prototype_keys<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    sink: &Node<'tree, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    key: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> bool {
    let key = compact(key.text().as_ref());
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "if_statement"
                && scope.start <= node.range().start
                && node.range().end <= sink.range().start
                && function_scope(node, root) == *scope
        })
        .any(|statement| {
            let (Some(condition), Some(consequence)) =
                (statement.field("condition"), statement.field("consequence"))
            else {
                return false;
            };
            let text = compact(condition.text().as_ref()).to_ascii_lowercase();
            text.contains(&key.to_ascii_lowercase())
                && text.contains("__proto__")
                && text.contains("prototype")
                && text.contains("constructor")
                && reachability::always_terminates(&consequence, literals)
        })
}

fn null_prototype_target(
    root: &Node<'_, StrDoc<SupportLang>>,
    target: &str,
    before: usize,
    scope: &Range<usize>,
) -> bool {
    latest_assigned_value(root, target, before, scope).is_some_and(|value| {
        compact(value.text().as_ref()).eq_ignore_ascii_case("object.create(null)")
    })
}

fn request_transport_is_scalar(origin: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let text = compact(origin.text().as_ref()).replace("?.", ".");
    text.starts_with("req.params.") || text.starts_with("request.params.")
}

fn direct_request_expression(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if !matches!(
        node.kind().as_ref(),
        "member_expression" | "member_access_expression" | "subscript_expression"
    ) {
        return false;
    }
    let text = compact(node.text().as_ref()).replace("?.", ".");
    [
        "req.body.",
        "req.query.",
        "req.params.",
        "request.body.",
        "request.query.",
        "request.params.",
    ]
    .iter()
    .any(|prefix| text.starts_with(prefix) && text.len() > prefix.len())
}

fn is_member_property(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind().as_ref(),
            "member_expression" | "member_access_expression"
        ) && parent
            .field("property")
            .or_else(|| parent.field("name"))
            .is_some_and(|property| property.range() == node.range())
    })
}

fn latest_assigned_value<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    before: usize,
    scope: &Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter_map(|node| {
            if node.range().end > before || function_scope(&node, root) != *scope {
                return None;
            }
            match node.kind().as_ref() {
                "variable_declarator"
                    if node
                        .field("name")
                        .is_some_and(|field| field.text().trim() == name) =>
                {
                    node.field("value").map(|value| (node.range().start, value))
                }
                "variable_declarator"
                    if node.field("name").is_some_and(|field| {
                        matches!(field.kind().as_ref(), "object_pattern" | "object")
                            && field
                                .text()
                                .trim()
                                .trim_matches(['{', '}'])
                                .split(',')
                                .any(|member| member.trim() == name)
                    }) =>
                {
                    node.field("value").map(|value| (node.range().start, value))
                }
                "assignment_expression"
                    if node
                        .field("left")
                        .is_some_and(|field| field.text().trim() == name) =>
                {
                    node.field("right").map(|value| (node.range().start, value))
                }
                _ => None,
            }
        })
        .max_by_key(|(start, _)| *start)
        .map(|(_, value)| value)
}

fn object_has_key(object: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    object
        .children()
        .filter(|property| property.is_named())
        .filter_map(|property| property.field("key"))
        .filter_map(|key| exact_property_key(&key))
        .any(|key| key == expected)
}

fn exact_property_key(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let text = node.text();
    exact_quoted(text.trim())
        .or_else(|| simple_identifier(text.trim()))
        .or_else(|| {
            let text = text.trim();
            text.strip_prefix('$')
                .filter(|name| simple_identifier(name).is_some())
                .map(|_| text)
        })
        .map(str::to_string)
}

fn is_collection_receiver(callee: &str, operation: &str) -> bool {
    let Some(receiver) = callee.strip_suffix(&format!(".{operation}")) else {
        return false;
    };
    receiver.contains(".collection(")
        || receiver
            .rsplit('.')
            .next()
            .is_some_and(|receiver| normalize_name(receiver).ends_with("collection"))
}

fn is_mass_assignment_sensitive(field: &str) -> bool {
    matches!(
        normalize_name(field).as_str(),
        "role"
            | "roles"
            | "admin"
            | "isadmin"
            | "permissions"
            | "privileges"
            | "verified"
            | "emailverified"
            | "isactive"
            | "balance"
            | "credit"
            | "userid"
            | "ownerid"
            | "accountid"
            | "tenantid"
    )
}

fn model_name(receiver: &str) -> Option<String> {
    let terminal = receiver.rsplit('.').next()?;
    let model = terminal.strip_suffix("Model").unwrap_or(terminal);
    simple_identifier(model).map(str::to_string)
}

fn join_fields(fields: &BTreeSet<String>) -> String {
    fields.iter().cloned().collect::<Vec<_>>().join(",")
}

fn is_request_body(text: &str) -> bool {
    matches!(
        compact(text).replace("?.", ".").as_str(),
        "req.body" | "request.body"
    )
}

fn contains_request_body(source_lower: &str) -> bool {
    source_lower.contains("req.body") || source_lower.contains("request.body")
}

fn contains_request_member(source_lower: &str) -> bool {
    [
        "req.body",
        "req.query",
        "req.params",
        "request.body",
        "request.query",
        "request.params",
    ]
    .iter()
    .any(|request| source_lower.contains(request))
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let text = node.text();
    let callee = text.get(..callee_length)?.trim().to_string();
    let arguments = arguments
        .children()
        .filter(|child| {
            child.is_named() && !super::comments::is_comment_kind(child.kind().as_ref())
        })
        .collect();
    Some(CallSite {
        node,
        callee,
        arguments,
    })
}

fn function_scope(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        })
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn language_rule(language: Language, suffix: &str) -> &'static str {
    match (language, suffix) {
        (Language::Javascript, "nosql-request-value") => "javascript-nosql-request-value",
        (Language::Typescript, "nosql-request-value") => "typescript-nosql-request-value",
        (Language::Tsx, "nosql-request-value") => "tsx-nosql-request-value",
        (Language::Javascript, "nosql-query-selector") => "javascript-nosql-query-selector",
        (Language::Typescript, "nosql-query-selector") => "typescript-nosql-query-selector",
        (Language::Tsx, "nosql-query-selector") => "tsx-nosql-query-selector",
        (Language::Javascript, "mass-assignment-request-body") => {
            "javascript-mass-assignment-request-body"
        }
        (Language::Typescript, "mass-assignment-request-body") => {
            "typescript-mass-assignment-request-body"
        }
        (Language::Tsx, "mass-assignment-request-body") => "tsx-mass-assignment-request-body",
        (Language::Javascript, "mass-assignment-sensitive-model") => {
            "javascript-mass-assignment-sensitive-model"
        }
        (Language::Typescript, "mass-assignment-sensitive-model") => {
            "typescript-mass-assignment-sensitive-model"
        }
        (Language::Tsx, "mass-assignment-sensitive-model") => "tsx-mass-assignment-sensitive-model",
        (Language::Javascript, "generated-resource-request-body") => {
            "javascript-generated-resource-request-body"
        }
        (Language::Typescript, "generated-resource-request-body") => {
            "typescript-generated-resource-request-body"
        }
        (Language::Tsx, "generated-resource-request-body") => "tsx-generated-resource-request-body",
        (Language::Javascript, "generated-resource-mass-assignment") => {
            "javascript-generated-resource-mass-assignment"
        }
        (Language::Typescript, "generated-resource-mass-assignment") => {
            "typescript-generated-resource-mass-assignment"
        }
        (Language::Tsx, "generated-resource-mass-assignment") => {
            "tsx-generated-resource-mass-assignment"
        }
        (Language::Javascript, "in-memory-resource-id") => "javascript-in-memory-resource-id",
        (Language::Typescript, "in-memory-resource-id") => "typescript-in-memory-resource-id",
        (Language::Tsx, "in-memory-resource-id") => "tsx-in-memory-resource-id",
        (Language::Javascript, "in-memory-resource-access") => {
            "javascript-in-memory-resource-access"
        }
        (Language::Typescript, "in-memory-resource-access") => {
            "typescript-in-memory-resource-access"
        }
        (Language::Tsx, "in-memory-resource-access") => "tsx-in-memory-resource-access",
        (Language::Javascript, "prototype-key-request-value") => {
            "javascript-prototype-key-request-value"
        }
        (Language::Typescript, "prototype-key-request-value") => {
            "typescript-prototype-key-request-value"
        }
        (Language::Tsx, "prototype-key-request-value") => "tsx-prototype-key-request-value",
        (Language::Javascript, "prototype-pollution-dynamic-write") => {
            "javascript-prototype-pollution-dynamic-write"
        }
        (Language::Typescript, "prototype-pollution-dynamic-write") => {
            "typescript-prototype-pollution-dynamic-write"
        }
        (Language::Tsx, "prototype-pollution-dynamic-write") => {
            "tsx-prototype-pollution-dynamic-write"
        }
        _ => unreachable!(),
    }
}

fn evidence_context<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> EvidenceContext {
    EvidenceContext {
        comment: comments.is_in_comment(node.range()),
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        ..EvidenceContext::default()
    }
}

fn provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: ENGINE.to_string(),
        rule_version: 1,
    }
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
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

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

fn exact_quoted(text: &str) -> Option<&str> {
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

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| {
            (first == '_' || first.is_ascii_alphabetic())
                && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
        })
        .then_some(text)
}

fn terminal_symbol(symbol: &str) -> &str {
    symbol.rsplit('.').next().unwrap_or(symbol)
}

fn normalize_name(text: &str) -> String {
    text.trim_matches(['\'', '"', '`'])
        .chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn is_node_language(language: Language) -> bool {
    matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    )
}

fn is_non_runtime_example_path(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.contains("/data/static/codefixes/") || path.starts_with("data/static/codefixes/")
}
