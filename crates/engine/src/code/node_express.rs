use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, SymbolConfidence, SymbolResolution, SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const EXPRESS_TYPE_ENGINE: &str = "ast-grep 0.45.1 + bounded-express-type-boundary";

#[derive(Default)]
struct ExpressTypes {
    requests: BTreeSet<String>,
    handlers: BTreeSet<String>,
    namespaces: BTreeSet<String>,
}

#[derive(Clone)]
struct RequestBinding<'tree> {
    name: String,
    node: Node<'tree, StrDoc<SupportLang>>,
    field: Option<String>,
    resolution: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_typed_express_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::Typescript | Language::Tsx) {
        return;
    }
    let types = express_types(root);
    if types.requests.is_empty() && types.handlers.is_empty() && types.namespaces.is_empty() {
        return;
    }

    for function in root
        .dfs()
        .filter(|node| is_function_scope(node.kind().as_ref()))
    {
        let (request_objects, mut value_bindings) = function_request_bindings(&function, &types);
        if request_objects.is_empty() && value_bindings.is_empty() {
            continue;
        }
        value_bindings.extend(local_destructured_bindings(&function, &request_objects));
        value_bindings.sort_by_key(|binding| binding.node.range().start);
        value_bindings.dedup_by(|left, right| {
            left.name == right.name && left.node.range() == right.node.range()
        });

        for binding in &value_bindings {
            let mut projections = function
                .dfs()
                .filter(|node| {
                    matches!(
                        node.kind().as_ref(),
                        "member_expression" | "subscript_expression"
                    ) && nearest_function_range(node) == Some(function.range())
                        && binding_projection(node, &binding.name)
                        && !node.parent().is_some_and(|parent| {
                            matches!(
                                parent.kind().as_ref(),
                                "member_expression" | "subscript_expression"
                            ) && binding_projection(&parent, &binding.name)
                        })
                })
                .collect::<Vec<_>>();
            if matches!(binding.field.as_deref(), Some("file" | "files")) {
                projections.retain(|node| {
                    let text = compact(&node.text());
                    text.contains(".buffer") || text.contains(".path")
                });
            }
            if projections.is_empty() {
                push_binding_source(
                    path,
                    language,
                    binding,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else {
                for projection in projections {
                    push_member_source(
                        path,
                        language,
                        &projection,
                        &binding.name,
                        binding.field.as_deref().unwrap_or("body"),
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
        }
        for node in function.dfs().filter(|node| {
            node.kind().as_ref() == "member_expression"
                && nearest_function_range(node) == Some(function.range())
        }) {
            let Some((request, field)) = request_member_root(&node, &request_objects) else {
                continue;
            };
            if request == "req" && field != "session" {
                continue;
            }
            if node.parent().is_some_and(|parent| {
                parent.kind().as_ref() == "member_expression"
                    && request_member_root(&parent, &request_objects).is_some()
            }) {
                continue;
            }
            push_member_source(
                path,
                language,
                &node,
                request,
                field,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        for call in function.dfs().filter(|node| {
            node.kind().as_ref() == "call_expression"
                && nearest_function_range(node) == Some(function.range())
        }) {
            let Some(callee) = call.field("function") else {
                continue;
            };
            let observed = compact(&callee.text()).replace("?.", ".");
            let Some((request, method)) = observed.rsplit_once('.') else {
                continue;
            };
            if !request_objects
                .iter()
                .any(|binding| binding.name == request)
                || !matches!(method, "get" | "header")
                || request == "req"
            {
                continue;
            }
            push_member_source(
                path,
                language,
                &call,
                request,
                "headers",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn express_types(root: &Node<'_, StrDoc<SupportLang>>) -> ExpressTypes {
    let mut types = ExpressTypes::default();
    for import in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = import.text();
        let Some((clause, module)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        if !matches!(
            exact_quoted(module.trim().trim_end_matches(';')),
            Some("express" | "express-serve-static-core")
        ) {
            continue;
        }
        let clause = clause.trim().strip_prefix("type ").unwrap_or(clause.trim());
        if let Some(namespace) = clause.strip_prefix("* as ") {
            types.namespaces.insert(namespace.trim().to_string());
        } else if clause.starts_with('{') {
            for entry in clause.trim_matches(['{', '}']).split(',') {
                let words = entry.split_whitespace().collect::<Vec<_>>();
                let words = words.strip_prefix(&["type"]).unwrap_or(words.as_slice());
                let Some(imported) = words.first().copied() else {
                    continue;
                };
                let visible = if words.get(1) == Some(&"as") {
                    words.get(2).copied().unwrap_or(imported)
                } else {
                    imported
                };
                match imported {
                    "Request" => {
                        types.requests.insert(visible.to_string());
                    }
                    "RequestHandler" => {
                        types.handlers.insert(visible.to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    for _ in 0..2 {
        let aliases = root
            .dfs()
            .filter_map(|node| request_type_alias(node, &types))
            .collect::<Vec<_>>();
        let mut changed = false;
        for alias in aliases {
            changed |= types.requests.insert(alias);
        }
        if !changed {
            break;
        }
    }
    types
}

fn request_type_alias(node: Node<'_, StrDoc<SupportLang>>, types: &ExpressTypes) -> Option<String> {
    match node.kind().as_ref() {
        "type_alias_declaration" => {
            let name = node.field("name")?.text().trim().to_string();
            let value = node
                .field("value")
                .or_else(|| node.children().filter(|child| child.is_named()).last())?;
            is_request_type(&value.text(), types).then_some(name)
        }
        "interface_declaration" => {
            let name = node.field("name")?.text().trim().to_string();
            let text = compact(&node.text());
            let extends = text.split_once("extends")?.1.split_once('{')?.0;
            extends
                .split(',')
                .any(|base| is_request_type(base, types))
                .then_some(name)
        }
        _ => None,
    }
}

fn is_request_type(text: &str, types: &ExpressTypes) -> bool {
    let compact = compact(text);
    let text = compact.trim_start_matches(':');
    if text.contains('|') {
        return false;
    }
    text.split('&').any(|part| {
        let base = part.split_once('<').map_or(part, |(base, _)| base);
        types.requests.contains(base)
            || types
                .namespaces
                .iter()
                .any(|namespace| base == format!("{namespace}.Request"))
    })
}

fn is_request_handler_type(text: &str, types: &ExpressTypes) -> bool {
    let compact = compact(text);
    let text = compact.trim_start_matches(':');
    if text.contains(['|', '&']) {
        return false;
    }
    let base = text.split_once('<').map_or(text, |(base, _)| base);
    types.handlers.contains(base)
        || types
            .namespaces
            .iter()
            .any(|namespace| base == format!("{namespace}.RequestHandler"))
}

fn function_request_bindings<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    types: &ExpressTypes,
) -> (Vec<RequestBinding<'tree>>, Vec<RequestBinding<'tree>>) {
    let mut objects = Vec::new();
    let mut values = Vec::new();
    let Some(parameters) = function.field("parameters") else {
        return (objects, values);
    };
    for parameter in parameters.children().filter(|child| child.is_named()) {
        let Some(type_node) = parameter.field("type") else {
            continue;
        };
        if !is_request_type(&type_node.text(), types) {
            continue;
        }
        let Some(pattern) = parameter
            .field("pattern")
            .or_else(|| parameter.field("name"))
        else {
            continue;
        };
        if pattern.kind().as_ref() == "identifier" {
            objects.push(RequestBinding {
                name: pattern.text().trim().to_string(),
                node: pattern,
                field: None,
                resolution: type_node.text().trim().to_string(),
            });
        } else if pattern.kind().as_ref() == "object_pattern" {
            for (field, binding) in object_bindings(&pattern.text(), true) {
                if let Some(node) = binding_identifier_node(&pattern, &binding) {
                    values.push(RequestBinding {
                        name: binding,
                        node,
                        field: Some(field),
                        resolution: type_node.text().trim().to_string(),
                    });
                }
            }
        }
    }
    if objects.is_empty()
        && values.is_empty()
        && contextual_request_handler_type(function)
            .is_some_and(|type_node| is_request_handler_type(&type_node.text(), types))
        && let Some(parameter) = parameters.children().find(|child| child.is_named())
        && parameter.field("type").is_none()
        && let Some(pattern) = parameter
            .field("pattern")
            .or_else(|| parameter.field("name"))
        && pattern.kind().as_ref() == "identifier"
    {
        objects.push(RequestBinding {
            name: pattern.text().trim().to_string(),
            node: pattern,
            field: None,
            resolution: "express.RequestHandler".to_string(),
        });
    }
    (objects, values)
}

fn contextual_request_handler_type<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let parent = function.parent()?;
    (parent.kind().as_ref() == "variable_declarator"
        && parent
            .field("value")
            .is_some_and(|value| value.range() == function.range()))
    .then(|| parent.field("type"))
    .flatten()
}

fn local_destructured_bindings<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    requests: &[RequestBinding<'tree>],
) -> Vec<RequestBinding<'tree>> {
    let mut bindings = Vec::new();
    for declarator in function.dfs().filter(|node| {
        node.kind().as_ref() == "variable_declarator"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let (Some(pattern), Some(value)) = (declarator.field("name"), declarator.field("value"))
        else {
            continue;
        };
        if pattern.kind().as_ref() != "object_pattern" {
            continue;
        }
        let value_text = compact(&value.text()).replace("?.", ".");
        let Some(request) = requests.iter().find(|request| {
            value_text == request.name || value_text.starts_with(&format!("{}.", request.name))
        }) else {
            continue;
        };
        let inherited_field = value_text
            .strip_prefix(&format!("{}.", request.name))
            .and_then(|tail| tail.split('.').next())
            .map(str::to_string);
        for (field, binding) in object_bindings(&pattern.text(), inherited_field.is_none()) {
            let Some(node) = binding_identifier_node(&pattern, &binding) else {
                continue;
            };
            bindings.push(RequestBinding {
                name: binding,
                node,
                field: inherited_field.clone().or(Some(field)),
                resolution: request.resolution.clone(),
            });
        }
    }
    bindings
}

fn object_bindings(text: &str, require_request_fields: bool) -> Vec<(String, String)> {
    let text = text.trim().trim_start_matches('{').trim_end_matches('}');
    split_top_level(text)
        .into_iter()
        .flat_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() || entry.starts_with("...") {
                return Vec::new();
            }
            let (field, binding) = split_once_top_level(entry, ':')
                .map_or((entry, entry), |(field, binding)| (field, binding));
            let field = field.trim().trim_end_matches('?');
            if require_request_fields && !is_request_field(field) {
                return Vec::new();
            }
            let binding = binding.trim();
            if binding.starts_with('{') {
                return object_bindings(binding, false)
                    .into_iter()
                    .map(|(_, binding)| (field.to_string(), binding))
                    .collect();
            }
            let binding = binding.split('=').next().unwrap_or(binding).trim();
            if is_identifier(binding) {
                vec![(field.to_string(), binding.to_string())]
            } else {
                Vec::new()
            }
        })
        .collect()
}

fn split_top_level(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

fn split_once_top_level(text: &str, delimiter: char) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth = depth.saturating_sub(1),
            value if value == delimiter && depth == 0 => {
                return Some((&text[..index], &text[index + value.len_utf8()..]));
            }
            _ => {}
        }
    }
    None
}

fn binding_identifier_node<'tree>(
    pattern: &Node<'tree, StrDoc<SupportLang>>,
    binding: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    pattern.dfs().find(|node| {
        matches!(
            node.kind().as_ref(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && node.text().trim() == binding
    })
}

fn request_member_root<'a>(
    node: &Node<'_, StrDoc<SupportLang>>,
    requests: &'a [RequestBinding<'_>],
) -> Option<(&'a str, &'static str)> {
    let text = compact(&node.text()).replace("?.", ".");
    requests.iter().find_map(|request| {
        let tail = text.strip_prefix(&format!("{}.", request.name))?;
        let field = canonical_request_field(tail.split(['.', '[']).next()?)?;
        Some((request.name.as_str(), field))
    })
}

fn binding_projection(node: &Node<'_, StrDoc<SupportLang>>, binding: &str) -> bool {
    let text = compact(&node.text()).replace("?.", ".");
    text.starts_with(&format!("{binding}.")) || text.starts_with(&format!("{binding}["))
}

fn is_request_field(field: &str) -> bool {
    canonical_request_field(field).is_some()
}

fn canonical_request_field(field: &str) -> Option<&'static str> {
    match field {
        "body" => Some("body"),
        "query" => Some("query"),
        "params" => Some("params"),
        "headers" => Some("headers"),
        "cookies" => Some("cookies"),
        "session" => Some("session"),
        "file" => Some("file"),
        "files" => Some("files"),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_binding_source<'tree>(
    path: &str,
    language: Language,
    binding: &RequestBinding<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let capability = binding_capability(binding.field.as_deref(), None);
    let rule_id = format!(
        "{}-express-request-binding-source",
        language_prefix(language)
    );
    push_source(
        path,
        &binding.node,
        capability,
        &rule_id,
        BTreeMap::from([
            ("parameter".to_string(), capture(path, &binding.node)),
            ("value".to_string(), capture(path, &binding.node)),
        ]),
        vec!["destructured-alias", "typed-request"],
        &binding.resolution,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_member_source<'tree>(
    path: &str,
    language: Language,
    node: &Node<'tree, StrDoc<SupportLang>>,
    request: &str,
    field: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let capability = binding_capability(Some(field), Some(&node.text()));
    let suffix = match capability {
        Capability::UploadedFileContent => "express-uploaded-file-content",
        Capability::UploadedFilePath => "express-uploaded-file-path",
        Capability::FileUpload => "express-file-upload",
        _ => "express-typed-request-data",
    };
    let rule_id = format!("{}-{suffix}", language_prefix(language));
    push_source(
        path,
        node,
        capability,
        &rule_id,
        BTreeMap::from([
            ("name".to_string(), text_capture(path, node, field)),
            ("request".to_string(), text_capture(path, node, request)),
        ]),
        vec!["renamed-request", "typed-request"],
        "express.Request",
        comments,
        conditional,
        literals,
        evidence,
    );
}

fn binding_capability(field: Option<&str>, expression: Option<&str>) -> Capability {
    match field {
        Some("file" | "files") if expression.is_some_and(|text| text.contains(".buffer")) => {
            Capability::UploadedFileContent
        }
        Some("file" | "files") if expression.is_some_and(|text| text.contains(".path")) => {
            Capability::UploadedFilePath
        }
        Some("file" | "files") => Capability::FileUpload,
        _ => Capability::HttpRequestData,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_source<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    capability: Capability,
    rule_id: &str,
    captures: BTreeMap<String, Capture>,
    extra_tags: Vec<&str>,
    observed_type: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range()) {
        return;
    }
    if evidence.iter().any(|item| {
        item.capability == capability
            && item.location.start.byte_offset == node.range().start
            && item.location.end.byte_offset == node.range().end
    }) {
        return;
    }
    let mut tags = vec![
        "http",
        "request",
        "attacker-controlled",
        "express",
        "typescript-type",
    ];
    tags.extend(extra_tags);
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, node.range().start, node.range().end),
        kind: EvidenceKind::Source,
        capability,
        location: location(path, node),
        enclosing_symbol: express_enclosing_symbol(node),
        captures,
        cwe_candidates: vec![
            match capability {
                Capability::UploadedFileContent
                | Capability::UploadedFilePath
                | Capability::FileUpload => "CWE-434",
                _ => "CWE-20",
            }
            .to_string(),
        ],
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: EXPRESS_TYPE_ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: Some(SymbolResolution {
            canonical: "express.Request".to_string(),
            observed: observed_type.to_string(),
            method: SymbolResolutionMethod::Alias,
            confidence: SymbolConfidence::High,
        }),
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn is_function_scope(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
    )
}

fn nearest_function_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|ancestor| is_function_scope(ancestor.kind().as_ref()))
        .map(|function| function.range())
}

fn express_enclosing_symbol(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    enclosing_symbol(node).or_else(|| {
        let function = node
            .ancestors()
            .find(|ancestor| is_function_scope(ancestor.kind().as_ref()))?;
        let declarator = function.parent()?;
        (declarator.kind().as_ref() == "variable_declarator")
            .then(|| declarator.field("name"))
            .flatten()
            .map(|name| name.text().into_owned())
    })
}

fn language_prefix(language: Language) -> &'static str {
    match language {
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => unreachable!(),
    }
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(|first| {
        (first == '_' || first == '$' || first.is_alphabetic())
            && characters.all(|character| {
                character == '_' || character == '$' || character.is_alphanumeric()
            })
    })
}

fn exact_quoted(text: &str) -> Option<&str> {
    let text = text.trim();
    let first = text.chars().next()?;
    matches!(first, '\'' | '"')
        .then(|| text.strip_prefix(first)?.strip_suffix(first))
        .flatten()
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn text_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: &str) -> Capture {
    Capture {
        text: text.to_string(),
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
