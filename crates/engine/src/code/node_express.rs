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
struct RequestTypes {
    koa: bool,
    requests: BTreeSet<String>,
    responses: BTreeSet<String>,
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
        // The legacy req rules cover collection members, not the collection
        // itself. Keep whole-collection reads behind the imported type boundary
        // and stop at writes rather than inferring the middleware's new value.
        let collection_writes = function
            .dfs()
            .filter(|node| {
                matches!(
                    node.kind().as_ref(),
                    "assignment_expression"
                        | "augmented_assignment_expression"
                        | "update_expression"
                ) || node.kind().as_ref() == "unary_expression"
                    && node
                        .field("operator")
                        .is_some_and(|operator| operator.text() == "delete")
            })
            .filter_map(|node| {
                let target = node.field("left").or_else(|| node.field("argument"))?;
                let access = super::security_paths::node_static_access(&target, 0)?;
                Some((node.range().start, access))
            })
            .collect::<Vec<_>>();
        for node in function.dfs().filter(|node| {
            matches!(
                node.kind().as_ref(),
                "member_expression" | "subscript_expression"
            ) && nearest_function_range(node) == Some(function.range())
        }) {
            let Some((request, field)) = request_member_root(&node, &request_objects) else {
                continue;
            };
            let collection = super::security_paths::node_static_access(&node, 0).filter(|access| {
                access.len() == 2
                    && matches!(field, "body" | "query" | "params" | "headers" | "cookies")
            });
            if let Some(access) = &collection {
                let written = collection_writes.iter().any(|(at, written)| {
                    *at < node.range().start
                        && (access.starts_with(written) || written.starts_with(access))
                });
                let assignment_target =
                    node.ancestors()
                        .take_while(|n| n.range() != function.range())
                        .any(|n| {
                            matches!(
                                n.kind().as_ref(),
                                "assignment_expression"
                                    | "augmented_assignment_expression"
                                    | "update_expression"
                            ) && n.field("left").or_else(|| n.field("argument")).is_some_and(
                                |left| {
                                    left.range().start <= node.range().start
                                        && node.range().end <= left.range().end
                                },
                            )
                        });
                if written || assignment_target {
                    continue;
                }
            }
            // Legacy rules cover req collection fields, but not whole
            // collections or URL scalars. Never seed a schema's return here.
            if request == "req"
                && field != "session"
                && url_metadata_field(field).is_none()
                && collection.is_none()
            {
                continue;
            }
            if node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind().as_ref(),
                    "member_expression" | "subscript_expression"
                ) && request_member_root(&parent, &request_objects).is_some()
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

/// Koa owns both a request and a response on its Context. In particular,
/// `ctx.body` and `ctx.state` are not request inputs. Only imported context
/// types (and bounded same-file aliases) establish receiver identity here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_typed_koa_boundaries<'tree>(
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
    // Exact imported Koa identity requires this module spelling. Avoid extra
    // AST walks in the much larger set of unrelated TS/browser files.
    if !root.text().contains("koa") {
        return;
    }
    let types = framework_types(root, true);
    if types.requests.is_empty() && types.namespaces.is_empty() {
        return;
    }
    let contexts = root
        .dfs()
        .filter(|n| is_function_scope(n.kind().as_ref()))
        .filter_map(|function| {
            let (objects, _) = function_request_bindings(&function, &types);
            (!objects.is_empty()).then_some((function.range().start, objects))
        })
        .collect::<BTreeMap<_, _>>();
    if contexts.is_empty() {
        return;
    }
    let mut writes = BTreeMap::<(usize, String), Vec<(usize, Vec<String>)>>::new();
    for node in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "assignment_expression" | "augmented_assignment_expression" | "update_expression"
        )
    }) {
        let Some(scope) = nearest_function_range(&node) else {
            continue;
        };
        let Some(target) = node.field("left").or_else(|| node.field("argument")) else {
            continue;
        };
        let Some(access) = super::security_paths::node_static_access(&target, 0).or_else(|| {
            target
                .field("object")
                .and_then(|n| super::security_paths::node_static_access(&n, 0))
        }) else {
            continue;
        };
        if let Some(head) = access.first() {
            writes
                .entry((scope.start, head.clone()))
                .or_default()
                .push((node.range().start, access));
        }
    }
    // A single pass over accesses; do not rescan each function body for every
    // parameter. Nested callables must establish their own context identity.
    for node in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "member_expression" | "subscript_expression" | "call_expression"
        )
    }) {
        let Some(bindings) =
            nearest_function_range(&node).and_then(|scope| contexts.get(&scope.start))
        else {
            continue;
        };
        let access_node = if node.kind().as_ref() == "call_expression" {
            node.field("function")
        } else {
            Some(node.clone())
        };
        let access = access_node
            .as_ref()
            .and_then(|n| super::security_paths::node_static_access(n, 0));
        if let Some(access) = &access {
            let Some(head) = access.first() else { continue };
            let Some(scope) = nearest_function_range(&node) else {
                continue;
            };
            if writes
                .get(&(scope.start, head.clone()))
                .is_some_and(|writes| {
                    writes.iter().any(|(at, written)| {
                        *at < node.range().start && access.starts_with(written)
                    })
                })
            {
                continue;
            }
            if access.len() == 2
                && access[1] == "redirect"
                && bindings.iter().any(|b| b.name == *head)
                && node.kind().as_ref() == "call_expression"
            {
                push_koa_redirect(
                    path,
                    language,
                    &node,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
                continue;
            }
        }
        let Some((binding, field)) = koa_input(&node, bindings) else {
            continue;
        };
        if node.parent().is_some_and(|parent| {
            koa_input(&parent, bindings).is_some()
                || (parent.kind().as_ref() == "call_expression"
                    && parent
                        .field("function")
                        .is_some_and(|callee| callee.range() == node.range()))
        }) {
            continue;
        }
        // A property assignment is not a read from the incoming request.
        if node
            .ancestors()
            .take_while(|n| !is_function_scope(n.kind().as_ref()))
            .any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "assignment_expression" | "augmented_assignment_expression"
                ) && n.field("left").is_some_and(|left| {
                    left.range().start <= node.range().start && node.range().end <= left.range().end
                })
            })
        {
            continue;
        }
        push_source(
            path,
            &node,
            Capability::HttpRequestData,
            &format!("{}-koa-typed-request-data", language_prefix(language)),
            BTreeMap::from([
                (
                    "request".to_string(),
                    text_capture(path, &node, &binding.name),
                ),
                ("name".to_string(), text_capture(path, &node, field)),
            ]),
            vec!["typed-request", "request-field"],
            &binding.resolution,
            "koa",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_koa_redirect<'tree>(
    path: &str,
    language: Language,
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range()) {
        return;
    }
    let Some(argument) = node
        .field("arguments")
        .and_then(|args| args.children().find(|n| n.is_named()))
    else {
        return;
    };
    let rule_id = format!("{}-koa-context-redirect", language_prefix(language));
    evidence.push(Evidence {
        id: evidence_id(path, &rule_id, node.range().start, node.range().end),
        kind: EvidenceKind::Sink,
        capability: Capability::Redirect,
        location: location(path, node),
        enclosing_symbol: express_enclosing_symbol(node),
        captures: BTreeMap::from([("location".to_string(), capture(path, &argument))]),
        cwe_candidates: vec!["CWE-601".to_string()],
        tags: [
            "http",
            "koa",
            "redirect",
            "exact-api-boundary",
            "review-admission:source-sink-required",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "ast-grep 0.45.1 + bounded-koa-type-boundary".to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: Some(SymbolResolution {
            canonical: "koa.Context.redirect".to_string(),
            observed: node
                .field("function")
                .map(|n| n.text().into_owned())
                .unwrap_or_default(),
            method: SymbolResolutionMethod::Alias,
            confidence: SymbolConfidence::High,
        }),
        rule_id,
        related_evidence: Vec::new(),
    });
}

fn koa_input<'a, 'tree>(
    node: &Node<'_, StrDoc<SupportLang>>,
    bindings: &'a [RequestBinding<'tree>],
) -> Option<(&'a RequestBinding<'tree>, &'static str)> {
    let access = if node.kind().as_ref() == "call_expression" {
        let callee = node.field("function")?;
        let access = super::security_paths::node_static_access(&callee, 0)?;
        let binding = bindings.iter().find(|b| access.first() == Some(&b.name))?;
        let tail = access
            .iter()
            .skip(1)
            .map(String::as_str)
            .collect::<Vec<_>>();
        let field = match tail.as_slice() {
            ["get"] | ["request", "get"] => "headers",
            ["cookies", "get"] => "cookies",
            _ => return None,
        };
        return Some((binding, field));
    } else {
        super::security_paths::node_static_access(node, 0)?
    };
    let binding = bindings.iter().find(|b| access.first() == Some(&b.name))?;
    let mut tail = access.iter().skip(1).map(String::as_str);
    let first = tail.next()?;
    let field = if first == "request" {
        tail.next()?
    } else {
        first
    };
    let field = match field {
        "body" if first == "request" => "body",
        "query" => "query",
        "params" if first != "request" => "params",
        "headers" | "header" => "headers",
        "url" | "originalUrl" => "url",
        "path" => "path",
        "querystring" => "querystring",
        "host" | "hostname" => "host",
        _ => return None,
    };
    Some((binding, field))
}

fn express_types(root: &Node<'_, StrDoc<SupportLang>>) -> RequestTypes {
    framework_types(root, false)
}

fn framework_types(root: &Node<'_, StrDoc<SupportLang>>, koa: bool) -> RequestTypes {
    let mut types = RequestTypes {
        koa,
        ..RequestTypes::default()
    };
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
        let module = exact_quoted(module.trim().trim_end_matches(';'));
        if !(if koa {
            module == Some("koa")
        } else {
            matches!(module, Some("express" | "express-serve-static-core"))
        }) {
            continue;
        }
        let clause = clause.trim().strip_prefix("type ").unwrap_or(clause.trim());
        let clause = if !clause.starts_with('{') && !clause.starts_with('*') {
            if let Some((default, rest)) = clause.split_once(',') {
                if is_identifier(default.trim()) {
                    types.namespaces.insert(default.trim().to_string());
                }
                rest.trim()
            } else {
                if is_identifier(clause) {
                    types.namespaces.insert(clause.to_string());
                }
                clause
            }
        } else {
            clause
        };
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
                    "Context" | "ParameterizedContext" | "DefaultContext" if koa => {
                        types.requests.insert(visible.to_string());
                    }
                    "Response" if !koa => {
                        types.responses.insert(visible.to_string());
                    }
                    "Request" if !koa => {
                        types.requests.insert(visible.to_string());
                    }
                    "RequestHandler" if !koa => {
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

fn request_type_alias(node: Node<'_, StrDoc<SupportLang>>, types: &RequestTypes) -> Option<String> {
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

/// Exact imported response types and contextual RequestHandler parameters.
/// Route registration supplies the corresponding identity for untyped JS.
pub(super) fn typed_response_bindings(
    root: &Node<'_, StrDoc<SupportLang>>,
) -> BTreeMap<usize, Vec<String>> {
    let types = express_types(root);
    let mut bindings = BTreeMap::new();
    for function in root.dfs().filter(|n| is_function_scope(n.kind().as_ref())) {
        let Some(parameters) = function.field("parameters") else {
            continue;
        };
        let contextual = contextual_request_handler_type(&function)
            .is_some_and(|n| is_request_handler_type(&n.text(), &types));
        for (index, parameter) in parameters.children().filter(|n| n.is_named()).enumerate() {
            let typed = parameter.field("type").is_some_and(|n| {
                let text = compact(&n.text());
                let text = text.trim_start_matches(':');
                let base = text.split_once('<').map_or(text, |(base, _)| base);
                types.responses.contains(base)
                    || types
                        .namespaces
                        .iter()
                        .any(|ns| base == format!("{ns}.Response"))
            });
            if !typed && !(contextual && index == 1 && parameter.field("type").is_none()) {
                continue;
            }
            let pattern = parameter
                .field("pattern")
                .or_else(|| parameter.field("name"))
                .unwrap_or(parameter);
            if pattern.kind().as_ref() == "identifier" {
                bindings
                    .entry(function.range().start)
                    .or_insert_with(Vec::new)
                    .push(pattern.text().into_owned());
            }
        }
    }
    bindings
}

fn is_request_type(text: &str, types: &RequestTypes) -> bool {
    let compact = compact(text);
    let text = compact.trim_start_matches(':');
    if text.contains('|') {
        return false;
    }
    text.split('&').any(|part| {
        let base = part.split_once('<').map_or(part, |(base, _)| base);
        types.requests.contains(base)
            || types.namespaces.iter().any(|namespace| {
                if types.koa {
                    ["Context", "ParameterizedContext", "DefaultContext"]
                        .iter()
                        .any(|name| base == format!("{namespace}.{name}"))
                } else {
                    base == format!("{namespace}.Request")
                }
            })
    })
}

fn is_request_handler_type(text: &str, types: &RequestTypes) -> bool {
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
    types: &RequestTypes,
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
    if let Some(access) = super::security_paths::node_static_access(node, 0)
        && access.len() == 2
        && url_metadata_field(&access[1]).is_some()
    {
        let request = requests.iter().find(|r| access[0] == r.name)?;
        return Some((request.name.as_str(), canonical_request_field(&access[1])?));
    }
    if node.kind().as_ref() == "subscript_expression" {
        return None; // Existing collection matching remains unchanged.
    }
    let text = compact(&node.text()).replace("?.", ".");
    requests.iter().find_map(|request| {
        let tail = text.strip_prefix(&format!("{}.", request.name))?;
        let field = canonical_request_field(tail.split(['.', '[']).next()?)?;
        if url_metadata_field(field).is_some() {
            return None; // Scalar property, not a method reference or subfield.
        }
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
        _ => url_metadata_field(field),
    }
}

pub(super) fn url_metadata_field(field: &str) -> Option<&'static str> {
    match field {
        "path" => Some("path"),
        "url" => Some("url"),
        "originalUrl" => Some("originalUrl"),
        "hostname" => Some("hostname"),
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
        "express",
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
        if url_metadata_field(field).is_some()
            || super::security_paths::node_static_access(node, 0).is_some_and(|access| {
                access.len() == 2
                    && matches!(field, "body" | "query" | "params" | "headers" | "cookies")
            })
        {
            vec![
                "renamed-request",
                "typed-request",
                "flow-contract:exact-node-operand",
            ]
        } else {
            vec!["renamed-request", "typed-request"]
        },
        "express.Request",
        "express",
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
    framework: &str,
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
        framework,
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
            engine: if framework == "koa" {
                "ast-grep 0.45.1 + bounded-koa-type-boundary"
            } else {
                EXPRESS_TYPE_ENGINE
            }
            .to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: Some(SymbolResolution {
            canonical: if framework == "koa" {
                "koa.Context"
            } else {
                "express.Request"
            }
            .to_string(),
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
