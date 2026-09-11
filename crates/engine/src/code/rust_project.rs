use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;
use super::rust_context::{canonical_path, is_identifier};

pub(crate) const ACTIX_PARAMETER_RULE_ID: &str = "rust-actix-request-extractor";
pub(crate) const ACTIX_FORWARDED_RULE_ID: &str = "rust-actix-forwarded-parameter";

#[derive(Clone, Debug)]
struct RouteFact {
    method: String,
    path: String,
}

#[derive(Clone, Debug)]
struct DirectBinding {
    path: String,
    function: String,
    parameter_index: usize,
    binding: String,
    routes: Vec<RouteFact>,
}

#[derive(Clone, Debug)]
struct ForwardedBinding {
    target_path: String,
    function: String,
    parameter_index: usize,
    caller_call: Capture,
    routes: Vec<RouteFact>,
}

#[derive(Default)]
pub(crate) struct RustProjectContext {
    direct: Vec<DirectBinding>,
    forwarded: Vec<ForwardedBinding>,
}

impl RustProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let sources = sources
            .filter(|(_, language, _)| *language == Language::Rust)
            .map(|(path, _, source)| (normalize(path), source.to_string()))
            .collect::<Vec<_>>();
        let mut registered = BTreeMap::<String, Vec<RouteFact>>::new();
        for (_, source) in &sources {
            with_root(source, |root| {
                collect_registered_handlers(root, &mut registered)
            });
        }

        let mut direct = Vec::new();
        let mut proposals = Vec::new();
        for (path, source) in &sources {
            with_root(source, |root| {
                let module = Path::new(path)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default();
                for function in root
                    .dfs()
                    .filter(|node| node.kind().as_ref() == "function_item")
                {
                    let Some(name) = function.field("name").map(|name| name.text().into_owned())
                    else {
                        continue;
                    };
                    let routes = registered
                        .get(&name)
                        .or_else(|| registered.get(&format!("{module}::{name}")))
                        .cloned();
                    let Some(routes) = routes else {
                        continue;
                    };
                    let bindings = actix_parameter_bindings(root, &function);
                    for (parameter_index, binding) in &bindings {
                        direct.push(DirectBinding {
                            path: path.clone(),
                            function: name.clone(),
                            parameter_index: *parameter_index,
                            binding: binding.clone(),
                            routes: routes.clone(),
                        });
                    }
                    for call in function.dfs().filter(|node| {
                        node.kind().as_ref() == "call_expression"
                            && node
                                .ancestors()
                                .find(|ancestor| ancestor.kind().as_ref() == "function_item")
                                .is_some_and(|owner| owner.range() == function.range())
                    }) {
                        let Some(callee) = call.field("function") else {
                            continue;
                        };
                        let callee_text = compact(callee.text().as_ref());
                        if callee_text.contains('.') || callee_text.ends_with('!') {
                            continue;
                        }
                        let Some(arguments) = call.field("arguments") else {
                            continue;
                        };
                        let tracked =
                            request_bindings_before(&function, &bindings, call.range().start);
                        for (argument_index, argument) in arguments
                            .children()
                            .filter(|child| child.is_named())
                            .enumerate()
                        {
                            let argument_text = compact(argument.text().as_ref());
                            let argument_name = argument_text.trim_start_matches('&');
                            if !tracked.contains(argument_name) {
                                continue;
                            }
                            let Some((target_path, target_function)) =
                                resolve_helper(path, &callee_text)
                            else {
                                continue;
                            };
                            proposals.push(ForwardedBinding {
                                target_path,
                                function: target_function,
                                parameter_index: argument_index,
                                caller_call: Capture {
                                    text: call.text().into_owned(),
                                    location: location(path, &call),
                                },
                                routes: routes.clone(),
                            });
                        }
                    }
                }
            });
        }

        let mut counts = BTreeMap::<(String, String), usize>::new();
        for proposal in &proposals {
            *counts
                .entry((proposal.target_path.clone(), proposal.function.clone()))
                .or_default() += 1;
        }
        let forwarded = proposals
            .into_iter()
            .filter(|proposal| {
                counts.get(&(proposal.target_path.clone(), proposal.function.clone())) == Some(&1)
            })
            .collect();
        Self { direct, forwarded }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if language != Language::Rust {
            return;
        }
        let normalized = normalize(path);
        for binding in self.direct.iter().filter(|item| item.path == normalized) {
            let Some(parameter) =
                function_parameter(root, &binding.function, binding.parameter_index)
            else {
                continue;
            };
            let Some(anchor) = binding_node(&parameter, &binding.binding) else {
                continue;
            };
            push_source(
                path,
                &anchor,
                ACTIX_PARAMETER_RULE_ID,
                None,
                &binding.routes,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        for binding in self
            .forwarded
            .iter()
            .filter(|item| item.target_path == normalized)
        {
            let Some(parameter) =
                function_parameter(root, &binding.function, binding.parameter_index)
            else {
                continue;
            };
            let Some(anchor) = parameter
                .field("pattern")
                .or_else(|| parameter.field("name"))
                .filter(|node| is_identifier(node.text().trim()))
            else {
                continue;
            };
            push_source(
                path,
                &anchor,
                ACTIX_FORWARDED_RULE_ID,
                Some(binding.caller_call.clone()),
                &binding.routes,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn request_bindings_before(
    function: &Node<'_, StrDoc<SupportLang>>,
    bindings: &[(usize, String)],
    before: usize,
) -> BTreeSet<String> {
    let mut tracked = bindings
        .iter()
        .map(|(_, binding)| binding.clone())
        .collect::<BTreeSet<_>>();
    let mut declarations = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "let_declaration" && node.range().end <= before)
        .collect::<Vec<_>>();
    declarations.sort_by_key(|node| node.range().start);
    for declaration in declarations {
        let Some(pattern) = declaration.field("pattern") else {
            continue;
        };
        let binding = compact(pattern.text().as_ref());
        if !is_identifier(&binding) {
            continue;
        }
        let Some(value) = declaration.field("value") else {
            tracked.remove(&binding);
            continue;
        };
        let value_text = compact(value.text().as_ref());
        let preserves_value = value_text.starts_with("format!(")
            || value.kind().as_ref() == "binary_expression"
            || value_text.ends_with(".into_inner()")
            || value_text.ends_with(".clone()")
            || value_text.ends_with(".to_owned()")
            || value_text.ends_with(".to_string()")
            || value_text.ends_with(".as_bytes()")
            || value_text.contains(".replace(");
        let derives_from_request = preserves_value
            && value.dfs().any(|node| {
                node.kind().as_ref() == "identifier" && tracked.contains(node.text().trim())
            });
        tracked.remove(&binding);
        if derives_from_request {
            tracked.insert(binding);
        }
    }
    tracked
}

fn with_root(source: &str, operation: impl FnOnce(&Node<'_, StrDoc<SupportLang>>)) {
    let Ok(document) = StrDoc::try_new(source, SupportLang::Rust) else {
        return;
    };
    let ast = AstGrep::doc(document);
    operation(&ast.root());
}

fn collect_registered_handlers(
    root: &Node<'_, StrDoc<SupportLang>>,
    registered: &mut BTreeMap<String, Vec<RouteFact>>,
) {
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
    {
        let Some(function) = call.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        let Some(receiver) = function_text.strip_suffix(".to") else {
            continue;
        };
        let method = if receiver == "web::get()" || receiver == "actix_web::web::get()" {
            "GET"
        } else if receiver == "web::post()" || receiver == "actix_web::web::post()" {
            "POST"
        } else if receiver == "web::put()" || receiver == "actix_web::web::put()" {
            "PUT"
        } else if receiver == "web::delete()" || receiver == "actix_web::web::delete()" {
            "DELETE"
        } else {
            continue;
        };
        let Some(arguments) = call.field("arguments") else {
            continue;
        };
        let Some(handler) = arguments.children().find(|child| child.is_named()) else {
            continue;
        };
        let handler = compact(handler.text().as_ref());
        if !handler.split("::").all(is_identifier) {
            continue;
        }
        let route_path = call
            .ancestors()
            .find(|ancestor| {
                ancestor.kind().as_ref() == "call_expression"
                    && ancestor.field("function").is_some_and(|function| {
                        compact(function.text().as_ref()).ends_with(".route")
                    })
            })
            .and_then(|route| route.field("arguments"))
            .and_then(|arguments| arguments.children().find(|child| child.is_named()))
            .map(|path| path.text().trim_matches('"').to_string())
            .unwrap_or_else(|| "unknown".to_string());
        registered.entry(handler).or_default().push(RouteFact {
            method: method.to_string(),
            path: route_path,
        });
    }
}

fn actix_parameter_bindings(
    root: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
) -> Vec<(usize, String)> {
    let Some(parameters) = function.field("parameters") else {
        return Vec::new();
    };
    parameters
        .children()
        .filter(|child| child.kind().as_ref() == "parameter")
        .enumerate()
        .filter_map(|(index, parameter)| {
            let kind = parameter.field("type")?;
            let type_text = compact(kind.text().as_ref());
            let base = type_text.split('<').next().unwrap_or(&type_text);
            let canonical = canonical_path(root, base);
            if !matches!(
                canonical.as_str(),
                "actix_web::web::Query"
                    | "actix_web::web::Form"
                    | "actix_web::web::Path"
                    | "actix_web::web::Json"
                    | "actix_web::web::Bytes"
            ) {
                return None;
            }
            let pattern = parameter
                .field("pattern")
                .or_else(|| parameter.field("name"))?;
            let text = compact(pattern.text().as_ref());
            let binding = text
                .split_once('(')
                .and_then(|(_, rest)| rest.strip_suffix(')'))
                .unwrap_or(&text)
                .trim_start_matches("mut");
            is_identifier(binding).then(|| (index, binding.to_string()))
        })
        .collect()
}

fn resolve_helper(current_path: &str, callee: &str) -> Option<(String, String)> {
    let parts = callee.split("::").collect::<Vec<_>>();
    if !parts.iter().all(|part| is_identifier(part)) {
        return None;
    }
    let function = parts.last()?.to_string();
    if parts.len() == 1 {
        return Some((normalize(current_path), function));
    }
    if parts.len() != 2 {
        return None;
    }
    let parent = Path::new(current_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let target = parent.join(format!("{}.rs", parts[0]));
    Some((normalize_path(&target), function))
}

fn function_parameter<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    function_name: &str,
    index: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let function = root.dfs().find(|node| {
        node.kind().as_ref() == "function_item"
            && node
                .field("name")
                .is_some_and(|name| name.text() == function_name)
    })?;
    function
        .field("parameters")?
        .children()
        .filter(|child| child.kind().as_ref() == "parameter")
        .nth(index)
}

fn binding_node<'tree>(
    parameter: &Node<'tree, StrDoc<SupportLang>>,
    binding: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    parameter
        .dfs()
        .find(|node| node.kind().as_ref() == "identifier" && node.text() == binding)
}

#[allow(clippy::too_many_arguments)]
fn push_source<'tree>(
    path: &str,
    anchor: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    caller_call: Option<Capture>,
    routes: &[RouteFact],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(anchor.range())
        || evidence.iter().any(|item| {
            item.rule_id == rule_id && item.location.start.byte_offset == anchor.range().start
        })
    {
        return;
    }
    let mut captures = BTreeMap::from([("parameter".to_string(), capture(path, anchor))]);
    if let Some(call) = caller_call {
        captures.insert("controller_call".to_string(), call);
    }
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, anchor.range().start, anchor.range().end),
        kind: EvidenceKind::Source,
        capability: Capability::HttpRequestData,
        location: location(path, anchor),
        enclosing_symbol: enclosing_symbol(anchor),
        captures,
        cwe_candidates: vec!["CWE-20".to_string()],
        tags: vec![
            "http".to_string(),
            "request".to_string(),
            "attacker-controlled".to_string(),
            "rust".to_string(),
            "actix-web".to_string(),
        ],
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "mehscan bounded-rust-project 1".to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(anchor, literals)),
            availability: Some(conditional.availability_for(anchor.range())),
            http_routes: routes
                .iter()
                .map(|route| HttpRouteContext {
                    method: route.method.clone(),
                    path: route.path.clone(),
                    access: HttpRouteAccess::Unknown,
                    guards: Vec::new(),
                })
                .collect(),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
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
        path: normalize(path),
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
    let input = format!("{}\0{rule_id}\0{start}\0{end}", normalize(path));
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

fn normalize_path(path: &Path) -> String {
    normalize(path.to_string_lossy().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actix_sources_require_route_registration_and_forward_one_unique_helper_hop() {
        let main = r#"
            use actix_web::web::{self, Query};
            async fn registered(Query(input): Query<String>) {
                let value = input.clone();
                helpers::consume(&value);
            }
            async fn unregistered(Query(ignored): Query<String>) {
                helpers::ignored(&ignored);
            }
            fn configure(cfg: &mut web::ServiceConfig) {
                cfg.route("/search", web::get().to(registered));
            }
        "#;
        let helper = r#"
            pub fn consume(value: &str) { println!("{}", value); }
            pub fn ignored(value: &str) { println!("{}", value); }
        "#;
        let context = RustProjectContext::from_sources(
            [
                ("src/main.rs", Language::Rust, main),
                ("src/helpers.rs", Language::Rust, helper),
            ]
            .into_iter(),
        );
        assert_eq!(context.direct.len(), 1);
        assert_eq!(context.direct[0].binding, "input");
        assert_eq!(context.direct[0].routes[0].method, "GET");
        assert_eq!(context.direct[0].routes[0].path, "/search");
        assert_eq!(context.forwarded.len(), 1);
        assert_eq!(context.forwarded[0].target_path, "src/helpers.rs");
        assert_eq!(context.forwarded[0].function, "consume");
    }
}
