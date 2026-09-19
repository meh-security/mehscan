use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

pub(crate) const RUST_WARP_PARAMETER_RULE_ID: &str = "rust-warp-path-parameter";
pub(crate) const RUST_FORWARDED_PARAMETER_RULE_ID: &str = "rust-forwarded-external-input";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_rust_sql_sources<'tree>(
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
    add_warp_path_parameters(path, root, comments, conditional, literals, evidence);
    add_unique_local_forwarded_parameters(path, root, comments, conditional, literals, evidence);
    add_fixed_origin_url_controls(path, root, comments, conditional, literals, evidence);
}

pub(crate) fn is_exact_axum_extractor(root: &Node<'_, StrDoc<SupportLang>>, visible: &str) -> bool {
    rust_imports(root).get(visible).is_some_and(|canonical| {
        matches!(
            canonical.as_str(),
            "axum::extract::Path"
                | "axum::extract::Query"
                | "axum::extract::Json"
                | "axum::extract::Form"
                | "axum::Json"
                | "axum::Form"
        )
    })
}

pub(crate) fn is_exact_database_query(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(call) = enclosing_call(matched) else {
        return false;
    };
    let Some(function) = call.field("function") else {
        return false;
    };
    let function_text = compact(function.text().as_ref());
    let canonical = canonical_path(root, &function_text);
    if matches!(
        canonical.as_str(),
        "sqlx::query"
            | "sqlx::query_with"
            | "sqlx::query_as_with"
            | "sqlx::query_scalar_with"
            | "sqlx::query_as"
            | "sqlx::query_scalar"
            | "diesel::sql_query"
            | "diesel::dsl::sql_query"
    ) {
        return true;
    }

    let Some((receiver, method)) = function_text.rsplit_once('.') else {
        return false;
    };
    matches!(
        method,
        "query" | "query_one" | "query_opt" | "execute" | "simple_query" | "batch_execute"
    ) && is_postgres_client(root, receiver)
}

pub(crate) fn is_exact_file_input(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    enclosing_call(matched)
        .and_then(|call| call.field("function"))
        .map(|function| canonical_path(root, &compact(function.text().as_ref())))
        .is_some_and(|canonical| {
            matches!(
                canonical.as_str(),
                "std::fs::read_to_string" | "std::fs::read"
            )
        })
}

pub(crate) fn is_exact_reqwest_request(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(call) = enclosing_call(matched) else {
        return false;
    };
    let Some(function) = call.field("function") else {
        return false;
    };
    let observed = compact(function.text().as_ref());
    let canonical = canonical_path(root, &observed);
    if matches!(
        canonical.as_str(),
        "reqwest::get" | "reqwest::blocking::get"
    ) {
        return true;
    }
    let Some((receiver, method)) = observed.rsplit_once('.') else {
        return false;
    };
    if !matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "request"
    ) {
        return false;
    }
    matches!(
        canonical_path(root, receiver).as_str(),
        "reqwest::Client::new()"
            | "reqwest::blocking::Client::new()"
            | "reqwest::Client::builder().build().unwrap()"
            | "reqwest::blocking::Client::builder().build().unwrap()"
    ) || is_reqwest_client(root, receiver)
}

pub(crate) fn is_exact_iron_request_access(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(function) = enclosing_call(matched).and_then(|call| call.field("function")) else {
        return false;
    };
    let observed = compact(function.text().as_ref());
    let Some((request, accessor)) = observed.split_once(".url.") else {
        return false;
    };
    matches!(accessor, "to_string" | "to_owned" | "path" | "query")
        && is_identifier(request)
        && is_iron_request_parameter(root, matched, request)
}

pub(crate) fn is_exact_iron_response(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(function) = enclosing_call(matched).and_then(|call| call.field("function")) else {
        return false;
    };
    let canonical = canonical_path(root, &compact(function.text().as_ref()));
    canonical == "iron::Response::with"
        || (function.text().as_ref() == "Response::with"
            && has_iron_prelude_glob(root)
            && enclosing_request_scope(matched).is_some())
}

pub(crate) fn is_exact_ammonia_clean(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    enclosing_call(matched)
        .and_then(|call| call.field("function"))
        .map(|function| canonical_path(root, &compact(function.text().as_ref())))
        .is_some_and(|canonical| canonical == "ammonia::clean")
}

pub(crate) fn is_exact_permissive_cors(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(call) = enclosing_call(matched) else {
        return false;
    };
    let Some(function) = call.field("function") else {
        return false;
    };
    let observed = compact(function.text().as_ref());
    let canonical = canonical_path(root, &observed);
    if matches!(
        canonical.as_str(),
        "tower_http::cors::CorsLayer::permissive" | "tower_http::cors::CorsLayer::very_permissive"
    ) {
        return true;
    }
    if observed.ends_with(".allow_any_origin") {
        let receiver = observed.trim_end_matches(".allow_any_origin");
        return canonical_path(root, receiver).starts_with("warp::cors()");
    }
    if observed.ends_with(".set")
        && compact(call.text().as_ref()).contains("AccessControlAllowOrigin::Any")
    {
        return rust_imports(root)
            .get("AccessControlAllowOrigin")
            .is_some_and(|path| path == "iron::headers::AccessControlAllowOrigin");
    }
    if observed.ends_with(".allow_origin") {
        let receiver = observed.trim_end_matches(".allow_origin");
        let receiver = canonical_path(root, receiver);
        let text = compact(call.text().as_ref());
        return receiver.starts_with("tower_http::cors::CorsLayer::new()")
            && (text.contains("allow_origin(Any)")
                || text.contains("allow_origin(\"*\"")
                || text.contains("allow_origin('*'"));
    }
    false
}

pub(crate) fn is_exact_actix_html_response(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(call) = enclosing_call(matched) else {
        return false;
    };
    let text = compact(call.text().as_ref());
    if !text.contains(".content_type(\"text/html\").body(") {
        return false;
    }
    let Some(response) = text.split(".content_type(").next() else {
        return false;
    };
    let Some((builder, status)) = response.rsplit_once("::") else {
        return false;
    };
    matches!(
        status.trim_end_matches("()"),
        "Ok" | "Created"
            | "BadRequest"
            | "Unauthorized"
            | "Forbidden"
            | "NotFound"
            | "InternalServerError"
    ) && canonical_path(root, builder) == "actix_web::HttpResponse"
}

pub(crate) fn is_exact_file_log_write(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(function) = enclosing_call(matched).and_then(|call| call.field("function")) else {
        return false;
    };
    let observed = compact(function.text().as_ref());
    let Some((writer, method)) = observed.rsplit_once('.') else {
        return false;
    };
    if method != "write_all" || !is_identifier(writer) {
        return false;
    }
    let has_write_trait = rust_imports(root)
        .get("Write")
        .is_some_and(|path| path == "std::io::Write");
    let scope = enclosing_request_scope(matched).or_else(|| {
        matched
            .ancestors()
            .find(|node| node.kind().as_ref() == "function_item")
    });
    has_write_trait
        && scope.is_some_and(|scope| {
            let text = compact(scope.text().as_ref());
            text.contains(&format!("letmut{writer}=matchOpenOptions::new()"))
                || text.contains(&format!("letmut{writer}=OpenOptions::new()"))
                || text.contains(&format!("letmut{writer}=File::create("))
        })
}

pub(crate) fn is_exact_review_control(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
    rule_id: &str,
) -> bool {
    let Some(function) = enclosing_call(matched).and_then(|call| call.field("function")) else {
        return false;
    };
    let observed = compact(function.text().as_ref());
    let canonical = canonical_path(root, &observed);
    match rule_id {
        "rust-process-argument-separation" => {
            canonical.starts_with("std::process::Command::new(")
                && (canonical.ends_with(".arg") || canonical.ends_with(".args"))
        }
        "rust-url-parsing" => canonical == "url::Url::parse",
        "rust-reqwest-tls-verification" => {
            matches!(
                observed.rsplit_once('.').map(|(_, method)| method),
                Some("danger_accept_invalid_certs" | "danger_accept_invalid_hostnames")
            ) && (canonical.starts_with("reqwest::Client::builder()")
                || canonical.starts_with("reqwest::blocking::Client::builder()"))
        }
        _ => false,
    }
}

pub(crate) fn is_exact_process_execution(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(function) = enclosing_call(matched).and_then(|call| call.field("function")) else {
        return false;
    };
    let observed = compact(function.text().as_ref());
    if observed.ends_with(".arg") || observed.ends_with(".args") {
        return true;
    }
    canonical_path(root, &observed) == "std::process::Command::new"
}

pub(crate) fn is_reviewable_safety_boundary(
    matched: &Node<'_, StrDoc<SupportLang>>,
    include_nonproduction: bool,
) -> bool {
    include_nonproduction
        || !std::iter::once(matched.clone())
            .chain(matched.ancestors())
            .filter(|node| matches!(node.kind().as_ref(), "function_item" | "mod_item"))
            .any(|node| {
                node.prev_all()
                    .take_while(|previous| previous.kind().as_ref() == "attribute_item")
                    .map(|attribute| compact(attribute.text().as_ref()))
                    .any(|attribute| attribute == "#[test]" || attribute == "#[cfg(test)]")
            })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_rust_safety_function_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    include_nonproduction: bool,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Rust {
        return;
    }
    let rule_id = "rust-unsafe-boundary";
    for function in root.dfs().filter(|node| {
        node.kind().as_ref() == "function_item"
            && node.children().any(|child| {
                child.kind().as_ref() == "function_modifiers"
                    && compact(child.text().as_ref()).contains("unsafe")
            })
    }) {
        if comments.is_in_comment(function.range())
            || !is_reviewable_safety_boundary(&function, include_nonproduction)
            || evidence.iter().any(|item| {
                item.rule_id == rule_id
                    && item.location.start.byte_offset == function.range().start
                    && item.location.end.byte_offset == function.range().end
            })
        {
            continue;
        }
        let mut captures = BTreeMap::new();
        if let Some(name) = function.field("name") {
            captures.insert("function".to_string(), capture(path, &name));
        }
        if let Some(body) = function.field("body") {
            captures.insert("body".to_string(), capture(path, &body));
        }
        evidence.push(Evidence {
            id: evidence_id(path, rule_id, function.range().start, function.range().end),
            kind: EvidenceKind::SensitiveOperation,
            capability: Capability::MemorySafetyBoundary,
            location: location(path, &function),
            enclosing_symbol: enclosing_symbol(&function),
            captures,
            cwe_candidates: vec!["CWE-119".to_string()],
            tags: vec![
                "rust".to_string(),
                "unsafe".to_string(),
                "memory-safety".to_string(),
                "review".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "mehscan bounded-rust-safety 1".to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&function, literals)),
                availability: Some(conditional.availability_for(function.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

pub(crate) fn annotate_rust_build_script(
    path: &str,
    language: Language,
    evidence: &mut [Evidence],
) {
    if language != Language::Rust
        || !path
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("build.rs"))
    {
        return;
    }
    for item in evidence {
        if !item.tags.iter().any(|tag| tag == "build-script") {
            item.tags.push("build-script".to_string());
        }
        if item.capability == Capability::ProcessExecution
            && !item.tags.iter().any(|tag| tag == "build-time-execution")
        {
            item.tags.push("build-time-execution".to_string());
        }
    }
}

pub(crate) fn is_effective_sql_parameterization(
    root: &Node<'_, StrDoc<SupportLang>>,
    matched: &Node<'_, StrDoc<SupportLang>>,
    query_text: &str,
) -> bool {
    let query = query_text.trim();
    if !is_string_literal(query) || !has_sql_placeholder(query) {
        return false;
    }
    matched
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .any(|call| is_exact_database_query(root, &call))
}

fn enclosing_call<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    std::iter::once(node.clone())
        .chain(node.ancestors())
        .find(|candidate| candidate.kind().as_ref() == "call_expression")
}

pub(crate) fn canonical_path(root: &Node<'_, StrDoc<SupportLang>>, path: &str) -> String {
    let first_end = path
        .find("::")
        .or_else(|| path.find('.'))
        .unwrap_or(path.len());
    let first = &path[..first_end];
    rust_imports(root).get(first).map_or_else(
        || path.to_string(),
        |canonical| format!("{}{}", canonical, &path[first_end..]),
    )
}

fn is_postgres_client(root: &Node<'_, StrDoc<SupportLang>>, receiver: &str) -> bool {
    if !is_identifier(receiver) {
        return false;
    }
    root.dfs()
        .filter(|node| node.kind().as_ref() == "let_declaration")
        .any(|declaration| {
            let text = compact(declaration.text().as_ref());
            let Some((left, right)) = text
                .strip_prefix("let")
                .and_then(|text| text.split_once('='))
            else {
                return false;
            };
            let left = left.strip_prefix("mut").unwrap_or(left);
            let declared = left.split(':').next().unwrap_or(left);
            if declared != receiver {
                return false;
            }
            let initializer = right.trim_end_matches(';');
            let Some(connect_path) = initializer.split('(').next() else {
                return false;
            };
            matches!(
                canonical_path(root, connect_path).as_str(),
                "postgres::Client::connect"
            )
        })
}

fn is_reqwest_client(root: &Node<'_, StrDoc<SupportLang>>, receiver: &str) -> bool {
    if !is_identifier(receiver) {
        return false;
    }
    root.dfs()
        .filter(|node| node.kind().as_ref() == "let_declaration")
        .any(|declaration| {
            let text = compact(declaration.text().as_ref());
            let Some((left, right)) = text
                .strip_prefix("let")
                .and_then(|text| text.split_once('='))
            else {
                return false;
            };
            let left = left.strip_prefix("mut").unwrap_or(left);
            if left.split(':').next().unwrap_or(left) != receiver {
                return false;
            }
            let initializer = right.trim_end_matches(';');
            let canonical = canonical_path(root, initializer);
            canonical.starts_with("reqwest::Client::new()")
                || canonical.starts_with("reqwest::blocking::Client::new()")
                || canonical.starts_with("reqwest::Client::builder().build()")
                || canonical.starts_with("reqwest::blocking::Client::builder().build()")
        })
}

fn is_iron_request_parameter(
    root: &Node<'_, StrDoc<SupportLang>>,
    node: &Node<'_, StrDoc<SupportLang>>,
    request: &str,
) -> bool {
    let Some(scope) = enclosing_request_scope(node) else {
        return false;
    };
    let parameters = scope
        .field("parameters")
        .map(|parameters| compact(parameters.text().as_ref()))
        .unwrap_or_else(|| compact(scope.text().as_ref()));
    let typed = parameters.contains(&format!("{request}:&mutRequest"))
        || parameters.contains(&format!("{request}:&mutiron::Request"));
    typed
        && (rust_imports(root)
            .get("Request")
            .is_some_and(|canonical| canonical == "iron::Request")
            || has_iron_prelude_glob(root)
            || parameters.contains("&mutiron::Request"))
}

fn enclosing_request_scope<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "function_item" | "closure_expression"
        ) && compact(ancestor.text().as_ref()).contains(":&mutRequest")
    })
}

fn has_iron_prelude_glob(root: &Node<'_, StrDoc<SupportLang>>) -> bool {
    root.dfs().any(|node| {
        node.kind().as_ref() == "use_declaration"
            && compact(node.text().as_ref()) == "useiron::prelude::*;"
    })
}

fn has_sql_placeholder(literal: &str) -> bool {
    let unquoted = literal
        .trim_start_matches('r')
        .trim_start_matches('#')
        .trim_matches('#')
        .trim_matches('"');
    let bytes = unquoted.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'?'
            || (*byte == b'$'
                && bytes
                    .get(index + 1)
                    .is_some_and(|next| next.is_ascii_digit() && *next != b'0'))
    })
}

fn is_string_literal(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with("r\"") && text.ends_with('"'))
        || (text.starts_with("r#\"") && text.ends_with("\"#"))
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn add_warp_path_parameters<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for closure in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "closure_expression")
    {
        let Some(call) = closure.ancestors().find(|ancestor| {
            ancestor.kind().as_ref() == "call_expression"
                && ancestor.field("function").is_some_and(|function| {
                    let function = compact(function.text().as_ref());
                    (function.ends_with(".then") || function.ends_with(".map"))
                        && function
                            .strip_suffix(".then")
                            .or_else(|| function.strip_suffix(".map"))
                            .is_some_and(|route| route == "warp::path::param()")
                })
        }) else {
            continue;
        };
        let Some(parameters) = closure.field("parameters") else {
            continue;
        };
        let Some(parameter) = parameters
            .dfs()
            .find(|node| node.kind().as_ref() == "identifier")
        else {
            continue;
        };
        push_parameter_source(
            path,
            &parameter,
            &call,
            RUST_WARP_PARAMETER_RULE_ID,
            Capability::HttpRequestData,
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn add_unique_local_forwarded_parameters<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let file_sources = evidence
        .iter()
        .filter(|item| item.rule_id == "rust-file-content-input")
        .cloned()
        .collect::<Vec<_>>();
    for source in file_sources {
        let Some(source_node) = smallest_node_containing(root, source.location.start.byte_offset)
        else {
            continue;
        };
        let Some(declaration) = source_node
            .ancestors()
            .find(|node| node.kind().as_ref() == "let_declaration")
        else {
            continue;
        };
        let Some(source_name) = declaration
            .field("pattern")
            .or_else(|| declaration.field("name"))
            .map(|node| node.text().trim().to_string())
            .filter(|name| is_identifier(name))
        else {
            continue;
        };

        for call in root.dfs().filter(|node| {
            node.kind().as_ref() == "call_expression"
                && node.range().start > declaration.range().end
        }) {
            let Some(function) = call.field("function") else {
                continue;
            };
            let function_name = function.text();
            if !is_identifier(function_name.trim()) {
                continue;
            }
            let Some(arguments) = call.field("arguments") else {
                continue;
            };
            let argument_nodes = arguments
                .children()
                .filter(|child| child.is_named())
                .collect::<Vec<_>>();
            let Some(index) = argument_nodes
                .iter()
                .position(|argument| argument.text().trim() == source_name)
            else {
                continue;
            };
            let calls_with_name = root
                .dfs()
                .filter(|candidate| {
                    candidate.kind().as_ref() == "call_expression"
                        && candidate
                            .field("function")
                            .is_some_and(|name| name.text() == function_name)
                })
                .count();
            if calls_with_name != 1 {
                continue;
            }
            let Some(function_item) = root.dfs().find(|candidate| {
                candidate.kind().as_ref() == "function_item"
                    && candidate
                        .field("name")
                        .is_some_and(|name| name.text() == function_name)
            }) else {
                continue;
            };
            if !evidence.iter().any(|item| {
                item.kind == EvidenceKind::Sink
                    && item.capability == Capability::DatabaseQuery
                    && function_item
                        .range()
                        .contains(&item.location.start.byte_offset)
            }) {
                continue;
            }
            let Some(parameters) = function_item.field("parameters") else {
                continue;
            };
            let parameter_nodes = parameters
                .children()
                .filter(|child| child.kind().as_ref() == "parameter")
                .collect::<Vec<_>>();
            let Some(parameter) = parameter_nodes.get(index).and_then(|parameter| {
                parameter
                    .field("pattern")
                    .or_else(|| parameter.field("name"))
            }) else {
                continue;
            };
            push_parameter_source(
                path,
                &parameter,
                &call,
                RUST_FORWARDED_PARAMETER_RULE_ID,
                Capability::ExternalInput,
                Some(&source.id),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn add_fixed_origin_url_controls<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for format in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "macro_invocation")
        .filter(|node| fixed_origin_format(node.text().as_ref()))
    {
        let value_node = format.dfs().find(|node| {
            node.kind().as_ref() == "identifier"
                && node.text().as_ref() != "format"
                && node
                    .parent()
                    .is_none_or(|parent| parent.kind().as_ref() != "scoped_identifier")
        });
        let value_name = value_node
            .as_ref()
            .map(|node| node.text().into_owned())
            .or_else(|| {
                fixed_origin_dynamic_identifier(format.text().as_ref()).map(str::to_string)
            });
        let Some(value_name) = value_name else {
            continue;
        };
        if comments.is_in_comment(format.range()) {
            continue;
        }
        let rule_id = "rust-fixed-origin-url";
        evidence.push(Evidence {
            id: evidence_id(path, rule_id, format.range().start, format.range().end),
            kind: EvidenceKind::Sanitizer,
            capability: Capability::UrlParsing,
            location: location(path, &format),
            enclosing_symbol: enclosing_symbol(&format),
            captures: BTreeMap::from([(
                "value".to_string(),
                value_node.as_ref().map_or_else(
                    || Capture {
                        text: value_name,
                        location: location(path, &format),
                    },
                    |value| capture(path, value),
                ),
            )]),
            cwe_candidates: vec!["CWE-918".to_string()],
            tags: vec![
                "http".to_string(),
                "ssrf".to_string(),
                "fixed-origin".to_string(),
                "rust".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "mehscan bounded-rust-context 1".to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&format, literals)),
                availability: Some(conditional.availability_for(format.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn fixed_origin_format(text: &str) -> bool {
    let compact = compact(text);
    let Some(literal) = compact.strip_prefix("format!(\"") else {
        return false;
    };
    let Some(end_quote) = literal.rfind('"') else {
        return false;
    };
    let template = &literal[..end_quote];
    let Some(scheme_end) = template.find("://") else {
        return false;
    };
    if !matches!(&template[..scheme_end], "http" | "https") {
        return false;
    }
    let destination = &template[scheme_end + 3..];
    let Some(path_start) = destination.find('/') else {
        return false;
    };
    let first_dynamic = destination.find('{').unwrap_or(destination.len());
    path_start < first_dynamic
        && path_start > 0
        && !destination[..path_start].contains(['{', '}', '@'])
}

fn fixed_origin_dynamic_identifier(text: &str) -> Option<&str> {
    let open = text.find('{')?;
    let close = text[open + 1..].find('}')? + open + 1;
    let name = &text[open + 1..close];
    is_identifier(name).then_some(name)
}

#[allow(clippy::too_many_arguments)]
fn push_parameter_source<'tree>(
    path: &str,
    parameter: &Node<'tree, StrDoc<SupportLang>>,
    call: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    capability: Capability,
    related: Option<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(parameter.range())
        || evidence.iter().any(|item| {
            item.rule_id == rule_id && item.location.start.byte_offset == parameter.range().start
        })
    {
        return;
    }
    let mut captures = BTreeMap::from([("parameter".to_string(), capture(path, parameter))]);
    captures.insert("controller_call".to_string(), capture(path, call));
    evidence.push(Evidence {
        id: evidence_id(
            path,
            rule_id,
            parameter.range().start,
            parameter.range().end,
        ),
        kind: EvidenceKind::Source,
        capability,
        location: location(path, parameter),
        enclosing_symbol: enclosing_symbol(parameter),
        captures,
        cwe_candidates: vec!["CWE-20".to_string()],
        tags: vec!["attacker-controlled".to_string(), "rust".to_string()],
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "mehscan bounded-rust-context 1".to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(parameter, literals)),
            availability: Some(conditional.availability_for(parameter.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: related.into_iter().map(str::to_string).collect(),
    });
}

fn smallest_node_containing<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    offset: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.range().start <= offset && offset < node.range().end)
        .min_by_key(|node| node.range().end - node.range().start)
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

pub(crate) fn rust_imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    let mut imports = BTreeMap::new();
    for declaration in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "use_declaration")
    {
        let text = declaration.text();
        let Some(specification) = text
            .trim()
            .strip_prefix("use ")
            .and_then(|text| text.strip_suffix(';'))
        else {
            continue;
        };
        expand_use("", specification.trim(), &mut imports);
    }
    imports
}

fn expand_use(prefix: &str, specification: &str, imports: &mut BTreeMap<String, String>) {
    let specification = specification.trim();
    if let Some(open) = specification.find('{') {
        let Some(close) = matching_brace(specification, open) else {
            return;
        };
        if !specification[close + 1..].trim().is_empty() {
            return;
        }
        let branch = specification[..open].trim().trim_end_matches("::");
        let nested_prefix = join_path(prefix, branch);
        for item in split_top_level(&specification[open + 1..close]) {
            expand_use(&nested_prefix, item, imports);
        }
        return;
    }

    if specification == "*" || specification.is_empty() {
        return;
    }
    let (path, visible) = specification
        .rsplit_once(" as ")
        .map_or((specification, None), |(path, alias)| {
            (path.trim(), Some(alias.trim()))
        });
    let canonical = if path == "self" {
        prefix.to_string()
    } else {
        join_path(prefix, path)
    };
    let visible =
        visible.unwrap_or_else(|| canonical.rsplit("::").next().unwrap_or(canonical.as_str()));
    if is_identifier(visible) && !canonical.is_empty() {
        imports.insert(visible.to_string(), canonical);
    }
}

fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, character) in text[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (offset, character) in text.char_indices() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(text[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    parts.push(text[start..].trim());
    parts
}

fn join_path(prefix: &str, suffix: &str) -> String {
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, _) => suffix.to_string(),
        (_, true) => prefix.to_string(),
        _ => format!("{prefix}::{suffix}"),
    }
}

pub(crate) fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_alphabetic())
        && characters.all(|character| character == '_' || character.is_alphanumeric())
}

#[cfg(test)]
mod tests {
    use ast_grep_core::AstGrep;

    use super::*;

    #[test]
    fn resolves_nested_axum_uses_and_aliases_without_globs() {
        let source = r#"
            use axum::{extract::{Path as RoutePath, Query}, Json};
            use lookalike::Path;
            use axum::extract::*;
        "#;
        let document = StrDoc::try_new(source, SupportLang::Rust).expect("valid Rust");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        assert!(is_exact_axum_extractor(&root, "RoutePath"));
        assert!(is_exact_axum_extractor(&root, "Query"));
        assert!(is_exact_axum_extractor(&root, "Json"));
        assert!(!is_exact_axum_extractor(&root, "Path"));
    }

    #[test]
    fn resolves_sql_aliases_and_rejects_query_name_collisions() {
        let source = r#"
            use diesel::dsl::sql_query as raw_sql;
            use postgres::Client as PgClient;
            fn sample() {
                raw_sql("SELECT 1");
                lookalike::sql_query("SELECT 1");
                let mut client = PgClient::connect("host=x", postgres::NoTls).unwrap();
                client.query("SELECT 1", &[]);
                object.query("SELECT 1", &[]);
            }
        "#;
        let document = StrDoc::try_new(source, SupportLang::Rust).expect("valid Rust");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let calls = root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter(|node| {
                matches!(
                    node.field("function")
                        .map(|function| function.text().into_owned())
                        .as_deref(),
                    Some("raw_sql")
                        | Some("lookalike::sql_query")
                        | Some("client.query")
                        | Some("object.query")
                )
            })
            .map(|call| {
                (
                    call.field("function").unwrap().text().into_owned(),
                    is_exact_database_query(&root, &call),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(calls["raw_sql"]);
        assert!(calls["client.query"]);
        assert!(!calls["lookalike::sql_query"]);
        assert!(!calls["object.query"]);
    }

    #[test]
    fn bind_requires_a_literal_placeholder() {
        assert!(has_sql_placeholder("\"SELECT * FROM t WHERE id = $1\""));
        assert!(has_sql_placeholder("\"SELECT * FROM t WHERE id = ?\""));
        assert!(!has_sql_placeholder("\"SELECT * FROM t WHERE id = {}\""));
    }

    #[test]
    fn resolves_reqwest_clients_and_rejects_receiver_collisions() {
        let source = r#"
            use reqwest::Client as HttpClient;
            use reqwest::blocking::get as blocking_get;
            fn sample() {
                blocking_get("https://example.test");
                HttpClient::new().post("https://example.test");
                let client = HttpClient::new();
                client.get("https://example.test");
                object.get("https://example.test");
            }
        "#;
        let document = StrDoc::try_new(source, SupportLang::Rust).expect("valid Rust");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let resolved = root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter_map(|call| {
                let function = call.field("function")?.text().into_owned();
                matches!(
                    function.as_str(),
                    "blocking_get" | "HttpClient::new().post" | "client.get" | "object.get"
                )
                .then(|| (function, is_exact_reqwest_request(&root, &call)))
            })
            .collect::<BTreeMap<_, _>>();
        assert!(resolved["blocking_get"]);
        assert!(resolved["HttpClient::new().post"]);
        assert!(resolved["client.get"]);
        assert!(!resolved["object.get"]);
    }

    #[test]
    fn exact_review_controls_reject_same_name_types() {
        let source = r#"
            use std::process::Command;
            use url::Url;
            fn sample(input: &str) {
                Command::new("tool").arg(input);
                Url::parse(input);
                reqwest::Client::builder().danger_accept_invalid_certs(true);
                lookalike::Command::new("tool").arg(input);
                lookalike::Url::parse(input);
                Client::builder().danger_accept_invalid_certs(true);
            }
        "#;
        let document = StrDoc::try_new(source, SupportLang::Rust).expect("valid Rust");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let outcomes = root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter_map(|call| {
                let text = compact(call.text().as_ref());
                let rule = if text.contains(".arg(") {
                    "rust-process-argument-separation"
                } else if text.contains("Url::parse(") {
                    "rust-url-parsing"
                } else if text.contains("danger_accept_invalid_certs(") {
                    "rust-reqwest-tls-verification"
                } else {
                    return None;
                };
                Some((text, is_exact_review_control(&root, &call, rule)))
            })
            .collect::<BTreeMap<_, _>>();
        assert!(outcomes["Command::new(\"tool\").arg(input)"]);
        assert!(outcomes["Url::parse(input)"]);
        assert!(outcomes["reqwest::Client::builder().danger_accept_invalid_certs(true)"]);
        assert!(!outcomes["lookalike::Command::new(\"tool\").arg(input)"]);
        assert!(!outcomes["lookalike::Url::parse(input)"]);
        assert!(!outcomes["Client::builder().danger_accept_invalid_certs(true)"]);
    }

    #[test]
    fn fixed_origin_requires_authority_before_dynamic_input() {
        assert!(fixed_origin_format(
            "format!(\"https://service.example/{request_path}\")"
        ));
        assert!(!fixed_origin_format(
            "format!(\"https://{request_host}/path\")"
        ));
        assert!(!fixed_origin_format("format!(\"{}\", request_url)"));
    }

    #[test]
    fn permissive_cors_requires_exact_framework_and_wildcard_shapes() {
        let source = r#"
            use tower_http::cors::CorsLayer;
            use http::HeaderValue;
            fn sample() {
                warp::cors().allow_any_origin();
                custom::cors().allow_any_origin();
                CorsLayer::new().allow_origin("*".parse::<HeaderValue>().unwrap());
                CorsLayer::new().allow_origin("https://app.example".parse::<HeaderValue>().unwrap());
            }
        "#;
        let document = StrDoc::try_new(source, SupportLang::Rust).expect("valid Rust");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let resolved = root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter_map(|call| {
                let text = compact(call.text().as_ref());
                (text.contains("allow_any_origin") || text.contains("allow_origin("))
                    .then(|| (text, is_exact_permissive_cors(&root, &call)))
            })
            .collect::<BTreeMap<_, _>>();
        assert!(resolved["warp::cors().allow_any_origin()"]);
        assert!(!resolved["custom::cors().allow_any_origin()"]);
        assert!(
            resolved
                .iter()
                .any(|(text, exact)| text.contains("allow_origin(\"*\"") && *exact)
        );
        assert!(resolved.iter().any(|(text, exact)| {
            text.contains("allow_origin(\"https://app.example\"") && !*exact
        }));
    }
}
