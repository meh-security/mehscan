use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language,
    LiteralState, Location, Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const RULE_ID: &str = "csharp-sql-command-text";
const ENGINE: &str = "mehscan csharp-command-summary 1";
const DAPPER_RULE_ID: &str = "csharp-dapper-database-query";
const WEBCLIENT_RULE_ID: &str = "csharp-webclient-outbound-http";
const HTTPCLIENT_RULE_ID: &str = "csharp-httpclient-outbound-http";
const CALL_ENGINE: &str = "mehscan csharp-call-summary 1";

#[derive(Clone)]
struct QueryComposition<'tree> {
    expression: Node<'tree, StrDoc<SupportLang>>,
    style: &'static str,
    references: Vec<String>,
}

pub(crate) fn add_typed_property_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }

    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        let operator = assignment_operator(&assignment);
        if comments.is_in_comment(assignment.range()) || !matches!(operator.as_str(), "=" | "+=") {
            continue;
        }
        let Some(left) = assignment.field("left") else {
            continue;
        };
        let (command, receiver_kind, object_initializer) =
            if let Some((receiver, member)) = member_assignment(&left) {
                if member != "CommandText" {
                    continue;
                }
                let Some(receiver_kind) =
                    database_command_receiver_kind(root, &assignment, receiver.as_str())
                else {
                    continue;
                };
                (receiver, receiver_kind, false)
            } else if left.text().trim() == "CommandText" {
                let Some(command_type) = database_command_initializer_type(&assignment) else {
                    continue;
                };
                (command_type, "typed-object-initializer", true)
            } else {
                continue;
            };
        let Some(query) = assignment.field("right") else {
            continue;
        };
        let stored_procedure = if object_initializer {
            initializer_sets_stored_procedure(&assignment)
        } else {
            command_type_is_stored_procedure(root, &assignment, &command)
        };
        let mut tags = vec![
            "database".to_string(),
            "sql".to_string(),
            "ado-net".to_string(),
            "command-text".to_string(),
            receiver_kind.to_string(),
            if stored_procedure {
                "query-role:stored-procedure-name".to_string()
            } else {
                "query-role:sql-text".to_string()
            },
        ];
        if operator == "+=" {
            tags.push("command-text-append".to_string());
        }
        evidence.push(Evidence {
            id: evidence_id(path, assignment.range().start, assignment.range().end),
            kind: EvidenceKind::Sink,
            capability: Capability::DatabaseQuery,
            location: location(path, &assignment),
            enclosing_symbol: enclosing_symbol(&assignment),
            captures: BTreeMap::from([
                (
                    "query".to_string(),
                    Capture {
                        text: query.text().into_owned(),
                        location: location(path, &query),
                    },
                ),
                (
                    "command".to_string(),
                    Capture {
                        text: command,
                        location: location(path, &left),
                    },
                ),
            ]),
            cwe_candidates: vec!["CWE-89".to_string()],
            tags,
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(assignment.range()),
                reachability: Some(reachability::classify(&assignment, literals)),
                availability: Some(conditional.availability_for(assignment.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }

    add_http_request_uri_properties(path, root, comments, conditional, literals, evidence);

    let dapper_imported = has_dapper_import(root);
    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some((receiver, method, argument)) = typed_instance_call(&invocation) else {
            continue;
        };
        if dapper_imported
            && matches!(
                method.as_str(),
                "Query"
                    | "QueryAsync"
                    | "QueryFirst"
                    | "QueryFirstAsync"
                    | "QueryFirstOrDefault"
                    | "QueryFirstOrDefaultAsync"
                    | "QuerySingle"
                    | "QuerySingleAsync"
                    | "QuerySingleOrDefault"
                    | "QuerySingleOrDefaultAsync"
                    | "Execute"
                    | "ExecuteAsync"
                    | "ExecuteScalar"
                    | "ExecuteScalarAsync"
                    | "ExecuteReader"
                    | "ExecuteReaderAsync"
                    | "QueryMultiple"
                    | "QueryMultipleAsync"
            )
            && receiver_is_database_connection(root, &invocation, &receiver)
        {
            push_call_sink(
                path,
                &invocation,
                &argument,
                "query",
                DAPPER_RULE_ID,
                Capability::DatabaseQuery,
                "CWE-89",
                &["database", "sql", "dapper", "typed-receiver"],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if matches!(
            method.as_str(),
            "GetAsync"
                | "GetStringAsync"
                | "GetByteArrayAsync"
                | "GetStreamAsync"
                | "PostAsync"
                | "PutAsync"
                | "PatchAsync"
                | "DeleteAsync"
        ) && receiver_is_http_client(root, &invocation, &receiver)
        {
            push_call_sink(
                path,
                &invocation,
                &argument,
                "endpoint",
                HTTPCLIENT_RULE_ID,
                Capability::OutboundNetworkRequest,
                "CWE-918",
                &["http", "network", "ssrf", "httpclient", "typed-receiver"],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if matches!(
            method.as_str(),
            "DownloadString"
                | "DownloadStringTaskAsync"
                | "DownloadData"
                | "DownloadDataTaskAsync"
                | "OpenRead"
                | "OpenReadTaskAsync"
        ) && receiver_has_type(root, &invocation, &receiver, is_webclient_type)
        {
            push_call_sink(
                path,
                &invocation,
                &argument,
                "endpoint",
                WEBCLIENT_RULE_ID,
                Capability::OutboundNetworkRequest,
                "CWE-918",
                &["http", "network", "ssrf", "webclient", "typed-receiver"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_http_request_uri_properties<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    const RULE: &str = "csharp-http-request-uri";
    // A source-declared type with this short name wins over framework implicit
    // usings. Avoid treating its ordinary RequestUri property as an HTTP sink.
    if declares_type(root, "HttpRequestMessage") {
        return;
    }
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        if comments.is_in_comment(assignment.range()) || assignment_operator(&assignment) != "=" {
            continue;
        }
        let Some(left) = assignment.field("left") else {
            continue;
        };
        let request = if let Some((receiver, member)) = member_assignment(&left) {
            if member != "RequestUri"
                || !receiver_has_type(
                    root,
                    &assignment,
                    receiver.as_str(),
                    is_http_request_message_type,
                )
            {
                continue;
            }
            receiver
        } else if left.text().trim() == "RequestUri" {
            let Some(request_type) = initializer_type(&assignment, is_http_request_message_type)
            else {
                continue;
            };
            request_type
        } else {
            continue;
        };
        let Some(value) = assignment.field("right") else {
            continue;
        };
        let endpoint = uri_constructor_operand(&value).unwrap_or_else(|| value.clone());
        evidence.push(Evidence {
            id: evidence_id_for(RULE, path, assignment.range().start, assignment.range().end),
            kind: EvidenceKind::Sink,
            capability: Capability::OutboundNetworkRequest,
            location: location(path, &assignment),
            enclosing_symbol: enclosing_symbol(&assignment),
            captures: BTreeMap::from([
                (
                    "endpoint".to_string(),
                    Capture {
                        text: endpoint.text().into_owned(),
                        location: location(path, &endpoint),
                    },
                ),
                (
                    "request".to_string(),
                    Capture {
                        text: request,
                        location: location(path, &left),
                    },
                ),
            ]),
            cwe_candidates: vec!["CWE-918".to_string()],
            tags: vec![
                "http".to_string(),
                "network".to_string(),
                "ssrf".to_string(),
                "http-request-message".to_string(),
                "request-uri-property".to_string(),
                "typed-receiver".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: CALL_ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&assignment, literals)),
                availability: Some(conditional.availability_for(assignment.range())),
                literals: BTreeMap::from([("endpoint".to_string(), literals.evaluate(&endpoint))]),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: RULE.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

/// Marks locally visible SQL string construction on every admitted C# query
/// sink. This is deliberately independent of controller/repository handoff
/// resolution: it describes the query operand without claiming its origin.
pub(crate) fn annotate_dynamic_query_composition<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut [Evidence],
) {
    if language != Language::Csharp {
        return;
    }
    for item in evidence.iter_mut().filter(|item| {
        item.location.path == path
            && item.kind == EvidenceKind::Sink
            && item.capability == Capability::DatabaseQuery
    }) {
        let Some(query_capture) = item.captures.get("query").cloned() else {
            continue;
        };
        let Some(query) = root
            .dfs()
            .filter(|node| {
                node.range().start == query_capture.location.start.byte_offset
                    && node.range().end == query_capture.location.end.byte_offset
            })
            .last()
        else {
            continue;
        };
        if query
            .ancestors()
            .find(|ancestor| {
                matches!(
                    ancestor.kind().as_ref(),
                    "object_creation_expression" | "implicit_object_creation_expression"
                )
            })
            .is_some_and(|creation| creation_sets_stored_procedure(&creation))
        {
            push_unique_tag(&mut item.tags, "query-role:stored-procedure-name");
        }
        let Some(composition) = query_composition(root, &query, literals, 0) else {
            continue;
        };
        push_unique_tag(&mut item.tags, "dynamic-query-composition");
        push_unique_tag(&mut item.tags, "review-origin:decision-critical");
        push_unique_tag(
            &mut item.tags,
            &format!("query-composition:{}", composition.style),
        );
        let parameters = enclosing_parameters(&query);
        let method_parameters = composition
            .references
            .iter()
            .filter_map(|reference| {
                parameters.iter().find_map(|(parameter, observed_type)| {
                    (reference == parameter
                        || reference
                            .strip_prefix(parameter.as_str())
                            .is_some_and(|tail| tail.starts_with('.')))
                    .then_some((reference, observed_type))
                })
            })
            .collect::<Vec<_>>();
        push_unique_tag(
            &mut item.tags,
            if !method_parameters.is_empty() {
                "dynamic-origin:method-parameter"
            } else {
                "dynamic-origin:local-expression"
            },
        );
        if method_parameters.len() == composition.references.len()
            && method_parameters
                .iter()
                .all(|(_, observed_type)| sql_safe_scalar(observed_type))
        {
            push_unique_tag(&mut item.tags, "dynamic-origin:constrained-scalar");
        }
        item.captures.insert(
            "query_composition".to_string(),
            Capture {
                text: composition.expression.text().into_owned(),
                location: location(path, &composition.expression),
            },
        );
        item.captures.insert(
            "dynamic_operands".to_string(),
            Capture {
                text: composition.references.join(", "),
                location: location(path, &composition.expression),
            },
        );
        if let Some(reference) = method_parameters
            .first()
            .map(|(reference, _)| *reference)
            .or_else(|| composition.references.first())
        {
            let operand = composition
                .expression
                .dfs()
                .filter(|node| node.is_named())
                .find(|node| node.text().trim() == reference)
                .unwrap_or_else(|| composition.expression.clone());
            item.captures.insert(
                "dynamic_operand".to_string(),
                Capture {
                    text: reference.clone(),
                    location: location(path, &operand),
                },
            );
        }
        if method_parameters.len() == 1 {
            let (_, observed_type) = method_parameters[0];
            item.captures.insert(
                "dynamic_operand_type".to_string(),
                Capture {
                    text: observed_type.clone(),
                    location: item.captures["dynamic_operand"].location.clone(),
                },
            );
        }
    }
}

/// Marks C# sink operands whose local shape already proves interpretation as
/// executable or structural grammar. The review layer retains origin as a
/// decision-critical question for these markers; ordinary API boundaries stay
/// advisory.
pub(crate) fn annotate_decision_critical_origins(language: Language, evidence: &mut [Evidence]) {
    if language != Language::Csharp {
        return;
    }
    let resolved_process_starts = evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-process-start-info")
        .map(|item| {
            (
                item.location.path.clone(),
                item.location.start.byte_offset,
                item.location.end.byte_offset,
            )
        })
        .collect::<BTreeSet<_>>();
    for item in evidence
        .iter_mut()
        .filter(|item| item.kind == EvidenceKind::Sink && item.rule_id.starts_with("csharp-"))
    {
        let strong_operand = match item.capability {
            Capability::HtmlOutput => {
                (item.tags.iter().any(|tag| tag == "trusted-markup")
                    || item.tags.iter().any(|tag| tag == "explicit-raw-html")
                    || item.rule_id == "csharp-razor-html-raw-output")
                    && capture_is_dynamic(item, "content", "html")
            }
            Capability::DynamicCodeExecution => capture_is_dynamic(item, "code", "code"),
            Capability::Deserialization => capture_is_dynamic(item, "payload", "payload"),
            Capability::LdapQuery => capture_is_dynamic(item, "filter", "distinguished_name"),
            Capability::DatabaseQuery
                if item
                    .tags
                    .iter()
                    .any(|tag| tag == "query-role:stored-procedure-name") =>
            {
                capture_is_dynamic(item, "query", "query")
            }
            Capability::DatabaseQuery if item.rule_id == "csharp-extended-nosql-json" => {
                capture_is_dynamic(item, "nosql_query", "nosql_query")
            }
            Capability::ProcessExecution => {
                let replaced_by_resolved_start_info = item.rule_id == "csharp-process-start"
                    && resolved_process_starts.contains(&(
                        item.location.path.clone(),
                        item.location.start.byte_offset,
                        item.location.end.byte_offset,
                    ));
                !replaced_by_resolved_start_info && process_origin_is_decision_critical(item)
            }
            _ => false,
        };
        if strong_operand {
            push_unique_tag(&mut item.tags, "review-origin:decision-critical");
        }
    }
}

fn process_origin_is_decision_critical(item: &Evidence) -> bool {
    if item.tags.iter().any(|tag| tag == "shell-command-text")
        && capture_is_dynamic(item, "arguments", "arguments")
    {
        return true;
    }
    if capture_is_dynamic(item, "command", "command") {
        return true;
    }
    fixed_literal_string(item, "command").is_some_and(is_shell_name)
        && capture_is_dynamic(item, "arguments", "arguments")
}

fn capture_is_dynamic(item: &Evidence, primary: &str, fallback: &str) -> bool {
    let role = if item.captures.contains_key(primary) {
        primary
    } else if item.captures.contains_key(fallback) {
        fallback
    } else {
        return false;
    };
    fixed_literal_string(item, role).is_none()
        && item
            .captures
            .get(role)
            .is_some_and(|capture| !is_quoted_literal(capture.text.trim()))
}

fn fixed_literal_string<'a>(item: &'a Evidence, role: &str) -> Option<&'a str> {
    let literal = item.context.literals.get(role)?;
    if literal.state != LiteralState::Known {
        return None;
    }
    match literal.value.as_ref()? {
        mehscan_core::LiteralValue::String(value) => Some(value),
        _ => None,
    }
}

fn is_shell_name(value: &str) -> bool {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    matches!(
        normalized.rsplit('/').next().unwrap_or(&normalized),
        "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "sh"
            | "bash"
            | "zsh"
    )
}

fn is_quoted_literal(value: &str) -> bool {
    let value = value.trim().trim_start_matches('@');
    (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with("\"\"\"") && value.ends_with("\"\"\""))
}

fn query_composition<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    query: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    depth: usize,
) -> Option<QueryComposition<'tree>> {
    if depth >= 4 {
        return None;
    }
    let evaluation = literals.evaluate(query);
    if evaluation.state == LiteralState::Partial && !evaluation.references.is_empty() {
        return Some(QueryComposition {
            expression: query.clone(),
            style: composition_style(query),
            references: evaluation.references,
        });
    }
    if let Some(composition) = formatted_string_composition(query, literals) {
        return Some(composition);
    }
    let query_text = query.text();
    let name = simple_identifier(query_text.trim())?;
    let value = latest_local_value(root, query, name)?;
    query_composition(root, &value, literals, depth + 1)
}

fn formatted_string_composition<'tree>(
    query: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<QueryComposition<'tree>> {
    if query.kind().as_ref() != "invocation_expression" {
        return None;
    }
    let function = compact(query.field("function")?.text().as_ref());
    if !matches!(
        function.as_str(),
        "string.Format" | "String.Format" | "string.Concat" | "String.Concat"
    ) {
        return None;
    }
    let arguments = invocation_arguments(query);
    if arguments.len() < 2 || literals.evaluate(&arguments[0]).state != LiteralState::Known {
        return None;
    }
    let mut references = Vec::new();
    for argument in arguments.iter().skip(1) {
        let evaluation = literals.evaluate(argument);
        if evaluation.state == LiteralState::Known {
            continue;
        }
        if evaluation.references.is_empty() {
            references.push(argument.text().trim().to_string());
        } else {
            references.extend(evaluation.references);
        }
    }
    references.sort();
    references.dedup();
    (!references.is_empty()).then(|| QueryComposition {
        expression: query.clone(),
        style: "format",
        references,
    })
}

fn latest_local_value<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let scope = scope_range(use_site, root);
    let mut values = root
        .dfs()
        .filter(|node| {
            scope.start <= node.range().start
                && node.range().end <= scope.end
                && node.range().start < use_site.range().start
        })
        .filter_map(|node| match node.kind().as_ref() {
            "variable_declarator"
                if node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name) =>
            {
                node.field("value")
                    .or_else(|| node.children().filter(|child| child.is_named()).last())
                    .map(|value| (node.range().start, value))
            }
            "assignment_expression"
                if assignment_operator(&node) == "="
                    && node
                        .field("left")
                        .is_some_and(|left| left.text().trim() == name) =>
            {
                node.field("right").map(|value| (node.range().start, value))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    values.sort_by_key(|(offset, _)| *offset);
    values.pop().map(|(_, value)| value)
}

fn invocation_arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .filter_map(argument_expression)
                .collect()
        })
        .unwrap_or_default()
}

fn enclosing_parameters(node: &Node<'_, StrDoc<SupportLang>>) -> Vec<(String, String)> {
    let Some(callable) = node.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "method_declaration" | "constructor_declaration" | "local_function_statement"
        )
    }) else {
        return Vec::new();
    };
    let Some(parameters) = callable.field("parameters") else {
        return Vec::new();
    };
    parameters
        .children()
        .filter(|parameter| parameter.kind().as_ref() == "parameter")
        .filter_map(|parameter| {
            let name = parameter.field("name")?;
            let observed_type = parameter.field("type")?;
            Some((
                name.text().trim().to_string(),
                observed_type.text().trim().to_string(),
            ))
        })
        .collect()
}

fn sql_safe_scalar(observed_type: &str) -> bool {
    matches!(
        observed_type
            .trim()
            .trim_end_matches('?')
            .rsplit('.')
            .next(),
        Some(
            "sbyte"
                | "byte"
                | "short"
                | "ushort"
                | "int"
                | "uint"
                | "long"
                | "ulong"
                | "nint"
                | "nuint"
                | "bool"
                | "Guid"
        )
    )
}

fn composition_style(node: &Node<'_, StrDoc<SupportLang>>) -> &'static str {
    if node.kind().as_ref() == "interpolated_string_expression"
        || node.text().trim().starts_with('$')
    {
        "interpolation"
    } else {
        "concatenation"
    }
}

fn push_unique_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn push_call_sink<'tree>(
    path: &str,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    argument: &Node<'tree, StrDoc<SupportLang>>,
    capture_role: &str,
    rule_id: &str,
    capability: Capability,
    cwe: &str,
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.push(Evidence {
        id: evidence_id_for(
            rule_id,
            path,
            invocation.range().start,
            invocation.range().end,
        ),
        kind: EvidenceKind::Sink,
        capability,
        location: location(path, invocation),
        enclosing_symbol: enclosing_symbol(invocation),
        captures: BTreeMap::from([(
            capture_role.to_string(),
            Capture {
                text: argument.text().into_owned(),
                location: location(path, argument),
            },
        )]),
        cwe_candidates: vec![cwe.to_string()],
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: CALL_ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(invocation.range()),
            reachability: Some(reachability::classify(invocation, literals)),
            availability: Some(conditional.availability_for(invocation.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn typed_instance_call<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(String, String, Node<'tree, StrDoc<SupportLang>>)> {
    let function = invocation.field("function")?;
    if function.kind().as_ref() != "member_access_expression" {
        return None;
    }
    let receiver = function.field("expression")?;
    let method = function.field("name")?;
    let receiver = simple_identifier(receiver.text().trim())?.to_string();
    let method_text = method.text();
    let method = method_text.split('<').next()?.trim().to_string();
    let arguments = invocation.field("arguments")?;
    let first = arguments.children().find(|child| child.is_named())?;
    Some((receiver, method, argument_expression(first)?))
}

fn argument_expression(
    argument: Node<'_, StrDoc<SupportLang>>,
) -> Option<Node<'_, StrDoc<SupportLang>>> {
    if argument.kind().as_ref() != "argument" {
        return Some(argument);
    }
    argument.children().find(|child| child.is_named())
}

fn has_dapper_import(root: &Node<'_, StrDoc<SupportLang>>) -> bool {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .map(|node| {
            node.text()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
        })
        .any(|using| matches!(using.as_str(), "usingDapper;" | "globalusingDapper;"))
}

fn assignment_operator(assignment: &Node<'_, StrDoc<SupportLang>>) -> String {
    assignment
        .field("operator")
        .map(|operator| operator.text().into_owned())
        .unwrap_or_default()
}

fn member_assignment(left: &Node<'_, StrDoc<SupportLang>>) -> Option<(String, String)> {
    if left.kind().as_ref() != "member_access_expression" {
        return None;
    }
    let receiver = left.field("expression")?;
    let member = left.field("name")?;
    let receiver = command_receiver_identifier(&receiver)?;
    Some((receiver, member.text().into_owned()))
}

fn command_receiver_identifier(receiver: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if let Some(receiver) = simple_identifier(receiver.text().trim()) {
        return Some(receiver.to_string());
    }
    if receiver.kind().as_ref() != "member_access_expression"
        || receiver
            .field("expression")
            .is_none_or(|owner| owner.text().trim() != "this")
    {
        return None;
    }
    receiver
        .field("name")
        .and_then(|name| simple_identifier(name.text().trim()).map(str::to_string))
}

fn database_command_initializer_type(assignment: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    initializer_type(assignment, is_database_command_type)
}

fn initializer_type(
    assignment: &Node<'_, StrDoc<SupportLang>>,
    predicate: fn(&str) -> bool,
) -> Option<String> {
    let creation = assignment.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "object_creation_expression" | "implicit_object_creation_expression"
        )
    })?;
    if let Some(observed) = creation.field("type")
        && predicate(observed.text().as_ref())
    {
        return Some(observed.text().trim().to_string());
    }
    let declarator = creation
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "variable_declarator")?;
    let declaration = declarator
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "variable_declaration")?;
    let observed = declaration.field("type")?;
    predicate(observed.text().as_ref()).then(|| observed.text().trim().to_string())
}

fn uri_constructor_operand<'tree>(
    expression: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if expression.kind().as_ref() != "object_creation_expression"
        || expression.field("type").is_none_or(|kind| {
            !matches!(
                kind.text().trim().rsplit('.').next(),
                Some("Uri" | "UriBuilder")
            )
        })
    {
        return None;
    }
    expression
        .field("arguments")
        .and_then(|arguments| arguments.children().find(|child| child.is_named()))
}

fn initializer_sets_stored_procedure(assignment: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let Some(creation) = assignment.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "object_creation_expression" | "implicit_object_creation_expression"
        )
    }) else {
        return false;
    };
    creation_sets_stored_procedure(&creation)
}

fn creation_sets_stored_procedure(creation: &Node<'_, StrDoc<SupportLang>>) -> bool {
    creation.dfs().any(|node| {
        node.kind().as_ref() == "assignment_expression"
            && node
                .field("left")
                .is_some_and(|left| left.text().trim() == "CommandType")
            && node.field("right").is_some_and(|right| {
                compact(right.text().as_ref()).ends_with("CommandType.StoredProcedure")
            })
    })
}

fn command_type_is_stored_procedure(
    root: &Node<'_, StrDoc<SupportLang>>,
    assignment: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> bool {
    let scope = scope_range(assignment, root);
    root.dfs().any(|node| {
        if node.kind().as_ref() != "assignment_expression"
            || node.range().start < scope.start
            || node.range().end > scope.end
        {
            return false;
        }
        let Some(left) = node.field("left") else {
            return false;
        };
        let Some((candidate, member)) = member_assignment(&left) else {
            return false;
        };
        candidate == receiver
            && member == "CommandType"
            && node.field("right").is_some_and(|right| {
                compact(right.text().as_ref()).ends_with("CommandType.StoredProcedure")
            })
    })
}

fn database_command_receiver_kind(
    root: &Node<'_, StrDoc<SupportLang>>,
    assignment: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> Option<&'static str> {
    if receiver_has_type(root, assignment, receiver, is_database_command_type) {
        return Some("typed-receiver");
    }
    (database_command_factory_initialized_receiver(root, assignment, receiver)
        && database_command_is_executed(root, assignment, receiver))
    .then_some("factory-created-receiver")
}

fn database_command_is_executed(
    root: &Node<'_, StrDoc<SupportLang>>,
    assignment: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> bool {
    let scope = scope_range(assignment, root);
    root.dfs().any(|node| {
        if node.kind().as_ref() != "invocation_expression"
            || node.range().start <= assignment.range().end
            || node.range().end > scope.end
        {
            return false;
        }
        let Some(function) = node.field("function") else {
            return false;
        };
        if function.kind().as_ref() != "member_access_expression"
            || function
                .field("expression")
                .is_none_or(|value| value.text().trim() != receiver)
        {
            return false;
        }
        function.field("name").is_some_and(|name| {
            matches!(
                name.text().trim(),
                "ExecuteReader"
                    | "ExecuteReaderAsync"
                    | "ExecuteNonQuery"
                    | "ExecuteNonQueryAsync"
                    | "ExecuteScalar"
                    | "ExecuteScalarAsync"
                    | "ExecuteXmlReader"
                    | "ExecuteXmlReaderAsync"
            )
        })
    })
}

fn database_command_factory_initialized_receiver(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> bool {
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        if node.kind().as_ref() != "variable_declarator"
            || scope.start > node.range().start
            || node.range().end > scope.end
            || node.range().start >= use_site.range().start
            || node
                .field("name")
                .is_none_or(|name| name.text().trim() != receiver)
        {
            return false;
        }
        let Some(initializer) = node.field("value").or_else(|| {
            node.children()
                .filter(|child| child.is_named())
                .find(|child| child.kind().as_ref() == "invocation_expression")
        }) else {
            return false;
        };
        let text = compact(initializer.text().as_ref());
        if text.contains(".Database.GetDbConnection().CreateCommand(") {
            return true;
        }
        let Some(invocation) = initializer
            .dfs()
            .find(|child| child.kind().as_ref() == "invocation_expression")
        else {
            return false;
        };
        let Some(function) = invocation.field("function") else {
            return false;
        };
        if function.kind().as_ref() != "member_access_expression"
            || function
                .field("name")
                .is_none_or(|name| name.text().trim() != "CreateCommand")
        {
            return false;
        }
        let Some(factory_receiver) = function.field("expression") else {
            return false;
        };
        let factory_receiver_text = factory_receiver.text();
        let Some(connection) = simple_identifier(factory_receiver_text.trim()) else {
            return false;
        };
        receiver_is_database_connection(root, &node, connection)
    })
}

fn receiver_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    predicate: fn(&str) -> bool,
) -> bool {
    let field_has_type = root.dfs().any(|node| {
        node.kind().as_ref() == "field_declaration"
            && node
                .dfs()
                .find(|child| child.kind().as_ref() == "variable_declaration")
                .and_then(|declaration| declaration.field("type"))
                .is_some_and(|kind| predicate(kind.text().as_ref()))
            && node.dfs().any(|child| {
                child.kind().as_ref() == "variable_declarator"
                    && child
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver)
            })
    });
    let scope = scope_range(use_site, root);
    let before = use_site.range().start;
    let mut events = root
        .dfs()
        .filter(|node| {
            scope.start <= node.range().start
                && node.range().end <= scope.end
                && node.range().start < before
                && scope_range(node, root) == scope
        })
        .filter_map(|node| receiver_type_event(node, receiver, predicate))
        .collect::<Vec<_>>();
    events.sort_by_key(|(offset, _)| *offset);
    if let Some((_, proven)) = events.last() {
        return *proven;
    }
    primary_constructor_parameter_has_type(use_site, receiver, predicate) || field_has_type
}

fn primary_constructor_parameter_has_type(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    predicate: fn(&str) -> bool,
) -> bool {
    use_site
        .ancestors()
        .find(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration" | "struct_declaration" | "record_declaration"
            )
        })
        .and_then(|declaration| {
            declaration
                .children()
                .find(|child| child.kind().as_ref() == "parameter_list")
        })
        .is_some_and(|parameters| {
            parameters.dfs().any(|parameter| {
                parameter.kind().as_ref() == "parameter"
                    && parameter
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver)
                    && parameter
                        .field("type")
                        .is_some_and(|kind| predicate(kind.text().as_ref()))
            })
        })
}

fn receiver_is_database_connection(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> bool {
    receiver_has_type(root, use_site, receiver, is_database_connection_type)
        || factory_initialized_receiver(
            root,
            use_site,
            receiver,
            &[
                "CreateConnection",
                "CreateConnectionAsync",
                "OpenConnection",
                "OpenConnectionAsync",
            ],
        )
}

fn receiver_is_http_client(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> bool {
    receiver_has_type(root, use_site, receiver, is_http_client_type)
        || factory_initialized_receiver(root, use_site, receiver, &["CreateClient"])
}

fn factory_initialized_receiver(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    factories: &[&str],
) -> bool {
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        node.kind().as_ref() == "variable_declarator"
            && scope.start <= node.range().start
            && node.range().end <= scope.end
            && node.range().start < use_site.range().start
            && node
                .field("name")
                .is_some_and(|name| name.text().trim() == receiver)
            && factories
                .iter()
                .any(|factory| compact(node.text().as_ref()).contains(&format!(".{factory}(")))
    })
}

fn receiver_type_event(
    node: Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    predicate: fn(&str) -> bool,
) -> Option<(usize, bool)> {
    match node.kind().as_ref() {
        "parameter" => {
            let name = node.field("name")?;
            (name.text().trim() == receiver).then(|| {
                (
                    node.range().start,
                    node.field("type")
                        .is_some_and(|kind| predicate(kind.text().as_ref())),
                )
            })
        }
        "variable_declarator" => {
            let name = node.field("name")?;
            if name.text().trim() != receiver {
                return None;
            }
            let declared_type = node
                .parent()
                .filter(|parent| parent.kind().as_ref() == "variable_declaration")
                .and_then(|declaration| declaration.field("type"))
                .is_some_and(|kind| predicate(kind.text().as_ref()));
            let constructed_type = node
                .dfs()
                .find(|child| child.kind().as_ref() == "object_creation_expression")
                .and_then(|creation| creation.field("type"))
                .is_some_and(|kind| predicate(kind.text().as_ref()));
            Some((node.range().start, declared_type || constructed_type))
        }
        "assignment_expression" => {
            let left = node.field("left")?;
            if simple_identifier(left.text().trim())? != receiver {
                return None;
            }
            let right = node.field("right")?;
            let constructed_type = right
                .dfs()
                .find(|child| child.kind().as_ref() == "object_creation_expression")
                .and_then(|creation| creation.field("type"))
                .is_some_and(|kind| predicate(kind.text().as_ref()));
            Some((node.range().start, constructed_type))
        }
        _ => None,
    }
}

fn is_database_command_type(observed: &str) -> bool {
    matches!(
        observed.trim().trim_end_matches('?').rsplit('.').next(),
        Some(
            "SqlCommand"
                | "DbCommand"
                | "IDbCommand"
                | "NpgsqlCommand"
                | "MySqlCommand"
                | "SqliteCommand"
                | "SQLiteCommand"
                | "OracleCommand"
                | "OleDbCommand"
                | "OdbcCommand"
                | "SqlBatchCommand"
                | "NpgsqlBatchCommand"
                | "MySqlBatchCommand"
        )
    )
}

fn is_database_connection_type(observed: &str) -> bool {
    matches!(
        observed.trim().trim_end_matches('?').rsplit('.').next(),
        Some(
            "IDbConnection"
                | "DbConnection"
                | "SqlConnection"
                | "NpgsqlConnection"
                | "MySqlConnection"
                | "MySqlConnector"
                | "SQLiteConnection"
                | "SqliteConnection"
                | "OracleConnection"
        )
    )
}

fn is_webclient_type(observed: &str) -> bool {
    matches!(
        observed.trim().trim_end_matches('?').rsplit('.').next(),
        Some("WebClient")
    )
}

fn is_http_client_type(observed: &str) -> bool {
    matches!(
        observed.trim().trim_end_matches('?').rsplit('.').next(),
        Some("HttpClient")
    )
}

fn is_http_request_message_type(observed: &str) -> bool {
    matches!(
        observed.trim().trim_end_matches('?').rsplit('.').next(),
        Some("HttpRequestMessage")
    )
}

fn declares_type(root: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == expected)
    })
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn scope_range(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "method_declaration"
                    | "constructor_declaration"
                    | "local_function_statement"
                    | "lambda_expression"
                    | "anonymous_method_expression"
            )
        })
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_alphabetic())
        || !characters.all(|character| character == '_' || character.is_alphanumeric())
    {
        return None;
    }
    Some(text)
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

fn evidence_id(path: &str, start: usize, end: usize) -> String {
    evidence_id_for(RULE_ID, path, start, end)
}

fn evidence_id_for(rule_id: &str, path: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
