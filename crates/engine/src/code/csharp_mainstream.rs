use std::collections::BTreeMap;
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan csharp-mainstream-summary 1";

pub(crate) fn add_mainstream_sinks<'tree>(
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

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some((callee, arguments)) = invocation_parts(&invocation) else {
            continue;
        };
        let compact_callee = compact(&callee);

        if compact_callee.ends_with("JsonConvert.DeserializeObject")
            && (compact_callee.starts_with("Newtonsoft.Json.")
                || has_using(root, "Newtonsoft.Json"))
            && arguments.len() >= 2
            && dangerous_json_settings(root, &invocation, &arguments[1])
        {
            push_sink(
                path,
                &invocation,
                Capability::Deserialization,
                "csharp-jsonnet-typename-deserialization",
                "CWE-502",
                &[
                    "deserialization",
                    "jsonnet",
                    "typenamehandling",
                    "object-graph",
                ],
                [("payload", &arguments[0]), ("settings", &arguments[1])],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if compact_callee.ends_with(".Deserialize")
            && !arguments.is_empty()
            && has_using(root, "Newtonsoft.Json")
            && callee
                .strip_suffix(".Deserialize")
                .and_then(simple_identifier)
                .is_some_and(|receiver| json_serializer_is_dangerous(root, &invocation, receiver))
        {
            push_sink(
                path,
                &invocation,
                Capability::Deserialization,
                "csharp-jsonnet-instance-typename-deserialization",
                "CWE-502",
                &[
                    "deserialization",
                    "jsonnet",
                    "instance-serializer",
                    "typenamehandling",
                    "object-graph",
                    "verify-serialization-binder",
                ],
                [("payload", &arguments[0])],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if (compact_callee.ends_with(".LoadXml") || compact_callee.ends_with(".Load"))
            && !arguments.is_empty()
            && has_using(root, "System.Xml")
            && callee
                .rsplit_once('.')
                .and_then(|(receiver, _)| simple_identifier(receiver))
                .is_some_and(|receiver| {
                    receiver_has_short_type(root, &invocation, receiver, "XmlDocument")
                        && xml_document_resolver_state(root, &invocation, receiver) == Some(true)
                })
        {
            push_sink(
                path,
                &invocation,
                Capability::XmlParsing,
                "csharp-xmldocument-external-resolver",
                "CWE-611",
                &["xml", "xxe", "xmldocument", "external-resolver"],
                [("payload", &arguments[0])],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if (compact_callee.ends_with(".LoadXml") || compact_callee.ends_with(".Load"))
            && !arguments.is_empty()
            && has_using(root, "System.Xml")
            && callee
                .rsplit_once('.')
                .and_then(|(receiver, _)| simple_identifier(receiver))
                .is_some_and(|receiver| {
                    receiver_has_short_type(root, &invocation, receiver, "XmlDocument")
                        && xml_document_resolver_state(root, &invocation, receiver) == Some(false)
                })
        {
            push_control(
                path,
                &invocation,
                Capability::XmlParsing,
                "csharp-xmldocument-null-resolver-control",
                "CWE-611",
                &["xml", "xxe", "xmldocument", "null-resolver"],
                [("payload", &arguments[0])],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if compact_callee.ends_with("XmlReader.Create")
            && (compact_callee.starts_with("System.Xml.") || has_using(root, "System.Xml"))
            && arguments.len() >= 2
            && dangerous_xml_settings(root, &invocation, &arguments[1])
        {
            push_sink(
                path,
                &invocation,
                Capability::XmlParsing,
                "csharp-xmlreader-external-entity",
                "CWE-611",
                &["xml", "xxe", "dtd", "external-entity"],
                [("payload", &arguments[0]), ("settings", &arguments[1])],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if compact_callee.ends_with(".AddScript")
            && !arguments.is_empty()
            && (compact_callee.starts_with("System.Management.Automation.PowerShell")
                || has_using(root, "System.Management.Automation"))
            && powershell_script_is_invoked(root, &invocation, &callee)
        {
            push_sink(
                path,
                &invocation,
                Capability::DynamicCodeExecution,
                "csharp-powershell-addscript",
                "CWE-94",
                &["dynamic-code", "powershell", "addscript"],
                [("code", &arguments[0]), ("script_api", &invocation)],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if compact_callee.ends_with("Process.Start") && arguments.len() == 1 {
            if let Some(command) = process_start_info_command(root, &invocation, &arguments[0]) {
                let process_arguments =
                    process_start_info_arguments(root, &invocation, &arguments[0], &command);
                let shell_policy = process_start_info_property(
                    root,
                    &invocation,
                    &arguments[0],
                    "UseShellExecute",
                );
                match (process_arguments, shell_policy) {
                    (Some(process_arguments), Some(shell_policy)) => push_sink(
                        path,
                        &invocation,
                        Capability::ProcessExecution,
                        "csharp-process-start-info",
                        "CWE-78",
                        &[
                            "command",
                            "process",
                            "process-start-info",
                            "argument-policy",
                        ],
                        [
                            ("command", &command),
                            ("arguments", &process_arguments),
                            ("start_info", &arguments[0]),
                            ("shell_policy", &shell_policy),
                        ],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    ),
                    (Some(process_arguments), None) => push_sink(
                        path,
                        &invocation,
                        Capability::ProcessExecution,
                        "csharp-process-start-info",
                        "CWE-78",
                        &[
                            "command",
                            "process",
                            "process-start-info",
                            "argument-policy",
                        ],
                        [
                            ("command", &command),
                            ("arguments", &process_arguments),
                            ("start_info", &arguments[0]),
                        ],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    ),
                    (None, Some(shell_policy)) => push_sink(
                        path,
                        &invocation,
                        Capability::ProcessExecution,
                        "csharp-process-start-info",
                        "CWE-78",
                        &["command", "process", "process-start-info", "shell-policy"],
                        [
                            ("command", &command),
                            ("start_info", &arguments[0]),
                            ("shell_policy", &shell_policy),
                        ],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    ),
                    (None, None) => push_sink(
                        path,
                        &invocation,
                        Capability::ProcessExecution,
                        "csharp-process-start-info",
                        "CWE-78",
                        &["command", "process", "process-start-info"],
                        [("command", &command), ("start_info", &arguments[0])],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    ),
                }
            }
        } else if matches!(compact_callee.as_str(), "File.Copy" | "System.IO.File.Copy")
            && arguments.len() >= 2
        {
            push_file_pair(
                path,
                &invocation,
                &arguments,
                "copy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if matches!(compact_callee.as_str(), "File.Move" | "System.IO.File.Move")
            && arguments.len() >= 2
        {
            push_file_pair(
                path,
                &invocation,
                &arguments,
                "move",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if compact_callee.ends_with(".ExtractToFile")
            && !arguments.is_empty()
            && has_using(root, "System.IO.Compression")
            && callee
                .strip_suffix(".ExtractToFile")
                .and_then(simple_identifier)
                .is_some_and(|receiver| {
                    receiver_has_short_type(root, &invocation, receiver, "ZipArchiveEntry")
                })
        {
            push_sink(
                path,
                &invocation,
                Capability::FilesystemWrite,
                "csharp-zip-entry-extract-to-file",
                "CWE-22",
                &[
                    "filesystem",
                    "path",
                    "archive",
                    "zip-extraction",
                    "needs-containment-review",
                ],
                [("path", &arguments[0]), ("entry", &invocation)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for creation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "object_creation_expression")
    {
        if comments.is_in_comment(creation.range())
            || creation
                .field("type")
                .is_none_or(|kind| short_type(kind.text().as_ref()) != "FileStream")
        {
            continue;
        }
        let Some(arguments) = node_arguments(&creation) else {
            continue;
        };
        if arguments.len() < 2 {
            continue;
        }
        let mode = compact(arguments[1].text().as_ref());
        let capability = if mode.ends_with("FileMode.Open") {
            Some(Capability::FilesystemRead)
        } else if ["Create", "CreateNew", "Append", "Truncate"]
            .iter()
            .any(|candidate| mode.ends_with(&format!("FileMode.{candidate}")))
        {
            Some(Capability::FilesystemWrite)
        } else {
            None
        };
        if let Some(capability) = capability {
            push_sink(
                path,
                &creation,
                capability,
                if capability == Capability::FilesystemRead {
                    "csharp-filestream-read"
                } else {
                    "csharp-filestream-write"
                },
                "CWE-22",
                &["filesystem", "path", "filestream", "explicit-file-mode"],
                [("path", &arguments[0]), ("mode", &arguments[1])],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

pub(crate) fn add_local_redirect_controls<'tree>(
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

    let local_helpers = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
        .filter_map(|method| {
            let name = method.field("name")?.text().into_owned();
            let returns = method
                .dfs()
                .filter(|node| node.kind().as_ref() == "return_statement")
                .filter_map(|statement| statement.children().find(|child| child.is_named()))
                .collect::<Vec<_>>();
            (!returns.is_empty()
                && returns
                    .iter()
                    .all(|expression| is_local_url_expression(expression)))
            .then_some(name)
        })
        .collect::<std::collections::BTreeSet<_>>();

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some((callee, _)) = invocation_parts(&invocation) else {
            continue;
        };
        let local_helper =
            simple_identifier(callee.trim()).is_some_and(|name| local_helpers.contains(name));
        if !is_local_url_expression(&invocation) && !local_helper {
            continue;
        }
        push_control(
            path,
            &invocation,
            Capability::RedirectDestinationValidation,
            if local_helper {
                "csharp-local-redirect-helper-summary"
            } else {
                "csharp-local-url-generation"
            },
            "CWE-601",
            &["http", "redirect", "local-destination", "value-generation"],
            [("location", &invocation)],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn is_local_url_expression(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let Some((callee, arguments)) = invocation_parts(node) else {
        return false;
    };
    let callee = compact(&callee);
    if callee == "Url.Action" {
        return !arguments.is_empty()
            && arguments.len() <= 2
            && !compact(node.text().as_ref()).contains("protocol:")
            && !compact(node.text().as_ref()).contains("host:");
    }
    if callee != "Url.Content" || arguments.len() != 1 {
        return false;
    }
    let value = compact(arguments[0].text().as_ref());
    value.starts_with("\"~/") || value.starts_with("@\"~/")
}

#[allow(clippy::too_many_arguments)]
fn push_file_pair<'tree>(
    path: &str,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    arguments: &[Node<'tree, StrDoc<SupportLang>>],
    operation: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let read_rule = format!("csharp-file-{operation}-source");
    push_sink_dynamic(
        path,
        invocation,
        Capability::FilesystemRead,
        &read_rule,
        "CWE-22",
        &["filesystem", "path", operation, "source"],
        [("path", &arguments[0]), ("operation", invocation)],
        comments,
        conditional,
        literals,
        evidence,
    );
    let write_rule = format!("csharp-file-{operation}-destination");
    push_sink_dynamic(
        path,
        invocation,
        Capability::FilesystemWrite,
        &write_rule,
        "CWE-22",
        &["filesystem", "path", operation, "destination"],
        [("path", &arguments[1]), ("operation", invocation)],
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_sink<'tree, const N: usize>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    capability: Capability,
    rule_id: &'static str,
    cwe: &str,
    tags: &[&str],
    captures: [(&str, &Node<'tree, StrDoc<SupportLang>>); N],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_sink_dynamic(
        path,
        node,
        capability,
        rule_id,
        cwe,
        tags,
        captures,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_control<'tree, const N: usize>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    capability: Capability,
    rule_id: &'static str,
    cwe: &str,
    tags: &[&str],
    captures: [(&str, &Node<'tree, StrDoc<SupportLang>>); N],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.push(Evidence {
        id: evidence_id(rule_id, path, node.range().start, node.range().end),
        kind: EvidenceKind::Validation,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: captures
            .into_iter()
            .map(|(role, capture)| {
                (
                    role.to_string(),
                    Capture {
                        text: capture.text().into_owned(),
                        location: location(path, capture),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        cwe_candidates: vec![cwe.to_string()],
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

#[allow(clippy::too_many_arguments)]
fn push_sink_dynamic<'tree, const N: usize>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    capability: Capability,
    rule_id: &str,
    cwe: &str,
    tags: &[&str],
    captures: [(&str, &Node<'tree, StrDoc<SupportLang>>); N],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.push(Evidence {
        id: evidence_id(rule_id, path, node.range().start, node.range().end),
        kind: EvidenceKind::Sink,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: captures
            .into_iter()
            .map(|(role, capture)| {
                (
                    role.to_string(),
                    Capture {
                        text: capture.text().into_owned(),
                        location: location(path, capture),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        cwe_candidates: vec![cwe.to_string()],
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn invocation_parts<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(String, Vec<Node<'tree, StrDoc<SupportLang>>>)> {
    let function = invocation.field("function")?.text().into_owned();
    Some((function, node_arguments(invocation)?))
}

fn node_arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Vec<Node<'tree, StrDoc<SupportLang>>>> {
    let arguments = node.field("arguments")?;
    Some(
        arguments
            .children()
            .filter(|child| child.is_named())
            .filter_map(argument_expression)
            .collect(),
    )
}

fn argument_expression(
    argument: Node<'_, StrDoc<SupportLang>>,
) -> Option<Node<'_, StrDoc<SupportLang>>> {
    if argument.kind().as_ref() != "argument" {
        return Some(argument);
    }
    argument.children().find(|child| child.is_named())
}

fn dangerous_json_settings(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    settings: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let value = compact(settings.text().as_ref());
    if dangerous_type_name_handling(&value) {
        return true;
    }
    let Some(name) = simple_identifier(&value) else {
        return false;
    };
    let scope = scope_range(use_site, root);
    let mut states = root
        .dfs()
        .filter(|node| is_prior_in_scope(node, use_site, &scope))
        .filter_map(|node| match node.kind().as_ref() {
            "variable_declarator"
                if node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
                    && lexical_declaration_visible_at(&node, use_site)
                    && node.dfs().any(|child| {
                        child.kind().as_ref() == "object_creation_expression"
                            && child.field("type").is_some_and(|kind| {
                                short_type(kind.text().as_ref()) == "JsonSerializerSettings"
                            })
                    }) =>
            {
                Some((
                    node.range().start,
                    dangerous_type_name_handling(&compact(node.text().as_ref())),
                ))
            }
            "assignment_expression"
                if compact(node.field("left")?.text().as_ref())
                    == format!("{name}.TypeNameHandling") =>
            {
                Some((
                    node.range().start,
                    dangerous_type_name_handling(&format!(
                        "TypeNameHandling={}",
                        compact(node.field("right")?.text().as_ref())
                    )),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    states.sort_by_key(|(offset, _)| *offset);
    states.last().is_some_and(|(_, dangerous)| *dangerous)
}

fn dangerous_type_name_handling(text: &str) -> bool {
    ["All", "Auto", "Objects", "Arrays"]
        .iter()
        .any(|value| text.contains(&format!("TypeNameHandling=TypeNameHandling.{value}")))
}

fn json_serializer_is_dangerous(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> bool {
    let scope = scope_range(use_site, root);
    let mut states = root
        .dfs()
        .filter(|node| is_prior_in_scope(node, use_site, &scope))
        .filter_map(|node| match node.kind().as_ref() {
            "variable_declarator"
                if node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == receiver) =>
            {
                if !lexical_declaration_visible_at(&node, use_site) {
                    return None;
                }
                let text = compact(node.text().as_ref());
                if text.contains("newJsonSerializer") {
                    return Some((node.range().start, dangerous_type_name_handling(&text)));
                }
                let creation = node.dfs().find(|child| {
                    child.kind().as_ref() == "invocation_expression"
                        && child.field("function").is_some_and(|function| {
                            compact(function.text().as_ref()).ends_with("JsonSerializer.Create")
                        })
                })?;
                let settings = node_arguments(&creation)?.into_iter().next()?;
                Some((
                    node.range().start,
                    dangerous_json_settings(root, use_site, &settings),
                ))
            }
            "assignment_expression"
                if compact(node.field("left")?.text().as_ref())
                    == format!("{receiver}.TypeNameHandling") =>
            {
                Some((
                    node.range().start,
                    dangerous_type_name_handling(&format!(
                        "TypeNameHandling={}",
                        compact(node.field("right")?.text().as_ref())
                    )),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    states.sort_by_key(|(offset, _)| *offset);
    states.last().is_some_and(|(_, dangerous)| *dangerous)
}

fn xml_document_resolver_state(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
) -> Option<bool> {
    let scope = scope_range(use_site, root);
    let mut states = root
        .dfs()
        .filter(|node| is_prior_in_scope(node, use_site, &scope))
        .filter_map(|node| {
            if node.kind().as_ref() == "variable_declarator"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == receiver)
                && lexical_declaration_visible_at(&node, use_site)
            {
                let text = compact(node.text().as_ref());
                if text.contains("XmlResolver=") {
                    return Some((node.range().start, !text.contains("XmlResolver=null")));
                }
            }
            if node.kind().as_ref() == "assignment_expression"
                && compact(node.field("left")?.text().as_ref()) == format!("{receiver}.XmlResolver")
            {
                return Some((
                    node.range().start,
                    compact(node.field("right")?.text().as_ref()) != "null",
                ));
            }
            None
        })
        .collect::<Vec<_>>();
    states.sort_by_key(|(offset, _)| *offset);
    states.pop().map(|(_, enabled)| enabled)
}

fn dangerous_xml_settings(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    settings: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let value = compact(settings.text().as_ref());
    if xml_settings_are_dangerous(&value, None) {
        return true;
    }
    let Some(name) = simple_identifier(&value) else {
        return false;
    };
    let scope = scope_range(use_site, root);
    let mut events = root
        .dfs()
        .filter(|node| is_prior_in_scope(node, use_site, &scope))
        .filter_map(|node| {
            if node.kind().as_ref() == "variable_declarator"
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
                && lexical_declaration_visible_at(&node, use_site)
                && node.dfs().any(|child| {
                    child.kind().as_ref() == "object_creation_expression"
                        && child.field("type").is_some_and(|kind| {
                            short_type(kind.text().as_ref()) == "XmlReaderSettings"
                        })
                })
            {
                let text = compact(node.text().as_ref());
                return Some((
                    node.range().start,
                    true,
                    text.contains("DtdProcessing=DtdProcessing.Parse")
                        .then_some(true),
                    text.contains("XmlResolver=")
                        .then_some(!text.contains("XmlResolver=null")),
                ));
            }
            if node.kind().as_ref() != "assignment_expression" {
                return None;
            }
            let left = compact(node.field("left")?.text().as_ref());
            let right = compact(node.field("right")?.text().as_ref());
            if left == format!("{name}.DtdProcessing") {
                Some((
                    node.range().start,
                    false,
                    Some(right == "DtdProcessing.Parse"),
                    None,
                ))
            } else if left == format!("{name}.XmlResolver") {
                Some((node.range().start, false, None, Some(right != "null")))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    events.sort_by_key(|(offset, _, _, _)| *offset);
    let (mut dtd, mut resolver) = (None, None);
    for (_, reset, next_dtd, next_resolver) in events {
        if reset {
            dtd = None;
            resolver = None;
        }
        if next_dtd.is_some() {
            dtd = next_dtd;
        }
        if next_resolver.is_some() {
            resolver = next_resolver;
        }
    }
    dtd == Some(true) && resolver == Some(true)
}

fn xml_settings_are_dangerous(text: &str, variable: Option<&str>) -> bool {
    let dtd = variable.map_or_else(
        || text.contains("DtdProcessing=DtdProcessing.Parse"),
        |name| {
            text.contains(&format!("{name}.DtdProcessing=DtdProcessing.Parse"))
                || (text.contains(&format!("{name}=newXmlReaderSettings{{"))
                    && text.contains("DtdProcessing=DtdProcessing.Parse"))
        },
    );
    let resolver = variable.map_or_else(
        || text.contains("XmlResolver=") && !text.contains("XmlResolver=null"),
        |name| {
            text.contains(&format!("{name}.XmlResolver="))
                && !text.contains(&format!("{name}.XmlResolver=null"))
                || (text.contains(&format!("{name}=newXmlReaderSettings{{"))
                    && text.contains("XmlResolver=")
                    && !text.contains("XmlResolver=null"))
        },
    );
    dtd && resolver
}

fn powershell_script_is_invoked(
    root: &Node<'_, StrDoc<SupportLang>>,
    add_script: &Node<'_, StrDoc<SupportLang>>,
    callee: &str,
) -> bool {
    if add_script
        .ancestors()
        .take_while(|ancestor| {
            !matches!(
                ancestor.kind().as_ref(),
                "expression_statement" | "block" | "method_declaration"
            )
        })
        .any(|ancestor| {
            ancestor.kind().as_ref() == "invocation_expression"
                && ancestor
                    .field("function")
                    .is_some_and(|function| compact(function.text().as_ref()).ends_with(".Invoke"))
        })
    {
        return true;
    }
    let receiver = callee
        .strip_suffix(".AddScript")
        .and_then(simple_identifier);
    receiver.is_some_and(|receiver| {
        let suffix = compact(&scope_suffix(root, add_script));
        suffix.contains(&format!("{receiver}.Invoke("))
            && receiver_has_short_type(root, add_script, receiver, "PowerShell")
    })
}

fn process_start_info_command<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    argument: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if argument.kind().as_ref() == "object_creation_expression"
        && argument
            .field("type")
            .is_some_and(|kind| short_type(kind.text().as_ref()) == "ProcessStartInfo")
    {
        if let Some(command) = node_arguments(argument)
            .unwrap_or_default()
            .into_iter()
            .next()
        {
            return Some(command);
        }
        return file_name_initializer(argument);
    }
    let argument_text = argument.text();
    let name = simple_identifier(argument_text.trim())?;
    let scope = scope_range(use_site, root);
    let before = use_site.range().start;
    let mut candidates = root
        .dfs()
        .filter(|node| {
            scope.start <= node.range().start
                && node.range().end <= scope.end
                && node.range().start < before
        })
        .filter_map(|node| {
            if node.kind().as_ref() == "variable_declarator"
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
                && lexical_declaration_visible_at(&node, use_site)
            {
                let creation = node.dfs().find(|child| {
                    child.kind().as_ref() == "object_creation_expression"
                        && child.field("type").is_some_and(|kind| {
                            short_type(kind.text().as_ref()) == "ProcessStartInfo"
                        })
                })?;
                if let Some(command) = node_arguments(&creation)
                    .unwrap_or_default()
                    .into_iter()
                    .next()
                {
                    return Some((node.range().start, command));
                }
                return file_name_initializer(&creation)
                    .map(|command| (node.range().start, command));
            }
            if node.kind().as_ref() == "assignment_expression" {
                let left = compact(node.field("left")?.text().as_ref());
                if left == format!("{name}.FileName") {
                    return Some((node.range().start, node.field("right")?));
                }
            }
            None
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(offset, _)| *offset);
    candidates.pop().map(|(_, command)| command)
}

fn process_start_info_arguments<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    start_info: &Node<'tree, StrDoc<SupportLang>>,
    command: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    process_start_info_property(root, use_site, start_info, "Arguments").or_else(|| {
        let executable = literal_string(command)?;
        let name = executable
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or(&executable)
            .to_ascii_lowercase();
        let interpreter = matches!(
            name.as_str(),
            "cmd"
                | "cmd.exe"
                | "powershell"
                | "powershell.exe"
                | "pwsh"
                | "pwsh.exe"
                | "sh"
                | "bash"
                | "dash"
                | "zsh"
                | "ksh"
        );
        let values = interpreter
            .then(|| argument_list_values(root, use_site, start_info))
            .flatten()?;
        values.windows(2).find_map(|pair| {
            let switch = literal_string(&pair[0])?.to_ascii_lowercase();
            matches!(
                switch.as_str(),
                "/c" | "/k" | "-c" | "-command" | "-encodedcommand" | "-file"
            )
            .then(|| pair[1].clone())
        })
    })
}

fn process_start_info_property<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    start_info: &Node<'tree, StrDoc<SupportLang>>,
    property: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if start_info.kind().as_ref() == "object_creation_expression" {
        return creation_property(start_info, property);
    }
    let start_info_text = start_info.text();
    let name = simple_identifier(start_info_text.trim())?;
    let scope = scope_range(use_site, root);
    let before = use_site.range().start;
    let mut candidates = root
        .dfs()
        .filter(|node| {
            scope.start <= node.range().start
                && node.range().end <= scope.end
                && node.range().start < before
        })
        .filter_map(|node| {
            if node.kind().as_ref() == "variable_declarator"
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
                && lexical_declaration_visible_at(&node, use_site)
            {
                let creation = node.dfs().find(|child| {
                    child.kind().as_ref() == "object_creation_expression"
                        && child.field("type").is_some_and(|kind| {
                            short_type(kind.text().as_ref()) == "ProcessStartInfo"
                        })
                })?;
                return creation_property(&creation, property)
                    .map(|value| (node.range().start, value));
            }
            if node.kind().as_ref() == "assignment_expression" {
                let left = compact(node.field("left")?.text().as_ref());
                if left == format!("{name}.{property}") {
                    return Some((node.range().start, node.field("right")?));
                }
            }
            None
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(offset, _)| *offset);
    candidates.pop().map(|(_, value)| value)
}

fn creation_property<'tree>(
    creation: &Node<'tree, StrDoc<SupportLang>>,
    property: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    initializer_property(creation, property).or_else(|| {
        (property == "Arguments")
            .then(|| node_arguments(creation)?.get(1).cloned())
            .flatten()
    })
}

fn argument_list_values<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    start_info: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Vec<Node<'tree, StrDoc<SupportLang>>>> {
    let start_info_text = start_info.text();
    let name = simple_identifier(start_info_text.trim())?;
    let scope = scope_range(use_site, root);
    let mut values = root
        .dfs()
        .filter(|node| is_prior_in_scope(node, use_site, &scope))
        .filter_map(|node| {
            (node.kind().as_ref() == "invocation_expression").then_some(())?;
            let function = compact(node.field("function")?.text().as_ref());
            (function == format!("{name}.ArgumentList.Add")).then_some(())?;
            let value = node_arguments(&node)?.into_iter().next()?;
            Some((node.range().start, value))
        })
        .collect::<Vec<_>>();
    values.sort_by_key(|(offset, _)| *offset);
    (!values.is_empty()).then(|| values.into_iter().map(|(_, value)| value).collect())
}

fn initializer_property<'tree>(
    creation: &Node<'tree, StrDoc<SupportLang>>,
    property: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    creation.dfs().find_map(|child| {
        (child.kind().as_ref() == "assignment_expression"
            && child.field("left").is_some_and(|left| {
                compact(left.text().as_ref()).trim_start_matches("this.") == property
            }))
        .then(|| child.field("right"))
        .flatten()
    })
}

fn literal_string(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let text = node.text();
    let text = text.trim();
    let text = text.strip_prefix('@').unwrap_or(text);
    (text.len() >= 2 && text.starts_with('"') && text.ends_with('"'))
        .then(|| text[1..text.len() - 1].replace("\\\"", "\""))
}

fn file_name_initializer<'tree>(
    creation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    creation.dfs().find_map(|child| {
        (child.kind().as_ref() == "assignment_expression"
            && child.field("left").is_some_and(|left| {
                compact(left.text().as_ref()).trim_start_matches("this.") == "FileName"
            }))
        .then(|| child.field("right"))
        .flatten()
    })
}

fn receiver_has_short_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    expected: &str,
) -> bool {
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        node.range().start < use_site.range().start
            && scope.start <= node.range().start
            && node.range().end <= scope.end
            && ((node.kind().as_ref() == "parameter"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == receiver)
                && node
                    .field("type")
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == expected))
                || (node.kind().as_ref() == "variable_declarator"
                    && lexical_declaration_visible_at(&node, use_site)
                    && node
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver)
                    && (node
                        .parent()
                        .and_then(|parent| parent.field("type"))
                        .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
                        || node.dfs().any(|child| {
                            child.kind().as_ref() == "object_creation_expression"
                                && child.field("type").is_some_and(|kind| {
                                    short_type(kind.text().as_ref()) == expected
                                })
                        })
                        || (expected == "PowerShell"
                            && compact(node.text().as_ref()).contains("=PowerShell.Create()")))))
    })
}

fn is_prior_in_scope(
    node: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    scope: &Range<usize>,
) -> bool {
    scope.start <= node.range().start
        && node.range().end <= scope.end
        && node.range().start < use_site.range().start
}

fn scope_suffix(
    root: &Node<'_, StrDoc<SupportLang>>,
    node: &Node<'_, StrDoc<SupportLang>>,
) -> String {
    slice_root(root, node.range().end..scope_range(node, root).end)
}

fn slice_root(root: &Node<'_, StrDoc<SupportLang>>, range: Range<usize>) -> String {
    let root_range = root.range();
    let text = root.text();
    let start = range.start.saturating_sub(root_range.start);
    let end = range.end.saturating_sub(root_range.start).min(text.len());
    text.get(start..end).unwrap_or_default().to_string()
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

fn short_type(text: &str) -> &str {
    text.trim()
        .trim_end_matches('?')
        .rsplit('.')
        .next()
        .unwrap_or(text)
}

fn has_using(root: &Node<'_, StrDoc<SupportLang>>, namespace: &str) -> bool {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .map(|node| compact(node.text().as_ref()))
        .any(|using| {
            using == format!("using{namespace};") || using == format!("globalusing{namespace};")
        })
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut chars = text.chars();
    let first = chars.next()?;
    (first == '_' || first.is_alphabetic()).then_some(())?;
    chars
        .all(|character| character == '_' || character.is_alphanumeric())
        .then_some(text)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
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

fn evidence_id(rule_id: &str, path: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
