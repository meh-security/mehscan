use std::collections::{BTreeMap, BTreeSet};

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

const ENGINE: &str = "mehscan csharp-standalone-boundaries 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_standalone_observations<'tree>(
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
    add_codedom_sinks(path, root, comments, conditional, literals, evidence);
    add_deserialization_sinks(path, root, comments, conditional, literals, evidence);
    add_process_sinks(path, root, comments, conditional, literals, evidence);
    add_smo_sinks(path, root, comments, conditional, literals, evidence);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_standalone_sources<'tree>(
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
    let impacted_symbols = evidence
        .iter()
        .filter(|item| {
            item.location.path == path
                && item.kind == EvidenceKind::Sink
                && matches!(
                    item.capability,
                    Capability::DatabaseQuery
                        | Capability::ProcessExecution
                        | Capability::DynamicCodeExecution
                        | Capability::Deserialization
                        | Capability::FilesystemRead
                        | Capability::FilesystemWrite
                )
        })
        .filter_map(|item| item.enclosing_symbol.clone())
        .collect::<BTreeSet<_>>();

    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if !matches!(
            compact(function.text().as_ref()).as_str(),
            "Console.ReadLine" | "System.Console.ReadLine"
        ) {
            continue;
        }
        if invocation.ancestors().any(|ancestor| {
            (ancestor.kind().as_ref() == "object_creation_expression"
                && ancestor.field("type").is_some_and(|kind| {
                    terminal_type(compact(kind.text().as_ref()).as_str()) == "SqlParameter"
                }))
                || (ancestor.kind().as_ref() == "invocation_expression"
                    && ancestor.field("function").is_some_and(|function| {
                        compact(function.text().as_ref()).ends_with(".Parameters.Add")
                    }))
        }) {
            continue;
        }
        let symbol = enclosing_symbol(&invocation);
        if !symbol
            .as_ref()
            .is_some_and(|symbol| impacted_symbols.contains(symbol))
        {
            continue;
        }
        push(
            path,
            &invocation,
            &invocation,
            EvidenceKind::Source,
            Capability::ExternalInput,
            "csharp-console-readline-source",
            "value",
            &["CWE-20"],
            &["console", "process-input", "externally-controlled"],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_codedom_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !has_using(root, "Microsoft.CodeDom.Providers.DotNetCompilerPlatform")
        || declares_type(root, "CSharpCodeProvider")
        || !root.dfs().any(|node| {
            node.kind().as_ref() == "object_creation_expression"
                && node.field("type").is_some_and(|kind| {
                    terminal_type(compact(kind.text().as_ref()).as_str()) == "CSharpCodeProvider"
                })
        })
    {
        return;
    }
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if !compact(function.text().as_ref()).ends_with(".CompileAssemblyFromSource") {
            continue;
        }
        let args = arguments(&invocation);
        let Some(code) = args.last() else {
            continue;
        };
        push(
            path,
            &invocation,
            code,
            EvidenceKind::Sink,
            Capability::DynamicCodeExecution,
            "csharp-codedom-source-compilation",
            "code",
            &["CWE-94"],
            &["codedom", "compiler", "dynamic-code"],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_deserialization_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let fastjson = has_using(root, "fastJSON") && !declares_type(root, "JSON");
    let fspickler = has_using(root, "MBrace.FsPickler.Json") && !declares_type(root, "FsPickler");
    let fspickler_receivers = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = declaration.field("value").or_else(|| {
                declaration
                    .children()
                    .filter(|child| child.is_named())
                    .last()
            })?;
            (compact(value.text().as_ref()) == "FsPickler.CreateJsonSerializer()")
                .then(|| name.text().trim().to_string())
        })
        .collect::<Vec<_>>();
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function = compact(function.text().as_ref());
        let args = arguments(&invocation);
        if fastjson
            && function == "JSON.ToObject"
            && args.len() >= 2
            && compact(args[1].text().as_ref()).contains("BadListTypeChecking=false")
        {
            push(
                path,
                &invocation,
                &args[0],
                EvidenceKind::Sink,
                Capability::Deserialization,
                "csharp-fastjson-unrestricted-deserialization",
                "payload",
                &["CWE-502"],
                &["fastjson", "type-restriction-disabled", "deserialization"],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if fastjson
            && function == "JSON.ToObject"
            && args.len() >= 2
            && compact(args[1].text().as_ref()).contains("BadListTypeChecking=true")
        {
            push(
                path,
                &invocation,
                &args[0],
                EvidenceKind::Validation,
                Capability::DeserializationRestriction,
                "csharp-fastjson-type-restriction-control",
                "payload",
                &["CWE-502"],
                &["fastjson", "type-restriction-enabled", "control"],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if fspickler
            && fspickler_receivers
                .iter()
                .any(|receiver| function.starts_with(&format!("{receiver}.Deserialize")))
            && let Some(payload) = args.first()
        {
            push(
                path,
                &invocation,
                payload,
                EvidenceKind::Sink,
                Capability::Deserialization,
                "csharp-fspickler-deserialization",
                "payload",
                &["CWE-502"],
                &["fspickler", "object-graph", "deserialization"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_process_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !has_using(root, "System.Diagnostics") && !root.text().contains("System.Diagnostics.Process")
    {
        return;
    }
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let left_text = compact(left.text().as_ref());
        let property = left_text.rsplit('.').next().unwrap_or(&left_text);
        if !matches!(property, "FileName" | "Arguments")
            || !contains_console_readline(&right)
            || !process_assignment(root, &assignment, &left_text)
        {
            continue;
        }
        push_process(
            path,
            &assignment,
            &right,
            property,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    for creation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "object_creation_expression")
    {
        if creation.field("type").is_none_or(|kind| {
            terminal_type(compact(kind.text().as_ref()).as_str()) != "ProcessStartInfo"
        }) {
            continue;
        }
        let args = arguments(&creation);
        for (index, value) in args.iter().take(2).enumerate() {
            if contains_console_readline(value) {
                push_process(
                    path,
                    &creation,
                    value,
                    if index == 0 { "FileName" } else { "Arguments" },
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_process<'tree>(
    path: &str,
    operation: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    property: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push(
        path,
        operation,
        value,
        EvidenceKind::Sink,
        Capability::ProcessExecution,
        if property == "FileName" {
            "csharp-process-start-info-executable"
        } else {
            "csharp-process-start-info-arguments"
        },
        if property == "FileName" {
            "command"
        } else {
            "arguments"
        },
        &["CWE-78"],
        &["process", "process-start-info", "dynamic-value"],
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_smo_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !has_using(root, "Microsoft.SqlServer.Management.Smo")
        || !has_using(root, "Microsoft.SqlServer.Management.Common")
        || declares_type(root, "Server")
    {
        return;
    }
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if !compact(function.text().as_ref()).ends_with(".ConnectionContext.ExecuteNonQuery") {
            continue;
        }
        let args = arguments(&invocation);
        let Some(query) = args.first() else {
            continue;
        };
        push(
            path,
            &invocation,
            query,
            EvidenceKind::Sink,
            Capability::DatabaseQuery,
            "csharp-smo-command-text",
            "query",
            &["CWE-89"],
            &["sql", "smo", "command-text"],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn process_assignment(
    root: &Node<'_, StrDoc<SupportLang>>,
    assignment: &Node<'_, StrDoc<SupportLang>>,
    left: &str,
) -> bool {
    if let Some((receiver, _)) = left.rsplit_once('.') {
        return variable_has_type(root, assignment, receiver, "ProcessStartInfo");
    }
    assignment.ancestors().any(|ancestor| {
        ancestor.kind().as_ref() == "object_creation_expression"
            && ancestor.field("type").is_some_and(|kind| {
                terminal_type(compact(kind.text().as_ref()).as_str()) == "ProcessStartInfo"
            })
    })
}

fn variable_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
    expected: &str,
) -> bool {
    root.dfs().any(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node.range().start < use_site.range().start
            && node
                .field("name")
                .is_some_and(|field| field.text().trim() == name)
            && node.parent().is_some_and(|parent| {
                let declared = parent
                    .field("type")
                    .map(|kind| compact(kind.text().as_ref()))
                    .unwrap_or_default();
                terminal_type(&declared) == expected
                    || (declared == "var"
                        && node.field("value").is_some_and(|value| {
                            value.kind().as_ref() == "object_creation_expression"
                                && value.field("type").is_some_and(|kind| {
                                    terminal_type(compact(kind.text().as_ref()).as_str())
                                        == expected
                                })
                        }))
            })
    }) || root.dfs().any(|node| {
        node.range().start < use_site.range().start
            && node.kind().as_ref() == "assignment_expression"
            && node
                .field("left")
                .is_some_and(|left| compact(left.text().as_ref()) == name)
            && node.field("right").is_some_and(|right| {
                right.kind().as_ref() == "object_creation_expression"
                    && right.field("type").is_some_and(|kind| {
                        terminal_type(compact(kind.text().as_ref()).as_str()) == expected
                    })
            })
    })
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
        .collect()
}

fn arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .collect()
        })
        .unwrap_or_default()
}

fn has_using(root: &Node<'_, StrDoc<SupportLang>>, namespace: &str) -> bool {
    let expected = format!("using{namespace};");
    root.dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .any(|node| compact(node.text().as_ref()) == expected)
}

fn declares_type(root: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == expected)
    })
}

fn terminal_type(text: &str) -> &str {
    text.rsplit('.').next().unwrap_or(text)
}

fn contains_console_readline(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.dfs().any(|candidate| {
        candidate.kind().as_ref() == "invocation_expression"
            && candidate.field("function").is_some_and(|function| {
                matches!(
                    compact(function.text().as_ref()).as_str(),
                    "Console.ReadLine" | "System.Console.ReadLine"
                )
            })
    })
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::from([(
            role.to_string(),
            Capture {
                text: value.text().into_owned(),
                location: location(path, value),
            },
        )]),
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: BTreeMap::from([(role.to_string(), literals.evaluate(value))]),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
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
    let hash = input.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    format!("ev-{hash:016x}")
}
