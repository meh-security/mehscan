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

const ZIP_ENTRY: &str = "System.IO.Compression.ZipArchiveEntry";
const ENGINE: &str = "mehscan bounded-csharp-archive 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_archive_observations<'tree>(
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

    // Replace broad declarative and older short-type observations with exact
    // type-aware evidence before security paths are constructed.
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "csharp-zip-entry-full-name" | "csharp-zip-entry-extract-to-file"
        )
    });

    for member in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "member_access_expression")
    {
        if comments.is_in_comment(member.range())
            || member
                .field("name")
                .is_none_or(|name| name.text().trim() != "FullName")
        {
            continue;
        }
        let Some(receiver) = member.field("expression") else {
            continue;
        };
        if !receiver_has_type(root, &member, &receiver, ZIP_ENTRY) {
            continue;
        }
        push(
            path,
            &member,
            EvidenceKind::Source,
            Capability::ArchiveEntryPath,
            "csharp-zip-entry-full-name",
            &["CWE-22"],
            &["archive", "zip", "entry-path", "attacker-controlled"],
            [("path", &member)],
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if function.kind().as_ref() != "member_access_expression" {
            continue;
        }
        let Some(receiver) = function.field("expression") else {
            continue;
        };
        let method = function
            .field("name")
            .map(|name| name.text().trim().to_string());
        let Some(arguments) = invocation_arguments(&invocation) else {
            continue;
        };

        if method.as_deref() == Some("ExtractToFile")
            && !arguments.is_empty()
            && receiver_has_type(root, &invocation, &receiver, ZIP_ENTRY)
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::FilesystemWrite,
                "csharp-zip-entry-extract-to-file",
                &["CWE-22"],
                &[
                    "filesystem",
                    "archive",
                    "zip-extraction",
                    "destination-path",
                ],
                [("path", &arguments[0]), ("entry", &receiver)],
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }

        if method.as_deref() != Some("StartsWith") || arguments.len() < 2 {
            continue;
        }
        let destination = compact(receiver.text().as_ref());
        let Some(destination_name) = simple_identifier(&destination) else {
            continue;
        };
        if compact(arguments[1].text().as_ref()) != "StringComparison.Ordinal"
            || !canonical_archive_destination(root, &invocation, destination_name, &arguments[0])
            || !separator_terminated_root(root, &invocation, &arguments[0])
        {
            continue;
        }
        push(
            path,
            &invocation,
            EvidenceKind::Validation,
            Capability::PathContainmentCheck,
            "csharp-zip-entry-rooted-containment",
            &["CWE-22"],
            &[
                "archive",
                "zip",
                "canonicalized",
                "component-boundary",
                "ordinal",
            ],
            [("path", &receiver), ("base", &arguments[0])],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn canonical_archive_destination<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    compared_base: &Node<'tree, StrDoc<SupportLang>>,
) -> bool {
    prior_declarator(root, use_site, name).is_some_and(|declaration| {
        let text = compact(declaration.text().as_ref());
        let compared_base = compact(compared_base.text().as_ref());
        text.contains("=Path.GetFullPath(Path.Combine(")
            && text.contains(&format!("Path.Combine({compared_base},"))
            && text.contains(".FullName")
            && text.ends_with(')')
    })
}

fn separator_terminated_root<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    base: &Node<'tree, StrDoc<SupportLang>>,
) -> bool {
    let text = compact(base.text().as_ref());
    if text.contains("Path.GetFullPath(")
        && (text.contains("Path.DirectorySeparatorChar")
            || text.contains("Path.AltDirectorySeparatorChar"))
    {
        return true;
    }
    let Some(name) = simple_identifier(&text) else {
        return false;
    };
    prior_declarator(root, use_site, name).is_some_and(|declaration| {
        let text = compact(declaration.text().as_ref());
        text.contains("Path.GetFullPath(")
            && (text.contains("Path.DirectorySeparatorChar")
                || text.contains("Path.AltDirectorySeparatorChar"))
    })
}

fn prior_declarator<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let scope = scope_range(use_site, root);
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && scope.start <= node.range().start
                && node.range().end <= scope.end
                && node.range().start < use_site.range().start
                && node
                    .field("name")
                    .is_some_and(|candidate| candidate.text().trim() == name)
        })
        .last()
}

fn receiver_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    canonical: &str,
) -> bool {
    let receiver_text = compact(receiver.text().as_ref());
    let Some(receiver_name) = simple_identifier(&receiver_text) else {
        return false;
    };
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        node.range().start < use_site.range().start
            && scope.start <= node.range().start
            && node.range().end <= scope.end
            && ((node.kind().as_ref() == "parameter"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == receiver_name)
                && node
                    .field("type")
                    .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical)))
                || (node.kind().as_ref() == "variable_declarator"
                    && lexical_declaration_visible_at(&node, use_site)
                    && node
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver_name)
                    && node
                        .parent()
                        .and_then(|parent| parent.field("type"))
                        .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical)))
                || (node.kind().as_ref() == "foreach_statement"
                    && lexical_declaration_visible_at(&node, use_site)
                    && node
                        .field("left")
                        .is_some_and(|left| left.text().trim() == receiver_name)
                    && node
                        .field("type")
                        .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical))))
    })
}

fn type_is(root: &Node<'_, StrDoc<SupportLang>>, actual: &str, canonical: &str) -> bool {
    let actual = compact(actual);
    if actual == canonical {
        return true;
    }
    let (namespace, short) = canonical.rsplit_once('.').unwrap_or(("", canonical));
    let shadowed = root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == short)
    });
    for directive in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .map(|node| compact(node.text().as_ref()))
    {
        let directive = directive
            .strip_prefix("globalusing")
            .or_else(|| directive.strip_prefix("using"))
            .unwrap_or(&directive)
            .trim_end_matches(';');
        if let Some((alias, target)) = directive.split_once('=') {
            if (target == canonical && actual == alias)
                || (target == namespace && actual == format!("{alias}.{short}"))
            {
                return true;
            }
        } else if directive == namespace && actual == short && !shadowed {
            return true;
        }
    }
    false
}

fn invocation_arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Vec<Node<'tree, StrDoc<SupportLang>>>> {
    Some(
        invocation
            .field("arguments")?
            .children()
            .filter(|child| child.is_named())
            .map(|argument| {
                if argument.kind().as_ref() == "argument" {
                    argument
                        .children()
                        .filter(|child| child.is_named())
                        .last()
                        .unwrap_or(argument)
                } else {
                    argument
                }
            })
            .collect(),
    )
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

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree, const N: usize>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    captures: [(&str, &Node<'tree, StrDoc<SupportLang>>); N],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let mut literal_values = BTreeMap::new();
    let captures = captures
        .into_iter()
        .map(|(role, capture)| {
            literal_values.insert(role.to_string(), literals.evaluate(capture));
            (
                role.to_string(),
                Capture {
                    text: capture.text().into_owned(),
                    location: location(path, capture),
                },
            )
        })
        .collect();
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: if kind == EvidenceKind::Source {
            Confidence::High
        } else {
            Confidence::Medium
        },
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: literal_values,
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
