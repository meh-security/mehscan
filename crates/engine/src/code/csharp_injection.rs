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
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan csharp-injection-summary 1";
type EncoderMatch<'tree> = (
    Node<'tree, StrDoc<SupportLang>>,
    Node<'tree, StrDoc<SupportLang>>,
);

pub(crate) fn add_injection_evidence<'tree>(
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

    for creation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "object_creation_expression")
    {
        if comments.is_in_comment(creation.range()) {
            continue;
        }
        let Some(kind) = creation.field("type") else {
            continue;
        };
        let kind = kind.text();
        let arguments = node_arguments(&creation).unwrap_or_default();
        if type_is(
            root,
            kind.as_ref(),
            "System.DirectoryServices.DirectorySearcher",
        ) {
            let filter = initializer_value(&creation, "Filter")
                .or_else(|| directory_searcher_filter_argument(root, &creation, &arguments));
            if let Some(filter) = filter {
                push_ldap_sink(
                    path,
                    root,
                    &creation,
                    "csharp-directory-searcher-filter",
                    "filter",
                    &filter,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        } else if type_is(
            root,
            kind.as_ref(),
            "System.DirectoryServices.Protocols.SearchRequest",
        ) && arguments.len() >= 2
            && !expression_has_type(root, &creation, &arguments[1], "System.Xml.XmlDocument")
        {
            push_ldap_sink(
                path,
                root,
                &creation,
                "csharp-ldap-search-request-filter",
                "filter",
                &arguments[1],
                comments,
                conditional,
                literals,
                evidence,
            );
            push_ldap_sink(
                path,
                root,
                &creation,
                "csharp-ldap-search-request-dn",
                "distinguished_name",
                &arguments[0],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if type_is(
            root,
            kind.as_ref(),
            "System.DirectoryServices.DirectoryEntry",
        ) && let Some(distinguished_name) =
            initializer_value(&creation, "Path").or_else(|| arguments.first().cloned())
        {
            push_ldap_sink(
                path,
                root,
                &creation,
                "csharp-directory-entry-path",
                "distinguished_name",
                &distinguished_name,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        if comments.is_in_comment(assignment.range()) {
            continue;
        }
        let (Some(left), Some(value)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let left = compact(left.text().as_ref());
        if let Some(receiver) = left.strip_suffix(".Filter").and_then(simple_identifier)
            && receiver_has_type(
                root,
                &assignment,
                receiver,
                "System.DirectoryServices.DirectorySearcher",
            )
        {
            push_ldap_sink(
                path,
                root,
                &assignment,
                "csharp-directory-searcher-filter-assignment",
                "filter",
                &value,
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if let Some(receiver) = left.strip_suffix(".Path").and_then(simple_identifier)
            && receiver_has_type(
                root,
                &assignment,
                receiver,
                "System.DirectoryServices.DirectoryEntry",
            )
        {
            push_ldap_sink(
                path,
                root,
                &assignment,
                "csharp-directory-entry-path-assignment",
                "distinguished_name",
                &value,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_ldap_sink<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    role: &'static str,
    input: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.push(build_evidence(
        path,
        node,
        EvidenceKind::Sink,
        Capability::LdapQuery,
        rule_id,
        &["ldap", if role == "filter" { "filter" } else { "dn" }],
        [(role, input)],
        comments,
        conditional,
        literals,
    ));

    let encoder_name = if role == "filter" {
        "LdapFilterEncode"
    } else {
        "LdapDistinguishedNameEncode"
    };
    let Some((encoder, value)) = find_antixss_encoder(root, input, encoder_name) else {
        return;
    };
    evidence.push(build_evidence(
        path,
        &encoder,
        EvidenceKind::Validation,
        if role == "filter" {
            Capability::LdapFilterEncoding
        } else {
            Capability::LdapDistinguishedNameEncoding
        },
        if role == "filter" {
            "csharp-antixss-filter-applied-to-ldap-filter"
        } else {
            "csharp-antixss-dn-applied-to-ldap-dn"
        },
        &["ldap", "encoding", "exact-context"],
        [(role, input), ("value", &value)],
        comments,
        conditional,
        literals,
    ));
}

#[allow(clippy::too_many_arguments)]
fn build_evidence<'tree, const N: usize>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    tags: &[&str],
    captures: [(&str, &Node<'tree, StrDoc<SupportLang>>); N],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    let captured_literals = captures
        .iter()
        .map(|(role, capture)| ((*role).to_string(), literals.evaluate(capture)))
        .collect();
    let captured_locations = captures
        .iter()
        .map(|(role, capture)| {
            (
                (*role).to_string(),
                Capture {
                    text: capture.text().into_owned(),
                    location: location(path, capture),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    Evidence {
        id: evidence_id(rule_id, path, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: captured_locations,
        cwe_candidates: vec!["CWE-90".to_string()],
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
            literals: captured_literals,
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    }
}

fn directory_searcher_filter_argument<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    creation: &Node<'tree, StrDoc<SupportLang>>,
    arguments: &[Node<'tree, StrDoc<SupportLang>>],
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let first = arguments.first()?;
    if expression_has_type(
        root,
        creation,
        first,
        "System.DirectoryServices.DirectoryEntry",
    ) {
        arguments.get(1).cloned()
    } else {
        Some(first.clone())
    }
}

fn initializer_value<'tree>(
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

fn find_antixss_encoder<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    input: &Node<'tree, StrDoc<SupportLang>>,
    method: &str,
) -> Option<EncoderMatch<'tree>> {
    input.dfs().find_map(|node| {
        if node.kind().as_ref() != "invocation_expression" {
            return None;
        }
        let function = node.field("function")?;
        let callee = compact(function.text().as_ref());
        let owner = callee.strip_suffix(&format!(".{method}"))?;
        if !type_is(root, owner, "Microsoft.Security.Application.Encoder") {
            return None;
        }
        let value = node_arguments(&node)?.into_iter().next()?;
        Some((node, value))
    })
}

fn expression_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    expression: &Node<'_, StrDoc<SupportLang>>,
    canonical: &str,
) -> bool {
    if expression.kind().as_ref() == "object_creation_expression" {
        return expression
            .field("type")
            .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical));
    }
    simple_identifier(expression.text().trim())
        .is_some_and(|name| receiver_has_type(root, use_site, name, canonical))
}

fn receiver_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    canonical: &str,
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
                    .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical)))
                || (node.kind().as_ref() == "variable_declarator"
                    && node
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver)
                    && (node
                        .parent()
                        .and_then(|parent| parent.field("type"))
                        .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical))
                        || node.dfs().any(|child| {
                            child.kind().as_ref() == "object_creation_expression"
                                && child.field("type").is_some_and(|kind| {
                                    type_is(root, kind.text().as_ref(), canonical)
                                })
                        }))))
    })
}

fn type_is(root: &Node<'_, StrDoc<SupportLang>>, actual: &str, canonical: &str) -> bool {
    let actual = compact(actual);
    if actual == canonical {
        return true;
    }
    let (namespace, short) = canonical.rsplit_once('.').unwrap_or(("", canonical));
    let declarations_shadow = root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == short)
    });
    for using in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .map(|node| compact(node.text().as_ref()))
    {
        let using = using
            .strip_prefix("globalusing")
            .or_else(|| using.strip_prefix("using"))
            .unwrap_or(&using)
            .trim_end_matches(';');
        if let Some((alias, target)) = using.split_once('=') {
            if (target == canonical && actual == alias)
                || (target == namespace && actual == format!("{alias}.{short}"))
            {
                return true;
            }
        } else if using == namespace && actual == short && !declarations_shadow {
            return true;
        }
    }
    false
}

fn node_arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Vec<Node<'tree, StrDoc<SupportLang>>>> {
    let arguments = node.field("arguments")?;
    Some(
        arguments
            .children()
            .filter(|child| child.is_named())
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
