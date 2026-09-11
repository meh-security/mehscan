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

const ENGINE: &str = "mehscan go-filesystem-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_go_filesystem_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Go || !root.text().contains("\"os\"") {
        return;
    }

    let os_qualifiers = os_qualifiers(root);
    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        match os_function(&call.callee, &os_qualifiers) {
            Some("Create") => {
                let Some(target) = call.arguments.first() else {
                    continue;
                };
                push(
                    path,
                    &call.node,
                    "go-os-create-symlink-following-review",
                    EvidenceKind::SensitiveOperation,
                    Capability::FilesystemWrite,
                    BTreeMap::from([("path".to_string(), capture(path, target))]),
                    &["CWE-59"],
                    &[
                        "filesystem",
                        "create",
                        "follows-existing-symlink",
                        "review-parent-directory-ownership",
                    ],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            Some("OpenFile") if exclusive_creation(&call) => {
                let Some(target) = call.arguments.first() else {
                    continue;
                };
                push(
                    path,
                    &call.node,
                    "go-openfile-exclusive-create-control",
                    EvidenceKind::Validation,
                    Capability::FilesystemWrite,
                    BTreeMap::from([
                        ("path".to_string(), capture(path, target)),
                        ("flags".to_string(), capture(path, &call.arguments[1])),
                    ]),
                    &[],
                    &[
                        "filesystem",
                        "create",
                        "exclusive",
                        "existing-path-rejected",
                        "control",
                    ],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            Some("Mkdir" | "MkdirAll") => {
                let Some(mode) = call.arguments.get(1) else {
                    continue;
                };
                let Some(bits) = parse_go_integer(mode.text().trim()) else {
                    continue;
                };
                if bits & 0o002 == 0 {
                    continue;
                }
                let Some(target) = call.arguments.first() else {
                    continue;
                };
                push(
                    path,
                    &call.node,
                    "go-world-writable-directory-mode",
                    EvidenceKind::SecurityConfiguration,
                    Capability::FilesystemWrite,
                    BTreeMap::from([
                        ("path".to_string(), capture(path, target)),
                        ("mode".to_string(), capture(path, mode)),
                    ]),
                    &["CWE-732"],
                    &["filesystem", "directory", "literal-mode", "world-writable"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            _ => {}
        }
    }
}

fn os_qualifiers(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_spec")
        .filter(|node| {
            node.field("path")
                .is_some_and(|path| path.text().trim_matches('"') == "os")
                || node.text().trim().ends_with("\"os\"")
        })
        .filter_map(|node| {
            node.field("name")
                .map(|name| name.text().trim().to_string())
                .or_else(|| {
                    let text = node.text();
                    let prefix = text.trim().strip_suffix("\"os\"")?.trim();
                    (!prefix.is_empty()).then(|| prefix.to_string())
                })
                .or_else(|| Some("os".to_string()))
        })
        .filter(|qualifier| qualifier != "." && qualifier != "_")
        .collect()
}

fn os_function<'a>(callee: &'a str, qualifiers: &BTreeSet<String>) -> Option<&'a str> {
    let (qualifier, function) = callee.split_once('.')?;
    qualifiers.contains(qualifier).then_some(function)
}

fn exclusive_creation(call: &CallSite<'_>) -> bool {
    let Some(flags) = call.arguments.get(1) else {
        return false;
    };
    let flags = flags.text();
    flags.contains(".O_CREATE") && flags.contains(".O_EXCL")
}

fn parse_go_integer(value: &str) -> Option<u32> {
    let value = value.replace('_', "");
    if let Some(value) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        u32::from_str_radix(value, 8).ok()
    } else if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(value, 16).ok()
    } else if let Some(value) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        u32::from_str_radix(value, 2).ok()
    } else if value.len() > 1 && value.starts_with('0') {
        u32::from_str_radix(&value[1..], 8).ok()
    } else {
        value.parse().ok()
    }
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
    let callee = node.text().get(..callee_length)?.trim().to_string();
    let arguments = arguments
        .children()
        .filter(|child| child.is_named())
        .collect();
    Some(CallSite {
        node,
        callee,
        arguments,
    })
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    cwes: &[&str],
    tags: &[&str],
    confidence: Confidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    );
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
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

#[cfg(test)]
mod tests {
    use super::parse_go_integer;

    #[test]
    fn parses_go_permission_literals() {
        assert_eq!(parse_go_integer("0777"), Some(0o777));
        assert_eq!(parse_go_integer("0o750"), Some(0o750));
        assert_eq!(parse_go_integer("0O755"), Some(0o755));
        assert_eq!(parse_go_integer("511"), Some(511));
        assert_eq!(parse_go_integer("mode"), None);
    }
}
