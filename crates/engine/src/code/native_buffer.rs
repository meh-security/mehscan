use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Availability, AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceKind,
    Language, Location, Position, Provenance, Resolution,
};

use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;

const CAPACITY_RULE_ID: &str = "c-family-local-buffer-capacity";

pub(crate) fn annotate_native_buffer_capacity(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    conditional: &ConditionalRegions,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::C | Language::Cpp) {
        return;
    }

    let mut validations = Vec::new();
    for sink in evidence
        .iter_mut()
        .filter(|item| item.capability == Capability::BufferWrite)
    {
        let string_copy = string_copy_kind(root, sink.location.start.byte_offset);
        let Some(destination) = sink.captures.get("destination").cloned() else {
            continue;
        };
        let destination_name = destination.text.trim();
        if !is_identifier(destination_name) {
            continue;
        }
        if string_copy.is_some() {
            sink.tags.push("string-termination:unproven".to_string());
        }
        let Some((capacity, capacity_capture)) = declared_byte_array_capacity(
            path,
            root,
            destination_name,
            sink.enclosing_symbol.as_deref(),
            sink.location.start.byte_offset,
        ) else {
            continue;
        };
        sink.captures
            .insert("capacity".to_string(), capacity_capture.clone());

        let Some(size) = sink.captures.get("size") else {
            continue;
        };
        let exact_size = parse_integer(size.text.trim());
        let uses_destination_sizeof = is_destination_sizeof(size.text.as_str(), destination_name);
        let sufficient = uses_destination_sizeof
            || capacity.is_some_and(|capacity| exact_size.is_some_and(|size| size <= capacity));
        let insufficient =
            capacity.is_some_and(|capacity| exact_size.is_some_and(|size| size > capacity));
        let function_scope = enclosing_function_range(root, sink.location.start.byte_offset);
        let terminator = string_copy
            .is_some()
            .then(|| {
                explicit_terminator(
                    root,
                    &TerminationSearch {
                        path,
                        destination: destination_name,
                        capacity,
                        symbol: sink.enclosing_symbol.as_deref(),
                        function_scope,
                        sink_end: sink.location.end.byte_offset,
                        conditional,
                        availability: sink.context.availability.as_ref(),
                    },
                )
            })
            .flatten();
        if terminator.is_some() {
            sink.tags.retain(|tag| tag != "string-termination:unproven");
        }
        if string_copy == Some("strncat") {
            sink.tags
                .push("buffer-capacity:destination-offset-unproven".to_string());
        }
        if insufficient {
            sink.tags
                .push("buffer-capacity:known-insufficient".to_string());
        } else if sufficient
            && (string_copy.is_none() || string_copy == Some("strncpy") && terminator.is_some())
        {
            sink.tags
                .push("buffer-capacity:proven-sufficient".to_string());
            let mut captures = BTreeMap::new();
            captures.insert("destination".to_string(), destination.clone());
            captures.insert("size".to_string(), size.clone());
            captures.insert("capacity".to_string(), capacity_capture.clone());
            validations.push(Evidence {
                id: format!("{}-capacity", sink.id),
                kind: EvidenceKind::Validation,
                capability: Capability::BufferCapacityValidation,
                location: sink.location.clone(),
                enclosing_symbol: sink.enclosing_symbol.clone(),
                captures,
                cwe_candidates: vec![
                    "CWE-120".to_string(),
                    "CWE-787".to_string(),
                    "CWE-805".to_string(),
                ],
                tags: vec![
                    "native".to_string(),
                    "memory".to_string(),
                    "exact-local-capacity".to_string(),
                ],
                confidence: Confidence::High,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "tree-sitter local capacity analysis".to_string(),
                    rule_version: 1,
                },
                context: sink.context.clone(),
                symbol_resolution: None,
                rule_id: CAPACITY_RULE_ID.to_string(),
                related_evidence: vec![sink.id.clone()],
            });
            if let Some(terminator) = terminator {
                validations.push(Evidence {
                    id: format!("{}-termination", sink.id),
                    kind: EvidenceKind::Validation,
                    capability: Capability::StringTerminationValidation,
                    location: terminator.location.clone(),
                    enclosing_symbol: sink.enclosing_symbol.clone(),
                    captures: BTreeMap::from([
                        ("destination".to_string(), destination.clone()),
                        ("capacity".to_string(), capacity_capture.clone()),
                        ("terminator".to_string(), terminator),
                    ]),
                    cwe_candidates: vec!["CWE-170".to_string()],
                    tags: vec![
                        "native".to_string(),
                        "string".to_string(),
                        "exact-local-termination".to_string(),
                    ],
                    confidence: Confidence::High,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "tree-sitter local string termination analysis".to_string(),
                        rule_version: 1,
                    },
                    context: sink.context.clone(),
                    symbol_resolution: None,
                    rule_id: "c-family-local-string-termination".to_string(),
                    related_evidence: vec![sink.id.clone()],
                });
            }
        }
    }
    evidence.extend(validations);
}

fn string_copy_kind(
    root: &Node<'_, StrDoc<SupportLang>>,
    sink_offset: usize,
) -> Option<&'static str> {
    root.dfs()
        .find(|node| node.kind().as_ref() == "call_expression" && node.range().start == sink_offset)
        .and_then(|call| call.field("function"))
        .and_then(|callee| match callee.text().trim() {
            "strncpy" => Some("strncpy"),
            "strncat" => Some("strncat"),
            _ => None,
        })
}

struct TerminationSearch<'a> {
    path: &'a str,
    destination: &'a str,
    capacity: Option<usize>,
    symbol: Option<&'a str>,
    function_scope: Option<std::ops::Range<usize>>,
    sink_end: usize,
    conditional: &'a ConditionalRegions,
    availability: Option<&'a Availability>,
}

fn explicit_terminator(
    root: &Node<'_, StrDoc<SupportLang>>,
    search: &TerminationSearch<'_>,
) -> Option<Capture> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| node.range().start > search.sink_end)
        .filter(|node| {
            search.function_scope.as_ref().is_none_or(|scope| {
                scope.start <= node.range().start && node.range().end <= scope.end
            })
        })
        .filter(|node| enclosing_symbol(node).as_deref() == search.symbol)
        .filter(|node| {
            let availability = search.conditional.availability_for(node.range());
            match availability.state {
                AvailabilityState::Always => true,
                AvailabilityState::Conditional | AvailabilityState::Unknown => search
                    .availability
                    .is_some_and(|sink| sink == &availability),
                AvailabilityState::Excluded => false,
            }
        })
        .find_map(|assignment| {
            let left = assignment.field("left")?;
            let right = assignment.field("right")?;
            let text = compact(left.text().as_ref());
            let destination = search.destination;
            let sizeof_indices = [
                format!("{destination}[sizeof({destination})-1]"),
                format!("{destination}[sizeof{destination}-1]"),
                format!("{destination}[(sizeof({destination}))-1]"),
                format!("{destination}[(sizeof{destination})-1]"),
            ];
            let matches_literal = search.capacity.is_some_and(|capacity| {
                text == format!("{destination}[{}]", capacity.saturating_sub(1))
            });
            let zero = compact(right.text().as_ref());
            ((matches_literal || sizeof_indices.contains(&text))
                && matches!(zero.as_str(), "0" | "'\\0'"))
            .then(|| Capture {
                text: assignment.text().into_owned(),
                location: location(search.path, &assignment),
            })
        })
}

fn enclosing_function_range(
    root: &Node<'_, StrDoc<SupportLang>>,
    sink_offset: usize,
) -> Option<std::ops::Range<usize>> {
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "call_expression" && node.range().start == sink_offset
        })
        .find_map(|call| {
            call.ancestors()
                .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
                .map(|function| function.range())
        })
}

fn declared_byte_array_capacity(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    destination: &str,
    symbol: Option<&str>,
    sink_offset: usize,
) -> Option<(Option<usize>, Capture)> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "array_declarator")
        .filter(|node| node.range().start < sink_offset)
        .filter(|node| enclosing_symbol(node).as_deref() == symbol)
        .filter_map(|node| {
            let declarator = node.field("declarator")?;
            let size = node.field("size")?;
            if declarator.text().trim() != destination || !is_byte_array_declaration(&node) {
                return None;
            }
            Some((
                parse_integer(size.text().trim()),
                Capture {
                    text: size.text().into_owned(),
                    location: location(path, &size),
                },
            ))
        })
        .last()
}

fn is_destination_sizeof(value: &str, destination: &str) -> bool {
    let mut value = compact(value);
    while value.starts_with('(') && value.ends_with(')') {
        value = value[1..value.len() - 1].to_string();
    }
    value == format!("sizeof({destination})") || value == format!("sizeof{destination}")
}

fn is_byte_array_declaration(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let Some(declaration) = node
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "declaration")
    else {
        return false;
    };
    let Some(declarator) = node.field("declarator") else {
        return false;
    };
    let prefix_length = declarator
        .range()
        .start
        .saturating_sub(declaration.range().start);
    let text = declaration.text();
    let prefix = text.get(..prefix_length).unwrap_or_default();
    prefix
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| matches!(token, "char" | "uint8_t"))
}

fn parse_integer(value: &str) -> Option<usize> {
    let value = value.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
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
