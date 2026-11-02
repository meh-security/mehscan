use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Availability, AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceKind,
    Language, Location, Position, Provenance, Resolution,
};

use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::native_api::NativeApiContext;

const CAPACITY_RULE_ID: &str = "c-family-local-buffer-capacity";

pub(super) fn accepts_write(call: &BufferNode<'_>, api: &NativeApiContext) -> bool {
    let Some(function) = call.field("function") else {
        return false;
    };
    let raw = function.text();
    let name = api.call_name(call).unwrap_or(raw.trim());
    let Some(arguments) = call.field("arguments") else {
        return false;
    };
    let arity = arguments
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
        .count();
    match name {
        "strcpy" | "strcat" => arity == 2,
        "memcpy" | "memmove" | "strncpy" | "strncat" => arity == 3,
        _ => false,
    }
}

pub(crate) fn annotate_native_buffer_capacity(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
    conditional: &ConditionalRegions,
    api: &NativeApiContext,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::C | Language::Cpp) {
        return;
    }
    if !evidence
        .iter()
        .any(|item| item.capability == Capability::BufferWrite)
    {
        return;
    }
    let index = BufferIndex::new(path, root, api, conditional);

    let mut validations = Vec::new();
    for sink in evidence
        .iter_mut()
        .filter(|item| item.capability == Capability::BufferWrite)
    {
        let call = index.calls.get(&sink.location.start.byte_offset);
        let Some(name @ ("memcpy" | "memmove" | "strncpy" | "strncat")) =
            call.and_then(|call| call.api_name)
        else {
            continue;
        };
        let string_copy = matches!(name, "strncpy" | "strncat").then_some(name);
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
        let Some(call_node) = call.map(|call| &call.node) else {
            continue;
        };
        let Some(binding) = index.destination_binding(call_node, destination_name) else {
            continue;
        };
        let Some(array) = index.arrays.get(&(binding.start, binding.end)) else {
            continue;
        };
        let capacity = array.capacity;
        let availability = conditional.availability_for(array.range.clone());
        if availability.state == AvailabilityState::Excluded
            || availability.state != AvailabilityState::Always
                && sink.context.availability.as_ref() != Some(&availability)
        {
            continue;
        }
        let capacity_capture = array.capture.clone();
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
        let function_scope = call.and_then(|call| call.function_scope.clone());
        let terminator = string_copy
            .is_some()
            .then(|| {
                explicit_terminator(
                    &index,
                    &TerminationSearch {
                        path,
                        destination: destination_name,
                        capacity,
                        symbol: sink.enclosing_symbol.as_deref(),
                        function_scope,
                        sink_end: sink.location.end.byte_offset,
                        conditional,
                        availability: sink.context.availability.as_ref(),
                        binding: array.binding.clone(),
                        call: call_node,
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

struct CallInfo<'tree> {
    node: BufferNode<'tree>,
    api_name: Option<&'static str>,
    function_scope: Option<std::ops::Range<usize>>,
}

struct ArrayCapacity {
    capacity: Option<usize>,
    capture: Capture,
    range: std::ops::Range<usize>,
    binding: std::ops::Range<usize>,
}

type BufferNode<'tree> = Node<'tree, StrDoc<SupportLang>>;
type Terminators<'tree> = BTreeMap<usize, Vec<(usize, BufferNode<'tree>)>>;

struct BufferIndex<'tree> {
    calls: BTreeMap<usize, CallInfo<'tree>>,
    arrays: BTreeMap<(usize, usize), ArrayCapacity>,
    terminators: BTreeMap<(Option<String>, usize, usize, String), Terminators<'tree>>,
    bindings: DestinationBindings,
    statement_starts: BTreeSet<usize>,
}

type DestinationBindings =
    BTreeMap<String, BTreeMap<(usize, usize), BTreeMap<usize, std::ops::Range<usize>>>>;

impl<'tree> BufferIndex<'tree> {
    fn new(
        path: &str,
        root: &BufferNode<'tree>,
        api: &NativeApiContext,
        conditional: &ConditionalRegions,
    ) -> Self {
        let mut index = Self {
            calls: BTreeMap::new(),
            arrays: BTreeMap::new(),
            terminators: BTreeMap::new(),
            bindings: BTreeMap::new(),
            statement_starts: BTreeSet::new(),
        };
        let mut terminators = Vec::new();
        let excluded = conditional.exclusion_index();
        for (order, node) in root.dfs().enumerate() {
            if excluded.contains(node.range()) {
                continue;
            }
            let kind = node.kind();
            if kind.as_ref() == "declaration"
                || kind.ends_with("_statement") && kind.as_ref() != "compound_statement"
            {
                index.statement_starts.insert(node.range().start);
            }
            match node.kind().as_ref() {
                "declaration"
                | "field_declaration"
                | "parameter_declaration"
                | "optional_parameter_declaration" => {
                    let parameter = matches!(
                        node.kind().as_ref(),
                        "parameter_declaration" | "optional_parameter_declaration"
                    );
                    let scope = node.ancestors().find(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "compound_statement"
                                | "field_declaration_list"
                                | "namespace_definition"
                                | "translation_unit"
                                | "for_statement"
                                | "for_range_loop"
                                | "catch_clause"
                        ) || parameter
                            && matches!(
                                n.kind().as_ref(),
                                "function_definition" | "lambda_expression"
                            )
                    });
                    let Some(scope) = scope else { continue };
                    for declarator in node.field_children("declarator") {
                        let Some(name) = super::native_api::declaration_name(&declarator) else {
                            continue;
                        };
                        index
                            .bindings
                            .entry(name)
                            .or_default()
                            .entry((scope.range().start, scope.range().end))
                            .or_default()
                            .insert(declarator.range().start, declarator.range());
                    }
                }
                "call_expression" => {
                    let scope = node
                        .ancestors()
                        .find(|n| n.kind().as_ref() == "function_definition")
                        .map(|n| n.range());
                    let info = index
                        .calls
                        .entry(node.range().start)
                        .or_insert_with(|| CallInfo {
                            node: node.clone(),
                            api_name: api.call_name(&node),
                            function_scope: None,
                        });
                    if info.function_scope.is_none() {
                        info.function_scope = scope;
                    }
                }
                "array_declarator" => {
                    let Some(size) = node.field("size") else {
                        continue;
                    };
                    if !is_byte_array_declaration(&node) {
                        continue;
                    }
                    let binding = std::iter::once(node.clone())
                        .chain(node.ancestors())
                        .take_while(|n| n.kind().as_ref() != "declaration")
                        .last()
                        .map_or_else(|| node.range(), |n| n.range());
                    index.arrays.insert(
                        (binding.start, binding.end),
                        ArrayCapacity {
                            capacity: parse_integer(size.text().trim()),
                            capture: Capture {
                                text: size.text().into_owned(),
                                location: location(path, &size),
                            },
                            range: node.range(),
                            binding,
                        },
                    );
                }
                "assignment_expression" => {
                    let (Some(left), Some(right)) = (node.field("left"), node.field("right"))
                    else {
                        continue;
                    };
                    if !matches!(compact(right.text().as_ref()).as_str(), "0" | "'\\0'") {
                        continue;
                    }
                    terminators.push((order, compact(left.text().as_ref()), node));
                }
                _ => {}
            }
        }
        for (order, text, node) in terminators {
            let Some((destination, _)) =
                text.split_once('[').filter(|(name, _)| is_identifier(name))
            else {
                continue;
            };
            let Some(binding) = index.destination_binding(&node, destination) else {
                continue;
            };
            index
                .terminators
                .entry((enclosing_symbol(&node), binding.start, binding.end, text))
                .or_default()
                .entry(node.range().start)
                .or_default()
                .push((order, node));
        }
        index
    }

    fn destination_binding(
        &self,
        site: &BufferNode<'_>,
        name: &str,
    ) -> Option<std::ops::Range<usize>> {
        let scopes = self.bindings.get(name)?;
        site.ancestors()
            .filter_map(|scope| {
                let bindings = scopes.get(&(scope.range().start, scope.range().end))?;
                let (_, declaration) = bindings.range(..=site.range().start).next_back()?;
                Some((scope.range().len(), declaration))
            })
            .min_by_key(|(width, declaration)| (*width, usize::MAX - declaration.start))
            .map(|(_, declaration)| declaration.clone())
    }
}

struct TerminationSearch<'a, 'tree> {
    path: &'a str,
    destination: &'a str,
    capacity: Option<usize>,
    symbol: Option<&'a str>,
    function_scope: Option<std::ops::Range<usize>>,
    sink_end: usize,
    conditional: &'a ConditionalRegions,
    availability: Option<&'a Availability>,
    binding: std::ops::Range<usize>,
    call: &'a BufferNode<'tree>,
}

fn explicit_terminator(
    index: &BufferIndex<'_>,
    search: &TerminationSearch<'_, '_>,
) -> Option<Capture> {
    use std::ops::Bound::{Excluded, Included, Unbounded};
    let destination = search.destination;
    // sizeof(VLA)-1 and a zero-length extension do not establish an in-bounds
    // byte. Keep those cases open rather than saturating zero into index zero.
    let capacity = search.capacity.filter(|capacity| *capacity > 0)?;
    let block = straight_line_block(search.call)?;
    let mut expressions = vec![
        format!("{destination}[sizeof({destination})-1]"),
        format!("{destination}[sizeof{destination}-1]"),
        format!("{destination}[(sizeof({destination}))-1]"),
        format!("{destination}[(sizeof{destination})-1]"),
    ];
    expressions.push(format!("{destination}[{}]", capacity - 1));
    let candidates = expressions
        .into_iter()
        .filter_map(|text| {
            index.terminators.get(&(
                search.symbol.map(str::to_string),
                search.binding.start,
                search.binding.end,
                text,
            ))
        })
        .collect::<Vec<_>>();
    // Stop at the first intervening effect. Earlier optional assignments of
    // the same final zero byte are harmless, but a read, handoff, return or
    // runtime branch cannot be crossed to find a more convenient terminator.
    let barrier = index
        .statement_starts
        .range((Excluded(search.sink_end), Unbounded))
        .find(|start| {
            !candidates
                .iter()
                .any(|assignments| assignments.contains_key(start))
        })
        .copied();
    candidates
        .into_iter()
        .filter_map(|assignments| {
            if search
                .function_scope
                .as_ref()
                .is_some_and(|scope| scope.end <= search.sink_end)
            {
                return None;
            }
            let end = search
                .function_scope
                .as_ref()
                .map_or(Unbounded, |scope| Included(scope.end));
            let end = match (end, barrier) {
                (Included(end), Some(barrier)) => Excluded(end.min(barrier)),
                (end, None) => end,
                (_, Some(barrier)) => Excluded(barrier),
            };
            assignments
                .range((Excluded(search.sink_end), end))
                .flat_map(|(_, nodes)| nodes)
                .find(|(_, node)| {
                    straight_line_block(node).as_ref() == Some(&block)
                        && search.function_scope.as_ref().is_none_or(|scope| {
                            scope.start <= node.range().start && node.range().end <= scope.end
                        })
                        && {
                            let availability = search.conditional.availability_for(node.range());
                            match availability.state {
                                AvailabilityState::Always => true,
                                AvailabilityState::Conditional | AvailabilityState::Unknown => {
                                    search
                                        .availability
                                        .is_some_and(|sink| sink == &availability)
                                }
                                AvailabilityState::Excluded => false,
                            }
                        }
                })
        })
        .min_by_key(|(order, _)| *order)
        .map(|(_, assignment)| Capture {
            text: assignment.text().into_owned(),
            location: location(search.path, &assignment),
        })
}

fn straight_line_block(node: &BufferNode<'_>) -> Option<std::ops::Range<usize>> {
    for parent in node.ancestors() {
        match parent.kind().as_ref() {
            "compound_statement" => return Some(parent.range()),
            "expression_statement"
            | "preproc_if"
            | "preproc_ifdef"
            | "preproc_elif"
            | "preproc_else" => {}
            _ => return None,
        }
    }
    None
}

fn is_destination_sizeof(value: &str, destination: &str) -> bool {
    let mut value = compact(value);
    while value.starts_with('(') && value.ends_with(')') {
        value = value[1..value.len() - 1].to_string();
    }
    value == format!("sizeof({destination})") || value == format!("sizeof{destination}")
}

fn is_byte_array_declaration(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if !node
        .field("declarator")
        .is_some_and(|declarator| declarator.kind().as_ref() == "identifier")
        || !node.parent().is_some_and(|parent| {
            matches!(parent.kind().as_ref(), "declaration" | "init_declarator")
        })
    {
        return false;
    }
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
    } else if value.len() > 1 && value.starts_with('0') {
        usize::from_str_radix(value, 8).ok()
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
