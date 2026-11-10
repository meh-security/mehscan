//! Bounded lexical navigation, not Python dataflow or an authorization proof.
use super::*;

struct Packet<'a> {
    file: &'a SourceFile,
    anchor: &'a Evidence,
    facts: Vec<ReviewNeighborhoodFact>,
    truncated: bool,
}

impl Packet<'_> {
    fn add(&mut self, node: &PyNode<'_>, role: &str, symbol: &str, detail: &str) {
        let span = node.range();
        if self.facts.iter().any(|f| {
            f.role == role
                && f.location.start.byte_offset == span.start
                && f.location.end.byte_offset == span.end
        }) {
            return;
        }
        if self.facts.len() >= 10 {
            self.truncated = true;
            return;
        }
        let text = &self.file.source[span.clone()];
        let bytes = text
            .split_inclusive('\n')
            .take(40)
            .map(str::len)
            .sum::<usize>()
            .min(4096);
        let end = floor_char_boundary(&self.file.source, span.start + bytes);
        self.truncated |= end < span.end;
        self.facts.push(ReviewNeighborhoodFact {
            role: role.into(), symbol: symbol.into(),
            location: location_from_offsets(&self.file.path, &self.file.source, span.start, end),
            excerpt: self.file.source[span.start..end].into(), evidence_id: Some(self.anchor.id.clone()),
            provenance: QueryProvenance { resolution: Resolution::Ast, engine: format!("Python ORM selection navigation 1; {detail}; lexical source only, not reaching-definition, same-record, batch membership, query correlation, authorization, freshness or execution proof") },
        });
    }
}

fn same_scope(node: &PyNode<'_>, function: &PyNode<'_>) -> bool {
    for parent in node.ancestors() {
        if parent.range() == function.range() {
            return true;
        }
        if matches!(
            parent.kind().as_ref(),
            "function_definition"
                | "class_definition"
                | "lambda"
                | "list_comprehension"
                | "dictionary_comprehension"
                | "set_comprehension"
                | "generator_expression"
        ) {
            return false;
        }
    }
    false
}

fn simple_reference(node: &PyNode<'_>) -> Option<String> {
    if !matches!(node.kind().as_ref(), "identifier" | "attribute") {
        return None;
    }
    let name = node.text();
    (!name.is_empty() && name.split('.').all(is_plain_identifier)).then(|| name.into_owned())
}

fn value<'a>(node: &PyNode<'a>) -> Option<PyNode<'a>> {
    node.field("right").or_else(|| node.field("value"))
}

fn target<'a>(node: &PyNode<'a>) -> Option<PyNode<'a>> {
    match node.kind().as_ref() {
        "assignment"
        | "augmented_assignment"
        | "named_expression"
        | "for_statement"
        | "for_in_clause" => node.field("left").or_else(|| node.field("name")),
        "function_definition" | "class_definition" => node.field("name"),
        "as_pattern" => node.field("alias"),
        _ => None,
    }
}

// Attribute/subscript stores change an object, not the local binding itself.
fn binds(node: &PyNode<'_>, name: &str) -> bool {
    if matches!(node.kind().as_ref(), "attribute" | "subscript") {
        return false;
    }
    node.kind().as_ref() == "identifier" && node.text() == name
        || node
            .children()
            .filter(|n| n.is_named())
            .any(|n| binds(&n, name))
}

fn receiver_expression<'a>(call: &PyNode<'a>) -> PyNode<'a> {
    let mut current = call.clone();
    for _ in 0..32 {
        let Some(parent) = current.parent() else {
            break;
        };
        let pass = match parent.kind().as_ref() {
            "parenthesized_expression" => true,
            "attribute" => parent
                .field("object")
                .is_some_and(|n| n.range() == current.range()),
            "call" => parent
                .field("function")
                .is_some_and(|n| n.range() == current.range()),
            _ => false,
        };
        if !pass {
            break;
        }
        current = parent;
    }
    current
}

fn input_sources<'a>(packet: &mut Packet<'_>, function: &PyNode<'a>, call: &PyNode<'a>) {
    let Some(args) = call.field("arguments") else {
        return;
    };
    let inputs = args
        .children()
        .filter(|n| n.kind().as_ref() == "keyword_argument")
        .filter_map(|n| {
            n.field("value")
                .and_then(|v| simple_reference(&v))
                .map(|name| (n, name))
        })
        .collect::<Vec<_>>();
    packet.truncated |= inputs.len() > 2;
    for (input, reference) in inputs.into_iter().take(2) {
        let name = reference.split('.').next().unwrap_or("");
        packet.add(&input, "python_orm_selection_input_context", &reference, "direct selector operand spelling; property/key meaning and model identity are unverified");
        let mut definitions = function
            .dfs()
            .filter(|n| {
                same_scope(n, function)
                    && n.range().end <= call.range().start
                    && value(n).is_some()
                    && target(n).is_some_and(|t| binds(&t, name))
            })
            .collect::<Vec<_>>();
        definitions.sort_by_key(|n| n.range().start);
        packet.truncated |= definitions.len() > 2;
        if definitions.is_empty() {
            if let Some(parameters) = function.field("parameters") {
                for parameter in parameters.children().filter(|n| n.is_named()) {
                    let binding = parameter.field("name").unwrap_or_else(|| parameter.clone());
                    if binding.kind().as_ref() == "identifier" && binding.text() == name
                        || parameter.kind().as_ref() == "typed_parameter"
                            && parameter
                                .children()
                                .next()
                                .is_some_and(|n| n.text() == name)
                    {
                        packet.add(&parameter, "python_orm_selection_origin_context", &reference, "selector input parameter declaration; caller authority and actual value remain open");
                    }
                }
            }
        } else {
            for definition in definitions.into_iter().rev().take(2).rev() {
                packet.add(&definition, "python_orm_selection_origin_context", &reference, "prior lexical binding candidate for selector input; alternatives, branches and intervening writes may change the runtime value");
            }
        }
    }
}

fn uses(node: &PyNode<'_>, names: &BTreeMap<String, usize>) -> Option<String> {
    node.dfs()
        .find(|n| {
            n.kind().as_ref() == "identifier"
                && !n.parent().is_some_and(|p| {
                    p.kind().as_ref() == "keyword_argument"
                        && p.field("name")
                            .is_some_and(|name| name.range() == n.range())
                        || p.kind().as_ref() == "attribute"
                            && p.field("attribute")
                                .is_some_and(|name| name.range() == n.range())
                })
                && (n.range() == node.range()
                    || !n
                        .ancestors()
                        .take_while(|p| p.range() != node.range())
                        .any(|p| {
                            matches!(
                                p.kind().as_ref(),
                                "lambda"
                                    | "function_definition"
                                    | "class_definition"
                                    | "list_comprehension"
                                    | "dictionary_comprehension"
                                    | "set_comprehension"
                                    | "generator_expression"
                            )
                        }))
                && names
                    .get(n.text().as_ref())
                    .is_some_and(|end| *end <= n.range().start)
        })
        .map(|n| n.text().into_owned())
}

fn rebinds(node: &PyNode<'_>, name: &str) -> bool {
    if target(node).is_some_and(|t| binds(&t, name)) {
        return true;
    }
    match node.kind().as_ref() {
        "delete_statement" | "global_statement" | "nonlocal_statement" => {
            node.children().any(|n| binds(&n, name))
        }
        "import_statement" | "import_from_statement" => node
            .field_children("name")
            .any(|n| n.field("alias").unwrap_or(n).text().split('.').next() == Some(name)),
        _ => false,
    }
}

fn receiver_root(node: &PyNode<'_>, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }
    match node.kind().as_ref() {
        "identifier" => Some(node.text().into_owned()),
        "attribute" => receiver_root(&node.field("object")?, depth - 1),
        "subscript" => receiver_root(&node.field("value")?, depth - 1),
        _ => None,
    }
}

fn consumers<'a>(
    packet: &mut Packet<'_>,
    function: &PyNode<'a>,
    binding: &PyNode<'a>,
    name: String,
) {
    let mut active = BTreeMap::from([(name, binding.range().end)]);
    let mut stopped = BTreeSet::new();
    let mut aliases = 0;
    let mut boundaries = 0;
    let mut consumers = Vec::new();
    let mut nodes = function
        .dfs()
        .filter(|n| same_scope(n, function) && n.range().start >= binding.range().end)
        .collect::<Vec<_>>();
    nodes.sort_by_key(|n| (n.range().start, std::cmp::Reverse(n.range().end)));
    for node in nodes {
        let alias = if node.kind().as_ref() == "assignment" {
            node.field("left")
                .filter(|n| n.kind().as_ref() == "identifier")
                .zip(value(&node).filter(|n| n.kind().as_ref() == "identifier"))
                .filter(|(_, right)| active.contains_key(right.text().as_ref()))
                .map(|(left, right)| (left.text().into_owned(), right.text().into_owned()))
        } else {
            None
        };
        let rebound = active
            .keys()
            .filter(|name| rebinds(&node, name))
            .cloned()
            .collect::<Vec<_>>();
        for name in rebound {
            active.remove(&name);
            stopped.insert(name.clone());
            if boundaries < 2 {
                packet.add(&node, "python_orm_binding_boundary_context", &name, "observed store/deletion/scope declaration stops navigation of this local name, even on a conditional branch");
                boundaries += 1;
            } else {
                packet.truncated = true;
            }
        }
        if let Some((left, right)) = alias {
            if aliases < 2 && !stopped.contains(&left) {
                packet.add(&node, "python_orm_alias_context", &left, &format!("direct local alias spelling from {right}; this does not establish that the assignment reaches later uses"));
                active.insert(left, node.range().end);
                aliases += 1;
            } else {
                packet.truncated = true;
            }
        }
        if node.kind().as_ref() == "assignment" || node.kind().as_ref() == "augmented_assignment" {
            if let Some(left) = node
                .field("left")
                .filter(|n| matches!(n.kind().as_ref(), "attribute" | "subscript"))
            {
                if let Some(name) = receiver_root(&left, 8).filter(|name| active.contains_key(name))
                {
                    consumers.push((1, node.clone(), name, "write through a selected-name/alias expression; receiver identity and effective effect remain open"));
                }
            }
        }
        if node.kind().as_ref() != "call" {
            continue;
        }
        let Some(function) = node.field("function") else {
            continue;
        };
        let receiver = function.field("object").and_then(|n| uses(&n, &active));
        let argument = node.field("arguments").and_then(|n| uses(&n, &active));
        let receiver_use = receiver.is_some();
        if let Some(name) = receiver.or(argument) {
            let method = function
                .field("attribute")
                .map(|n| n.text().into_owned())
                .unwrap_or_default();
            let priority = if matches!(
                method.as_str(),
                "save"
                    | "delete"
                    | "update"
                    | "bulk_update"
                    | "bulk_create"
                    | "add"
                    | "remove"
                    | "clear"
                    | "set"
            ) {
                0
            } else if receiver_use {
                3
            } else {
                2
            };
            consumers.push((priority, node, name, "call referencing a selected local name or direct alias; method/helper effects, branch reachability and runtime object identity are unverified"));
        }
    }
    consumers
        .sort_by_key(|(priority, node, _, _)| (*priority, node.range().start, node.range().end));
    packet.truncated |= consumers.len() > 4;
    for (_, node, name, detail) in consumers.into_iter().take(4) {
        packet.add(
            &node,
            "python_orm_selection_consumer_context",
            &name,
            detail,
        );
    }
}

pub(super) fn facts<'a>(
    file: &SourceFile,
    call: &PyNode<'a>,
    anchor: &Evidence,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let Some(function) = owner(call) else {
        return (Vec::new(), false);
    };
    if function
        .dfs()
        .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
    {
        return (Vec::new(), false);
    }
    let mut packet = Packet {
        file,
        anchor,
        facts: Vec::new(),
        truncated: false,
    };
    input_sources(&mut packet, &function, call);
    let expression = receiver_expression(call);
    let binding = expression.parent().filter(|n| {
        matches!(n.kind().as_ref(), "assignment" | "named_expression")
            && value(n).is_some_and(|v| v.range() == expression.range())
            && target(n).is_some_and(|t| t.kind().as_ref() == "identifier")
    });
    if let Some(binding) = binding {
        let name = target(&binding).unwrap().text().into_owned();
        packet.add(&binding, "python_orm_selection_binding_context", &name, "selected receiver expression assigned to a name; result type, policy preservation and dominance are unverified");
        if let Some(declaration) = function.dfs().find(|n| {
            same_scope(n, &function)
                && matches!(n.kind().as_ref(), "global_statement" | "nonlocal_statement")
                && rebinds(n, &name)
        }) {
            packet.add(
                &declaration,
                "python_orm_binding_boundary_context",
                &name,
                "nonlocal/global declaration prevents local-name navigation",
            );
        } else {
            consumers(&mut packet, &function, &binding, name);
        }
    } else if expression.range() != call.range() {
        packet.add(&expression, "python_orm_selection_consumer_context", "receiver chain", "selected call occurs syntactically on this extended receiver chain; return types and filtering preservation remain open");
    }
    (packet.facts, packet.truncated)
}
