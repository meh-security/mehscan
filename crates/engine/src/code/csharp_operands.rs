//! Local query envelopes and command producers; observations, never safety closure.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capture, Evidence, Language, Location, OperandFact, OperandFactKind, Position};
use std::collections::{BTreeMap, BTreeSet};

type CsNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(crate) fn annotate(language: Language, root: &CsNode<'_>, evidence: &mut [Evidence]) {
    if language != Language::Csharp {
        return;
    }
    let relevant = |item: &Evidence| {
        matches!(
            item.rule_id.as_str(),
            "csharp-dapper-database-query" | "csharp-sql-command-text"
        )
    };
    let ranges = evidence
        .iter()
        .filter(|e| relevant(e))
        .filter_map(|e| e.captures.get("query"))
        .map(|c| (c.location.start.byte_offset, c.location.end.byte_offset))
        .collect::<BTreeSet<_>>();
    if ranges.is_empty() {
        return;
    }
    let mut nodes = BTreeMap::new();
    let mut bindings = BTreeMap::<String, Vec<CsNode<'_>>>::new();
    let mut uses = BTreeMap::<String, Vec<CsNode<'_>>>::new();
    let mut ambiguous_definition = false;
    for node in root.dfs().filter(|n| n.is_named()) {
        if ranges.contains(&(node.range().start, node.range().end)) {
            nodes.insert((node.range().start, node.range().end), node.clone());
        }
        if node.kind().as_ref() == "variable_declarator" {
            if let Some(name) = node.field("name") {
                bindings
                    .entry(name.text().to_string())
                    .or_default()
                    .push(node.clone());
            }
        }
        if matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|n| n.text() == "CommandDefinition")
        {
            ambiguous_definition = true;
        }
        if node.kind().as_ref() == "using_directive"
            && node.text().contains('=')
            && node
                .text()
                .split('=')
                .next()
                .is_some_and(|n| n.split_whitespace().any(|s| s == "CommandDefinition"))
        {
            ambiguous_definition = true;
        }
        if node.kind().as_ref() == "identifier" {
            uses.entry(node.text().to_string()).or_default().push(node);
        }
    }
    for item in evidence.iter_mut().filter(|e| relevant(e)) {
        let Some(query) = item.captures.get("query") else {
            continue;
        };
        let Some(node) = nodes.get(&(
            query.location.start.byte_offset,
            query.location.end.byte_offset,
        )) else {
            continue;
        };
        if item.rule_id == "csharp-sql-command-text" {
            let left = node
                .ancestors()
                .find(|n| {
                    n.kind().as_ref() == "assignment_expression"
                        && n.range().start == item.location.start.byte_offset
                })
                .and_then(|n| n.field("left"));
            if item.tags.iter().any(|t| t == "typed-object-initializer") {
                if let Some(creation) = node.ancestors().find(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "object_creation_expression" | "implicit_object_creation_expression"
                    )
                }) {
                    fact(
                        item,
                        "command",
                        OperandFactKind::LocalOperandOrigin,
                        &creation,
                        "command_initializer",
                        &[
                            "receiver_or_constructor_contract",
                            "statement_ownership",
                            "execution_and_access_policy",
                        ],
                    );
                    if creation.range().len() <= 2048 {
                        item.captures
                            .insert("command_origin".into(), capture(item, &creation));
                    }
                }
                continue;
            }
            if let Some(name) = item.captures.get("command").map(|c| c.text.clone()) {
                if !left
                    .as_ref()
                    .is_some_and(|left| left.text().trim() == format!("{name}.CommandText"))
                {
                    boundary(
                        item,
                        "command",
                        left.as_ref().unwrap_or(node),
                        "field_or_nonlocal_receiver",
                    );
                    continue;
                }
                local_origin(item, node, &name, "command", &bindings, &uses);
            }
            continue;
        }
        let producer = if node.kind().as_ref() == "identifier" {
            let Some(origin) =
                local_origin(item, node, node.text().as_ref(), "query", &bindings, &uses)
            else {
                continue;
            };
            origin
        } else {
            node.clone()
        };
        if producer.kind().as_ref() != "object_creation_expression" {
            boundary(item, "query", &producer, "command_definition_constructor");
            continue;
        }
        if ambiguous_definition
            || !producer.field("type").is_some_and(|n| {
                matches!(
                    n.text().as_ref(),
                    "CommandDefinition" | "Dapper.CommandDefinition"
                )
            })
        {
            boundary(item, "query", &producer, "command_definition_identity");
            continue;
        }
        if producer.range().len() > 2048 {
            boundary(item, "query", &producer, "oversized_operand_initializer");
            continue;
        }
        let Some(slots) = definition_slots(&producer) else {
            boundary(item, "query", &producer, "command_definition_arguments");
            continue;
        };
        let Some(text) = slots.get("commandText") else {
            boundary(item, "query", &producer, "command_text_slot");
            continue;
        };
        item.captures
            .insert("query_text".into(), capture(item, text));
        if let Some(parameters) = slots.get("parameters") {
            item.captures
                .insert("query_values".into(), capture(item, parameters));
        }
        if let Some(mode) = slots.get("commandType") {
            item.captures
                .insert("query_command_type".into(), capture(item, mode));
        }
        let fixed = matches!(
            text.kind().as_ref(),
            "string_literal" | "verbatim_string_literal" | "raw_string_literal"
        );
        fact(
            item,
            "query",
            OperandFactKind::QueryStructure,
            text,
            if fixed && slots.contains_key("parameters") {
                "fixed_text_with_values"
            } else if fixed {
                "fixed_text"
            } else {
                "nonliteral_text"
            },
            &[
                "driver_and_overload_contract",
                "effective_command_type",
                "parameter_behavior",
                "data_access_policy",
            ],
        );
    }
}

fn callable(node: &CsNode<'_>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "method_declaration"
                    | "constructor_declaration"
                    | "local_function_statement"
                    | "lambda_expression"
                    | "anonymous_method_expression"
            )
        })
        .map(|n| n.range())
}

fn owner(node: &CsNode<'_>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "block" | "using_statement" | "for_statement" | "foreach_statement"
            )
        })
        .map(|n| n.range())
}

fn local_origin<'a>(
    item: &mut Evidence,
    use_site: &CsNode<'a>,
    name: &str,
    role: &str,
    bindings: &BTreeMap<String, Vec<CsNode<'a>>>,
    uses: &BTreeMap<String, Vec<CsNode<'a>>>,
) -> Option<CsNode<'a>> {
    let eligible = bindings
        .get(name)
        .into_iter()
        .flatten()
        .filter(|binding| {
            binding.range().end < use_site.range().start
                && callable(binding) == callable(use_site)
                && owner(binding).is_some_and(|range| {
                    range.start <= use_site.range().start && range.end >= use_site.range().end
                })
        })
        .collect::<Vec<_>>();
    let [binding] = eligible.as_slice() else {
        boundary(item, role, use_site, "unique_local_operand_binding");
        return None;
    };
    let Some(value) = binding.field("value").or_else(|| {
        binding
            .children()
            .filter(|n| n.is_named())
            .last()
            .filter(|n| {
                n.range().start > binding.field("name").map_or(usize::MAX, |n| n.range().end)
            })
    }) else {
        boundary(item, role, binding, "operand_initializer");
        return None;
    };
    fact(
        item,
        role,
        OperandFactKind::LocalOperandOrigin,
        &value,
        name,
        &[
            "receiver_or_constructor_contract",
            "statement_ownership",
            "execution_and_access_policy",
        ],
    );
    let before = if role == "command" {
        item.location.start.byte_offset
    } else {
        use_site.range().start
    };
    if let Some(usage) = uses.get(name).into_iter().flatten().find(|n| {
        n.range().start >= binding.range().end
            && (n.range().start < before || callable(n) != callable(binding))
            && owner(binding).is_some_and(|r| n.range().start >= r.start && n.range().end <= r.end)
    }) {
        boundary(item, role, usage, "intervening_use_or_escape");
        return None;
    }
    if value.range().len() > 2048 {
        boundary(item, role, &value, "oversized_operand_initializer");
        return None;
    }
    item.captures
        .insert(format!("{role}_origin"), capture(item, &value));
    Some(value)
}

fn definition_slots<'a>(creation: &CsNode<'a>) -> Option<BTreeMap<&'static str, CsNode<'a>>> {
    let names = [
        "commandText",
        "parameters",
        "transaction",
        "commandTimeout",
        "commandType",
        "flags",
        "cancellationToken",
    ];
    let arguments = creation.field("arguments")?;
    let mut slots = BTreeMap::new();
    for (position, arg) in arguments
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
        .enumerate()
    {
        if arg.kind().as_ref() != "argument"
            || arg
                .children()
                .any(|n| matches!(n.kind().as_ref(), "ref" | "out" | "in"))
        {
            return None;
        }
        let mut children = arg
            .children()
            .filter(|n| n.is_named() && n.kind().as_ref() != "comment");
        let first = children.next()?;
        let named = arg.children().any(|n| n.kind().as_ref() == ":");
        let (name, value) = if named {
            (
                names
                    .iter()
                    .copied()
                    .find(|name| *name == first.text().as_ref())?,
                children.last()?,
            )
        } else {
            (*names.get(position)?, first)
        };
        if slots.insert(name, value).is_some() {
            return None;
        }
    }
    Some(slots)
}

fn capture(item: &Evidence, node: &CsNode<'_>) -> Capture {
    let start = node.start_pos();
    let end = node.end_pos();
    Capture {
        text: node.text().to_string(),
        location: Location {
            path: item.location.path.clone(),
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
        },
    }
}
fn fact(
    item: &mut Evidence,
    role: &str,
    kind: OperandFactKind,
    node: &CsNode<'_>,
    value: &str,
    checks: &[&str],
) {
    item.context.operand_facts.push(OperandFact {
        role: role.into(),
        kind,
        location: capture(item, node).location,
        value: value.into(),
        remaining_checks: checks.iter().map(|s| (*s).into()).collect(),
    });
}
fn boundary(item: &mut Evidence, role: &str, node: &CsNode<'_>, check: &str) {
    fact(
        item,
        role,
        OperandFactKind::OperandBoundary,
        node,
        check,
        &[check],
    );
}
