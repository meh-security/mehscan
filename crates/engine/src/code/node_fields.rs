//! Bounded field copies and selected helper returns.
//! No heap, schema, middleware or arbitrary object-alias inference.
use super::{Node, NodeOperandIndex, Range, StrDoc, SupportLang};

type Ast<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn source_in_object(source: &Ast<'_>, scope: &Range<usize>) -> bool {
    source
        .ancestors()
        .take_while(|n| n.range() != *scope)
        .any(|n| {
            n.kind().as_ref() == "variable_declarator"
                && n.field("name")
                    .is_some_and(|n| matches!(n.kind().as_ref(), "identifier" | "object_pattern"))
                && n.field("value")
                    .is_some_and(|v| v.kind().as_ref() == "object")
        })
}

pub(super) struct Selection<'a> {
    pub value: Ast<'a>,
    pub steps: Vec<super::SecurityPathStep>,
}

pub(super) fn is_return_call(
    node: &Ast<'_>,
    summaries: &std::collections::BTreeMap<String, super::super::node_context::ReturnedObject>,
) -> bool {
    node.kind().as_ref() == "call_expression"
        && node.field("function").is_some_and(|callee| {
            summaries.contains_key(&super::compact_expression(&callee.text()))
        })
}

pub(super) fn source_in_return_call(
    source: &Ast<'_>,
    scope: &Range<usize>,
    summaries: &std::collections::BTreeMap<String, super::super::node_context::ReturnedObject>,
    sink: &Range<usize>,
) -> bool {
    source
        .ancestors()
        .take_while(|n| n.range() != *scope)
        .any(|n| is_return_call(&n, summaries) && !super::contains_range(n.range(), sink.clone()))
}

pub(super) fn destructured_bindings(pattern: &Ast<'_>) -> Option<Vec<(String, Vec<String>)>> {
    fn walk(
        node: &Ast<'_>,
        prefix: &[String],
        result: &mut Vec<(String, Vec<String>)>,
        work: &mut usize,
    ) -> Option<()> {
        if *work == 0 || prefix.len() > 4 {
            return None;
        }
        *work -= 1;
        match node.kind().as_ref() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                result.push((node.text().into_owned(), prefix.to_vec()))
            }
            "object_pattern" => {
                for field in node.children().filter(|n| n.is_named()) {
                    if field.kind().as_ref() == "comment" {
                        continue;
                    }
                    let (key, value) = if field.kind().as_ref() == "pair_pattern" {
                        (field.field("key")?, field.field("value")?)
                    } else if field.kind().as_ref() == "shorthand_property_identifier_pattern" {
                        (field.clone(), field)
                    } else {
                        return None;
                    };
                    let key = static_key(&key)?;
                    let mut path = prefix.to_vec();
                    path.push(key);
                    walk(&value, &path, result, work)?;
                }
            }
            _ => return None,
        }
        Some(())
    }
    let mut result = Vec::new();
    walk(pattern, &[], &mut result, &mut 64)?;
    Some(result)
}

fn static_key(node: &Ast<'_>) -> Option<String> {
    match node.kind().as_ref() {
        "property_identifier" | "shorthand_property_identifier_pattern" => {
            Some(node.text().into_owned())
        }
        "string" if !node.text().contains('\\') => {
            super::simple_string_literal(&node.text()).map(str::to_string)
        }
        _ => None,
    }
}

pub(super) fn projected_value<'a>(
    target: &Ast<'a>,
    index: &NodeOperandIndex<'a>,
    scope: &Range<usize>,
    depth: usize,
    work: &mut usize,
) -> Option<Selection<'a>> {
    let key = static_key(
        &target.field(if target.kind().as_ref() == "subscript_expression" {
            "index"
        } else {
            "property"
        })?,
    )?;
    selected_value(
        &target.field("object")?,
        &[key],
        target,
        index,
        scope,
        depth,
        work,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn selected_value<'a>(
    receiver: &Ast<'a>,
    keys: &[String],
    at: &Ast<'a>,
    index: &NodeOperandIndex<'a>,
    scope: &Range<usize>,
    depth: usize,
    work: &mut usize,
) -> Option<Selection<'a>> {
    if depth > super::MAX_PROPAGATION_DEPTH || *work == 0 {
        return None;
    }
    *work -= 1;
    if keys.is_empty() {
        return Some(Selection {
            value: receiver.clone(),
            steps: Vec::new(),
        });
    }
    let selected = match receiver.kind().as_ref() {
        "identifier" => {
            let binding = index.alias_assignment(scope, receiver)?;
            if !binding.projection.is_empty()
                || !(binding.right.kind().as_ref() == "object"
                    || is_return_call(&binding.right, &index.returned_objects))
            {
                return None;
            }
            let name = receiver.text();
            let start = binding.node.range().end;
            let end = at.range().start;
            if index
                .writes
                .get(name.as_ref())
                .into_iter()
                .flatten()
                .any(|w| {
                    (w.range.start >= start && w.range.start < end)
                        || (w.scope != (scope.start, scope.end)
                            && scope.start <= w.scope.0
                            && w.scope.1 <= scope.end)
                })
                || index
                    .object_escapes()
                    .get(name.as_ref())
                    .into_iter()
                    .flatten()
                    .any(|r| {
                        scope.start <= r.start
                            && r.end <= scope.end
                            && !super::contains_range(at.range(), r.clone())
                    })
            {
                return None;
            }
            selected_value(&binding.right, keys, at, index, scope, depth + 1, work)?
        }
        "member_expression" | "subscript_expression" => {
            let key = static_key(&receiver.field(
                if receiver.kind().as_ref() == "subscript_expression" {
                    "index"
                } else {
                    "property"
                },
            )?)?;
            let mut projection = vec![key];
            projection.extend_from_slice(keys);
            selected_value(
                &receiver.field("object")?,
                &projection,
                at,
                index,
                scope,
                depth + 1,
                work,
            )?
        }
        "call_expression" => {
            let callee = receiver.field("function")?;
            let observed = super::compact_expression(&callee.text());
            let summary = index.returned_objects.get(&observed)?;
            if !stable_call(&callee, index, summary) {
                return None;
            }
            let (parameter, input_path) = summary.fields.as_ref()?.get(keys)?;
            let arguments = receiver.field("arguments")?;
            if arguments
                .children()
                .any(|n| n.kind().as_ref() == "spread_element")
            {
                return None;
            }
            let argument = arguments
                .children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .nth(*parameter)?;
            let mut value = selected_value(
                &argument,
                input_path,
                &argument,
                index,
                scope,
                depth + 1,
                work,
            )?;
            value.steps.push(super::SecurityPathStep {
                kind: super::SecurityPathStepKind::Alias,
                location: summary.location.clone(),
                evidence_id: None,
                symbol: Some(format!(
                    "returned field: {}.{}",
                    summary.canonical,
                    keys.join(".")
                )),
            });
            value
        }
        "object" => {
            let mut found = None;
            let mut seen = std::collections::BTreeSet::new();
            for field in receiver.children().filter(|n| n.is_named()) {
                if *work == 0 {
                    return None;
                }
                *work -= 1;
                if field.kind().as_ref() == "comment" {
                    continue;
                }
                if field.kind().as_ref() != "pair" {
                    return None;
                }
                let key = static_key(&field.field("key")?)?;
                if key == "__proto__" || !seen.insert(key.clone()) {
                    return None;
                }
                if key == keys[0] {
                    found = field.field("value");
                }
            }
            selected_value(&found?, &keys[1..], at, index, scope, depth, work)?
        }
        _ => return None,
    };
    Some(selected)
}

fn stable_call(
    callee: &Ast<'_>,
    index: &NodeOperandIndex<'_>,
    summary: &super::super::node_context::ReturnedObject,
) -> bool {
    let observed = super::compact_expression(&callee.text());
    let Some(head) = observed.split('.').next() else {
        return false;
    };
    let at = callee.range().start;
    let imported = summary.imported || index.imported.contains(head);
    if imported
        && index
            .bindings
            .values()
            .filter_map(|names| names.get(head))
            .map(|b| b.declarations.len())
            .sum::<usize>()
            > 1
    {
        return false;
    }
    let callable = index
        .callable_declarations
        .get(head)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let visible = callable
        .iter()
        .filter(|(_, scope)| scope.start <= at && at < scope.end)
        .collect::<Vec<_>>();
    if !visible.is_empty() {
        if imported {
            return false;
        }
        let nearest = visible
            .iter()
            .map(|(_, scope)| scope.end - scope.start)
            .min()
            .unwrap();
        let targets = visible
            .iter()
            .filter(|(_, scope)| scope.end - scope.start == nearest)
            .collect::<Vec<_>>();
        if targets.len() != 1 || !targets[0].0.contains(&summary.location.start.byte_offset) {
            return false;
        }
    } else if !imported && !callable.is_empty() {
        return false;
    }
    let declarations = index
        .declarations
        .get(head)
        .into_iter()
        .flatten()
        .filter(|(_, scope)| scope.0 <= at && at < scope.1)
        .collect::<Vec<_>>();
    declarations.len() <= 1
        && declarations.iter().all(|(range, _)| range.end <= at)
        && (declarations.is_empty() || !imported)
        && !index
            .writes
            .get(head)
            .into_iter()
            .flatten()
            .any(|w| w.range.start < at)
        && !callee
            .ancestors()
            .filter(|n| super::is_function_scope(n.kind().as_ref()))
            .any(|n| {
                index
                    .nested_binding_writes
                    .contains(&((n.range().start, n.range().end), head.to_string()))
            })
        && !callee
            .ancestors()
            .filter(|n| super::is_function_scope(n.kind().as_ref()))
            .filter_map(|n| n.field("parameters"))
            .any(|p| {
                p.dfs()
                    .any(|n| n.kind().as_ref() == "identifier" && n.text() == head)
            })
}
