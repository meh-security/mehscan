//! Bounded source witnesses for data-selected traversal with repeated growth.
use super::*;
use rust_parser_provenance::{
    arguments, declared_type, enclosing_function, literal, named, peel, same_binding, scope,
    slice_type, tuple_type, unique, vector,
};
use rust_receiver_types::{lexical_binding, local_binding};
use rust_shared_state::AstNode as N;

pub(super) const RULE: &str = "rust-input-chain-growth-review";

fn statement<'a>(node: N<'a>) -> N<'a> {
    if node.kind().as_ref() == "expression_statement" {
        return named(&node).next().unwrap_or_else(|| node.clone());
    }
    node
}

fn bound_cursor<'a>(value: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let binding = lexical_binding(value, function)?;
    let mutable = binding
        .children()
        .any(|n| n.kind().as_ref() == "mutable_specifier");
    mutable.then_some(binding)
}

fn read_parameter<'a>(root: &N<'a>, value: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let parameter = local_binding(value, function).filter(|n| n.kind().as_ref() == "parameter")?;
    let ty = parameter.field("type")?;
    let referent = ty
        .field("type")
        .filter(|_| ty.kind().as_ref() == "reference_type")
        .unwrap_or(ty);
    let read = |n: &N<'a>| {
        rust_raw_memory::canonical(root, n, &n.text()).as_deref() == Some("std::io::Read")
    };
    if referent.dfs().any(|n| read(&n)) {
        return Some(parameter);
    }
    function
        .field("type_parameters")?
        .children()
        .any(|param| {
            param
                .field("name")
                .is_some_and(|n| n.text() == referent.text())
                && param.dfs().any(|n| read(&n))
        })
        .then_some(parameter)
}

fn buffer_witness<'a>(
    root: &N<'a>,
    buffer: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
    local_globs: &impl Fn(&N<'a>) -> Option<Vec<Capture>>,
) -> Option<(N<'a>, Vec<Capture>)> {
    let binding = lexical_binding(buffer, function).filter(enabled)?;
    if let Some((ty, declaration)) = declared_type(buffer.clone(), function, enabled, 0)
        .or_else(|| tuple_type(buffer, function, enabled))
        && let Some((_, support)) = vector(root, &ty, local_globs)
    {
        return Some((declaration, support));
    }
    let initializer = binding.field("value").and_then(peel)?;
    rust_raw_memory::api(root, &initializer)
        .is_some_and(|api| {
            matches!(
                api.as_str(),
                "std::vec::Vec::new"
                    | "alloc::vec::Vec::new"
                    | "std::vec::Vec::with_capacity"
                    | "alloc::vec::Vec::with_capacity"
            )
        })
        .then_some((binding, Vec::new()))
}

fn input_and_next<'a>(
    root: &N<'a>,
    update: &N<'a>,
    cursor: &N<'a>,
    buffer: &N<'a>,
    growth: &N<'a>,
    function: &N<'a>,
) -> Option<N<'a>> {
    let next = peel(update.field("right")?)?;
    if next.kind().as_ref() == "index_expression" {
        let table = named(&next).next()?;
        let index = peel(named(&next).nth(1)?)?;
        if !same_binding(&index, cursor, function) {
            return None;
        }
        let parameter =
            local_binding(&table, function).filter(|n| n.kind().as_ref() == "parameter")?;
        let slice = slice_type(&parameter.field("type")?)?;
        let element = slice.field("element").or_else(|| slice.field("type"))?;
        if !matches!(
            element.text().as_ref(),
            "u8" | "u16" | "u32" | "u64" | "usize"
        ) {
            return None;
        }
        return Some(parameter);
    }
    let (pop, name) = rust_allocation::method(&next)?;
    let pop = if matches!(name.as_str(), "unwrap" | "expect" | "ok_or" | "ok_or_else") {
        pop
    } else {
        next
    };
    let (receiver, name) = rust_allocation::method(&pop)?;
    if name != "pop" || !arguments(&pop)?.is_empty() || !same_binding(&receiver, buffer, function) {
        return None;
    }
    // Bind the same cursor and a typed reader to one input-reading call that
    // supplies the appended data. Names of project reader helpers are immaterial.
    growth
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
        .find_map(|read| {
            let args = arguments(&read)?;
            if !args
                .iter()
                .any(|a| peel(a.clone()).is_some_and(|a| same_binding(&a, cursor, function)))
            {
                return None;
            }
            args.into_iter()
                .filter_map(peel)
                .find_map(|a| read_parameter(root, &a, function))
        })
}

fn exits(branch: &N<'_>) -> bool {
    branch
        .field("consequence")
        .and_then(|body| named(&body).next())
        .map(statement)
        .is_some_and(|n| matches!(n.kind().as_ref(), "return_expression" | "break_expression"))
}

fn divisor_minimum<'a>(
    divisor: N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<usize> {
    if let Some(n) = literal(&divisor) {
        return Some(n);
    }
    let cast = local_binding(&divisor, function)
        .filter(|n| enabled(n) && !named(n).any(|n| n.kind().as_ref() == "mutable_specifier"))?
        .field("value")?;
    if cast.kind().as_ref() != "type_cast_expression" || cast.field("type")?.text() != "usize" {
        return None;
    }
    let field = cast.field("value")?;
    if field.kind().as_ref() != "field_expression" {
        return None;
    }
    let receiver = field.field("value")?;
    let (owner, _) = declared_type(receiver.clone(), function, enabled, 0)
        .or_else(|| tuple_type(&receiver, function, enabled))?;
    let module = scope(function)?;
    let named_item = |kind: &str, name: &str| {
        unique(named(&module).filter(|n| {
            n.kind().as_ref() == kind
                && enabled(n)
                && n.field("name").is_some_and(|n| n.text() == name)
        }))
    };
    let record = named_item("struct_item", &owner.text())?;
    let member = field.field("field")?;
    let fields = record.field("body")?;
    let member = unique(
        named(&fields)
            .filter(|n| enabled(n) && n.field("name").is_some_and(|n| n.text() == member.text())),
    )?;
    let enumeration = named_item("enum_item", &member.field("type")?.text())?;
    let variants = enumeration.field("body")?;
    named(&variants)
        .map(|variant| literal(&variant.field("value")?).filter(|value| *value <= u16::MAX.into()))
        .try_fold(usize::MAX, |min, value| Some(min.min(value?)))
}

// Prove an architecture-independent gap below usize::MAX for a strict
// counter comparison. Dividing an input extent by at least two leaves room.
fn finite_bound<'a>(
    bound: N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
    slack: usize,
    depth: usize,
) -> bool {
    if depth > 6 || !enabled(&bound) {
        return false;
    }
    if let Some(value) = literal(&bound) {
        return value
            .checked_add(slack)
            .is_some_and(|n| n < i8::MAX as usize);
    }
    if bound.kind().as_ref() == "identifier" {
        return local_binding(&bound, function)
            .filter(|n| enabled(n) && !named(n).any(|n| n.kind().as_ref() == "mutable_specifier"))
            .and_then(|n| n.field("value"))
            .is_some_and(|value| finite_bound(value, function, enabled, slack, depth + 1));
    }
    if let Some((base, method)) = rust_allocation::method(&bound) {
        return method == "saturating_add"
            && arguments(&bound)
                .and_then(|args| {
                    let [arg]: [_; 1] = args.try_into().ok()?;
                    slack.checked_add(literal(&arg)?)
                })
                .is_some_and(|slack| finite_bound(base, function, enabled, slack, depth + 1));
    }
    bound.kind().as_ref() == "binary_expression"
        && bound.field("operator").is_some_and(|n| n.text() == "/")
        && slack < usize::from(u16::MAX) / 2
        && bound
            .field("left")
            .and_then(|n| declared_type(n, function, enabled, 0))
            .is_some_and(|(ty, _)| ty.text() == "usize")
        && bound
            .field("right")
            .and_then(|n| divisor_minimum(n, function, enabled))
            .is_some_and(|n| n >= 2)
}

fn counted_exit<'a>(
    steps: &[N<'a>],
    growth: &N<'a>,
    loop_node: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> bool {
    steps
        .iter()
        .filter(|node| {
            node.range().end <= growth.range().start
                && enabled(node)
                && node.kind().as_ref() == "if_expression"
                && exits(node)
        })
        .any(|branch| {
            let Some(condition) = branch.field("condition") else {
                return false;
            };
            let (Some(counter), Some(bound), Some(operator)) = (
                condition.field("left"),
                condition.field("right"),
                condition.field("operator"),
            ) else {
                return false;
            };
            if !matches!(operator.text().as_ref(), ">" | ">=")
                || !finite_bound(bound, function, enabled, 0, 0)
            {
                return false;
            }
            let Some(binding) = bound_cursor(&counter, function).filter(enabled) else {
                return false;
            };
            if binding.range().end > loop_node.range().start
                || binding.field("value").as_ref().and_then(literal) != Some(0)
                || binding.field("type").is_some_and(|ty| ty.text() != "usize")
            {
                return false;
            }
            let Some(increment) = unique(steps.iter().filter(|n| {
                n.range().end <= branch.range().start
                    && enabled(n)
                    && n.kind().as_ref() == "compound_assignment_expr"
                    && n.field("operator").is_some_and(|n| n.text() == "+=")
                    && n.field("right").as_ref().and_then(literal) == Some(1)
                    && n.field("left")
                        .is_some_and(|n| same_binding(&n, &counter, function))
            })) else {
                return false;
            };
            if steps.iter().any(|n| {
                n.range().start >= increment.range().end
                    && n.range().end <= branch.range().start
                    && n.kind().as_ref() != "empty_statement"
            }) {
                return false;
            }
            !function
                .dfs()
                .filter(|n| {
                    n.range().start >= binding.range().end
                        && n.range().end <= loop_node.range().end
                        && n.range() != increment.range()
                })
                .any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "assignment_expression" | "compound_assignment_expr"
                    ) && n
                        .field("left")
                        .is_some_and(|n| same_binding(&n, &counter, function))
                        || n.kind().as_ref() == "reference_expression"
                            && named(&n).any(|n| n.kind().as_ref() == "mutable_specifier")
                            && n.field("value")
                                .is_some_and(|n| same_binding(&n, &counter, function))
                })
        })
}

fn repeated_cursor_exit<'a>(
    root: &N<'a>,
    steps: &[N<'a>],
    growth: &N<'a>,
    loop_node: &N<'a>,
    cursor: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> bool {
    steps
        .iter()
        .take_while(|n| n.range().end <= growth.range().start)
        .filter(|n| n.kind().as_ref() == "if_expression" && enabled(n) && exits(n))
        .any(|branch| {
            let Some(test) = branch.field("condition") else {
                return false;
            };
            if test.kind().as_ref() != "unary_expression"
                || !test.children().any(|n| n.text() == "!")
            {
                return false;
            }
            let Some(insert) = named(&test).next() else {
                return false;
            };
            let Some((set, method)) = rust_allocation::method(&insert) else {
                return false;
            };
            let Some([key]) = arguments(&insert).and_then(|args| <[_; 1]>::try_from(args).ok())
            else {
                return false;
            };
            if method != "insert" || !same_binding(&key, cursor, function) {
                return false;
            }
            let Some(binding) = local_binding(&set, function).filter(enabled) else {
                return false;
            };
            let Some(initial) = binding.field("value") else {
                return false;
            };
            if binding.range().end > loop_node.range().start
                || !rust_raw_memory::api(root, &initial).is_some_and(|api| {
                    matches!(
                        api.as_str(),
                        "std::collections::HashSet::new"
                            | "std::collections::BTreeSet::new"
                            | "alloc::collections::BTreeSet::new"
                    )
                })
            {
                return false;
            }
            // Other uses can clear, replace or hand off the set between steps.
            !loop_node.dfs().any(|n| {
                n.range() != set.range()
                    && n.kind().as_ref() == "identifier"
                    && same_binding(&n, &set, function)
            })
        })
}

pub(super) fn groups<'a>(
    file: &'a SourceFile,
    root: &N<'a>,
    scope: Option<&mehscan_core::ImpactScanScope>,
    enabled: &impl Fn(&N<'a>) -> bool,
    local_globs: &impl Fn(&N<'a>) -> Option<Vec<Capture>>,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    if !file.source.contains("while") || !file.source.contains(".extend") {
        return groups;
    }
    for loop_node in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "while_expression" && enabled(n))
    {
        let Some(function) = enclosing_function(&loop_node) else {
            continue;
        };
        if !rust_shared_state::owns(&loop_node, &function)
            || function.range().len() > 32768
            || !rust_buffer_initialization::runtime_path(&loop_node, &function)
        {
            continue;
        }
        let Some(condition) = loop_node.field("condition") else {
            continue;
        };
        if !condition
            .field("operator")
            .is_some_and(|n| matches!(n.text().as_ref(), "<" | "!="))
        {
            continue;
        }
        let Some(cursor) = condition.field("left") else {
            continue;
        };
        let Some(cursor_binding) = bound_cursor(&cursor, &function).filter(enabled) else {
            continue;
        };
        let Some(body) = loop_node.field("body") else {
            continue;
        };
        let steps = named(&body).map(statement).collect::<Vec<_>>();
        let Some(update) = unique(steps.iter().filter(|n| {
            enabled(n)
                && n.kind().as_ref() == "assignment_expression"
                && n.field("left")
                    .is_some_and(|left| same_binding(&left, &cursor, &function))
        })) else {
            continue;
        };
        for growth in steps
            .iter()
            .take_while(|node| node.range().end <= update.range().start)
            .filter(|node| enabled(node))
        {
            let Some((buffer, method)) = rust_allocation::method(growth) else {
                continue;
            };
            if !matches!(method.as_str(), "extend" | "extend_from_slice") {
                continue;
            }
            let Some((declaration, support)) =
                buffer_witness(root, &buffer, &function, enabled, local_globs)
            else {
                continue;
            };
            let Some(input) =
                input_and_next(root, update, &cursor, &buffer, growth, &function).filter(enabled)
            else {
                continue;
            };
            if function.dfs().any(|n| n.is_error() || n.is_missing())
                || !rust_buffer_initialization::runtime_path(growth, &function)
                || counted_exit(&steps, growth, &loop_node, &function, enabled)
                || repeated_cursor_exit(
                    root, &steps, growth, &loop_node, &cursor, &function, enabled,
                )
            {
                continue;
            }
            let operation = rust_dependencies::capture(file, growth);
            let location = operation.location.clone();
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            let id = review_admission_marker_id(
                &file.path,
                RULE,
                growth.range().start,
                growth.range().end,
            );
            let symbol = function
                .field("name")
                .map(|n| n.text().into_owned())
                .unwrap_or_default();
            let mut captures = BTreeMap::from([("chain_growth".into(), operation)]);
            for (role, node) in [
                ("chain_loop", &loop_node),
                ("cursor_binding", &cursor_binding),
                ("next_cursor", update),
                ("buffer_declaration", &declaration),
                ("input_parameter", &input),
                ("parser_definition", &function),
            ] {
                captures.insert(role.into(), rust_dependencies::capture(file, node));
            }
            for (index, capture) in support.into_iter().enumerate() {
                captures.insert(format!("buffer_type_support_{index:02}"), capture);
            }
            groups.push(ObservationGroup {
                path: file.path.clone(),
                symbol: symbol.clone(),
                anchor_evidence_ids: vec![id.clone()],
                priority: 1,
                review_material: is_review_material_path(&file.path),
                evidence: vec![Evidence {
                    id,
                    rule_id: RULE.into(),
                    kind: EvidenceKind::SensitiveOperation,
                    capability: Capability::RustParserResourceReview,
                    location,
                    enclosing_symbol: Some(symbol),
                    captures,
                    cwe_candidates: vec!["CWE-400".into(), "CWE-835".into()],
                    tags: vec!["review-admission-marker".into()],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded Rust input-selected chain and repeated growth".into(),
                        rule_version: 1,
                    },
                    context: EvidenceContext::default(),
                    symbol_resolution: None,
                    related_evidence: vec![],
                }],
            });
        }
    }
    groups
}
