//! Input-decoded distances collapsed before copying from output history.
use super::*;
use rust_allocation::method;
use rust_receiver_types::{lexical_binding, local_binding};
use rust_shared_state::{AstNode as N, compact, owns};

const RULE: &str = "rust-decoder-back-reference-review";

fn named<'a, 'n>(node: &'n N<'a>) -> impl Iterator<Item = N<'a>> + 'n {
    node.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
}

fn unwrap<'a>(mut node: N<'a>) -> Option<N<'a>> {
    for _ in 0..8 {
        node = match node.kind().as_ref() {
            "parenthesized_expression" | "try_expression" => named(&node).next()?,
            "reference_expression" | "type_cast_expression" => node.field("value")?,
            "unsafe_block" | "block" => {
                let mut children = named(&node);
                let child = children.next()?;
                if children.next().is_some() || child.kind().as_ref() == "expression_statement" {
                    return None;
                }
                child
            }
            _ => return Some(node),
        };
    }
    None
}

fn args<'a>(call: &N<'a>) -> Option<Vec<N<'a>>> {
    Some(named(&call.field("arguments")?).collect())
}

fn one_arg<'a>(call: &N<'a>) -> Option<N<'a>> {
    let [arg]: [_; 1] = args(call)?.try_into().ok()?;
    Some(arg)
}

fn same_binding<'a>(left: &N<'a>, right: &N<'a>, function: &N<'a>) -> bool {
    left.text() == right.text()
        && lexical_binding(left, function)
            .zip(lexical_binding(right, function))
            .is_some_and(|(a, b)| a.range() == b.range())
}

fn initializer<'a>(use_site: &N<'a>, function: &N<'a>) -> Option<(N<'a>, N<'a>)> {
    let binding = local_binding(use_site, function)?;
    let value = unwrap(binding.field("value")?)?;
    Some((binding, value))
}

// The bound must reject in the same block immediately before the adjustment.
// A debug assertion or a check inside a dictionary-only branch is insufficient.
fn adjacent_rejection<'a>(
    binding: &N<'a>,
    offset: &N<'a>,
    bound: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> bool {
    let Some(block) = binding.parent().filter(|n| n.kind().as_ref() == "block") else {
        return false;
    };
    let Some(previous) = named(&block)
        .take_while(|n| n.range().end <= binding.range().start)
        .last()
    else {
        return false;
    };
    let condition = if previous.kind().as_ref() == "expression_statement" {
        named(&previous).next()
    } else {
        Some(previous)
    };
    condition.is_some_and(|branch| {
        if branch.kind().as_ref() != "if_expression" || !enabled(&branch) {
            return false;
        }
        let Some(test) = branch.field("condition") else {
            return false;
        };
        let compare = |role: &str, value: &N<'_>| {
            test.field(role)
                .is_some_and(|n| compact(&n.text()) == compact(&value.text()))
        };
        let rejects = match test.field("operator").as_ref().map(|n| n.text()).as_deref() {
            Some(">") => compare("left", offset) && compare("right", bound),
            Some("<") => compare("left", bound) && compare("right", offset),
            _ => false,
        };
        rejects
            && branch
                .field("consequence")
                .and_then(|block| named(&block).next())
                .is_some_and(|node| {
                    let expression = if node.kind().as_ref() == "expression_statement" {
                        named(&node).next()
                    } else {
                        Some(node)
                    };
                    expression.is_some_and(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "return_expression" | "continue_expression" | "break_expression"
                        )
                    })
                })
    })
}

type Captures<'a> = Vec<(&'static str, N<'a>)>;

fn slice_copy<'a>(
    call: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<(N<'a>, Captures<'a>)> {
    let (output, name) = method(call)?;
    if !matches!(
        name.as_str(),
        "extend_from_within" | "extend_from_within_overlapping"
    ) {
        return None;
    }
    let start = args(call)?.into_iter().next()?;
    let (start_binding, adjustment) = initializer(&start, function)?;
    let (position, name) = method(&adjustment)?;
    if name != "saturating_sub" {
        return None;
    }
    let (receiver, position_method) = method(&position)?;
    if position_method != "pos"
        || !args(&position)?.is_empty()
        || !same_binding(&receiver, &output, function)
    {
        return None;
    }
    let owner = local_binding(&output, function)?;
    let ty = owner.field("type")?;
    if ty.kind().as_ref() != "reference_type"
        || !named(&ty).any(|n| n.kind().as_ref() == "mutable_specifier")
    {
        return None;
    }
    let offset = one_arg(&adjustment)?;
    if adjacent_rejection(&start_binding, &offset, &position, enabled) {
        return None;
    }
    Some((
        offset,
        vec![
            ("history_adjustment", adjustment),
            ("copy_start_binding", start_binding),
            ("initialized_prefix", position),
            ("output_binding", owner),
        ],
    ))
}

fn standard_copy<'a>(root: &N<'a>, call: &N<'a>) -> bool {
    rust_raw_memory::api(root, call).is_some_and(|api| {
        matches!(
            api.as_str(),
            "core::ptr::copy"
                | "core::ptr::copy_nonoverlapping"
                | "std::ptr::copy"
                | "std::ptr::copy_nonoverlapping"
        )
    })
}

fn local_function<'a>(
    call: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<N<'a>> {
    let callee = call
        .field("function")
        .filter(|n| n.kind().as_ref() == "identifier")?;
    let named_function = |n: &N<'a>| {
        n.kind().as_ref() == "function_item"
            && enabled(n)
            && n.field("name")
                .is_some_and(|name| name.text() == callee.text())
    };
    if lexical_binding(&callee, function).is_some()
        || callee
            .ancestors()
            .take_while(|n| n.range() != function.range())
            .any(|n| n.kind().as_ref() == "block" && named(&n).any(|item| named_function(&item)))
    {
        return None;
    }
    let module = function.parent().filter(|n| {
        n.kind().as_ref() == "source_file"
            || (n.kind().as_ref() == "declaration_list"
                && n.parent()
                    .is_some_and(|item| item.kind().as_ref() == "mod_item"))
    })?;
    let mut definitions = named(&module).filter(named_function);
    let definition = definitions.next()?;
    (definitions.next().is_none() && definition.range().len() <= 4096).then_some(definition)
}

fn raw_copy_arguments<'a>(
    root: &N<'a>,
    call: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<(N<'a>, N<'a>, Captures<'a>)> {
    let arguments = args(call)?;
    let [first, second, _count] = arguments.as_slice() else {
        return None;
    };
    if standard_copy(root, call) {
        return Some((first.clone(), second.clone(), Vec::new()));
    }
    if first.kind().as_ref() != "reference_expression"
        || !named(first).any(|n| n.kind().as_ref() == "mutable_specifier")
    {
        return None;
    }
    let helper = local_function(call, function, enabled)?;
    let params = helper.field("parameters")?;
    let mut params = named(&params);
    let destination = params.next()?;
    let source = params.next()?;
    if compact(&destination.field("type")?.text()) != "&mut*mutu8"
        || !matches!(
            compact(&source.field("type")?.text()).as_str(),
            "*constu8" | "*mutu8"
        )
    {
        return None;
    }
    let copy = helper.dfs().find(|node| {
        if !owns(node, &helper)
            || !enabled(node)
            || !standard_copy(root, node)
            || !rust_buffer_initialization::runtime_path(node, &helper)
        {
            return false;
        }
        let Some(arguments) = args(node) else {
            return false;
        };
        let [read, write, _] = arguments.as_slice() else {
            return false;
        };
        let dereferenced = write.kind().as_ref() == "unary_expression"
            && write.children().any(|n| n.text() == "*");
        dereferenced
            && named(write)
                .next()
                .and_then(|n| lexical_binding(&n, &helper))
                .is_some_and(|binding| binding.range() == destination.range())
            && lexical_binding(read, &helper)
                .is_some_and(|binding| binding.range() == source.range())
    })?;
    Some((
        second.clone(),
        unwrap(first.clone())?,
        vec![("history_copy_helper", helper), ("history_read", copy)],
    ))
}

fn raw_copy<'a>(
    root: &N<'a>,
    call: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<(N<'a>, Captures<'a>)> {
    let (source, destination, mut captures) = raw_copy_arguments(root, call, function, enabled)?;
    let (start_binding, start) = initializer(&source, function)?;
    let (cursor, name) = method(&start)?;
    if name != "sub" || !same_binding(&cursor, &destination, function) {
        return None;
    }
    let (offset_binding, adjustment) = initializer(&one_arg(&start)?, function)?;
    let (offset, name) = method(&adjustment)?;
    if name != "min" {
        return None;
    }
    let bound = one_arg(&adjustment)?;
    if bound.kind().as_ref() != "binary_expression" || bound.field("operator")?.text() != "+" {
        return None;
    }
    let prefix = bound.field("left")?;
    let dictionary = bound.field("right")?;
    let (_, name) = method(&dictionary)?;
    if name != "len" || !args(&dictionary)?.is_empty() {
        return None;
    }
    let (prefix_binding, position) = initializer(&prefix, function)?;
    let (prefix_cursor, name) = method(&position)?;
    if name != "offset_from" || !same_binding(&cursor, &prefix_cursor, function) {
        return None;
    }
    let (base_binding, base) = initializer(&one_arg(&position)?, function)?;
    let (_, name) = method(&base)?;
    if !matches!(name.as_str(), "as_mut_ptr" | "base_mut_ptr") || !args(&base)?.is_empty() {
        return None;
    }
    if adjacent_rejection(&offset_binding, &offset, &bound, enabled) {
        return None;
    }
    captures.extend([
        ("history_adjustment", adjustment),
        ("copy_start_binding", start_binding),
        ("initialized_prefix", prefix_binding),
        ("output_base_binding", base_binding),
        ("adjusted_offset_binding", offset_binding),
        ("dictionary_extent", dictionary),
    ]);
    Some((offset, captures))
}

fn input_parameter<'a>(mut source: N<'a>, function: &N<'a>) -> Option<N<'a>> {
    for _ in 0..8 {
        source = unwrap(source)?;
        source = match source.kind().as_ref() {
            "identifier" => {
                let binding = local_binding(&source, function)?;
                if binding.kind().as_ref() == "parameter" {
                    return (compact(&binding.field("type")?.text()) == "&[u8]").then_some(binding);
                }
                binding.field("value")?
            }
            "index_expression" => named(&source).next()?,
            "call_expression" => {
                let (receiver, name) = method(&source)?;
                if !matches!(name.as_str(), "try_into" | "unwrap") || !args(&source)?.is_empty() {
                    return None;
                }
                receiver
            }
            _ => return None,
        };
    }
    None
}

// Resolve a direct same-module byte decoder and keep the read itself as evidence.
fn decoded_offset<'a>(
    root: &N<'a>,
    offset: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<Captures<'a>> {
    let (binding, call) = initializer(offset, function)?;
    let decoder = local_function(&call, function, enabled)?;
    let input = named(&decoder.field("parameters")?).next()?;
    let ty = compact(&input.field("type")?.text());
    let raw = matches!(ty.as_str(), "&mut*constu8" | "&mut*mutu8");
    if !raw && ty != "&[u8]" {
        return None;
    }
    let tail = named(&decoder.field("body")?).last()?;
    let convert = if tail.field("function").is_some_and(|n| n.text() == "Ok") {
        one_arg(&tail)?
    } else {
        tail
    };
    let conversion = compact(&convert.field("function")?.text());
    if !rust_buffer_initialization::runtime_path(&convert, &decoder)
        || !(if raw {
            matches!(conversion.as_str(), "u16::from_le" | "u16::from_be")
        } else {
            matches!(
                conversion.as_str(),
                "u16::from_le_bytes" | "u16::from_be_bytes"
            )
        })
    {
        return None;
    }
    let actual = unwrap(args(&call)?.into_iter().next()?)?;
    let source = if raw {
        let pointer = lexical_binding(&actual, function)?;
        let (source, name) = method(&unwrap(pointer.field("value")?)?)?;
        if name != "as_ptr" {
            return None;
        }
        source
    } else {
        actual
    };
    let caller_input = input_parameter(source, function)?;
    let bytes = one_arg(&convert)?;
    let mut captures = vec![
        ("decoded_offset_binding", binding),
        ("offset_conversion", convert.clone()),
        ("input_parameter", caller_input),
    ];
    if raw {
        let input_name = input.field("pattern")?;
        let read = decoder.dfs().find(|node| {
            if node.range().end > convert.range().start
                || !owns(node, &decoder)
                || !enabled(node)
                || !rust_buffer_initialization::runtime_path(node, &decoder)
                || !rust_raw_memory::api(root, node).is_some_and(|api| {
                    matches!(
                        api.as_str(),
                        "core::ptr::copy_nonoverlapping" | "std::ptr::copy_nonoverlapping"
                    )
                })
            {
                return false;
            }
            let Some(arguments) = args(node) else {
                return false;
            };
            let [source, destination, count] = arguments.as_slice() else {
                return false;
            };
            compact(&source.text()) == format!("*{}", input_name.text())
                && count.text() == "2"
                && unwrap(destination.clone())
                    .is_some_and(|dest| same_binding(&dest, &bytes, &decoder))
        })?;
        captures.push(("offset_input_read", read));
    } else if rust_allocation::origin(&bytes, &decoder, 0)?.range() != input.range() {
        return None;
    }
    captures.push(("offset_decoder", decoder));
    Some(captures)
}

pub(super) fn groups(
    sources: &RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    for file in sources.files.values().filter(|f| {
        f.language == Some(Language::Rust)
            && ((f.source.contains("saturating_sub") && f.source.contains("extend_from_within"))
                || (f.source.contains(".min") && f.source.contains("offset_from")))
    }) {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        let enabled = |n: &N<'_>| !selection.excluded(&file.path, n.range());
        for call in root
            .dfs()
            .filter(|n| n.kind().as_ref() == "call_expression" && enabled(n))
        {
            let Some(function) = call
                .ancestors()
                .find(|n| matches!(n.kind().as_ref(), "function_item" | "closure_expression"))
            else {
                continue;
            };
            if function.kind().as_ref() != "function_item" || function.range().len() > 32768 {
                continue;
            }
            let Some((offset, mut captures)) = slice_copy(&call, &function, &enabled)
                .or_else(|| raw_copy(&root, &call, &function, &enabled))
            else {
                continue;
            };
            if function.dfs().any(|n| n.is_error() || n.is_missing())
                || !rust_buffer_initialization::runtime_path(&call, &function)
            {
                continue;
            }
            let Some(decoder) = decoded_offset(&root, &offset, &function, &enabled) else {
                continue;
            };
            captures.extend(decoder);
            if captures.iter().any(|(_, node)| !enabled(node)) {
                continue;
            }
            let copy = rust_dependencies::capture(file, &call);
            let location = copy.location.clone();
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            let id =
                review_admission_marker_id(&file.path, RULE, call.range().start, call.range().end);
            let symbol = function
                .field("name")
                .map(|n| n.text().into_owned())
                .unwrap_or_default();
            let captures = captures
                .into_iter()
                .map(|(name, node)| (name.into(), rust_dependencies::capture(file, &node)))
                .chain([
                    ("history_copy".into(), copy),
                    (
                        "decoder_definition".into(),
                        rust_dependencies::capture(file, &function),
                    ),
                ])
                .collect();
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
                    capability: Capability::RustRawMemoryReview,
                    location,
                    enclosing_symbol: Some(symbol),
                    captures,
                    cwe_candidates: vec!["CWE-125".into(), "CWE-200".into()],
                    tags: vec![
                        "review-admission-marker".into(),
                        "rust-back-reference-obligation".into(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded Rust decoder output history".into(),
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
