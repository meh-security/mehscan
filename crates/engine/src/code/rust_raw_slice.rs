//! Concrete null-state to raw-slice relationships, without expanding macros.
use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind,
    Language, Provenance, Resolution, SecurityPath, SecurityPathProvenance, SecurityPathState,
    SecurityPathStep, SecurityPathStepKind,
};

use super::{
    comments::CommentRanges, conditional::ConditionalRegions, context::enclosing_symbol,
    literals::LiteralEnvironment, reachability, rust_http,
};

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const ENGINE: &str = "tree-sitter rust raw-slice non-null relationship";

struct NullState<'a> {
    owner: String,
    field: String,
    origin: N<'a>,
    constructor: N<'a>,
    binding: Option<N<'a>>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_observations<'a>(
    path: &str,
    root: &N<'a>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) -> Vec<SecurityPath> {
    if language != Language::Rust || !root.text().contains("from_raw_parts") {
        return vec![];
    }
    let states = null_states(path, root, conditional);
    if states.is_empty() {
        return vec![];
    }
    let mut paths = Vec::new();
    let mut emitted = evidence
        .iter()
        .map(|e| e.id.clone())
        .collect::<BTreeSet<_>>();
    for call in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        let Some(function) = call.field("function") else {
            continue;
        };
        let Some((name, slice_import)) = function_identity(root, &call) else {
            continue;
        };
        if !matches!(
            name.as_str(),
            "std::slice::from_raw_parts"
                | "std::slice::from_raw_parts_mut"
                | "core::slice::from_raw_parts"
                | "core::slice::from_raw_parts_mut"
        ) {
            continue;
        }
        if !complete(&call, conditional) || comments.is_in_comment(call.range()) {
            continue;
        }
        let Some(accessor) = call
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_item")
        else {
            continue;
        };
        if unsafe_function(&accessor) {
            continue;
        }
        let Some(owner) = accessor
            .ancestors()
            .find(|n| n.kind().as_ref() == "impl_item")
        else {
            continue;
        };
        if owner.field("type_parameters").is_some() {
            continue;
        }
        let Some(ty) = owner.field("type") else {
            continue;
        };
        let Some(owner_key) = type_key(path, root, &ty, ty.text().as_ref()) else {
            continue;
        };
        let arguments = args(&call);
        if arguments.len() != 2 {
            continue;
        }
        let pointer = strip_cast(arguments[0].clone());
        let observed = compact(pointer.text().as_ref());
        let Some(field) = observed.strip_prefix("self.") else {
            continue;
        };
        if !field.split('.').all(super::rust_context::is_identifier) {
            continue;
        }
        if accessor
            .dfs()
            .filter(|n| n.range().start < call.range().start)
            .filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "assignment_expression" | "compound_assignment_expr"
                )
            })
            .filter(|n| {
                !n.ancestors()
                    .take_while(|a| a.range() != accessor.range())
                    .any(|a| {
                        matches!(
                            a.kind().as_ref(),
                            "if_expression"
                                | "match_expression"
                                | "for_expression"
                                | "while_expression"
                                | "loop_expression"
                                | "closure_expression"
                                | "function_item"
                        )
                    })
            })
            .filter_map(|n| n.field("left"))
            .any(|left| {
                let left = compact(left.text().as_ref());
                observed == left || observed.starts_with(&format!("{left}."))
            })
        {
            continue;
        }
        for state in states
            .iter()
            .filter(|s| s.owner == owner_key && s.field == field)
        {
            // A field state is a possible safe-constructor result, not proof
            // that every caller uses it or that an arbitrary FFI call returns.
            let mut source_captures = BTreeMap::from([
                ("null_pointer".into(), capture(path, &state.origin)),
                ("safe_constructor".into(), capture(path, &state.constructor)),
            ]);
            if let Some(binding) = &state.binding {
                source_captures.insert("field_transfer".into(), capture(path, binding));
            }
            if let Some((_, Some(import))) = function_identity(root, &state.origin) {
                source_captures.insert("null_api_import".into(), capture(path, &import));
            }
            let fact = |node: &N<'a>, rule: &str, kind, capability, captures, related| Evidence {
                id: id(
                    "ev",
                    &format!(
                        "{path}\0{rule}\0{}\0{}",
                        node.range().start,
                        state.origin.range().start
                    ),
                ),
                kind,
                capability,
                location: super::matcher::location(path, node),
                enclosing_symbol: enclosing_symbol(node),
                captures,
                cwe_candidates: vec!["CWE-476".into()],
                tags: vec![
                    "rust".into(),
                    "raw-slice-non-null".into(),
                    "invariant:non-null-only".into(),
                    "initial-state:possible-not-executed".into(),
                    "parse-recovery:locally-complete".into(),
                ],
                confidence: Confidence::High,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: ENGINE.into(),
                    rule_version: 1,
                },
                context: EvidenceContext {
                    comment: comments.is_in_comment(node.range()),
                    reachability: Some(reachability::classify(node, literals)),
                    availability: Some(conditional.availability_for(node.range())),
                    ..Default::default()
                },
                symbol_resolution: None,
                rule_id: rule.into(),
                related_evidence: related,
            };
            let source = fact(
                &state.origin,
                "rust-null-initialized-slice-field",
                EvidenceKind::Source,
                Capability::RawNullPointerState,
                source_captures,
                vec![],
            );
            let guard = nonnull_guard(&accessor, &call, &observed, conditional);
            let protection = guard.map(|guard| {
                fact(
                    &guard,
                    "rust-raw-slice-non-null-validation",
                    EvidenceKind::Validation,
                    Capability::RawSliceNonNullValidation,
                    BTreeMap::from([("non_null_check".into(), capture(path, &guard))]),
                    vec![source.id.clone()],
                )
            });
            let mut related = vec![source.id.clone()];
            if let Some(p) = &protection {
                related.push(p.id.clone());
            }
            let mut sink_captures = BTreeMap::from([
                ("pointer".into(), capture(path, &arguments[0])),
                ("length".into(), capture(path, &arguments[1])),
                ("safe_accessor".into(), capture(path, &accessor)),
                ("owner_type".into(), capture(path, &ty)),
                ("slice_function".into(), capture(path, &function)),
            ]);
            if let Some(import) = &slice_import {
                sink_captures.insert("slice_api_import".into(), capture(path, import));
            }
            let sink = fact(
                &call,
                "rust-nullable-field-raw-slice",
                EvidenceKind::Sink,
                Capability::RustRawSliceConstruction,
                sink_captures,
                related,
            );
            let state = if protection.is_some() {
                SecurityPathState::Protected
            } else {
                SecurityPathState::Unknown
            };
            let mut steps = vec![step(SecurityPathStepKind::Source, &source)];
            if let Some(p) = &protection {
                steps.push(step(SecurityPathStepKind::Protection, p));
            }
            steps.push(step(SecurityPathStepKind::Sink, &sink));
            paths.push(SecurityPath {
                id: id("path", &format!("{}\0{}\0{state:?}", source.id, sink.id)),
                source_evidence_id: source.id.clone(),
                sink_evidence_id: sink.id.clone(),
                capability: Capability::RustRawSliceConstruction,
                cwe_candidates: vec!["CWE-476".into()],
                state,
                steps,
                protection_evidence_ids: protection
                    .as_ref()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default(),
                uncertainty_reasons: if state == SecurityPathState::Unknown {
                    vec![
                        "possible_null_safe_state_reaches_raw_slice".into(),
                        "constructor_to_accessor_runtime_applicability_requires_review".into(),
                    ]
                } else {
                    vec![]
                },
                provenance: SecurityPathProvenance {
                    engine: "mehscan rust raw-slice non-null relationship 1".into(),
                    maximum_propagation_depth: 2,
                },
            });
            for fact in [Some(source), Some(sink), protection].into_iter().flatten() {
                if emitted.insert(fact.id.clone()) {
                    evidence.push(fact);
                }
            }
        }
    }
    paths
}

fn null_states<'a>(
    path: &str,
    root: &N<'a>,
    conditional: &ConditionalRegions,
) -> Vec<NullState<'a>> {
    let mut states = Vec::new();
    for function in root.dfs().filter(|n| n.kind().as_ref() == "function_item") {
        if unsafe_function(&function) || !complete(&function, conditional) {
            continue;
        }
        let Some(owner) = function
            .ancestors()
            .find(|n| n.kind().as_ref() == "impl_item")
        else {
            continue;
        };
        if owner.field("trait").is_some() || owner.field("type_parameters").is_some() {
            continue;
        }
        let Some(ty) = owner.field("type") else {
            continue;
        };
        let Some(key) = type_key(path, root, &ty, ty.text().as_ref()) else {
            continue;
        };
        let Some(ret) = function.field("return_type") else {
            continue;
        };
        if compact(ret.text().as_ref()) != "Self"
            && type_key(path, root, &ret, ret.text().as_ref()).as_ref() != Some(&key)
        {
            continue;
        }
        let Some(returned) = function.field("body").and_then(tail) else {
            continue;
        };
        if returned.kind().as_ref() == "struct_expression" {
            let Some(created) = returned.field("name") else {
                continue;
            };
            if compact(created.text().as_ref()) != "Self"
                && type_key(path, root, &created, created.text().as_ref()).as_ref() != Some(&key)
            {
                continue;
            }
            for (field, value) in fields(&returned) {
                if is_null(root, &value) {
                    states.push(NullState {
                        owner: key.clone(),
                        field,
                        origin: value,
                        constructor: function.clone(),
                        binding: None,
                    });
                }
            }
            continue;
        }
        if returned.kind().as_ref() != "call_expression" {
            continue;
        }
        let arguments = args(&returned);
        if arguments.len() != 1 {
            continue;
        }
        let Some(callee) = returned.field("function") else {
            continue;
        };
        let Some((callee_name, _)) = rust_http::canonical(root, &callee, callee.text().as_ref())
        else {
            continue;
        };
        let Some((trait_name, method_name)) = callee_name.rsplit_once("::") else {
            continue;
        };
        let value = strip_cast(arguments[0].clone());
        let Some(raw) = value
            .field("value")
            .filter(|_| value.kind().as_ref() == "reference_expression")
        else {
            continue;
        };
        if raw.kind().as_ref() != "struct_expression" {
            continue;
        }
        let Some(raw_type) = raw.field("name") else {
            continue;
        };
        let Some(raw_key) = type_key(path, root, &raw_type, raw_type.text().as_ref()) else {
            continue;
        };
        let bindings = root
            .dfs()
            .filter(|n| n.kind().as_ref() == "impl_item")
            .filter(|n| n.field("type_parameters").is_none())
            .filter(|n| {
                n.field("type")
                    .and_then(|t| type_key(path, root, &t, t.text().as_ref()))
                    .as_ref()
                    == Some(&key)
            })
            .filter(|n| {
                n.field("trait")
                    .and_then(|t| rust_http::canonical(root, &t, t.text().as_ref()))
                    .is_some_and(|(name, _)| name == trait_name)
            })
            .flat_map(|n| {
                n.field("body")
                    .into_iter()
                    .flat_map(|b| b.children().collect::<Vec<_>>())
            })
            .filter(|n| {
                n.kind().as_ref() == "function_item"
                    && n.field("name")
                        .is_some_and(|name| name.text().as_ref() == method_name)
            })
            .collect::<Vec<_>>();
        if bindings.len() != 1 || !complete(&bindings[0], conditional) {
            continue;
        }
        let binding = &bindings[0];
        let params = binding
            .field("parameters")
            .into_iter()
            .flat_map(|p| p.children().collect::<Vec<_>>())
            .filter(|n| n.kind().as_ref() == "parameter")
            .collect::<Vec<_>>();
        if params.len() != 1 {
            continue;
        }
        let (Some(param), Some(param_type)) = (params[0].field("pattern"), params[0].field("type"))
        else {
            continue;
        };
        if param.kind().as_ref() != "identifier" || param_type.kind().as_ref() != "pointer_type" {
            continue;
        }
        let Some(pointee) = param_type.field("type") else {
            continue;
        };
        if type_key(path, root, &pointee, pointee.text().as_ref()).as_ref() != Some(&raw_key) {
            continue;
        }
        let Some(body) = binding.field("body") else {
            continue;
        };
        let statements = body
            .children()
            .filter(|n| n.is_named() && !n.kind().contains("comment"))
            .collect::<Vec<_>>();
        if statements.len() != 1 {
            continue;
        }
        let Some(wrapped) = tail(body) else { continue };
        if wrapped.kind().as_ref() != "struct_expression" {
            continue;
        }
        let Some(wrapped_type) = wrapped.field("name") else {
            continue;
        };
        if compact(wrapped_type.text().as_ref()) != "Self"
            && type_key(path, root, &wrapped_type, wrapped_type.text().as_ref()).as_ref()
                != Some(&key)
        {
            continue;
        }
        for (outer, value) in fields(&wrapped) {
            if compact(value.text().as_ref()) != format!("*{}", param.text()) {
                continue;
            }
            for (inner, value) in fields(&raw) {
                if is_null(root, &value) {
                    states.push(NullState {
                        owner: key.clone(),
                        field: format!("{outer}.{inner}"),
                        origin: value,
                        constructor: function.clone(),
                        binding: binding
                            .ancestors()
                            .find(|n| n.kind().as_ref() == "impl_item"),
                    });
                }
            }
        }
    }
    states
}

fn nonnull_guard<'a>(
    function: &N<'a>,
    call: &N<'a>,
    pointer: &str,
    conditional: &ConditionalRegions,
) -> Option<N<'a>> {
    for statement in function
        .dfs()
        .filter(|n| n.kind().as_ref() == "if_expression")
    {
        let Some(condition) = statement.field("condition") else {
            continue;
        };
        if compact(condition.text().as_ref()) != format!("{pointer}.is_null()") {
            continue;
        }
        let Some(branch) = statement.field("consequence") else {
            continue;
        };
        if statement.range().end >= call.range().start || !complete(&statement, conditional) {
            continue;
        }
        // Restrict to an unconditional same-block rejecting guard. A length
        // check or an unexpanded macro is not a non-null proof.
        let parent = statement.parent().and_then(|n| {
            if n.kind().as_ref() == "expression_statement" {
                n.parent()
            } else {
                Some(n)
            }
        });
        if parent.as_ref().map(|n| n.range())
            != call
                .ancestors()
                .find(|n| n.kind().as_ref() == "block" && n.range().start < statement.range().start)
                .map(|n| n.range())
        {
            continue;
        }
        if call
            .ancestors()
            .take_while(|n| parent.as_ref().is_none_or(|p| p.range() != n.range()))
            .any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "loop_expression"
                        | "while_expression"
                        | "for_expression"
                        | "closure_expression"
                        | "function_item"
                )
            })
        {
            continue;
        }
        let Some(mut last) = branch
            .children()
            .filter(|n| n.is_named() && !n.kind().contains("comment"))
            .last()
        else {
            continue;
        };
        if last.kind().as_ref() == "expression_statement" {
            let Some(expression) = last.children().find(|n| n.is_named()) else {
                continue;
            };
            last = expression;
        }
        if last.kind().as_ref() != "return_expression" {
            continue;
        }
        if function
            .dfs()
            .filter(|n| {
                condition.range().end < n.range().start && n.range().end < call.range().start
            })
            .any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "assignment_expression"
                        | "compound_assignment_expr"
                        | "call_expression"
                        | "macro_invocation"
                )
            })
        {
            continue;
        }
        return Some(condition);
    }
    None
}

fn type_key<'a>(path: &str, root: &N<'a>, site: &N<'a>, name: &str) -> Option<String> {
    let (name, _) = rust_http::canonical(root, site, name)?;
    Some(rust_http::local_key(path, site, &name))
}
fn complete(node: &N<'_>, conditional: &ConditionalRegions) -> bool {
    conditional.availability_for(node.range()).state == AvailabilityState::Always
        && !node.dfs().any(|n| n.kind().as_ref() == "ERROR")
}
fn unsafe_function(node: &N<'_>) -> bool {
    node.children()
        .filter(|n| n.kind().as_ref() == "function_modifiers")
        .any(|n| n.text().split_whitespace().any(|s| s == "unsafe"))
}
fn tail(mut node: N<'_>) -> Option<N<'_>> {
    loop {
        node = match node.kind().as_ref() {
            "block" => node
                .children()
                .filter(|n| n.is_named() && !n.kind().contains("comment"))
                .last()?,
            "unsafe_block" | "return_expression" => node.children().find(|n| n.is_named())?,
            "expression_statement" if !node.text().trim_end().ends_with(';') => {
                node.children().find(|n| n.is_named())?
            }
            _ => return Some(node),
        };
    }
}
fn strip_cast(mut node: N<'_>) -> N<'_> {
    while matches!(
        node.kind().as_ref(),
        "type_cast_expression" | "parenthesized_expression"
    ) {
        let Some(value) = node
            .field("value")
            .or_else(|| node.children().find(|n| n.is_named()))
        else {
            break;
        };
        node = value;
    }
    node
}
fn fields<'a>(node: &N<'a>) -> Vec<(String, N<'a>)> {
    node.field("body")
        .into_iter()
        .flat_map(|b| b.children().collect::<Vec<_>>())
        .filter(|n| n.kind().as_ref() == "field_initializer")
        .filter_map(|n| Some((n.field("field")?.text().into_owned(), n.field("value")?)))
        .collect()
}
fn args<'a>(call: &N<'a>) -> Vec<N<'a>> {
    call.field("arguments")
        .into_iter()
        .flat_map(|n| n.children().collect::<Vec<_>>())
        .filter(|n| n.is_named())
        .collect()
}
fn is_null<'a>(root: &N<'a>, node: &N<'a>) -> bool {
    if node.kind().as_ref() != "call_expression" || !args(node).is_empty() {
        return false;
    }
    function_identity(root, node).is_some_and(|(name, _)| {
        matches!(
            name.as_str(),
            "std::ptr::null" | "std::ptr::null_mut" | "core::ptr::null" | "core::ptr::null_mut"
        )
    })
}
pub(crate) fn function_identity<'a>(root: &N<'a>, call: &N<'a>) -> Option<(String, Option<N<'a>>)> {
    let mut function = call.field("function")?;
    if function.kind().as_ref() == "generic_function" {
        function = function.field("function")?;
    }
    if function.kind().as_ref() == "identifier" {
        let name = function.text();
        for scope in call.ancestors().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "block" | "source_file" | "declaration_list"
            )
        }) {
            if scope.children().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "function_item" | "const_item" | "static_item"
                ) && n.field("name").is_some_and(|v| v.text() == name)
                    || n.kind().as_ref() == "let_declaration"
                        && n.range().end < call.range().start
                        && n.field("pattern")
                            .is_some_and(|v| v.text().trim().trim_start_matches("mut ") == name)
            }) {
                return None;
            }
        }
        if call
            .ancestors()
            .filter_map(|n| n.field("parameters"))
            .any(|p| {
                p.dfs()
                    .any(|n| n.field("pattern").is_some_and(|v| v.text() == name))
            })
        {
            return None;
        }
    }
    rust_http::canonical(root, &function, function.text().as_ref())
}
fn capture(path: &str, node: &N<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: super::matcher::location(path, node),
    }
}
fn compact(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}
fn id(prefix: &str, s: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}
fn step(kind: SecurityPathStepKind, e: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        evidence_id: Some(e.id.clone()),
        location: e.location.clone(),
        symbol: e.enclosing_symbol.clone(),
    }
}
