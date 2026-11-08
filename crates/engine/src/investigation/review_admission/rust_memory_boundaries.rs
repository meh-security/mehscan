//! Typed unsafe-operation obligations at safe function boundaries.
use super::*;
use rust_allocation::{method, receiver_type};
use rust_shared_state::AstNode as N;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Vector,
    Slice,
    Pointer,
    Uninit,
}

fn named<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
        .collect()
}
fn type_kind<'a>(root: &N<'a>, ty: &N<'a>) -> Option<Kind> {
    if ty.kind().as_ref() == "reference_type" {
        return type_kind(root, &ty.field("type")?);
    }
    match ty.kind().as_ref() {
        "array_type" | "slice_type" => return Some(Kind::Slice),
        "pointer_type" => return Some(Kind::Pointer),
        _ => {}
    }
    match rust_raw_memory::canonical(root, ty, &ty.text())?.as_str() {
        "std::vec::Vec" | "alloc::vec::Vec" => Some(Kind::Vector),
        "std::mem::MaybeUninit" | "core::mem::MaybeUninit" => Some(Kind::Uninit),
        _ => None,
    }
}
fn witness<'a>(
    root: &N<'a>,
    value: &N<'a>,
    function: &N<'a>,
    depth: usize,
) -> Option<(Kind, N<'a>)> {
    if depth > 8 {
        return None;
    }
    if matches!(
        value.kind().as_ref(),
        "reference_expression" | "parenthesized_expression" | "try_expression"
    ) {
        return witness(
            root,
            &value
                .field("value")
                .or_else(|| named(value).into_iter().next())?,
            function,
            depth + 1,
        );
    }
    if value.kind().as_ref() == "type_cast_expression" {
        return Some((type_kind(root, &value.field("type")?)?, value.clone()));
    }
    if value.kind().as_ref() == "array_expression" {
        return Some((Kind::Slice, value.clone()));
    }
    if value.kind().as_ref() == "call_expression" {
        if receiver_type(root, value, function, 0)
            .is_some_and(|s| matches!(s.as_str(), "std::vec::Vec" | "alloc::vec::Vec"))
        {
            return Some((Kind::Vector, value.clone()));
        }
        if let Some(api) = rust_raw_memory::api(root, value)
            && matches!(
                api.as_str(),
                "std::mem::MaybeUninit::new"
                    | "std::mem::MaybeUninit::uninit"
                    | "std::mem::MaybeUninit::zeroed"
                    | "core::mem::MaybeUninit::new"
                    | "core::mem::MaybeUninit::uninit"
                    | "core::mem::MaybeUninit::zeroed"
            )
        {
            return Some((Kind::Uninit, value.clone()));
        }
        if let Some((receiver, name)) = method(value)
            && matches!(name.as_str(), "as_ptr" | "as_mut_ptr")
        {
            let (kind, binding) = witness(root, &receiver, function, depth + 1)?;
            return matches!(kind, Kind::Vector | Kind::Slice | Kind::Uninit)
                .then_some((Kind::Pointer, binding));
        }
        return None;
    }
    if value.kind().as_ref() != "identifier" {
        return None;
    }
    let name = value.text();
    for scope in value
        .ancestors()
        .take_while(|n| n.range() != function.range())
    {
        if scope.kind().as_ref() == "block" {
            if let Some(binding) = scope
                .children()
                .filter(|n| {
                    n.kind().as_ref() == "let_declaration"
                        && n.range().end <= value.range().start
                        && n.field("pattern").is_some_and(|p| {
                            p.dfs()
                                .any(|n| n.kind().as_ref() == "identifier" && n.text() == name)
                        })
                })
                .last()
            {
                if binding.field("pattern")?.kind().as_ref() != "identifier" {
                    return None;
                }
                if function.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "assignment_expression" | "compound_assignment_expr"
                    ) && n.range().start > binding.range().end
                        && n.range().start < value.range().start
                        && n.field("left").is_some_and(|n| n.text() == name)
                }) {
                    return None;
                }
                if let Some(ty) = binding.field("type") {
                    return Some((type_kind(root, &ty)?, binding));
                }
                let (kind, _) = witness(root, &binding.field("value")?, function, depth + 1)?;
                return Some((kind, binding));
            }
        } else if scope.kind().as_ref() != "let_declaration"
            && scope
                .field("pattern")
                .or_else(|| scope.field("condition").and_then(|c| c.field("pattern")))
                .is_some_and(|p| p.dfs().any(|n| n.text() == name))
        {
            return None;
        }
    }
    let p = function.field("parameters")?.children().find(|p| {
        p.kind().as_ref() == "parameter"
            && p.field("pattern")
                .is_some_and(|p| p.kind().as_ref() == "identifier" && p.text() == name)
    })?;
    Some((type_kind(root, &p.field("type")?)?, p))
}

pub(super) fn groups(
    sources: &RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|f| f.language == Some(Language::Rust))
    {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        let api = rust_raw_memory::ApiNames::new(&root, &["transmute", "transmute_copy"]);
        for call in root.dfs().filter(|n| {
            n.kind().as_ref() == "call_expression" && !selection.excluded(&file.path, n.range())
        }) {
            let selected = if let Some((_, name)) = method(&call) {
                matches!(
                    name.as_str(),
                    "get_unchecked"
                        | "get_unchecked_mut"
                        | "set_len"
                        | "add"
                        | "sub"
                        | "offset"
                        | "assume_init"
                        | "assume_init_read"
                        | "assume_init_ref"
                        | "assume_init_mut"
                        | "assume_init_drop"
                )
            } else {
                api.resolve(&root, &call).is_some_and(|s| {
                    matches!(
                        s.as_str(),
                        "std::mem::transmute"
                            | "core::mem::transmute"
                            | "std::mem::transmute_copy"
                            | "core::mem::transmute_copy"
                    )
                })
            };
            if !selected {
                continue;
            }
            let Some(function) = call
                .ancestors()
                .find(|n| matches!(n.kind().as_ref(), "function_item" | "closure_expression"))
            else {
                continue;
            };
            if function.kind().as_ref() != "function_item"
                || function.range().len() > 32768
                || function.children().any(|n| {
                    n.kind().as_ref() == "function_modifiers" && n.text().contains("unsafe")
                })
                || function.dfs().any(|n| n.is_error() || n.is_missing())
                || !rust_buffer_initialization::runtime_path(&call, &function)
            {
                continue;
            }
            let mut captures = BTreeMap::new();
            let rule = if let Some((receiver, name)) = method(&call) {
                let Some((kind, binding)) = witness(&root, &receiver, &function, 0) else {
                    continue;
                };
                let rule = match (kind, name.as_str()) {
                    (Kind::Vector | Kind::Slice, "get_unchecked" | "get_unchecked_mut") => {
                        "rust-unchecked-index-review"
                    }
                    (Kind::Vector, "set_len") => "rust-vector-length-publication-review",
                    (Kind::Pointer, "add" | "sub" | "offset") => "rust-pointer-offset-review",
                    (
                        Kind::Uninit,
                        "assume_init" | "assume_init_read" | "assume_init_ref" | "assume_init_mut"
                        | "assume_init_drop",
                    ) => "rust-assume-initialized-review",
                    _ => continue,
                };
                captures.insert(
                    "memory_receiver".into(),
                    rust_dependencies::capture(file, &receiver),
                );
                captures.insert(
                    "memory_type_witness".into(),
                    rust_dependencies::capture(file, &binding),
                );
                rule
            } else if rust_raw_memory::api(&root, &call).is_some_and(|s| {
                matches!(
                    s.as_str(),
                    "std::mem::transmute"
                        | "core::mem::transmute"
                        | "std::mem::transmute_copy"
                        | "core::mem::transmute_copy"
                )
            }) {
                "rust-transmute-representation-review"
            } else {
                continue;
            };
            let location = rust_dependencies::capture(file, &call).location;
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            captures.insert(
                "raw_operation".into(),
                rust_dependencies::capture(file, &call),
            );
            captures.insert(
                "raw_operation_definition".into(),
                rust_dependencies::capture(file, &function),
            );
            let id =
                review_admission_marker_id(&file.path, rule, call.range().start, call.range().end);
            let symbol = function
                .field("name")
                .map(|n| n.text().into_owned())
                .unwrap_or_default();
            groups.push(ObservationGroup {
                path: file.path.clone(),
                symbol: symbol.clone(),
                anchor_evidence_ids: vec![id.clone()],
                priority: 1,
                review_material: is_review_material_path(&file.path),
                evidence: vec![Evidence {
                    id,
                    rule_id: rule.into(),
                    kind: EvidenceKind::SensitiveOperation,
                    capability: Capability::RustRawMemoryReview,
                    location,
                    enclosing_symbol: Some(symbol),
                    captures,
                    cwe_candidates: vec![if rule == "rust-assume-initialized-review" {
                        "CWE-457".into()
                    } else {
                        "CWE-119".into()
                    }],
                    tags: vec![
                        "review-admission-marker".into(),
                        "typed-rust-safe-memory-boundary".into(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded typed Rust unsafe memory obligation".into(),
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

pub(super) fn byte_input<'a>(root: &N<'a>, value: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let (kind, _) = witness(root, value, function, 0)?;
    if kind != Kind::Slice {
        return None;
    }
    let parameter = rust_allocation::origin(value, function, 0)?;
    let mut ty = parameter.field("type")?;
    if ty.kind().as_ref() != "reference_type" {
        return None;
    }
    ty = ty.field("type")?;
    ((ty.kind().as_ref() == "slice_type"
        || (ty.kind().as_ref() == "array_type" && ty.field("length").is_none()))
        && ty
            .field("element")
            .or_else(|| ty.field("type"))
            .is_some_and(|t| t.text() == "u8"))
    .then_some(parameter)
}
