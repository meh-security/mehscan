//! Source-defined size arithmetic reaching recognized vector allocations.
use super::*;
use rust_shared_state::AstNode as N;
fn named<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children().filter(|n| n.is_named()).collect()
}
fn computation<'a>(value: &N<'a>, function: &N<'a>, depth: usize) -> Option<N<'a>> {
    if depth > 8 {
        return None;
    }
    if value.kind().as_ref() == "binary_expression"
        && value
            .field("operator")
            .is_some_and(|n| matches!(n.text().as_ref(), "+" | "-" | "*" | "<<"))
    {
        return Some(value.clone());
    }
    if let Some((_, name)) = rust_allocation::method(value)
        && matches!(
            name.as_str(),
            "checked_add"
                | "checked_sub"
                | "checked_mul"
                | "checked_shl"
                | "saturating_add"
                | "saturating_sub"
                | "saturating_mul"
                | "wrapping_add"
                | "wrapping_sub"
                | "wrapping_mul"
        )
    {
        return Some(value.clone());
    }
    if value.kind().as_ref() == "identifier" {
        let name = value.text();
        for scope in value
            .ancestors()
            .take_while(|n| n.range() != function.range())
        {
            if scope.kind().as_ref() != "block" {
                continue;
            }
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
                if binding.field("pattern")?.kind().as_ref() != "identifier"
                    || binding
                        .children()
                        .any(|n| n.kind().as_ref() == "mutable_specifier")
                {
                    return None;
                }
                return computation(&binding.field("value")?, function, depth + 1);
            }
        }
        return None;
    }
    if matches!(
        value.kind().as_ref(),
        "closure_expression" | "macro_invocation" | "function_item"
    ) {
        return None;
    }
    named(value)
        .iter()
        .find_map(|n| computation(n, function, depth + 1))
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
        for call in root.dfs().filter(|n| {
            n.kind().as_ref() == "call_expression" && !selection.excluded(&file.path, n.range())
        }) {
            if !rust_raw_memory::api(&root, &call).is_some_and(|s| {
                matches!(
                    s.as_str(),
                    "std::vec::Vec::with_capacity" | "alloc::vec::Vec::with_capacity"
                )
            }) {
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
                || function.dfs().any(|n| n.is_error() || n.is_missing())
                || !rust_buffer_initialization::runtime_path(&call, &function)
            {
                continue;
            }
            let Some(extent) = call
                .field("arguments")
                .and_then(|n| named(&n).into_iter().next())
            else {
                continue;
            };
            let Some(parameter) = rust_allocation::origin(&extent, &function, 0) else {
                continue;
            };
            let Some(arithmetic) = computation(&extent, &function, 0) else {
                continue;
            };
            let location = rust_dependencies::capture(file, &call).location;
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            let rule = "rust-allocation-extent-arithmetic-review";
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
                    capability: Capability::RustAllocationReview,
                    location,
                    enclosing_symbol: Some(symbol),
                    captures: BTreeMap::from([
                        ("allocation".into(), rust_dependencies::capture(file, &call)),
                        (
                            "arithmetic".into(),
                            rust_dependencies::capture(file, &arithmetic),
                        ),
                        (
                            "input_parameter".into(),
                            rust_dependencies::capture(file, &parameter),
                        ),
                        (
                            "allocation_definition".into(),
                            rust_dependencies::capture(file, &function),
                        ),
                    ]),
                    cwe_candidates: vec!["CWE-190".into()],
                    tags: vec![
                        "review-admission-marker".into(),
                        "allocation-extent-arithmetic".into(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded Rust allocation arithmetic obligation".into(),
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
