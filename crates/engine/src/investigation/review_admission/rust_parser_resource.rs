//! Input-backed byte slice operations with explicit panic/precondition questions.
use super::*;
use rust_shared_state::AstNode as N;
fn named<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children().filter(|n| n.is_named()).collect()
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
        for operation in root.dfs().filter(|n| {
            matches!(n.kind().as_ref(), "index_expression" | "call_expression")
                && !selection.excluded(&file.path, n.range())
        }) {
            if operation.kind().as_ref() == "call_expression"
                && !rust_allocation::method(&operation).is_some_and(|(_, name)| name == "unwrap")
            {
                continue;
            }
            let Some(function) = operation
                .ancestors()
                .find(|n| matches!(n.kind().as_ref(), "function_item" | "closure_expression"))
            else {
                continue;
            };
            if function.kind().as_ref() != "function_item"
                || function.range().len() > 32768
                || function.dfs().any(|n| n.is_error() || n.is_missing())
                || !rust_buffer_initialization::runtime_path(&operation, &function)
            {
                continue;
            }
            let input = if operation.kind().as_ref() == "index_expression" {
                named(&operation).into_iter().next()
            } else {
                rust_allocation::method(&operation).and_then(|(get, name)| {
                    if name != "unwrap" {
                        return None;
                    }
                    let (input, name) = rust_allocation::method(&get)?;
                    (name == "get").then_some(input)
                })
            };
            let Some(input) = input else {
                continue;
            };
            let Some(parameter) = rust_memory_boundaries::byte_input(&root, &input, &function)
            else {
                continue;
            };
            let location = rust_dependencies::capture(file, &operation).location;
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            let rule = "rust-input-slice-boundary-review";
            let id = review_admission_marker_id(
                &file.path,
                rule,
                operation.range().start,
                operation.range().end,
            );
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
                    capability: Capability::RustParserResourceReview,
                    location,
                    enclosing_symbol: Some(symbol),
                    captures: BTreeMap::from([
                        (
                            "parser_operation".into(),
                            rust_dependencies::capture(file, &operation),
                        ),
                        (
                            "input_parameter".into(),
                            rust_dependencies::capture(file, &parameter),
                        ),
                        (
                            "parser_definition".into(),
                            rust_dependencies::capture(file, &function),
                        ),
                    ]),
                    cwe_candidates: vec!["CWE-20".into(), "CWE-248".into()],
                    tags: vec![
                        "review-admission-marker".into(),
                        "input-backed-byte-parser".into(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded Rust input slice panic obligation".into(),
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
