//! Same-owner raw element destruction, scalar metadata and destructor context.
use super::*;
use rust_shared_state::{AstNode as N, owns};

fn self_field<'a>(node: &N<'a>) -> Option<String> {
    (node.kind().as_ref() == "field_expression" && node.field("value")?.text() == "self")
        .then(|| node.field("field").map(|n| n.text().into_owned()))
        .flatten()
}
fn scalar(field: &N<'_>) -> bool {
    field.field("type").is_some_and(|t| {
        matches!(
            t.text().as_ref(),
            "usize" | "u64" | "u32" | "u16" | "u8" | "isize" | "i64" | "i32"
        )
    })
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
        for function in root.dfs().filter(|n| {
            n.kind().as_ref() == "function_item" && !selection.excluded(&file.path, n.range())
        }) {
            if function.range().len() > 32768
                || function.dfs().any(|n| n.is_error() || n.is_missing())
            {
                continue;
            }
            let Some(implementation) = function
                .ancestors()
                .find(|n| n.kind().as_ref() == "impl_item")
            else {
                continue;
            };
            let Some(owner_type) = implementation.field("type") else {
                continue;
            };
            let key = rust_dependencies::type_key(&file.path, selection, &owner_type);
            let owners = root
                .dfs()
                .filter(|n| {
                    n.kind().as_ref() == "struct_item" && !selection.excluded(&file.path, n.range())
                })
                .filter(|n| {
                    n.field("name").is_some_and(|name| {
                        rust_dependencies::type_key(&file.path, selection, &name) == key
                    })
                })
                .collect::<Vec<_>>();
            if owners.len() != 1 {
                continue;
            }
            let fields = owners[0]
                .field("body")
                .map(|b| {
                    b.children()
                        .filter(|n| n.kind().as_ref() == "field_declaration")
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let metadata = function
                .dfs()
                .filter(|n| n.kind().as_ref() == "assignment_expression" && owns(n, &function))
                .filter_map(|n| {
                    let name = self_field(&n.field("left")?)?;
                    fields
                        .iter()
                        .any(|f| scalar(f) && f.field("name").is_some_and(|n| n.text() == name))
                        .then_some(n)
                })
                .collect::<Vec<_>>();
            if metadata.is_empty() {
                continue;
            }
            let drops = root
                .dfs()
                .filter(|n| {
                    n.kind().as_ref() == "impl_item" && !selection.excluded(&file.path, n.range())
                })
                .filter(|n| {
                    n.field("type").is_some_and(|ty| {
                        rust_dependencies::type_key(&file.path, selection, &ty) == key
                    }) && n.field("trait").is_some_and(|t| {
                        rust_raw_memory::canonical(&root, &t, &t.text()).is_some_and(|s| {
                            matches!(s.as_str(), "std::ops::Drop" | "core::ops::Drop")
                        })
                    })
                })
                .filter(|n| n.range().len() <= 16384)
                .collect::<Vec<_>>();
            if drops.len() != 1 {
                continue;
            }
            for call in function.dfs().filter(|n| {
                n.kind().as_ref() == "call_expression"
                    && owns(n, &function)
                    && !selection.excluded(&file.path, n.range())
                    && rust_buffer_initialization::runtime_path(n, &function)
            }) {
                if !rust_raw_memory::api(&root, &call).is_some_and(|s| {
                    matches!(
                        s.as_str(),
                        "std::ptr::drop_in_place" | "core::ptr::drop_in_place"
                    )
                }) {
                    continue;
                }
                let Some(args) = call.field("arguments") else {
                    continue;
                };
                let storage = fields.iter().find(|f| {
                    f.field("name").is_some_and(|name| {
                        args.dfs()
                            .any(|n| self_field(&n).is_some_and(|s| s == name.text()))
                    }) && f.field("type").is_some_and(|ty| {
                        ty.dfs().any(|n| {
                            n.kind().as_ref() == "pointer_type"
                                || n.kind().as_ref() == "array_type"
                                || rust_raw_memory::canonical(&root, &n, &n.text()).is_some_and(
                                    |s| {
                                        matches!(
                                            s.as_str(),
                                            "std::mem::MaybeUninit" | "core::mem::MaybeUninit"
                                        )
                                    },
                                )
                        })
                    })
                });
                let Some(storage) = storage else {
                    continue;
                };
                let location = rust_dependencies::capture(file, &call).location;
                if scope.is_some_and(|s| {
                    s.result_policy == "changed_locations"
                        && !crate::impact::location_is_changed(&location, &s.changed_files)
                }) {
                    continue;
                }
                let rule = "rust-panic-cleanup-metadata-review";
                let id = review_admission_marker_id(
                    &file.path,
                    rule,
                    call.range().start,
                    call.range().end,
                );
                let symbol = function
                    .field("name")
                    .map(|n| n.text().into_owned())
                    .unwrap_or_default();
                let mut captures = BTreeMap::from([
                    (
                        "element_destruction".into(),
                        rust_dependencies::capture(file, &call),
                    ),
                    (
                        "cleanup_definition".into(),
                        rust_dependencies::capture(file, &function),
                    ),
                    (
                        "owner_storage".into(),
                        rust_dependencies::capture(file, storage),
                    ),
                    (
                        "owner_destructor".into(),
                        rust_dependencies::capture(file, &drops[0]),
                    ),
                ]);
                for (index, assignment) in metadata.iter().take(8).enumerate() {
                    captures.insert(
                        format!("metadata_assignment_{index:02}"),
                        rust_dependencies::capture(file, assignment),
                    );
                }
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
                        cwe_candidates: vec!["CWE-415".into(), "CWE-416".into()],
                        tags: vec![
                            "review-admission-marker".into(),
                            "rust-panic-cleanup-obligation".into(),
                        ],
                        confidence: Confidence::Medium,
                        provenance: Provenance {
                            resolution: Resolution::Ast,
                            engine: "bounded same-owner Rust panic cleanup obligation".into(),
                            rule_version: 1,
                        },
                        context: EvidenceContext::default(),
                        symbol_resolution: None,
                        related_evidence: vec![],
                    }],
                });
            }
        }
    }
    groups
}
