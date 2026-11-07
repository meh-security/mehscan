//! Same-owner storage obligations for unsafe standard Send/Sync assertions.
use super::*;
use rust_shared_state::AstNode as N;

fn standard_trait<'a>(root: &N<'a>, site: &N<'a>) -> Option<String> {
    let identity = rust_raw_memory::canonical(root, site, &site.text())?;
    if matches!(
        identity.as_str(),
        "std::marker::Send" | "core::marker::Send" | "std::marker::Sync" | "core::marker::Sync"
    ) {
        return Some(identity);
    }
    if !matches!(identity.as_str(), "Send" | "Sync") {
        return None;
    }
    if root.children().any(|n| {
        n.kind().as_ref() == "inner_attribute_item" && n.text().contains("no_implicit_prelude")
    }) {
        return None;
    }
    if site
        .ancestors()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "block" | "source_file" | "declaration_list"
            )
        })
        .flat_map(|n| n.children().collect::<Vec<_>>())
        .any(|n| {
            n.kind().as_ref() == "use_declaration"
                && n.dfs().any(|n| n.kind().as_ref() == "use_wildcard")
        })
    {
        return None;
    }
    Some(format!("core::marker::{identity}"))
}
fn storage<'a>(root: &N<'a>, owner: &N<'a>) -> Option<N<'a>> {
    let generics = owner
        .field("type_parameters")
        .map(|p| {
            p.children()
                .filter_map(|p| p.field("name").map(|n| n.text().into_owned()))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    owner
        .field("body")?
        .dfs()
        .filter(|n| n.kind().as_ref() == "field_declaration")
        .find_map(|field| {
            let ty = field.field("type")?;
            if ty.dfs().any(|n| generics.contains(n.text().as_ref())) {
                return Some(field);
            }
            let sensitive = ty
                .dfs()
                .filter(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "generic_type" | "scoped_type_identifier" | "type_identifier"
                    )
                })
                .any(|n| {
                    rust_raw_memory::canonical(root, &n, &n.text()).is_some_and(|s| {
                        matches!(
                            s.as_str(),
                            "std::cell::Cell"
                                | "core::cell::Cell"
                                | "std::cell::UnsafeCell"
                                | "core::cell::UnsafeCell"
                                | "std::cell::RefCell"
                                | "core::cell::RefCell"
                                | "std::rc::Rc"
                                | "alloc::rc::Rc"
                        )
                    })
                });
            sensitive.then_some(field)
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
        for implementation in root.dfs().filter(|n| {
            n.kind().as_ref() == "impl_item" && !selection.excluded(&file.path, n.range())
        }) {
            if implementation.range().len() > 16384
                || implementation.dfs().any(|n| n.is_error() || n.is_missing())
                || !implementation.children().any(|n| n.text() == "unsafe")
            {
                continue;
            }
            let (Some(trait_node), Some(owner_type)) =
                (implementation.field("trait"), implementation.field("type"))
            else {
                continue;
            };
            let Some(trait_name) = standard_trait(&root, &trait_node) else {
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
            if owners.len() != 1 || owners[0].range().len() > 16384 {
                continue;
            }
            let owner = &owners[0];
            let Some(field) = storage(&root, owner) else {
                continue;
            };
            let location = rust_dependencies::capture(file, &implementation).location;
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            let rule = "rust-thread-safety-implementation-review";
            let id = review_admission_marker_id(
                &file.path,
                rule,
                implementation.range().start,
                implementation.range().end,
            );
            let symbol = owner_type.text().into_owned();
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
                    captures: BTreeMap::from([
                        (
                            "thread_assertion".into(),
                            rust_dependencies::capture(file, &implementation),
                        ),
                        (
                            "thread_trait".into(),
                            rust_dependencies::capture(file, &trait_node),
                        ),
                        (
                            "thread_storage".into(),
                            rust_dependencies::capture(file, &field),
                        ),
                        (
                            "thread_owner_definition".into(),
                            rust_dependencies::capture(file, owner),
                        ),
                    ]),
                    cwe_candidates: vec!["CWE-362".into()],
                    tags: vec![
                        "review-admission-marker".into(),
                        "rust-thread-safety-obligation".into(),
                        format!("asserted-trait:{trait_name}"),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded same-owner Rust Send/Sync obligation".into(),
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
