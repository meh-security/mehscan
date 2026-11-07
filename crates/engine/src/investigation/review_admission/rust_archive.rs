//! Typed extraction and ZIP-entry-to-write obligations, not traversal verdicts.
use super::*;
use rust_allocation::{method, receiver_type};
use rust_shared_state::AstNode as N;

fn named<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children().filter(|n| n.is_named()).collect()
}
fn strip<'a>(n: &N<'a>) -> Option<N<'a>> {
    let mut n = n.clone();
    for _ in 0..8 {
        if !matches!(
            n.kind().as_ref(),
            "try_expression" | "reference_expression" | "parenthesized_expression"
        ) {
            return Some(n);
        }
        n = named(&n).into_iter().next()?;
    }
    None
}
fn initializer<'a>(value: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let name = value.text();
    for scope in value
        .ancestors()
        .take_while(|n| n.range() != function.range())
    {
        if scope.kind().as_ref() != "block" {
            if scope
                .field("pattern")
                .is_some_and(|p| p.dfs().any(|n| n.text() == name))
            {
                return None;
            }
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
            if binding.field("pattern")?.kind().as_ref() != "identifier" {
                return None;
            }
            if function.dfs().any(|n| {
                n.kind().as_ref() == "assignment_expression"
                    && n.range().start >= binding.range().end
                    && n.range().start < value.range().start
                    && n.field("left").is_some_and(|n| n.text() == name)
            }) {
                return None;
            }
            return binding.field("value");
        }
    }
    None
}
fn zip_entry<'a>(root: &N<'a>, expression: &N<'a>, function: &N<'a>, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    let Some(value) = strip(expression) else {
        return false;
    };
    if value.kind().as_ref() == "identifier" {
        return initializer(&value, function)
            .is_some_and(|n| zip_entry(root, &n, function, depth + 1));
    }
    let Some((archive, name)) = method(&value) else {
        return false;
    };
    if matches!(name.as_str(), "unwrap" | "expect") {
        return zip_entry(root, &archive, function, depth + 1);
    }
    matches!(name.as_str(), "by_index" | "by_name")
        && receiver_type(root, &archive, function, 0).as_deref() == Some("zip::ZipArchive")
}

fn tar_entries<'a>(root: &N<'a>, expression: &N<'a>, function: &N<'a>, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    let Some(value) = strip(expression) else {
        return false;
    };
    if value.kind().as_ref() == "identifier" {
        return initializer(&value, function)
            .is_some_and(|n| tar_entries(root, &n, function, depth + 1))
            || receiver_type(root, &value, function, 0).as_deref() == Some("tar::Entries");
    }
    let Some((archive, name)) = method(&value) else {
        return false;
    };
    if matches!(name.as_str(), "unwrap" | "expect") {
        return tar_entries(root, &archive, function, depth + 1);
    }
    matches!(name.as_str(), "entries" | "entries_with_seek")
        && receiver_type(root, &archive, function, 0).as_deref() == Some("tar::Archive")
}

// Resolve a tar iterator's loop binding or a selected `Some` result of `next`.
fn tar_entry<'a>(root: &N<'a>, expression: &N<'a>, function: &N<'a>, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    let Some(value) = strip(expression) else {
        return false;
    };
    if let Some((receiver, name)) = method(&value)
        && matches!(name.as_str(), "unwrap" | "expect")
    {
        return tar_entry(root, &receiver, function, depth + 1);
    }
    if value.kind().as_ref() != "identifier" {
        return false;
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
                if binding
                    .field("pattern")
                    .is_none_or(|p| p.kind().as_ref() != "identifier")
                {
                    return false;
                }
                if reassigned(function, &name, binding.range().end, value.range().start) {
                    return false;
                }
                return binding
                    .field("value")
                    .is_some_and(|v| tar_entry(root, &v, function, depth + 1));
            }
        } else if scope.kind().as_ref() != "let_declaration"
            && scope
                .field("pattern")
                .or_else(|| scope.field("condition").and_then(|c| c.field("pattern")))
                .is_some_and(|p| p.dfs().any(|n| n.text() == name))
        {
            let in_body = |body: Option<N<'a>>| {
                body.is_some_and(|b| {
                    b.range().start <= value.range().start
                        && value.range().end <= b.range().end
                        && !reassigned(function, &name, b.range().start, value.range().start)
                })
            };
            if scope.kind().as_ref() == "for_expression" {
                return scope
                    .field("pattern")
                    .is_some_and(|p| p.kind().as_ref() == "identifier" && p.text() == name)
                    && in_body(scope.field("body"))
                    && scope
                        .field("value")
                        .is_some_and(|v| tar_entries(root, &v, function, depth + 1));
            }
            if scope.kind().as_ref() == "if_expression"
                && in_body(scope.field("consequence"))
                && let Some(condition) = scope.field("condition")
                && condition.kind().as_ref() == "let_condition"
                && let Some(pattern) = condition.field("pattern")
                && pattern.kind().as_ref() == "tuple_struct_pattern"
                && let Some(variant) = pattern.field("type")
                && matches!(
                    variant.text().as_ref(),
                    "Some"
                        | "Option::Some"
                        | "std::option::Option::Some"
                        | "core::option::Option::Some"
                )
                && pattern
                    .children()
                    .filter(|n| n.is_named() && n.range() != variant.range())
                    .all(|n| n.kind().as_ref() == "identifier" && n.text() == name)
                && let Some((iterator, next)) = condition.field("value").and_then(|v| method(&v))
                && next == "next"
            {
                return tar_entries(root, &iterator, function, depth + 1);
            }
            return false;
        }
    }
    !reassigned(function, &name, function.range().start, value.range().start)
        && receiver_type(root, &value, function, 0).as_deref() == Some("tar::Entry")
}

fn reassigned(function: &N<'_>, name: &str, after: usize, before: usize) -> bool {
    function.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "assignment_expression" | "compound_assignment_expr"
        ) && n.range().start >= after
            && n.range().start < before
            && n.field("left").is_some_and(|n| n.text() == name)
    })
}
fn path_source<'a>(root: &N<'a>, value: &N<'a>, function: &N<'a>, depth: usize) -> Option<N<'a>> {
    if depth > 8 {
        return None;
    }
    let value = strip(value)?;
    if value.kind().as_ref() == "identifier" {
        return path_source(root, &initializer(&value, function)?, function, depth + 1);
    }
    if let Some((entry, name)) = method(&value)
        && ((name == "name" && zip_entry(root, &entry, function, 0))
            || (name == "path" && tar_entry(root, &entry, function, 0)))
    {
        return Some(value);
    }
    if matches!(
        value.kind().as_ref(),
        "closure_expression" | "function_item" | "macro_invocation"
    ) {
        return None;
    }
    named(&value)
        .iter()
        .find_map(|n| path_source(root, n, function, depth + 1))
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
            let Some(destination) = call
                .field("arguments")
                .and_then(|n| named(&n).into_iter().next())
            else {
                continue;
            };
            let extraction = method(&call).is_some_and(|(receiver, name)| {
                let owner = receiver_type(&root, &receiver, &function, 0);
                matches!(
                    (owner.as_deref(), name.as_str()),
                    (Some("tar::Archive"), "unpack")
                        | (
                            Some("zip::ZipArchive"),
                            "extract" | "extract_with_options" | "extract_unwrapped_root_dir"
                        )
                )
            });
            let entry_extraction = method(&call).is_some_and(|(receiver, name)| {
                matches!(name.as_str(), "unpack" | "unpack_in")
                    && tar_entry(&root, &receiver, &function, 0)
            });
            let write = rust_raw_memory::api(&root, &call).is_some_and(|s| {
                matches!(
                    s.as_str(),
                    "std::fs::File::create" | "std::fs::write" | "std::fs::create_dir_all"
                )
            });
            let entry = if write {
                path_source(&root, &destination, &function, 0)
            } else {
                None
            };
            if !extraction && !entry_extraction && entry.is_none() {
                continue;
            }
            let location = rust_dependencies::capture(file, &call).location;
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            let rule = if entry_extraction {
                "rust-archive-entry-extraction-review"
            } else if extraction {
                "rust-archive-extraction-review"
            } else {
                "rust-archive-entry-write-review"
            };
            let id =
                review_admission_marker_id(&file.path, rule, call.range().start, call.range().end);
            let symbol = function
                .field("name")
                .map(|n| n.text().into_owned())
                .unwrap_or_default();
            let mut captures = BTreeMap::from([
                (
                    "extraction_operation".into(),
                    rust_dependencies::capture(file, &call),
                ),
                (
                    "destination".into(),
                    rust_dependencies::capture(file, &destination),
                ),
                (
                    "extraction_definition".into(),
                    rust_dependencies::capture(file, &function),
                ),
            ]);
            if let Some(entry) = entry {
                captures.insert(
                    "archive_entry_path".into(),
                    rust_dependencies::capture(file, &entry),
                );
            }
            if entry_extraction && let Some(mut f) = call.field("function") {
                if f.kind().as_ref() == "generic_function"
                    && let Some(inner) = f.field("function")
                {
                    f = inner;
                }
                if let Some(method) = f.field("field") {
                    captures.insert(
                        "entry_extraction_method".into(),
                        rust_dependencies::capture(file, &method),
                    );
                }
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
                    capability: Capability::RustArchiveExtractionReview,
                    location,
                    enclosing_symbol: Some(symbol),
                    captures,
                    cwe_candidates: vec!["CWE-22".into()],
                    tags: vec![
                        "review-admission-marker".into(),
                        "typed-archive-operation".into(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded Rust archive extraction relationship".into(),
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
