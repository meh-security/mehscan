//! Unchecked offset-adjusted capacity checks that gate view metadata publication.
use super::*;
use rust_allocation::method;
use rust_receiver_types::local_binding;
use rust_shared_state::AstNode as N;

pub(super) const RULE: &str = "rust-capacity-reuse-overflow-review";

fn named<'a, 'n>(node: &'n N<'a>) -> impl Iterator<Item = N<'a>> + 'n {
    node.children()
        .filter(|child| child.is_named() && !child.kind().contains("comment"))
}

fn unwrap_expression<'a>(mut node: N<'a>) -> Option<N<'a>> {
    for _ in 0..8 {
        let inner = match node.kind().as_ref() {
            "parenthesized_expression" => named(&node).next()?,
            "unsafe_block" => {
                let block = named(&node).next()?;
                let mut expressions = named(&block);
                let expression = expressions.next()?;
                if expressions.next().is_some()
                    || expression.kind().as_ref() == "expression_statement"
                {
                    return None;
                }
                expression
            }
            _ => return Some(node),
        };
        node = inner;
    }
    None
}

fn resolve_aliases<'a>(value: N<'a>, function: &N<'a>, bindings: &mut Vec<N<'a>>) -> Option<N<'a>> {
    let mut value = unwrap_expression(value)?;
    for _ in 0..8 {
        if value.kind().as_ref() != "identifier" {
            return Some(value);
        }
        let binding = local_binding(&value, function)?;
        if binding.kind().as_ref() != "let_declaration"
            || binding
                .children()
                .any(|n| n.kind().as_ref() == "mutable_specifier")
        {
            return None;
        }
        value = unwrap_expression(binding.field("value")?)?;
        bindings.push(binding);
    }
    None
}

fn stable_binding<'a>(value: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let binding = local_binding(value, function)?;
    let reassigned = function.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "assignment_expression" | "compound_assignment_expr"
        ) && n.range().start >= binding.range().end
            && n.range().start < value.range().start
            && n.field("left")
                .is_some_and(|left| left.text() == value.text())
    });
    (!reassigned).then_some(binding)
}

fn self_field(node: &N<'_>) -> bool {
    node.kind().as_ref() == "field_expression"
        && node
            .field("value")
            .is_some_and(|owner| owner.kind().as_ref() == "self")
}

fn comparison<'a>(condition: &N<'a>, function: &N<'a>) -> Option<(N<'a>, N<'a>, Vec<N<'a>>)> {
    let condition = unwrap_expression(condition.clone())?;
    if condition.kind().as_ref() != "binary_expression" {
        return None;
    }
    let left = condition.field("left")?;
    let right = condition.field("right")?;
    let (available, required) = match condition.field("operator")?.text().as_ref() {
        ">=" | ">" => (left, right),
        "<=" | "<" => (right, left),
        _ => return None,
    };
    let mut aliases = Vec::new();
    let required = resolve_aliases(required, function, &mut aliases)?;
    if required.kind().as_ref() != "binary_expression"
        || required.field("operator").is_none_or(|op| op.text() != "+")
    {
        return None;
    }
    let available = resolve_aliases(available, function, &mut aliases)?;
    Some((available, required, aliases))
}

fn offset_provenance<'a>(
    offset: N<'a>,
    backing: &N<'a>,
    function: &N<'a>,
    aliases: &mut Vec<N<'a>>,
) -> Option<(N<'a>, N<'a>, N<'a>, bool)> {
    let offset = resolve_aliases(offset, function, aliases)?;
    if offset.kind().as_ref() != "type_cast_expression"
        || offset.field("type").is_none_or(|ty| ty.text() != "usize")
    {
        return None;
    }
    let offset_call = unwrap_expression(offset.field("value")?)?;
    let (view, method_name) = method(&offset_call)?;
    if method_name != "offset_from" {
        return None;
    }
    let args = offset_call.field("arguments")?;
    let mut args = named(&args);
    let base = resolve_aliases(args.next()?, function, aliases)?;
    if args.next().is_some() {
        return None;
    }
    let (base_owner, base_method) = method(&base)?;
    if !matches!(base_method.as_str(), "as_ptr" | "as_mut_ptr")
        || stable_binding(&base_owner, function)?.range() != backing.range()
    {
        return None;
    }
    let view = resolve_aliases(view, function, aliases)?;
    let (field, nonnull) = if self_field(&view) {
        (view, false)
    } else {
        let (receiver, name) = method(&view)?;
        if name != "as_ptr" || !self_field(&receiver) {
            return None;
        }
        (receiver, true)
    };
    Some((offset, base, field, nonnull))
}

fn publication<'a>(branch: &N<'a>, extent: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let requested = stable_binding(extent, function)?;
    named(branch)
        .filter_map(|statement| {
            if statement.kind().as_ref() == "expression_statement" {
                named(&statement).next()
            } else {
                Some(statement)
            }
        })
        .find(|assignment| {
            assignment.kind().as_ref() == "assignment_expression"
                && assignment
                    .field("left")
                    .is_some_and(|left| self_field(&left))
                && assignment
                    .field("right")
                    .and_then(unwrap_expression)
                    .and_then(|right| stable_binding(&right, function))
                    .is_some_and(|binding| binding.range() == requested.range())
        })
}

pub(super) fn groups(
    sources: &RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
) -> Vec<ObservationGroup> {
    let project = std::cell::OnceCell::new();
    let mut groups = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|f| f.language == Some(Language::Rust))
    {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        for branch in root.dfs().filter(|n| n.kind().as_ref() == "if_expression") {
            let Some(condition) = branch.field("condition") else {
                continue;
            };
            if selection.excluded(&file.path, condition.range()) {
                continue;
            }
            let Some(function) = branch
                .ancestors()
                .find(|n| matches!(n.kind().as_ref(), "function_item" | "closure_expression"))
            else {
                continue;
            };
            if function.kind().as_ref() != "function_item" || function.range().len() > 32768 {
                continue;
            }
            let Some((capacity, sum, aliases)) = comparison(&condition, &function) else {
                continue;
            };
            let Some((storage, name)) = method(&capacity) else {
                continue;
            };
            if name != "capacity" {
                continue;
            }
            let Some(backing) = stable_binding(&storage, &function) else {
                continue;
            };
            let (Some(left), Some(right), Some(consequence)) = (
                sum.field("left"),
                sum.field("right"),
                branch.field("consequence"),
            ) else {
                continue;
            };
            for (extent, offset) in [(left.clone(), right.clone()), (right, left)] {
                let Some(extent) = unwrap_expression(extent) else {
                    continue;
                };
                let Some(assignment) = publication(&consequence, &extent, &function) else {
                    continue;
                };
                let mut aliases = aliases.clone();
                let Some((offset, base, view, nonnull)) =
                    offset_provenance(offset, &backing, &function, &mut aliases)
                else {
                    continue;
                };
                if function.dfs().any(|n| n.is_error() || n.is_missing())
                    || !rust_buffer_initialization::runtime_path(&condition, &function)
                    || !rust_buffer_initialization::runtime_path(&assignment, &function)
                {
                    continue;
                }
                let Some(field) = assignment.field("left") else {
                    continue;
                };
                let project = project.get_or_init(|| {
                    rust_module_bindings::Project::build(sources, parsed, selection)
                });
                let Some(mut types) =
                    rust_receiver_types::vector_support(project, &storage, &function, file)
                else {
                    continue;
                };
                let Some(pointer_type) = rust_receiver_types::pointer_field_support(
                    project, &view, &function, file, nonnull,
                ) else {
                    continue;
                };
                let Some(extent_type) =
                    rust_receiver_types::extent_field_support(project, &field, &function, file)
                else {
                    continue;
                };
                types.extend(pointer_type);
                types.extend(extent_type);
                let location = rust_dependencies::capture(file, &condition).location;
                if scope.is_some_and(|s| {
                    s.result_policy == "changed_locations"
                        && !crate::impact::location_is_changed(&location, &s.changed_files)
                }) {
                    continue;
                }
                let id = review_admission_marker_id(
                    &file.path,
                    RULE,
                    condition.range().start,
                    condition.range().end,
                );
                let symbol = function
                    .field("name")
                    .map(|n| n.text().into_owned())
                    .unwrap_or_default();
                let mut captures = BTreeMap::new();
                for (role, node) in [
                    ("capacity_comparison", &condition),
                    ("backing_capacity", &capacity),
                    ("extent_arithmetic", &sum),
                    ("requested_extent", &extent),
                    ("view_offset", &offset),
                    ("backing_pointer", &base),
                    ("view_pointer_field", &view),
                    ("extent_publication", &assignment),
                    ("reuse_definition", &function),
                ] {
                    captures.insert(role.into(), rust_dependencies::capture(file, node));
                }
                if let Some(binding) = stable_binding(&extent, &function) {
                    aliases.push(binding);
                }
                types.extend(
                    aliases
                        .iter()
                        .map(|node| rust_dependencies::capture(file, node)),
                );
                let mut seen = BTreeSet::new();
                for (index, capture) in types
                    .into_iter()
                    .filter(|c| {
                        seen.insert((
                            c.location.path.clone(),
                            c.location.start.byte_offset,
                            c.location.end.byte_offset,
                        ))
                    })
                    .enumerate()
                {
                    captures.insert(format!("reuse_support_{index:02}"), capture);
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
                        capability: Capability::RustRawMemoryReview,
                        location,
                        enclosing_symbol: Some(symbol),
                        captures,
                        cwe_candidates: vec!["CWE-190".into(), "CWE-119".into()],
                        tags: vec![
                            "review-admission-marker".into(),
                            "rust-capacity-reuse".into(),
                        ],
                        confidence: Confidence::Medium,
                        provenance: Provenance {
                            resolution: Resolution::Ast,
                            engine: "bounded Rust view capacity publication".into(),
                            rule_version: 1,
                        },
                        context: EvidenceContext::default(),
                        symbol_resolution: None,
                        related_evidence: vec![],
                    }],
                });
                break;
            }
        }
    }
    groups
}
