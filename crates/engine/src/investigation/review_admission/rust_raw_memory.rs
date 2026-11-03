//! Source-bound raw-memory obligations, separated by the deciding invariant.
use super::*;
use rust_shared_state::{AstNode as N, compact, owns};

fn named<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
        .collect()
}
fn args<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.field("arguments").map(|n| named(&n)).unwrap_or_default()
}
fn strip<'a>(mut n: N<'a>) -> N<'a> {
    for _ in 0..8 {
        if !matches!(
            n.kind().as_ref(),
            "type_cast_expression"
                | "reference_expression"
                | "parenthesized_expression"
                | "try_expression"
        ) {
            break;
        }
        let Some(value) = n.field("value").or_else(|| named(&n).into_iter().next()) else {
            break;
        };
        n = value;
    }
    n
}
fn method<'a>(n: &N<'a>) -> Option<(N<'a>, String)> {
    let f = n.field("function")?;
    (f.kind().as_ref() == "field_expression").then_some(())?;
    Some((f.field("value")?, f.field("field")?.text().into_owned()))
}
fn without_generics(value: &str) -> String {
    let mut depth = 0;
    let mut text = String::new();
    for c in value.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => text.push(c),
            _ => {}
        }
    }
    while text.contains("::::") {
        text = text.replace("::::", "::");
    }
    text
}
fn canonical<'a>(root: &N<'a>, site: &N<'a>, value: &str) -> Option<String> {
    let value = without_generics(&compact(value));
    let (mut result, _) = crate::code::rust_http::canonical(root, site, &value)?;
    if result == "Drop"
        || result == "Vec"
        || result.starts_with("Vec::")
        || result == "Box"
        || result.starts_with("Box::")
    {
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
        if result == "Drop" {
            return Some("core::ops::Drop".into());
        }
        result = format!(
            "alloc::{}::{result}",
            if result.starts_with("Vec") {
                "vec"
            } else {
                "boxed"
            }
        );
    }
    Some(result)
}
fn api<'a>(root: &N<'a>, call: &N<'a>) -> Option<String> {
    let mut function = call.field("function")?;
    if function.kind().as_ref() == "generic_function" {
        function = function.field("function")?;
    }
    if !matches!(function.kind().as_ref(), "identifier" | "scoped_identifier") {
        return None;
    }
    let (value, _) = crate::code::rust_raw_slice::function_identity(root, call)?;
    canonical(root, call, &value)
}
fn owned_type<'a>(root: &N<'a>, node: &N<'a>) -> bool {
    let ty = compact(&node.text());
    if ty.starts_with('&') || !ty.contains('<') {
        return false;
    }
    canonical(root, node, ty.split('<').next().unwrap_or_default()).is_some_and(|s| {
        matches!(
            s.as_str(),
            "std::vec::Vec" | "alloc::vec::Vec" | "std::boxed::Box" | "alloc::boxed::Box"
        )
    })
}
fn parameter_name(n: &N<'_>) -> Option<String> {
    let p = n.field("pattern")?;
    if p.kind().as_ref() == "identifier" {
        Some(p.text().into_owned())
    } else {
        None
    }
}
fn parameters<'a>(f: &N<'a>) -> Vec<N<'a>> {
    f.field("parameters")
        .map(|n| {
            named(&n)
                .into_iter()
                .filter(|n| n.kind().as_ref() == "parameter")
                .collect()
        })
        .unwrap_or_default()
}

struct Function<'a> {
    root: N<'a>,
    node: N<'a>,
    nodes: Vec<N<'a>>,
    lets: BTreeMap<String, Vec<N<'a>>>,
    terminated: BTreeMap<usize, usize>,
}
impl<'a> Function<'a> {
    fn new(root: N<'a>, node: N<'a>) -> Self {
        let nodes = node.dfs().filter(|n| owns(n, &node)).collect::<Vec<_>>();
        let mut lets = BTreeMap::<_, Vec<_>>::new();
        for n in nodes.iter().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "let_declaration" | "assignment_expression"
            )
        }) {
            if let Some(p) = n
                .field("pattern")
                .or_else(|| n.field("left"))
                .filter(|p| p.kind().as_ref() == "identifier")
            {
                lets.entry(p.text().into_owned())
                    .or_default()
                    .push(n.clone());
            }
        }
        let terminated = nodes
            .iter()
            .filter(|n| n.kind().as_ref() == "block")
            .filter_map(|block| {
                let first = named(block).into_iter().find(|n| {
                    n.kind().as_ref() == "return_expression"
                        || n.kind().as_ref() == "break_expression"
                        || n.kind().as_ref() == "continue_expression"
                        || (n.kind().as_ref() == "expression_statement"
                            && named(n).first().is_some_and(|n| {
                                matches!(
                                    n.kind().as_ref(),
                                    "return_expression"
                                        | "break_expression"
                                        | "continue_expression"
                                )
                            }))
                })?;
                Some((block.range().start, first.range().end))
            })
            .collect();
        Self {
            root,
            node,
            nodes,
            lets,
            terminated,
        }
    }
    fn origin(
        &self,
        value: &N<'a>,
        before: usize,
        depth: usize,
    ) -> Option<(String, Option<String>, usize)> {
        if depth > 8 {
            return None;
        }
        let value = strip(value.clone());
        if value.kind().as_ref() == "call_expression"
            && api(&self.root, &value).is_some_and(|s| {
                matches!(
                    s.as_str(),
                    "std::mem::ManuallyDrop::new" | "core::mem::ManuallyDrop::new"
                )
            })
        {
            return self.origin(args(&value).first()?, value.range().start, depth + 1);
        }
        if value.kind().as_ref() == "identifier" {
            let name = value.text().into_owned();
            if let Some(binding) = self
                .lets
                .get(&name)
                .into_iter()
                .flatten()
                .filter(|n| {
                    n.range().end <= before
                        && n.ancestors()
                            .find(|n| n.kind().as_ref() == "block")
                            .is_some_and(|b| {
                                b.range().start <= value.range().start
                                    && value.range().end <= b.range().end
                            })
                })
                .max_by_key(|n| n.range().start)
            {
                if binding
                    .field("type")
                    .is_some_and(|t| owned_type(&self.root, &t))
                    || binding
                        .field("value")
                        .or_else(|| binding.field("right"))
                        .is_some_and(|v| {
                            api(&self.root, &v).is_some_and(|s| {
                                matches!(
                                    s.as_str(),
                                    "std::vec::Vec::new"
                                        | "alloc::vec::Vec::new"
                                        | "std::vec::Vec::with_capacity"
                                        | "alloc::vec::Vec::with_capacity"
                                        | "std::boxed::Box::new"
                                        | "alloc::boxed::Box::new"
                                )
                            })
                        })
                {
                    return Some((name, None, binding.range().start));
                }
                return self.origin(
                    &binding.field("value").or_else(|| binding.field("right"))?,
                    binding.range().start,
                    depth + 1,
                );
            }
            let binding = parameters(&self.node)
                .into_iter()
                .find(|p| parameter_name(p).as_deref() == Some(&name))
                .map(|p| p.range().start)
                .unwrap_or(usize::MAX);
            return Some((name, None, binding));
        }
        if let Some((receiver, name)) = method(&value) {
            if matches!(name.as_str(), "as_ptr" | "as_mut_ptr") {
                let (base, _, binding) = self.origin(&receiver, value.range().start, depth + 1)?;
                return Some((base, Some(name), binding));
            }
            if matches!(name.as_str(), "cast" | "cast_const" | "cast_mut") {
                return self.origin(&receiver, value.range().start, depth + 1);
            }
        }
        None
    }
}
fn safe(f: &N<'_>) -> bool {
    !f.children()
        .any(|n| n.kind().as_ref() == "function_modifiers" && n.text().contains("unsafe"))
}
fn reachable<'a>(
    file: &SourceFile,
    n: &N<'a>,
    function: &Function<'a>,
    selection: &rust_configuration::Selection,
    literals: &crate::code::literals::LiteralEnvironment<
        'a,
        StrDoc<ast_grep_language::SupportLang>,
    >,
) -> bool {
    if selection.excluded(&file.path, n.range()) {
        return false;
    }
    let mut current = n.clone();
    while let Some(parent) = current.parent() {
        if parent.range() == function.node.range() {
            break;
        }
        if parent.kind().as_ref() == "block"
            && function
                .terminated
                .get(&parent.range().start)
                .is_some_and(|end| *end <= current.range().start)
        {
            return false;
        }
        if matches!(parent.kind().as_ref(), "if_expression" | "while_expression") {
            if let Some(value) = parent
                .field("condition")
                .and_then(|c| literals.known_bool(&c))
            {
                let contains = |branch: &str| {
                    parent.field(branch).is_some_and(|b| {
                        b.range().start <= n.range().start && n.range().end <= b.range().end
                    })
                };
                if (!value && contains("consequence"))
                    || (value && contains("alternative"))
                    || (!value && parent.kind().as_ref() == "while_expression")
                {
                    return false;
                }
            }
        }
        current = parent;
    }
    true
}
fn owned_binding<'a>(
    owners: &BTreeMap<String, Vec<N<'a>>>,
    _function: &Function<'a>,
    name: &str,
    binding: usize,
) -> Option<N<'a>> {
    owners
        .get(name)?
        .iter()
        .find(|n| n.range().start == binding)
        .cloned()
}
fn ownership_disabled<'a>(
    root: &N<'a>,
    f: &Function<'a>,
    _owner: &str,
    binding: usize,
    before: usize,
) -> bool {
    let same = |call: &N<'a>| {
        args(call)
            .first()
            .and_then(|v| f.origin(v, call.range().start, 0))
            .is_some_and(|(_, _, id)| id == binding)
    };
    if f.nodes
        .iter()
        .filter(|n| n.kind().as_ref() == "call_expression" && n.range().end < before)
        .any(|n| {
            api(root, n).is_some_and(|s| {
                matches!(
                    s.as_str(),
                    "std::mem::ManuallyDrop::drop"
                        | "core::mem::ManuallyDrop::drop"
                        | "std::mem::ManuallyDrop::into_inner"
                        | "core::mem::ManuallyDrop::into_inner"
                )
            }) && same(n)
        })
    {
        return false;
    }
    f.nodes
        .iter()
        .filter(|n| n.kind().as_ref() == "call_expression" && n.range().end < before)
        .any(|n| {
            api(root, n).is_some_and(|s| {
                matches!(
                    s.as_str(),
                    "std::mem::forget"
                        | "core::mem::forget"
                        | "std::mem::ManuallyDrop::new"
                        | "core::mem::ManuallyDrop::new"
                )
            }) && same(n)
                && n.ancestors()
                    .take_while(|n| n.range() != f.node.range())
                    .all(|n| {
                        !matches!(
                            n.kind().as_ref(),
                            "if_expression"
                                | "match_expression"
                                | "for_expression"
                                | "while_expression"
                                | "loop_expression"
                                | "closure_expression"
                        )
                    })
        })
}

#[allow(clippy::too_many_arguments)]
fn emit(
    file: &SourceFile,
    f: &Function<'_>,
    anchor: &N<'_>,
    rule: &str,
    cwe: &str,
    mut captures: BTreeMap<String, Capture>,
    groups: &mut Vec<ObservationGroup>,
    scope: Option<&mehscan_core::ImpactScanScope>,
) {
    let location = rust_dependencies::capture(file, anchor).location;
    if scope.is_some_and(|s| {
        s.result_policy == "changed_locations"
            && !crate::impact::location_is_changed(&location, &s.changed_files)
    }) {
        return;
    }
    captures.insert(
        "raw_operation".into(),
        rust_dependencies::capture(file, anchor),
    );
    if f.node.range().len() <= 32768 {
        captures.insert(
            "raw_operation_definition".into(),
            rust_dependencies::capture(file, &f.node),
        );
    }
    let id = review_admission_marker_id(&file.path, rule, anchor.range().start, anchor.range().end);
    let symbol = f
        .node
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
            kind: EvidenceKind::SensitiveOperation,
            capability: Capability::RustRawMemoryReview,
            location,
            enclosing_symbol: Some(symbol),
            captures,
            cwe_candidates: vec![cwe.into()],
            tags: vec![
                "review-admission-marker".into(),
                "rust-raw-memory-invariant".into(),
                "source-bound-owner-or-safe-boundary".into(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "bounded Rust raw-memory invariant relationship".into(),
                rule_version: 1,
            },
            context: EvidenceContext::default(),
            symbol_resolution: None,
            rule_id: rule.into(),
            related_evidence: vec![],
        }],
    });
}

pub(super) fn groups(
    sources: &RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    include_material: bool,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
    dependencies: &rust_dependencies::Dependencies,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    let mut functions = BTreeMap::new();
    let mut environments = BTreeMap::new();
    let mut drops = BTreeMap::<(String, String), Vec<N<'_>>>::new();
    for file in sources.files.values().filter(|f| {
        f.language == Some(Language::Rust)
            && (f.source.contains("from_raw_parts")
                || f.source.contains("copy")
                || f.source.contains("Drop"))
    }) {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        let mut relevant = false;
        for implementation in root.dfs().filter(|n| {
            n.kind().as_ref() == "impl_item"
                && !selection.excluded(&file.path, n.range())
                && n.range().len() <= 16384
                && !n.dfs().any(|c| c.is_error() || c.is_missing())
        }) {
            if implementation.field("trait").is_some_and(|t| {
                canonical(&root, &t, &compact(&t.text()))
                    .is_some_and(|t| matches!(t.as_str(), "std::ops::Drop" | "core::ops::Drop"))
            }) {
                if let Some(owner) = implementation.field("type") {
                    drops
                        .entry((
                            file.path.clone(),
                            rust_dependencies::type_key(&file.path, selection, &owner),
                        ))
                        .or_default()
                        .push(implementation);
                }
            }
        }
        for function in root.dfs().filter(|n| {
            n.kind().as_ref() == "function_item" && !selection.excluded(&file.path, n.range())
        }) {
            if function.dfs().any(|n| n.is_error() || n.is_missing()) {
                continue;
            }
            if !parameters(&function).iter().any(|p| {
                p.field("type").is_some_and(|ty| {
                    owned_type(&root, &ty)
                        || ty.kind().as_ref() == "pointer_type"
                        || ty.kind().as_ref() == "reference_type"
                })
            }) && function
                .field("return_type")
                .is_none_or(|t| t.kind().as_ref() != "pointer_type" && !owned_type(&root, &t))
            {
                continue;
            }
            relevant = true;
            functions.insert(
                (file.path.clone(), function.range().start),
                Function::new(root.clone(), function),
            );
        }
        if relevant {
            environments.insert(
                file.path.clone(),
                crate::code::literals::LiteralEnvironment::build(&root, Language::Rust),
            );
        }
    }
    for ((path, _), f) in &functions {
        let file = &sources.files[path];
        if !include_material && is_review_material_path(path) {
            continue;
        }
        if scope.is_some_and(|s| {
            matches!(s.result_policy.as_str(), "changed_files" | "impact_scope")
                && !s.included_files.iter().any(|p| p.path == *path)
        }) {
            continue;
        }
        let root = parsed.root(path).unwrap();
        let literals = &environments[path];
        let params = parameters(&f.node);
        let mut owned = params
            .iter()
            .filter(|p| p.field("type").is_some_and(|ty| owned_type(&root, &ty)))
            .filter_map(|p| Some((parameter_name(p)?, vec![p.clone()])))
            .collect::<BTreeMap<_, _>>();
        for declaration in f.lets.values().flatten() {
            let declared = declaration
                .field("type")
                .is_some_and(|t| owned_type(&root, &t));
            let constructed = declaration
                .field("value")
                .or_else(|| declaration.field("right"))
                .is_some_and(|v| {
                    api(&root, &v).is_some_and(|s| {
                        matches!(
                            s.as_str(),
                            "std::vec::Vec::new"
                                | "alloc::vec::Vec::new"
                                | "std::vec::Vec::with_capacity"
                                | "alloc::vec::Vec::with_capacity"
                                | "std::boxed::Box::new"
                                | "alloc::boxed::Box::new"
                        )
                    })
                });
            if declared || constructed {
                if let Some(name) = declaration
                    .field("pattern")
                    .or_else(|| declaration.field("left"))
                {
                    owned
                        .entry(name.text().into_owned())
                        .or_default()
                        .push(declaration.clone());
                }
            }
        }
        let raw = params
            .iter()
            .filter(|p| {
                p.field("type")
                    .is_some_and(|ty| ty.kind().as_ref() == "pointer_type")
            })
            .filter_map(|p| Some((parameter_name(p)?, p.clone())))
            .collect::<BTreeMap<_, _>>();
        let slices = params
            .iter()
            .filter(|p| {
                p.field("type").is_some_and(|ty| {
                    ty.kind().as_ref() == "reference_type"
                        && ty
                            .dfs()
                            .any(|n| matches!(n.kind().as_ref(), "array_type" | "slice_type"))
                })
            })
            .filter_map(|p| Some((parameter_name(p)?, p.clone())))
            .collect::<BTreeMap<_, _>>();
        if owned.is_empty() && raw.is_empty() && slices.is_empty() {
            continue;
        }
        for call in f.nodes.iter().filter(|n| {
            n.kind().as_ref() == "call_expression" && reachable(file, n, f, selection, &literals)
        }) {
            let name = api(&root, call).unwrap_or_default();
            let arguments = args(call);
            let reconstruct = matches!(
                name.as_str(),
                "std::vec::Vec::from_raw_parts" | "alloc::vec::Vec::from_raw_parts"
            );
            let slice = matches!(
                name.as_str(),
                "std::slice::from_raw_parts"
                    | "core::slice::from_raw_parts"
                    | "std::slice::from_raw_parts_mut"
                    | "core::slice::from_raw_parts_mut"
            );
            if (slice || reconstruct) && arguments.len() >= 2 {
                if let Some((base, method, origin_binding)) =
                    f.origin(&arguments[0], call.range().start, 0)
                {
                    if safe(&f.node)
                        && f.node
                            .children()
                            .any(|n| n.kind().as_ref() == "visibility_modifier")
                        && ((raw
                            .get(&base)
                            .is_some_and(|n| n.range().start == origin_binding)
                            && method.is_none())
                            || (slices
                                .get(&base)
                                .is_some_and(|n| n.range().start == origin_binding)
                                && method.is_some()))
                    {
                        emit(
                            file,
                            f,
                            call,
                            "rust-safe-raw-memory-boundary-review",
                            "CWE-119",
                            BTreeMap::from([(
                                "raw_pointer_parameter".into(),
                                rust_dependencies::capture(
                                    file,
                                    raw.get(&base).or_else(|| slices.get(&base)).unwrap(),
                                ),
                            )]),
                            &mut groups,
                            scope,
                        );
                    }
                    if reconstruct
                        && arguments.len() == 3
                        && owned_binding(&owned, f, &base, origin_binding).is_some()
                        && method.is_some()
                    {
                        let captures = BTreeMap::from([
                            (
                                "owned_source_parameter".into(),
                                rust_dependencies::capture(
                                    file,
                                    &owned_binding(&owned, f, &base, origin_binding).unwrap(),
                                ),
                            ),
                            (
                                "length_operand".into(),
                                rust_dependencies::capture(file, &arguments[1]),
                            ),
                            (
                                "capacity_operand".into(),
                                rust_dependencies::capture(file, &arguments[2]),
                            ),
                        ]);
                        emit(
                            file,
                            f,
                            call,
                            "rust-vector-metadata-review",
                            "CWE-119",
                            captures.clone(),
                            &mut groups,
                            scope,
                        );
                        if !ownership_disabled(&root, f, &base, origin_binding, call.range().start)
                        {
                            emit(
                                file,
                                f,
                                call,
                                "rust-vector-ownership-review",
                                "CWE-415",
                                captures.clone(),
                                &mut groups,
                                scope,
                            );
                        }
                        if arguments[0]
                            .dfs()
                            .any(|n| n.kind().as_ref() == "type_cast_expression")
                        {
                            emit(
                                file,
                                f,
                                call,
                                "rust-vector-layout-review",
                                "CWE-704",
                                captures,
                                &mut groups,
                                scope,
                            );
                        }
                    }
                }
            }
            let copy = matches!(
                name.as_str(),
                "std::ptr::copy_nonoverlapping"
                    | "core::ptr::copy_nonoverlapping"
                    | "std::ptr::copy"
                    | "core::ptr::copy"
            );
            if copy && arguments.len() == 3 {
                if safe(&f.node)
                    && f.node
                        .children()
                        .any(|n| n.kind().as_ref() == "visibility_modifier")
                {
                    let source = f.origin(&arguments[0], call.range().start, 0);
                    let target = f.origin(&arguments[1], call.range().start, 0);
                    if let (Some((s, sm, source_binding)), Some((d, dm, target_binding))) =
                        (source, target)
                    {
                        if (raw
                            .get(&s)
                            .is_some_and(|n| n.range().start == source_binding)
                            && sm.is_none()
                            || slices
                                .get(&s)
                                .is_some_and(|n| n.range().start == source_binding)
                                && sm.is_some())
                            && (raw
                                .get(&d)
                                .is_some_and(|n| n.range().start == target_binding)
                                && dm.is_none()
                                || slices
                                    .get(&d)
                                    .is_some_and(|n| n.range().start == target_binding)
                                    && dm.is_some()
                                || owned_binding(&owned, f, &d, target_binding).is_some()
                                    && dm.is_some())
                        {
                            let source = raw.get(&s).or_else(|| slices.get(&s)).unwrap();
                            let target = raw
                                .get(&d)
                                .or_else(|| slices.get(&d))
                                .cloned()
                                .or_else(|| owned_binding(&owned, f, &d, target_binding))
                                .unwrap();
                            emit(
                                file,
                                f,
                                call,
                                "rust-raw-copy-range-review",
                                "CWE-119",
                                BTreeMap::from([
                                    (
                                        "copy_source_parameter".into(),
                                        rust_dependencies::capture(file, source),
                                    ),
                                    (
                                        "copy_target_parameter".into(),
                                        rust_dependencies::capture(file, &target),
                                    ),
                                    (
                                        "copy_count".into(),
                                        rust_dependencies::capture(file, &arguments[2]),
                                    ),
                                ]),
                                &mut groups,
                                scope,
                            );
                        }
                    }
                }
                if let Some((base, Some(_), origin_binding)) =
                    f.origin(&arguments[0], call.range().start, 0)
                {
                    if owned_binding(&owned, f, &base, origin_binding).is_some()
                        && f.node
                            .field("return_type")
                            .is_some_and(|ty| owned_type(&root, &ty))
                    {
                        emit(
                            file,
                            f,
                            call,
                            "rust-owned-buffer-copy-review",
                            "CWE-415",
                            BTreeMap::from([(
                                "owned_source_parameter".into(),
                                rust_dependencies::capture(
                                    file,
                                    &owned_binding(&owned, f, &base, origin_binding).unwrap(),
                                ),
                            )]),
                            &mut groups,
                            scope,
                        );
                    }
                }
            }
            // Bounded source-defined copy helper: borrow an owned buffer, return
            // storage into a destructor-bearing owner. Neither a helper name nor
            // a raw copy alone establishes duplicated ownership.
            if !safe(&f.node)
                || f.node
                    .field("return_type")
                    .is_none_or(|t| compact(&t.text()) != "Self")
            {
                continue;
            }
            let Some(helper) = dependencies.call_definition(path, selection, call) else {
                continue;
            };
            let Some(h) = functions.get(&(
                helper.location.path.clone(),
                helper.location.start.byte_offset,
            )) else {
                continue;
            };
            let helper_root = parsed.root(&helper.location.path).unwrap();
            let hp = parameters(&h.node);
            for (index, argument) in arguments.iter().enumerate() {
                if argument.kind().as_ref() != "reference_expression" {
                    continue;
                }
                let Some((source, None, source_binding)) =
                    f.origin(argument, call.range().start, 0)
                else {
                    continue;
                };
                let Some(parameter) = owned_binding(&owned, f, &source, source_binding) else {
                    continue;
                };
                let Some(helper_parameter) = hp.get(index).and_then(parameter_name) else {
                    continue;
                };
                let Some(copy) = h
                    .nodes
                    .iter()
                    .filter(|n| n.kind().as_ref() == "call_expression")
                    .find(|n| {
                        api(&helper_root, n).is_some_and(|s| {
                            matches!(
                                s.as_str(),
                                "core::ptr::copy_nonoverlapping" | "std::ptr::copy_nonoverlapping"
                            )
                        })
                    })
                else {
                    continue;
                };
                let a = args(copy);
                if a.len() != 3
                    || h.origin(&a[0], copy.range().start, 0)
                        .is_none_or(|(base, m, id)| {
                            base != helper_parameter || m.is_none() || id != hp[index].range().start
                        })
                {
                    continue;
                }
                let Some(owner) = f
                    .node
                    .ancestors()
                    .find(|n| n.kind().as_ref() == "impl_item")
                    .and_then(|n| n.field("type"))
                else {
                    continue;
                };
                let owner = rust_dependencies::type_key(path, selection, &owner);
                let Some(drop) = drops
                    .get(&(path.clone(), owner))
                    .filter(|items| items.len() == 1)
                    .and_then(|items| items.first())
                else {
                    continue;
                };
                let mut captures = BTreeMap::from([
                    (
                        "owned_source_parameter".into(),
                        rust_dependencies::capture(file, &parameter),
                    ),
                    (
                        "copy_helper_call".into(),
                        rust_dependencies::capture(file, call),
                    ),
                    ("copy_helper_definition".into(), helper.clone()),
                    (
                        "destination_owner_drop".into(),
                        rust_dependencies::capture(file, &drop),
                    ),
                ]);
                captures.insert(
                    "copy_operation".into(),
                    rust_dependencies::capture(&sources.files[&helper.location.path], copy),
                );
                emit(
                    file,
                    f,
                    call,
                    "rust-owned-buffer-copy-review",
                    "CWE-415",
                    captures,
                    &mut groups,
                    scope,
                );
            }
        }
    }
    groups
}
