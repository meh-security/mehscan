//! Scoped element-drop guards and late metadata updates in same-owner callers.
use super::*;
use rust_receiver_types::{local_binding, local_pattern_binding};
use rust_shared_state::{AstNode as N, owns};

const RULE: &str = "rust-panic-cleanup-helper-review";

fn named<'a, 'n>(node: &'n N<'a>) -> impl Iterator<Item = N<'a>> + 'n {
    node.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
}

fn self_path(node: &N<'_>) -> Option<Vec<String>> {
    let mut current = node.clone();
    let mut fields = Vec::new();
    while current.kind().as_ref() == "field_expression" && fields.len() < 4 {
        fields.push(current.field("field")?.text().into_owned());
        current = current.field("value")?;
    }
    if current.kind().as_ref() != "self" || fields.is_empty() {
        return None;
    }
    fields.reverse();
    Some(fields)
}

fn field_origin<'a>(
    value: &N<'a>,
    helper: &N<'a>,
    projection: Option<usize>,
    depth: usize,
) -> Option<Vec<N<'a>>> {
    if depth > 12 {
        return None;
    }
    if projection.is_none() && self_path(value).is_some() {
        return rust_buffer_initialization::runtime_path(value, helper)
            .then(|| vec![value.clone()]);
    }
    let next = |node: &N<'a>, index| field_origin(node, helper, index, depth + 1);
    match value.kind().as_ref() {
        "reference_expression" => next(&value.field("value")?, projection),
        "parenthesized_expression" => next(&named(value).next()?, projection),
        "index_expression" if projection.is_none() => next(&named(value).next()?, None),
        "block" => next(&named(value).last()?, projection),
        "if_expression" => next(&value.field("consequence")?, projection).or_else(|| {
            let alternative = value.field("alternative")?;
            next(&named(&alternative).next()?, projection)
        }),
        "tuple_expression" => next(&named(value).nth(projection?)?, None),
        "identifier" => {
            let binding = local_pattern_binding(value, helper)?;
            let pattern = binding.field("pattern")?;
            let index = match pattern.kind().as_ref() {
                "identifier" => projection,
                "tuple_pattern" if projection.is_none() => {
                    let parts: Vec<_> = named(&pattern).collect();
                    if parts.iter().any(|n| n.kind().as_ref() != "identifier") {
                        return None;
                    }
                    Some(parts.iter().position(|n| n.text() == value.text())?)
                }
                _ => return None,
            };
            let mut path = next(&binding.field("value")?, index)?;
            path.push(binding);
            Some(path)
        }
        _ => None,
    }
}

fn extent_origin<'a>(
    value: &N<'a>,
    function: &N<'a>,
    field: &[String],
    depth: usize,
) -> Option<Vec<N<'a>>> {
    if depth > 8 {
        return None;
    }
    if self_path(value).as_deref() == Some(field) {
        return Some(vec![value.clone()]);
    }
    if value.kind().as_ref() == "identifier" {
        let binding = local_binding(value, function)?;
        let mut path = extent_origin(&binding.field("value")?, function, field, depth + 1)?;
        path.push(binding);
        return Some(path);
    }
    if !matches!(
        value.kind().as_ref(),
        "range_expression" | "binary_expression" | "parenthesized_expression"
    ) {
        return None;
    }
    named(value).find_map(|child| extent_origin(&child, function, field, depth + 1))
}

fn drop_impl<'a>(root: &N<'a>, item: &N<'a>) -> bool {
    item.field("trait").is_some_and(|ty| {
        rust_raw_memory::canonical(root, &ty, &ty.text())
            .is_some_and(|name| matches!(name.as_str(), "core::ops::Drop" | "std::ops::Drop"))
    })
}

fn assignment(node: &N<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "assignment_expression" | "compound_assignment_expr"
    )
}

fn following_updates<'a>(call: &N<'a>) -> Vec<N<'a>> {
    let mut statement = call.clone();
    while let Some(parent) = statement.parent() {
        match parent.kind().as_ref() {
            "expression_statement" | "unsafe_block" => statement = parent,
            "block" => {
                let mut following = named(&parent)
                    .filter(|n| {
                        n.range().start >= statement.range().end
                            && n.kind().as_ref() != "empty_statement"
                    })
                    .peekable();
                if following.peek().is_none()
                    && parent
                        .parent()
                        .is_some_and(|n| n.kind().as_ref() == "unsafe_block")
                {
                    statement = parent.clone();
                    continue;
                }
                return following
                    .map(|node| {
                        if node.kind().as_ref() == "expression_statement" {
                            named(&node).next().unwrap_or(node.clone())
                        } else {
                            node
                        }
                    })
                    .take_while(assignment)
                    .take(8)
                    .collect();
            }
            _ => break,
        }
    }
    Vec::new()
}

struct Guard<'a> {
    definition: N<'a>,
    construction: N<'a>,
    destructor: N<'a>,
    raw_drop: N<'a>,
    storage: Vec<N<'a>>,
}

fn scoped_guard<'a>(
    root: &N<'a>,
    helper: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<Guard<'a>> {
    let body = helper.field("body")?;
    for binding in named(&body).filter(|n| n.kind().as_ref() == "let_declaration" && enabled(n)) {
        let (Some(pattern), Some(construct)) = (binding.field("pattern"), binding.field("value"))
        else {
            continue;
        };
        if pattern.kind().as_ref() != "identifier"
            || construct.kind().as_ref() != "call_expression"
            || !rust_buffer_initialization::runtime_path(&binding, helper)
        {
            continue;
        }
        if body.dfs().any(|n| {
            n.kind().as_ref() == "identifier"
                && n.range().start >= binding.range().end
                && n.text() == pattern.text()
        }) {
            continue;
        }
        let Some(ctor) = construct
            .field("function")
            .filter(|n| n.kind().as_ref() == "identifier")
        else {
            continue;
        };
        if helper.dfs().any(|n| {
            n.field("pattern")
                .is_some_and(|p| p.dfs().any(|n| n.text() == ctor.text()))
        }) {
            continue;
        }
        let structs: Vec<_> = named(&body)
            .filter(|n| {
                n.kind().as_ref() == "struct_item"
                    && enabled(n)
                    && n.field("name")
                        .is_some_and(|name| name.text() == ctor.text())
            })
            .collect();
        let [guard] = structs.as_slice() else {
            continue;
        };
        let Some(fields) = guard
            .field("body")
            .filter(|n| n.kind().as_ref() == "ordered_field_declaration_list")
        else {
            continue;
        };
        let fields: Vec<_> = named(&fields).collect();
        let [borrow] = fields.as_slice() else {
            continue;
        };
        if borrow.kind().as_ref() != "reference_type"
            || !borrow
                .children()
                .any(|n| n.kind().as_ref() == "mutable_specifier")
        {
            continue;
        }
        let Some(referent) = borrow.field("type") else {
            continue;
        };
        let element = match referent.kind().as_ref() {
            "array_type" | "slice_type" => {
                referent.field("element").or_else(|| referent.field("type"))
            }
            _ => Some(referent),
        };
        if !element.is_some_and(|ty| {
            rust_raw_memory::canonical(root, &ty, &ty.text()).is_some_and(|name| {
                matches!(
                    name.as_str(),
                    "core::mem::MaybeUninit" | "std::mem::MaybeUninit"
                )
            })
        }) {
            continue;
        }
        let impls: Vec<_> = named(&body)
            .filter(|n| {
                n.kind().as_ref() == "impl_item"
                    && enabled(n)
                    && drop_impl(root, n)
                    && n.field("type")
                        .is_some_and(|ty| ty.field("type").unwrap_or(ty).text() == ctor.text())
            })
            .collect();
        let [destructor] = impls.as_slice() else {
            continue;
        };
        let Some(implementation) = destructor.field("body") else {
            continue;
        };
        let Some(drop_method) = named(&implementation).find(|node| {
            enabled(node)
                && node.kind().as_ref() == "function_item"
                && node.field("name").is_some_and(|name| name.text() == "drop")
        }) else {
            continue;
        };
        let Some(raw_drop) = drop_method.dfs().find(|call| {
            enabled(call)
                && owns(call, &drop_method)
                && rust_buffer_initialization::runtime_path(call, &drop_method)
                && rust_raw_memory::api(root, call).is_some_and(|api| {
                    matches!(
                        api.as_str(),
                        "core::ptr::drop_in_place" | "std::ptr::drop_in_place"
                    )
                })
                && call
                    .field("arguments")
                    .and_then(|args| named(&args).next())
                    .is_some_and(|argument| {
                        rust_allocation::method(&argument).is_some_and(|(receiver, name)| {
                            name == "assume_init_mut"
                                && self_path(&receiver).is_some_and(|fields| fields == ["0"])
                        })
                    })
        }) else {
            continue;
        };
        let Some(argument) = construct
            .field("arguments")
            .and_then(|args| named(&args).next())
        else {
            continue;
        };
        let Some(storage) = field_origin(&argument, helper, None, 0) else {
            continue;
        };
        return Some(Guard {
            definition: guard.clone(),
            construction: binding,
            destructor: destructor.clone(),
            raw_drop,
            storage,
        });
    }
    None
}

#[derive(Default)]
struct Owner<'a> {
    methods: BTreeMap<String, Vec<N<'a>>>,
    destructor: Vec<N<'a>>,
}

fn owners<'a>(
    root: &N<'a>,
    path: &str,
    selection: &rust_configuration::Selection,
) -> BTreeMap<String, Owner<'a>> {
    let mut result = BTreeMap::<String, Owner<'a>>::new();
    for item in root.dfs().filter(|n| {
        n.kind().as_ref() == "impl_item"
            && !selection.excluded(path, n.range())
            && !n
                .ancestors()
                .any(|n| matches!(n.kind().as_ref(), "function_item" | "closure_expression"))
    }) {
        let Some(ty) = item.field("type") else {
            continue;
        };
        let owner = result
            .entry(rust_dependencies::type_key(path, selection, &ty))
            .or_default();
        if drop_impl(root, &item) {
            owner.destructor.push(item);
        } else if item.field("trait").is_none() {
            let Some(body) = item.field("body") else {
                continue;
            };
            for function in named(&body).filter(|n| {
                n.kind().as_ref() == "function_item" && !selection.excluded(path, n.range())
            }) {
                if let Some(name) = function.field("name") {
                    owner
                        .methods
                        .entry(name.text().into_owned())
                        .or_default()
                        .push(function);
                }
            }
        }
    }
    result
}

fn local_calls<'a>(function: &N<'a>, enabled: &impl Fn(&N<'a>) -> bool) -> Vec<(N<'a>, String)> {
    if function.range().len() > 32768 || function.dfs().any(|n| n.is_error() || n.is_missing()) {
        return Vec::new();
    }
    function
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression" && owns(n, function) && enabled(n))
        .filter_map(|call| {
            let (receiver, name) = rust_allocation::method(&call)?;
            (receiver.kind().as_ref() == "self"
                && rust_buffer_initialization::runtime_path(&call, function))
            .then_some((call, name))
        })
        .collect()
}

struct Seed<'a> {
    call: N<'a>,
    captures: BTreeMap<String, Capture>,
}

fn route<'a>(
    target: &str,
    calls: &BTreeMap<String, Vec<(N<'a>, String)>>,
    seeds: &BTreeMap<String, Vec<Seed<'a>>>,
    visited: &mut Vec<String>,
) -> Option<(String, Vec<N<'a>>)> {
    if seeds.contains_key(target) {
        return Some((target.into(), Vec::new()));
    }
    if visited.len() >= 3 || visited.iter().any(|name| name == target) {
        return None;
    }
    visited.push(target.into());
    let path = calls.get(target).and_then(|edges| {
        edges.iter().find_map(|(call, callee)| {
            let (seed, mut path) = route(callee, calls, seeds, visited)?;
            path.push(call.clone());
            Some((seed, path))
        })
    });
    visited.pop();
    path
}

fn seed<'a>(
    call: &N<'a>,
    function: &N<'a>,
    helper: &N<'a>,
    guard: &Guard<'a>,
    destructor: &N<'a>,
    project: &rust_module_bindings::Project<'a>,
    file: &'a SourceFile,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<Seed<'a>> {
    let storage = self_path(guard.storage.first()?)?;
    let container = &storage[..storage.len() - 1];
    // A helper that writes the same container's metadata needs its own ordering
    // model. In particular, a pre-drop update cannot certify a late caller update.
    if helper
        .dfs()
        .filter(|n| assignment(n) && owns(n, helper) && enabled(n))
        .any(|n| {
            n.field("left")
                .and_then(|n| self_path(&n))
                .is_some_and(|p| p.len() == storage.len() && p.starts_with(container))
        })
    {
        return None;
    }
    let args = call.field("arguments")?;
    for update in following_updates(call).into_iter().filter(enabled) {
        let Some(left) = update.field("left") else {
            continue;
        };
        let Some(path) = self_path(&left) else {
            continue;
        };
        if path.len() != storage.len() || !path.starts_with(container) || path == storage {
            continue;
        }
        let Some(range) = named(&args).find_map(|arg| extent_origin(&arg, function, &path, 0))
        else {
            continue;
        };
        let Some(types) = rust_receiver_types::extent_field_support(project, &left, function, file)
        else {
            continue;
        };
        let mut captures = BTreeMap::new();
        for (name, node) in [
            ("cleanup_call", call),
            ("cleanup_definition", function),
            ("destruction_helper", helper),
            ("guard_definition", &guard.definition),
            ("guard_construction", &guard.construction),
            ("guard_destructor", &guard.destructor),
            ("element_destruction", &guard.raw_drop),
            ("owner_storage", &guard.storage[0]),
            ("metadata_assignment_00", &update),
            ("owner_destructor", destructor),
        ] {
            captures.insert(name.into(), rust_dependencies::capture(file, node));
        }
        for (index, node) in guard.storage.iter().skip(1).chain(range.iter()).enumerate() {
            captures.insert(
                format!("cleanup_binding_{index:02}"),
                rust_dependencies::capture(file, node),
            );
        }
        for (index, ty) in types.into_iter().enumerate() {
            captures.insert(format!("metadata_type_{index:02}"), ty);
        }
        return Some(Seed {
            call: call.clone(),
            captures,
        });
    }
    None
}

pub(super) fn groups(
    sources: &RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
) -> Vec<ObservationGroup> {
    let project = std::cell::OnceCell::new();
    let mut groups = Vec::new();
    for file in sources.files.values().filter(|f| {
        f.language == Some(Language::Rust)
            && f.source.contains("MaybeUninit")
            && f.source.contains("drop_in_place")
    }) {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        let enabled = |node: &N<'_>| !selection.excluded(&file.path, node.range());
        for owner in owners(&root, &file.path, selection).into_values() {
            let [destructor] = owner.destructor.as_slice() else {
                continue;
            };
            if destructor.range().len() > 16384 {
                continue;
            }
            let methods: BTreeMap<_, _> = owner
                .methods
                .into_iter()
                .filter_map(|(name, mut definitions)| {
                    (definitions.len() == 1).then(|| (name, definitions.remove(0)))
                })
                .collect();
            let guards: BTreeMap<_, _> = methods
                .iter()
                .filter_map(|(name, function)| {
                    if function.range().len() > 8192
                        || function.dfs().any(|n| n.is_error() || n.is_missing())
                    {
                        return None;
                    }
                    Some((name.clone(), scoped_guard(&root, function, &enabled)?))
                })
                .collect();
            if guards.is_empty() {
                continue;
            }
            let calls: BTreeMap<_, _> = methods
                .iter()
                .map(|(name, function)| (name.clone(), local_calls(function, &enabled)))
                .collect();
            let mut seeds = BTreeMap::<String, Vec<Seed<'_>>>::new();
            for (name, edges) in &calls {
                for (call, callee) in edges {
                    let Some(guard) = guards.get(callee) else {
                        continue;
                    };
                    let project = project.get_or_init(|| {
                        rust_module_bindings::Project::build(sources, parsed, selection)
                    });
                    if let Some(seed) = seed(
                        call,
                        &methods[name],
                        &methods[callee],
                        guard,
                        destructor,
                        project,
                        file,
                        &enabled,
                    ) {
                        seeds.entry(name.clone()).or_default().push(seed);
                    }
                }
            }
            if seeds.is_empty() {
                continue;
            }
            for (name, edges) in &calls {
                let function = &methods[name];
                if function.children().any(|n| {
                    n.kind().as_ref() == "function_modifiers" && n.text().contains("unsafe")
                }) {
                    continue;
                }
                for (call, callee) in edges {
                    let mut captures = if let Some(seed) = seeds.get(name).and_then(|seeds| {
                        seeds.iter().find(|seed| seed.call.range() == call.range())
                    }) {
                        seed.captures.clone()
                    } else {
                        let Some((target, path)) =
                            route(callee, &calls, &seeds, &mut vec![name.clone()])
                        else {
                            continue;
                        };
                        if target == *name {
                            continue;
                        }
                        let mut captures = seeds[&target][0].captures.clone();
                        captures.insert(
                            "caller_definition".into(),
                            rust_dependencies::capture(file, function),
                        );
                        for (index, hop) in path.iter().rev().enumerate() {
                            captures.insert(
                                format!("cleanup_handoff_{index:02}"),
                                rust_dependencies::capture(file, hop),
                            );
                        }
                        captures
                    };
                    let operation = rust_dependencies::capture(file, call);
                    if scope.is_some_and(|s| {
                        s.result_policy == "changed_locations"
                            && !crate::impact::location_is_changed(
                                &operation.location,
                                &s.changed_files,
                            )
                    }) {
                        continue;
                    }
                    let location = operation.location.clone();
                    captures.insert("caller_operation".into(), operation);
                    let id = review_admission_marker_id(
                        &file.path,
                        RULE,
                        call.range().start,
                        call.range().end,
                    );
                    groups.push(ObservationGroup {
                        path: file.path.clone(),
                        symbol: name.clone(),
                        anchor_evidence_ids: vec![id.clone()],
                        priority: 1,
                        review_material: is_review_material_path(&file.path),
                        evidence: vec![Evidence {
                            id,
                            rule_id: RULE.into(),
                            kind: EvidenceKind::SensitiveOperation,
                            capability: Capability::RustRawMemoryReview,
                            location,
                            enclosing_symbol: Some(name.clone()),
                            captures,
                            cwe_candidates: vec!["CWE-415".into(), "CWE-416".into()],
                            tags: vec![
                                "review-admission-marker".into(),
                                "rust-panic-cleanup-obligation".into(),
                            ],
                            confidence: Confidence::Medium,
                            provenance: Provenance {
                                resolution: Resolution::Ast,
                                engine: "bounded Rust scoped element destruction and metadata"
                                    .into(),
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
    }
    groups
}
