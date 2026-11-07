//! Bounded parameter-to-allocation review. Admission is not a missing-limit verdict.
use super::*;
use rust_shared_state::AstNode as N;

fn named<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children().filter(|n| n.is_named()).collect()
}

// Resolve immutable same-function bindings by lexical scope. Do not infer through
// mutation, closure dispatch, nested functions or destructuring.
pub(super) fn origin<'a>(expression: &N<'a>, function: &N<'a>, depth: usize) -> Option<N<'a>> {
    if depth > 8 || expression.range().len() > 4096 {
        return None;
    }
    if expression.kind().as_ref() == "identifier" {
        let name = expression.text();
        for scope in expression
            .ancestors()
            .take_while(|n| n.range() != function.range())
        {
            if scope.kind().as_ref() != "block" {
                continue;
            }
            let binding = scope
                .children()
                .filter(|n| {
                    n.kind().as_ref() == "let_declaration"
                        && n.range().end <= expression.range().start
                        && n.field("pattern").is_some_and(|p| {
                            p.dfs()
                                .any(|v| v.kind().as_ref() == "identifier" && v.text() == name)
                        })
                })
                .last();
            if let Some(binding) = binding {
                if binding
                    .field("pattern")
                    .is_none_or(|p| p.kind().as_ref() != "identifier")
                    || binding
                        .children()
                        .any(|n| n.kind().as_ref() == "mutable_specifier")
                {
                    return None;
                }
                return origin(&binding.field("value")?, function, depth + 1);
            }
        }
        // A binding introduced by a loop/conditional pattern is not the outer
        // parameter. Mutable input and writes require a different value model.
        if expression
            .ancestors()
            .take_while(|n| n.range() != function.range())
            .any(|n| {
                n.field("pattern")
                    .is_some_and(|p| p.dfs().any(|v| v.text() == name))
            })
            || function.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "assignment_expression" | "compound_assignment_expr"
                ) && n.range().start < expression.range().start
                    && n.field("left").is_some_and(|p| p.text() == name)
            })
        {
            return None;
        }
        let parameters = function.field("parameters")?;
        return parameters.children().find(|p| {
            p.kind().as_ref() == "parameter"
                && p.field("pattern")
                    .is_some_and(|n| n.kind().as_ref() == "identifier" && n.text() == name)
        });
    }
    if matches!(
        expression.kind().as_ref(),
        "closure_expression" | "block" | "macro_invocation"
    ) {
        return None;
    }
    // Function names and field names are not value dependencies. Receiver values
    // and actual arguments are; the complete enclosing definition is evidence.
    if expression.kind().as_ref() == "call_expression" {
        if let Some((receiver, _)) = method(expression)
            && let Some(p) = origin(&receiver, function, depth + 1)
        {
            return Some(p);
        }
        return expression
            .field("arguments")
            .into_iter()
            .flat_map(|n| named(&n))
            .find_map(|n| origin(&n, function, depth + 1));
    }
    if matches!(
        expression.kind().as_ref(),
        "field_expression" | "type_cast_expression"
    ) {
        return origin(&expression.field("value")?, function, depth + 1);
    }
    named(expression)
        .iter()
        .find_map(|n| origin(n, function, depth + 1))
}

pub(super) fn method<'a>(call: &N<'a>) -> Option<(N<'a>, String)> {
    let mut f = call.field("function")?;
    if f.kind().as_ref() == "generic_function" {
        f = f.field("function")?;
    }
    (f.kind().as_ref() == "field_expression").then_some(())?;
    Some((f.field("value")?, f.field("field")?.text().into_owned()))
}

// Type witnesses only: no dispatch or value-invariant claim. The nearest lexical
// binding wins, and unknown initializers never borrow an outer binding's type.
pub(super) fn receiver_type<'a>(
    root: &N<'a>,
    value: &N<'a>,
    function: &N<'a>,
    depth: usize,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    if matches!(
        value.kind().as_ref(),
        "try_expression" | "reference_expression" | "parenthesized_expression"
    ) {
        return receiver_type(root, &named(value).into_iter().next()?, function, depth + 1);
    }
    if value.kind().as_ref() == "call_expression" {
        if let Some((receiver, name)) = method(value) {
            if matches!(name.as_str(), "unwrap" | "expect") {
                return receiver_type(root, &receiver, function, depth + 1);
            }
            return None;
        }
        let api = rust_raw_memory::api(root, value)?;
        let (owner, constructor) = api.rsplit_once("::")?;
        return (matches!(
            (owner, constructor),
            ("std::vec::Vec" | "alloc::vec::Vec", "new" | "with_capacity")
                | ("tar::Archive" | "zip::ZipArchive", "new")
        ))
        .then(|| owner.into());
    }
    if value.kind().as_ref() != "identifier" {
        return None;
    }
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
            return receiver_type(root, &binding.field("value")?, function, depth + 1);
        }
    }
    if value
        .ancestors()
        .take_while(|n| n.range() != function.range())
        .any(|n| {
            n.field("pattern")
                .is_some_and(|p| p.dfs().any(|n| n.text() == name))
        })
    {
        return None;
    }
    let parameter = function.field("parameters")?.children().find(|p| {
        p.kind().as_ref() == "parameter"
            && p.field("pattern")
                .is_some_and(|p| p.kind().as_ref() == "identifier" && p.text() == name)
    })?;
    let mut ty = parameter.field("type")?;
    while ty.kind().as_ref() == "reference_type" {
        ty = ty.field("type")?;
    }
    rust_raw_memory::canonical(root, &ty, &ty.text())
}

fn repeat_extent<'a>(root: &N<'a>, call: &N<'a>) -> Option<(N<'a>, bool)> {
    let tokens = call
        .children()
        .find(|n| n.kind().as_ref() == "token_tree")?;
    let children = tokens.children().collect::<Vec<_>>();
    let semicolon = children.iter().position(|n| n.text() == ";")?;
    let count = children.get(semicolon + 1)?;
    // The optional primitive cast is interpreted only by the decoded-length
    // path. Do not expand the macro or treat other count expressions as IDs.
    let suffix = &children[semicolon + 2..];
    let (closing, cast) = match suffix {
        [closing] => (closing, false),
        [op, ty, closing] if op.text() == "as" && ty.text() == "usize" => (closing, true),
        _ => return None,
    };
    if count.kind().as_ref() != "identifier" || !matches!(closing.text().as_ref(), "]" | ")" | "}")
    {
        return None;
    }
    let name = call.field("macro")?;
    let (identity, _) = crate::code::rust_http::canonical(root, &name, &name.text())?;
    if !matches!(identity.as_str(), "vec" | "std::vec" | "alloc::vec") {
        return None;
    }
    if identity == "vec"
        && (root.children().any(|n| {
            n.kind().as_ref() == "inner_attribute_item" && n.text().contains("no_implicit_prelude")
        }) || call
            .ancestors()
            .filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "block" | "source_file" | "declaration_list"
                )
            })
            .flat_map(|n| n.children().collect::<Vec<_>>())
            .any(|n| {
                (n.kind().as_ref() == "macro_definition"
                    && n.field("name").is_some_and(|n| n.text() == "vec"))
                    || (n.kind().as_ref() == "use_declaration"
                        && n.dfs().any(|n| n.kind().as_ref() == "use_wildcard"))
            }))
    {
        return None;
    }
    Some((count.clone(), cast))
}

pub(super) fn groups(
    sources: &RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
    handled_extents: &BTreeSet<(String, usize)>,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    let module_bindings = std::cell::OnceCell::new();
    for file in sources
        .files
        .values()
        .filter(|f| f.language == Some(Language::Rust))
    {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        let has_read_exact = file.source.contains("read_exact");
        let has_scalar_read = file.source.contains("read_i32") || file.source.contains("read_i64");
        let api = rust_raw_memory::ApiNames::new(&root, &["with_capacity"]);
        for call in root.dfs().filter(|n| {
            matches!(n.kind().as_ref(), "call_expression" | "macro_invocation")
                && !selection.excluded(&file.path, n.range())
        }) {
            let repeated = if call.kind().as_ref() == "macro_invocation" {
                repeat_extent(&root, &call)
            } else {
                None
            };
            let vector_receiver = method(&call).and_then(|(receiver, name)| {
                matches!(
                    name.as_str(),
                    "reserve"
                        | "reserve_exact"
                        | "try_reserve"
                        | "try_reserve_exact"
                        | "resize"
                        | "resize_with"
                )
                .then_some(receiver)
            });
            // Reject unrelated syntax before resolving a call through lexical
            // imports or walking its entire enclosing function for errors.
            let constructor = api.resolve(&root, &call).is_some_and(|name| {
                matches!(
                    name.as_str(),
                    "std::vec::Vec::with_capacity" | "alloc::vec::Vec::with_capacity"
                )
            });
            if !constructor && repeated.is_none() && vector_receiver.is_none() {
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
            let mut receiver_support = Vec::new();
            let mut receiver_capture = None;
            let vector_method = vector_receiver.is_some_and(|receiver| {
                let project = module_bindings.get_or_init(|| {
                    rust_module_bindings::Project::build(sources, parsed, selection)
                });
                if let Some(support) =
                    rust_receiver_types::vector_support(project, &receiver, &function, file)
                {
                    receiver_capture = Some(rust_dependencies::capture(file, &receiver));
                    receiver_support = support;
                    return true;
                }
                false
            });
            let extent = if constructor || vector_method {
                call.field("arguments")
                    .and_then(|a| named(&a).into_iter().next())
                    .map(|extent| (extent, false))
            } else {
                repeated
            };
            let Some((extent, macro_cast)) = extent else {
                continue;
            };
            if !handled_extents.is_empty()
                && handled_extents.contains(&(file.path.clone(), call.range().start))
            {
                continue;
            }
            let mut input = if let Some(parameter) = (!macro_cast)
                .then(|| origin(&extent, &function, 0))
                .flatten()
            {
                BTreeMap::from([(
                    "input_parameter".into(),
                    rust_dependencies::capture(file, &parameter),
                )])
            } else {
                if !has_read_exact && !has_scalar_read {
                    continue;
                }
                let body = function.text();
                let read_filled = has_read_exact && body.contains("read_exact");
                let scalar_read =
                    has_scalar_read && (body.contains("read_i32") || body.contains("read_i64"));
                if !read_filled && !scalar_read {
                    continue;
                }
                let project = module_bindings.get_or_init(|| {
                    rust_module_bindings::Project::build(sources, parsed, selection)
                });
                let read_evidence = if read_filled {
                    rust_read_extent::evidence(&root, &extent, &call, &function, file, project)
                        .or_else(|| {
                            vector_method.then_some(())?;
                            rust_read_extent::async_field_evidence(
                                &root, &extent, &call, &function, file, project,
                            )
                        })
                } else {
                    None
                };
                let Some(input) = read_evidence.or_else(|| {
                    scalar_read.then_some(())?;
                    rust_read_extent::scalar_field_evidence(
                        &root, &extent, &call, &function, file, project,
                    )
                }) else {
                    continue;
                };
                input
            };
            let location = rust_dependencies::capture(file, &call).location;
            if scope.is_some_and(|s| {
                s.result_policy == "changed_locations"
                    && !crate::impact::location_is_changed(&location, &s.changed_files)
            }) {
                continue;
            }
            let rule = "rust-allocation-extent-review";
            let id =
                review_admission_marker_id(&file.path, rule, call.range().start, call.range().end);
            let symbol = function
                .field("name")
                .map(|n| n.text().into_owned())
                .unwrap_or_default();
            let mut captures = BTreeMap::from([
                ("allocation".into(), rust_dependencies::capture(file, &call)),
                ("extent".into(), rust_dependencies::capture(file, &extent)),
                (
                    "allocation_definition".into(),
                    rust_dependencies::capture(file, &function),
                ),
            ]);
            let mut tags = vec![
                "review-admission-marker".into(),
                "caller-influenced-allocation".into(),
            ];
            if input.contains_key("input_read") {
                tags.push("read-filled-allocation-extent".into());
            }
            if input.contains_key("scalar_length_read") {
                tags.push("signed-wire-allocation-extent".into());
            }
            if input.contains_key("allocation_guard") {
                tags.push("pre-allocation-rejecting-comparison".into());
            }
            captures.append(&mut input);
            if let Some(receiver) = receiver_capture {
                captures.insert("allocation_receiver".into(), receiver);
            }
            for (i, support) in receiver_support.into_iter().enumerate() {
                captures.insert(format!("allocation_type_support_{i:02}"), support);
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
                    capability: Capability::RustAllocationReview,
                    location,
                    enclosing_symbol: Some(symbol),
                    captures,
                    cwe_candidates: vec!["CWE-789".into(), "CWE-400".into()],
                    tags,
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "bounded Rust allocation extent relationship".into(),
                        rule_version: 3,
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
