//! Small source-owned declaration witnesses for Rust parser relationships.
use super::*;
use rust_receiver_types::{lexical_binding, local_binding};
use rust_shared_state::AstNode as N;

pub(super) fn named<'a, 'n>(node: &'n N<'a>) -> impl Iterator<Item = N<'a>> + 'n {
    node.children()
        .filter(|child| child.is_named() && !child.kind().contains("comment"))
}

pub(super) fn peel<'a>(mut value: N<'a>) -> Option<N<'a>> {
    for _ in 0..8 {
        value = match value.kind().as_ref() {
            "parenthesized_expression" | "try_expression" => named(&value).next()?,
            "reference_expression" | "type_cast_expression" => value.field("value")?,
            _ => return Some(value),
        };
    }
    None
}

pub(super) fn literal(node: &N<'_>) -> Option<usize> {
    (node.kind().as_ref() == "integer_literal").then_some(())?;
    let text = node.text().replace('_', "");
    let value = [
        "usize", "u128", "u64", "u32", "u16", "u8", "isize", "i128", "i64", "i32", "i16", "i8",
    ]
    .into_iter()
    .find_map(|suffix| text.strip_suffix(suffix))
    .unwrap_or(&text);
    value.parse().ok()
}

pub(super) fn arguments<'a>(node: &N<'a>) -> Option<Vec<N<'a>>> {
    Some(named(&node.field("arguments")?).collect())
}

pub(super) fn scope<'a>(function: &N<'a>) -> Option<N<'a>> {
    function.ancestors().find(|n| {
        n.kind().as_ref() == "source_file"
            || (n.kind().as_ref() == "declaration_list"
                && n.parent().is_some_and(|p| p.kind().as_ref() == "mod_item"))
    })
}

pub(super) fn enclosing_function<'a>(node: &N<'a>) -> Option<N<'a>> {
    node.ancestors()
        .find(|n| n.kind().as_ref() == "function_item")
}

pub(super) fn private(node: &N<'_>) -> bool {
    !named(node).any(|n| n.kind().as_ref() == "visibility_modifier")
}

pub(super) fn unique<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

pub(super) fn associated<'a>(
    module: &N<'a>,
    owner: &str,
    name: &str,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<N<'a>> {
    // Unqualified owners must be declared in this exact module.
    let record = unique(
        named(module).filter(|n| n.field("name").is_some_and(|n| n.text() == owner) && enabled(n)),
    )?;
    if record.kind().as_ref() != "struct_item" {
        return None;
    }
    unique(
        named(module)
            .filter(|n| {
                n.kind().as_ref() == "impl_item"
                    && enabled(n)
                    && n.field("trait").is_none()
                    && n.field("type").is_some_and(|ty| ty.text() == owner)
            })
            .filter_map(|n| n.field("body"))
            .flat_map(|n| named(&n).collect::<Vec<_>>())
            .filter(|n| {
                n.kind().as_ref() == "function_item"
                    && enabled(n)
                    && n.field("name").is_some_and(|n| n.text() == name)
            }),
    )
}

pub(super) fn scoped_name<'a>(callee: &N<'a>) -> Option<(N<'a>, N<'a>)> {
    (callee.kind().as_ref() == "scoped_identifier").then_some(())?;
    let owner = callee.field("path")?;
    (owner.kind().as_ref() == "identifier").then_some((owner, callee.field("name")?))
}

// Support local free calls, unqualified associated calls and methods on a
// declared local record. Type aliases, trait dispatch and dynamic calls stay open.
pub(super) fn definition<'a>(
    call: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
    depth: usize,
) -> Option<N<'a>> {
    if depth > 6 || call.kind().as_ref() != "call_expression" || !enabled(call) {
        return None;
    }
    let module = scope(function)?;
    let callee = call.field("function")?;
    if let Some((receiver, name)) = rust_allocation::method(call) {
        let (mut ty, _) = declared_type(receiver, function, enabled, depth + 1)?;
        if ty.kind().as_ref() == "reference_type" {
            ty = ty.field("type")?;
        }
        return associated(&module, &ty.text(), &name, enabled);
    }
    if let Some((owner, name)) = scoped_name(&callee) {
        if callee
            .ancestors()
            .take_while(|n| n.range() != module.range())
            .filter(|n| n.kind().as_ref() == "block")
            .any(|n| {
                named(&n).any(|item| {
                    item.kind().as_ref() == "use_declaration"
                        || item.field("name").is_some_and(|n| n.text() == owner.text())
                })
            })
        {
            return None;
        }
        return associated(&module, &owner.text(), &name.text(), enabled);
    }
    if callee.kind().as_ref() != "identifier"
        || local_binding(&callee, function).is_some()
        || callee
            .ancestors()
            .take_while(|n| n.range() != module.range())
            .filter(|n| n.kind().as_ref() == "block")
            .any(|n| {
                named(&n).any(|item| {
                    item.kind().as_ref() == "use_declaration"
                        || item
                            .field("name")
                            .is_some_and(|n| n.text() == callee.text())
                })
            })
    {
        return None;
    }
    unique(named(&module).filter(|n| {
        enabled(n)
            && n.kind().as_ref() == "function_item"
            && n.field("name").is_some_and(|n| n.text() == callee.text())
    }))
}

pub(super) fn declared_type<'a>(
    value: N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
    depth: usize,
) -> Option<(N<'a>, N<'a>)> {
    if depth > 6 || !enabled(&value) {
        return None;
    }
    if value.kind().as_ref() == "try_expression" {
        let (ty, declaration) = declared_type(named(&value).next()?, function, enabled, depth + 1)?;
        return Some((result_value(&ty)?, declaration));
    }
    let value = peel(value)?;
    if value.kind().as_ref() == "identifier" {
        let binding = local_binding(&value, function).filter(enabled)?;
        return if let Some(ty) = binding.field("type") {
            Some((ty, binding))
        } else {
            declared_type(binding.field("value")?, function, enabled, depth + 1)
        };
    }
    let declaration = definition(&value, function, enabled, depth + 1)?;
    Some((declaration.field("return_type")?, declaration))
}

pub(super) fn result_value<'a>(ty: &N<'a>) -> Option<N<'a>> {
    let head = ty.field("type")?;
    if !matches!(
        head.text().as_ref(),
        "Result" | "std::result::Result" | "core::result::Result"
    ) {
        return None;
    }
    named(&ty.field("type_arguments")?).next()
}

pub(super) fn vector<'a>(
    root: &N<'a>,
    ty: &N<'a>,
    local_globs: &impl Fn(&N<'a>) -> Option<Vec<Capture>>,
) -> Option<(N<'a>, Vec<Capture>)> {
    let head = ty.field("type")?;
    let support = if rust_raw_memory::canonical(root, &head, &head.text())
        .is_some_and(|s| matches!(s.as_str(), "std::vec::Vec" | "alloc::vec::Vec"))
    {
        Vec::new()
    } else if head.text() == "Vec" {
        local_globs(&head)?
    } else {
        return None;
    };
    Some((named(&ty.field("type_arguments")?).next()?, support))
}

// The ordinary canonicalizer leaves unqualified prelude names open under
// wildcard imports. Resolve only source-owned crate globs with visible exports.
pub(super) fn prelude_vector_under_globs<'a>(
    project: &rust_module_bindings::Project<'a>,
    file: &'a SourceFile,
    root: &N<'a>,
    head: &N<'a>,
) -> Option<Vec<Capture>> {
    if crate::code::rust_http::canonical(root, head, "Vec")?.0 != "Vec" {
        return None;
    }
    let place = project.locate(file, head.clone());
    let crate_root = project.crate_scope(&place)?;
    let custom_prelude = |n: &N<'a>| {
        n.kind().as_ref() == "inner_attribute_item"
            && (n.text().contains("no_implicit_prelude") || n.text().contains("no_std"))
    };
    if root.children().any(|n| custom_prelude(&n))
        || crate_root.node.children().any(|n| custom_prelude(&n))
    {
        return None;
    }
    let mut support = Vec::new();
    for import in head
        .ancestors()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "block" | "declaration_list" | "source_file"
            )
        })
        .flat_map(|scope| named(&scope).collect::<Vec<_>>())
        .filter(|n| {
            n.kind().as_ref() == "use_declaration"
                && n.dfs().any(|n| n.kind().as_ref() == "use_wildcard")
        })
    {
        let import = place.with_node(import);
        if !project.selected(&import) {
            continue;
        }
        let text = rust_shared_state::compact(&import.node.text());
        let path = text.strip_prefix("usecrate::")?.strip_suffix("::*;")?;
        let parts = path.split("::").collect::<Vec<_>>();
        if parts.len() > 4 {
            return None;
        }
        let mut module = crate_root.clone();
        for part in parts {
            let item = unique(named(&module.node).filter(|n| {
                n.kind().as_ref() == "mod_item"
                    && n.field("name").is_some_and(|n| n.text() == part)
                    && project.selected(&module.with_node(n.clone()))
            }))?;
            module = project.child_scope(&module, &item)?;
        }
        if module.node.dfs().any(|n| n.is_error() || n.is_missing()) {
            return None;
        }
        for item in named(&module.node).filter(|n| project.selected(&module.with_node(n.clone()))) {
            if item.field("name").is_some_and(|n| n.text() == "Vec")
                || matches!(
                    item.kind().as_ref(),
                    "macro_invocation" | "extern_crate_declaration"
                )
                || item
                    .children()
                    .any(|n| n.kind().as_ref() == "macro_invocation")
            {
                return None;
            }
            if item.kind().as_ref() == "use_declaration" {
                let mut bindings = Vec::new();
                rust_shared_state::imports(&item, "", false, &mut bindings);
                if bindings
                    .iter()
                    .any(|(name, _, _)| matches!(name.as_str(), "Vec" | "*"))
                    || item.dfs().any(|n| n.kind().as_ref() == "use_wildcard")
                {
                    return None;
                }
            }
        }
        support.push(import.capture());
        support.extend(project.support(&module));
    }
    (!support.is_empty()).then_some(support)
}

pub(super) fn slice_type<'a>(ty: &N<'a>) -> Option<N<'a>> {
    let ty = ty
        .field("type")
        .filter(|_| ty.kind().as_ref() == "reference_type")?;
    matches!(ty.kind().as_ref(), "slice_type" | "array_type").then_some(ty)
}

pub(super) fn same_binding<'a>(left: &N<'a>, right: &N<'a>, function: &N<'a>) -> bool {
    left.text() == right.text()
        && lexical_binding(left, function)
            .zip(lexical_binding(right, function))
            .is_some_and(|(left, right)| left.range() == right.range())
}

pub(super) fn tuple_type<'a>(
    value: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<(N<'a>, N<'a>)> {
    let binding = lexical_binding(value, function).filter(enabled)?;
    let pattern = binding.field("pattern")?;
    if pattern.kind().as_ref() != "tuple_pattern" {
        return None;
    }
    let index = named(&pattern).position(|part| {
        part.text() == value.text()
            || (part.kind().as_ref() == "mut_pattern"
                && named(&part)
                    .any(|n| n.kind().as_ref() == "identifier" && n.text() == value.text()))
    })?;
    let (ty, declaration) = declared_type(binding.field("value")?, function, enabled, 0)?;
    (ty.kind().as_ref() == "tuple_type").then_some(())?;
    Some((named(&ty).nth(index)?, declaration))
}
