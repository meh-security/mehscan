use super::identity::{self, Imports, KNode};

pub(super) fn known<'a>(
    root: &KNode<'a>,
    expression: &KNode<'a>,
    canonical: &str,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let symbol = expression.text();
    if expression.kind().as_ref() == "simple_identifier"
        || expression.kind().as_ref() == "navigation_expression"
            && symbol
                .strip_prefix("this.")
                .is_some_and(|name| !name.is_empty() && !name.contains('.') && !name.contains('?'))
    {
        if !identity::receiver_unchanged(root, expression, &symbol) {
            return false;
        }
        let imports = Imports::build(root);
        if let Some(ty) = identity::binding_type(root, expression, &symbol) {
            return imports.exact(root, expression, &ty, canonical);
        }
        let Some(binding) = identity::binding(root, expression, &symbol) else {
            return false;
        };
        if identity::callable(&binding).is_none()
            || identity::callable(&binding).map(|n| n.range())
                != identity::callable(expression).map(|n| n.range())
        {
            return false;
        }
        let Some(property) = binding
            .parent()
            .filter(|n| n.kind().as_ref() == "property_declaration")
        else {
            return false;
        };
        return property
            .children()
            .any(|n| n.kind().as_ref() == "binding_pattern_kind" && n.text().as_ref() == "val")
            && property
                .children()
                .filter(|n| n.is_named())
                .last()
                .is_some_and(|value| {
                    value.range() != binding.range() && known(root, &value, canonical, depth - 1)
                });
    }
    factory(root, expression, canonical, depth - 1).is_some()
}

fn factory<'a>(
    root: &KNode<'a>,
    expression: &KNode<'a>,
    canonical: &str,
    depth: usize,
) -> Option<Vec<KNode<'a>>> {
    if depth == 0 {
        return None;
    }
    let call = identity::call(expression)?;
    if call.arguments.iter().any(|arg| arg.name.is_some()) {
        return None;
    }
    let imports = Imports::build(root);
    let text = call.callee.text();
    if call.arguments.len() == 1 {
        let value = &call.arguments[0].value;
        if super::path::known_path(root, value, depth)
            || known(root, value, "java.net.URL", depth - 1)
            || known(root, value, "java.net.URI", depth - 1)
            || value.kind().as_ref() == "simple_identifier"
                && identity::binding_type(root, value, &value.text())
                    .is_some_and(|ty| !imports.exact(root, value, &ty, "kotlin.String"))
            || matches!(
                value.kind().as_ref(),
                "integer_literal" | "real_literal" | "boolean_literal" | "null_literal"
            )
        {
            return None;
        }
    }
    if call.arguments.len() == 1 && imports.exact(root, expression, &text, canonical) {
        // Only the one-String constructor. Explicit URLStreamHandlers and URL
        // context constructors need their own transport/relative-URL reasoning.
        return Some(call.arguments.into_iter().map(|arg| arg.value).collect());
    }
    let (head, method) = text.rsplit_once('.')?;
    if canonical == "java.net.URI"
        && method == "create"
        && call.arguments.len() == 1
        && imports.exact(root, expression, head, canonical)
    {
        return Some(call.arguments.into_iter().map(|arg| arg.value).collect());
    }
    if canonical == "java.net.URL" && method == "toURL" && call.arguments.is_empty() {
        let receiver = call.callee.children().find(|n| n.is_named())?;
        return known(root, &receiver, "java.net.URI", depth - 1).then_some(vec![receiver]);
    }
    None
}

/// URL/URI construction preserves input; parsing is not destination approval.
pub(super) fn operands<'a>(
    root: &KNode<'a>,
    expression: &KNode<'a>,
    depth: usize,
) -> Option<Vec<KNode<'a>>> {
    factory(root, expression, "java.net.URL", depth)
        .or_else(|| factory(root, expression, "java.net.URI", depth))
}
