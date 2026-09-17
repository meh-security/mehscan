use super::identity::{self, Imports, KNode};

fn receiver<'a>(callee: &KNode<'a>) -> Option<KNode<'a>> {
    (callee.kind().as_ref() == "navigation_expression")
        .then(|| callee.children().find(|n| n.is_named()))?
}

pub(super) fn known_path<'a>(root: &KNode<'a>, expression: &KNode<'a>, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    if expression.kind().as_ref() == "simple_identifier" {
        let symbol = expression.text();
        if !identity::receiver_unchanged(root, expression, &symbol) {
            return false;
        }
        if identity::binding_type(root, expression, &symbol).is_some_and(|ty| {
            Imports::build(root).exact(root, expression, &ty, "java.nio.file.Path")
        }) {
            return true;
        }
        let Some(binding) = identity::binding(root, expression, &symbol) else {
            return false;
        };
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
                    value.range() != binding.range() && known_path(root, &value, depth - 1)
                });
    }
    operands(root, expression, depth - 1).is_some()
}

/// Only canonical JVM Path factories and value-preserving Path operations.
/// Normalization preserves influence; it is not a root-containment protection.
pub(super) fn operands<'a>(
    root: &KNode<'a>,
    expression: &KNode<'a>,
    depth: usize,
) -> Option<Vec<KNode<'a>>> {
    if depth == 0 {
        return None;
    }
    let call = identity::call(expression)?;
    if call.arguments.iter().any(|arg| arg.name.is_some()) {
        return None;
    }
    let observed = call.callee.text();
    let (head, method) = observed.rsplit_once('.')?;
    let imports = Imports::build(root);
    if !call.arguments.is_empty()
        && ((method == "of" && imports.exact(root, expression, head, "java.nio.file.Path"))
            || (method == "get" && imports.exact(root, expression, head, "java.nio.file.Paths")))
    {
        return Some(call.arguments.into_iter().map(|arg| arg.value).collect());
    }
    let receiver = receiver(&call.callee)?;
    if !known_path(root, &receiver, depth - 1) {
        return None;
    }
    let valid = match method {
        "normalize" | "toAbsolutePath" => call.arguments.is_empty(),
        "resolve" | "resolveSibling" => !call.arguments.is_empty(),
        _ => false,
    };
    valid.then(|| {
        std::iter::once(receiver)
            .chain(call.arguments.into_iter().map(|arg| arg.value))
            .collect()
    })
}
