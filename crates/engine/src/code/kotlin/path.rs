use super::identity::{self, Imports, KNode};

fn receiver<'a>(callee: &KNode<'a>) -> Option<KNode<'a>> {
    (callee.kind().as_ref() == "navigation_expression")
        .then(|| callee.children().find(|n| n.is_named()))?
}

pub(super) fn known_path<'a>(root: &KNode<'a>, expression: &KNode<'a>, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    if expression.kind().as_ref() == "simple_identifier"
        || expression.kind().as_ref() == "navigation_expression"
            && expression
                .text()
                .strip_prefix("this.")
                .is_some_and(|name| !name.is_empty() && !name.contains('.') && !name.contains('?'))
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    #[test]
    fn explicit_member_paths_do_not_borrow_local_receiver_types() {
        for (member, local, expected) in [("Path", "Other", true), ("Other", "Path", false)] {
            let source = format!(
                "import java.nio.file.Path\nclass C(val root: {member}) {{\n fun f(name: String, other: {local}) {{\n val root: {local} = other\n consume(this.root.resolve(name))\n }}\n}}"
            );
            let ast = SupportLang::Kotlin.ast_grep(&source);
            let root = ast.root();
            assert!(
                !root.dfs().any(|n| n.kind().as_ref() == "ERROR"),
                "{source}"
            );
            let call = root
                .dfs()
                .find_map(|n| {
                    identity::call(&n).filter(|call| call.callee.text().as_ref() == "consume")
                })
                .unwrap();
            assert_eq!(
                known_path(&root, &call.arguments[0].value, 8),
                expected,
                "{source}"
            );
        }
    }
}
