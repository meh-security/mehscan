use super::identity::{self, Imports, KNode};

/// Bounded JVM factory identity, independent of whether SQL is safe or executed.
/// PreparedStatement is deliberately not treated as a text-taking Statement:
/// its inherited SQL-string overloads are prohibited by the JDBC contract.
pub(super) fn receiver<'a>(
    root: &KNode<'a>,
    imports: &Imports,
    expression: &KNode<'a>,
    canonical: &str,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let symbol = expression.text();
    if expression.kind().as_ref() == "postfix_expression" && symbol.ends_with("!!") {
        return expression
            .children()
            .find(|n| n.is_named())
            .is_some_and(|value| receiver(root, imports, &value, canonical, depth - 1));
    }
    if expression.kind().as_ref() == "simple_identifier"
        || expression.kind().as_ref() == "navigation_expression"
            && symbol
                .strip_prefix("this.")
                .is_some_and(|name| !name.is_empty() && !name.contains('.') && !name.contains('?'))
    {
        if !identity::receiver_unchanged(root, expression, &symbol) {
            return false;
        }
        if let Some(ty) = identity::binding_type(root, expression, &symbol) {
            return imports.exact(root, expression, &ty, canonical);
        }
        let Some(binding) = identity::binding(root, expression, &symbol) else {
            return false;
        };
        // Local immutable initializers only. A field can be initialized by a
        // different execution context, which this bounded inference cannot prove.
        if identity::callable(&binding).map(|n| n.range())
            != identity::callable(expression).map(|n| n.range())
            || identity::callable(&binding).is_none()
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
                    value.range() != binding.range()
                        && receiver(root, imports, &value, canonical, depth - 1)
                });
    }
    let Some(call) = identity::call(expression) else {
        return false;
    };
    if call.arguments.iter().any(|arg| arg.name.is_some()) {
        return false;
    }
    let observed = call.callee.text();
    let Some((head, method)) = observed.rsplit_once('.') else {
        return false;
    };
    if canonical == "java.sql.Connection"
        && method == "getConnection"
        && imports.exact(root, expression, head, "java.sql.DriverManager")
    {
        return (1..=3).contains(&call.arguments.len());
    }
    let Some(owner) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    match (canonical, method) {
        ("java.sql.Statement", "createStatement") => {
            matches!(call.arguments.len(), 0 | 2 | 3)
                && receiver(root, imports, &owner, "java.sql.Connection", depth - 1)
        }
        ("java.sql.Connection", "getConnection") => {
            matches!(call.arguments.len(), 0 | 2)
                && receiver(root, imports, &owner, "javax.sql.DataSource", depth - 1)
        }
        _ => false,
    }
}
