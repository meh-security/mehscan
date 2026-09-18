use super::identity::{self, Imports, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

fn prepared_origin<'a>(
    root: &KNode<'a>,
    expression: &KNode<'a>,
    depth: usize,
) -> Option<KNode<'a>> {
    if depth == 0 {
        return None;
    }
    if let Some(call) = identity::call(expression) {
        let text = call.callee.text();
        if matches!(
            text.rsplit('.').next(),
            Some("prepareStatement" | "prepareCall")
        ) {
            return Some(expression.clone());
        }
        return None;
    }
    let symbol = expression.text();
    if !identity::receiver_unchanged(root, expression, &symbol) {
        return None;
    }
    let binding = identity::binding(root, expression, &symbol)?;
    if identity::callable(&binding).map(|n| n.range())
        != identity::callable(expression).map(|n| n.range())
    {
        return None;
    }
    let property = binding
        .parent()
        .filter(|n| n.kind().as_ref() == "property_declaration")?;
    if !property
        .children()
        .any(|n| n.kind().as_ref() == "binding_pattern_kind" && n.text().as_ref() == "val")
    {
        return None;
    }
    let value = property.children().filter(|n| n.is_named()).last()?;
    (value.range() != binding.range())
        .then(|| prepared_origin(root, &value, depth - 1))
        .flatten()
}

/// Exact same-callable use context, never an execution or protection summary.
pub(crate) fn prepared_facts(
    path: &str,
    source: &str,
    sink: &Evidence,
) -> Vec<ReviewNeighborhoodFact> {
    if sink.rule_id != "kotlin-jdbc-prepare-query" {
        return vec![];
    }
    let ast = SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(preparation) = root.dfs().find(|n| {
        n.kind().as_ref() == "call_expression"
            && n.range().start == sink.location.start.byte_offset
            && n.range().end == sink.location.end.byte_offset
    }) else {
        return vec![];
    };
    let Some(scope) = identity::callable(&preparation) else {
        return vec![];
    };
    let imports = Imports::build(&root);
    let rule = "kotlin-jdbc-prepare-query";
    if !super::accept(&root, &imports, rule, &preparation) {
        return vec![];
    }
    let mut facts = Vec::new();
    for node in scope.dfs().filter(|n| {
        n.kind().as_ref() == "call_expression"
            && n.range().start >= preparation.range().start
            && identity::callable(n).is_some_and(|owner| owner.range() == scope.range())
    }) {
        let Some(call) = identity::call(&node) else {
            continue;
        };
        if call.arguments.iter().any(|arg| arg.name.is_some()) {
            continue;
        }
        let text = call.callee.text();
        let Some((_, method)) = text.rsplit_once('.') else {
            continue;
        };
        let role = match method {
            "execute" | "executeQuery" | "executeUpdate" | "executeLargeUpdate"
            | "executeBatch" | "executeLargeBatch"
                if call.arguments.is_empty() =>
            {
                "prepared_statement_execution_context"
            }
            "setString" | "setInt" | "setLong" | "setObject" | "setBoolean" | "setDouble"
            | "setFloat" | "setShort" | "setByte" | "setBytes" | "setNull" | "setDate"
            | "setTimestamp" | "setBigDecimal"
                if call.arguments.len() >= 2 =>
            {
                "prepared_statement_binding_context"
            }
            "clearParameters" | "addBatch" | "clearBatch" | "close"
                if call.arguments.is_empty() =>
            {
                "prepared_statement_lifecycle_context"
            }
            _ => continue,
        };
        let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
            continue;
        };
        if !prepared_origin(&root, &receiver, 8)
            .is_some_and(|origin| origin.range() == preparation.range())
        {
            continue;
        }
        if node.range().len() > 4096 || facts.len() >= 12 {
            return vec![];
        }
        facts.push(ReviewNeighborhoodFact {
            role: role.into(), symbol: receiver.text().into_owned(),
            location: crate::code::matcher::location(path, &node), excerpt: format!("Exact use of this preparation's immutable local receiver in the same callable. This is source context; enclosing conditions, binding resets and runtime execution still require review.\n{}", node.text()),
            evidence_id: Some(sink.id.clone()), provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin bounded prepared receiver origin and same-callable use 1".into() },
        });
    }
    facts
}

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
            return imports.exact(
                root,
                expression,
                ty.split('<').next().unwrap_or(&ty),
                canonical,
            ) || canonical == "javax.sql.PooledConnection"
                && imports.exact(root, expression, &ty, "javax.sql.XAConnection");
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
    if canonical == "org.springframework.jdbc.core.JdbcTemplate"
        && matches!(call.arguments.len(), 0..=2)
        && imports.exact(root, expression, &call.callee.text(), canonical)
    {
        return true;
    }
    if canonical == "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate"
        && call.arguments.len() == 1
        && imports.exact(root, expression, &call.callee.text(), canonical)
    {
        return true;
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
                || call.arguments.is_empty()
                    && receiver(
                        root,
                        imports,
                        &owner,
                        "javax.sql.PooledConnection",
                        depth - 1,
                    )
        }
        ("javax.sql.PooledConnection", "getPooledConnection") => {
            matches!(call.arguments.len(), 0 | 2)
                && receiver(
                    root,
                    imports,
                    &owner,
                    "javax.sql.ConnectionPoolDataSource",
                    depth - 1,
                )
        }
        ("javax.sql.PooledConnection" | "javax.sql.XAConnection", "getXAConnection") => {
            matches!(call.arguments.len(), 0 | 2)
                && receiver(root, imports, &owner, "javax.sql.XADataSource", depth - 1)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_distinguish_real_statements_aliases_and_callable_handoffs() {
        let ast = SupportLang::Kotlin.ast_grep("fun f(c: Connection, q: String) { val first = c.prepareStatement(q); val second = c.prepareStatement(\"SELECT 1\"); val alias = first; second.setString(1, q); alias.executeQuery(); run { first.executeQuery() } }");
        let root = ast.root();
        assert!(!root.dfs().any(|n| n.is_error() || n.is_missing()));
        let mut origins = Vec::new();
        for node in root.dfs() {
            let Some(call) = identity::call(&node) else {
                continue;
            };
            if matches!(
                call.callee.text().as_ref(),
                "second.setString" | "alias.executeQuery" | "first.executeQuery"
            ) {
                let receiver = call.callee.children().find(|n| n.is_named()).unwrap();
                origins.push((
                    call.callee.text().into_owned(),
                    prepared_origin(&root, &receiver, 8).map(|n| n.text().into_owned()),
                ));
            }
        }
        assert_eq!(
            origins,
            vec![
                (
                    "second.setString".into(),
                    Some("c.prepareStatement(\"SELECT 1\")".into())
                ),
                (
                    "alias.executeQuery".into(),
                    Some("c.prepareStatement(q)".into())
                ),
                ("first.executeQuery".into(), None),
            ]
        );
    }
}
