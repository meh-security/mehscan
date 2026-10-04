//! Bounded local JDBC ownership. Locations are context, never safety closure.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, Language, OperandFact, OperandFactKind};

type JNode<'a> = Node<'a, StrDoc<SupportLang>>;

fn owner<'a>(node: &JNode<'a>) -> Option<JNode<'a>> {
    node.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "method_declaration" | "constructor_declaration" | "lambda_expression"
        )
    })
}

fn role(method: &str, count: usize) -> Option<&'static str> {
    match method {
        "execute" | "executeQuery" | "executeUpdate" | "executeLargeUpdate" | "executeBatch"
        | "executeLargeBatch"
            if count == 0 =>
        {
            Some("prepared_statement_execution_context")
        }
        "setString" | "setInt" | "setLong" | "setObject" | "setBoolean" | "setDouble"
        | "setFloat" | "setShort" | "setByte" | "setBytes" | "setNull" | "setDate" | "setTime"
        | "setTimestamp" | "setBigDecimal"
            if count >= 2 =>
        {
            Some("prepared_statement_binding_context")
        }
        "clearParameters" | "addBatch" | "clearBatch" | "close" if count == 0 => {
            Some("prepared_statement_lifecycle_context")
        }
        _ => None,
    }
}

fn operation(node: &JNode<'_>) -> Option<&'static str> {
    role(
        node.field("name")?.text().as_ref(),
        node.field("arguments")?
            .children()
            .filter(|n| n.is_named())
            .count(),
    )
}

fn origin<'a>(scope: &JNode<'a>, expression: &JNode<'a>, depth: usize) -> Option<JNode<'a>> {
    if depth == 0 {
        return None;
    }
    if expression.kind().as_ref() == "method_invocation" {
        return expression
            .field("name")
            .is_some_and(|n| matches!(n.text().as_ref(), "prepareStatement" | "prepareCall"))
            .then(|| expression.clone());
    }
    if expression.kind().as_ref() != "identifier" {
        return None;
    }
    let name = expression.text();
    let bindings = scope
        .dfs()
        .filter(|n| {
            matches!(n.kind().as_ref(), "variable_declarator" | "resource")
                && n.field("name").is_some_and(|n| n.text() == name)
                && n.range().end <= expression.range().start
                && owner(n).map(|n| n.range()) == Some(scope.range())
                && super::context::lexical_declaration_visible_at(n, expression)
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return None;
    };
    // No reassignment, handoff, capture, or unclassified receiver operation
    // between this declaration and the use. Source order is not dominance.
    for use_site in scope.dfs().filter(|n| {
        n.kind().as_ref() == "identifier"
            && n.text() == name
            && n.range().start >= binding.range().end
            && n.range().start < expression.range().start
    }) {
        if owner(&use_site).map(|n| n.range()) != Some(scope.range()) {
            return None;
        }
        let parent = use_site.parent()?;
        let known_receiver = parent.kind().as_ref() == "method_invocation"
            && parent
                .field("object")
                .is_some_and(|n| n.range() == use_site.range())
            && operation(&parent).is_some();
        // A prior alias can escape independently. Resolve its own uses, but
        // do not propagate ownership into later uses of the original receiver.
        if !known_receiver {
            return None;
        }
    }
    origin(scope, &binding.field("value")?, depth - 1)
}

pub(super) fn annotate(language: Language, root: &JNode<'_>, evidence: &mut [Evidence]) {
    if language != Language::Java
        || !evidence.iter().any(|e| e.rule_id == "java-database-query")
        || root.dfs().any(|n| n.is_error() || n.is_missing())
    {
        return;
    }
    let preparations = root
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "method_invocation"
                && n.field("name").is_some_and(|n| {
                    matches!(n.text().as_ref(), "prepareStatement" | "prepareCall")
                })
        })
        .collect::<Vec<_>>();
    for sink in evidence
        .iter_mut()
        .filter(|e| e.rule_id == "java-database-query")
    {
        let Some(preparation) = preparations.iter().find(|n| {
            n.range() == (sink.location.start.byte_offset..sink.location.end.byte_offset)
        }) else {
            continue;
        };
        let Some(connection) = preparation.field("object") else {
            continue;
        };
        if !super::java_persistence::prepared_connection_receiver(root, &connection) {
            continue;
        }
        let Some(scope) = owner(preparation) else {
            continue;
        };
        if scope.range().len() > 32 * 1024
            || scope
                .dfs()
                .filter(|n| n.kind().as_ref() == "method_invocation")
                .take(129)
                .count()
                > 128
        {
            continue;
        }
        let mut facts = Vec::new();
        for call in scope.dfs().filter(|n| {
            n.kind().as_ref() == "method_invocation"
                && n.range().start > preparation.range().start
                && owner(n).is_some_and(|n| n.range() == scope.range())
        }) {
            let Some(role) = operation(&call) else {
                continue;
            };
            let Some(receiver) = call.field("object") else {
                continue;
            };
            if !origin(&scope, &receiver, 4).is_some_and(|n| n.range() == preparation.range()) {
                continue;
            }
            if facts.len() >= 12 || call.range().len() > 4096 {
                facts.clear();
                break;
            }
            facts.push(OperandFact {
                role: role.into(),
                kind: OperandFactKind::PreparedStatementUse,
                location: super::matcher::location(&sink.location.path, &call),
                value: receiver.text().into_owned(),
                remaining_checks: vec!["conditions_order_resets_and_execution".into()],
            });
        }
        sink.context.operand_facts.extend(facts);
    }
}
