//! Bounded local JDBC ownership. Locations are context, never safety closure.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, Language, OperandFact, OperandFactKind};
use std::collections::BTreeMap;

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

struct PreparedUse<'a> {
    call: JNode<'a>,
    role: &'static str,
    receiver: String,
}

struct ScopeIndex<'a> {
    scope: JNode<'a>,
    within_bound: bool,
    bindings: BTreeMap<String, Vec<JNode<'a>>>,
    references: BTreeMap<String, Vec<JNode<'a>>>,
    uses: BTreeMap<(usize, usize), Vec<PreparedUse<'a>>>,
}

impl<'a> ScopeIndex<'a> {
    fn new(scope: JNode<'a>) -> Self {
        let mut index = Self {
            scope,
            within_bound: false,
            bindings: BTreeMap::new(),
            references: BTreeMap::new(),
            uses: BTreeMap::new(),
        };
        if index.scope.range().len() > 32 * 1024 {
            return index;
        }
        let mut calls = Vec::new();
        let scope = index.scope.clone();
        for node in scope.dfs() {
            match node.kind().as_ref() {
                "method_invocation" => {
                    calls.push(node);
                    // The established budget counts nested callable calls too.
                    if calls.len() > 128 {
                        return index;
                    }
                }
                "variable_declarator" | "resource"
                    if owner(&node).map(|n| n.range()) == Some(index.scope.range()) =>
                {
                    if let Some(name) = node.field("name") {
                        index
                            .bindings
                            .entry(name.text().into_owned())
                            .or_default()
                            .push(node);
                    }
                }
                "identifier" => {
                    // Retain nested references: a capture is an ownership boundary.
                    index
                        .references
                        .entry(node.text().into_owned())
                        .or_default()
                        .push(node);
                }
                _ => (),
            }
        }
        index.within_bound = true;
        for call in calls {
            if owner(&call).map(|n| n.range()) != Some(index.scope.range()) {
                continue;
            }
            let Some(role) = operation(&call) else {
                continue;
            };
            let Some(receiver) = call.field("object") else {
                continue;
            };
            let Some(preparation) = origin(&index, &receiver, 4) else {
                continue;
            };
            if call.range().start <= preparation.range().start {
                continue;
            }
            index
                .uses
                .entry((preparation.range().start, preparation.range().end))
                .or_default()
                .push(PreparedUse {
                    call,
                    role,
                    receiver: receiver.text().into_owned(),
                });
        }
        index
    }
}

fn origin<'a>(index: &ScopeIndex<'a>, expression: &JNode<'a>, depth: usize) -> Option<JNode<'a>> {
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
    let bindings = index
        .bindings
        .get(name.as_ref())
        .into_iter()
        .flatten()
        .filter(|n| {
            matches!(n.kind().as_ref(), "variable_declarator" | "resource")
                && n.field("name").is_some_and(|n| n.text() == name)
                && n.range().end <= expression.range().start
                && super::context::lexical_declaration_visible_at(n, expression)
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return None;
    };
    // No reassignment, handoff, capture, or unclassified receiver operation
    // between this declaration and the use. Source order is not dominance.
    let references = index
        .references
        .get(name.as_ref())
        .map_or(&[][..], Vec::as_slice);
    let start = references.partition_point(|n| n.range().start < binding.range().end);
    let end = references.partition_point(|n| n.range().start < expression.range().start);
    for use_site in &references[start..end] {
        if owner(use_site).map(|n| n.range()) != Some(index.scope.range()) {
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
    origin(index, &binding.field("value")?, depth - 1)
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
        .fold(BTreeMap::new(), |mut index, node| {
            index
                .entry((node.range().start, node.range().end))
                .or_insert(node);
            index
        });
    let receivers = super::java_persistence::DatabaseReceiverIndex::new(root);
    let mut scopes = BTreeMap::new();
    for sink in evidence
        .iter_mut()
        .filter(|e| e.rule_id == "java-database-query")
    {
        let Some(preparation) = preparations.get(&(
            sink.location.start.byte_offset,
            sink.location.end.byte_offset,
        )) else {
            continue;
        };
        let Some(connection) = preparation.field("object") else {
            continue;
        };
        let Some(scope) = owner(preparation) else {
            continue;
        };
        let index = scopes
            .entry((scope.range().start, scope.range().end))
            .or_insert_with(|| ScopeIndex::new(scope));
        if !index.within_bound
            || !super::java_persistence::prepared_connection_receiver(root, &connection, &receivers)
        {
            continue;
        }
        let uses = index
            .uses
            .get(&(preparation.range().start, preparation.range().end))
            .map_or(&[][..], Vec::as_slice);
        if uses.len() > 12
            || uses
                .iter()
                .any(|use_site| use_site.call.range().len() > 4096)
        {
            continue;
        }
        sink.context
            .operand_facts
            .extend(uses.iter().map(|use_site| OperandFact {
                role: use_site.role.into(),
                kind: OperandFactKind::PreparedStatementUse,
                location: super::matcher::location(&sink.location.path, &use_site.call),
                value: use_site.receiver.clone(),
                remaining_checks: vec!["conditions_order_resets_and_execution".into()],
            }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;

    #[test]
    fn prepared_use_index_keeps_capture_alias_and_nested_call_limits() {
        let ast = SupportLang::Java.ast_grep(
            r#"
class C {
    void safe(Connection db, String q) throws Exception {
        PreparedStatement first = db.prepareStatement(q);
        first.setString(1, q);
        first.execute();
        PreparedStatement second = db.prepareStatement(q);
        consume(second);
        second.execute();
        PreparedStatement third = db.prepareStatement(q);
        Runnable captured = () -> consume(third);
        third.execute();
    }
}
"#,
        );
        let root = ast.root();
        let method = root
            .dfs()
            .find(|n| n.kind().as_ref() == "method_declaration")
            .unwrap();
        let index = ScopeIndex::new(method);
        assert!(index.within_bound);
        let counts: Vec<_> = root
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "method_invocation"
                    && n.field("name")
                        .is_some_and(|n| n.text() == "prepareStatement")
            })
            .map(|n| {
                index
                    .uses
                    .get(&(n.range().start, n.range().end))
                    .map_or(0, Vec::len)
            })
            .collect();
        assert_eq!(counts, [2, 0, 0]);
        // A method with nested lambda calls still consumes the established
        // callable-wide budget, even though those uses are not joined outward.
        let text = format!(
            "class C {{void f() {{Runnable r = () -> {{ {} }};}}}}",
            "work();".repeat(129)
        );
        let ast = SupportLang::Java.ast_grep(&text);
        let method = ast
            .root()
            .dfs()
            .find(|n| n.kind().as_ref() == "method_declaration")
            .unwrap();
        assert!(!ScopeIndex::new(method).within_bound);
    }
}
