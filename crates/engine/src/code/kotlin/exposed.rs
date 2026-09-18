use super::identity::{self, Imports, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

const TRANSACTION: &str = "org.jetbrains.exposed.v1.jdbc.JdbcTransaction";
const MANAGER: &str = "org.jetbrains.exposed.v1.jdbc.transactions.TransactionManager";
const DSL: &str = "org.jetbrains.exposed.v1.jdbc.transactions.transaction";

fn owned_receiver<'a>(root: &KNode<'a>, node: &KNode<'a>, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    if super::jvm::owned(root, node, TRANSACTION, depth) {
        return true;
    }
    let imports = Imports::build(root);
    if let Some(factory) = identity::call(node) {
        return factory.arguments.is_empty()
            && factory
                .callee
                .text()
                .strip_suffix(".current")
                .is_some_and(|head| imports.exact(root, node, head, MANAGER));
    }
    let symbol = node.text();
    if !identity::receiver_unchanged(root, node, &symbol) {
        return false;
    }
    let Some(binding) = identity::binding(root, node, &symbol) else {
        return false;
    };
    if identity::callable(&binding).map(|n| n.range())
        != identity::callable(node).map(|n| n.range())
    {
        return false;
    }
    let Some(property) = binding
        .parent()
        .filter(|n| n.kind().as_ref() == "property_declaration")
    else {
        return false;
    };
    if !property
        .children()
        .any(|n| n.kind().as_ref() == "binding_pattern_kind" && n.text().as_ref() == "val")
    {
        return false;
    }
    property
        .children()
        .filter(|n| n.is_named())
        .last()
        .is_some_and(|value| {
            value.range() != binding.range() && owned_receiver(root, &value, depth - 1)
        })
}

pub(super) fn accepts<'a>(root: &KNode<'a>, node: &KNode<'a>) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    let text = call.callee.text();
    let imports = Imports::build(root);
    if call.arguments.is_empty() {
        return false;
    }
    // BlockingExecutable overloads are not SQL-string boundaries.
    let sql = &call.arguments[0];
    if sql.name.as_deref().is_some_and(|n| n != "stmt")
        || matches!(
            sql.value.kind().as_ref(),
            "lambda_literal"
                | "object_literal"
                | "integer_literal"
                | "real_literal"
                | "boolean_literal"
                | "null_literal"
                | "character_literal"
        )
        || identity::binding_type(root, &sql.value, &sql.value.text())
            .is_some_and(|ty| !matches!(ty.as_str(), "String" | "kotlin.String"))
    {
        return false;
    }
    if let Some((_, method)) = text.rsplit_once('.') {
        if method != "exec" {
            return false;
        }
        let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
            return false;
        };
        return owned_receiver(root, &receiver, 8);
    }
    if text != "exec" || identity::name_shadowed(root, node, "exec") {
        return false;
    }
    let Some(lambda) = identity::callable(node).filter(|n| n.kind().as_ref() == "lambda_literal")
    else {
        return false;
    };
    let Some(container) = lambda
        .ancestors()
        .skip(1)
        .find(|n| n.kind().as_ref() == "call_expression")
    else {
        return false;
    };
    let Some(owner) = identity::call(&container) else {
        return false;
    };
    owner
        .arguments
        .last()
        .is_some_and(|a| a.value.range() == lambda.range())
        && imports.exact(root, &container, &owner.callee.text(), DSL)
}

/// Keep the scalar producer outside an owned transaction lambda available to
/// source review without asserting native cross-lambda propagation.
pub(crate) fn facts(path: &str, source: &str, anchor: &Evidence) -> Vec<ReviewNeighborhoodFact> {
    if anchor.rule_id != "kotlin-exposed-sql-exec" {
        return vec![];
    }
    let ast = SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(node) = root.dfs().find(|n| {
        n.range() == (anchor.location.start.byte_offset..anchor.location.end.byte_offset)
    }) else {
        return vec![];
    };
    if !accepts(&root, &node) {
        return vec![];
    }
    let Some(function) = node
        .ancestors()
        .find(|n| n.kind().as_ref() == "function_declaration")
    else {
        return vec![];
    };
    if function.range().len() > 16384 {
        return vec![];
    }
    vec![ReviewNeighborhoodFact {
        role: "exposed_containing_function_context".into(),
        symbol: identity::name(&function).unwrap_or_default(),
        location: crate::code::matcher::location(path, &function),
        excerpt: format!(
            "Exact containing function for this owned Exposed SQL-string exec boundary. Inspect SQL construction, argument binding and transaction entry from source; this is not a native cross-lambda path or runtime dispatch proof.\n{}",
            function.text()
        ),
        evidence_id: Some(anchor.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin Exposed v1 JDBC exact SQL boundary and bounded containing function 1"
                .into(),
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_identity_rejects_foreign_factories_mutation_and_receiver_scopes() {
        let imports = "import org.jetbrains.exposed.v1.jdbc.JdbcTransaction as Tx\nimport org.jetbrains.exposed.v1.jdbc.transactions.TransactionManager as M\nimport org.jetbrains.exposed.v1.jdbc.transactions.transaction\n";
        for (body, target, expected) in [
            (
                "fun f(tx: Tx, q: String) { tx.exec(q) }",
                "tx.exec(q)",
                true,
            ),
            (
                "fun f(q: String) { val tx = M.current(); val alias = tx; alias.exec(q) }",
                "alias.exec(q)",
                true,
            ),
            (
                "fun f(q: String) { val tx = helper(); tx.exec(q) }",
                "tx.exec(q)",
                false,
            ),
            (
                "fun f(q: String) { var tx = M.current(); tx.exec(q) }",
                "tx.exec(q)",
                false,
            ),
            ("fun f(tx: Tx) { tx.exec(1) }", "tx.exec(1)", false),
            ("fun f(tx: Tx, q: Int) { tx.exec(q) }", "tx.exec(q)", false),
            (
                "fun f(q: String) { transaction { exec(q) } }",
                "exec(q)",
                true,
            ),
            (
                "fun f(q: String) { transaction { other.apply { exec(q) } } }",
                "exec(q)",
                false,
            ),
            (
                "fun transaction(block: () -> Unit) { block() }\nfun f(q: String) { transaction { exec(q) } }",
                "exec(q)",
                false,
            ),
        ] {
            let source = format!("{imports}{body}");
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let node = root
                .dfs()
                .find(|n| n.kind().as_ref() == "call_expression" && n.text().as_ref() == target)
                .unwrap();
            assert_eq!(accepts(&root, &node), expected, "{body}");
        }
    }
}
