use super::identity::{self, Imports, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

fn interpolations<'a>(
    root: &KNode<'a>,
    node: &KNode<'a>,
    imports: &Imports,
    depth: usize,
) -> Option<Vec<String>> {
    if depth == 0 {
        return None;
    }
    match node.kind().as_ref() {
        "simple_identifier" => {
            let binding = identity::binding(root, node, &node.text())?;
            let property = binding
                .parent()
                .filter(|n| n.kind().as_ref() == "property_declaration")?;
            if !identity::receiver_unchanged(root, node, &node.text())
                || !property.children().any(|n| {
                    n.kind().as_ref() == "binding_pattern_kind" && n.text().as_ref() == "val"
                })
            {
                return None;
            }
            let value = property.children().filter(|n| n.is_named()).last()?;
            if value.range() == binding.range() {
                return None;
            }
            interpolations(root, &value, imports, depth - 1)
        }
        "string_literal" => {
            let mut result = Vec::new();
            for child in node.children().filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "interpolated_identifier" | "interpolated_expression"
                )
            }) {
                let expression = if child.kind().as_ref() == "interpolated_expression" {
                    child.children().find(|n| n.is_named())?
                } else {
                    child
                };
                if !matches!(
                    expression.kind().as_ref(),
                    "simple_identifier" | "interpolated_identifier"
                ) {
                    return None;
                }
                let symbol = expression.text();
                if !identity::receiver_unchanged(root, &expression, &symbol) {
                    return None;
                }
                let ty = identity::binding_type(root, &expression, &symbol)?;
                let canonical = ["kotlin.Byte", "kotlin.Short", "kotlin.Int", "kotlin.Long"]
                    .into_iter()
                    .find(|canonical| imports.exact(root, &expression, &ty, canonical))?;
                result.push(format!("{symbol}: {canonical}"));
            }
            Some(result)
        }
        _ => None,
    }
}

/// Explain a proved scalar representation constraint, scoped only to the
/// captured query operand. Numeric request influence is not SQL syntax influence.
pub(crate) fn query_fact(
    path: &str,
    source: &str,
    sink: &Evidence,
) -> Option<ReviewNeighborhoodFact> {
    if sink.rule_id != "kotlin-persistence-query" {
        return None;
    }
    let capture = sink.captures.get("query")?;
    let ast = SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return None;
    }
    let node = root.dfs().find(|n| {
        n.range().start == capture.location.start.byte_offset
            && n.range().end == capture.location.end.byte_offset
            && n.kind().as_ref() != "value_argument"
    })?;
    let values = interpolations(&root, &node, &Imports::build(&root), 8)?;
    if values.is_empty() {
        return None;
    }
    Some(ReviewNeighborhoodFact {
        role: "numeric_query_operand_context".into(),
        symbol: sink.enclosing_symbol.clone().unwrap_or_default(),
        location: capture.location.clone(),
        excerpt: format!(
            "The captured query operand at {path}:{} contains only these dynamic string-template values: {}. Their exact declared Kotlin integer types produce numeric representations, not caller-selected HQL/SQL delimiters. This constraint applies only to this query operand; it does not protect other queries or establish authorization.",
            capture.location.start.line,
            values.join(", ")
        ),
        evidence_id: Some(sink.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin exact integer string-template representation constraint 1".into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_interpolated_values_must_have_owned_integer_types() {
        for (body, expected) in [
            ("fun f(id: Long) { consume(\"id = $id\") }", true),
            (
                "fun f(id: Long) { val query = \"id = ${id}\"; consume(query) }",
                true,
            ),
            (
                "fun f(id: Long, name: String) { consume(\"id = $id AND name = '$name'\") }",
                false,
            ),
            ("fun f(id: String) { consume(\"id = $id\") }", false),
            (
                "class Long\nfun f(id: Long) { consume(\"id = $id\") }",
                false,
            ),
            ("fun f(id: Long) { consume(\"id = ${helper(id)}\") }", false),
            (
                "fun f(id: Long) { id = helper(); consume(\"id = $id\") }",
                false,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(body);
            let root = ast.root();
            let call = root
                .dfs()
                .find_map(|n| identity::call(&n).filter(|c| c.callee.text().as_ref() == "consume"))
                .unwrap();
            assert_eq!(
                interpolations(&root, &call.arguments[0].value, &Imports::build(&root), 8)
                    .is_some(),
                expected,
                "{body}"
            );
        }
    }
}
