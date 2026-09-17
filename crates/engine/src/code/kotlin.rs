mod flow;
mod identity;
mod project;
pub(super) use flow::{paths, sources};
pub(crate) use project::caller_facts;
mod numeric;
pub(crate) use numeric::constant_query_fact;
pub(crate) use numeric::query_fact;

pub(super) use identity::Imports;
use identity::{KNode, binding_type, receiver_unchanged};

pub(crate) fn callable_range(source: &str, offset: usize) -> Option<std::ops::Range<usize>> {
    use ast_grep_core::tree_sitter::LanguageExt;
    let ast = ast_grep_language::SupportLang::Kotlin.ast_grep(source);
    ast.root()
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "function_declaration" | "lambda_literal" | "secondary_constructor"
            )
        })
        .map(|n| n.range())
        .filter(|r| r.contains(&offset))
        .min_by_key(|r| r.len())
}

pub(crate) fn function_range(source: &str, offset: usize) -> Option<std::ops::Range<usize>> {
    use ast_grep_core::tree_sitter::LanguageExt;
    let ast = ast_grep_language::SupportLang::Kotlin.ast_grep(source);
    ast.root()
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "function_declaration" | "secondary_constructor"
            )
        })
        .map(|n| n.range())
        .filter(|r| r.contains(&offset))
        .min_by_key(|r| r.len())
}

/// Resolve each boundary at its lexical use site, including local shadows.
pub(super) fn accept<'a>(
    root: &KNode<'a>,
    imports: &Imports,
    rule: &str,
    node: &KNode<'a>,
) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    if call
        .arguments
        .iter()
        .any(|arg| arg.name.is_some() || arg.value.is_missing())
    {
        return false;
    }
    let observed = call.callee.text();
    let Some((receiver, method)) = observed.rsplit_once('.') else {
        return false;
    };
    match rule {
        "kotlin-runtime-exec" => receiver
            .strip_suffix(".getRuntime()")
            .is_some_and(|r| imports.exact(root, node, r, "java.lang.Runtime")),
        "kotlin-files-read" | "kotlin-files-write" => {
            imports.exact(root, node, receiver, "java.nio.file.Files")
        }
        "kotlin-message-digest" => {
            imports.exact(root, node, receiver, "java.security.MessageDigest")
        }
        "kotlin-uri-parsing" => imports.exact(root, node, receiver, "java.net.URI"),
        "kotlin-jdbc-statement-query"
        | "kotlin-jdbc-prepare-query"
        | "kotlin-jdbc-template-query" => {
            let Some(query) = call.arguments.first().map(|arg| &arg.value) else {
                return false;
            };
            if matches!(
                query.kind().as_ref(),
                "lambda_literal" | "anonymous_function"
            ) {
                return false;
            }
            if query.kind().as_ref() == "simple_identifier" {
                if binding_type(root, query, &query.text())
                    .is_some_and(|ty| !imports.exact(root, query, &ty, "kotlin.String"))
                {
                    return false;
                }
            }
            let canonical = match rule {
                "kotlin-jdbc-statement-query" => "java.sql.Statement",
                "kotlin-jdbc-prepare-query" => "java.sql.Connection",
                _ => "org.springframework.jdbc.core.JdbcTemplate",
            };
            receiver_unchanged(root, node, receiver)
                && binding_type(root, node, receiver)
                    .is_some_and(|ty| imports.exact(root, node, &ty, canonical))
        }
        "kotlin-persistence-query" => {
            matches!(method, "createQuery" | "createNativeQuery")
                && receiver_unchanged(root, node, receiver)
                && binding_type(root, node, receiver).is_some_and(|ty| {
                    [
                        "javax.persistence.EntityManager",
                        "jakarta.persistence.EntityManager",
                    ]
                    .iter()
                    .any(|canonical| imports.exact(root, node, &ty, canonical))
                })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    fn count(source: &str, rule: &str) -> usize {
        let ast = SupportLang::Kotlin.ast_grep(source);
        let root = ast.root();
        let imports = Imports::build(&root);
        root.dfs()
            .filter(|n| accept(&root, &imports, rule, n))
            .count()
    }

    #[test]
    fn imported_boundaries_respect_aliases_and_lexical_shadows() {
        for source in [
            "import java.nio.file.Files\nfun f(p: Path) { Files.readString(p) }",
            "import java.nio.file.Files as Disk\nfun f(p: Path) { Disk.readString(p) }",
            "import java.nio.file.*\nfun f(p: Path) { Files.readString(p) }",
            "fun f(p: Path) { java.nio.file.Files.readString(p) }\nfun other(java: Client) {}",
            "import java.nio.file.Files\nfun f(p: Path) { items.map { Files -> Files.readString(p) }; Files.readString(p) }",
            "import java.nio.file.Files\nfun f(p: Path) { for (Files in items) { Files.readString(p) }; Files.readString(p) }",
        ] {
            assert_eq!(count(source, "kotlin-files-read"), 1, "{source}");
        }
        for source in [
            "import demo.Files\nfun f(p: Path) { Files.readString(p) }",
            "import java.nio.file.Files\nfun f(Files: Client) { Files.readString(p) }",
            "import java.nio.file.Files\nfun f(p: Path) { val Files = client; Files.readString(p) }",
            "fun f(p: Path) { java.nio.file.Files.readString(p) }\nval java = client",
            "import java.nio.file.*\nimport demo.*\nfun f(p: Path) { Files.readString(p) }",
            "import java.nio.file.Files\nfun f(p: Path) { items.map { Files -> Files.readString(p) } }",
            "import java.nio.file.Files\nfun f(p: Path) { try {} catch (Files: Error) { Files.readString(p) } }",
        ] {
            assert_eq!(count(source, "kotlin-files-read"), 0, "{source}");
        }
    }

    #[test]
    fn persistence_receiver_identity_is_owned_and_not_reassigned() {
        for source in [
            "import jakarta.persistence.EntityManager\nfun f(em: EntityManager, q: String) { em.createQuery(q) }",
            "import javax.persistence.EntityManager as EM\nclass C(val em: EM) { fun f(q: String) { em.createQuery(q) } }",
            "import jakarta.persistence.EntityManager\nclass C { val em: EntityManager? = null; fun f(q: String) { em!!.createQuery(q) } }",
        ] {
            assert_eq!(count(source, "kotlin-persistence-query"), 1, "{source}");
        }
        for source in [
            "import demo.EntityManager\nfun f(em: EntityManager, q: String) { em.createQuery(q) }",
            "import jakarta.persistence.EntityManager\nclass C(val em: EntityManager) { fun f(q: String) { val em = other; em.createQuery(q) } }",
            "import jakarta.persistence.EntityManager\nfun f(em: EntityManager, q: String) { em = other; em.createQuery(q) }",
            "import jakarta.persistence.EntityManager\nfun f(em: EntityManager) {}\nfun g(em: Other, q: String) { em.createQuery(q) }",
        ] {
            assert_eq!(count(source, "kotlin-persistence-query"), 0, "{source}");
        }
    }

    #[test]
    fn jdbc_ownership_excludes_lookalikes_prepared_values_and_reassigned_receivers() {
        for (rule, canonical, method) in [
            (
                "kotlin-jdbc-statement-query",
                "java.sql.Statement",
                "executeQuery",
            ),
            (
                "kotlin-jdbc-prepare-query",
                "java.sql.Connection",
                "prepareStatement",
            ),
            (
                "kotlin-jdbc-template-query",
                "org.springframework.jdbc.core.JdbcTemplate",
                "queryForList",
            ),
        ] {
            let source = format!(
                "import {canonical} as SQL\nfun f(db: SQL, query: String) {{ db.{method}(query) }}"
            );
            assert_eq!(count(&source, rule), 1);
            for source in [
                format!("import fake.SQL\nfun f(db: SQL, query: String) {{ db.{method}(query) }}"),
                format!(
                    "import {canonical} as SQL\nfun f(db: SQL, query: String) {{ val db = unknown; db.{method}(query) }}"
                ),
                format!(
                    "import {canonical} as SQL\nfun f(db: SQL, query: String) {{ db = other; db.{method}(query) }}"
                ),
                format!(
                    "import {canonical} as SQL\nfun other(db: SQL) {{}}\nfun f(db: Unknown, query: String) {{ db.{method}(query) }}"
                ),
            ] {
                assert_eq!(count(&source, rule), 0, "{source}");
            }
        }
        assert_eq!(
            count(
                "import java.sql.PreparedStatement\nfun f(db: PreparedStatement, value: String) { db.setString(1, value); db.executeQuery() }",
                "kotlin-jdbc-statement-query"
            ),
            0
        );
        assert_eq!(
            count(
                "import org.springframework.jdbc.core.JdbcTemplate\nimport org.springframework.jdbc.core.PreparedStatementCreator\nfun f(db: JdbcTemplate, callback: PreparedStatementCreator) { db.update(callback) }",
                "kotlin-jdbc-template-query"
            ),
            0
        );
    }
}
