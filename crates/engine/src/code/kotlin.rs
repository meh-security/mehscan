mod flow;
mod identity;
mod jdbc;
mod network;
pub(crate) use jdbc::prepared_facts;
mod path;
mod project;
pub(super) use flow::{paths, sources};
pub(crate) use project::caller_facts;
pub(crate) use project::member_receiver_facts;
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
                "function_declaration"
                    | "lambda_literal"
                    | "secondary_constructor"
                    | "anonymous_initializer"
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
                "function_declaration" | "secondary_constructor" | "anonymous_initializer"
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
        "kotlin-url-read" | "kotlin-url-connection" => call
            .callee
            .children()
            .find(|n| n.is_named())
            .is_some_and(|receiver| network::known(root, &receiver, "java.net.URL", 8)),
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
            let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
                return false;
            };
            jdbc::receiver(root, imports, &receiver, canonical, 8)
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
    fn jvm_default_imports_do_not_override_explicit_package_wildcards() {
        for source in [
            "fun f(command: String) { Runtime.getRuntime().exec(command) }",
            "import java.lang.*\nfun f(command: String) { Runtime.getRuntime().exec(command) }",
            "import custom.*\nimport java.lang.Runtime\nfun f(command: String) { Runtime.getRuntime().exec(command) }",
            "import custom.*\nimport java.lang.Runtime as JVM\nfun f(command: String) { JVM.getRuntime().exec(command) }",
            "import custom.*\nfun f(command: String) { java.lang.Runtime.getRuntime().exec(command) }",
        ] {
            assert_eq!(count(source, "kotlin-runtime-exec"), 1, "{source}");
        }
        for source in [
            "import custom.*\nfun f(command: String) { Runtime.getRuntime().exec(command) }",
            "import java.lang.*\nimport custom.*\nfun f(command: String) { Runtime.getRuntime().exec(command) }",
        ] {
            assert_eq!(count(source, "kotlin-runtime-exec"), 0, "{source}");
        }
    }

    #[test]
    fn jdbc_factory_identity_is_bounded_and_owned() {
        let initializer = "import java.sql.Connection\nclass C(val connection: Connection) { init { val s = connection.createStatement(); s.executeUpdate(\"CREATE TABLE t (id INT)\") } }";
        assert_eq!(count(initializer, "kotlin-jdbc-statement-query"), 1);
        assert_eq!(
            count(
                "import java.sql.Statement\nfun f(s: Statement?, sql: String) { s!!.executeQuery(sql) }",
                "kotlin-jdbc-statement-query"
            ),
            1
        );
        for body in [
            "val s = connection.createStatement(); s.executeQuery(sql)",
            "connection.createStatement().executeQuery(sql)",
            "val c = connection; val s = c.createStatement(1, 2); val copy = s; copy.executeQuery(sql)",
            "val c = source.getConnection(); val s = c.createStatement(); s.executeQuery(sql)",
            "val c = java.sql.DriverManager.getConnection(url); c.createStatement().executeQuery(sql)",
        ] {
            let source = format!(
                "import java.sql.Connection\nimport javax.sql.DataSource\nfun f(connection: Connection, source: DataSource, sql: String, url: String) {{ {body} }}"
            );
            assert_eq!(count(&source, "kotlin-jdbc-statement-query"), 1, "{source}");
        }
        for body in [
            "val s = fake.createStatement(); s.executeQuery(sql)",
            "var s = connection.createStatement(); s.executeQuery(sql)",
            "var c: Connection = connection; c = fake; val s = c.createStatement(); s.executeQuery(sql)",
            "val s = connection.prepareStatement(sql); s.executeQuery(sql)",
            "val s = connection.createStatement(); run { s.executeQuery(sql) }",
            "val s = connection.createStatement(); fun other() { s.executeQuery(sql) }",
            "val c = DriverManager.getConnection(url); c.createStatement().executeQuery(sql)",
        ] {
            let source = format!(
                "import java.sql.Connection\nimport custom.DriverManager\nfun f(connection: Connection, fake: Other, sql: String, url: String) {{ {body} }}"
            );
            assert_eq!(count(&source, "kotlin-jdbc-statement-query"), 0, "{source}");
        }
    }

    #[test]
    fn url_identity_rejects_lookalikes_mutation_and_unknown_helpers() {
        for source in [
            "import java.net.URI\nfun f(url: String) { URI.create(url).toURL().openStream() }",
            "import java.net.URL as Address\nfun f(url: String) { val a = Address(url); val b = a; b.openStream() }",
            "fun f(a: java.net.URL) { a.openStream() }",
        ] {
            assert_eq!(count(source, "kotlin-url-read"), 1, "{source}");
        }
        for source in [
            "import custom.URI\nfun f(url: String) { URI.create(url).toURL().openStream() }",
            "import java.net.URI\nfun f(URI: Other, url: String) { URI.create(url).toURL().openStream() }",
            "import java.net.URL\nfun f(url: String) { var a = URL(url); a.openStream() }",
            "fun f(url: String) { val a = unknown(url); a.openStream() }",
            "import java.net.URL\nfun f(url: String) { val a = URL(url); run { a.openStream() } }",
        ] {
            assert_eq!(count(source, "kotlin-url-read"), 0, "{source}");
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
    fn explicit_this_uses_member_identity_instead_of_local_types() {
        for (member, local, expected) in
            [("EntityManager", "Other", 1), ("Other", "EntityManager", 0)]
        {
            let source = format!(
                "import jakarta.persistence.EntityManager\nclass C(val em: {member}) {{\n fun f(q: String, other: {local}) {{\n val em: {local} = other\n this.em.createQuery(q)\n }}\n}}"
            );
            assert_eq!(
                count(&source, "kotlin-persistence-query"),
                expected,
                "{source}"
            );
        }
        for body in [
            "fun Other.f(q: String) {\n this.em.createQuery(q)\n }",
            "fun f(q: String) {\n other.apply {\n this.em.createQuery(q)\n }\n }",
            "fun f(q: String) {\n val other = object : Other() {\n fun g() {\n this.em.createQuery(q)\n }\n }\n }",
            "val Other.query: Any\n get() = this.em.createQuery(\"fixed\")",
        ] {
            let source = format!(
                "import jakarta.persistence.EntityManager\nclass C(val em: EntityManager) {{\n {body}\n}}"
            );
            assert_eq!(count(&source, "kotlin-persistence-query"), 0, "{source}");
        }
        let source = "import jakarta.persistence.EntityManager\nclass C(var em: EntityManager) {\n fun f(q: String, other: EntityManager) {\n this.em = other\n this.em.createQuery(q)\n }\n}";
        assert_eq!(count(source, "kotlin-persistence-query"), 0);
        let source = "import jakarta.persistence.EntityManager\nclass C(val em: EntityManager) {\n fun f(q: String, other: Other) {\n var em: Other = other\n em = other\n this.em.createQuery(q)\n }\n}";
        assert_eq!(count(source, "kotlin-persistence-query"), 1);
        let source = "import jakarta.persistence.EntityManager\nclass C(val em: EntityManager) {\n val query: Any\n get() = this.em.createQuery(\"fixed\")\n}";
        assert_eq!(count(source, "kotlin-persistence-query"), 1);
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

    #[test]
    fn generic_parameters_shadow_jvm_imports_only_in_their_owner() {
        for source in [
            "import java.sql.Statement\nclass C<Statement : Other>(val db: Statement) { fun f(q: String) { db.executeQuery(q) } }",
            "import java.sql.Statement\nfun <Statement : Other> f(db: Statement, q: String) { db.executeQuery(q) }",
            "import java.sql.Statement as SQL\nfun <SQL : Other> f(db: SQL, q: String) { db.executeQuery(q) }",
        ] {
            assert_eq!(count(source, "kotlin-jdbc-statement-query"), 0, "{source}");
        }
        for source in [
            "import java.sql.Statement\nfun <Statement : Other> f(db: java.sql.Statement, q: String) { db.executeQuery(q) }",
            "import java.sql.Statement\nclass C<Statement : Other>(val fake: Statement) {}\nfun f(db: Statement, q: String) { db.executeQuery(q) }",
        ] {
            assert_eq!(count(source, "kotlin-jdbc-statement-query"), 1, "{source}");
        }
        let source = "import java.net.URL\nfun <URL : Other> f(url: URL) { url.openStream() }";
        assert_eq!(count(source, "kotlin-url-read"), 0);
        let fixture = include_str!("../../../../tests/fixtures/kotlin-generics/app.kt");
        assert_eq!(count(fixture, "kotlin-jdbc-statement-query"), 2);
        assert_eq!(count(fixture, "kotlin-url-read"), 0);
    }
}
