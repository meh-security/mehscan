mod flow;
mod identity;
mod project;
pub(super) use flow::{paths, sources};
pub(crate) use project::caller_facts;
mod numeric;
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
}
