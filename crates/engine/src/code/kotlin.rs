use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;

/// Only explicit JVM package paths are currently modeled. A local `java`
/// binding can turn the same syntax into an unrelated receiver chain. Reject
/// the entire file conservatively rather than infer Kotlin lexical scopes.
pub(super) fn has_package_shadow(root: &Node<'_, StrDoc<SupportLang>>) -> bool {
    root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "simple_identifier" | "identifier" | "type_identifier"
        ) && node.text().as_ref() == "java"
            && node.parent().is_some_and(|ancestor| {
                matches!(
                    ancestor.kind().as_ref(),
                    "variable_declaration"
                        | "parameter"
                        | "class_parameter"
                        | "type_alias"
                        | "class_declaration"
                        | "object_declaration"
                )
            })
    }) || root.dfs().any(|node| {
        node.kind().as_ref() == "import_header"
            && node.text().split_whitespace().last() == Some("java")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;

    #[test]
    fn distinguishes_package_paths_from_local_bindings() {
        for source in [
            "val java = client\njava.nio.file.Files.readString(path)",
            "fun f(java: Client) { java.lang.Runtime.getRuntime().exec(cmd) }",
            "class C(val java: Client)",
            "object java {}",
            "class java {}",
            "import demo.Client as java",
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            assert!(has_package_shadow(&ast.root()), "{source}");
        }
        for source in [
            "class C { fun f() { java.nio.file.Files.readString(path) } }",
            "val result = java.nio.file.Files.readString(path)",
            "fun f(path: java.nio.file.Path) { java.nio.file.Files.readString(path) }",
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            assert!(!has_package_shadow(&ast.root()), "{source}");
        }
    }
}
