//! Bounded identities for standard native APIs, including visible shadows.
use std::collections::BTreeMap;
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::Language;

#[derive(Clone)]
struct Binding {
    scope: Range<usize>,
    global: bool,
    start: usize,
    target: Option<String>,
    namespace: bool,
}

#[derive(Default)]
pub(crate) struct NativeApiContext {
    bindings: BTreeMap<String, Vec<Binding>>,
    definitions: BTreeMap<String, usize>,
}

impl NativeApiContext {
    pub(crate) fn new(root: &Node<'_, StrDoc<SupportLang>>, language: Language) -> Self {
        if !matches!(language, Language::C | Language::Cpp) {
            return Self::default();
        }
        let mut result = Self::default();
        for node in root.dfs() {
            let kind = node.kind();
            if kind.as_ref() == "function_definition"
                && let Some(name) = node.field("declarator").and_then(|d| declaration_name(&d))
            {
                let mut namespaces = node
                    .ancestors()
                    .filter(|n| n.kind().as_ref() == "namespace_definition")
                    .filter_map(|n| n.field("name").map(|n| compact(n.text().as_ref())))
                    .collect::<Vec<_>>();
                namespaces.reverse();
                namespaces.push(name);
                result
                    .definitions
                    .insert(namespaces.join("::"), node.range().start);
            }
            if kind.as_ref() == "namespace_alias_definition" {
                let text = compact(node.text().as_ref());
                if let Some((name, target)) = text
                    .strip_prefix("namespace")
                    .and_then(|text| text.strip_suffix(';'))
                    .and_then(|text| text.split_once('='))
                    .filter(|(name, _)| identifier(name))
                {
                    result.insert(&node, name, Some(target.to_string()), true);
                }
                continue;
            }
            if kind.as_ref() == "using_declaration" {
                let text = compact(node.text().as_ref());
                if let Some(target) = text.strip_prefix("using").and_then(|s| s.strip_suffix(';'))
                    && let Some((_, name)) = target.rsplit_once("::")
                    && identifier(name)
                {
                    result.insert(&node, name, Some(target.to_string()), false);
                }
                continue;
            }
            if matches!(kind.as_ref(), "preproc_def" | "preproc_function_def") {
                if let Some(name) = node.field("name") {
                    result.insert(&node, name.text().as_ref(), None, false);
                }
                continue;
            }
            if matches!(kind.as_ref(), "declaration" | "field_declaration") {
                for declarator in node.field_children("declarator") {
                    if declarator.kind().as_ref() != "init_declarator"
                        && !function_prototype(&declarator)
                        && let Some(name) = declaration_name(&declarator)
                    {
                        result.insert(&node, &name, None, false);
                    }
                }
                continue;
            }
            let declarator = match kind.as_ref() {
                "parameter_declaration"
                | "optional_parameter_declaration"
                | "init_declarator"
                | "function_definition" => node.field("declarator"),
                "alias_declaration" | "class_specifier" | "struct_specifier" => node.field("name"),
                _ => None,
            };
            let Some(declarator) = declarator else {
                continue;
            };
            let Some(name) = declaration_name(&declarator) else {
                continue;
            };
            let target = if kind.as_ref() == "init_declarator"
                && (declarator.dfs().any(|child| {
                    child.kind().as_ref() == "type_qualifier" && child.text().trim() == "const"
                }) || node.parent().is_some_and(|parent| {
                    parent.children().any(|child| {
                        child.kind().as_ref() == "type_qualifier" && child.text().trim() == "const"
                    })
                })) {
                node.field("value").map(|value| {
                    let value = compact(value.text().as_ref());
                    value.strip_prefix('&').unwrap_or(&value).to_string()
                })
            } else {
                None
            };
            result.insert(&node, &name, target, false);
        }
        result
    }

    pub(crate) fn call_name(&self, call: &Node<'_, StrDoc<SupportLang>>) -> Option<&'static str> {
        let function = call.field("function")?;
        let text = compact(function.text().as_ref());
        if identifier(&text) {
            let mut namespaces = call
                .ancestors()
                .filter(|n| n.kind().as_ref() == "namespace_definition")
                .filter_map(|n| n.field("name").map(|n| compact(n.text().as_ref())))
                .collect::<Vec<_>>();
            namespaces.reverse();
            namespaces.push(text.clone());
            if self.definitions.contains_key(&namespaces.join("::")) {
                return None;
            }
        }
        self.resolve(&text, call.range().start, 0)
    }

    fn resolve(&self, text: &str, offset: usize, depth: usize) -> Option<&'static str> {
        if depth > 4 {
            return None;
        }
        if let Some((prefix, name)) = text.rsplit_once("::") {
            let canonical = standard_name(name)?;
            let prefix = prefix.strip_prefix("::").unwrap_or(prefix);
            if prefix.is_empty() {
                return (!matches!(canonical, "copy" | "copy_n")
                    && !self.global_definition_shadows(name, offset))
                .then_some(canonical);
            }
            if prefix == "std" {
                if self.definitions.contains_key(&format!("std::{name}")) {
                    return None;
                }
                if self
                    .binding("std", offset)
                    .is_some_and(|b| !b.namespace || b.target.as_deref() != Some("std"))
                {
                    return None;
                }
                return standard_namespace_name(canonical).then_some(canonical);
            }
            let binding = self.binding(prefix, offset)?;
            if !binding.namespace {
                return None;
            }
            let target = binding.target.as_deref()?;
            return self.resolve(&format!("{target}::{name}"), offset, depth + 1);
        }
        if !identifier(text) {
            return None;
        }
        if let Some(binding) = self.binding(text, offset) {
            if binding.namespace {
                return None;
            }
            let target = binding.target.as_deref()?;
            if !target.contains("::") {
                return None;
            }
            return self.resolve(target, offset, depth + 1);
        }
        standard_name(text).filter(|name| !matches!(*name, "copy" | "copy_n"))
    }

    fn binding(&self, name: &str, offset: usize) -> Option<&Binding> {
        self.bindings
            .get(name)?
            .iter()
            .filter(|b| b.start <= offset && b.scope.start <= offset && offset < b.scope.end)
            .min_by_key(|b| (b.scope.end - b.scope.start, usize::MAX - b.start))
    }

    fn global_definition_shadows(&self, name: &str, offset: usize) -> bool {
        self.definitions.contains_key(name)
            || self.bindings.get(name).is_some_and(|bindings| {
                bindings
                    .iter()
                    .any(|b| b.global && b.start <= offset && b.target.is_none())
            })
    }

    fn insert(
        &mut self,
        node: &Node<'_, StrDoc<SupportLang>>,
        name: &str,
        target: Option<String>,
        namespace: bool,
    ) {
        let parameter = matches!(
            node.kind().as_ref(),
            "parameter_declaration" | "optional_parameter_declaration"
        );
        if parameter
            && !node.ancestors().any(|ancestor| {
                matches!(
                    ancestor.kind().as_ref(),
                    "function_definition" | "lambda_expression"
                )
            })
        {
            return;
        }
        let scope = node.ancestors().find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "compound_statement"
                    | "field_declaration_list"
                    | "namespace_definition"
                    | "translation_unit"
                    | "for_statement"
                    | "for_range_loop"
                    | "catch_clause"
            ) || parameter
                && matches!(
                    ancestor.kind().as_ref(),
                    "function_definition" | "lambda_expression"
                )
        });
        if let Some(scope) = scope {
            self.bindings
                .entry(name.to_string())
                .or_default()
                .push(Binding {
                    global: scope.kind().as_ref() == "translation_unit",
                    scope: scope.range(),
                    start: node.range().start,
                    target,
                    namespace,
                });
        }
    }
}

fn function_prototype(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.dfs()
        .find(|n| n.kind().as_ref() == "function_declarator")
        .and_then(|n| n.field("declarator"))
        .is_some_and(|n| {
            matches!(
                n.kind().as_ref(),
                "identifier" | "field_identifier" | "qualified_identifier"
            )
        })
}

fn declaration_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if matches!(
        node.kind().as_ref(),
        "identifier" | "type_identifier" | "field_identifier"
    ) {
        return Some(node.text().into_owned());
    }
    if matches!(
        node.kind().as_ref(),
        "qualified_identifier" | "scoped_identifier"
    ) {
        // Out-of-line member definitions do not introduce global API shadows.
        return None;
    }
    if let Some(declarator) = node.field("declarator") {
        return declaration_name(&declarator);
    }
    node.children()
        .filter(|n| n.is_named())
        .find_map(|n| declaration_name(&n))
}

fn standard_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "memcpy" => "memcpy",
        "memmove" => "memmove",
        "memset" => "memset",
        "bcopy" => "bcopy",
        "malloc" => "malloc",
        "calloc" => "calloc",
        "realloc" => "realloc",
        "aligned_alloc" => "aligned_alloc",
        "free" => "free",
        "strdup" => "strdup",
        "strndup" => "strndup",
        "fread" => "fread",
        "copy" => "copy",
        "copy_n" => "copy_n",
        _ => return None,
    })
}

fn standard_namespace_name(name: &str) -> bool {
    !matches!(name, "bcopy" | "strdup" | "strndup")
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphabetic() || b == b'_' || i > 0 && b.is_ascii_digit())
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;

    fn names(source: &str) -> Vec<Option<&'static str>> {
        let ast = SupportLang::Cpp.ast_grep(source);
        let root = ast.root();
        assert!(
            !root.dfs().any(|n| n.kind().as_ref() == "ERROR"),
            "{source}"
        );
        let context = NativeApiContext::new(&root, Language::Cpp);
        root.dfs()
            .filter(|n| n.kind().as_ref() == "call_expression")
            .map(|n| context.call_name(&n))
            .collect()
    }

    #[test]
    fn standard_qualifications_aliases_and_algorithm_names_keep_identity() {
        assert_eq!(
            names(
                r#"
            namespace crt = std;
            namespace runtime = crt;
            using std::memmove;
            void run() {
                memcpy(dst, src, len);
                ::memcpy(dst, src, len);
                std::memcpy(dst, src, len);
                ::std::memcpy(dst, src, len);
                crt::memcpy(dst, src, len);
                runtime::memcpy(dst, src, len);
                memmove(dst, src, len);
                const auto copier = std::memcpy;
                copier(dst, src, len);
                std::copy_n(src, len, dst);
            }
        "#
            ),
            vec![Some("memcpy"); 6]
                .into_iter()
                .chain([Some("memmove"), Some("memcpy"), Some("copy_n")])
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn lexical_shadows_and_lookalikes_are_not_library_effects() {
        assert_eq!(
            names(
                r#"
            namespace other = project;
            void run(void (*memcpy)(void*, void*, unsigned)) {
                memcpy(dst, src, len);
                std::memcpy(dst, src, len);
                other::memcpy(dst, src, len);
                project::memcpy(dst, src, len);
                object.memcpy(dst, src, len);
                copy_n(src, len, dst);
                ::copy_n(src, len, dst);
                auto copier = std::memcpy;
                copier(dst, src, len);
                { int memmove; memmove(dst, src, len); }
                memmove(dst, src, len);
            }
        "#
            ),
            vec![
                None,
                Some("memcpy"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("memmove")
            ]
        );
    }

    #[test]
    fn source_defined_functions_do_not_gain_standard_contracts() {
        assert_eq!(
            names(
                r#"
            void memcpy(void*, void*, unsigned) {}
            namespace std { void memmove(void*, void*, unsigned) {} }
            void run() {
                memcpy(dst, src, len);
                ::memcpy(dst, src, len);
                std::memmove(dst, src, len);
                std::memcpy(dst, src, len);
            }
        "#
            ),
            vec![None, None, None, Some("memcpy")]
        );
    }

    #[test]
    fn library_prototypes_do_not_shadow_but_function_pointer_variables_do() {
        assert_eq!(
            names(
                r#"
            void *memcpy(void *out, const void *input, unsigned size);
            void run() {
                memcpy(dst, src, len);
                { void (*memcpy)(void*, void*, unsigned); memcpy(dst, src, len); }
                { int first, memmove; memmove(dst, src, len); }
                const auto * const copier = &std::memcpy;
                copier(dst, src, len);
            }
        "#
            ),
            vec![Some("memcpy"), None, None, Some("memcpy")]
        );
    }
}
