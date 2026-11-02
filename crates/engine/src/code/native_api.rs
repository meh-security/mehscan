//! Bounded identities for standard native APIs, including visible shadows.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::Language;

#[derive(Clone)]
struct Binding {
    scope: Range<usize>,
    local: bool,
    target: Option<String>,
    namespace: bool,
}

#[derive(Default)]
pub(crate) struct NativeApiContext {
    bindings: BTreeMap<String, BTreeMap<(usize, usize), BTreeMap<usize, Binding>>>,
    definitions: BTreeMap<String, usize>,
    macros: BTreeMap<String, usize>,
    call_aliases: BTreeSet<String>,
    global_scope: (usize, usize),
    namespace_imports: BTreeMap<(usize, usize), bool>,
}

impl NativeApiContext {
    pub(crate) fn new(root: &Node<'_, StrDoc<SupportLang>>, language: Language) -> Self {
        if !matches!(language, Language::C | Language::Cpp) {
            return Self::default();
        }
        let mut result = Self::default();
        result.global_scope = (root.range().start, root.range().end);
        for node in root.dfs() {
            let kind = node.kind();
            if kind.as_ref() == "namespace_definition"
                && let Some(name) = node.field("name").filter(|n| identifier(n.text().as_ref()))
            {
                let global_std = name.text().trim() == "std"
                    && !node
                        .ancestors()
                        .any(|n| n.kind().as_ref() == "namespace_definition");
                result.insert(
                    &node,
                    name.text().as_ref(),
                    global_std.then(|| "std".to_string()),
                    true,
                );
            }
            if kind.as_ref() == "function_definition"
                && let Some(name) = node.field("declarator").and_then(|d| function_name(&d))
            {
                let mut namespaces = node
                    .ancestors()
                    .filter(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "namespace_definition" | "class_specifier" | "struct_specifier"
                        )
                    })
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
                if let Some(target) = text
                    .strip_prefix("usingnamespace")
                    .and_then(|s| s.strip_suffix(';'))
                {
                    if let Some(scope) = node.ancestors().find(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "compound_statement" | "namespace_definition" | "translation_unit"
                        )
                    }) {
                        let foreign = target != "std" && target != "::std";
                        *result
                            .namespace_imports
                            .entry((scope.range().start, scope.range().end))
                            .or_default() |= foreign;
                    }
                    continue;
                }
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
                    // Preprocessing names are not confined to C/C++ lexical
                    // scopes. Without expansion, even an undefined or
                    // conditional macro leaves the contract unproven.
                    result
                        .macros
                        .entry(name.text().into_owned())
                        .or_insert(node.range().start);
                    result.insert(&node, name.text().as_ref(), None, false);
                }
                continue;
            }
            if matches!(kind.as_ref(), "declaration" | "field_declaration") {
                for declarator in node.field_children("declarator") {
                    if kind.as_ref() == "declaration" && function_prototype(&declarator) {
                        let mut namespaces = node
                            .ancestors()
                            .filter(|n| n.kind().as_ref() == "namespace_definition")
                            .filter_map(|n| n.field("name").map(|n| compact(n.text().as_ref())))
                            .collect::<Vec<_>>();
                        namespaces.reverse();
                        if !namespaces.is_empty()
                            && namespaces != ["std"]
                            && let Some(name) = declaration_name(&declarator)
                        {
                            namespaces.push(name);
                            result
                                .definitions
                                .insert(namespaces.join("::"), node.range().start);
                        }
                    }
                    if declarator.kind().as_ref() != "init_declarator"
                        && (kind.as_ref() == "field_declaration"
                            || !function_prototype(&declarator))
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
            let target = if kind.as_ref() == "init_declarator" && constant_alias(&node, &declarator)
            {
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
        let unqualified = identifier(&text);
        if unqualified && standard_name(&text).is_none() && !self.call_aliases.contains(&text) {
            return None;
        }
        let scopes = call
            .ancestors()
            .map(|node| (node.range().start, node.range().end))
            .collect::<Vec<_>>();
        let local_alias = unqualified
            && self
                .binding(&text, call.range().start, &scopes)
                .is_some_and(|b| b.local && b.target.is_some());
        if unqualified && !local_alias {
            if scopes.iter().any(|scope| {
                self.namespace_imports.get(scope).is_some_and(|foreign| {
                    *foreign || self.definitions.contains_key(&format!("std::{text}"))
                })
            }) || call.ancestors().any(|node| {
                matches!(node.kind().as_ref(), "class_specifier" | "struct_specifier")
                    && node
                        .children()
                        .any(|child| child.kind().as_ref() == "base_class_clause")
            }) {
                return None;
            }
            let mut namespaces = call
                .ancestors()
                .filter(|n| n.kind().as_ref() == "namespace_definition")
                .filter_map(|n| n.field("name").map(|n| compact(n.text().as_ref())))
                .collect::<Vec<_>>();
            namespaces.reverse();
            loop {
                let key = namespaces
                    .iter()
                    .map(String::as_str)
                    .chain([text.as_str()])
                    .collect::<Vec<_>>()
                    .join("::");
                if self.definitions.contains_key(&key) {
                    return None;
                }
                if namespaces.pop().is_none() {
                    break;
                }
            }
        }
        self.resolve(&text, call.range().start, &scopes, 0)
    }

    pub(super) fn local_shadow(&self, call: &Node<'_, StrDoc<SupportLang>>, name: &str) -> bool {
        let Some(function) = call.ancestors().find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_definition" | "lambda_expression"
            )
        }) else {
            return false;
        };
        let scopes = call
            .ancestors()
            .map(|node| (node.range().start, node.range().end))
            .collect::<Vec<_>>();
        self.binding(name, call.range().start, &scopes)
            .is_some_and(|binding| {
                function.range().start <= binding.scope.start
                    && binding.scope.end <= function.range().end
            })
    }

    fn resolve(
        &self,
        text: &str,
        offset: usize,
        scopes: &[(usize, usize)],
        depth: usize,
    ) -> Option<&'static str> {
        if depth > 4 {
            return None;
        }
        if let Some((prefix, name)) = text.rsplit_once("::") {
            if self.macro_precedes(name, offset) {
                return None;
            }
            let canonical = standard_name(name)?;
            let prefix = prefix.strip_prefix("::").unwrap_or(prefix);
            if self.macro_precedes(prefix, offset) {
                return None;
            }
            if prefix.is_empty() {
                return (!matches!(canonical, "copy" | "copy_n")
                    && !self.global_definition_shadows(name, offset))
                .then_some(canonical);
            }
            if prefix == "std" {
                if self.definitions.contains_key(&format!("std::{name}")) {
                    return None;
                }
                let std_binding = if text.starts_with("::") {
                    self.bindings
                        .get("std")
                        .and_then(|bindings| bindings.get(&self.global_scope))
                        .and_then(|bindings| {
                            bindings
                                .range(..=offset)
                                .next_back()
                                .map(|(_, binding)| binding)
                        })
                } else {
                    self.binding("std", offset, scopes)
                };
                if std_binding.is_some_and(|b| !b.namespace || b.target.as_deref() != Some("std")) {
                    return None;
                }
                return standard_namespace_name(canonical).then_some(canonical);
            }
            let binding = self.binding(prefix, offset, scopes)?;
            if !binding.namespace {
                return None;
            }
            let target = binding.target.as_deref()?;
            return self.resolve(&format!("{target}::{name}"), offset, scopes, depth + 1);
        }
        if !identifier(text) {
            return None;
        }
        if self.macro_precedes(text, offset) {
            return None;
        }
        if let Some(binding) = self.binding(text, offset, scopes) {
            if binding.namespace {
                return None;
            }
            let target = binding.target.as_deref()?;
            if !target.contains("::") {
                return None;
            }
            return self.resolve(target, offset, scopes, depth + 1);
        }
        standard_name(text).filter(|name| !matches!(*name, "copy" | "copy_n"))
    }

    fn macro_precedes(&self, name: &str, offset: usize) -> bool {
        self.macros.get(name).is_some_and(|start| *start <= offset)
    }

    fn binding(&self, name: &str, offset: usize, scopes: &[(usize, usize)]) -> Option<&Binding> {
        let bindings = self.bindings.get(name)?;
        scopes.iter().find_map(|scope| {
            bindings
                .get(scope)?
                .range(..=offset)
                .next_back()
                .map(|(_, binding)| binding)
        })
    }

    fn global_definition_shadows(&self, name: &str, offset: usize) -> bool {
        self.definitions.contains_key(name)
            || self.bindings.get(name).is_some_and(|bindings| {
                bindings.get(&self.global_scope).is_some_and(|bindings| {
                    bindings.range(..=offset).any(|(_, b)| b.target.is_none())
                })
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
            if target.is_some() && !namespace {
                self.call_aliases.insert(name.to_string());
            }
            let start = if scope.kind().as_ref() == "field_declaration_list" {
                scope.range().start
            } else {
                node.range().start
            };
            self.bindings
                .entry(name.to_string())
                .or_default()
                .entry((scope.range().start, scope.range().end))
                .or_default()
                .insert(
                    start,
                    Binding {
                        scope: scope.range(),
                        local: !matches!(
                            scope.kind().as_ref(),
                            "namespace_definition" | "translation_unit" | "field_declaration_list"
                        ),
                        // C++ member declarations are visible throughout the class,
                        // including bodies preceding their textual declaration.
                        target,
                        namespace,
                    },
                );
        }
    }
}

fn constant_alias(
    node: &Node<'_, StrDoc<SupportLang>>,
    declarator: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let mut current = declarator.clone();
    let mut pointer_const = None;
    for _ in 0..16 {
        if current.kind().as_ref() == "pointer_declarator" {
            pointer_const = Some(current.children().any(|child| {
                child.kind().as_ref() == "type_qualifier" && child.text().trim() == "const"
            }));
        }
        if current.kind().as_ref() == "identifier" {
            // Only the pointer nearest the bound name qualifies its storage.
            // Const pointees, return types and parameters cannot make a
            // mutable function pointer an immutable standard-library alias.
            return pointer_const.unwrap_or_else(|| {
                node.parent().is_some_and(|parent| {
                    parent.children().any(|child| {
                        child.kind().as_ref() == "type_qualifier" && child.text().trim() == "const"
                    })
                })
            });
        }
        let next = current.field("declarator").or_else(|| {
            matches!(
                current.kind().as_ref(),
                "parenthesized_declarator" | "reference_declarator"
            )
            .then(|| {
                current
                    .children()
                    .find(|child| child.is_named() && child.kind().as_ref() != "type_qualifier")
            })
            .flatten()
        });
        let Some(next) = next else { return false };
        current = next;
    }
    false
}

fn function_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let function = node
        .dfs()
        .find(|n| n.kind().as_ref() == "function_declarator")?;
    let name = function.field("declarator")?;
    matches!(
        name.kind().as_ref(),
        "identifier" | "field_identifier" | "qualified_identifier"
    )
    .then(|| {
        compact(name.text().as_ref())
            .trim_start_matches("::")
            .to_string()
    })
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

pub(super) fn declaration_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
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
        "strcpy" => "strcpy",
        "strcat" => "strcat",
        "strncpy" => "strncpy",
        "strncat" => "strncat",
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

    #[test]
    fn explicit_global_namespace_bypasses_local_shadow_but_nested_std_does_not() {
        assert_eq!(
            names(
                r#"
            namespace std { void *memcpy(void*, const void*, unsigned); }
            namespace project {
                namespace std { void *memcpy(void*, const void*, unsigned); }
                void run() { std::memcpy(dst, src, len); ::std::memcpy(dst, src, len); }
            }
            void other(int std) { std::memcpy(dst, src, len); ::std::memcpy(dst, src, len); }
        "#
            ),
            vec![None, Some("memcpy"), None, Some("memcpy")]
        );
    }

    #[test]
    fn class_method_prototypes_do_not_borrow_standard_api_contracts() {
        assert_eq!(
            names(
                r#"
            struct Custom {
                void run() { memcpy(dst,src,n); std::memcpy(dst,src,n); }
                virtual void memcpy(void*,const void*,unsigned);
            };
        "#
            ),
            vec![None, Some("memcpy")]
        );
    }

    #[test]
    fn string_qualifications_imports_and_constant_aliases_share_identity() {
        assert_eq!(
            names(
                r#"
            namespace runtime = std;
            using std::strncat;
            void run() {
                strncpy(dst, src, n); ::strncpy(dst, src, n);
                std::strncpy(dst, src, n); ::std::strncpy(dst, src, n);
                runtime::strncpy(dst, src, n);
                const auto copier = std::strncpy; copier(dst, src, n);
                strncat(dst, src, n); std::strcpy(dst, src); std::strcat(dst, src);
            }
        "#
            ),
            [
                vec![Some("strncpy"); 6],
                vec![Some("strncat"), Some("strcpy"), Some("strcat")]
            ]
            .concat()
        );
    }

    #[test]
    fn namespace_prototypes_reopenings_and_macros_cannot_supply_standard_effects() {
        assert_eq!(
            names(
                r#"
            char *strncpy(char*, const char*, unsigned);
            namespace app { char *strncpy(char*, const char*, unsigned); }
            namespace app {
                namespace inner { void run() { strncpy(dst, src, n); std::strncpy(dst, src, n); } }
                void run() { strncpy(dst, src, n); using std::strncpy; strncpy(dst, src, n); }
            }
            void clean() { strncpy(dst, src, n); }
            void install() {
                #define strncpy(a,b,c) custom(a,b,c)
            }
            void expanded() { strncpy(dst, src, n); std::strncpy(dst, src, n); ::strncpy(dst, src, n); }
        "#
            ),
            vec![
                None,
                Some("strncpy"),
                None,
                Some("strncpy"),
                Some("strncpy"),
                None,
                None,
                None
            ]
        );
    }

    #[test]
    fn imported_overloads_foreign_namespaces_and_unknown_bases_keep_contracts_open() {
        assert_eq!(
            names(
                r#"
            namespace app {
                using std::strncpy;
                char *strncpy(char*,const char*,unsigned);
                void run() { strncpy(dst,src,n); }
                void explicit_import() { using std::strncpy; strncpy(dst,src,n); }
            }
            namespace other { void memcpy(void*,const void*,unsigned); }
            void imported() { using namespace other; memcpy(dst,src,n); ::memcpy(dst,src,n); }
            struct Derived : Unknown {
                void run() { strncpy(dst,src,n); std::strncpy(dst,src,n); }
                void explicit_import() { using std::strncpy; strncpy(dst,src,n); }
            };
        "#
            ),
            vec![
                None,
                Some("strncpy"),
                None,
                Some("memcpy"),
                None,
                Some("strncpy"),
                Some("strncpy")
            ]
        );
    }

    #[test]
    fn out_of_line_standard_definitions_are_not_builtin_effects() {
        assert_eq!(
            names(
                r#"
            namespace std { char *strncpy(char*,const char*,unsigned); }
            char *std::strncpy(char *dst,const char *src,unsigned n) { return dst; }
            void run() { std::strncpy(dst,src,n); ::std::strncpy(dst,src,n); }
        "#
            ),
            vec![None, None]
        );
    }

    #[test]
    fn alias_immutability_belongs_to_the_pointer_not_its_parameter_or_return_types() {
        assert_eq!(
            names(
                r#"
            void run() {
                char *(*mutable_copy)(char*,const char*,unsigned long)=std::strncpy;
                mutable_copy=replacement; mutable_copy(dst,src,n);
                char *(* const fixed_copy)(char*,const char*,unsigned long)=std::strncpy;
                fixed_copy(dst,src,n);
                const auto *mutable_auto=std::memcpy;
                mutable_auto=replacement; mutable_auto(dst,src,n);
                auto * const fixed_auto=std::memcpy; fixed_auto(dst,src,n);
                const auto * const fixed_both=std::memcpy; fixed_both(dst,src,n);
                const void *(*returned_const)(void*,const void*,unsigned)=std::memcpy;
                returned_const(dst,src,n);
                const auto &reference=std::memcpy; reference(dst,src,n);
            }
        "#
            ),
            vec![
                None,
                Some("strncpy"),
                None,
                Some("memcpy"),
                Some("memcpy"),
                None,
                Some("memcpy")
            ]
        );
    }
}
