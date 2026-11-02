//! Lexical exclusions for explicitly enumerated static hash APIs. The shared
//! symbol resolver remains responsible for the concrete SDK identity.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::collections::{BTreeMap, BTreeSet};

type CsNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) struct StaticReceiverIndex {
    scopes: BTreeMap<usize, BTreeSet<String>>,
}

impl StaticReceiverIndex {
    pub(super) fn new(root: &CsNode<'_>) -> Self {
        let mut scopes: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        for declaration in root.dfs().filter(|node| {
            matches!(
                node.kind().as_ref(),
                "variable_declarator"
                    | "property_declaration"
                    | "method_declaration"
                    | "local_function_statement"
                    | "declaration_pattern"
                    | "foreach_statement"
            )
        }) {
            let Some(name) = declaration
                .field("name")
                .or_else(|| declaration.field("left"))
            else {
                continue;
            };
            let Some(scope) = declaration.ancestors().find(|node| {
                matches!(
                    node.kind().as_ref(),
                    "block"
                        | "for_statement"
                        | "foreach_statement"
                        | "using_statement"
                        | "fixed_statement"
                        | "switch_section"
                        | "catch_clause"
                        | "class_declaration"
                        | "struct_declaration"
                        | "record_declaration"
                        | "interface_declaration"
                )
            }) else {
                continue;
            };
            scopes
                .entry(scope.node_id())
                .or_default()
                .insert(name.text().trim().to_string());
        }
        Self { scopes }
    }

    pub(super) fn accepts(&self, site: &CsNode<'_>, observed: &str) -> bool {
        // A constructor resolves in type space; a same-named value parameter
        // does not turn `new CryptoProvider()` into an instance method call.
        if site.kind().as_ref() == "object_creation_expression" || observed.starts_with("global::")
        {
            return true;
        }
        let head = observed.split(['.', ':']).next().unwrap_or(observed).trim();
        !super::symbols::parameter_shadows_name(site, head, mehscan_core::Language::Csharp)
            && !site.ancestors().any(|scope| {
                self.scopes
                    .get(&scope.node_id())
                    .is_some_and(|names| names.contains(head))
            })
    }
}
