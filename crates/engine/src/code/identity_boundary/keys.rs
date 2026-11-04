//! Bounded lexical key provenance. No caller discovery or cross-file value flow.
use super::super::{node_identity, symbols::FileSymbolEnvironment};
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::collections::BTreeMap;

type N<'a> = Node<'a, StrDoc<SupportLang>>;
type Key = (usize, String);

struct Definition<'a> {
    start: usize,
    value: Option<N<'a>>,
    module: Option<(String, Option<N<'a>>)>,
}

struct Binding<'a> {
    owner: Option<usize>,
    definitions: Vec<Definition<'a>>,
    writes: Vec<(usize, Option<usize>, bool)>,
}

pub(super) struct KeyIndex<'a> {
    scopes: BTreeMap<usize, BTreeMap<String, Binding<'a>>>,
}

fn owner(node: &N<'_>) -> Option<usize> {
    node.ancestors()
        .find(|n| node_identity::function(n.kind().as_ref()))
        .map(|n| n.node_id())
}

fn loop_declaration(node: &N<'_>) -> Option<bool> {
    node.children()
        .find_map(|child| match child.text().as_ref() {
            "var" => Some(true),
            "let" | "const" | "using" => Some(false),
            _ => None,
        })
}

fn string(node: &N<'_>) -> Option<String> {
    if !matches!(node.kind().as_ref(), "string" | "template_string")
        || node
            .dfs()
            .any(|n| n.kind().as_ref() == "template_substitution")
    {
        return None;
    }
    let text = node.text();
    let quote = text.chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }
    let content = text.strip_prefix(quote)?.strip_suffix(quote)?;
    (!content.is_empty()).then(|| content.to_string())
}

fn require_module<'a>(value: &N<'a>) -> Option<(String, Option<N<'a>>)> {
    let call = if value.kind().as_ref() == "member_expression" {
        value.field("object")?
    } else {
        value.clone()
    };
    if call.kind().as_ref() != "call_expression"
        || call.field("function")?.text().trim() != "require"
    {
        return None;
    }
    let args = call.field("arguments")?;
    let module = string(&args.children().find(|n| n.is_named())?)?;
    Some((module, Some(call)))
}

impl<'a> KeyIndex<'a> {
    pub(super) fn new(root: &N<'a>) -> Self {
        let mut index = Self {
            scopes: BTreeMap::new(),
        };
        let mut writes = Vec::new();
        for node in root.dfs() {
            let kind = node.kind();
            if node_identity::function(kind.as_ref()) {
                let mut parameters = node
                    .field("parameters")
                    .map(|n| n.children().filter(|n| n.is_named()).collect::<Vec<_>>())
                    .unwrap_or_default();
                parameters.extend(node.field("parameter"));
                for parameter in parameters {
                    index.define(&node, &parameter, None, None, owner(&parameter));
                }
                if let Some(name) = node
                    .field("name")
                    .filter(|_| kind.as_ref() != "method_definition")
                {
                    let scope = if matches!(
                        kind.as_ref(),
                        "function_declaration" | "generator_function_declaration"
                    ) {
                        node_identity::scope_node(&node, false)
                    } else {
                        Some(node.clone())
                    };
                    if let Some(scope) = scope {
                        index.define(&scope, &name, None, None, owner(&node));
                    }
                }
            } else if kind.as_ref() == "variable_declarator" {
                let is_var = node
                    .parent()
                    .is_some_and(|n| n.kind().as_ref() == "variable_declaration");
                if let (Some(scope), Some(name)) =
                    (node_identity::scope_node(&node, is_var), node.field("name"))
                {
                    let value = node.field("value");
                    let module = value.as_ref().and_then(require_module);
                    index.define(
                        &scope,
                        &name,
                        (name.kind().as_ref() == "identifier")
                            .then_some(value)
                            .flatten(),
                        module,
                        owner(&node),
                    );
                }
            } else if kind.as_ref() == "catch_clause" {
                if let Some(pattern) = node.field("parameter") {
                    index.define(&node, &pattern, None, None, owner(&node));
                }
            } else if kind.as_ref() == "for_in_statement" {
                if let (Some(is_var), Some(left)) = (loop_declaration(&node), node.field("left")) {
                    let scope = if is_var {
                        node_identity::scope_node(&node, true)
                    } else {
                        Some(node.clone())
                    };
                    if let Some(scope) = scope {
                        index.define(&scope, &left, None, None, owner(&node));
                    }
                }
            } else if matches!(kind.as_ref(), "class_declaration" | "enum_declaration") {
                if let (Some(scope), Some(name)) =
                    (node_identity::scope_node(&node, false), node.field("name"))
                {
                    index.define(&scope, &name, None, None, owner(&node));
                }
            } else if kind.as_ref() == "import_statement"
                && !node.text().trim_start().starts_with("import type ")
            {
                let module = node.field("source").and_then(|n| string(&n));
                if let Some(scope) = node_identity::scope_node(&node, false) {
                    for part in node.dfs() {
                        let name = match part.kind().as_ref() {
                            "import_specifier"
                                if !part.text().trim_start().starts_with("type ") =>
                            {
                                part.field("alias").or_else(|| part.field("name"))
                            }
                            "identifier"
                                if part.parent().is_some_and(|n| {
                                    matches!(
                                        n.kind().as_ref(),
                                        "import_clause" | "namespace_import"
                                    )
                                }) =>
                            {
                                Some(part.clone())
                            }
                            _ => None,
                        };
                        if let Some(name) = name {
                            index.define(
                                &scope,
                                &name,
                                None,
                                module.clone().map(|m| (m, None)),
                                None,
                            );
                        }
                    }
                }
            }
            if matches!(
                kind.as_ref(),
                "assignment_expression"
                    | "augmented_assignment_expression"
                    | "update_expression"
                    | "for_in_statement"
            ) && !(kind.as_ref() == "for_in_statement" && loop_declaration(&node) == Some(false))
            {
                if let Some(left) = node.field("left").or_else(|| node.field("argument")) {
                    let mut names = Vec::new();
                    node_identity::bound_names(&left, &mut names);
                    // Explicit mutation of an imported object also makes its
                    // SDK identity uncertain; do not keep a stale module fact.
                    if left.kind().as_ref() == "member_expression" {
                        if let Some(object) = left.field("object") {
                            node_identity::bound_names(&object, &mut names);
                        }
                    }
                    for name in names {
                        writes.push((node.clone(), name));
                    }
                }
            }
        }
        for names in index.scopes.values_mut() {
            for binding in names.values_mut() {
                binding.definitions.sort_by_key(|d| d.start);
            }
        }
        for (write, name) in writes {
            let Some(key) = index.resolve(&write, &name).map(|(key, _)| key) else {
                continue;
            };
            let loop_write = std::iter::once(write.clone())
                .chain(write.ancestors())
                .any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "for_statement" | "for_in_statement" | "while_statement" | "do_statement"
                    )
                });
            index
                .scopes
                .get_mut(&key.0)
                .unwrap()
                .get_mut(&key.1)
                .unwrap()
                .writes
                .push((write.range().start, owner(&write), loop_write));
        }
        index
    }

    fn define(
        &mut self,
        scope: &N<'a>,
        pattern: &N<'a>,
        value: Option<N<'a>>,
        module: Option<(String, Option<N<'a>>)>,
        owner: Option<usize>,
    ) {
        let mut names = Vec::new();
        node_identity::bound_names(pattern, &mut names);
        let empty_var = pattern.parent().is_some_and(|declaration| {
            declaration.kind().as_ref() == "variable_declarator"
                && declaration.field("value").is_none()
                && declaration
                    .parent()
                    .is_some_and(|parent| parent.kind().as_ref() == "variable_declaration")
        });
        for name in names {
            let binding = self
                .scopes
                .entry(scope.node_id())
                .or_default()
                .entry(name)
                .or_insert_with(|| Binding {
                    owner,
                    definitions: Vec::new(),
                    writes: Vec::new(),
                });
            if empty_var && !binding.definitions.is_empty() {
                continue;
            }
            binding.definitions.push(Definition {
                start: pattern.range().start,
                value: value.clone(),
                module: module.clone(),
            });
        }
    }

    fn resolve(&self, site: &N<'_>, name: &str) -> Option<(Key, &Binding<'a>)> {
        std::iter::once(site.clone())
            .chain(site.ancestors())
            .find_map(|scope| {
                self.scopes
                    .get(&scope.node_id())?
                    .get(name)
                    .map(|binding| ((scope.node_id(), name.to_string()), binding))
            })
    }

    fn definition(&self, site: &N<'_>, name: &str) -> Option<(Key, &Definition<'a>)> {
        let (key, binding) = self.resolve(site, name)?;
        let captured = binding.owner != owner(site);
        if binding.writes.iter().any(|(at, writer, repeated)| {
            captured || *writer != binding.owner || *at < site.range().start || *repeated
        }) {
            return None;
        }
        let definition = if captured {
            (binding.definitions.len() == 1).then(|| &binding.definitions[0])?
        } else {
            let end = binding
                .definitions
                .partition_point(|d| d.start < site.range().start);
            binding.definitions.get(end.checked_sub(1)?)?
        };
        Some((key, definition))
    }

    fn module_owned(
        &self,
        site: &N<'_>,
        head: &str,
        module: &str,
        symbols: &FileSymbolEnvironment,
        depth: usize,
    ) -> bool {
        if depth == 0 {
            return false;
        }
        let Some((_, definition)) = self.definition(site, head) else {
            return false;
        };
        let Some((observed, require)) = &definition.module else {
            return false;
        };
        if observed != module
            && !(module != "jsonwebtoken" && observed == &format!("node:{module}"))
        {
            return false;
        }
        require
            .as_ref()
            .is_none_or(|call| self.require_owned(call, symbols, depth - 1))
    }

    fn require_owned(&self, call: &N<'_>, symbols: &FileSymbolEnvironment, depth: usize) -> bool {
        if self.resolve(call, "require").is_none() {
            return true;
        }
        if depth == 0 {
            return false;
        }
        let Some((_, definition)) = self.definition(call, "require") else {
            return false;
        };
        let Some(value) = &definition.value else {
            return false;
        };
        let Some(function) = value.field("function") else {
            return false;
        };
        let callee = super::compact(&function.text());
        symbols
            .resolve(&callee, "module.createRequire")
            .is_some_and(|r| r.confidence != mehscan_core::SymbolConfidence::Ambiguous)
            && self.module_owned(
                value,
                callee.split('.').next().unwrap_or(&callee),
                "module",
                symbols,
                depth - 1,
            )
    }

    pub(super) fn api_owned(
        &self,
        site: &N<'_>,
        callee: &str,
        symbols: &FileSymbolEnvironment,
    ) -> bool {
        self.module_owned(
            site,
            callee.split('.').next().unwrap_or(callee),
            "jsonwebtoken",
            symbols,
            8,
        )
    }

    pub(super) fn hardcoded(&self, value: &N<'a>, symbols: &FileSymbolEnvironment) -> bool {
        self.constant(value, symbols, 8, &mut Vec::new())
    }

    fn constant(
        &self,
        value: &N<'a>,
        symbols: &FileSymbolEnvironment,
        depth: usize,
        visiting: &mut Vec<Key>,
    ) -> bool {
        if depth == 0
            || value
                .ancestors()
                .any(|n| n.kind().as_ref() == "with_statement")
        {
            return false;
        }
        if string(value).is_some() {
            return true;
        }
        if matches!(
            value.kind().as_ref(),
            "parenthesized_expression"
                | "as_expression"
                | "satisfies_expression"
                | "non_null_expression"
        ) {
            return value
                .children()
                .find(|n| n.is_named())
                .is_some_and(|n| self.constant(&n, symbols, depth - 1, visiting));
        }
        if value.kind().as_ref() == "identifier" {
            let Some((key, definition)) = self.definition(value, &value.text()) else {
                return false;
            };
            if visiting.contains(&key) {
                return false;
            }
            visiting.push(key);
            let constant = definition
                .value
                .as_ref()
                .is_some_and(|n| self.constant(n, symbols, depth - 1, visiting));
            visiting.pop();
            return constant;
        }
        if value.kind().as_ref() == "call_expression" {
            let Some(function) = value.field("function") else {
                return false;
            };
            let callee = super::compact(&function.text());
            let buffer = callee == "Buffer.from" && self.resolve(value, "Buffer").is_none()
                || symbols
                    .resolve(&callee, "buffer.Buffer.from")
                    .is_some_and(|r| r.confidence != mehscan_core::SymbolConfidence::Ambiguous)
                    && self.module_owned(
                        value,
                        callee.split('.').next().unwrap_or(&callee),
                        "buffer",
                        symbols,
                        depth - 1,
                    );
            if buffer {
                let Some(args) = value.field("arguments") else {
                    return false;
                };
                let args = args.children().filter(|n| n.is_named()).collect::<Vec<_>>();
                return matches!(args.len(), 1 | 2)
                    && args
                        .get(1)
                        .is_none_or(|encoding| string(encoding).is_some())
                    && self.constant(&args[0], symbols, depth - 1, visiting);
            }
        }
        false
    }
}
