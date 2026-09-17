use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::collections::{BTreeMap, BTreeSet};

pub(super) type KNode<'a> = Node<'a, StrDoc<SupportLang>>;

#[derive(Default)]
pub(in crate::code) struct Imports {
    aliases: BTreeMap<String, BTreeSet<String>>,
    wildcards: BTreeSet<String>,
}

impl Imports {
    pub(in crate::code) fn build(root: &KNode<'_>) -> Self {
        let mut result = Self::default();
        for import in root.dfs().filter(|n| n.kind().as_ref() == "import_header") {
            let text = import.text();
            let words = text
                .trim()
                .trim_end_matches(';')
                .split_whitespace()
                .collect::<Vec<_>>();
            let Some(path) = words.get(1) else { continue };
            if let Some(package) = path.strip_suffix(".*") {
                result.wildcards.insert(package.to_string());
            } else {
                let alias = if words.get(2) == Some(&"as") {
                    words.get(3).copied()
                } else {
                    path.rsplit('.').next()
                };
                if let Some(alias) = alias {
                    result
                        .aliases
                        .entry(alias.trim_matches('`').to_string())
                        .or_default()
                        .insert(path.to_string());
                }
            }
        }
        result
    }

    pub(super) fn exact(
        &self,
        root: &KNode<'_>,
        use_site: &KNode<'_>,
        observed: &str,
        canonical: &str,
    ) -> bool {
        let observed = observed.trim().trim_end_matches('?');
        let Some(head) = observed.split('.').next() else {
            return false;
        };
        if name_shadowed(root, use_site, head) {
            return false;
        }
        if observed == canonical {
            return true;
        }
        if let Some(paths) = self.aliases.get(head) {
            return paths.len() == 1
                && paths
                    .iter()
                    .any(|path| format!("{path}{}", &observed[head.len()..]) == canonical);
        }
        if observed == canonical.rsplit('.').next().unwrap_or(canonical) {
            if let Some((package, _)) = canonical.rsplit_once('.') {
                return self.wildcards.len() == 1 && self.wildcards.contains(package)
                    || (matches!(package, "java.lang" | "kotlin")
                        && !self.aliases.contains_key(observed));
            }
        }
        false
    }
}

pub(super) fn named_child<'a>(node: &KNode<'a>, kind: &str) -> Option<KNode<'a>> {
    node.children().find(|n| n.kind().as_ref() == kind)
}

pub(super) fn name(node: &KNode<'_>) -> Option<String> {
    node.children()
        .find(|n| matches!(n.kind().as_ref(), "simple_identifier" | "type_identifier"))
        .map(|n| n.text().trim_matches('`').to_string())
}

pub(super) fn callable<'a>(node: &KNode<'a>) -> Option<KNode<'a>> {
    node.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_declaration" | "lambda_literal" | "anonymous_function"
        )
    })
}

pub(super) fn owner<'a>(node: &KNode<'a>) -> Option<KNode<'a>> {
    node.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "class_declaration" | "object_declaration"
        )
    })
}

fn scope<'a>(declaration: &KNode<'a>) -> Option<KNode<'a>> {
    if declaration.kind().as_ref() == "catch_block" {
        return Some(declaration.clone());
    }
    if declaration.kind().as_ref() == "parameter" {
        return callable(declaration);
    }
    if declaration.kind().as_ref() == "class_parameter" {
        return owner(declaration);
    }
    declaration.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "statements"
                | "class_body"
                | "source_file"
                | "lambda_literal"
                | "for_statement"
                | "catch_block"
        )
    })
}

pub(super) fn visible(declaration: &KNode<'_>, use_site: &KNode<'_>) -> bool {
    scope(declaration).is_some_and(|scope| {
        let range = scope.range();
        let use_range = use_site.range();
        range.start <= use_range.start
            && use_range.end <= range.end
            && (matches!(
                declaration.kind().as_ref(),
                "parameter"
                    | "class_parameter"
                    | "class_declaration"
                    | "object_declaration"
                    | "type_alias"
            ) || matches!(scope.kind().as_ref(), "class_body" | "source_file")
                || declaration.range().start < use_range.start)
    })
}

pub(super) fn name_shadowed(root: &KNode<'_>, use_site: &KNode<'_>, symbol: &str) -> bool {
    root.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "variable_declaration"
                | "parameter"
                | "class_parameter"
                | "class_declaration"
                | "object_declaration"
                | "type_alias"
                | "function_declaration"
                | "catch_block"
        ) && name(&n).as_deref() == Some(symbol.trim_matches('`'))
            && visible(&n, use_site)
    })
}

pub(super) fn binding_type<'a>(
    root: &KNode<'a>,
    use_site: &KNode<'a>,
    symbol: &str,
) -> Option<String> {
    let declaration = binding(root, use_site, symbol)?;
    declaration
        .children()
        .find(|n| matches!(n.kind().as_ref(), "user_type" | "nullable_type"))
        .map(|n| n.text().trim_end_matches('?').to_string())
}

pub(super) fn binding<'a>(
    root: &KNode<'a>,
    use_site: &KNode<'a>,
    symbol: &str,
) -> Option<KNode<'a>> {
    let symbol = symbol
        .strip_prefix("this.")
        .unwrap_or(symbol)
        .trim_end_matches("!!");
    let mut declarations = root
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "variable_declaration" | "parameter" | "class_parameter"
            ) && name(n).as_deref() == Some(symbol)
                && visible(n, use_site)
        })
        .collect::<Vec<_>>();
    declarations.sort_by_key(|n| {
        (
            scope(n).map_or(usize::MAX, |s| s.range().len()),
            usize::MAX - n.range().start,
        )
    });
    // An unknown local declaration shadows a typed field; never fall back to it.
    declarations.first().cloned()
}

pub(super) fn receiver_unchanged(root: &KNode<'_>, use_site: &KNode<'_>, symbol: &str) -> bool {
    let symbol = symbol
        .strip_prefix("this.")
        .unwrap_or(symbol)
        .trim_end_matches("!!");
    !root.dfs().any(|n| {
        n.kind().as_ref() == "assignment"
            && n.range().start < use_site.range().start
            && callable(&n).map(|s| s.range()) == callable(use_site).map(|s| s.range())
            && n.children()
                .find(|n| n.is_named())
                .is_some_and(|n| n.text().trim() == symbol)
    })
}

pub(super) struct Argument<'a> {
    pub name: Option<String>,
    pub value: KNode<'a>,
}
pub(super) struct Call<'a> {
    pub callee: KNode<'a>,
    pub arguments: Vec<Argument<'a>>,
}

pub(super) fn call<'a>(node: &KNode<'a>) -> Option<Call<'a>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let callee = node
        .children()
        .find(|n| n.is_named() && n.kind().as_ref() != "call_suffix")?;
    let suffix = named_child(node, "call_suffix")?;
    let arguments = named_child(&suffix, "value_arguments")?;
    let mut values = Vec::new();
    for argument in arguments
        .children()
        .filter(|n| n.kind().as_ref() == "value_argument")
    {
        if argument.text().trim_start().starts_with('*') {
            return None;
        }
        let named = argument.children().any(|n| n.text().as_ref() == "=");
        let children = argument
            .children()
            .filter(|n| n.is_named())
            .collect::<Vec<_>>();
        let value = children.last()?.clone();
        values.push(Argument {
            name: named.then(|| children[0].text().into_owned()),
            value,
        });
    }
    Some(Call {
        callee,
        arguments: values,
    })
}

pub(super) fn annotation(
    root: &KNode<'_>,
    imports: &Imports,
    node: &KNode<'_>,
    canonical: &str,
) -> bool {
    std::iter::once(node.clone())
        .chain(node.children())
        .filter(|n| matches!(n.kind().as_ref(), "modifiers" | "parameter_modifiers"))
        .flat_map(|n| {
            n.dfs()
                .filter(|n| n.kind().as_ref() == "annotation")
                .collect::<Vec<_>>()
        })
        .any(|a| {
            let text = a.text();
            let observed = text
                .trim_start_matches('@')
                .split('(')
                .next()
                .unwrap_or("")
                .trim();
            imports.exact(root, &a, observed, canonical)
        })
}
