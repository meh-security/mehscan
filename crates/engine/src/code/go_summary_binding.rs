//! Declaration identity for bounded Go helper summaries, not a Go type checker.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::path::Path;

type N<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn compatible_http_call(root: &N<'_>, call: &N<'_>) -> bool {
    let Some(function) = call.field("function") else {
        return true;
    };
    if !function.field("field").is_some_and(|n| n.text() == "Do") {
        return true;
    }
    let arguments = call
        .field("arguments")
        .map(|n| n.children().filter(|n| n.is_named()).collect::<Vec<_>>())
        .unwrap_or_default();
    // net/http.Client.Do takes exactly one *Request, never a callback. Unknown
    // expressions remain reviewable; no receiver-name allow/deny list is used.
    if arguments.len() != 1 {
        return false;
    }
    let mut value = arguments[0].clone();
    while value.kind() == "parenthesized_expression" {
        let Some(inner) = value.children().find(|n| n.is_named()) else {
            break;
        };
        value = inner;
    }
    if value.kind() == "func_literal" {
        return false;
    }
    if value.kind() == "identifier" {
        let name = value.text();
        if root.children().any(|n| {
            n.kind() == "function_declaration" && n.field("name").is_some_and(|n| n.text() == name)
        }) && !shadowed(root, &value, name.as_ref())
        {
            return false;
        }
        let mut declarations = root
            .dfs()
            .filter(|n| {
                visible(n, &value)
                    && n.range().start < value.range().start
                    && matches!(
                        n.kind().as_ref(),
                        "parameter_declaration" | "var_spec" | "short_var_declaration"
                    )
                    && declared_names(n).iter().any(|s| s == name.as_ref())
            })
            .collect::<Vec<_>>();
        declarations.sort_by_key(|n| (visibility_size(n), std::cmp::Reverse(n.range().start)));
        if let Some(n) = declarations.first() {
            if let Some(ty) = n.field("type") {
                return ty.kind() != "function_type";
            }
            if declared_names(n).len() == 1
                && n.field("right")
                    .or_else(|| n.field("value"))
                    .is_some_and(|v| v.children().any(|n| n.kind() == "func_literal"))
            {
                return false;
            }
        }
    }
    if value.kind() == "selector_expression" {
        let Some(receiver) = value.field("operand") else {
            return true;
        };
        let Some(name) = value.field("field") else {
            return true;
        };
        let bindings = Bindings::default();
        if root
            .children()
            .filter(|n| n.kind() == "method_declaration")
            .filter(|n| n.field("name").is_some_and(|n| n.text() == name.text()))
            .filter_map(|n| scope("", root, &n))
            .any(|owner| bindings.receiver_matches(&owner, "", root, &receiver, 4))
        {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Scope {
    path: String,
    package: String,
    name: String,
    receiver: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Bindings {
    factories: Vec<(Scope, String, usize)>,
    variables: Vec<(Scope, String)>,
}

fn directory(path: &str) -> String {
    Path::new(path)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_string_lossy()
        .replace('\\', "/")
}

fn package(root: &N<'_>) -> String {
    root.children()
        .find(|n| n.kind() == "package_clause")
        .and_then(|n| n.children().find(|c| c.kind() == "package_identifier"))
        .map(|n| n.text().into_owned())
        .unwrap_or_default()
}

fn simple_type(text: &str) -> &str {
    text.trim().trim_start_matches('*').trim()
}

pub(super) fn scope(path: &str, root: &N<'_>, declaration: &N<'_>) -> Option<Scope> {
    let name = declaration.field("name")?.text().into_owned();
    let receiver = declaration.field("receiver").and_then(|r| {
        r.children()
            .find(|n| n.kind() == "parameter_declaration")
            .and_then(|n| n.field("type"))
            .map(|n| simple_type(n.text().as_ref()).to_string())
    });
    Some(Scope {
        path: path.into(),
        package: package(root),
        name,
        receiver,
    })
}

impl Bindings {
    pub(super) fn collect(&mut self, path: &str, root: &N<'_>) {
        for n in root
            .dfs()
            .filter(|n| n.kind() == "var_spec" && enclosing_function(n).is_none())
        {
            let Some(ty) = n.field("type") else { continue };
            let ty = simple_type(ty.text().as_ref()).to_string();
            if ty.contains('.') {
                continue;
            }
            for name in declared_names(&n) {
                self.variables.push((
                    Scope {
                        path: path.into(),
                        package: package(root),
                        name,
                        receiver: None,
                    },
                    ty.clone(),
                ));
            }
        }
        for n in root
            .children()
            .filter(|n| n.kind() == "function_declaration")
        {
            let Some(result) = n.field("result") else {
                continue;
            };
            let returns = if result.kind() == "parameter_list" {
                result
                    .children()
                    .filter(|n| n.kind() == "parameter_declaration")
                    .filter_map(|n| {
                        n.field("type")
                            .map(|ty| vec![ty.text().into_owned(); declared_names(&n).len().max(1)])
                    })
                    .flatten()
                    .collect::<Vec<String>>()
            } else {
                vec![result.text().into_owned()]
            };
            let Some(first) = returns.first() else {
                continue;
            };
            let ty = simple_type(first);
            // Explicit local result type, never a factory-name guess. A tuple's
            // first result is usable only at the matching first assignment slot.
            if !ty.is_empty()
                && ty.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && let Some(owner) = scope(path, root, &n)
            {
                self.factories.push((owner, ty.to_string(), returns.len()));
            }
        }
    }

    pub(super) fn matches(&self, expected: &Scope, path: &str, root: &N<'_>, call: &N<'_>) -> bool {
        let Some(function) = call.field("function") else {
            return false;
        };
        if expected.receiver.is_none() {
            return function_matches(expected, path, root, &function);
        }
        function.kind() == "selector_expression"
            && function
                .field("field")
                .is_some_and(|n| n.text() == expected.name)
            && function
                .field("operand")
                .is_some_and(|n| self.receiver_matches(expected, path, root, &n, 4))
    }

    fn receiver_matches(
        &self,
        expected: &Scope,
        path: &str,
        root: &N<'_>,
        value: &N<'_>,
        depth: usize,
    ) -> bool {
        if depth == 0 {
            return false;
        }
        if value.kind() == "identifier" {
            let name = value.text();
            let mut declarations = root
                .dfs()
                .filter(|n| {
                    n.range().start < value.range().start
                        && visible(n, value)
                        && matches!(
                            n.kind().as_ref(),
                            "parameter_declaration" | "var_spec" | "short_var_declaration"
                        )
                        && declared_names(n).iter().any(|s| s == name.as_ref())
                })
                .collect::<Vec<_>>();
            declarations.sort_by_key(|n| (visibility_size(n), std::cmp::Reverse(n.range().start)));
            let Some(declaration) = declarations.first() else {
                let globals = self
                    .variables
                    .iter()
                    .filter(|(owner, _)| {
                        owner.name == name.as_ref() && same_package(owner, path, &package(root))
                    })
                    .collect::<Vec<_>>();
                return globals.len() == 1
                    && globals[0].1 == expected.receiver.as_deref().unwrap_or_default()
                    && same_package(&globals[0].0, &expected.path, &expected.package);
            };
            if let Some(ty) = declaration.field("type") {
                return type_matches(expected, path, root, &ty);
            }
            if root.dfs().any(|n| {
                n.kind() == "assignment_statement"
                    && n.range().start > declaration.range().end
                    && n.range().start < value.range().start
                    && visible(&n, value)
                    && n.field("left")
                        .is_some_and(|l| l.children().any(|x| x.text() == name))
            }) {
                return false;
            }
            let Some(list) = declaration
                .field("right")
                .or_else(|| declaration.field("value"))
            else {
                return false;
            };
            let values = list.children().filter(|n| n.is_named()).collect::<Vec<_>>();
            let names = declared_names(declaration);
            let Some(index) = names.iter().position(|s| s == name.as_ref()) else {
                return false;
            };
            if values.len() == 1 && names.len() > 1 && index == 0 {
                return self.factory_matches(expected, path, root, &values[0], names.len());
            }
            if values.len() != names.len() {
                return false;
            }
            return values
                .get(index)
                .is_some_and(|n| self.receiver_matches(expected, path, root, n, depth - 1));
        }
        if value.kind() == "unary_expression" && value.text().starts_with('&') {
            return value
                .field("operand")
                .is_some_and(|n| self.receiver_matches(expected, path, root, &n, depth - 1));
        }
        if value.kind() == "composite_literal" {
            return value
                .field("type")
                .is_some_and(|n| type_matches(expected, path, root, &n));
        }
        if value.kind() == "call_expression" {
            let Some(function) = value.field("function") else {
                return false;
            };
            if function.text() == "new"
                && !shadowed(root, &function, "new")
                && !root.children().any(|n| {
                    n.kind() == "function_declaration"
                        && n.field("name").is_some_and(|n| n.text() == "new")
                })
            {
                return value
                    .field("arguments")
                    .and_then(|n| n.children().find(|n| n.is_named()))
                    .is_some_and(|n| type_matches(expected, path, root, &n));
            }
            return self.factory_matches(expected, path, root, value, 1);
        }
        false
    }

    fn factory_matches(
        &self,
        expected: &Scope,
        path: &str,
        root: &N<'_>,
        call: &N<'_>,
        arity: usize,
    ) -> bool {
        if call.kind() != "call_expression" {
            return false;
        }
        let Some(function) = call.field("function") else {
            return false;
        };
        let factories = self
            .factories
            .iter()
            .filter(|(owner, _, _)| function_matches(owner, path, root, &function))
            .collect::<Vec<_>>();
        factories.len() == 1
            && factories[0].1 == expected.receiver.as_deref().unwrap_or_default()
            && factories[0].2 == arity
            && same_package(&factories[0].0, &expected.path, &expected.package)
    }
}

fn same_package(expected: &Scope, path: &str, package: &str) -> bool {
    directory(&expected.path) == directory(path) && expected.package == package
}

fn imported(expected: &Scope, root: &N<'_>, qualifier: &str) -> bool {
    let target = directory(&expected.path);
    if target.is_empty() {
        return false;
    }
    root.dfs().filter(|n| n.kind() == "import_spec").any(|n| {
        let alias = n
            .field("name")
            .map(|n| n.text().into_owned())
            .unwrap_or_else(|| expected.package.clone());
        alias == qualifier
            && alias != "_"
            && alias != "."
            && n.field("path").is_some_and(|p| {
                let text = p.text();
                let text = text.trim_matches(['"', '`']);
                text == target || text.ends_with(&format!("/{target}"))
            })
    })
}

fn function_matches(expected: &Scope, path: &str, root: &N<'_>, function: &N<'_>) -> bool {
    if expected.receiver.is_some() {
        return false;
    }
    if function.kind() == "identifier" {
        return function.text() == expected.name
            && same_package(expected, path, &package(root))
            && !shadowed(root, function, &expected.name);
    }
    let Some(qualifier) = function.field("operand") else {
        return false;
    };
    qualifier.kind() == "identifier"
        && function
            .field("field")
            .is_some_and(|n| n.text() == expected.name)
        && imported(expected, root, qualifier.text().as_ref())
        && !shadowed(root, function, qualifier.text().as_ref())
}

fn type_matches(expected: &Scope, path: &str, root: &N<'_>, ty: &N<'_>) -> bool {
    let text = ty.text();
    let name = simple_type(text.as_ref());
    if let Some((qualifier, name)) = name.split_once('.') {
        name == expected.receiver.as_deref().unwrap_or_default()
            && imported(expected, root, qualifier)
            && !shadowed(root, ty, qualifier)
    } else {
        name == expected.receiver.as_deref().unwrap_or_default()
            && same_package(expected, path, &package(root))
            && !shadowed(root, ty, name)
            && !root.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "type_spec" | "type_parameter_declaration"
                ) && enclosing_function(&n).is_some()
                    && visible(&n, ty)
                    && n.field("name").is_some_and(|n| n.text() == name)
            })
    }
}

fn declared_names(n: &N<'_>) -> Vec<String> {
    if n.kind() == "short_var_declaration" {
        return n
            .field("left")
            .map(|l| {
                l.children()
                    .filter(|n| n.kind() == "identifier")
                    .map(|n| n.text().into_owned())
                    .collect()
            })
            .unwrap_or_default();
    }
    let end = n
        .field("type")
        .or_else(|| n.field("value"))
        .map(|n| n.range().start)
        .unwrap_or(usize::MAX);
    n.children()
        .filter(|n| n.kind() == "identifier" && n.range().start < end)
        .map(|n| n.text().into_owned())
        .collect()
}

fn enclosing_function<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
    })
}

fn visibility_size(n: &N<'_>) -> usize {
    lexical_scope(n)
        .or_else(|| enclosing_function(n))
        .map(|n| n.range().len())
        .unwrap_or(usize::MAX)
}

fn visible(declaration: &N<'_>, at: &N<'_>) -> bool {
    if let Some(block) = lexical_scope(declaration) {
        return block.range().contains(&at.range().start);
    }
    enclosing_function(declaration).is_none_or(|f| f.range().contains(&at.range().start))
}

fn lexical_scope<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "block"
                | "if_statement"
                | "for_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
        )
    })
}

fn shadowed(root: &N<'_>, at: &N<'_>, name: &str) -> bool {
    root.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "parameter_declaration" | "var_spec" | "short_var_declaration"
        ) && visible(&n, at)
            && declared_names(&n).iter().any(|s| s == name)
            && (n.kind() == "parameter_declaration" || n.range().start < at.range().start)
    })
}
