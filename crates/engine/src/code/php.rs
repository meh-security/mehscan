//! Exact native PHP identities. Unknown namespaces and receiver origins fail closed.
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;

type PhpNode<'a> = Node<'a, StrDoc<SupportLang>>;

struct Import {
    alias: String,
    target: String,
    function: bool,
    scope: Range<usize>,
}

pub(super) struct PhpContext<'a> {
    root: PhpNode<'a>,
    imports: Vec<Import>,
}

impl<'a> PhpContext<'a> {
    pub(super) fn build(root: &PhpNode<'a>) -> Self {
        let mut imports = Vec::new();
        for declaration in root
            .dfs()
            .filter(|n| n.kind().as_ref() == "namespace_use_declaration")
        {
            // Group imports require a prefix merge; do not guess their identity.
            if declaration.field("body").is_some() {
                continue;
            }
            let function = declaration
                .field("type")
                .is_some_and(|n| n.text().trim() == "function");
            for clause in declaration
                .children()
                .filter(|n| n.kind().as_ref() == "namespace_use_clause")
            {
                let alias_node = clause.field("alias");
                let Some(target) = clause.children().find(|n| {
                    n.is_named()
                        && alias_node
                            .as_ref()
                            .is_none_or(|alias| alias.range() != n.range())
                }) else {
                    continue;
                };
                let target = target
                    .text()
                    .trim()
                    .trim_start_matches('\\')
                    .to_ascii_lowercase();
                let alias = alias_node
                    .map(|n| n.text().to_ascii_lowercase())
                    .unwrap_or_else(|| target.rsplit('\\').next().unwrap_or_default().to_string());
                imports.push(Import {
                    alias,
                    target,
                    function: function
                        || clause
                            .field("type")
                            .is_some_and(|n| n.text().trim() == "function"),
                    scope: namespace_scope(&declaration, root),
                });
            }
        }
        Self {
            root: root.clone(),
            imports,
        }
    }

    pub(super) fn accepts(&self, rule: &str, node: &PhpNode<'a>) -> bool {
        // Named/reordered arguments and unpacking need a separate argument-role
        // summary; positional wildcard matching must not invent those roles.
        if node.field("arguments").is_some_and(|arguments| {
            arguments
                .dfs()
                .any(|child| matches!(child.kind().as_ref(), ":" | "..."))
        }) {
            return false;
        };
        if rule == "php-http-request-data" {
            let Some(base) = node.children().find(|n| n.is_named()) else {
                return false;
            };
            let text = base.text();
            return base.kind().as_ref() == "variable_name"
                && matches!(
                    text.as_ref(),
                    "$_GET" | "$_POST" | "$_REQUEST" | "$_COOKIE" | "$_FILES"
                )
                && !node.parent().is_some_and(|parent| {
                    parent.kind().as_ref() == "assignment_expression"
                        && parent
                            .field("left")
                            .is_some_and(|left| left.range() == node.range())
                })
                && !self.root.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "assignment_expression" | "augmented_assignment_expression"
                    ) && n.range().start < node.range().start
                        && n.field("left").is_some_and(|left| left.text() == text)
                });
        }
        if rule == "php-html-output" {
            return matches!(node.kind().as_ref(), "echo_statement" | "print_intrinsic");
        }
        if rule == "php-pdo-query" {
            return node.field("name").is_some_and(|name| {
                name.kind().as_ref() == "name"
                    && matches!(
                        name.text().to_ascii_lowercase().as_str(),
                        "query" | "exec" | "prepare"
                    )
            }) && node
                .field("object")
                .is_some_and(|object| self.pdo_receiver(&object, node));
        }
        let Some(function) = node.field("function") else {
            return false;
        };
        if !matches!(function.kind().as_ref(), "name" | "qualified_name") {
            return false;
        }
        if rule == "php-dynamic-code" {
            // eval is a language construct, not a namespaced/importable function.
            return function.kind().as_ref() == "name"
                && function.text().eq_ignore_ascii_case("eval");
        }
        let Some(canonical) = self.resolve(&function, true) else {
            return false;
        };
        match rule {
            "php-command-execution" => matches!(
                canonical.as_str(),
                "shell_exec" | "exec" | "system" | "passthru" | "popen"
            ),
            "php-mysqli-query" => {
                matches!(
                    canonical.as_str(),
                    "mysqli_query" | "mysqli_real_query" | "mysqli_execute_query"
                )
            }
            "php-mysqli-parameterization" => {
                canonical == "mysqli_execute_query"
                    && node.field("arguments").is_some_and(|arguments| {
                        arguments
                            .children()
                            .filter(|arg| arg.is_named())
                            .nth(1)
                            .is_some_and(|query| {
                                query.dfs().any(|n| {
                                    matches!(n.kind().as_ref(), "string" | "encapsed_string")
                                }) && !query.dfs().any(|n| {
                                    matches!(
                                        n.kind().as_ref(),
                                        "variable_name"
                                            | "function_call_expression"
                                            | "member_call_expression"
                                    )
                                })
                            })
                    })
            }
            "php-html-encoding" => {
                matches!(canonical.as_str(), "htmlspecialchars" | "htmlentities")
            }
            "php-shell-argument-quoting" => canonical == "escapeshellarg",
            "php-filesystem-read" => matches!(
                canonical.as_str(),
                "file_get_contents" | "readfile" | "file"
            ),
            "php-filesystem-write" => canonical == "file_put_contents",
            "php-path-canonicalization" => canonical == "realpath",
            "php-deserialization" => canonical == "unserialize",
            _ => false,
        }
    }

    fn resolve(&self, name: &PhpNode<'a>, function: bool) -> Option<String> {
        let observed = name.text().trim().to_ascii_lowercase();
        let scope = namespace_scope(name, &self.root);
        let collision = self.root.dfs().any(|declaration| {
            declaration.kind().as_ref()
                == if function {
                    "function_definition"
                } else {
                    "class_declaration"
                }
                && namespace_scope(&declaration, &self.root) == scope
                && declaration
                    .field("name")
                    .is_some_and(|n| n.text().eq_ignore_ascii_case(&observed))
        });
        if collision {
            return None;
        };
        if observed.starts_with('\\') {
            let canonical = observed.trim_start_matches('\\');
            return (!canonical.contains('\\')).then(|| canonical.to_string());
        }
        if observed.contains('\\') {
            return None;
        };
        if let Some(import) = self.imports.iter().find(|import| {
            import.function == function && import.alias == observed && import.scope == scope
        }) {
            return (!import.target.contains('\\')).then(|| import.target.clone());
        }
        // Bare names in a namespace may resolve to another included file's API.
        let namespaced = self.root.dfs().any(|n| {
            n.kind().as_ref() == "namespace_definition"
                && n.field("name").is_some()
                && namespace_scope(&n, &self.root) == scope
        });
        (!namespaced).then_some(observed)
    }

    fn pdo_receiver(&self, receiver: &PhpNode<'a>, call: &PhpNode<'a>) -> bool {
        if receiver.kind().as_ref() != "variable_name" {
            return false;
        };
        let owner = function_scope(call, &self.root);
        // A by-reference helper can replace a local receiver. Without a call
        // summary, do not carry its construction/type through that boundary.
        if self.root.dfs().any(|prior| {
            prior.kind().as_ref() == "function_call_expression"
                && prior.range().start < call.range().start
                && function_scope(&prior, &self.root) == owner
                && prior.field("arguments").is_some_and(|args| {
                    args.dfs().any(|arg| {
                        arg.kind().as_ref() == "variable_name" && arg.text() == receiver.text()
                    })
                })
        }) {
            return false;
        }
        let assignments: Vec<_> = self
            .root
            .dfs()
            .filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "assignment_expression" | "augmented_assignment_expression"
                ) && function_scope(n, &self.root) == owner
                    && n.range().start < call.range().start
                    && n.field("left")
                        .is_some_and(|left| left.text() == receiver.text())
            })
            .collect();
        if !assignments.is_empty() {
            if assignments.len() != 1 {
                return false;
            };
            let assignment = &assignments[0];
            if assignment
                .ancestors()
                .take_while(|n| n.range() != owner)
                .any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "if_statement"
                            | "else_clause"
                            | "for_statement"
                            | "foreach_statement"
                            | "while_statement"
                            | "switch_statement"
                            | "try_statement"
                    )
                })
            {
                return false;
            };
            let Some(block) = assignment
                .ancestors()
                .find(|n| n.kind().as_ref() == "compound_statement")
            else {
                return self.creation_is_pdo(assignment);
            };
            if !contains(&block.range(), &call.range()) {
                return false;
            };
            return self.creation_is_pdo(assignment);
        }
        self.root.dfs().any(|parameter| {
            parameter.kind().as_ref() == "simple_parameter"
                && function_scope(&parameter, &self.root) == owner
                && parameter
                    .field("name")
                    .is_some_and(|n| n.text() == receiver.text())
                && parameter.field("type").is_some_and(|ty| {
                    self.resolve(&ty, false)
                        .is_some_and(|canonical| canonical == "pdo")
                })
        })
    }

    fn creation_is_pdo(&self, assignment: &PhpNode<'a>) -> bool {
        assignment.field("right").is_some_and(|right| {
            right.kind().as_ref() == "object_creation_expression"
                && right
                    .children()
                    .find(|n| n.is_named() && n.kind().as_ref() != "arguments")
                    .is_some_and(|name| {
                        self.resolve(&name, false)
                            .is_some_and(|canonical| canonical == "pdo")
                    })
        })
    }
}

fn namespace_scope(node: &PhpNode<'_>, root: &PhpNode<'_>) -> Range<usize> {
    if let Some(namespace) = std::iter::once(node.clone())
        .chain(node.ancestors())
        .find(|n| n.kind().as_ref() == "namespace_definition" && n.field("body").is_some())
    {
        return namespace.range();
    }
    let namespaces: Vec<_> = root
        .children()
        .filter(|n| n.kind().as_ref() == "namespace_definition")
        .collect();
    let Some(current) = namespaces
        .iter()
        .rev()
        .find(|n| n.range().start <= node.range().start)
    else {
        return root.range();
    };
    current.range().start
        ..namespaces
            .iter()
            .find(|n| n.range().start > current.range().start)
            .map_or(root.range().end, |next| next.range().start)
}

fn function_scope(node: &PhpNode<'_>, root: &PhpNode<'_>) -> Range<usize> {
    node.ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_definition"
                    | "method_declaration"
                    | "anonymous_function"
                    | "arrow_function"
            )
        })
        .map_or(root.range(), |n| n.range())
}

fn contains(outer: &Range<usize>, inner: &Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}
