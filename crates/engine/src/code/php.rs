//! Exact native PHP identities. Unknown namespaces and receiver origins fail closed.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use ast_grep_core::AstGrep;
use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{Capture, Language};

type PhpNode<'a> = Node<'a, StrDoc<SupportLang>>;
type DatabaseExports = BTreeMap<String, (String, Capture)>;
type IncludedDatabase = (Range<usize>, String, DatabaseExports);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_function_filter_preserves_imports_and_namespace_shadowing() {
        let ast = AstGrep::doc(StrDoc::new(
            "<?php namespace NativeCalls { use function \\json_decode as decode_body; function positive() { decode_body('[]', true); \\JSON_DECODE('[]'); unrelated('[]'); } } namespace LocalCalls { function json_decode($text) {} function negative() { json_decode('[]'); } }",
            SupportLang::PhpMixed,
        ));
        let root = ast.root();
        let context = PhpContext::build(&root);
        let results: Vec<_> = root
            .dfs()
            .filter(|n| n.kind().as_ref() == "function_call_expression")
            .map(|n| {
                (
                    n.field("function").unwrap().text().to_string(),
                    context.exact_function(&n, "json_decode"),
                )
            })
            .collect();
        assert_eq!(
            results,
            vec![
                ("decode_body".into(), true),
                ("\\JSON_DECODE".into(), true),
                ("unrelated".into(), false),
                ("json_decode".into(), false),
            ]
        );
    }
}

#[derive(Default)]
pub(crate) struct PhpProjectContext {
    exports: BTreeMap<String, DatabaseExports>,
}

impl PhpProjectContext {
    pub(crate) fn from_sources<'s>(
        sources: impl IntoIterator<Item = (&'s str, Language, &'s str)>,
    ) -> Self {
        let mut exports = BTreeMap::new();
        for (path, language, source) in sources {
            if language != Language::Php || source.len() > 512 * 1024 {
                continue;
            }
            let lower = source.to_ascii_lowercase();
            if !lower.contains("pdo") && !lower.contains("mysqli") {
                continue;
            }
            let ast = AstGrep::doc(StrDoc::new(source, SupportLang::PhpMixed));
            let root = ast.root();
            // A config summary cannot stand in for executing arbitrary code.
            if root.dfs().any(|n| {
                n.is_error()
                    || n.is_missing()
                    || matches!(
                        n.kind().as_ref(),
                        "function_call_expression"
                            | "member_call_expression"
                            | "include_expression"
                            | "include_once_expression"
                            | "require_expression"
                            | "require_once_expression"
                            | "namespace_definition"
                            | "reference_assignment_expression"
                    )
            }) {
                continue;
            }
            let context = PhpContext::build(&root);
            if root
                .dfs()
                .filter(|n| n.kind().as_ref() == "object_creation_expression")
                .any(|creation| {
                    creation
                        .children()
                        .find(|n| n.is_named() && n.kind().as_ref() != "arguments")
                        .and_then(|name| context.resolve(&name, false))
                        .is_none_or(|name| !matches!(name.as_str(), "pdo" | "mysqli"))
                })
            {
                continue;
            }
            let mut bindings = BTreeMap::new();
            for binding in root.dfs().filter(|n| {
                n.kind().as_ref() == "assignment_expression"
                    && function_scope(n, &root) == root.range()
            }) {
                let Some(left) = binding.field("left") else {
                    continue;
                };
                if left.kind().as_ref() != "variable_name"
                    || binding
                        .parent()
                        .is_none_or(|n| n.kind().as_ref() != "expression_statement")
                    || binding.ancestors().any(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "if_statement"
                                | "for_statement"
                                | "foreach_statement"
                                | "while_statement"
                                | "do_statement"
                                | "switch_statement"
                                | "try_statement"
                        )
                    })
                {
                    continue;
                }
                let writes = root
                    .dfs()
                    .filter(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "assignment_expression"
                                | "augmented_assignment_expression"
                                | "update_expression"
                                | "unset_statement"
                        ) && n.dfs().any(|part| {
                            part.kind().as_ref() == "variable_name" && part.text() == left.text()
                        }) && n.field("left").is_none_or(|target| {
                            target.dfs().any(|part| part.text() == left.text())
                        })
                    })
                    .count();
                if writes != 1 {
                    continue;
                }
                for class in ["pdo", "mysqli"] {
                    if context.creation_is_native_database(&binding, class) {
                        bindings.insert(
                            left.text().to_string(),
                            (
                                class.to_string(),
                                Capture {
                                    text: binding.text().into_owned(),
                                    location: super::matcher::location(path, &binding),
                                },
                            ),
                        );
                    }
                }
            }
            exports.insert(path.to_string(), bindings);
        }
        Self { exports }
    }
}

struct Import {
    alias: String,
    target: String,
    function: bool,
    scope: Range<usize>,
}

pub(super) struct PhpContext<'a> {
    root: PhpNode<'a>,
    imports: Vec<Import>,
    declarations: Vec<(String, bool, Range<usize>)>,
    namespaced_scopes: Vec<Range<usize>>,
    included: Vec<IncludedDatabase>,
    json_candidates: BTreeSet<(usize, usize, String)>,
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
        let declarations = root
            .dfs()
            .filter_map(|node| {
                let function = match node.kind().as_ref() {
                    "function_definition" => true,
                    "class_declaration" => false,
                    _ => return None,
                };
                Some((
                    node.field("name")?.text().to_ascii_lowercase(),
                    function,
                    namespace_scope(&node, root),
                ))
            })
            .collect();
        let namespaced_scopes = root
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "namespace_definition" && node.field("name").is_some()
            })
            .map(|node| namespace_scope(&node, root))
            .collect();
        let mut context = Self {
            root: root.clone(),
            imports,
            declarations,
            namespaced_scopes,
            included: Vec::new(),
            json_candidates: BTreeSet::new(),
        };
        for binding in root
            .dfs()
            .filter(|n| n.kind().as_ref() == "assignment_expression")
        {
            if binding
                .field("right")
                .is_some_and(|right| context.exact_function(&right, "json_decode"))
                && let Some(left) = binding
                    .field("left")
                    .filter(|n| n.kind().as_ref() == "variable_name")
            {
                let owner = function_scope(&binding, root);
                context
                    .json_candidates
                    .insert((owner.start, owner.end, left.text().to_string()));
            }
        }
        context
    }

    pub(super) fn with_project(mut self, path: &str, project: &PhpProjectContext) -> Self {
        for include in self.root.dfs().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "include_expression"
                    | "include_once_expression"
                    | "require_expression"
                    | "require_once_expression"
            )
        }) {
            let Some(expression) = include.children().find(|n| n.is_named()) else {
                continue;
            };
            // __DIR__ fixes resolution independently of cwd and include_path.
            let text = expression.text();
            let Some(relative) = text
                .trim()
                .strip_prefix("__DIR__")
                .and_then(|s| s.trim().strip_prefix('.'))
                .map(str::trim)
            else {
                continue;
            };
            let Some(relative) = relative
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .or_else(|| relative.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
            else {
                continue;
            };
            if !relative.starts_with('/') || relative.contains(['\\', '$', '\'', '"', ':']) {
                continue;
            }
            let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            let mut components = parent
                .split('/')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            let mut valid = true;
            for component in relative.split('/') {
                match component {
                    "" | "." => (),
                    ".." => {
                        if components.pop().is_none() {
                            valid = false;
                            break;
                        }
                    }
                    value => components.push(value),
                }
            }
            if !valid {
                continue;
            }
            let target = components.join("/");
            if let Some(exports) = project.exports.get(&target) {
                self.included
                    .push((include.range(), target, exports.clone()));
            }
        }
        self
    }

    pub(super) fn supplemental_captures(
        &self,
        rule: &str,
        node: &PhpNode<'a>,
        path: &str,
    ) -> BTreeMap<String, Capture> {
        let mut captures = BTreeMap::new();
        if rule == "php-pdo-statement-parameters"
            && let Some((prepare, query)) = self.pdo_statement_origin(node)
        {
            captures.insert(
                "query".to_string(),
                Capture {
                    text: query.text().into_owned(),
                    location: super::matcher::location(path, &query),
                },
            );
            captures.insert(
                "statement_producer".to_string(),
                Capture {
                    text: prepare.text().into_owned(),
                    location: super::matcher::location(path, &prepare),
                },
            );
        }
        if matches!(rule, "php-curl-request" | "php-curl-tls-validation")
            && let Some((binding, endpoint)) = self.curl_origin(node)
        {
            captures.insert(
                "curl_handle_origin".to_string(),
                Capture {
                    text: binding.text().into_owned(),
                    location: super::matcher::location(path, &binding),
                },
            );
            captures.insert(
                "endpoint".to_string(),
                Capture {
                    text: endpoint.text().into_owned(),
                    location: super::matcher::location(path, &endpoint),
                },
            );
        }
        if matches!(rule, "php-http-json-field" | "php-http-json-property")
            && let Some(base) = node.children().find(|n| n.is_named())
            && let Some(binding) = self.root.dfs().find(|n| {
                n.kind().as_ref() == "assignment_expression"
                    && function_scope(n, &self.root) == function_scope(node, &self.root)
                    && n.range().end < node.range().start
                    && n.field("left")
                        .is_some_and(|left| left.text() == base.text())
            })
        {
            captures.insert(
                "request_body_producer".to_string(),
                Capture {
                    text: binding.text().into_owned(),
                    location: super::matcher::location(path, &binding),
                },
            );
            if let Some(read) = binding
                .field("right")
                .and_then(|decode| self.request_body_read(&decode))
                && read.kind().as_ref() == "assignment_expression"
            {
                captures.insert(
                    "request_body_read".to_string(),
                    Capture {
                        text: read.text().into_owned(),
                        location: super::matcher::location(path, &read),
                    },
                );
            }
        }
        if matches!(rule, "php-pdo-query" | "php-mysqli-method-query")
            && let Some(receiver) = node.field("object")
        {
            if receiver.kind().as_ref() == "member_access_expression"
                && let Some(class) = node
                    .ancestors()
                    .find(|n| n.kind().as_ref() == "class_declaration")
                && let Some(binding) = class.dfs().find(|n| {
                    n.kind().as_ref() == "assignment_expression"
                        && n.field("left")
                            .is_some_and(|left| left.text() == receiver.text())
                        && n.ancestors()
                            .find(|n| n.kind().as_ref() == "class_declaration")
                            .is_some_and(|n| n.range() == class.range())
                })
            {
                captures.insert(
                    "database_receiver_origin".to_string(),
                    Capture {
                        text: binding.text().into_owned(),
                        location: super::matcher::location(path, &binding),
                    },
                );
            }
            let owner = function_scope(node, &self.root);
            for (range, _, exports) in &self.included {
                if range.end <= node.range().start
                    && contains(&owner, range)
                    && let Some((_, origin)) = exports.get(receiver.text().as_ref())
                {
                    captures.insert("database_receiver_origin".to_string(), origin.clone());
                    if let Some(include) = self.root.dfs().find(|n| n.range() == *range) {
                        captures.insert(
                            "database_include".to_string(),
                            Capture {
                                text: include.text().into_owned(),
                                location: super::matcher::location(path, &include),
                            },
                        );
                    }
                }
            }
        }
        captures
    }

    pub(super) fn accepts(&self, rule: &str, node: &PhpNode<'a>) -> bool {
        // Positional matches must not invent roles for named/reordered or
        // unpacked arguments, including the extended driver entrypoints.
        if node
            .field("arguments")
            .or_else(|| node.children().find(|n| n.kind().as_ref() == "arguments"))
            .is_some_and(|arguments| {
                arguments
                    .dfs()
                    .any(|child| matches!(child.kind().as_ref(), ":" | "..."))
            })
        {
            return false;
        }
        if rule == "php-extended-nosql-query" {
            return node.kind().as_ref() == "object_creation_expression"
                && node
                    .children()
                    .find(|n| n.is_named() && n.kind().as_ref() != "arguments")
                    .is_some_and(|name| self.sdk_class_exact(&name, "mongodb\\driver\\query"));
        }
        if rule == "php-extended-sql-facade" {
            return node.field("scope").is_some_and(|name| {
                self.sdk_class_exact(&name, "illuminate\\support\\facades\\db")
            });
        }
        if rule == "php-extended-sql-builder" {
            return node.field("object").is_some_and(|receiver| {
                self.sdk_receiver(
                    &receiver,
                    node,
                    &[
                        "doctrine\\dbal\\connection",
                        "doctrine\\dbal\\query\\querybuilder",
                        "doctrine\\orm\\querybuilder",
                        "doctrine\\orm\\entitymanagerinterface",
                        "illuminate\\database\\query\\builder",
                    ],
                    8,
                )
            });
        }
        if rule == "php-extended-pgsql-query" {
            return [
                "pg_query",
                "pg_query_params",
                "pg_send_query",
                "pg_send_query_params",
                "pg_prepare",
                "pg_send_prepare",
            ]
            .iter()
            .any(|name| self.exact_function(node, name));
        }
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
        if matches!(rule, "php-http-json-field" | "php-http-json-property") {
            return self.json_request_field(node);
        }
        if rule == "php-pdo-statement-parameters" {
            return node.field("name").is_some_and(|name| {
                name.kind().as_ref() == "name" && name.text().eq_ignore_ascii_case("execute")
            }) && self.pdo_statement_origin(node).is_some();
        }
        if matches!(rule, "php-curl-request" | "php-curl-tls-validation") {
            return (if rule == "php-curl-request" {
                self.exact_function(node, "curl_exec")
            } else {
                self.exact_function(node, "curl_setopt")
                    && node.field("arguments").is_some_and(|args| {
                        let args: Vec<_> = args.children().filter(|n| n.is_named()).collect();
                        args.len() == 3
                            && matches!(
                                args[1].text().trim(),
                                "CURLOPT_SSL_VERIFYPEER" | "CURLOPT_SSL_VERIFYHOST"
                            )
                    })
            }) && self.curl_origin(node).is_some();
        }
        if rule == "php-html-output" {
            return matches!(node.kind().as_ref(), "echo_statement" | "print_intrinsic");
        }
        if rule == "php-file-inclusion" {
            return matches!(
                node.kind().as_ref(),
                "include_expression"
                    | "include_once_expression"
                    | "require_expression"
                    | "require_once_expression"
            );
        }
        if matches!(rule, "php-pdo-query" | "php-mysqli-method-query") {
            let class = if rule == "php-pdo-query" {
                "pdo"
            } else {
                "mysqli"
            };
            return node.field("name").is_some_and(|name| {
                name.kind().as_ref() == "name"
                    && (class == "pdo"
                        && matches!(
                            name.text().to_ascii_lowercase().as_str(),
                            "query" | "exec" | "prepare"
                        )
                        || class == "mysqli"
                            && matches!(
                                name.text().to_ascii_lowercase().as_str(),
                                "query"
                                    | "real_query"
                                    | "multi_query"
                                    | "prepare"
                                    | "execute_query"
                            ))
            }) && node
                .field("object")
                .is_some_and(|object| self.native_database_receiver(&object, node, class));
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
            "php-url-stream-read" => matches!(
                canonical.as_str(),
                "file_get_contents" | "readfile" | "file"
            ),
            "php-url-parsing" => canonical == "parse_url",
            "php-weak-hash-selection" => matches!(canonical.as_str(), "md5" | "sha1"),
            "php-filesystem-write" => canonical == "file_put_contents",
            "php-upload-move" => canonical == "move_uploaded_file",
            "php-header-redirect" => {
                canonical == "header"
                    && node.field("arguments").is_some_and(|args| {
                        args.children()
                            .find(|arg| arg.is_named())
                            .is_some_and(|arg| {
                                // Admit only a visible Location header prefix, not an arbitrary
                                // request-selected header name or an unrelated header value.
                                let text = arg.text();
                                let prefix = text.trim_start().trim_start_matches('(').trim_start();
                                prefix.strip_prefix(['\'', '"']).is_some_and(|value| {
                                    value.to_ascii_lowercase().starts_with("location:")
                                })
                            })
                    })
            }
            "php-path-canonicalization" => canonical == "realpath",
            "php-deserialization" => canonical == "unserialize",
            _ => false,
        }
    }

    fn sdk_class_exact(&self, name: &PhpNode<'a>, canonical: &str) -> bool {
        let observed = name.text().trim().to_ascii_lowercase();
        let scope = namespace_scope(name, &self.root);
        if self.declarations.iter().any(|(declared, function, owner)| {
            !function && *owner == scope && *declared == observed
        }) {
            return false;
        }
        if observed.starts_with('\\') {
            return observed.trim_start_matches('\\') == canonical;
        }
        let candidates: Vec<_> = self
            .imports
            .iter()
            .filter(|import| !import.function && import.alias == observed && import.scope == scope)
            .collect();
        if let [import] = candidates.as_slice() {
            return import.target == canonical;
        }
        !self.namespaced_scope(&scope) && observed == canonical
    }

    fn sdk_receiver(
        &self,
        receiver: &PhpNode<'a>,
        call: &PhpNode<'a>,
        types: &[&str],
        depth: usize,
    ) -> bool {
        if depth == 0 {
            return false;
        }
        if receiver.kind().as_ref() == "scoped_call_expression" {
            return receiver.field("scope").is_some_and(|scope| {
                self.sdk_class_exact(&scope, "illuminate\\support\\facades\\db")
            }) && receiver
                .field("name")
                .is_some_and(|name| matches!(name.text().as_ref(), "table" | "query"));
        }
        if receiver.kind().as_ref() == "member_call_expression" {
            return receiver.field("name").is_some_and(|name| {
                matches!(
                    name.text().as_ref(),
                    "createQueryBuilder" | "where" | "select" | "from" | "table"
                )
            }) && receiver
                .field("object")
                .is_some_and(|object| self.sdk_receiver(&object, call, types, depth - 1));
        }
        if receiver.kind().as_ref() != "variable_name" {
            return false;
        }
        let scope = function_scope(call, &self.root);
        if self.root.dfs().any(|n| {
            n.range().start < call.range().start
                && function_scope(&n, &self.root) == scope
                && matches!(
                    n.kind().as_ref(),
                    "include_expression"
                        | "include_once_expression"
                        | "require_expression"
                        | "require_once_expression"
                )
        }) {
            return false;
        }
        let writes: Vec<_> = self
            .root
            .dfs()
            .filter(|n| {
                function_scope(n, &self.root) == scope
                    && matches!(
                        n.kind().as_ref(),
                        "assignment_expression"
                            | "augmented_assignment_expression"
                            | "reference_assignment_expression"
                    )
                    && n.field("left")
                        .is_some_and(|left| left.text() == receiver.text())
            })
            .collect();
        if let [write] = writes.as_slice() {
            return write.range().start < call.range().start
                && write
                    .field("right")
                    .is_some_and(|value| self.sdk_receiver(&value, call, types, depth - 1));
        }
        if !writes.is_empty() {
            return false;
        }
        if self.root.dfs().any(|n| {
            n.range().start < call.range().start
                && function_scope(&n, &self.root) == scope
                && matches!(
                    n.kind().as_ref(),
                    "function_call_expression" | "member_call_expression"
                )
                && n.field("arguments").is_some_and(|args| {
                    args.dfs().any(|arg| {
                        arg.kind().as_ref() == "variable_name" && arg.text() == receiver.text()
                    })
                })
        }) {
            return false;
        }
        self.root
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "simple_parameter" && function_scope(n, &self.root) == scope
            })
            .any(|param| {
                param
                    .field("name")
                    .is_some_and(|name| name.text() == receiver.text())
                    && param.field("type").is_some_and(|ty| {
                        types
                            .iter()
                            .any(|canonical| self.sdk_class_exact(&ty, canonical))
                    })
            })
    }

    fn resolve(&self, name: &PhpNode<'a>, function: bool) -> Option<String> {
        let observed = name.text().trim().to_ascii_lowercase();
        let scope = namespace_scope(name, &self.root);
        let collision = self
            .declarations
            .iter()
            .any(|(name, kind, owner)| *kind == function && *owner == scope && *name == observed);
        if collision {
            return None;
        };
        if observed.starts_with('\\') {
            let canonical = observed.trim_start_matches('\\');
            return (!canonical.contains('\\') && !self.global_shadow(canonical, function))
                .then(|| canonical.to_string());
        }
        if observed.contains('\\') {
            return None;
        };
        if let Some(import) = self.imports.iter().find(|import| {
            import.function == function && import.alias == observed && import.scope == scope
        }) {
            return (!import.target.contains('\\')
                && !self.global_shadow(&import.target, function))
            .then(|| import.target.clone());
        }
        // Bare names in a namespace may resolve to another included file's API.
        (!self.namespaced_scope(&scope) && !self.global_shadow(&observed, function))
            .then_some(observed)
    }

    // A decoded field is a source only with a unique, unconditional native
    // associative JSON-body producer in the same lexical owner. This is not
    // a general array alias or framework request summary.
    fn json_request_field(&self, node: &PhpNode<'a>) -> bool {
        let Some(base) = node.children().find(|n| n.is_named()) else {
            return false;
        };
        if base.kind().as_ref() != "variable_name" {
            return false;
        }
        let owner = function_scope(node, &self.root);
        if !self
            .json_candidates
            .contains(&(owner.start, owner.end, base.text().to_string()))
        {
            return false;
        }
        let writes: Vec<_> = self
            .root
            .dfs()
            .filter(|write| {
                function_scope(write, &self.root) == owner
                    && write.range().start < node.range().start
                    && matches!(
                        write.kind().as_ref(),
                        "assignment_expression"
                            | "augmented_assignment_expression"
                            | "reference_assignment_expression"
                    )
                    && write.field("left").is_some_and(|left| {
                        left.dfs().any(|part| {
                            part.kind().as_ref() == "variable_name" && part.text() == base.text()
                        })
                    })
            })
            .collect();
        let [binding] = writes.as_slice() else {
            return false;
        };
        if binding.kind().as_ref() != "assignment_expression"
            || binding
                .parent()
                .is_none_or(|parent| parent.kind().as_ref() != "expression_statement")
            || binding.range().end > node.range().start
            || binding
                .ancestors()
                .take_while(|parent| parent.range() != owner)
                .any(|parent| {
                    matches!(
                        parent.kind().as_ref(),
                        "if_statement"
                            | "else_clause"
                            | "for_statement"
                            | "foreach_statement"
                            | "while_statement"
                            | "do_statement"
                            | "switch_statement"
                            | "catch_clause"
                    )
                })
            || node.ancestors().any(|parent| {
                matches!(
                    parent.kind().as_ref(),
                    "assignment_expression"
                        | "augmented_assignment_expression"
                        | "reference_assignment_expression"
                ) && parent
                    .field("left")
                    .is_some_and(|left| contains(&left.range(), &node.range()))
            })
        {
            return false;
        }
        // Any intervening helper can replace or mutate an array passed by
        // reference. unset/increment and aliases also invalidate this budget.
        if self.root.dfs().any(|prior| {
            function_scope(&prior, &self.root) == owner
                && prior.range().start >= binding.range().end
                && prior.range().end <= node.range().start
                && matches!(
                    prior.kind().as_ref(),
                    "function_call_expression"
                        | "member_call_expression"
                        | "unset_statement"
                        | "update_expression"
                        | "reference_assignment_expression"
                )
                && !["is_array", "is_object", "is_null", "is_string"]
                    .iter()
                    .any(|name| self.exact_function(&prior, name))
                && prior.dfs().any(|part| {
                    part.kind().as_ref() == "variable_name" && part.text() == base.text()
                })
        }) {
            return false;
        }
        let Some(decode) = binding.field("right") else {
            return false;
        };
        if !self.exact_function(&decode, "json_decode") {
            return false;
        }
        let Some(args) = decode.field("arguments") else {
            return false;
        };
        let args: Vec<_> = args.children().filter(|arg| arg.is_named()).collect();
        if node.kind().as_ref() == "member_access_expression" {
            if node
                .field("name")
                .is_none_or(|name| name.kind().as_ref() != "name")
                || args.is_empty()
                || args.len() > 3
                || args
                    .get(1)
                    .is_some_and(|arg| !matches!(arg.text().trim(), "false" | "null"))
            {
                return false;
            }
        } else if args.len() < 2 || args[1].text().trim() != "true" {
            return false;
        }
        self.request_body_read(&decode).is_some()
    }

    fn request_body_read(&self, decode: &PhpNode<'a>) -> Option<PhpNode<'a>> {
        let args = decode.field("arguments")?;
        let args: Vec<_> = args.children().filter(|arg| arg.is_named()).collect();
        if args.is_empty() {
            return None;
        }
        let mut read = args[0].children().find(|part| part.is_named())?;
        let mut origin = read.clone();
        if read.kind().as_ref() == "variable_name" {
            let owner = function_scope(decode, &self.root);
            let writes: Vec<_> = self
                .root
                .dfs()
                .filter(|n| {
                    function_scope(n, &self.root) == owner
                        && n.range().start < decode.range().start
                        && matches!(
                            n.kind().as_ref(),
                            "assignment_expression"
                                | "augmented_assignment_expression"
                                | "reference_assignment_expression"
                        )
                        && n.field("left")
                            .is_some_and(|left| left.text() == read.text())
                })
                .collect();
            let [binding] = writes.as_slice() else {
                return None;
            };
            if binding.kind().as_ref() != "assignment_expression"
                || !mandatory_before(binding, decode, &owner)
                || self.root.dfs().any(|prior| {
                    function_scope(&prior, &self.root) == owner
                        && prior.range().start >= binding.range().end
                        && prior.range().end <= decode.range().start
                        && matches!(
                            prior.kind().as_ref(),
                            "function_call_expression"
                                | "member_call_expression"
                                | "unset_statement"
                                | "update_expression"
                                | "reference_assignment_expression"
                                | "include_expression"
                                | "require_expression"
                                | "include_once_expression"
                                | "require_once_expression"
                        )
                        && (matches!(
                            prior.kind().as_ref(),
                            "include_expression"
                                | "require_expression"
                                | "include_once_expression"
                                | "require_once_expression"
                        ) || prior.dfs().any(|part| {
                            part.kind().as_ref() == "variable_name" && part.text() == read.text()
                        }))
                })
            {
                return None;
            }
            origin = binding.clone();
            read = binding.field("right")?;
        }
        if !self.exact_function(&read, "file_get_contents") {
            return None;
        }
        let args = read.field("arguments")?;
        let args: Vec<_> = args.children().filter(|arg| arg.is_named()).collect();
        if args.len() == 1 && matches!(args[0].text().trim(), "'php://input'" | "\"php://input\"") {
            Some(origin)
        } else {
            None
        }
    }

    pub(super) fn exact_function(&self, node: &PhpNode<'a>, canonical: &str) -> bool {
        node.kind().as_ref() == "function_call_expression"
            && node
                .field("function")
                .filter(|name| {
                    let observed = name.text().trim().to_ascii_lowercase();
                    observed.trim_start_matches('\\') == canonical
                        || self.imports.iter().any(|import| {
                            import.function
                                && import.alias == observed
                                && import.target == canonical
                        })
                })
                .and_then(|name| self.resolve(&name, true))
                .as_deref()
                == Some(canonical)
            && node.field("arguments").is_some_and(|args| {
                !args
                    .dfs()
                    .any(|part| matches!(part.kind().as_ref(), ":" | "..."))
            })
    }

    fn curl_origin(&self, call: &PhpNode<'a>) -> Option<(PhpNode<'a>, PhpNode<'a>)> {
        if self.namespaced_scope(&namespace_scope(call, &self.root)) {
            return None;
        }
        let arguments = call.field("arguments")?;
        let handle_arg = arguments.children().find(|n| n.is_named())?;
        let handle = handle_arg.children().find(|n| n.is_named())?;
        if handle.kind().as_ref() != "variable_name" {
            return None;
        }
        let owner = function_scope(call, &self.root);
        let writes: Vec<_> = self
            .root
            .dfs()
            .filter(|n| {
                n.range().start < call.range().start
                    && matches!(
                        n.kind().as_ref(),
                        "assignment_expression"
                            | "reference_assignment_expression"
                            | "augmented_assignment_expression"
                    )
                    && function_scope(n, &self.root) == owner
                    && n.field("left")
                        .is_some_and(|left| left.text() == handle.text())
            })
            .collect();
        let [binding] = writes.as_slice() else {
            return None;
        };
        if binding.kind().as_ref() != "assignment_expression"
            || !mandatory_before(binding, call, &owner)
        {
            return None;
        }
        let init = binding.field("right")?;
        if !self.exact_function(&init, "curl_init") {
            return None;
        }
        let init_args = init.field("arguments")?;
        let init_args: Vec<_> = init_args.children().filter(|n| n.is_named()).collect();
        if init_args.len() > 1 {
            return None;
        }
        let mut endpoint = init_args.first().cloned();
        for prior in self.root.dfs().filter(|n| {
            n.range().start >= binding.range().end
                && n.range().end <= call.range().start
                && function_scope(n, &self.root) == owner
        }) {
            if matches!(
                prior.kind().as_ref(),
                "include_expression"
                    | "include_once_expression"
                    | "require_expression"
                    | "require_once_expression"
                    | "reference_assignment_expression"
                    | "unset_statement"
            ) {
                return None;
            }
            if !matches!(
                prior.kind().as_ref(),
                "function_call_expression" | "member_call_expression"
            ) {
                continue;
            }
            let Some(args) = prior.field("arguments") else {
                continue;
            };
            if !args
                .dfs()
                .any(|n| n.kind().as_ref() == "variable_name" && n.text() == handle.text())
            {
                continue;
            }
            if !self.exact_function(&prior, "curl_setopt") {
                return None;
            }
            let args: Vec<_> = args.children().filter(|n| n.is_named()).collect();
            if args.len() != 3 || args[0].text() != handle.text() {
                return None;
            }
            // No option-array or callback summaries; unknown/dynamic options
            // can replace URL, mutate handles, or change transport behavior.
            if !matches!(
                args[1].text().trim(),
                "CURLOPT_URL"
                    | "CURLOPT_SSL_VERIFYPEER"
                    | "CURLOPT_SSL_VERIFYHOST"
                    | "CURLOPT_RETURNTRANSFER"
                    | "CURLOPT_TIMEOUT"
                    | "CURLOPT_CONNECTTIMEOUT"
                    | "CURLOPT_FOLLOWLOCATION"
                    | "CURLOPT_NOBODY"
            ) {
                return None;
            }
            if !mandatory_before(&prior, call, &owner) {
                return None;
            }
            if args[1].text().trim() == "CURLOPT_URL" {
                endpoint = Some(args[2].clone());
            }
        }
        Some((binding.clone(), endpoint?))
    }

    fn pdo_statement_origin(&self, call: &PhpNode<'a>) -> Option<(PhpNode<'a>, PhpNode<'a>)> {
        let receiver = call.field("object")?;
        if receiver.kind().as_ref() != "variable_name" {
            return None;
        }
        let owner = function_scope(call, &self.root);
        let writes: Vec<_> = self
            .root
            .dfs()
            .filter(|n| {
                n.range().start < call.range().start
                    && function_scope(n, &self.root) == owner
                    && matches!(
                        n.kind().as_ref(),
                        "assignment_expression"
                            | "reference_assignment_expression"
                            | "augmented_assignment_expression"
                    )
                    && n.field("left")
                        .is_some_and(|left| left.text() == receiver.text())
            })
            .collect();
        let [binding] = writes.as_slice() else {
            return None;
        };
        if binding.kind().as_ref() != "assignment_expression"
            || !mandatory_before(binding, call, &owner)
        {
            return None;
        }
        let prepare = binding.field("right")?;
        if prepare.kind().as_ref() != "member_call_expression"
            || !prepare
                .field("name")?
                .text()
                .eq_ignore_ascii_case("prepare")
            || !self.native_database_receiver(&prepare.field("object")?, &prepare, "pdo")
        {
            return None;
        }
        let args = prepare.field("arguments")?;
        if args.dfs().any(|n| matches!(n.kind().as_ref(), ":" | "...")) {
            return None;
        }
        let query = args.children().find(|n| n.is_named())?;
        let expression = query.children().find(|n| n.is_named())?;
        // Preparing interpolated SQL must never become parameter protection.
        if !matches!(expression.kind().as_ref(), "string" | "encapsed_string")
            || expression.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "variable_name" | "function_call_expression" | "member_call_expression"
                )
            })
        {
            return None;
        }
        if self.root.dfs().any(|n| {
            function_scope(&n, &self.root) == owner
                && n.range().start >= binding.range().end
                && n.range().end <= call.range().start
                && (matches!(
                    n.kind().as_ref(),
                    "include_expression"
                        | "include_once_expression"
                        | "require_expression"
                        | "require_once_expression"
                        | "reference_assignment_expression"
                        | "unset_statement"
                ) || matches!(
                    n.kind().as_ref(),
                    "function_call_expression" | "member_call_expression"
                ) && n.field("arguments").is_some_and(|args| {
                    args.dfs().any(|arg| {
                        arg.kind().as_ref() == "variable_name" && arg.text() == receiver.text()
                    })
                }))
        }) {
            return None;
        }
        Some((binding.clone(), query))
    }

    fn namespaced_scope(&self, scope: &Range<usize>) -> bool {
        self.namespaced_scopes.contains(scope)
    }

    fn global_shadow(&self, canonical: &str, function: bool) -> bool {
        self.declarations.iter().any(|(name, kind, scope)| {
            *kind == function && name == canonical && !self.namespaced_scope(scope)
        })
    }

    fn native_database_receiver(
        &self,
        receiver: &PhpNode<'a>,
        call: &PhpNode<'a>,
        class: &str,
    ) -> bool {
        if receiver.kind().as_ref() == "member_access_expression" {
            return self.native_database_property(receiver, call, class);
        }
        if receiver.kind().as_ref() != "variable_name" {
            return false;
        };
        let owner = function_scope(call, &self.root);
        let includes: Vec<_> = self
            .root
            .dfs()
            .filter(|prior| {
                prior.range().start < call.range().start
                    && function_scope(prior, &self.root) == owner
                    && matches!(
                        prior.kind().as_ref(),
                        "include_expression"
                            | "include_once_expression"
                            | "require_expression"
                            | "require_once_expression"
                    )
            })
            .collect();
        // Unknown includes can replace any receiver. Only one mandatory,
        // anchored include with a conservative config summary is admitted.
        let included_origin = if includes.is_empty() {
            None
        } else {
            let [include] = includes.as_slice() else {
                return false;
            };
            if include
                .parent()
                .is_none_or(|n| n.kind().as_ref() != "expression_statement")
                || include
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
                                | "do_statement"
                                | "switch_statement"
                                | "catch_clause"
                        )
                    })
            {
                return false;
            }
            let Some((_, _, exports)) = self
                .included
                .iter()
                .find(|(range, _, _)| *range == include.range())
            else {
                return false;
            };
            Some(exports)
        };
        // A by-reference helper can replace a local receiver. Without a call
        // summary, do not carry its construction/type through that boundary.
        if self.root.dfs().any(|prior| {
            matches!(
                prior.kind().as_ref(),
                "function_call_expression" | "member_call_expression"
            ) && prior.range().start < call.range().start
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
                    "assignment_expression"
                        | "augmented_assignment_expression"
                        | "reference_assignment_expression"
                ) && function_scope(n, &self.root) == owner
                    && n.range().start < call.range().start
                    && n.field("left")
                        .is_some_and(|left| left.text() == receiver.text())
            })
            .collect();
        if !assignments.is_empty() {
            if included_origin.is_some() {
                return false;
            }
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
                return self.creation_is_native_database(assignment, class);
            };
            if !contains(&block.range(), &call.range()) {
                return false;
            };
            return self.creation_is_native_database(assignment, class);
        }
        if let Some(exports) = included_origin {
            return !self.global_shadow(class, false)
                && exports
                    .get(receiver.text().as_ref())
                    .is_some_and(|(native, _)| native == class);
        }
        self.root.dfs().any(|parameter| {
            parameter.kind().as_ref() == "simple_parameter"
                && function_scope(&parameter, &self.root) == owner
                && parameter
                    .field("name")
                    .is_some_and(|n| n.text() == receiver.text())
                && parameter.field("type").is_some_and(|ty| {
                    self.resolve(&ty, false)
                        .is_some_and(|canonical| canonical == class)
                })
        })
    }

    // A single constructor assignment in the exact lexical class is a bounded
    // receiver identity fact, not cross-method value-flow inference.
    fn native_database_property(
        &self,
        receiver: &PhpNode<'a>,
        call: &PhpNode<'a>,
        class: &str,
    ) -> bool {
        if receiver.field("object").is_none_or(|n| n.text() != "$this")
            || receiver
                .field("name")
                .is_none_or(|n| n.kind().as_ref() != "name")
        {
            return false;
        }
        let Some(owner) = call
            .ancestors()
            .find(|n| n.kind().as_ref() == "class_declaration")
        else {
            return false;
        };
        let writes: Vec<_> = owner
            .dfs()
            .filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "assignment_expression"
                        | "augmented_assignment_expression"
                        | "reference_assignment_expression"
                ) && n
                    .ancestors()
                    .find(|n| n.kind().as_ref() == "class_declaration")
                    .is_some_and(|n| n.range() == owner.range())
                    && n.field("left").is_some_and(|n| n.text() == receiver.text())
            })
            .collect();
        let [binding] = writes.as_slice() else {
            return false;
        };
        let Some(constructor) = binding
            .ancestors()
            .find(|n| n.kind().as_ref() == "method_declaration")
        else {
            return false;
        };
        constructor
            .field("name")
            .is_some_and(|n| n.text().eq_ignore_ascii_case("__construct"))
            && binding
                .ancestors()
                .take_while(|n| n.range() != constructor.range())
                .all(|n| {
                    !matches!(
                        n.kind().as_ref(),
                        "if_statement"
                            | "else_clause"
                            | "for_statement"
                            | "foreach_statement"
                            | "while_statement"
                            | "do_statement"
                            | "switch_statement"
                            | "try_statement"
                            | "anonymous_function"
                            | "arrow_function"
                    )
                })
            && self.creation_is_native_database(binding, class)
    }

    fn creation_is_native_database(&self, assignment: &PhpNode<'a>, class: &str) -> bool {
        assignment.field("right").is_some_and(|right| {
            right.kind().as_ref() == "object_creation_expression"
                && right
                    .children()
                    .find(|n| n.is_named() && n.kind().as_ref() != "arguments")
                    .is_some_and(|name| {
                        self.resolve(&name, false)
                            .is_some_and(|canonical| canonical == class)
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

fn mandatory_before(node: &PhpNode<'_>, call: &PhpNode<'_>, owner: &Range<usize>) -> bool {
    node.range().end <= call.range().start
        && node
            .parent()
            .is_some_and(|n| n.kind().as_ref() == "expression_statement")
        && node
            .ancestors()
            .take_while(|n| n.range() != *owner)
            .all(|n| match n.kind().as_ref() {
                "for_statement" | "foreach_statement" | "while_statement" | "do_statement"
                | "switch_statement" => false,
                "if_statement" | "else_clause" | "catch_clause" | "try_statement" => node
                    .ancestors()
                    .find(|block| block.kind().as_ref() == "compound_statement")
                    .is_some_and(|block| {
                        contains(&n.range(), &block.range())
                            && contains(&block.range(), &call.range())
                    }),
                _ => true,
            })
}
