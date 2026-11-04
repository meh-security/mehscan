//! Bounded local digest summaries. Names and unrelated imports prove no hashing.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::collections::BTreeMap;

type N<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) struct DigestHelpers<'a> {
    helpers: BTreeMap<String, Option<N<'a>>>,
    imports: BTreeMap<String, String>,
    scopes: BTreeMap<usize, BTreeMap<String, usize>>,
}

impl<'a> DigestHelpers<'a> {
    pub(super) fn new(root: &N<'a>) -> Self {
        let mut index = Self {
            helpers: BTreeMap::new(),
            imports: BTreeMap::new(),
            scopes: BTreeMap::new(),
        };
        for declaration in root.children().filter(|n| n.kind() == "import_declaration") {
            for node in declaration.dfs().filter(|n| n.kind() == "import_spec") {
                let Some(path) = node.field("path") else {
                    continue;
                };
                let path = path.text().trim_matches(['"', '`']).to_string();
                let alias = node
                    .field("name")
                    .map(|n| n.text().into_owned())
                    .unwrap_or_else(|| path.rsplit('/').next().unwrap_or_default().to_string());
                if alias != "." && alias != "_" {
                    index.imports.insert(alias, path);
                }
            }
        }
        if !index.imports.values().any(|path| path == "crypto/md5") {
            return index;
        }
        for node in root.dfs() {
            let names = match node.kind().as_ref() {
                "short_var_declaration" | "range_clause" => node
                    .field("left")
                    .map(|left| {
                        left.children()
                            .filter(|n| n.kind() == "identifier")
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                "parameter_declaration"
                | "variadic_parameter_declaration"
                | "var_spec"
                | "const_spec" => {
                    let end = node
                        .field("type")
                        .or_else(|| node.field("value"))
                        .map(|n| n.range().start)
                        .unwrap_or(usize::MAX);
                    node.children()
                        .filter(|n| n.kind() == "identifier" && n.range().start < end)
                        .collect()
                }
                _ => Vec::new(),
            };
            if names.is_empty() {
                continue;
            }
            let parameter = matches!(
                node.kind().as_ref(),
                "parameter_declaration" | "variadic_parameter_declaration"
            );
            let Some(scope) = node.ancestors().find(|n| {
                if parameter {
                    matches!(
                        n.kind().as_ref(),
                        "function_declaration" | "method_declaration" | "func_literal"
                    )
                } else {
                    matches!(
                        n.kind().as_ref(),
                        "block"
                            | "if_statement"
                            | "for_statement"
                            | "expression_switch_statement"
                            | "type_switch_statement"
                            | "source_file"
                    )
                }
            }) else {
                continue;
            };
            for name in names {
                let start = if parameter || scope.kind() == "source_file" {
                    0
                } else {
                    node.range().end
                };
                index
                    .scopes
                    .entry(scope.node_id())
                    .or_default()
                    .entry(name.text().into_owned())
                    .and_modify(|at| *at = (*at).min(start))
                    .or_insert(start);
            }
        }
        for function in root
            .children()
            .filter(|n| n.kind() == "function_declaration")
        {
            let Some(name) = function.field("name") else {
                continue;
            };
            let name = name.text().into_owned();
            let proof = index.summarizes(&function).then_some(function);
            // Ambiguous declarations never lend another implementation's proof.
            index
                .helpers
                .entry(name)
                .and_modify(|old| *old = None)
                .or_insert(proof);
        }
        index.helpers.retain(|_, proof| proof.is_some());
        index
    }

    pub(super) fn is_empty(&self) -> bool {
        self.helpers.is_empty()
    }

    fn unshadowed(&self, at: &N<'_>, name: &str) -> bool {
        !at.ancestors().any(|scope| {
            self.scopes
                .get(&scope.node_id())
                .and_then(|names| names.get(name))
                .is_some_and(|start| *start <= at.range().start)
        })
    }

    fn api(&self, call: &N<'_>, package: &str, member: &str) -> bool {
        let Some(function) = call.field("function") else {
            return false;
        };
        let Some(receiver) = function.field("operand") else {
            return false;
        };
        let name = receiver.text();
        receiver.kind() == "identifier"
            && function.field("field").is_some_and(|n| n.text() == member)
            && self
                .imports
                .get(name.as_ref())
                .is_some_and(|path| path == package)
            && self.unshadowed(call, name.as_ref())
    }

    fn summarizes(&self, function: &N<'_>) -> bool {
        let Some(parameters) = function.field("parameters") else {
            return false;
        };
        let parameters = parameters
            .children()
            .filter(|n| n.is_named())
            .collect::<Vec<_>>();
        if parameters.len() != 1 {
            return false;
        }
        let parameter = &parameters[0];
        if !parameter
            .field("type")
            .is_some_and(|n| n.text() == "string")
        {
            return false;
        }
        let names = parameter
            .children()
            .filter(|n| n.kind() == "identifier")
            .collect::<Vec<_>>();
        if names.len() != 1 {
            return false;
        }
        let input = names[0].text();
        let Some(body) = function.field("body") else {
            return false;
        };
        // Straight-line construction only. Extra branches, writes, rebindings or
        // returns require a separate summary, never a best-effort name guess.
        let Some(statements) = body.children().find(|n| n.kind() == "statement_list") else {
            return false;
        };
        let statements = statements
            .children()
            .filter(|n| n.is_named() && n.kind() != "comment")
            .collect::<Vec<_>>();
        if statements.len() != 3 {
            return false;
        }
        let first = &statements[0];
        if first.kind() != "short_var_declaration" {
            return false;
        }
        let Some(left) = first.field("left") else {
            return false;
        };
        let names = left.children().filter(|n| n.is_named()).collect::<Vec<_>>();
        if names.len() != 1 || names[0].kind() != "identifier" {
            return false;
        }
        let receiver = names[0].text();
        let Some(right) = first.field("right") else {
            return false;
        };
        let values = right
            .children()
            .filter(|n| n.is_named())
            .collect::<Vec<_>>();
        if values.len() != 1
            || !self.api(&values[0], "crypto/md5", "New")
            || !arguments(&values[0]).is_empty()
        {
            return false;
        }
        let Some(write) = statements[1]
            .children()
            .find(|n| n.kind() == "call_expression")
        else {
            return false;
        };
        if !write
            .field("function")
            .is_some_and(|n| compact(&n.text()) == format!("{receiver}.Write"))
            || arguments(&write).len() != 1
            || compact(&arguments(&write)[0].text()) != format!("[]byte({input})")
        {
            return false;
        }
        if statements[2].kind() != "return_statement" {
            return false;
        }
        let Some(returned) = statements[2].children().find(|n| n.is_named()) else {
            return false;
        };
        let value = if returned.kind() == "expression_list" {
            let values = returned
                .children()
                .filter(|n| n.is_named())
                .collect::<Vec<_>>();
            if values.len() != 1 {
                return false;
            }
            values[0].clone()
        } else {
            returned
        };
        let args = arguments(&value);
        self.api(&value, "encoding/hex", "EncodeToString")
            && args.len() == 1
            && compact(&args[0].text()) == format!("{receiver}.Sum(nil)")
    }

    pub(super) fn proof(&self, call: &N<'_>) -> Option<&N<'a>> {
        if arguments(call).len() != 1 {
            return None;
        }
        let function = call.field("function")?;
        if function.kind() != "identifier" {
            return None;
        }
        let name = function.text();
        self.unshadowed(call, name.as_ref()).then_some(())?;
        self.helpers.get(name.as_ref())?.as_ref()
    }
}

fn arguments<'a>(call: &N<'a>) -> Vec<N<'a>> {
    call.field("arguments")
        .map(|n| n.children().filter(|n| n.is_named()).collect())
        .unwrap_or_default()
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}
