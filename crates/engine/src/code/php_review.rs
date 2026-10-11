//! Bounded producer navigation for review admission, never protection proofs.
use super::{PhpContext, PhpNode, function_scope, namespace_scope, unwrap_operand};
use std::collections::BTreeMap;

type ScopeName = (usize, usize, String);

#[derive(Default)]
pub(super) struct Producers<'a> {
    writes: BTreeMap<ScopeName, Vec<PhpNode<'a>>>,
    helpers: BTreeMap<ScopeName, Vec<PhpNode<'a>>>,
    calls: BTreeMap<ScopeName, Vec<PhpNode<'a>>>,
    owners: BTreeMap<(usize, usize), PhpNode<'a>>,
}

fn key(scope: &std::ops::Range<usize>, name: &str) -> ScopeName {
    (scope.start, scope.end, name.to_ascii_lowercase())
}

impl<'a> Producers<'a> {
    pub(super) fn collect(root: &PhpNode<'a>) -> Self {
        let mut result = Self::default();
        for node in root.dfs() {
            match node.kind().as_ref() {
                "assignment_expression"
                | "reference_assignment_expression"
                | "augmented_assignment_expression" => {
                    if let Some(left) = node.field("left") {
                        let scope = function_scope(&node, root);
                        result
                            .writes
                            .entry((scope.start, scope.end, left.text().to_string()))
                            .or_default()
                            .push(node);
                    }
                }
                "function_definition" => {
                    if let Some(name) = node.field("name") {
                        let scope = namespace_scope(&node, root);
                        result
                            .helpers
                            .entry(key(&scope, &name.text()))
                            .or_default()
                            .push(node.clone());
                        result
                            .owners
                            .insert((node.range().start, node.range().end), node);
                    }
                }
                "function_call_expression" => {
                    if let Some(name) = node
                        .field("function")
                        .filter(|n| n.kind().as_ref() == "name")
                    {
                        let scope = namespace_scope(&node, root);
                        result
                            .calls
                            .entry(key(&scope, &name.text()))
                            .or_default()
                            .push(node);
                    }
                }
                _ => (),
            }
        }
        result
    }

    fn local_value(&self, node: &PhpNode<'a>, context: &PhpContext<'a>) -> Option<PhpNode<'a>> {
        let scope = function_scope(node, &context.root);
        let write = self
            .writes
            .get(&(scope.start, scope.end, node.text().to_string()))?
            .iter()
            .filter(|n| n.range().end < node.range().start)
            .max_by_key(|n| n.range().start)?;
        (write.kind().as_ref() == "assignment_expression")
            .then(|| write.field("right"))
            .flatten()
    }

    fn possible_values(&self, node: &PhpNode<'a>, context: &PhpContext<'a>) -> Vec<PhpNode<'a>> {
        let scope = function_scope(node, &context.root);
        let mut values = Vec::new();
        for write in self
            .writes
            .get(&(scope.start, scope.end, node.text().to_string()))
            .into_iter()
            .flatten()
            .rev()
            .filter(|n| n.range().end < node.range().start)
        {
            if !matches!(
                write.kind().as_ref(),
                "assignment_expression"
                    | "reference_assignment_expression"
                    | "augmented_assignment_expression"
            ) {
                break;
            }
            if let Some(value) = write.field("right") {
                values.push(value);
            }
            // Appending text preserves the earlier content producer.
            if write.kind().as_ref() == "augmented_assignment_expression" {
                continue;
            }
            // A conditional later assignment cannot erase an earlier producer.
            if !write
                .ancestors()
                .take_while(|n| n.range() != scope)
                .any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "if_statement"
                            | "else_clause"
                            | "else_if_clause"
                            | "switch_statement"
                            | "for_statement"
                            | "foreach_statement"
                            | "while_statement"
                            | "do_statement"
                            | "try_statement"
                    )
                })
            {
                break;
            }
        }
        values
    }

    pub(super) fn origin(
        &self,
        node: &PhpNode<'a>,
        context: &PhpContext<'a>,
        depth: usize,
    ) -> Option<(&'static str, PhpNode<'a>)> {
        if depth == 0 {
            return None;
        }
        let node = unwrap_operand(node.clone());
        if direct_request(&node) {
            return Some(("request_producer", node));
        }
        if data_reader(&node, context, self) {
            return Some(("stored_data_read", node));
        }
        if matches!(
            node.kind().as_ref(),
            "variable_name" | "member_access_expression"
        ) {
            let values = self.possible_values(&node, context);
            if !values.is_empty() {
                return values
                    .iter()
                    .find_map(|value| self.origin(value, context, depth - 1));
            }
            // Exact same-file function parameter and observed call argument.
            let scope = function_scope(&node, &context.root);
            let owner = self.owners.get(&(scope.start, scope.end))?;
            let parameters = owner.field("parameters")?;
            let index = parameters
                .children()
                .filter(|n| n.is_named())
                .position(|p| {
                    p.field("name")
                        .is_some_and(|name| name.text() == node.text())
                })?;
            let name = owner.field("name")?;
            let namespace = namespace_scope(owner, &context.root);
            if context.imports.iter().any(|i| {
                i.function && i.scope == namespace && i.alias.eq_ignore_ascii_case(&name.text())
            }) {
                return None;
            }
            let helpers = self.helpers.get(&key(&namespace, &name.text()))?;
            if helpers.len() != 1 {
                return None;
            }
            for call in self
                .calls
                .get(&key(&namespace, &name.text()))
                .into_iter()
                .flatten()
            {
                let Some(args) = call.field("arguments") else {
                    continue;
                };
                if args.dfs().any(|n| {
                    matches!(n.kind().as_ref(), "variadic_unpacking")
                        || n.kind().as_ref() == "argument" && n.field("name").is_some()
                }) {
                    continue;
                }
                let Some(arg) = args.children().filter(|n| n.is_named()).nth(index) else {
                    continue;
                };
                if let Some(origin) = self.origin(&arg, context, depth - 1) {
                    return Some(origin);
                }
            }
            return None;
        }
        if node.kind().as_ref() == "function_call_expression" {
            let name = node.field("function")?;
            let namespace = namespace_scope(&node, &context.root);
            // Imports and qualified/dynamic calls need another binding layer.
            if name.kind().as_ref() == "name"
                && !name.text().contains('\\')
                && !context.imports.iter().any(|i| {
                    i.function && i.scope == namespace && i.alias.eq_ignore_ascii_case(&name.text())
                })
                && let Some(helpers) = self.helpers.get(&key(&namespace, &name.text()))
                && let [helper] = helpers.as_slice()
            {
                for returned in helper.dfs().filter(|n| {
                    n.kind().as_ref() == "return_statement"
                        && function_scope(n, &context.root) == helper.range()
                }) {
                    if let Some(value) = returned.children().find(|n| n.is_named())
                        && let Some(origin) = self.origin(&value, context, depth - 1)
                    {
                        return Some(origin);
                    }
                }
            }
        }
        // Children are syntax-bound parts of this operand, not nearby sources.
        node.children()
            .filter(|n| n.is_named())
            .find_map(|part| self.origin(&part, context, depth - 1))
    }
}

pub(super) fn direct_request(node: &PhpNode<'_>) -> bool {
    let node = unwrap_operand(node.clone());
    match node.kind().as_ref() {
        "variable_name" => matches!(
            node.text().as_ref(),
            "$_GET" | "$_POST" | "$_REQUEST" | "$_COOKIE" | "$_FILES"
        ),
        "subscript_expression" => node
            .children()
            .find(|n| n.is_named())
            .is_some_and(|n| direct_request(&n)),
        "binary_expression" if node.field("operator").is_some_and(|n| n.text() == ".") => {
            node.field("left").is_some_and(|n| direct_request(&n))
                || node.field("right").is_some_and(|n| direct_request(&n))
        }
        "encapsed_string" => node
            .children()
            .filter(|n| n.is_named())
            .any(|n| direct_request(&n)),
        _ => false,
    }
}

fn data_reader<'a>(
    node: &PhpNode<'a>,
    context: &PhpContext<'a>,
    producers: &Producers<'a>,
) -> bool {
    if [
        "file_get_contents",
        "mysqli_fetch_assoc",
        "mysqli_fetch_array",
        "mysqli_fetch_row",
        "mysqli_fetch_object",
        "mysqli_fetch_column",
        "pg_fetch_assoc",
        "pg_fetch_array",
        "pg_fetch_result",
    ]
    .iter()
    .any(|name| context.exact_function(node, name))
    {
        return true;
    }
    if node.kind().as_ref() != "member_call_expression"
        || node.field("name").is_none_or(|n| {
            !matches!(
                n.text().to_ascii_lowercase().as_str(),
                "fetch" | "fetchall" | "fetchcolumn" | "fetchobject" | "fetcharray"
            )
        })
    {
        return false;
    }
    let Some(receiver) = node.field("object") else {
        return false;
    };
    if context.native_database_receiver(&receiver, node, "pdostatement")
        || context.native_database_receiver(&receiver, node, "sqlite3result")
        || context.pdo_statement_origin(node).is_some()
    {
        return true;
    }
    let value = producers
        .local_value(&receiver, context)
        .unwrap_or(receiver);
    value.kind().as_ref() == "member_call_expression"
        && value
            .field("name")
            .is_some_and(|n| matches!(n.text().to_ascii_lowercase().as_str(), "query" | "prepare"))
        && value
            .field("object")
            .is_some_and(|object| context.native_database_receiver(&object, &value, "pdo"))
}
