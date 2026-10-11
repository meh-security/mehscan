//! Bounded query objects and process options. No heap/CFG or verdict transfer.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Evidence, EvidenceKind, Language, Location, OperandFact, OperandFactKind,
    Position,
};
use std::collections::{BTreeMap, BTreeSet};

type JsNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(crate) fn annotate(
    language: Language,
    source: &str,
    root: &JsNode<'_>,
    evidence: &mut [Evidence],
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        return;
    }
    let targets = evidence.iter().any(|item| {
        item.kind == EvidenceKind::Sink
            && matches!(
                item.capability,
                Capability::DatabaseQuery | Capability::ProcessExecution
            )
    });
    if !targets {
        return;
    }
    let ranges = evidence
        .iter()
        .filter(|item| {
            matches!(
                item.capability,
                Capability::DatabaseQuery | Capability::ProcessExecution
            )
        })
        .flat_map(|item| {
            std::iter::once((
                item.location.start.byte_offset,
                item.location.end.byte_offset,
            ))
            .chain(item.captures.get("query").map(|capture| {
                (
                    capture.location.start.byte_offset,
                    capture.location.end.byte_offset,
                )
            }))
        })
        .collect::<BTreeSet<_>>();
    let index = LocalObjects::new(root, &ranges);
    for item in evidence
        .iter_mut()
        .filter(|item| item.kind == EvidenceKind::Sink)
    {
        match item.capability {
            Capability::DatabaseQuery if item.tags.iter().any(|tag| tag == "sql") => {
                let Some(capture) = item.captures.get("query") else {
                    continue;
                };
                let Some(node) = index.nodes.get(&(
                    capture.location.start.byte_offset,
                    capture.location.end.byte_offset,
                )) else {
                    continue;
                };
                if !matches!(node.kind().as_ref(), "identifier" | "object") {
                    continue;
                }
                let Some(object) = resolve_object(&index, source, item, node, "query") else {
                    continue;
                };
                let Some(properties) = properties(&object) else {
                    boundary(
                        source,
                        item,
                        "query",
                        &object,
                        "object_members_or_overrides",
                    );
                    continue;
                };
                let text = properties.get("text").or_else(|| properties.get("sql"));
                let Some(text) = text else {
                    boundary(source, item, "query", &object, "query_text_slot");
                    continue;
                };
                if properties.contains_key("text") && properties.contains_key("sql") {
                    boundary(source, item, "query", &object, "ambiguous_query_text_slot");
                    continue;
                }
                item.captures
                    .insert("query_text".into(), capture_at(source, item, text));
                let values = properties.get("values");
                if let Some(values) = values {
                    item.captures
                        .insert("query_values".into(), capture_at(source, item, values));
                }
                let fixed = fixed_string(text);
                fact(
                    source,
                    item,
                    "query",
                    OperandFactKind::QueryStructure,
                    text,
                    if fixed && values.is_some() {
                        "fixed_text_with_values"
                    } else if fixed {
                        "fixed_text"
                    } else {
                        "nonliteral_text"
                    },
                    &[
                        "driver_binding_contract",
                        "value_shape",
                        "data_access_policy",
                    ],
                );
                // The owned driver receives fixed grammar and separate data slots.
                // This closes injection, not record authorization.
                if fixed
                    && values.is_some_and(|value| value.kind().as_ref() == "array")
                    && item
                        .symbol_resolution
                        .as_ref()
                        .is_some_and(|identity| identity.canonical == "pg.Client.query")
                    && !properties
                        .keys()
                        .any(|key| !matches!(key.as_str(), "text" | "values"))
                    && invocation_arguments(&index, item).is_some_and(|args| args.len() == 1)
                {
                    if let Some(write) = index.query_writes.first() {
                        boundary(source, item, "query", write, "observed_query_method_write");
                    } else {
                        tag(item, "query-closure:pg-fixed-bound-object");
                        for fact in &mut item.context.operand_facts {
                            if fact.kind == OperandFactKind::QueryStructure {
                                fact.remaining_checks = vec!["data_access_policy".into()];
                            }
                        }
                    }
                }
            }
            Capability::ProcessExecution => {
                let Some(identity) = item.symbol_resolution.as_ref() else {
                    continue;
                };
                if !matches!(
                    identity.canonical.as_str(),
                    "child_process.execFile"
                        | "child_process.execFileSync"
                        | "child_process.spawn"
                        | "child_process.spawnSync"
                ) {
                    continue;
                }
                let Some(args) = invocation_arguments(&index, item) else {
                    continue;
                };
                // Only the unambiguous (program, argv array, options) overload.
                if args.len() < 3 || args[1].kind().as_ref() != "array" {
                    continue;
                }
                let node = &args[2];
                if matches!(
                    node.kind().as_ref(),
                    "arrow_function" | "function_expression"
                ) {
                    continue; // The callback overload, not an options object.
                }
                if node.range().len() <= 2048 {
                    item.captures.insert(
                        "process_options_operand".into(),
                        capture_at(source, item, node),
                    );
                }
                let Some(object) = resolve_object(&index, source, item, node, "process_options")
                else {
                    tag(item, "review-origin:decision-critical");
                    continue;
                };
                let Some(properties) = properties(&object) else {
                    boundary(
                        source,
                        item,
                        "process_options",
                        &object,
                        "object_members_or_overrides",
                    );
                    tag(item, "review-origin:decision-critical");
                    continue;
                };
                if properties.contains_key("__proto__") {
                    boundary(
                        source,
                        item,
                        "process_options",
                        &object,
                        "prototype_options",
                    );
                    tag(item, "review-origin:decision-critical");
                    continue;
                }
                let Some(shell) = properties.get("shell") else {
                    continue;
                };
                let mode = match shell.kind().as_ref() {
                    "true" => "true",
                    "false" => "false",
                    "string" if shell.text().len() > 2 => "custom_shell",
                    _ => "unresolved",
                };
                item.captures
                    .insert("shell_mode".into(), capture_at(source, item, shell));
                fact(
                    source,
                    item,
                    "process_options",
                    OperandFactKind::ProcessShellMode,
                    shell,
                    mode,
                    &["executable_policy", "argument_semantics", "platform"],
                );
                if matches!(mode, "true" | "custom_shell") {
                    item.tags
                        .retain(|tag| tag != "process-invocation:executable-selection");
                    tag(item, "process-invocation:shell-command");
                    tag(item, "shell-command-text");
                    if let Some(arguments) = item.captures.get("arguments").cloned() {
                        item.captures.insert("shell_command".into(), arguments);
                    }
                }
                if mode != "false" {
                    tag(item, "review-origin:decision-critical");
                }
            }
            _ => {}
        }
    }
}

struct LocalObjects<'a> {
    nodes: BTreeMap<(usize, usize), JsNode<'a>>,
    bindings: BTreeMap<(usize, String), Vec<JsNode<'a>>>,
    uses: BTreeMap<String, Vec<JsNode<'a>>>,
    query_writes: Vec<JsNode<'a>>,
}

impl<'a> LocalObjects<'a> {
    fn new(root: &JsNode<'a>, ranges: &BTreeSet<(usize, usize)>) -> Self {
        let mut index = Self {
            nodes: BTreeMap::new(),
            bindings: BTreeMap::new(),
            uses: BTreeMap::new(),
            query_writes: Vec::new(),
        };
        for node in root.dfs().filter(|node| node.is_named()) {
            // A visible method write invalidates identity-based query closure.
            // Deliberately file-wide: no receiver/alias/dispatch proof is claimed.
            if matches!(
                node.kind().as_ref(),
                "assignment_expression" | "augmented_assignment_expression" | "update_expression"
            ) {
                if let Some(left) = node.field("left").or_else(|| node.field("argument")) {
                    if (left.kind().as_ref() == "member_expression"
                        && left
                            .field("property")
                            .is_some_and(|key| key.text() == "query"))
                        || left.kind().as_ref() == "subscript_expression"
                    {
                        index.query_writes.push(left);
                    }
                }
            }
            if ranges.contains(&(node.range().start, node.range().end)) {
                index
                    .nodes
                    .insert((node.range().start, node.range().end), node.clone());
            }
            if node.kind().as_ref() == "variable_declarator" {
                if let Some(name) = node
                    .field("name")
                    .filter(|name| name.kind().as_ref() == "identifier")
                {
                    if let Some(scope) = scope(&node) {
                        index
                            .bindings
                            .entry((scope.range().start, name.text().to_string()))
                            .or_default()
                            .push(node.clone());
                    }
                }
            }
            if matches!(
                node.kind().as_ref(),
                "identifier" | "shorthand_property_identifier"
            ) {
                index
                    .uses
                    .entry(node.text().to_string())
                    .or_default()
                    .push(node);
            }
        }
        index
    }
}

fn scope<'a>(node: &JsNode<'a>) -> Option<JsNode<'a>> {
    node.ancestors()
        .find(|node| matches!(node.kind().as_ref(), "statement_block" | "program"))
}

fn resolve_object<'a>(
    index: &LocalObjects<'a>,
    source: &str,
    item: &mut Evidence,
    node: &JsNode<'a>,
    role: &str,
) -> Option<JsNode<'a>> {
    if node.range().len() > 2048 {
        boundary(source, item, role, node, "oversized_object_initializer");
        return None;
    }
    if node.kind().as_ref() == "object" {
        return Some(node.clone());
    }
    if node.kind().as_ref() != "identifier" {
        boundary(source, item, role, node, "operand_producer");
        return None;
    }
    let owner = scope(node)?;
    let bindings = index
        .bindings
        .get(&(owner.range().start, node.text().to_string()));
    let Some([binding]) = bindings.map(Vec::as_slice) else {
        boundary(source, item, role, node, "unique_local_const_binding");
        return None;
    };
    let declaration = binding.parent()?;
    let const_binding = declaration.kind().as_ref() == "lexical_declaration"
        && declaration
            .children()
            .any(|child| child.kind().as_ref() == "const")
        && declaration
            .parent()
            .is_some_and(|parent| parent.range() == owner.range())
        && declaration.range().end <= node.range().start;
    let Some(value) = binding.field("value") else {
        boundary(source, item, role, binding, "operand_initializer");
        return None;
    };
    fact(
        source,
        item,
        role,
        OperandFactKind::LocalOperandOrigin,
        &value,
        &node.text(),
        &["local_binding_applicability"],
    );
    if !const_binding {
        boundary(source, item, role, binding, "direct_local_const_binding");
        return None;
    }
    if let Some(usage) = index
        .uses
        .get(node.text().as_ref())
        .into_iter()
        .flatten()
        .find(|usage| {
            usage.range().start >= binding.range().end
                && usage.range().start < node.range().start
                && usage.range().start >= owner.range().start
                && usage.range().end <= owner.range().end
        })
    {
        boundary(source, item, role, usage, "intervening_use_or_escape");
        return None;
    }
    // An expression-bodied nested callable can capture the outer block binding.
    let callable = |node: &JsNode<'a>| {
        node.ancestors()
            .find(|node| {
                matches!(
                    node.kind().as_ref(),
                    "function_declaration"
                        | "function_expression"
                        | "arrow_function"
                        | "method_definition"
                        | "generator_function"
                        | "generator_function_declaration"
                )
            })
            .map(|node| node.range())
    };
    if callable(binding) != callable(node) {
        boundary(source, item, role, node, "callable_owner");
        return None;
    }
    if value.kind().as_ref() != "object" {
        boundary(source, item, role, &value, "one_object_initializer");
        return None;
    }
    if value.range().len() > 2048 {
        boundary(source, item, role, &value, "oversized_object_initializer");
        return None;
    }
    item.captures
        .insert(format!("{role}_origin"), capture_at(source, item, &value));
    Some(value)
}

fn properties<'a>(object: &JsNode<'a>) -> Option<BTreeMap<String, JsNode<'a>>> {
    let mut properties = BTreeMap::new();
    for child in object
        .children()
        .filter(|child| child.is_named() && child.kind().as_ref() != "comment")
    {
        if child.kind().as_ref() != "pair" {
            return None;
        }
        let key = child.field("key")?;
        if !matches!(key.kind().as_ref(), "property_identifier" | "string") {
            return None;
        }
        let name = key.text().trim_matches(['\'', '"']).to_string();
        // Escaped string keys are direction, not a decoded property identity.
        if name.contains('\\') || properties.insert(name, child.field("value")?).is_some() {
            return None;
        }
    }
    Some(properties)
}

fn invocation_arguments<'a>(index: &LocalObjects<'a>, item: &Evidence) -> Option<Vec<JsNode<'a>>> {
    let call = index.nodes.get(&(
        item.location.start.byte_offset,
        item.location.end.byte_offset,
    ))?;
    let args = call.field("arguments")?;
    let args = args
        .children()
        .filter(|child| child.is_named() && child.kind().as_ref() != "comment")
        .collect::<Vec<_>>();
    (!args
        .iter()
        .any(|arg| arg.kind().as_ref() == "spread_element"))
    .then_some(args)
}

fn fixed_string(node: &JsNode<'_>) -> bool {
    matches!(node.kind().as_ref(), "string" | "template_string")
        && !node
            .dfs()
            .any(|part| part.kind().as_ref() == "template_substitution")
}

pub(super) fn capture_at(_source: &str, item: &Evidence, node: &JsNode<'_>) -> Capture {
    let start = node.start_pos();
    let end = node.end_pos();
    Capture {
        text: node.text().to_string(),
        location: Location {
            path: item.location.path.clone(),
            start: Position {
                line: start.line() + 1,
                column: start.column(node) + 1,
                byte_offset: node.range().start,
            },
            end: Position {
                line: end.line() + 1,
                column: end.column(node) + 1,
                byte_offset: node.range().end,
            },
        },
    }
}

fn fact(
    source: &str,
    item: &mut Evidence,
    role: &str,
    kind: OperandFactKind,
    node: &JsNode<'_>,
    value: &str,
    checks: &[&str],
) {
    item.context.operand_facts.push(OperandFact {
        role: role.into(),
        kind,
        location: capture_at(source, item, node).location,
        value: value.into(),
        remaining_checks: checks.iter().map(|check| (*check).into()).collect(),
    });
}
fn boundary(source: &str, item: &mut Evidence, role: &str, node: &JsNode<'_>, check: &str) {
    fact(
        source,
        item,
        role,
        OperandFactKind::OperandBoundary,
        node,
        check,
        &[check],
    );
}
fn tag(item: &mut Evidence, value: &str) {
    if !item.tags.iter().any(|tag| tag == value) {
        item.tags.push(value.into());
    }
}
