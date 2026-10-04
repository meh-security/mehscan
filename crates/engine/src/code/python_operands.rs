//! Bounded subprocess keyword evidence; no execution or safety closure.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capture, Evidence, Language, OperandFact, OperandFactKind};
use std::collections::{BTreeMap, BTreeSet};
type PyNode<'a> = Node<'a, StrDoc<SupportLang>>;

fn owner<'a>(node: &PyNode<'a>) -> Option<PyNode<'a>> {
    node.ancestors()
        .find(|n| matches!(n.kind().as_ref(), "function_definition" | "lambda"))
}

fn fact(item: &mut Evidence, role: &str, kind: OperandFactKind, node: &PyNode<'_>, value: &str) {
    item.context.operand_facts.push(OperandFact {
        role: role.into(),
        kind,
        location: super::matcher::location(&item.location.path, node),
        value: value.into(),
        remaining_checks: vec![
            "callable_contract".into(),
            "argument_semantics".into(),
            "platform_and_execution".into(),
        ],
    });
}
fn boundary(item: &mut Evidence, node: &PyNode<'_>, reason: &str) {
    fact(
        item,
        "process_options",
        OperandFactKind::OperandBoundary,
        node,
        reason,
    );
    if !item
        .tags
        .iter()
        .any(|t| t == "review-origin:decision-critical")
    {
        item.tags.push("review-origin:decision-critical".into());
    }
}

struct Locals<'a> {
    calls: BTreeMap<(usize, usize), PyNode<'a>>,
    bindings: BTreeMap<(usize, String), Vec<PyNode<'a>>>,
    uses: BTreeMap<String, Vec<PyNode<'a>>>,
    method_write: Option<PyNode<'a>>,
}
impl<'a> Locals<'a> {
    fn new(root: &PyNode<'a>, ranges: &BTreeSet<(usize, usize)>) -> Self {
        let mut index = Self {
            calls: BTreeMap::new(),
            bindings: BTreeMap::new(),
            uses: BTreeMap::new(),
            method_write: None,
        };
        for node in root.dfs().filter(|n| n.is_named()) {
            if ranges.contains(&(node.range().start, node.range().end)) {
                index
                    .calls
                    .insert((node.range().start, node.range().end), node.clone());
            }
            if matches!(
                node.kind().as_ref(),
                "assignment" | "augmented_assignment" | "named_expression"
            ) {
                if let Some(left) = node
                    .field("left")
                    .filter(|n| n.kind().as_ref() == "attribute")
                {
                    if left.field("attribute").is_some_and(|n| {
                        matches!(
                            n.text().as_ref(),
                            "run" | "Popen" | "call" | "check_call" | "check_output"
                        )
                    }) {
                        index.method_write = Some(left);
                    }
                }
                if let Some(left) = node
                    .field("left")
                    .or_else(|| node.field("name"))
                    .filter(|n| n.kind().as_ref() == "identifier")
                {
                    if let Some(scope) = owner(&node) {
                        index
                            .bindings
                            .entry((scope.range().start, left.text().into_owned()))
                            .or_default()
                            .push(node.clone());
                    }
                }
            }
            if node.kind().as_ref() == "identifier" {
                index
                    .uses
                    .entry(node.text().into_owned())
                    .or_default()
                    .push(node);
            }
        }
        index
    }
    fn dictionary(&self, item: &mut Evidence, expression: &PyNode<'a>) -> Option<PyNode<'a>> {
        if expression.range().len() > 2048 {
            boundary(item, expression, "oversized_options");
            return None;
        }
        if expression.kind().as_ref() == "dictionary" {
            return Some(expression.clone());
        }
        if expression.kind().as_ref() != "identifier" {
            boundary(item, expression, "options_producer");
            return None;
        }
        let Some(scope) = owner(expression)
            .filter(|n| n.kind().as_ref() == "function_definition" && n.range().len() <= 32 * 1024)
        else {
            boundary(item, expression, "local_callable_options");
            return None;
        };
        let Some([binding]) = self
            .bindings
            .get(&(scope.range().start, expression.text().into_owned()))
            .map(Vec::as_slice)
        else {
            boundary(item, expression, "unique_local_options_binding");
            return None;
        };
        let direct = binding.parent().and_then(|n| n.parent()).map(|n| n.range())
            == scope.field("body").map(|n| n.range());
        if !direct || binding.range().end >= expression.range().start {
            boundary(item, binding, "options_binding_order_or_branch");
            return None;
        }
        let Some(value) = binding
            .field("right")
            .filter(|n| n.kind().as_ref() == "dictionary" && n.range().len() <= 2048)
        else {
            boundary(item, binding, "literal_options_initializer");
            return None;
        };
        // Python ** expansion copies keyword slots; arbitrary prior uses can
        // mutate or leak the original dictionary, so stop rather than infer them.
        if let Some(usage) = self
            .uses
            .get(expression.text().as_ref())
            .into_iter()
            .flatten()
            .find(|n| {
                n.range().start >= binding.range().end
                    && n.range().end <= scope.range().end
                    && (n.range().start < expression.range().start
                        || owner(n).map(|n| n.range()) != Some(scope.range()))
            })
        {
            boundary(item, usage, "options_use_mutation_alias_or_capture");
            return None;
        }
        // Function-scoped rebinding targets include parameters, loops, imports,
        // global/nonlocal declarations and with/as bindings, not just assignments.
        if let Some(usage) = self
            .uses
            .get(expression.text().as_ref())
            .into_iter()
            .flatten()
            .find(|n| {
                n.range().start < binding.range().start
                    && owner(n).map(|n| n.range()) == Some(scope.range())
            })
        {
            boundary(item, usage, "earlier_options_binding_or_use");
            return None;
        }
        fact(
            item,
            "process_options",
            OperandFactKind::LocalOperandOrigin,
            &value,
            expression.text().as_ref(),
        );
        Some(value.clone())
    }
}

fn option_slots<'a>(dictionary: &PyNode<'a>) -> Option<BTreeMap<String, PyNode<'a>>> {
    let mut slots = BTreeMap::new();
    for pair in dictionary
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
    {
        if pair.kind().as_ref() != "pair" {
            return None;
        }
        let key = pair.field("key")?;
        let key = plain_string(&key)?;
        if slots.len() >= 32 || slots.insert(key, pair.field("value")?).is_some() {
            return None;
        }
    }
    Some(slots)
}

fn plain_string(node: &PyNode<'_>) -> Option<String> {
    let text = node.text();
    if !(node.kind().as_ref() == "string"
        && matches!(text.as_bytes().first(), Some(b'\'' | b'"'))
        && !text.contains('\\')
        && !node.dfs().any(|n| n.kind().as_ref() == "interpolation"))
    {
        return None;
    }
    let width = if text.starts_with("'''") || text.starts_with("\"\"\"") {
        3
    } else {
        1
    };
    text.get(width..text.len().checked_sub(width)?)
        .map(str::to_string)
}

fn explicit_shell(item: &mut Evidence, index: &Locals<'_>) {
    let Some(sequence) = item
        .captures
        .get("command")
        .and_then(|c| {
            index
                .calls
                .get(&(c.location.start.byte_offset, c.location.end.byte_offset))
        })
        .filter(|n| matches!(n.kind().as_ref(), "list" | "tuple"))
    else {
        return;
    };
    let parts = sequence
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
        .take(3)
        .collect::<Vec<_>>();
    let [program, option, script] = parts.as_slice() else {
        return;
    };
    if script.kind().as_ref() == "list_splat" {
        return;
    }
    let Some(program_name) = plain_string(program) else {
        return;
    };
    // Only exact common POSIX shell forms. PATH, runtime identity, other flags,
    // computed argv and executable replacement remain reviewer questions.
    if !matches!(
        program_name.as_str(),
        "sh" | "bash"
            | "dash"
            | "/bin/sh"
            | "/bin/bash"
            | "/bin/dash"
            | "/usr/bin/sh"
            | "/usr/bin/bash"
            | "/usr/bin/dash"
    ) || plain_string(option).as_deref() != Some("-c")
    {
        return;
    }
    for (role, node) in [("executable", program), ("shell_command", script)] {
        item.captures.insert(
            role.into(),
            Capture {
                text: node.text().into_owned(),
                location: super::matcher::location(&item.location.path, node),
            },
        );
    }
    if !item.tags.iter().any(|t| t == "shell-command-text") {
        item.tags.push("shell-command-text".into());
    }
}

pub(super) fn annotate(language: Language, root: &PyNode<'_>, evidence: &mut [Evidence]) {
    if language != Language::Python {
        return;
    }
    let relevant = |e: &&Evidence| {
        e.rule_id == "python-process-execution"
            && e.symbol_resolution.as_ref().is_some_and(|s| {
                matches!(
                    s.canonical.as_str(),
                    "subprocess.run"
                        | "subprocess.Popen"
                        | "subprocess.call"
                        | "subprocess.check_call"
                        | "subprocess.check_output"
                )
            })
    };
    let ranges = evidence
        .iter()
        .filter(relevant)
        .map(|e| (e.location.start.byte_offset, e.location.end.byte_offset))
        .collect::<BTreeSet<_>>();
    if ranges.is_empty() || root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return;
    }
    let mut node_ranges = ranges.clone();
    for item in evidence
        .iter()
        .filter(|e| ranges.contains(&(e.location.start.byte_offset, e.location.end.byte_offset)))
    {
        if let Some(c) = item.captures.get("command") {
            node_ranges.insert((c.location.start.byte_offset, c.location.end.byte_offset));
        }
    }
    let index = Locals::new(root, &node_ranges);
    'items: for item in evidence.iter_mut().filter(|e| {
        e.rule_id == "python-process-execution"
            && ranges.contains(&(e.location.start.byte_offset, e.location.end.byte_offset))
    }) {
        let Some(call) = index.calls.get(&(
            item.location.start.byte_offset,
            item.location.end.byte_offset,
        )) else {
            continue;
        };
        let Some(args) = call.field("arguments") else {
            continue;
        };
        if let Some(write) = &index.method_write {
            boundary(item, write, "observed_process_method_write");
            continue;
        }
        let mut slots = BTreeMap::new();
        for keyword in args
            .children()
            .filter(|n| n.kind().as_ref() == "keyword_argument")
        {
            let (Some(name), Some(value)) = (keyword.field("name"), keyword.field("value")) else {
                continue;
            };
            if slots.insert(name.text().into_owned(), value).is_some() {
                boundary(item, &keyword, "duplicate_keyword_argument");
                continue 'items;
            }
        }
        let splats = args
            .children()
            .filter(|n| n.kind().as_ref() == "dictionary_splat")
            .collect::<Vec<_>>();
        if let [splat] = splats.as_slice() {
            if let Some(expression) = splat
                .children()
                .find(|n| n.is_named() && n.range().len() <= 2048)
            {
                item.captures.insert(
                    "process_options_operand".into(),
                    Capture {
                        text: expression.text().into_owned(),
                        location: super::matcher::location(&item.location.path, &expression),
                    },
                );
            }
        }
        if splats.len() > 1 {
            boundary(item, &args, "multiple_keyword_expansions");
            continue;
        }
        if let [splat] = splats.as_slice() {
            let Some(expression) = splat.children().find(|n| n.is_named()) else {
                continue;
            };
            let Some(dictionary) = index.dictionary(item, &expression) else {
                continue;
            };
            match option_slots(&dictionary) {
                Some(properties) => {
                    for (name, value) in properties {
                        if slots.insert(name, value).is_some() {
                            boundary(item, &dictionary, "keyword_expansion_collision");
                            continue 'items;
                        }
                    }
                }
                None => {
                    boundary(item, &dictionary, "options_keys_merges_or_duplicates");
                    continue;
                }
            }
        }
        if let Some(executable) = slots.get("executable") {
            item.captures.insert(
                "executable".into(),
                Capture {
                    text: executable.text().into_owned(),
                    location: super::matcher::location(&item.location.path, executable),
                },
            );
            fact(
                item,
                "executable",
                OperandFactKind::LocalOperandOrigin,
                executable,
                "subprocess_executable_override",
            );
        }
        if !slots.contains_key("executable")
            && slots
                .get("shell")
                .is_none_or(|n| n.kind().as_ref() == "false")
        {
            explicit_shell(item, &index);
        }
        let Some(shell) = slots.get("shell") else {
            continue;
        };
        let mode = match shell.kind().as_ref() {
            "true" => "true",
            "false" => "false",
            _ => "unresolved",
        };
        fact(
            item,
            "process_options",
            OperandFactKind::ProcessShellMode,
            &shell,
            mode,
        );
        item.captures.insert(
            "shell_mode".into(),
            Capture {
                text: shell.text().into_owned(),
                location: super::matcher::location(&item.location.path, &shell),
            },
        );
        if mode == "true" {
            if !item.tags.iter().any(|t| t == "shell-command-text") {
                item.tags.push("shell-command-text".into());
            }
            let sequence = item
                .captures
                .get("command")
                .and_then(|c| {
                    index
                        .calls
                        .get(&(c.location.start.byte_offset, c.location.end.byte_offset))
                })
                .filter(|n| matches!(n.kind().as_ref(), "list" | "tuple"));
            if let Some(sequence) = sequence {
                if let Some(first) = sequence
                    .children()
                    .find(|n| n.is_named() && n.kind().as_ref() != "comment")
                {
                    item.captures.insert(
                        "posix_shell_command".into(),
                        Capture {
                            text: first.text().into_owned(),
                            location: super::matcher::location(&item.location.path, &first),
                        },
                    );
                }
            } else if let Some(command) = item.captures.get("command").cloned() {
                item.captures.insert("shell_command".into(), command);
            }
        }
        if mode == "unresolved" {
            boundary(item, &shell, "shell_truth_value");
        }
    }
}
