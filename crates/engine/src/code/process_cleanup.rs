//! Local process construction accounting. Builders describe a future launch;
//! they are not executions. Escapes and ambiguous state remain unresolved.
use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Capture, Evidence, EvidenceKind, Language};

type N<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn annotate<'a>(
    language: Language,
    source: &str,
    root: &N<'a>,
    literals: &super::literals::LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::Sink && e.capability == Capability::ProcessExecution)
    {
        return;
    }
    if matches!(language, Language::Java | Language::Go | Language::Rust) {
        builders(language, source, root, literals, evidence);
    }
    if language == Language::Python {
        // Separate an inline direct argv vector's executable from its data.
        // Explicit executable= overrides and unresolved options keep priority.
        let ranges = evidence
            .iter()
            .filter(|e| {
                e.capability == Capability::ProcessExecution
                    && !e.captures.contains_key("executable")
            })
            .filter_map(|e| e.captures.get("command"))
            .map(|c| (c.location.start.byte_offset, c.location.end.byte_offset))
            .collect::<BTreeSet<_>>();
        let nodes = root
            .dfs()
            .filter(|n| ranges.contains(&(n.range().start, n.range().end)))
            .map(|n| ((n.range().start, n.range().end), n))
            .collect::<BTreeMap<_, _>>();
        for e in evidence.iter_mut().filter(|e| {
            e.capability == Capability::ProcessExecution && !e.captures.contains_key("executable")
        }) {
            if e.tags.iter().any(|t| t == "shell-command-text")
                || e.context.operand_facts.iter().any(|f| {
                    f.role == "process_options"
                        && (f.kind == mehscan_core::OperandFactKind::OperandBoundary
                            || f.value != "false")
                })
            {
                continue;
            }
            if let Some(n) = e
                .captures
                .get("command")
                .and_then(|c| {
                    nodes.get(&(c.location.start.byte_offset, c.location.end.byte_offset))
                })
                .filter(|n| matches!(n.kind().as_ref(), "list" | "tuple"))
                && let Some(executable) = n.children().find(|n| n.is_named())
            {
                e.captures
                    .insert("executable".into(), capture(e, &executable));
                e.context
                    .literals
                    .insert("executable".into(), literals.evaluate(&executable));
            }
        }
    }
    for e in evidence
        .iter_mut()
        .filter(|e| e.kind == EvidenceKind::Sink && e.capability == Capability::ProcessExecution)
    {
        super::decision_origins::annotate_process_semantics(language, source, e);
    }
    // Recovered semantic captures need the same literal facts as declarative
    // captures. One indexed walk; never transfer a builder-wide safe verdict.
    let ranges = evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Sink && e.capability == Capability::ProcessExecution)
        .flat_map(|e| {
            ["executable", "shell_command"].into_iter().filter_map(|r| {
                e.captures
                    .get(r)
                    .filter(|_| !e.context.literals.contains_key(r))
            })
        })
        .map(|c| (c.location.start.byte_offset, c.location.end.byte_offset))
        .collect::<BTreeSet<_>>();
    if !ranges.is_empty() {
        let nodes = root
            .dfs()
            .filter(|n| ranges.contains(&(n.range().start, n.range().end)))
            .map(|n| ((n.range().start, n.range().end), n))
            .collect::<BTreeMap<_, _>>();
        for e in evidence.iter_mut().filter(|e| {
            e.kind == EvidenceKind::Sink && e.capability == Capability::ProcessExecution
        }) {
            for role in ["executable", "shell_command"] {
                if !e.context.literals.contains_key(role)
                    && let Some(n) = e.captures.get(role).and_then(|c| {
                        nodes.get(&(c.location.start.byte_offset, c.location.end.byte_offset))
                    })
                {
                    e.context.literals.insert(role.into(), literals.evaluate(n));
                }
            }
        }
    }
}

fn builders<'a>(
    language: Language,
    source: &str,
    root: &N<'a>,
    literals: &super::literals::LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let calls = root.dfs().filter(|n| is_call(n)).collect::<Vec<_>>();
    let producers = evidence
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            if e.kind != EvidenceKind::Sink || e.capability != Capability::ProcessExecution {
                return None;
            }
            let n = calls.iter().find(|n| {
                n.range().start == e.location.start.byte_offset
                    && n.range().end == e.location.end.byte_offset
            })?;
            let method = method(n)?;
            let builder = match language {
                Language::Java => {
                    n.kind().as_ref() == "object_creation_expression"
                        && n.field("type").is_some_and(|t| {
                            matches!(
                                t.text().as_ref(),
                                "ProcessBuilder" | "java.lang.ProcessBuilder"
                            )
                        })
                        || e.tags
                            .iter()
                            .any(|t| t == "process-builder-command-mutation")
                }
                Language::Go => matches!(method.as_str(), "Command" | "CommandContext"),
                Language::Rust => matches!(method.as_str(), "new" | "arg" | "args"),
                _ => false,
            };
            builder.then(|| (i, n.clone()))
        })
        .collect::<Vec<_>>();
    let mut consumed = BTreeSet::new();
    let mut discarded = BTreeSet::new();
    let mut launches = Vec::new();
    for terminal in &calls {
        let Some(terminal_method) = method(terminal) else {
            continue;
        };
        let executes = match language {
            Language::Java => terminal_method == "start",
            Language::Go => matches!(
                terminal_method.as_str(),
                "Start" | "Run" | "Output" | "CombinedOutput"
            ),
            Language::Rust => matches!(terminal_method.as_str(), "spawn" | "status" | "output"),
            _ => false,
        };
        if !executes {
            continue;
        }
        let Some(receiver) = call_receiver(terminal) else {
            continue;
        };
        let origin = if receiver.kind().as_ref() == "identifier" {
            local_initializer(root, &receiver)
        } else {
            None
        };
        let mut inputs = producers
            .iter()
            .filter(|(_, n)| {
                let inline = receiver_chain_contains(&receiver, n);
                let local = origin.as_ref().is_some_and(|(b, value)| {
                    receiver_chain_contains(value, n)
                        || (call_receiver(n).is_some_and(|r| r.text() == receiver.text())
                            && scope(n) == scope(terminal)
                            && n.range().end <= terminal.range().start
                            && super::context::lexical_declaration_visible_at(b, terminal))
                });
                inline || local
            })
            .collect::<Vec<_>>();
        inputs.sort_by_key(|(_, n)| n.range().start);
        if inputs.is_empty() {
            continue;
        }
        let mut launch = evidence[inputs[0].0].clone();
        launch.location = super::matcher::location(&launch.location.path, terminal);
        launch.id = super::matcher::evidence_id(
            &launch.location.path,
            &launch.rule_id,
            terminal.range().start,
            terminal.range().end,
        );
        launch.enclosing_symbol = super::context::enclosing_symbol(terminal);
        launch.context.reachability = Some(super::reachability::classify(terminal, literals));
        launch.captures.clear();
        launch.context.literals.clear();
        launch.context.operand_facts.clear();
        launch
            .tags
            .retain(|t| t != "process-builder-command-mutation");
        launch.tags.push("process-invocation:actual-launch".into());
        let mut arguments = Vec::new();
        for (i, n) in &inputs {
            let item = &evidence[*i];
            // A command mutation replaces Java's argv. Rust arg/args append.
            if let Some(c) = item
                .captures
                .get("command")
                .filter(|_| language != Language::Rust || method(n).as_deref() == Some("new"))
            {
                launch.captures.insert("command".into(), c.clone());
                if let Some(f) = item.context.literals.get("command") {
                    launch.context.literals.insert("command".into(), f.clone());
                }
                if language == Language::Java {
                    arguments.clear();
                }
            }
            if let Some(c) = item.captures.get("arguments") {
                arguments.push(c.clone());
                if let Some(f) = item.context.literals.get("arguments") {
                    launch.context.literals.insert(
                        format!("argument_literal_{}", c.location.start.byte_offset),
                        f.clone(),
                    );
                }
            }
            // Generated Java command mutations currently capture just argv[0].
            if language == Language::Java
                && let Some(args) = n.field("arguments")
            {
                let values = args.children().filter(|n| n.is_named()).collect::<Vec<_>>();
                if values.len() > 1 {
                    arguments.push(span_capture(
                        source,
                        &launch,
                        &values[1],
                        values.last().unwrap(),
                    ));
                }
            }
            if let Some(c) = item.captures.get("context") {
                launch.captures.insert("context".into(), c.clone());
            }
            launch.related_evidence.push(item.id.clone());
        }
        if !arguments.is_empty() {
            arguments.sort_by_key(|c| c.location.start.byte_offset);
            arguments.dedup_by(|a, b| a.location == b.location);
            let mut aggregate = arguments[0].clone();
            aggregate.location.end = arguments.last().unwrap().location.end.clone();
            aggregate.text = source
                [aggregate.location.start.byte_offset..aggregate.location.end.byte_offset]
                .to_string();
            let values = arguments
                .iter()
                .map(|c| {
                    launch.context.literals.get(&format!(
                        "argument_literal_{}",
                        c.location.start.byte_offset
                    ))
                })
                .collect::<Vec<_>>();
            let known = values.iter().all(|f| {
                f.is_some_and(|f| f.state == mehscan_core::LiteralState::Known && f.value.is_some())
            });
            if known {
                launch.context.literals.insert(
                    "arguments".into(),
                    mehscan_core::LiteralEvaluation {
                        state: mehscan_core::LiteralState::Known,
                        value: Some(mehscan_core::LiteralValue::Array(
                            values
                                .into_iter()
                                .filter_map(|f| f.and_then(|f| f.value.clone()))
                                .collect(),
                        )),
                        constant_fragments: Vec::new(),
                        references: Vec::new(),
                    },
                );
            }
            launch.captures.insert("arguments".into(), aggregate);
            for (i, c) in arguments.into_iter().enumerate() {
                if let Some(f) = launch.context.literals.remove(&format!(
                    "argument_literal_{}",
                    c.location.start.byte_offset
                )) {
                    launch
                        .context
                        .literals
                        .insert(format!("process_argument_{i}"), f);
                }
                launch.captures.insert(format!("process_argument_{i}"), c);
            }
        }
        // Configuration is context on this launch. Do not hide cwd/env changes
        // merely because the executable itself is fixed.
        launch
            .context
            .literals
            .retain(|role, _| !role.starts_with("argument_literal_"));
        for call in &calls {
            let Some(r) = call_receiver(call) else {
                continue;
            };
            let inline = contains(&receiver, call);
            let local = origin.as_ref().is_some_and(|(b, _)| {
                r.text() == receiver.text()
                    && scope(call) == scope(terminal)
                    && b.range().end <= call.range().start
                    && call.range().end <= terminal.range().start
            });
            if (inline || local)
                && matches!(
                    method(call).as_deref(),
                    Some(
                        "env"
                            | "envs"
                            | "env_remove"
                            | "env_clear"
                            | "current_dir"
                            | "directory"
                            | "stdin"
                            | "stdout"
                            | "stderr"
                            | "redirectInput"
                            | "redirectOutput"
                            | "redirectError"
                    )
                )
            {
                let parts = call
                    .field("arguments")
                    .map(|args| {
                        args.children()
                            .filter(|n| n.is_named() && !n.kind().as_ref().contains("comment"))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if let (Some(first), Some(last)) = (parts.first(), parts.last()) {
                    let role = format!("process_configuration_{}", call.range().start);
                    let facts = parts
                        .iter()
                        .map(|n| literals.evaluate(n))
                        .collect::<Vec<_>>();
                    let known = facts
                        .iter()
                        .all(|f| f.state == mehscan_core::LiteralState::Known && f.value.is_some());
                    launch.context.literals.insert(
                        role.clone(),
                        mehscan_core::LiteralEvaluation {
                            state: if known {
                                mehscan_core::LiteralState::Known
                            } else {
                                mehscan_core::LiteralState::Unknown
                            },
                            value: known.then(|| {
                                mehscan_core::LiteralValue::Array(
                                    facts.into_iter().filter_map(|f| f.value).collect(),
                                )
                            }),
                            constant_fragments: Vec::new(),
                            references: Vec::new(),
                        },
                    );
                    launch
                        .captures
                        .insert(role, span_capture(source, &launch, first, last));
                }
            }
        }
        let uncertain = origin
            .as_ref()
            .is_some_and(|(b, _)| !simple_uses(root, b, &receiver, language));
        if uncertain {
            launch
                .tags
                .push("process-invocation:unresolved-builder-state".into());
        }
        if !launch.captures.contains_key("command") {
            launch
                .captures
                .insert("command".into(), capture(&launch, &receiver));
        }
        // Retain a factory lead when the same builder also escapes local control.
        if !uncertain {
            for (i, _) in inputs {
                consumed.insert(*i);
            }
        }
        launches.push(launch);
    }
    for (i, n) in &producers {
        if consumed.contains(i) {
            continue;
        }
        let bound = binding(n).or_else(|| {
            call_receiver(n)
                .and_then(|r| local_initializer(root, &r).map(|(b, _)| (b, r.text().into_owned())))
        });
        let unused = bound.as_ref().is_some_and(|(b, name)| {
            scope_node(b).is_some_and(|s| {
                let reads = s
                    .dfs()
                    .filter(|r| {
                        r.kind().as_ref() == "identifier"
                            && r.text().trim() == name
                            && r.range().start >= b.range().end
                    })
                    .collect::<Vec<_>>();
                reads.is_empty()
                    || (simple_uses(root, b, &reads[0], language)
                        && reads.iter().all(|r| {
                            !r.ancestors().take(3).any(|p| {
                                is_call(&p)
                                    && matches!(
                                        method(&p).as_deref(),
                                        Some(
                                            "start"
                                                | "Start"
                                                | "Run"
                                                | "Output"
                                                | "CombinedOutput"
                                                | "spawn"
                                                | "status"
                                                | "output"
                                        )
                                    )
                            })
                        }))
            })
        }) || (bound.is_none() && discarded_expression(n));
        if unused {
            discarded.insert(*i);
        } else {
            evidence[*i]
                .tags
                .push("process-invocation:unresolved-execution".into());
        }
    }
    for i in consumed {
        evidence[i].kind = EvidenceKind::Resource;
        evidence[i]
            .tags
            .push("process-context:consumed-builder".into());
        let id = evidence[i].id.clone();
        evidence[i].related_evidence.extend(
            launches
                .iter()
                .filter(|l| l.related_evidence.contains(&id))
                .map(|l| l.id.clone()),
        );
    }
    // A returned local builder owns one unresolved factory question. Retain
    // all shown argument operands, including conditional mutations, as context;
    // this is not a reaching-value or execution proof.
    for (i, n) in &producers {
        if discarded.contains(i) || evidence[*i].kind != EvidenceKind::Sink {
            continue;
        }
        let Some((b, name)) = binding(n) else {
            continue;
        };
        if launches
            .iter()
            .any(|l| l.related_evidence.contains(&evidence[*i].id))
        {
            continue;
        }
        let modifiers = producers
            .iter()
            .filter(|(j, p)| {
                *j != *i
                    && evidence[*j].kind == EvidenceKind::Sink
                    && !discarded.contains(j)
                    && scope(p) == scope(n)
                    && call_receiver(p).is_some_and(|r| {
                        r.text().trim() == name
                            && local_initializer(root, &r)
                                .is_some_and(|(owner, _)| owner.range() == b.range())
                    })
            })
            .collect::<Vec<_>>();
        let mut args = modifiers
            .iter()
            .filter_map(|(j, _)| evidence[*j].captures.get("arguments").cloned())
            .collect::<Vec<_>>();
        if !args.is_empty() {
            args.sort_by_key(|c| c.location.start.byte_offset);
            let mut c = args[0].clone();
            c.location.end = args.last().unwrap().location.end.clone();
            c.text = source[c.location.start.byte_offset..c.location.end.byte_offset].into();
            evidence[*i].captures.insert("arguments".into(), c);
        }
        for (j, _) in modifiers {
            let id = evidence[*j].id.clone();
            let owner = evidence[*i].id.clone();
            evidence[*i].related_evidence.push(id);
            evidence[*j].kind = EvidenceKind::Resource;
            evidence[*j]
                .tags
                .push("process-context:consumed-builder".into());
            evidence[*j].related_evidence.push(owner);
            evidence[*i]
                .tags
                .push("process-invocation:unresolved-builder-state".into());
        }
    }
    // One escaping inline factory is one unresolved question. Nested arg calls
    // do not each own another executable-selection question.
    for (i, n) in &producers {
        if discarded.contains(i) || evidence[*i].kind != EvidenceKind::Sink {
            continue;
        }
        if let Some((outer_i, _)) = producers
            .iter()
            .filter(|(j, p)| {
                *j != *i
                    && evidence[*j].kind == EvidenceKind::Sink
                    && !discarded.contains(j)
                    && call_receiver(p).is_some_and(|r| contains(&r, n))
            })
            .max_by_key(|(_, p)| p.range().end - p.range().start)
        {
            let outer_id = evidence[*outer_i].id.clone();
            let id = evidence[*i].id.clone();
            if let Some(c) = evidence[*i].captures.get("arguments").cloned() {
                let mut aggregate = c.clone();
                if let Some(later) = evidence[*outer_i].captures.get("arguments") {
                    aggregate.location.end = later.location.end.clone();
                }
                aggregate.text = source
                    [aggregate.location.start.byte_offset..aggregate.location.end.byte_offset]
                    .into();
                evidence[*outer_i]
                    .captures
                    .insert("arguments".into(), aggregate);
                evidence[*outer_i].captures.insert(
                    format!("process_argument_{}", c.location.start.byte_offset),
                    c,
                );
                evidence[*outer_i].context.literals.remove("arguments");
            }
            evidence[*i].kind = EvidenceKind::Resource;
            evidence[*i].related_evidence.push(outer_id);
            evidence[*outer_i].related_evidence.push(id);
            evidence[*i]
                .tags
                .push("process-context:consumed-builder".into());
        }
    }
    let discarded_ranges = discarded
        .iter()
        .map(|i| {
            (
                evidence[*i].location.start.byte_offset,
                evidence[*i].location.end.byte_offset,
            )
        })
        .collect::<BTreeSet<_>>();
    let mut index = 0;
    evidence.retain(|e| {
        let keep = !discarded.contains(&index)
            && !(e.capability == Capability::ProcessArgumentSeparation
                && discarded_ranges
                    .contains(&(e.location.start.byte_offset, e.location.end.byte_offset)));
        index += 1;
        keep
    });
    evidence.extend(launches);
}

fn span_capture(source: &str, item: &Evidence, first: &N<'_>, last: &N<'_>) -> Capture {
    let mut c = capture(item, first);
    c.location.end = super::matcher::location(&item.location.path, last).end;
    c.text = source[first.range().start..last.range().end].to_string();
    c
}
fn capture(item: &Evidence, n: &N<'_>) -> Capture {
    Capture {
        text: n.text().into_owned(),
        location: super::matcher::location(&item.location.path, n),
    }
}
fn contains(a: &N<'_>, b: &N<'_>) -> bool {
    a.range().start <= b.range().start && b.range().end <= a.range().end
}
fn receiver_chain_contains(a: &N<'_>, b: &N<'_>) -> bool {
    if a.range() == b.range() {
        return true;
    }
    is_call(a)
        && method(a).is_some_and(|m| configuration_method(&m))
        && call_receiver(a).is_some_and(|r| receiver_chain_contains(&r, b))
}
fn is_call(n: &N<'_>) -> bool {
    matches!(
        n.kind().as_ref(),
        "call_expression" | "method_invocation" | "object_creation_expression"
    )
}
fn method(n: &N<'_>) -> Option<String> {
    if n.kind().as_ref() == "object_creation_expression" {
        return Some("new".into());
    }
    n.field("name")
        .or_else(|| {
            n.field("function")
                .and_then(|f| f.field("field").or_else(|| f.field("name")).or(Some(f)))
        })
        .map(|m| m.text().rsplit("::").next().unwrap_or_default().to_string())
}
fn call_receiver<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.field("object").or_else(|| {
        n.field("function")
            .and_then(|f| f.field("value").or_else(|| f.field("operand")))
    })
}
fn scope_node<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(|p| {
        matches!(
            p.kind().as_ref(),
            "function_item"
                | "function_declaration"
                | "method_declaration"
                | "lambda_expression"
                | "func_literal"
                | "closure_expression"
        )
    })
}
fn scope(n: &N<'_>) -> Option<usize> {
    scope_node(n).map(|s| s.range().start)
}
fn binding<'a>(n: &N<'a>) -> Option<(N<'a>, String)> {
    n.ancestors()
        .take_while(|p| {
            !matches!(
                p.kind().as_ref(),
                "expression_statement" | "return_statement" | "block"
            ) && (!is_call(p)
                || (method(p).is_some_and(|m| configuration_method(&m))
                    && call_receiver(p).is_some_and(|r| contains(&r, n))))
        })
        .find_map(|b| {
            let name = match b.kind().as_ref() {
                "let_declaration" => b.field("pattern"),
                "variable_declarator" => b.field("name"),
                "short_var_declaration" => b
                    .field("left")
                    .and_then(|l| l.children().find(|n| n.is_named())),
                _ => None,
            }?;
            (name.kind().as_ref() == "identifier").then(|| (b.clone(), name.text().into_owned()))
        })
}
fn local_initializer<'a>(root: &N<'a>, site: &N<'a>) -> Option<(N<'a>, N<'a>)> {
    let candidates = root
        .dfs()
        .filter_map(|b| {
            let (name, value) = match b.kind().as_ref() {
                "let_declaration" => (b.field("pattern")?, b.field("value")?),
                "variable_declarator" => (b.field("name")?, b.field("value")?),
                "short_var_declaration" => (
                    b.field("left")?.children().find(|n| n.is_named())?,
                    b.field("right")?.children().find(|n| n.is_named())?,
                ),
                _ => return None,
            };
            (name.text() == site.text()
                && b.range().end <= site.range().start
                && scope(&b) == scope(site)
                && super::context::lexical_declaration_visible_at(&b, site))
            .then_some((b, value))
        })
        .collect::<Vec<_>>();
    (candidates.len() == 1).then(|| candidates[0].clone())
}
fn simple_uses(root: &N<'_>, b: &N<'_>, site: &N<'_>, language: Language) -> bool {
    let Some(s) = scope_node(b) else {
        return false;
    };
    s.dfs()
        .filter(|n| {
            n.kind().as_ref() == "identifier"
                && n.text() == site.text()
                && n.range().start >= b.range().end
        })
        .all(|n| {
            let Some(call) = n.ancestors().take(3).find(|p| is_call(p)) else {
                return false;
            };
            let Some(receiver) = call_receiver(&call) else {
                return false;
            };
            if !contains(&receiver, &n) {
                return false;
            }
            let allowed = method(&call).is_some_and(|m| match language {
                Language::Rust => {
                    rust_configuration(&m) || matches!(m.as_str(), "spawn" | "status" | "output")
                }
                Language::Java => java_configuration(&m) || m == "start",
                Language::Go => matches!(
                    m.as_str(),
                    "Start" | "Run" | "Output" | "CombinedOutput" | "Wait"
                ),
                _ => false,
            });
            // Conditional mutations can change which executable/arguments reach a
            // launch. Keep the original lead instead of inventing a reaching value.
            allowed
                && !call
                    .ancestors()
                    .take_while(|p| p.range() != s.range())
                    .any(|p| {
                        matches!(
                            p.kind().as_ref(),
                            "if_statement"
                                | "for_statement"
                                | "while_statement"
                                | "match_expression"
                                | "switch_expression"
                        )
                    })
        })
        && root.range().start <= b.range().start
}
fn discarded_expression(n: &N<'_>) -> bool {
    if matches!(method(n).as_deref(), Some("arg" | "args" | "command"))
        && call_receiver(n).is_some_and(|r| r.kind().as_ref() == "identifier")
    {
        return false;
    }
    for p in n.ancestors() {
        if p.kind().as_ref() == "expression_statement" {
            return true;
        }
        if is_call(&p) {
            if !call_receiver(&p).is_some_and(|r| contains(&r, n))
                || !method(&p).is_some_and(|m| configuration_method(&m))
            {
                return false;
            }
        } else if !matches!(
            p.kind().as_ref(),
            "field_expression" | "selector_expression" | "parenthesized_expression"
        ) {
            return false;
        }
    }
    false
}

pub(super) fn owned_rust_receiver<'a>(root: &N<'a>, n: &N<'a>, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    if n.kind().as_ref() == "identifier" {
        if let Some((binding, value)) = local_initializer(root, n) {
            return owned_rust_receiver(root, &value, depth - 1)
                || rust_command_type(root, &binding);
        }
        if root.dfs().any(|b| {
            b.kind().as_ref() == "let_declaration"
                && b.range().end <= n.range().start
                && scope(&b) == scope(n)
                && super::context::lexical_declaration_visible_at(&b, n)
                && b.field("pattern")
                    .is_some_and(|p| p.text().trim().trim_start_matches("mut ") == n.text())
        }) {
            return false; // Ambiguous/shadowing locals cannot inherit a parameter's type.
        }
        return root
            .dfs()
            .filter(|b| b.kind().as_ref() == "parameter" && scope(b) == scope(n))
            .any(|b| {
                b.field("pattern")
                    .is_some_and(|p| p.text().trim().trim_start_matches("mut ") == n.text())
                    && rust_command_type(root, &b)
            });
    }
    if let Some(function) = n.field("function") {
        if matches!(
            super::rust_context::canonical_path(root, function.text().as_ref()).as_str(),
            "std::process::Command::new" | "tokio::process::Command::new"
        ) {
            return true;
        }
        if method(n).is_some_and(|m| rust_configuration(&m)) {
            return call_receiver(n).is_some_and(|r| owned_rust_receiver(root, &r, depth - 1));
        }
    }
    false
}

fn rust_command_type(root: &N<'_>, binding: &N<'_>) -> bool {
    binding.field("type").is_some_and(|t| {
        let text = t.text();
        let name = text
            .trim()
            .trim_start_matches('&')
            .trim()
            .trim_start_matches("mut ")
            .trim();
        matches!(
            super::rust_context::canonical_path(root, name).as_str(),
            "std::process::Command" | "tokio::process::Command"
        )
    })
}

fn rust_configuration(method: &str) -> bool {
    matches!(
        method,
        "arg"
            | "args"
            | "env"
            | "envs"
            | "env_remove"
            | "env_clear"
            | "current_dir"
            | "stdin"
            | "stdout"
            | "stderr"
    )
}
fn java_configuration(method: &str) -> bool {
    matches!(
        method,
        "command"
            | "directory"
            | "redirectInput"
            | "redirectOutput"
            | "redirectError"
            | "redirectErrorStream"
            | "inheritIO"
    )
}
fn configuration_method(method: &str) -> bool {
    rust_configuration(method) || java_configuration(method)
}
