//! Narrow Value scheduling rules. Raw evidence and Comprehensive stay intact.
use super::*;

pub(super) struct Chain<'a> {
    pub span: std::ops::Range<usize>,
    pub anchors: Vec<&'a Evidence>,
}

// Bind the selector through its recorded callee span, rather than its operand:
// a positional Exists operand is itself a call in a different query scope.
pub(super) fn chains<'a>(root: &PyNode<'_>, anchors: &[&'a Evidence]) -> Vec<Chain<'a>> {
    if root
        .dfs()
        .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
    {
        return Vec::new();
    }
    let mut groups = BTreeMap::<(usize, usize), Vec<&Evidence>>::new();
    for anchor in anchors {
        let Some(callee) = anchor.captures.get("model") else {
            continue;
        };
        let Some(call) = root.dfs().find(|n| {
            n.kind().as_ref() == "call"
                && n.field("function").is_some_and(|f| {
                    f.range().start == callee.location.start.byte_offset
                        && f.range().end == callee.location.end.byte_offset
                })
        }) else {
            continue;
        };
        let expression = selection::receiver_expression(&call);
        if !filter_chain(&expression)
            || expression.range().len() > 4096
            || expression.text().lines().count() > 40
        {
            continue;
        }
        groups
            .entry((expression.range().start, expression.range().end))
            .or_default()
            .push(anchor);
    }
    groups
        .into_iter()
        .filter_map(|((start, end), mut anchors)| {
            anchors.sort_by_key(|e| (e.location.start.byte_offset, &e.id));
            anchors.dedup_by(|a, b| a.id == b.id);
            (anchors.len() > 1).then_some(Chain {
                span: start..end,
                anchors,
            })
        })
        .collect()
}

fn filter_chain(node: &PyNode<'_>) -> bool {
    let mut current = node.clone();
    let mut terminal = true;
    let mut filters = 0;
    for _ in 0..32 {
        if current.kind().as_ref() == "parenthesized_expression" {
            let Some(inner) = current.children().find(|n| n.is_named()) else {
                return false;
            };
            current = inner;
            continue;
        }
        if current.kind().as_ref() != "call" {
            return !terminal
                && filters > 0
                && current.kind().as_ref() == "attribute"
                && current
                    .field("attribute")
                    .is_some_and(|n| n.text() == "objects")
                && !current
                    .dfs()
                    .any(|n| !matches!(n.kind().as_ref(), "attribute" | "identifier" | "."));
        }
        let Some(function) = current.field("function") else {
            return false;
        };
        let Some(method) = function.field("attribute") else {
            return false;
        };
        if terminal {
            if !matches!(
                method.text().as_ref(),
                "first" | "get" | "update" | "delete"
            ) {
                return false;
            }
            terminal = false;
        } else if method.text() == "filter" {
            filters += 1;
        } else {
            // Unknown transforms and earlier resource terminals may introduce
            // independent effects. Do not combine their review obligations.
            return false;
        }
        let Some(receiver) = function.field("object") else {
            return false;
        };
        current = receiver;
    }
    false
}

fn django_response(root: &PyNode<'_>, call: &PyNode<'_>) -> bool {
    let Some(function) = call
        .field("function")
        .filter(|n| n.kind().as_ref() == "identifier")
    else {
        return false;
    };
    let symbol = function.text();
    let imports = root
        .children()
        .filter(|n| {
            n.kind().as_ref() == "import_from_statement"
                && n.range().end < call.range().start
                && n.field("module_name")
                    .is_some_and(|m| m.text() == "django.http")
        })
        .flat_map(|n| n.field_children("name").collect::<Vec<_>>())
        .filter(|n| {
            n.field("name").unwrap_or_else(|| n.clone()).text() == "HttpResponse"
                && n.field("alias").unwrap_or_else(|| n.clone()).text() == symbol
        })
        .collect::<Vec<_>>();
    let [import] = imports.as_slice() else {
        return false;
    };
    // Every occurrence must be this import or a direct call. Parameters,
    // rebinding, aliases, wildcard imports and competing imports stay unknown.
    !root.dfs().any(|n| {
        n.kind().as_ref() == "wildcard_import"
            || n.kind().as_ref() == "identifier"
                && n.text() == symbol
                && !(import.range().start <= n.range().start && n.range().end <= import.range().end)
                && !n.parent().is_some_and(|p| {
                    p.kind().as_ref() == "call"
                        && p.field("function").is_some_and(|f| f.range() == n.range())
                })
    })
}

fn fixed_text(node: &PyNode<'_>) -> bool {
    node.kind().as_ref() == "string" && fixed_sql_string(node.text().as_ref())
}

fn fixed_response_arguments(call: &PyNode<'_>) -> bool {
    let Some(arguments) = call.field("arguments") else {
        return false;
    };
    let mut content = false;
    for arg in arguments
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
    {
        if arg.kind().as_ref() != "keyword_argument" {
            if content || !fixed_text(&arg) {
                return false;
            }
            content = true;
            continue;
        }
        let Some(name) = arg.field("name") else {
            return false;
        };
        let Some(value) = arg.field("value") else {
            return false;
        };
        match name.text().as_ref() {
            "content" if !content && fixed_text(&value) => content = true,
            "status" if value.kind().as_ref() == "integer" => (),
            "content_type" | "charset" | "reason" if fixed_text(&value) => (),
            _ => return false,
        }
    }
    true
}

fn fixed_response_use(call: &PyNode<'_>) -> bool {
    let mut expression = call.clone();
    while let Some(p) = expression
        .parent()
        .filter(|p| p.kind().as_ref() == "parenthesized_expression")
    {
        expression = p;
    }
    let Some(parent) = expression.parent() else {
        return false;
    };
    if parent.kind().as_ref() == "return_statement" {
        return true;
    }
    if parent.kind().as_ref() != "assignment"
        || !selection::value(&parent).is_some_and(|v| v.range() == expression.range())
    {
        return false;
    }
    let Some(target) = selection::target(&parent).filter(|n| n.kind().as_ref() == "identifier")
    else {
        return false;
    };
    let Some(scope) = owner(call) else {
        return false;
    };
    let name = target.text();
    let mut returns = 0;
    for use_ in scope
        .dfs()
        .filter(|n| n.kind().as_ref() == "identifier" && n.text() == name)
    {
        if !selection::same_scope(&use_, &scope) {
            return false;
        }
        if use_.range() == target.range() {
            continue;
        }
        let Some(p) = use_.parent() else { return false };
        if p.kind().as_ref() == "return_statement" {
            returns += 1;
            continue;
        }
        if p.kind().as_ref() == "attribute"
            && p.field("object").is_some_and(|n| n.range() == use_.range())
            && p.field("attribute").is_some_and(|n| n.text() == "content")
            && p.parent().is_some_and(|a| {
                a.kind().as_ref() == "assignment"
                    && selection::target(&a).is_some_and(|n| n.range() == p.range())
                    && selection::value(&a).is_some_and(|v| fixed_text(&v))
            })
        {
            continue;
        }
        return false;
    }
    returns > 0
}

pub(super) fn apply(
    entries: &mut [ReviewInventoryEntry],
    evidence: &[Evidence],
    sources: &RepositorySources,
) {
    let by_id = evidence
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    let paths = entries
        .iter()
        .filter(|e| {
            e.value_hint.is_none()
                && matches!(
                    e.rule_id.as_str(),
                    "python-django-orm-resource-access" | "python-html-output"
                )
        })
        .map(|e| e.path.clone())
        .collect::<BTreeSet<_>>();
    for path in paths {
        let Some(file) = sources.files.get(&path) else {
            continue;
        };
        let Some(ast) = parse(file) else { continue };
        let root = ast.root();
        if root
            .dfs()
            .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
        {
            continue;
        }
        let mut orm = Vec::new();
        let mut indices = BTreeMap::new();
        for (index, entry) in entries
            .iter_mut()
            .enumerate()
            .filter(|(_, e)| e.path == path && e.value_hint.is_none())
        {
            let Some(anchor) = entry
                .identity
                .as_ref()
                .and_then(|i| by_id.get(i.anchor_id.as_str()))
                .copied()
            else {
                continue;
            };
            if entry.rule_id == "python-django-orm-resource-access"
                && entry.cwe_candidates == ["CWE-639"]
            {
                orm.push(anchor);
                indices.insert(anchor.id.as_str(), index);
            } else if entry.rule_id == "python-html-output" && entry.cwe_candidates == ["CWE-79"] {
                let call = root
                    .dfs()
                    .filter(|n| {
                        n.kind().as_ref() == "call"
                            && n.range().start <= anchor.location.start.byte_offset
                            && anchor.location.end.byte_offset <= n.range().end
                    })
                    .min_by_key(|n| n.range().len());
                if call.is_some_and(|c| {
                    django_response(&root, &c)
                        && fixed_response_arguments(&c)
                        && fixed_response_use(&c)
                }) {
                    entry.value_hint = Some(ValueReviewHint {
                        reason: "python_fixed_http_response_body_research".into(), target: entry.path.clone(),
                        assumption: "Imported Django HttpResponse has only a fixed or omitted body and fixed constructor options; a local response may only receive fixed content before return. Value defers this HTML input question. Comprehensive retains it; caller policy, middleware and response effects remain unreviewed.".into(), depends_on: None,
                    });
                }
            }
        }
        for chain in chains(&root, &orm) {
            let representative = entries[indices[chain.anchors[0].id.as_str()]]
                .review_id
                .clone();
            for anchor in chain.anchors.iter().skip(1) {
                entries[indices[anchor.id.as_str()]].value_hint = Some(ValueReviewHint {
                    reason: "python_shared_orm_receiver_chain".into(),
                    target: format!("{}:{}:{}", path, chain.span.start, chain.span.end),
                    assumption: "Another selector in the exact same direct filter receiver chain. Review every predicate and the terminal effect together in the dependency's complete shared-chain excerpt. Nested queries and separate operations are independent. Comprehensive retains every ID; no authorization, correlation or safe verdict is transferred.".into(),
                    depends_on: Some(representative.clone()),
                });
            }
        }
    }
}
