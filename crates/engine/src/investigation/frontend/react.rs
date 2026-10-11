//! Owned React state/list navigation, not a reaching-value or completeness proof.
use super::*;

pub(super) fn collection<'a>(
    file: &SourceFile,
    root: &Node<'a, StrDoc<SupportLang>>,
    element: &Node<'a, StrDoc<SupportLang>>,
    facts: &mut Vec<ReviewNeighborhoodFact>,
    partial: &mut bool,
    id: &str,
) {
    // A spread stays unresolved. Supply the enclosing list's source separately.
    let Some(callback) = element.ancestors().find(callable) else {
        return;
    };
    let Some(arguments) = callback
        .parent()
        .filter(|n| n.kind().as_ref() == "arguments")
    else {
        return;
    };
    let Some(call) = arguments
        .parent()
        .filter(|n| n.kind().as_ref() == "call_expression")
    else {
        return;
    };
    let Some(callee) = call
        .field("function")
        .filter(|n| n.kind().as_ref() == "member_expression")
    else {
        return;
    };
    if !callee.field("property").is_some_and(|n| n.text() == "map") {
        return;
    }
    let Some(input) = callee.field("object") else {
        return;
    };
    if !valid(&input) || input.range().len() > MAX_FACT_BYTES {
        *partial = true;
        return;
    }
    if facts.iter().any(|f| {
        f.role == "frontend_collection_producer_context"
            && f.location.path == file.path
            && f.location.start.byte_offset == input.range().start
    }) {
        return;
    }
    if facts
        .iter()
        .filter(|f| f.role == "frontend_collection_producer_context")
        .count()
        == MAX_CALLERS
    {
        *partial = true;
        return;
    }
    facts.push(fact(
        file,
        &input,
        "frontend_collection_producer_context",
        "enclosing map receiver; spread fields and callback semantics require review",
        id,
    ));
    dependencies(
        file,
        root,
        vec![input],
        facts,
        partial,
        id,
        "frontend_prop_producer_context",
    );
}

pub(super) fn state<'a>(
    file: &SourceFile,
    root: &Node<'a, StrDoc<SupportLang>>,
    name: &Node<'a, StrDoc<SupportLang>>,
    facts: &mut Vec<ReviewNeighborhoodFact>,
    partial: &mut bool,
    id: &str,
) -> Option<Vec<Node<'a, StrDoc<SupportLang>>>> {
    if !file.source.contains("useState") {
        return None;
    }
    let binding = lexical_declaration(root, name)?;
    if !binding.parent()?.text().trim_start().starts_with("const ") {
        return None;
    }
    let pattern = binding
        .field("name")
        .filter(|n| n.kind().as_ref() == "array_pattern")?;
    let parts: Vec<_> = pattern.children().filter(|n| n.is_named()).collect();
    if parts.len() != 2
        || parts.iter().any(|n| n.kind().as_ref() != "identifier")
        || parts[0].text() != name.text()
    {
        return None;
    }
    let value = binding
        .field("value")
        .filter(|n| n.kind().as_ref() == "call_expression")?;
    if !react_api(root, &value.field("function")?, &["useState"]) {
        return None;
    }
    if facts.iter().any(|f| {
        f.role == "frontend_state_declaration_context"
            && f.location.path == file.path
            && f.location.start.byte_offset == binding.range().start
    }) {
        return Some(Vec::new());
    }
    if binding.range().len() > MAX_FACT_BYTES
        || facts
            .iter()
            .filter(|f| f.role == "frontend_state_declaration_context")
            .count()
            == 2
    {
        *partial = true;
        return Some(Vec::new());
    }
    let owner = binding.ancestors().find(callable)?;
    let setter = &parts[1];
    facts.push(fact(
        file,
        &binding,
        "frontend_state_declaration_context",
        &format!(
            "{} / {}; initializer is not the final state",
            parts[0].text(),
            setter.text()
        ),
        id,
    ));
    let mut inputs: Vec<_> = value
        .field("arguments")
        .into_iter()
        .flat_map(|n| n.children().filter(|n| n.is_named()).collect::<Vec<_>>())
        .collect();
    for call in owner
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression" && valid(n))
    {
        let Some(callee) = call
            .field("function")
            .filter(|n| n.kind().as_ref() == "identifier" && n.text() == setter.text())
        else {
            continue;
        };
        if !lexical_declaration(root, &callee).is_some_and(|n| n.range() == binding.range()) {
            continue;
        }
        let mut candidate = call.clone();
        if let Some(callback) = call
            .ancestors()
            .find(callable)
            .filter(|n| n.range() != owner.range())
        {
            let effect = callback
                .parent()
                .filter(|n| n.kind().as_ref() == "arguments")
                .and_then(|n| n.parent())
                .filter(|n| n.kind().as_ref() == "call_expression")
                .filter(|n| {
                    n.field("function")
                        .is_some_and(|f| react_api(root, &f, &["useEffect"]))
                });
            let context = effect.unwrap_or(callback);
            if context.range().len() <= MAX_FACT_BYTES && valid(&context) {
                candidate = context;
            } else {
                *partial = true;
            }
        }
        if facts.iter().any(|f| {
            f.role == "frontend_state_writer_context"
                && f.location.path == file.path
                && f.location.start.byte_offset == candidate.range().start
        }) {
            continue;
        }
        if candidate.range().len() > MAX_FACT_BYTES
            || facts
                .iter()
                .filter(|f| f.role == "frontend_state_writer_context")
                .count()
                == 3
        {
            *partial = true;
            continue;
        }
        facts.push(fact(
            file,
            &candidate,
            "frontend_state_writer_context",
            &format!(
                "{} writer candidate; invocation, branches and later updates require review",
                setter.text()
            ),
            id,
        ));
        if let Some(arguments) = call.field("arguments") {
            inputs.extend(arguments.children().filter(|n| n.is_named()));
        }
    }
    Some(inputs)
}
