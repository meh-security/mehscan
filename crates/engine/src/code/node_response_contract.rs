//! A deliberately small response contract, not a general call/dataflow pass.
//! Only synchronous straight-line header setters and one exact local preparer
//! may precede a terminal send. Unknown effects invalidate the whole contract.
use super::*;

#[derive(Default)]
struct Headers {
    plain: bool,
    nosniff: bool,
}

pub(super) fn plain_text_controls(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
    bindings: &SummaryBindingIndex,
) -> Vec<Capture> {
    let mut headers = Headers::default();
    let mut controls = Vec::new();
    if walk(
        path,
        root,
        function,
        bindings,
        &mut headers,
        &mut controls,
        true,
    ) && headers.plain
        && headers.nosniff
    {
        controls.insert(0, capture(path, function));
        controls
    } else {
        Vec::new()
    }
}

fn literal(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if node.kind().as_ref() != "string" {
        return None;
    }
    let text = node.text();
    let text = text.trim();
    if text.len() < 2 || text.contains('\\') {
        return None;
    }
    Some(text[1..text.len() - 1].trim().to_ascii_lowercase())
}

#[allow(clippy::too_many_arguments)]
fn walk(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
    bindings: &SummaryBindingIndex,
    headers: &mut Headers,
    controls: &mut Vec<Capture>,
    terminal_send: bool,
) -> bool {
    if function.children().any(|n| n.kind().as_ref() == "async") {
        return false;
    }
    let Some(body) = function.field("body") else {
        return false;
    };
    if body.kind().as_ref() != "statement_block" {
        return false;
    }
    let parameters = function_parameter_names(function);
    // Destructuring/defaults do not establish that the preparer mutates the
    // same response object supplied by the wrapper. Leave these unresolved.
    if !terminal_send
        && function_parameter_nodes(function)
            .iter()
            .any(|parameter| parameter.kind().as_ref() != "identifier")
    {
        return false;
    }
    let statements = body
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
        .collect::<Vec<_>>();
    if statements.is_empty() || statements.len() > 8 {
        return false;
    }
    // The terminal response receiver must be a simple parameter. Header-only
    // preparers take exactly that receiver, never a request or another object.
    let receiver = if terminal_send {
        let Some(last) = statements
            .last()
            .and_then(|s| s.children().find(|n| n.is_named()))
            .and_then(call_site)
        else {
            return false;
        };
        let callee = compact(&last.callee);
        let Some((receiver, "send")) = callee.rsplit_once('.') else {
            return false;
        };
        if last.arguments.len() != 1 || !parameters.iter().any(|p| p == receiver) {
            return false;
        }
        receiver.to_string()
    } else {
        let [receiver] = parameters.as_slice() else {
            return false;
        };
        receiver.clone()
    };
    for (i, statement) in statements.iter().enumerate() {
        let is_send = terminal_send && i + 1 == statements.len();
        if statement.kind().as_ref() != "expression_statement"
            && !(is_send && statement.kind().as_ref() == "return_statement")
        {
            return false;
        }
        let Some(call) = statement
            .children()
            .find(|n| n.is_named())
            .and_then(call_site)
        else {
            return false;
        };
        if is_send {
            continue;
        }
        let callee = compact(&call.callee);
        if let Some(method) = callee.strip_prefix(&format!("{receiver}.")) {
            let (name, value) = match (method, call.arguments.as_slice()) {
                ("type" | "contentType", [value]) => ("content-type".to_string(), literal(value)),
                ("set" | "header" | "setHeader", [name, value]) => {
                    let Some(name) = literal(name) else {
                        return false;
                    };
                    (name, literal(value))
                }
                _ => return false,
            };
            let Some(value) = value else { return false };
            match name.as_str() {
                "content-type" => headers.plain = value.split(';').next() == Some("text/plain"),
                "x-content-type-options" => headers.nosniff = value == "nosniff",
                _ => return false,
            }
            continue;
        }
        // Only the outer response helper may call a preparer. It must resolve
        // uniquely to a stable module-level definition in this very file.
        if !terminal_send
            || simple_identifier(&callee).is_none()
            || call.arguments.len() != 1
            || call.arguments[0].text().trim() != receiver
            || !continuation_binding_is_stable(bindings, &call.node, &callee, true)
        {
            return false;
        }
        let definitions = named_functions(root)
            .into_iter()
            .filter(|(name, _)| name == &callee)
            .collect::<Vec<_>>();
        let [(name, definition)] = definitions.as_slice() else {
            return false;
        };
        if nearest_function_range(definition).is_some()
            || definition
                .ancestors()
                .any(|n| n.kind().as_ref() == "statement_block")
            || root.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "assignment_expression"
                        | "augmented_assignment_expression"
                        | "update_expression"
                ) && n
                    .field("left")
                    .or_else(|| (n.kind().as_ref() == "update_expression").then(|| n.clone()))
                    .is_some_and(|left| left.text().trim() == callee)
            })
            || !walk(path, root, definition, bindings, headers, controls, false)
        {
            return false;
        }
        controls.push(Capture {
            text: name.clone(),
            location: location(path, definition),
        });
    }
    true
}
