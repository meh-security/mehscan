use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Evidence, EvidenceKind, Language, LiteralState, LiteralValue,
};

/// Marks strong interpreter operands for every supported language. This pass
/// consumes capture/literal facts already produced while scanning the file; it
/// performs no repository traversal and does not infer a source-to-sink path.
pub(crate) fn annotate(
    language: Language,
    source: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    evidence: &mut [Evidence],
) {
    for item in evidence.iter_mut().filter(|item| {
        item.kind == EvidenceKind::Sink
            || (item.kind == EvidenceKind::SensitiveOperation
                && item.capability == Capability::DatabaseQuery
                && item.cwe_candidates.iter().any(|cwe| cwe == "CWE-943"))
    }) {
        if item.capability == Capability::DatabaseQuery {
            normalize_database_query_operand(language, source, root, item);
            annotate_database_query_facts(source, item);
            annotate_dynamic_sql(language, source, root, item);
            annotate_nosql_structure(root, item);
        }
        if item.capability == Capability::ProcessExecution {
            annotate_process_semantics(language, source, item);
        }

        if has_marker(item) {
            continue;
        }

        let strong = match item.capability {
            Capability::HtmlOutput => {
                explicit_html_trust_boundary(item) && capture_is_dynamic(item, &["content", "html"])
            }
            Capability::ProcessExecution => {
                if process_is_shell_api(language, source, item) {
                    push_tag(&mut item.tags, "shell-command-text");
                }
                process_operand_is_dynamic(item)
            }
            Capability::FormatStringOutput => capture_is_dynamic(item, &["format"]),
            Capability::DynamicCodeExecution => capture_is_dynamic(item, &["code"]),
            Capability::TemplateEvaluation => capture_is_dynamic(item, &["template"]),
            Capability::Deserialization => {
                executable_deserializer(item) && capture_is_dynamic(item, &["payload", "stream"])
            }
            Capability::DatabaseQuery => raw_nosql_boundary(item),
            Capability::LdapQuery => capture_is_dynamic(item, &["filter", "distinguished_name"]),
            Capability::XpathQuery => capture_is_dynamic(item, &["expression"]),
            Capability::OutboundNetworkRequest => {
                capture_is_dynamic(item, &["url", "destination", "endpoint"])
            }
            Capability::Redirect => capture_is_dynamic(item, &["location", "destination", "url"]),
            _ => false,
        };
        if strong {
            push_tag(&mut item.tags, "review-origin:decision-critical");
            push_tag(
                &mut item.tags,
                &format!("review-language:{}", language_tag(language)),
            );
        }
    }
}

fn annotate_database_query_facts(source: &str, item: &mut Evidence) {
    if item.tags.iter().any(|tag| tag == "sql")
        && !item.tags.iter().any(|tag| tag.starts_with("query-role:"))
    {
        push_tag(&mut item.tags, "query-role:sql-text");
    }
    if ["parameters", "bindings", "values"]
        .into_iter()
        .any(|role| item.captures.contains_key(role))
    {
        push_tag(&mut item.tags, "query-bindings:separate");
    }
    let operation = source
        .get(
            item.location.start.byte_offset.min(source.len())
                ..item.location.end.byte_offset.min(source.len()),
        )
        .unwrap_or_default();
    let compact = operation
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let lower = compact.to_ascii_lowercase();
    if item.captures.contains_key("query_envelope")
        && (lower.contains("values:") || lower.contains("parameters:"))
    {
        push_tag(&mut item.tags, "query-bindings:separate");
    }
    if item.rule_id == "csharp-dapper-database-query"
        && lower.contains("commandtype:commandtype.storedprocedure")
    {
        item.tags.retain(|tag| tag != "query-role:sql-text");
        push_tag(&mut item.tags, "query-role:stored-procedure-name");
    }
}

fn annotate_dynamic_sql(
    language: Language,
    source: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    item: &mut Evidence,
) {
    if item.tags.iter().any(|tag| tag == "nosql")
        || item.tags.iter().any(|tag| {
            matches!(
                tag.as_str(),
                "dynamic-query-composition" | "dynamic-query-operand"
            )
        })
    {
        return;
    }
    let Some(query) = item.captures.get("query").cloned() else {
        return;
    };
    let literal = item.context.literals.get("query");
    let references = literal
        .map(|literal| literal.references.clone())
        .unwrap_or_default();
    let composition = if literal.is_some_and(|literal| literal.state == LiteralState::Partial) {
        Some(("partial-literal", references))
    } else {
        bounded_query_composition(language, source, root, item, &query, query.text.trim())
    };
    let Some((style, mut references)) = composition else {
        if query_is_fixed_local_alias(language, source, root, item, &query)
            || !capture_is_dynamic(item, &["query"])
        {
            return;
        }
        push_tag(&mut item.tags, "dynamic-query-operand");
        push_tag(&mut item.tags, "review-origin:decision-critical");
        push_tag(&mut item.tags, "query-operand:nonliteral");
        push_tag(&mut item.tags, "dynamic-origin:unknown");
        item.captures.insert(
            "dynamic_operand".to_string(),
            Capture {
                text: query.text.trim().to_string(),
                location: query.location,
            },
        );
        return;
    };
    if references.is_empty() {
        references.push(query.text.trim().trim_start_matches('&').to_string());
    }

    push_tag(&mut item.tags, "dynamic-query-composition");
    push_tag(&mut item.tags, "review-origin:decision-critical");
    push_tag(&mut item.tags, &format!("query-composition:{style}"));
    push_tag(&mut item.tags, "dynamic-origin:local-expression");
    item.captures
        .insert("query_composition".to_string(), query.clone());
    item.captures.insert(
        "dynamic_operands".to_string(),
        Capture {
            text: references.join(", "),
            location: query.location.clone(),
        },
    );
    if let Some(reference) = references.first() {
        item.captures.insert(
            "dynamic_operand".to_string(),
            Capture {
                text: reference.clone(),
                location: query.location,
            },
        );
    }
}

fn normalize_database_query_operand(
    language: Language,
    source: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    item: &mut Evidence,
) {
    let Some(query) = item.captures.get("query").cloned() else {
        return;
    };
    let Some(node) = capture_node(root, &query) else {
        return;
    };
    let normalized = match language {
        Language::Javascript | Language::Typescript | Language::Tsx
            if matches!(node.kind().as_ref(), "object" | "object_expression") =>
        {
            object_property(&node, &["sql", "text"])
                .map(|value| (value, "query-envelope:object-property"))
        }
        Language::Csharp
            if node.kind().as_ref() == "object_creation_expression"
                && node.field("type").is_some_and(|kind| {
                    kind.text().trim().rsplit('.').next() == Some("CommandDefinition")
                }) =>
        {
            csharp_command_definition_text(&node)
                .map(|value| (value, "query-envelope:dapper-command-definition"))
        }
        _ => None,
    };
    let Some((value, tag)) = normalized else {
        return;
    };
    item.captures.insert("query_envelope".to_string(), query);
    item.captures
        .insert("query".to_string(), capture_for_node(source, item, &value));
    push_tag(&mut item.tags, tag);
}

fn annotate_nosql_structure(root: &Node<'_, StrDoc<SupportLang>>, item: &mut Evidence) {
    if !is_nosql_boundary(item) {
        return;
    }
    let role = if item.captures.contains_key("nosql_expression") {
        "nosql_expression"
    } else if item.captures.contains_key("nosql_query") {
        "nosql_query"
    } else if item.captures.contains_key("filter") {
        "filter"
    } else {
        return;
    };
    let Some(operand) = item.captures.get(role).cloned() else {
        return;
    };
    if !capture_is_dynamic(item, &[role]) {
        return;
    }
    let fixed_keys = capture_node(root, &operand).is_some_and(|node| fixed_document_shape(&node));
    if fixed_keys {
        push_tag(&mut item.tags, "query-shape:fixed-document-keys");
    }
    let style = if item.rule_id.contains("mongodb-where") {
        "executable-predicate"
    } else if item.rule_id.contains("nosql-json") {
        "raw-document-text"
    } else if role == "nosql_expression" {
        "expression-syntax"
    } else if fixed_keys {
        "fixed-keys-unknown-values"
    } else {
        "unknown-document-structure"
    };
    push_tag(&mut item.tags, "dynamic-nosql-structure");
    push_tag(&mut item.tags, &format!("nosql-structure:{style}"));
    item.captures.insert("dynamic_operand".to_string(), operand);
}

fn is_nosql_boundary(item: &Evidence) -> bool {
    item.tags.iter().any(|tag| tag == "nosql")
        || item.cwe_candidates.iter().any(|cwe| cwe == "CWE-943")
}

fn capture_node<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    capture: &Capture,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| {
            node.range().start == capture.location.start.byte_offset
                && node.range().end == capture.location.end.byte_offset
        })
        .last()
}

fn capture_for_node(
    source: &str,
    item: &Evidence,
    node: &Node<'_, StrDoc<SupportLang>>,
) -> Capture {
    let prefix = source
        .get(
            item.location.start.byte_offset.min(source.len())..node.range().start.min(source.len()),
        )
        .unwrap_or_default();
    let location_start = advance_position(&item.location.start, prefix);
    let location_end = advance_position(&location_start, node.text().as_ref());
    Capture {
        text: node.text().into_owned(),
        location: mehscan_core::Location {
            path: item.location.path.clone(),
            start: location_start,
            end: location_end,
        },
    }
}

fn object_property<'tree>(
    object: &Node<'tree, StrDoc<SupportLang>>,
    names: &[&str],
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let mut matches = object.children().filter_map(|child| {
        if child.kind().as_ref() != "pair" {
            return None;
        }
        let key = child.field("key")?;
        names
            .contains(&key.text().trim_matches(['\'', '"']))
            .then(|| child.field("value"))
            .flatten()
    });
    let value = matches.next()?;
    matches.next().is_none().then_some(value)
}

fn csharp_command_definition_text<'tree>(
    creation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let arguments = creation.field("arguments")?;
    let mut first = None;
    for argument in arguments.children().filter(|child| child.is_named()) {
        let text = argument.text();
        let compact = text
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let value = argument
            .field("expression")
            .or_else(|| argument.children().filter(|child| child.is_named()).last())
            .unwrap_or_else(|| argument.clone());
        if compact.starts_with("commandText:") {
            return Some(value);
        }
        first.get_or_insert(value);
    }
    first
}

fn fixed_document_shape(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if !matches!(
        node.kind().as_ref(),
        "object" | "object_expression" | "dictionary"
    ) {
        return false;
    }
    node.children()
        .filter(|child| child.is_named())
        .all(|child| {
            if matches!(
                child.kind().as_ref(),
                "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
                    | "comment"
            ) {
                return true;
            }
            if child.kind().as_ref() != "pair" {
                return false;
            }
            let Some(key) = child.field("key") else {
                return false;
            };
            let key = key.text();
            let key = key.trim_matches(['\'', '"']);
            let fixed = key.chars().enumerate().all(|(index, character)| {
                character.is_alphanumeric() || character == '_' || (index == 0 && character == '$')
            });
            fixed && !matches!(key, "$where" | "$expr" | "$function" | "$accumulator")
        })
}

fn query_is_fixed_local_alias(
    language: Language,
    source: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    item: &Evidence,
    query_capture: &Capture,
) -> bool {
    let name = query_capture
        .text
        .trim()
        .trim_start_matches('&')
        .trim_start_matches('$');
    if !plain_identifier(name) {
        return false;
    }
    let Some(scope_start) = callable_start(root, query_capture) else {
        return false;
    };
    let Some(prefix) = source.get(scope_start..item.location.start.byte_offset.min(source.len()))
    else {
        return false;
    };
    for statement in bounded_statements(prefix).into_iter().rev().take(96) {
        let trimmed = statement.trim();
        if mutation_value(trimmed, name, language).is_some() {
            return false;
        }
        if matches_assignment_to(trimmed, name, language) {
            return assignment_value(trimmed).is_some_and(is_quoted_literal);
        }
    }
    false
}

fn bounded_query_composition(
    language: Language,
    source: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    item: &Evidence,
    query_capture: &Capture,
    query: &str,
) -> Option<(&'static str, Vec<String>)> {
    if expression_is_composed(language, query) {
        return Some(("inline-expression", expression_references(language, query)));
    }
    let name = query.trim().trim_start_matches('&').trim_start_matches('$');
    if !plain_identifier(name) {
        return None;
    }
    let scope_start = callable_start(root, query_capture).unwrap_or(0);
    let prefix = source.get(scope_start..item.location.start.byte_offset.min(source.len()))?;
    for statement in bounded_statements(prefix).into_iter().rev().take(96) {
        let trimmed = statement.trim();
        if let Some(value) = mutation_value(trimmed, name, language) {
            if value_is_dynamic(value) {
                return Some((
                    "bounded-local-builder",
                    expression_references(language, value),
                ));
            }
            continue;
        }
        if matches_assignment_to(trimmed, name, language) {
            let value = assignment_value(trimmed)?;
            return expression_is_composed(language, value).then(|| {
                (
                    "bounded-local-alias",
                    expression_references(language, value),
                )
            });
        }
        if matches!(language, Language::C | Language::Cpp)
            && (trimmed.contains(&format!("sprintf({name},"))
                || trimmed.contains(&format!("snprintf({name},")))
        {
            return Some((
                "native-format-buffer",
                native_format_arguments(trimmed, name),
            ));
        }
    }
    None
}

fn native_format_arguments(statement: &str, buffer: &str) -> Vec<String> {
    let (call, format_index) = if statement.contains(&format!("snprintf({buffer},")) {
        ("snprintf", 2)
    } else {
        ("sprintf", 1)
    };
    let Some(start) = statement.find(&format!("{call}(")) else {
        return vec![buffer.to_string()];
    };
    let arguments = &statement[start + call.len() + 1..];
    let arguments = arguments.strip_suffix(')').unwrap_or(arguments);
    let values = split_arguments(arguments);
    let references = values
        .into_iter()
        .skip(format_index + 1)
        .flat_map(identifier_tokens)
        .filter(|reference| reference != buffer)
        .collect::<Vec<_>>();
    if references.is_empty() {
        vec![buffer.to_string()]
    } else {
        references
    }
}

fn split_arguments(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut arguments = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                arguments.push(source[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    arguments.push(source[start..].trim());
    arguments
}

fn bounded_statements(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut statements = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b';' | b'\n' => {
                if let Some(statement) = source.get(start..index)
                    && !statement.trim().is_empty()
                {
                    statements.push(statement);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    if let Some(statement) = source.get(start..)
        && !statement.trim().is_empty()
    {
        statements.push(statement);
    }
    statements
}

fn callable_start(root: &Node<'_, StrDoc<SupportLang>>, capture: &Capture) -> Option<usize> {
    let node = root
        .dfs()
        .filter(|node| {
            node.range().start == capture.location.start.byte_offset
                && node.range().end == capture.location.end.byte_offset
        })
        .last()?;
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_definition"
                    | "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "generator_function"
                    | "generator_function_declaration"
                    | "method_declaration"
                    | "method_definition"
                    | "constructor_declaration"
                    | "function_item"
            )
        })
        .map(|ancestor| ancestor.range().start)
}

fn mutation_value<'a>(line: &'a str, name: &str, language: Language) -> Option<&'a str> {
    for operator in match language {
        Language::Php => [".=", "+="].as_slice(),
        _ => ["+=", ".="].as_slice(),
    } {
        let left = if language == Language::Php {
            format!("${name} {operator}")
        } else {
            format!("{name} {operator}")
        };
        if let Some(value) = line.strip_prefix(&left) {
            return Some(value.trim().trim_end_matches(';'));
        }
    }
    for method in ["append", "Append", "push_str", "WriteString"] {
        let prefix = format!("{name}.{method}(");
        if let Some(value) = line
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(");"))
        {
            return Some(value.trim());
        }
    }
    None
}

fn value_is_dynamic(value: &str) -> bool {
    let value = value.trim();
    !is_quoted_literal(value)
        && value.parse::<i128>().is_err()
        && !matches!(value, "true" | "false" | "null" | "nil")
}

fn expression_is_composed(language: Language, expression: &str) -> bool {
    let compact = expression.trim();
    match language {
        Language::Kotlin => {
            compact.contains("${")
                || compact.split('$').skip(1).any(|part| {
                    part.chars()
                        .next()
                        .is_some_and(|c| c == '_' || c.is_alphabetic())
                })
                || compact.contains('+')
                || compact.contains("String.format(")
        }
        Language::Go => compact.contains("fmt.Sprintf(") || compact.contains('+'),
        Language::Rust => compact.contains("format!(") || compact.contains('+'),
        Language::Php => compact.contains(" . ") || compact.contains("sprintf("),
        Language::Python => {
            compact.starts_with("f\"")
                || compact.starts_with("f'")
                || compact.contains(".format(")
                || compact.contains(" % ")
                || compact.contains('+')
        }
        Language::Javascript | Language::Typescript | Language::Tsx => {
            compact.contains("${") || compact.contains('+')
        }
        _ => compact.contains('+') || compact.contains("format(") || compact.contains("Format("),
    }
}

fn matches_assignment_to(line: &str, name: &str, language: Language) -> bool {
    let candidates = match language {
        Language::Php => vec![format!("${name} =")],
        Language::Go => vec![
            format!("{name} :="),
            format!("var {name} ="),
            format!("{name} ="),
        ],
        Language::Rust => vec![
            format!("let {name} ="),
            format!("let mut {name} ="),
            format!("{name} ="),
        ],
        Language::Javascript | Language::Typescript | Language::Tsx => vec![
            format!("const {name} ="),
            format!("let {name} ="),
            format!("var {name} ="),
            format!("{name} ="),
        ],
        Language::Kotlin => vec![
            format!("val {name} ="),
            format!("var {name} ="),
            format!("{name} ="),
        ],
        _ => vec![format!("{name} =")],
    };
    candidates.iter().any(|candidate| {
        line.starts_with(candidate)
            || line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(candidate.split_whitespace().count())
                .any(|window| window.join(" ").starts_with(candidate))
    })
}

fn assignment_value(line: &str) -> Option<&str> {
    line.split_once("=")
        .map(|(_, value)| value.trim().trim_end_matches(';'))
}

fn expression_references(language: Language, expression: &str) -> Vec<String> {
    let focused = match language {
        Language::Kotlin | Language::Javascript | Language::Typescript | Language::Tsx => {
            dollar_references(expression)
        }
        Language::Python | Language::Rust => brace_references(expression),
        Language::Php => expression
            .split('$')
            .skip(1)
            .filter_map(identifier_prefix)
            .collect(),
        Language::Go => expression
            .split_once(',')
            .map(|(_, arguments)| identifier_tokens(arguments))
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    if !focused.is_empty() {
        return focused;
    }
    identifier_tokens(expression)
}

fn dollar_references(expression: &str) -> Vec<String> {
    expression
        .split('$')
        .skip(1)
        .filter_map(|part| {
            let part = part.strip_prefix('{').unwrap_or(part);
            identifier_prefix(part)
        })
        .collect()
}

fn brace_references(expression: &str) -> Vec<String> {
    let mut references = Vec::new();
    let mut rest = expression;
    while let Some((_, after_open)) = rest.split_once('{') {
        let Some((inside, after_close)) = after_open.split_once('}') else {
            break;
        };
        if let Some(reference) = identifier_prefix(inside)
            && !references.contains(&reference)
        {
            references.push(reference);
        }
        rest = after_close;
    }
    references
}

fn identifier_prefix(value: &str) -> Option<String> {
    let value = value.trim_start();
    let end = value
        .find(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
        .unwrap_or(value.len());
    let token = &value[..end];
    plain_identifier(token).then(|| token.to_string())
}

fn identifier_tokens(expression: &str) -> Vec<String> {
    let mut references = Vec::new();
    for token in expression.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if token.len() > 1
            && token
                .chars()
                .next()
                .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
            && ![
                "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "VALUES", "format",
                "sprintf", "Sprintf", "String", "fmt", "let", "var", "const",
            ]
            .contains(&token)
            && !references.iter().any(|existing| existing == token)
        {
            references.push(token.to_string());
        }
    }
    references
}

fn plain_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn explicit_html_trust_boundary(item: &Evidence) -> bool {
    if item.captures.contains_key("template") {
        return false;
    }
    if item.rule_id.contains("browser-dom-html-output")
        || item.rule_id.contains("react-dangerous-html-output")
    {
        return true;
    }
    item.tags.iter().any(|tag| {
        matches!(
            tag.as_str(),
            "trusted-markup"
                | "trusted-content-bypass"
                | "explicit-raw-html"
                | "dangerously-set-inner-html"
        )
    }) || matches!(
        item.rule_id.as_str(),
        "rust-axum-html-output"
            | "rust-warp-html-output"
            | "rust-actix-html-output"
            | "kotlin-ktor-html-output"
    )
}

fn process_operand_is_dynamic(item: &Evidence) -> bool {
    if item.tags.iter().any(|tag| tag == "shell-command-text") {
        return capture_is_dynamic(item, &["shell_command", "arguments", "command"]);
    }
    // Rust builder-chain matches also contain the nested Command::new call.
    // The constructor owns executable selection; later .arg/.args matches do
    // not create another dynamic-executable question for the same launch.
    if item.rule_id == "rust-process-execution" && item.captures.contains_key("arguments") {
        return false;
    }
    if capture_is_dynamic(item, &["executable", "command"]) {
        return true;
    }
    fixed_literal_string(item, "command").is_some_and(is_shell_name)
        && capture_is_dynamic(item, &["arguments"])
}

/// Recovers exact local launch semantics that variadic AST captures cannot
/// represent on their own. This stays inside the matched invocation or Rust
/// builder chain and does not infer values across statements or call sites.
fn annotate_process_semantics(language: Language, source: &str, item: &mut Evidence) {
    let start = item.location.start.byte_offset.min(source.len());
    let end = item.location.end.byte_offset.min(source.len());
    let operation = source.get(start..end).unwrap_or_default();

    if language == Language::Rust
        && let Some((value, offset)) = rust_command_new_operand(operation)
    {
        insert_process_capture(item, operation, "executable", value, offset);
    }

    let shell_api = process_is_shell_api(language, source, item);
    let shell_executable = item
        .captures
        .get("executable")
        .or_else(|| item.captures.get("command"))
        .and_then(|capture| quoted_string(capture.text.trim()))
        .is_some_and(is_shell_name);
    if !shell_api && !shell_executable {
        return;
    }
    push_tag(&mut item.tags, "shell-command-text");

    if let Some((payload, offset)) = exact_shell_payload(language, operation) {
        insert_process_capture(item, operation, "shell_command", payload, offset);
    } else if shell_api {
        let node_shell_option = matches!(
            language,
            Language::Javascript | Language::Typescript | Language::Tsx
        ) && operation
            .replace(char::is_whitespace, "")
            .contains("shell:true");
        let payload = if node_shell_option {
            item.captures
                .get("arguments")
                .cloned()
                .or_else(|| item.captures.get("command").cloned())
        } else {
            item.captures
                .get("command")
                .cloned()
                .or_else(|| item.captures.get("arguments").cloned())
        };
        if let Some(payload) = payload {
            item.captures.insert("shell_command".to_string(), payload);
        }
    } else if let Some(arguments) = item.captures.get("arguments").cloned() {
        item.captures.insert("shell_command".to_string(), arguments);
    }
}

fn insert_process_capture(
    item: &mut Evidence,
    operation: &str,
    role: &str,
    value: &str,
    relative_offset: usize,
) {
    let prefix = operation.get(..relative_offset).unwrap_or(operation);
    let start = advance_position(&item.location.start, prefix);
    let end = advance_position(&start, value);
    item.captures.insert(
        role.to_string(),
        Capture {
            text: value.trim().to_string(),
            location: mehscan_core::Location {
                path: item.location.path.clone(),
                start,
                end,
            },
        },
    );
}

fn advance_position(start: &mehscan_core::Position, text: &str) -> mehscan_core::Position {
    let mut position = start.clone();
    position.byte_offset += text.len();
    for character in text.chars() {
        if character == '\n' {
            position.line += 1;
            position.column = 1;
        } else {
            position.column += 1;
        }
    }
    position
}

fn rust_command_new_operand(operation: &str) -> Option<(&str, usize)> {
    let marker = "Command::new(";
    let start = operation.find(marker)? + marker.len();
    let end = matching_delimiter(operation, start - 1, b'(', b')')?;
    let value = operation.get(start..end)?.trim();
    let offset = operation.get(start..end)?.find(value)? + start;
    Some((value, offset))
}

fn exact_shell_payload(language: Language, operation: &str) -> Option<(&str, usize)> {
    if language == Language::Rust {
        let mut values = Vec::new();
        let mut search = 0usize;
        while let Some(found) = operation.get(search..)?.find(".arg(") {
            let open = search + found + ".arg".len();
            let close = matching_delimiter(operation, open, b'(', b')')?;
            let raw = operation.get(open + 1..close)?;
            let value = raw.trim();
            let offset = open + 1 + raw.find(value)?;
            values.push((value, offset));
            search = close + 1;
        }
        return shell_switch_payload(&values);
    }

    let open = operation.find('(')?;
    let close = matching_delimiter(operation, open, b'(', b')')?;
    let inside = operation.get(open + 1..close)?;
    let values = split_arguments(inside)
        .into_iter()
        .filter(|value| !value.trim_start().starts_with("shell="))
        .map(|value| {
            let trimmed = value.trim();
            let offset = open + 1 + inside.find(value)? + value.find(trimmed)?;
            Some((trimmed, offset))
        })
        .collect::<Option<Vec<_>>>()?;
    shell_switch_payload(&values)
}

fn shell_switch_payload<'a>(values: &[(&'a str, usize)]) -> Option<(&'a str, usize)> {
    values.windows(2).find_map(|pair| {
        let switch = quoted_string(pair[0].0)?.to_ascii_lowercase();
        matches!(
            switch.as_str(),
            "/c" | "/k" | "-c" | "-command" | "-encodedcommand" | "-file"
        )
        .then_some(pair[1])
    })
}

fn matching_delimiter(source: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    (bytes.get(open) == Some(&opening)).then_some(())?;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate().skip(open) {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            byte if byte == opening => depth += 1,
            byte if byte == closing => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn quoted_string(value: &str) -> Option<&str> {
    let value = value.trim().trim_start_matches('@');
    (value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))))
    .then(|| &value[1..value.len() - 1])
}

fn process_is_shell_api(language: Language, source: &str, item: &Evidence) -> bool {
    if item.rule_id == "php-command-execution" {
        return true;
    }
    let operation = source
        .get(
            item.location.start.byte_offset.min(source.len())
                ..item.location.end.byte_offset.min(source.len()),
        )
        .unwrap_or_default()
        .replace(char::is_whitespace, "");
    match language {
        Language::Javascript | Language::Typescript | Language::Tsx => {
            operation.contains(".exec(")
                || operation.contains(".execSync(")
                || operation.contains("shell:true")
        }
        Language::Python => {
            operation.contains("os.system(")
                || operation.contains("os.popen(")
                || operation.contains("shell=True")
        }
        Language::C | Language::Cpp => {
            operation.starts_with("system(") || operation.starts_with("popen(")
        }
        _ => false,
    }
}

fn executable_deserializer(item: &Evidence) -> bool {
    if item.tags.iter().any(|tag| {
        matches!(
            tag.as_str(),
            "executable-functions" | "executable-object" | "unsafe-yaml"
        )
    }) {
        return true;
    }
    match item.rule_id.as_str() {
        "php-deserialization" | "kotlin-object-deserialization" => true,
        // This shared rule also covers Jackson readValue. A captured target
        // type identifies that ordinary structured-data branch.
        "java-object-deserialization" => !item.captures.contains_key("type"),
        rule if rule.starts_with("java-") => matches!(
            rule,
            "java-native-object-deserialization"
                | "java-xstream-object-deserialization"
                | "java-xml-decoder-deserialization"
                | "java-snakeyaml-load"
        ),
        _ => false,
    }
}

fn raw_nosql_boundary(item: &Evidence) -> bool {
    item.tags.iter().any(|tag| tag == "dynamic-nosql-structure")
}

fn capture_is_dynamic(item: &Evidence, roles: &[&str]) -> bool {
    let Some(role) = roles.iter().find(|role| item.captures.contains_key(**role)) else {
        return false;
    };
    if fixed_literal_string(item, role).is_some() {
        return false;
    }
    item.captures
        .get(*role)
        .is_some_and(|capture| !is_quoted_literal(capture.text.trim()))
}

fn fixed_literal_string<'a>(item: &'a Evidence, role: &str) -> Option<&'a str> {
    let literal = item.context.literals.get(role)?;
    if literal.state != LiteralState::Known {
        return None;
    }
    match literal.value.as_ref()? {
        LiteralValue::String(value) => Some(value),
        _ => None,
    }
}

fn is_quoted_literal(value: &str) -> bool {
    value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('`') && value.ends_with('`')))
}

fn is_shell_name(value: &str) -> bool {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    matches!(
        normalized.rsplit('/').next().unwrap_or(&normalized),
        "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "sh"
            | "bash"
            | "zsh"
    )
}

fn has_marker(item: &Evidence) -> bool {
    item.tags
        .iter()
        .any(|tag| tag == "review-origin:decision-critical")
}

fn push_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|candidate| candidate == tag) {
        tags.push(tag.to_string());
    }
}

fn language_tag(language: Language) -> &'static str {
    match language {
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Csharp => "csharp",
        Language::Go => "go",
        Language::Java => "java",
        Language::Javascript => "javascript",
        Language::Kotlin => "kotlin",
        Language::Php => "php",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::Tsx => "tsx",
        Language::Typescript => "typescript",
    }
}
