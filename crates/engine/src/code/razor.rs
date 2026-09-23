use std::collections::BTreeMap;
use std::ops::Range;

use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceKind, Location, Position, Provenance,
    Resolution,
};

use super::context::unknown_textual_context;

const RULE_ID: &str = "csharp-razor-html-raw-output";
const LITERAL_RULE_ID: &str = "csharp-razor-literal-raw-output-control";

#[derive(Clone, Debug, Eq, PartialEq)]
enum OutputContext {
    HtmlText,
    HtmlAttribute(String),
    UrlAttribute(String),
    JavaScriptString,
    JavaScriptCode,
    ComplexAttribute(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncoderKind {
    Html,
    JavaScript,
    UrlComponent,
}

pub(crate) fn scan_escape_hatches(path: &str, source: &str) -> Vec<Evidence> {
    let comments = razor_comment_ranges(source);
    let mut evidence = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("@Html.Raw") {
        let start = cursor + relative;
        cursor = start + "@Html.Raw".len();
        if comments
            .iter()
            .any(|range| range.start <= start && start < range.end)
            || start
                .checked_sub(1)
                .is_some_and(|offset| source.as_bytes()[offset] == b'@')
        {
            continue;
        }
        let mut open = cursor;
        while source
            .as_bytes()
            .get(open)
            .is_some_and(u8::is_ascii_whitespace)
        {
            open += 1;
        }
        if source.as_bytes().get(open) != Some(&b'(') {
            continue;
        }
        let Some(close) = matching_parenthesis(source, open) else {
            continue;
        };
        let argument_range = trim_range(source, open + 1..close);
        if argument_range.is_empty() {
            continue;
        }
        let evidence_range = start..close + 1;
        let argument = &source[argument_range.clone()];
        let output_context = output_context(source, start);
        if is_plain_string_literal(argument) {
            let rule_id = literal_rule_id(&output_context);
            evidence.push(make_evidence(
                path,
                source,
                &evidence_range,
                &argument_range,
                rule_id,
                EvidenceKind::Validation,
                Capability::HtmlOutput,
                literal_tags(&output_context),
                Vec::new(),
            ));
        } else {
            let rule_id = sink_rule_id(&output_context);
            let sink = make_evidence(
                path,
                source,
                &evidence_range,
                &argument_range,
                rule_id,
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                sink_tags(&output_context, encoder_kind(source, argument)),
                Vec::new(),
            );
            let sink_id = sink.id.clone();
            evidence.push(sink);
            if let Some(encoder) = encoder_kind(source, argument)
                && let Some((control_rule, control_tags)) =
                    encoding_control(&output_context, encoder)
            {
                evidence.push(make_evidence(
                    path,
                    source,
                    &evidence_range,
                    &argument_range,
                    control_rule,
                    EvidenceKind::Validation,
                    Capability::HtmlEncoding,
                    control_tags,
                    vec![sink_id.clone()],
                ));
            }
            if output_context == OutputContext::JavaScriptCode
                && let Some(serializer) = json_serialization_control(source, argument)
            {
                evidence.push(make_evidence(
                    path,
                    source,
                    &evidence_range,
                    &argument_range,
                    "csharp-razor-javascript-json-serialization-control",
                    EvidenceKind::Validation,
                    Capability::HtmlEncoding,
                    vec![
                        "aspnet-core".to_string(),
                        "razor".to_string(),
                        "output-context:javascript-code".to_string(),
                        format!("json-serializer:{serializer}"),
                        "json-serialization".to_string(),
                        "recommendation:control-present".to_string(),
                    ],
                    vec![sink_id],
                ));
            }
        }
        cursor = close + 1;
    }
    // Razor components render MarkupString without HTML encoding. Restrict this
    // textual detector to expressions rendered directly in markup; constructing
    // a value inside @code does not establish an output sink by itself.
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("@(") {
        let start = cursor + relative;
        let open = start + 1;
        cursor = open + 1;
        if comments
            .iter()
            .any(|range| range.start <= start && start < range.end)
            || start
                .checked_sub(1)
                .is_some_and(|offset| source.as_bytes()[offset] == b'@')
        {
            continue;
        }
        let Some(close) = matching_parenthesis(source, open) else {
            continue;
        };
        let expression = trim_range(source, open + 1..close);
        let value = if source[expression.clone()].starts_with("(MarkupString)") {
            trim_range(
                source,
                expression.start + "(MarkupString)".len()..expression.end,
            )
        } else if let Some(prefix) = [
            "new MarkupString(",
            "new Microsoft.AspNetCore.Components.MarkupString(",
        ]
        .into_iter()
        .find(|prefix| source[expression.clone()].starts_with(prefix))
        {
            let constructor_open = expression.start + prefix.len() - 1;
            if matching_parenthesis(source, constructor_open) != Some(expression.end - 1) {
                cursor = close + 1;
                continue;
            }
            trim_range(source, constructor_open + 1..expression.end - 1)
        } else {
            cursor = close + 1;
            continue;
        };
        if value.is_empty() {
            cursor = close + 1;
            continue;
        }
        let context = output_context(source, start);
        let literal = is_plain_string_literal(&source[value.clone()]);
        let mut tags = if literal {
            literal_tags(&context)
        } else {
            sink_tags(&context, encoder_kind(source, &source[value.clone()]))
        };
        tags.push("blazor-markupstring".to_string());
        evidence.push(make_evidence(
            path,
            source,
            &(start..close + 1),
            &value,
            if literal {
                "csharp-blazor-literal-markupstring-control"
            } else {
                "csharp-blazor-markupstring-raw-output"
            },
            if literal {
                EvidenceKind::Validation
            } else {
                EvidenceKind::Sink
            },
            Capability::HtmlOutput,
            tags,
            Vec::new(),
        ));
        cursor = close + 1;
    }
    evidence
}

#[allow(clippy::too_many_arguments)]
fn make_evidence(
    path: &str,
    source: &str,
    evidence_range: &Range<usize>,
    argument_range: &Range<usize>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    tags: Vec<String>,
    related_evidence: Vec<String>,
) -> Evidence {
    let legacy = matches!(rule_id, RULE_ID | LITERAL_RULE_ID);
    Evidence {
        id: evidence_id(path, rule_id, evidence_range),
        kind,
        capability,
        location: location(path, source, evidence_range.clone()),
        enclosing_symbol: Some(if path.ends_with(".razor") {
            "Razor component".to_string()
        } else {
            "Razor view".to_string()
        }),
        captures: BTreeMap::from([(
            if capability == Capability::HtmlOutput {
                "html"
            } else {
                "encoded_value"
            }
            .to_string(),
            Capture {
                text: source[argument_range.clone()].to_string(),
                location: location(path, source, argument_range.clone()),
            },
        )]),
        cwe_candidates: vec!["CWE-79".to_string()],
        tags,
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Textual,
            engine: format!("mehscan razor-escape-hatch {}", if legacy { 1 } else { 2 }),
            rule_version: 1,
        },
        context: unknown_textual_context(),
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    }
}

fn sink_rule_id(context: &OutputContext) -> &'static str {
    match context {
        OutputContext::HtmlText => RULE_ID,
        OutputContext::HtmlAttribute(_) => "csharp-razor-attribute-raw-output",
        OutputContext::UrlAttribute(_) => "csharp-razor-url-attribute-raw-output",
        OutputContext::JavaScriptString => "csharp-razor-javascript-string-raw-output",
        OutputContext::JavaScriptCode => "csharp-razor-javascript-code-raw-output",
        OutputContext::ComplexAttribute(_) => "csharp-razor-complex-attribute-raw-output-review",
    }
}

fn literal_rule_id(context: &OutputContext) -> &'static str {
    match context {
        OutputContext::HtmlText => LITERAL_RULE_ID,
        OutputContext::HtmlAttribute(_) => "csharp-razor-literal-attribute-raw-output-control",
        OutputContext::UrlAttribute(_) => "csharp-razor-literal-url-raw-output-control",
        OutputContext::JavaScriptString => {
            "csharp-razor-literal-javascript-string-raw-output-control"
        }
        OutputContext::JavaScriptCode => "csharp-razor-literal-javascript-code-raw-output-control",
        OutputContext::ComplexAttribute(_) => {
            "csharp-razor-literal-complex-attribute-raw-output-control"
        }
    }
}

fn sink_tags(context: &OutputContext, encoder: Option<EncoderKind>) -> Vec<String> {
    let mut tags = vec![
        "aspnet-core".to_string(),
        "razor".to_string(),
        "explicit-raw-html".to_string(),
        "stored-content-provenance-unresolved".to_string(),
        "recommendation:review-data-provenance".to_string(),
    ];
    match context {
        OutputContext::HtmlText => return tags,
        OutputContext::HtmlAttribute(attribute) => {
            tags.push("output-context:html-attribute".to_string());
            tags.push(format!("attribute:{attribute}"));
        }
        OutputContext::UrlAttribute(attribute) => {
            tags.push("output-context:url-attribute".to_string());
            tags.push(format!("attribute:{attribute}"));
            tags.push("url-scheme-validation-unresolved".to_string());
        }
        OutputContext::JavaScriptString => {
            tags.push("output-context:javascript-string".to_string());
        }
        OutputContext::JavaScriptCode => {
            tags.push("output-context:javascript-code".to_string());
            tags.push("javascript-value-shape-unresolved".to_string());
        }
        OutputContext::ComplexAttribute(attribute) => {
            tags.push("output-context:complex-attribute".to_string());
            tags.push(format!("attribute:{attribute}"));
            tags.push("encoding-context-unresolved".to_string());
            tags.push("recommendation:review-output-context".to_string());
        }
    }
    if let Some(encoder) = encoder {
        if matches!(context, OutputContext::ComplexAttribute(_)) {
            return tags;
        }
        let expected = matches!(
            (context, encoder),
            (OutputContext::HtmlAttribute(_), EncoderKind::Html)
                | (OutputContext::JavaScriptString, EncoderKind::JavaScript)
                | (
                    OutputContext::UrlAttribute(_),
                    EncoderKind::Html | EncoderKind::UrlComponent
                )
        );
        if !expected {
            tags.push(format!("wrong-context-encoder:{}", encoder_tag(encoder)));
        }
    }
    tags
}

fn literal_tags(context: &OutputContext) -> Vec<String> {
    let mut tags = vec![
        "aspnet-core".to_string(),
        "razor".to_string(),
        "explicit-raw-html".to_string(),
        "trusted-literal".to_string(),
        "recommendation:control-present".to_string(),
    ];
    match context {
        OutputContext::HtmlText => {}
        OutputContext::HtmlAttribute(attribute) => {
            tags.push("output-context:html-attribute".to_string());
            tags.push(format!("attribute:{attribute}"));
        }
        OutputContext::UrlAttribute(attribute) => {
            tags.push("output-context:url-attribute".to_string());
            tags.push(format!("attribute:{attribute}"));
        }
        OutputContext::JavaScriptString => {
            tags.push("output-context:javascript-string".to_string());
        }
        OutputContext::JavaScriptCode => {
            tags.push("output-context:javascript-code".to_string());
        }
        OutputContext::ComplexAttribute(attribute) => {
            tags.push("output-context:complex-attribute".to_string());
            tags.push(format!("attribute:{attribute}"));
        }
    }
    tags
}

fn encoding_control(
    context: &OutputContext,
    encoder: EncoderKind,
) -> Option<(&'static str, Vec<String>)> {
    let (rule_id, context_tag, mut tags) = match (context, encoder) {
        (OutputContext::HtmlText, EncoderKind::Html) => (
            "csharp-razor-html-text-encoding-control",
            "output-context:html-text",
            vec!["context-matched-encoder".to_string()],
        ),
        (OutputContext::HtmlAttribute(_), EncoderKind::Html) => (
            "csharp-razor-attribute-encoding-control",
            "output-context:html-attribute",
            vec!["context-matched-encoder".to_string()],
        ),
        (OutputContext::JavaScriptString, EncoderKind::JavaScript) => (
            "csharp-razor-javascript-string-encoding-control",
            "output-context:javascript-string",
            vec!["context-matched-encoder".to_string()],
        ),
        (OutputContext::UrlAttribute(_), EncoderKind::Html) => (
            "csharp-razor-url-attribute-html-encoding-control",
            "output-context:url-attribute",
            vec![
                "attribute-encoding-control-present".to_string(),
                "url-scheme-validation-unresolved".to_string(),
            ],
        ),
        (OutputContext::UrlAttribute(_), EncoderKind::UrlComponent) => (
            "csharp-razor-url-component-encoding-observation",
            "output-context:url-attribute",
            vec![
                "url-component-encoding-only".to_string(),
                "url-scheme-validation-unresolved".to_string(),
            ],
        ),
        _ => return None,
    };
    tags.extend([
        "aspnet-core".to_string(),
        "razor".to_string(),
        context_tag.to_string(),
        format!("encoder:{}", encoder_tag(encoder)),
        if matches!(context, OutputContext::UrlAttribute(_)) {
            "recommendation:review-url-policy".to_string()
        } else {
            "recommendation:control-present".to_string()
        },
    ]);
    Some((rule_id, tags))
}

fn encoder_tag(encoder: EncoderKind) -> &'static str {
    match encoder {
        EncoderKind::Html => "html",
        EncoderKind::JavaScript => "javascript",
        EncoderKind::UrlComponent => "url-component",
    }
}

fn output_context(source: &str, start: usize) -> OutputContext {
    if let Some(in_string) = javascript_context(source, start) {
        return if in_string {
            OutputContext::JavaScriptString
        } else {
            OutputContext::JavaScriptCode
        };
    }
    if let Some(attribute) = enclosing_attribute(source, start) {
        if is_url_attribute(&attribute) {
            OutputContext::UrlAttribute(attribute)
        } else if is_complex_attribute(&attribute) {
            OutputContext::ComplexAttribute(attribute)
        } else {
            OutputContext::HtmlAttribute(attribute)
        }
    } else {
        OutputContext::HtmlText
    }
}

fn is_complex_attribute(attribute: &str) -> bool {
    attribute.starts_with("on") || matches!(attribute, "style" | "srcdoc")
}

fn enclosing_attribute(source: &str, start: usize) -> Option<String> {
    let prefix = source.get(..start)?;
    let tag_start = prefix.rfind('<')?;
    if prefix.rfind('>').is_some_and(|end| end > tag_start) {
        return None;
    }
    let tag = &source[tag_start + 1..start];
    if tag.starts_with('!') || tag.starts_with('/') || tag.starts_with('@') {
        return None;
    }
    let equals = tag.rfind('=')?;
    let value_prefix = tag[equals + 1..].trim_start();
    if value_prefix.len() > 1 {
        let first = value_prefix.as_bytes()[0];
        if matches!(first, b'\'' | b'"') && value_prefix.as_bytes()[1..].contains(&first) {
            return None;
        }
        if !matches!(first, b'\'' | b'"')
            && value_prefix.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return None;
        }
    }
    let before_equals = tag[..equals].trim_end();
    let name_start = before_equals
        .rfind(|character: char| {
            !character.is_ascii_alphanumeric() && !matches!(character, '-' | ':' | '_' | '@')
        })
        .map_or(0, |offset| offset + 1);
    let name = before_equals[name_start..]
        .trim_start_matches('@')
        .to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

fn is_url_attribute(attribute: &str) -> bool {
    matches!(
        attribute,
        "href"
            | "src"
            | "action"
            | "formaction"
            | "poster"
            | "cite"
            | "data"
            | "background"
            | "srcset"
            | "xlink:href"
    )
}

fn javascript_context(source: &str, start: usize) -> Option<bool> {
    let lower = source[..start].to_ascii_lowercase();
    let script_start = lower.rfind("<script")?;
    if lower
        .rfind("</script")
        .is_some_and(|script_end| script_end > script_start)
    {
        return None;
    }
    let body_start = source[script_start..start]
        .find('>')
        .map(|offset| script_start + offset + 1)?;
    Some(javascript_quote_at(&source.as_bytes()[body_start..start]).is_some())
}

fn javascript_quote_at(bytes: &[u8]) -> Option<u8> {
    let mut quote = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        let next = bytes.get(cursor + 1).copied();
        if line_comment {
            if byte == b'\n' {
                line_comment = false;
            }
        } else if block_comment {
            if byte == b'*' && next == Some(b'/') {
                block_comment = false;
                cursor += 1;
            }
        } else if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
        } else if byte == b'/' && next == Some(b'/') {
            line_comment = true;
            cursor += 1;
        } else if byte == b'/' && next == Some(b'*') {
            block_comment = true;
            cursor += 1;
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        }
        cursor += 1;
    }
    quote
}

fn encoder_kind(source: &str, expression: &str) -> Option<EncoderKind> {
    let compact = expression
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let open = compact.find('(')?;
    let function = &compact[..open];
    if matching_parenthesis(&compact, open) != Some(compact.len() - 1)
        || !function.ends_with(".Encode")
    {
        return None;
    }
    let receiver = function.strip_suffix(".Encode")?;
    let encoder_type = receiver.strip_suffix(".Default").unwrap_or(receiver);
    [
        ("System.Text.Encodings.Web.HtmlEncoder", EncoderKind::Html),
        (
            "System.Text.Encodings.Web.JavaScriptEncoder",
            EncoderKind::JavaScript,
        ),
        (
            "System.Text.Encodings.Web.UrlEncoder",
            EncoderKind::UrlComponent,
        ),
    ]
    .into_iter()
    .find_map(|(canonical, kind)| {
        razor_type_matches(source, encoder_type, canonical).then_some(kind)
    })
}

fn json_serialization_control(source: &str, expression: &str) -> Option<&'static str> {
    let compact = expression
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let open = compact.find('(')?;
    if matching_parenthesis(&compact, open) != Some(compact.len() - 1) {
        return None;
    }
    let function = &compact[..open];
    if function == "Json.Serialize" {
        let shadowed = source.lines().map(str::trim).any(|line| {
            line.strip_prefix("@inject ")
                .and_then(|inject| {
                    let mut fields = inject.split_whitespace();
                    Some((fields.next()?, fields.next()?))
                })
                .is_some_and(|(kind, name)| {
                    name == "Json"
                        && !matches!(
                            kind,
                            "IJsonHelper" | "Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper"
                        )
                })
        }) || source.contains(" Json {")
            || source.contains(" Json =>");
        return (!shadowed).then_some("aspnet-ijsonhelper");
    }
    let serializer = function.strip_suffix(".Serialize")?;
    if !razor_type_matches(source, serializer, "System.Text.Json.JsonSerializer")
        || compact.contains("UnsafeRelaxedJsonEscaping")
    {
        return None;
    }
    let arguments = &compact[open + 1..compact.len() - 1];
    let parts = split_top_level_arguments(arguments);
    (parts.len() == 1 || parts.len() == 2 && parts[1].starts_with("newJsonSerializerOptions{"))
        .then_some("system-text-json")
}

fn split_top_level_arguments(arguments: &str) -> Vec<&str> {
    let bytes = arguments.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (offset, byte) in bytes.iter().copied().enumerate() {
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
                parts.push(arguments[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    if start < arguments.len() {
        parts.push(arguments[start..].trim());
    }
    parts
}

fn razor_type_matches(source: &str, actual: &str, canonical: &str) -> bool {
    if actual == canonical {
        return true;
    }
    let short = canonical.rsplit('.').next().unwrap_or(canonical);
    let namespace = canonical
        .rsplit_once('.')
        .map_or("", |(namespace, _)| namespace);
    if source.contains(&format!("class {short}")) || source.contains(&format!("struct {short}")) {
        return false;
    }
    for line in source.lines().map(str::trim) {
        if let Some(using) = line.strip_prefix("@using ") {
            let using = using.trim_end_matches(';').trim();
            if using == namespace && actual == short {
                return true;
            }
            if let Some((alias, target)) = using.split_once('=')
                && alias.trim() == actual
                && target.trim() == canonical
            {
                return true;
            }
        }
        if let Some(inject) = line.strip_prefix("@inject ") {
            let mut fields = inject.split_whitespace();
            let (Some(kind), Some(name)) = (fields.next(), fields.next()) else {
                continue;
            };
            if name == actual
                && (kind == canonical
                    || kind == short
                        && source
                            .lines()
                            .map(str::trim)
                            .any(|candidate| candidate == "@using System.Text.Encodings.Web"))
            {
                return true;
            }
        }
    }
    false
}

fn is_plain_string_literal(text: &str) -> bool {
    let text = text.trim();
    !text.starts_with('$')
        && ((text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with("@\"") && text.ends_with('"')))
}

fn razor_comment_ranges(source: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("@*") {
        let start = cursor + relative;
        let end = source[start + 2..]
            .find("*@")
            .map_or(source.len(), |relative| start + 2 + relative + 2);
        ranges.push(start..end);
        cursor = end;
    }
    ranges
}

fn matching_parenthesis(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (offset, byte) in bytes.iter().copied().enumerate().skip(open) {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => depth += 1,
            b')' if depth == 1 => return Some(offset),
            b')' => depth = depth.checked_sub(1)?,
            _ => {}
        }
    }
    None
}

fn trim_range(source: &str, mut range: Range<usize>) -> Range<usize> {
    while range.start < range.end && source.as_bytes()[range.start].is_ascii_whitespace() {
        range.start += 1;
    }
    while range.start < range.end && source.as_bytes()[range.end - 1].is_ascii_whitespace() {
        range.end -= 1;
    }
    range
}

fn location(path: &str, source: &str, range: Range<usize>) -> Location {
    Location {
        path: path.to_string(),
        start: position(source, range.start),
        end: position(source, range.end),
    }
}

fn position(source: &str, offset: usize) -> Position {
    let prefix = &source.as_bytes()[..offset.min(source.len())];
    let line = prefix.iter().filter(|byte| **byte == b'\n').count() + 1;
    let line_start = prefix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| position + 1);
    Position {
        line,
        column: offset.saturating_sub(line_start) + 1,
        byte_offset: offset,
    }
}

fn evidence_id(path: &str, rule_id: &str, range: &Range<usize>) -> String {
    let input = format!("{path}\0{rule_id}\0{}\0{}", range.start, range.end);
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_direct_raw_output_and_ignores_razor_comments() {
        let source = "@Model.Name\n@Html.Raw(Model.Contents)\n@* @Html.Raw(Model.Hidden) *@\n";
        let evidence = scan_escape_hatches("Index.cshtml", source);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].location.start.line, 2);
        assert_eq!(evidence[0].captures["html"].text, "Model.Contents");
    }

    #[test]
    fn finds_direct_blazor_markupstring_output() {
        let source = "@page \"/pages\"\n@((MarkupString)Page.Contents)\n@(new MarkupString(model.Html))\n@* @((MarkupString)Hidden) *@\n@code { var value = new MarkupString(model.Other); }\n";
        let evidence = scan_escape_hatches("Pages/Render.razor", source);
        assert_eq!(evidence.len(), 2);
        assert!(evidence.iter().all(|item| item.kind == EvidenceKind::Sink));
        assert_eq!(evidence[0].captures["html"].text, "Page.Contents");
        assert_eq!(evidence[1].captures["html"].text, "model.Html");
    }
}
