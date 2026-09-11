use std::collections::BTreeMap;
use std::ops::Range;

use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceKind, Location, Position, Provenance,
    Resolution, SecurityPath, SecurityPathProvenance, SecurityPathState, SecurityPathStep,
    SecurityPathStepKind,
};

use super::context::unknown_textual_context;

const ENGINE: &str = "mehscan webforms-inline-output 1";

pub(crate) fn scan_inline_output(path: &str, source: &str) -> (Vec<Evidence>, Vec<SecurityPath>) {
    let comments = comment_ranges(source);
    let mut evidence = Vec::new();
    let mut paths = Vec::new();

    add_request_validation_directives(path, source, &comments, &mut evidence);

    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("<%") {
        let start = cursor + relative;
        if comments.iter().any(|range| range.contains(&start)) {
            cursor = start + 2;
            continue;
        }
        let marker = source.as_bytes().get(start + 2).copied();
        if !matches!(marker, Some(b'=') | Some(b':')) {
            cursor = start + 2;
            continue;
        }
        let Some(relative_end) = source[start + 3..].find("%>") else {
            break;
        };
        let end = start + 3 + relative_end + 2;
        let expression = trim_range(source, start + 3..end - 2);
        cursor = end;
        if expression.is_empty() {
            continue;
        }

        let encoded_marker = marker == Some(b':');
        let text = source[expression.clone()].trim();
        let explicitly_encoded = encoded_marker || has_html_encoder(text);
        if explicitly_encoded || is_string_literal(text) {
            evidence.push(make_evidence(
                path,
                source,
                start..end,
                expression,
                if explicitly_encoded {
                    "csharp-webforms-inline-encoding-control"
                } else {
                    "csharp-webforms-literal-inline-output-control"
                },
                EvidenceKind::Validation,
                if explicitly_encoded {
                    Capability::HtmlEncoding
                } else {
                    Capability::HtmlOutput
                },
                "encoded_value",
                &["webforms", "inline-output", "encoding-control"],
            ));
            continue;
        }

        let sink = make_evidence(
            path,
            source,
            start..end,
            expression.clone(),
            "csharp-webforms-inline-raw-output",
            EvidenceKind::Sink,
            Capability::HtmlOutput,
            "content",
            &[
                "webforms",
                "inline-output",
                "explicit-raw-html",
                "recommendation:review-data-provenance",
            ],
        );
        let request_expression = is_request_expression(text);
        let source_evidence = request_expression.then(|| {
            make_evidence(
                path,
                source,
                expression.clone(),
                expression,
                "csharp-webforms-inline-request-source",
                EvidenceKind::Source,
                Capability::HttpRequestData,
                "value",
                &[
                    "webforms",
                    "request",
                    "attacker-controlled",
                    if text.contains("Request.Unvalidated") {
                        "request-validation-bypass"
                    } else {
                        "request-value"
                    },
                ],
            )
        });
        if let Some(source_evidence) = source_evidence {
            paths.push(direct_path(&source_evidence, &sink));
            evidence.push(source_evidence);
        }
        evidence.push(sink);
    }

    (evidence, paths)
}

fn add_request_validation_directives(
    path: &str,
    source: &str,
    comments: &[Range<usize>],
    evidence: &mut Vec<Evidence>,
) {
    let lower = source.to_ascii_lowercase();
    let mut cursor = 0usize;
    for needle in ["validaterequest=\"false\"", "validaterequest='false'"] {
        while let Some(relative) = lower[cursor..].find(needle) {
            let start = cursor + relative;
            let end = start + needle.len();
            cursor = end;
            if comments.iter().any(|range| range.contains(&start)) {
                continue;
            }
            evidence.push(make_evidence(
                path,
                source,
                start..end,
                start..end,
                "csharp-webforms-request-validation-disabled",
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                "setting",
                &[
                    "webforms",
                    "request-validation",
                    "disabled",
                    "review-output-encoding",
                ],
            ));
        }
        cursor = 0;
    }
}

fn direct_path(source: &Evidence, sink: &Evidence) -> SecurityPath {
    let steps = vec![
        SecurityPathStep {
            kind: SecurityPathStepKind::Source,
            location: source.location.clone(),
            evidence_id: Some(source.id.clone()),
            symbol: None,
        },
        SecurityPathStep {
            kind: SecurityPathStepKind::Sink,
            location: sink.location.clone(),
            evidence_id: Some(sink.id.clone()),
            symbol: None,
        },
    ];
    SecurityPath {
        id: path_id(source, sink, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::HtmlOutput,
        cwe_candidates: vec!["CWE-79".to_string()],
        state: SecurityPathState::Direct,
        steps,
        protection_evidence_ids: Vec::new(),
        uncertainty_reasons: vec!["specialized_webforms_textual_scan".to_string()],
        provenance: SecurityPathProvenance {
            engine: ENGINE.to_string(),
            maximum_propagation_depth: 0,
        },
    }
}

fn path_id(source: &Evidence, sink: &Evidence, steps: &[SecurityPathStep]) -> String {
    let mut input = format!("{}\0{}\0Direct", source.id, sink.id);
    for step in steps {
        input.push_str(&format!(
            "\0{:?}\0{}\0{}",
            step.kind, step.location.start.byte_offset, step.location.end.byte_offset
        ));
    }
    format!("path-{:016x}", fnv(input.as_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn make_evidence(
    path: &str,
    source: &str,
    evidence_range: Range<usize>,
    capture_range: Range<usize>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    role: &str,
    tags: &[&str],
) -> Evidence {
    Evidence {
        id: format!(
            "ev-{:016x}",
            fnv(format!(
                "{path}\0{rule_id}\0{}\0{}",
                evidence_range.start, evidence_range.end
            )
            .as_bytes())
        ),
        kind,
        capability,
        location: location(path, source, evidence_range),
        enclosing_symbol: Some("WebForms template".to_string()),
        captures: BTreeMap::from([(
            role.to_string(),
            Capture {
                text: source[capture_range.clone()].to_string(),
                location: location(path, source, capture_range),
            },
        )]),
        cwe_candidates: vec!["CWE-79".to_string()],
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Textual,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: unknown_textual_context(),
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    }
}

fn location(path: &str, source: &str, range: Range<usize>) -> Location {
    Location {
        path: path.to_string(),
        start: position(source, range.start),
        end: position(source, range.end),
    }
}

fn position(source: &str, offset: usize) -> Position {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len() + 1, |(_, tail)| tail.len() + 1);
    Position {
        line,
        column,
        byte_offset: offset,
    }
}

fn is_request_expression(text: &str) -> bool {
    [
        "Request[",
        "Request.Params[",
        "Request.QueryString[",
        "Request.Form[",
        "Request.Headers[",
        "Request.RawUrl",
        "Request.Unvalidated.",
        "HttpContext.Current.Request.",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn has_html_encoder(text: &str) -> bool {
    [
        "HttpUtility.HtmlEncode(",
        "Server.HtmlEncode(",
        "WebUtility.HtmlEncode(",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn is_string_literal(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with("@\"") && text.ends_with('"'))
}

fn trim_range(source: &str, mut range: Range<usize>) -> Range<usize> {
    while range.start < range.end && source.as_bytes()[range.start].is_ascii_whitespace() {
        range.start += 1;
    }
    while range.end > range.start && source.as_bytes()[range.end - 1].is_ascii_whitespace() {
        range.end -= 1;
    }
    range
}

fn comment_ranges(source: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("<%--") {
        let start = cursor + relative;
        let Some(relative_end) = source[start + 4..].find("--%>") else {
            ranges.push(start..source.len());
            break;
        };
        let end = start + 4 + relative_end + 4;
        ranges.push(start..end);
        cursor = end;
    }
    ranges
}

fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_raw_request_output_from_encoding_and_comments() {
        let source = r#"<%@ Page ValidateRequest="false" %>
<%= Request["name"] %>
<%: Request["encoded"] %>
<%= HttpUtility.HtmlEncode(Request["alsoEncoded"]) %>
<%-- <%= Request["commented"] %> --%>
<%= "literal" %>"#;
        let (evidence, paths) = scan_inline_output("Default.aspx", source);
        assert_eq!(paths.len(), 1);
        assert_eq!(
            evidence
                .iter()
                .filter(|item| item.rule_id == "csharp-webforms-inline-raw-output")
                .count(),
            1
        );
        assert_eq!(
            evidence
                .iter()
                .filter(|item| item.rule_id == "csharp-webforms-inline-encoding-control")
                .count(),
            2
        );
        assert!(
            evidence
                .iter()
                .any(|item| { item.rule_id == "csharp-webforms-request-validation-disabled" })
        );
    }
}
