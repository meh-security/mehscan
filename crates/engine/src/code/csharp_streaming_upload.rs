use std::collections::BTreeMap;
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;

const MULTIPART_READER: &str = "Microsoft.AspNetCore.WebUtilities.MultipartReader";
const CONTENT_DISPOSITION: &str = "Microsoft.Net.Http.Headers.ContentDispositionHeaderValue";
const FILE_STREAM: &str = "System.IO.FileStream";
const HTTP_REQUEST: &str = "Microsoft.AspNetCore.Http.HttpRequest";
const ENGINE: &str = "mehscan bounded-csharp-streaming-upload 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_streaming_upload_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "csharp-multipart-section-body"
                | "csharp-multipart-content-disposition-filename"
                | "csharp-streamed-upload-file-copy"
        )
    });

    for member in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "member_access_expression")
    {
        if comments.is_in_comment(member.range()) {
            continue;
        }
        let text = compact(member.text().as_ref());
        if request_body_member(root, &member, &text) {
            push(
                path,
                &member,
                EvidenceKind::Source,
                Capability::HttpRequestData,
                "csharp-http-request-body-stream",
                &["CWE-20"],
                &["http", "request-body", "stream", "attacker-controlled"],
                [("value", &member)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        let Some((section, property)) = member_receiver_property(&member) else {
            continue;
        };
        if property == "Body" && section_is_multipart(root, &member, &section) {
            push(
                path,
                &member,
                EvidenceKind::Source,
                Capability::UploadedFileContent,
                "csharp-multipart-section-body",
                &["CWE-434"],
                &["http", "multipart", "streaming", "upload", "content"],
                [("content", &member)],
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }

        if property == "Value"
            && let Some(filename_member) = member.field("expression")
            && filename_member.kind().as_ref() == "member_access_expression"
            && filename_member
                .field("name")
                .is_some_and(|name| matches!(name.text().trim(), "FileName" | "FileNameStar"))
            && let Some(disposition) = filename_member.field("expression")
            && disposition_is_from_multipart(root, &member, disposition.text().trim())
        {
            push(
                path,
                &member,
                EvidenceKind::Source,
                Capability::UploadedFilePath,
                "csharp-multipart-content-disposition-filename",
                &["CWE-434", "CWE-22"],
                &[
                    "http",
                    "multipart",
                    "upload",
                    "filename",
                    "attacker-controlled",
                ],
                [("path", &member)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if function.kind().as_ref() != "member_access_expression"
            || function
                .field("name")
                .is_none_or(|name| !matches!(name.text().trim(), "CopyTo" | "CopyToAsync"))
        {
            continue;
        }
        let Some(content) = function.field("expression") else {
            continue;
        };
        let content_text = compact(content.text().as_ref());
        let multipart_content = content_text
            .strip_suffix(".Body")
            .is_some_and(|section| section_is_multipart(root, &invocation, section));
        let request_content = request_body_member(root, &content, &content_text);
        let Some(arguments) = invocation_arguments(&invocation) else {
            continue;
        };
        if arguments.is_empty()
            || (!multipart_content && !request_content)
            || !file_backed_destination(root, &invocation, &arguments[0])
        {
            continue;
        }
        push(
            path,
            &invocation,
            EvidenceKind::Sink,
            Capability::FileUpload,
            "csharp-streamed-upload-file-copy",
            &["CWE-434"],
            &["http", "multipart", "streaming", "upload", "file-storage"],
            [("content", &content), ("destination", &arguments[0])],
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        let Some(left) = assignment.field("left") else {
            continue;
        };
        let Some(right) = assignment.field("right") else {
            continue;
        };
        let left_text = compact(left.text().as_ref());
        let Some((reader, property)) = left_text.rsplit_once('.') else {
            continue;
        };
        if !matches!(
            property,
            "BodyLengthLimit" | "HeadersCountLimit" | "HeadersLengthLimit"
        ) || !reader_is_multipart(root, &assignment, reader)
        {
            continue;
        }
        push(
            path,
            &assignment,
            EvidenceKind::SecurityConfiguration,
            Capability::FileUpload,
            "csharp-multipart-reader-limit",
            &["CWE-400", "CWE-434"],
            &["http", "multipart", "streaming", "limit", "review-context"],
            [("reader", &left), ("limit", &right)],
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for attribute in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "attribute")
    {
        let text = compact(attribute.text().as_ref());
        if !(text.starts_with("RequestSizeLimit(")
            || (text.starts_with("RequestFormLimits(")
                && text.contains("MultipartBodyLengthLimit=")))
        {
            continue;
        }
        push(
            path,
            &attribute,
            EvidenceKind::SecurityConfiguration,
            Capability::FileUpload,
            "csharp-request-upload-size-limit",
            &["CWE-400", "CWE-434"],
            &["http", "upload", "request-limit", "review-context"],
            [("limit", &attribute)],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn request_body_member(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    text: &str,
) -> bool {
    if matches!(
        text,
        "Request.Body"
            | "Request.BodyReader"
            | "HttpContext.Request.Body"
            | "HttpContext.Request.BodyReader"
    ) {
        return enclosing_controller(root, use_site);
    }
    let Some((receiver, property)) = text.rsplit_once('.') else {
        return false;
    };
    matches!(property, "Body" | "BodyReader")
        && simple_identifier(receiver).is_some()
        && receiver_has_type(root, use_site, receiver, HTTP_REQUEST)
}

fn enclosing_controller(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(class) = use_site
        .ancestors()
        .find(|node| node.kind().as_ref() == "class_declaration")
    else {
        return false;
    };
    class.dfs().any(|node| {
        node.kind().as_ref() == "base_list"
            && ["Controller", "ControllerBase"]
                .iter()
                .any(|base| compact(node.text().as_ref()).contains(base))
    }) || class.text().contains("[ApiController]")
        || root.text().contains("using Microsoft.AspNetCore.Mvc;")
            && class.text().contains("Controller")
}

fn section_is_multipart(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    section: &str,
) -> bool {
    let Some(section) = simple_identifier(section) else {
        return false;
    };
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        if scope.start > node.range().start
            || node.range().end > scope.end
            || node.range().start >= use_site.range().start
        {
            return false;
        }
        let matches_binding = (node.kind().as_ref() == "variable_declarator"
            && node
                .field("name")
                .is_some_and(|name| name.text().trim() == section))
            || (node.kind().as_ref() == "assignment_expression"
                && node
                    .field("left")
                    .is_some_and(|left| left.text().trim() == section));
        if !matches_binding {
            return false;
        }
        let value = compact(node.text().as_ref());
        value.contains(".ReadNextSectionAsync(")
            && value
                .split(".ReadNextSectionAsync(")
                .next()
                .and_then(|prefix| prefix.rsplit(['=', '(']).next())
                .map(|reader| reader.trim_start_matches("await"))
                .is_some_and(|reader| reader_is_multipart(root, &node, reader))
    })
}

fn reader_is_multipart(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    reader: &str,
) -> bool {
    let Some(reader) = simple_identifier(reader) else {
        return false;
    };
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        node.kind().as_ref() == "variable_declarator"
            && scope.start <= node.range().start
            && node.range().end <= scope.end
            && node.range().start < use_site.range().start
            && node
                .field("name")
                .is_some_and(|name| name.text().trim() == reader)
            && node.dfs().any(|creation| {
                creation.kind().as_ref() == "object_creation_expression"
                    && creation
                        .field("type")
                        .is_some_and(|kind| type_is(root, kind.text().as_ref(), MULTIPART_READER))
                    && invocation_arguments(&creation).is_some_and(|arguments| {
                        arguments.len() >= 2
                            && matches!(
                                compact(arguments[1].text().as_ref()).as_str(),
                                "Request.Body" | "HttpContext.Request.Body"
                            )
                    })
            })
    })
}

fn disposition_is_from_multipart(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    disposition: &str,
) -> bool {
    let Some(disposition) = simple_identifier(disposition) else {
        return false;
    };
    let scope = scope_range(use_site, root);
    root.dfs().any(|invocation| {
        if invocation.kind().as_ref() != "invocation_expression"
            || scope.start > invocation.range().start
            || invocation.range().end > scope.end
            || invocation.range().start >= use_site.range().start
        {
            return false;
        }
        let Some(function) = invocation.field("function") else {
            return false;
        };
        let function = compact(function.text().as_ref());
        let Some(receiver) = function.strip_suffix(".TryParse") else {
            return false;
        };
        if !type_is(root, receiver, CONTENT_DISPOSITION) {
            return false;
        }
        invocation_arguments(&invocation).is_some_and(|arguments| {
            arguments.len() >= 2
                && compact(arguments[0].text().as_ref()).ends_with(".ContentDisposition")
                && out_argument_identifier(arguments[1].text().as_ref()) == Some(disposition)
                && compact(arguments[0].text().as_ref())
                    .strip_suffix(".ContentDisposition")
                    .is_some_and(|section| section_is_multipart(root, &invocation, section))
        })
    })
}

fn out_argument_identifier(text: &str) -> Option<&str> {
    let text = text.trim();
    text.strip_prefix("out var ")
        .or_else(|| text.strip_prefix("out "))
        .or_else(|| text.strip_prefix("var "))
        .or_else(|| simple_identifier(text))
        .and_then(simple_identifier)
}

fn file_backed_destination<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    destination: &Node<'tree, StrDoc<SupportLang>>,
) -> bool {
    if destination.kind().as_ref() == "object_creation_expression" {
        return destination
            .field("type")
            .is_some_and(|kind| type_is(root, kind.text().as_ref(), FILE_STREAM));
    }
    let text = compact(destination.text().as_ref());
    if text.starts_with("File.Create(") || text.starts_with("System.IO.File.Create(") {
        return true;
    }
    let Some(name) = simple_identifier(&text) else {
        return false;
    };
    receiver_has_type(root, use_site, name, FILE_STREAM)
        || prior_declarator(root, use_site, name).is_some_and(|declaration| {
            let text = compact(declaration.text().as_ref());
            text.contains("=File.Create(") || text.contains("=System.IO.File.Create(")
        })
}

fn receiver_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    canonical: &str,
) -> bool {
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        node.range().start < use_site.range().start
            && scope.start <= node.range().start
            && node.range().end <= scope.end
            && ((node.kind().as_ref() == "parameter"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == receiver)
                && node
                    .field("type")
                    .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical)))
                || (node.kind().as_ref() == "variable_declarator"
                    && lexical_declaration_visible_at(&node, use_site)
                    && node
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver)
                    && node
                        .parent()
                        .and_then(|parent| parent.field("type"))
                        .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical))))
    })
}

fn prior_declarator<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let scope = scope_range(use_site, root);
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && lexical_declaration_visible_at(node, use_site)
                && scope.start <= node.range().start
                && node.range().end <= scope.end
                && node.range().start < use_site.range().start
                && node
                    .field("name")
                    .is_some_and(|candidate| candidate.text().trim() == name)
        })
        .last()
}

fn member_receiver_property(member: &Node<'_, StrDoc<SupportLang>>) -> Option<(String, String)> {
    Some((
        compact(member.field("expression")?.text().as_ref()),
        member.field("name")?.text().trim().to_string(),
    ))
}

fn type_is(root: &Node<'_, StrDoc<SupportLang>>, actual: &str, canonical: &str) -> bool {
    let actual = compact(actual);
    if actual == canonical {
        return true;
    }
    let (namespace, short) = canonical.rsplit_once('.').unwrap_or(("", canonical));
    let shadowed = root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == short)
    });
    for directive in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .map(|node| compact(node.text().as_ref()))
    {
        let directive = directive
            .strip_prefix("globalusing")
            .or_else(|| directive.strip_prefix("using"))
            .unwrap_or(&directive)
            .trim_end_matches(';');
        if let Some((alias, target)) = directive.split_once('=') {
            if (target == canonical && actual == alias)
                || (target == namespace && actual == format!("{alias}.{short}"))
            {
                return true;
            }
        } else if directive == namespace && actual == short && !shadowed {
            return true;
        }
    }
    false
}

fn invocation_arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Vec<Node<'tree, StrDoc<SupportLang>>>> {
    Some(
        node.field("arguments")?
            .children()
            .filter(|child| child.is_named())
            .map(|argument| {
                if argument.kind().as_ref() == "argument" {
                    argument
                        .children()
                        .filter(|child| child.is_named())
                        .last()
                        .unwrap_or(argument)
                } else {
                    argument
                }
            })
            .collect(),
    )
}

fn scope_range(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "method_declaration"
                    | "constructor_declaration"
                    | "local_function_statement"
                    | "lambda_expression"
                    | "anonymous_method_expression"
            )
        })
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_alphabetic())
        || !characters.all(|character| character == '_' || character.is_alphanumeric())
    {
        return None;
    }
    Some(text)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree, const N: usize>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    captures: [(&str, &Node<'tree, StrDoc<SupportLang>>); N],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let mut literal_values = BTreeMap::new();
    let captures = captures
        .into_iter()
        .map(|(role, capture)| {
            literal_values.insert(role.to_string(), literals.evaluate(capture));
            (
                role.to_string(),
                Capture {
                    text: capture.text().into_owned(),
                    location: location(path, capture),
                },
            )
        })
        .collect();
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: if kind == EvidenceKind::SecurityConfiguration {
            Confidence::Medium
        } else {
            Confidence::High
        },
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: literal_values,
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
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
    }
}

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let hash = input.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    format!("ev-{hash:016x}")
}
