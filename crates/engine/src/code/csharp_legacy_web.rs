use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan csharp legacy-web-and-cookie-trust 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_legacy_web_observations<'tree>(
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
    add_webforms_request_values(path, root, comments, conditional, literals, evidence);
    add_request_validation_policy(path, root, comments, conditional, literals, evidence);
    add_webforms_script_includes(path, root, comments, conditional, literals, evidence);
    add_webforms_upload_content(path, root, comments, conditional, literals, evidence);
    add_unverified_sso_cookie_identity(path, root, comments, conditional, literals, evidence);
}

#[allow(clippy::too_many_arguments)]
fn add_webforms_request_values<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !has_exact_using(root, "System.Web") {
        return;
    }
    for access in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "element_access_expression" | "element_access"
        )
    }) {
        let text = compact(access.text().as_ref());
        if !(text.starts_with("Request[")
            || text.starts_with("Request.Params[")
            || text.starts_with("Request.QueryString[")
            || text.starts_with("Request.Form[")
            || text.starts_with("Request.Cookies[")
            || text.starts_with("HttpContext.Current.Request.Params[")
            || text.starts_with("HttpContext.Current.Request.QueryString[")
            || text.starts_with("HttpContext.Current.Request.Form[")
            || text.starts_with("HttpContext.Current.Request.Cookies["))
            && !text.starts_with("Request.Unvalidated.")
        {
            continue;
        }
        push(
            path,
            &access,
            &access,
            EvidenceKind::Source,
            Capability::HttpRequestData,
            "csharp-webforms-request-data",
            "value",
            &["CWE-20"],
            &["aspnet", "webforms", "request", "attacker-controlled"],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_request_validation_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !has_exact_using(root, "System.Web.Mvc")
        || declares_type(root, "ValidateInputAttribute")
        || declares_type(root, "AllowHtmlAttribute")
    {
        return;
    }
    for attribute in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "attribute")
    {
        let text = compact(attribute.text().as_ref());
        let rule_id = if text == "ValidateInput(false)" {
            "csharp-mvc-request-validation-disabled"
        } else if text == "AllowHtml" || text == "AllowHtmlAttribute" {
            "csharp-mvc-property-request-validation-bypass"
        } else {
            continue;
        };
        push(
            path,
            &attribute,
            &attribute,
            EvidenceKind::SecurityConfiguration,
            Capability::HttpRequestHandling,
            rule_id,
            "setting",
            &["CWE-20", "CWE-79"],
            &[
                "aspnet-mvc",
                "request-validation",
                "bypass",
                "review-output-encoding",
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_webforms_script_includes<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !has_exact_using(root, "System.Web.UI") || declares_type(root, "ClientScriptManager") {
        return;
    }
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function = compact(function.text().as_ref());
        if !function.ends_with(".RegisterClientScriptInclude")
            || !(function.starts_with("Page.ClientScript.")
                || function.starts_with("ClientScript.")
                || typed_receiver(root, &invocation, &function, "ClientScriptManager"))
        {
            continue;
        }
        let arguments = arguments(&invocation);
        let Some(url) = arguments.last() else {
            continue;
        };
        push(
            path,
            &invocation,
            url,
            EvidenceKind::Sink,
            Capability::HtmlOutput,
            "csharp-webforms-client-script-include",
            "content",
            &["CWE-79", "CWE-829"],
            &["webforms", "html", "script", "remote-script-include"],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_webforms_upload_content<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !has_exact_using(root, "System.Web") {
        return;
    }
    let webforms_page =
        has_webforms_page(root) && has_exact_using(root, "System.Web.UI.WebControls");
    for member in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "member_access_expression")
    {
        let text = compact(member.text().as_ref());
        let exact_collection = matches!(
            text.as_str(),
            "Request.Files" | "HttpContext.Current.Request.Files"
        );
        let property = member
            .field("name")
            .map(|name| name.text().trim().to_string());
        let receiver = member.field("expression");
        let typed_posted_file = receiver.as_ref().is_some_and(|receiver| {
            variable_has_type(
                root,
                &member,
                receiver.text().trim(),
                &["HttpPostedFile", "HttpPostedFileBase"],
            )
        });
        let posted_file_chain = receiver
            .as_ref()
            .is_some_and(|receiver| compact(receiver.text().as_ref()).ends_with(".PostedFile"));
        let exact_stream = property.as_deref() == Some("InputStream") && typed_posted_file;
        let exact_content =
            matches!(property.as_deref(), Some("FileBytes") | Some("FileContent")) && webforms_page;
        let exact_filename = property.as_deref() == Some("FileName")
            && (typed_posted_file || (webforms_page && posted_file_chain));
        if !exact_collection && !exact_stream && !exact_content && !exact_filename {
            continue;
        }
        push(
            path,
            &member,
            &member,
            EvidenceKind::Source,
            if exact_filename {
                Capability::UploadedFilePath
            } else {
                Capability::UploadedFileContent
            },
            if exact_filename {
                "csharp-webforms-uploaded-filename"
            } else if exact_stream {
                "csharp-webforms-upload-stream"
            } else if exact_content {
                "csharp-webforms-upload-content"
            } else {
                "csharp-webforms-request-files"
            },
            if exact_filename { "path" } else { "content" },
            if exact_filename {
                &["CWE-434", "CWE-22"]
            } else {
                &["CWE-434"]
            },
            if exact_filename {
                &["webforms", "upload", "attacker-controlled", "filename"]
            } else {
                &["webforms", "upload", "attacker-controlled", "content"]
            },
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        let args = arguments(&invocation);
        let save_as = function_text.ends_with(".SaveAs")
            && args.len() == 1
            && function.field("expression").is_some_and(|receiver| {
                let receiver_text = compact(receiver.text().as_ref());
                receiver_text.ends_with(".PostedFile")
                    || variable_has_type(
                        root,
                        &invocation,
                        receiver.text().trim(),
                        &["HttpPostedFile", "HttpPostedFileBase"],
                    )
            });
        let file_write = matches!(
            function_text.as_str(),
            "File.WriteAllBytes"
                | "File.WriteAllText"
                | "System.IO.File.WriteAllBytes"
                | "System.IO.File.WriteAllText"
        ) && args.len() >= 2
            && webforms_page;
        if !save_as && !file_write {
            continue;
        }
        let content = if save_as {
            function.field("expression").expect("SaveAs receiver")
        } else {
            args[1].clone()
        };
        let destination = &args[0];
        if save_as
            && !evidence.iter().any(|item| {
                item.capability == Capability::UploadedFileContent
                    && item.location.start.byte_offset == content.range().start
                    && item.location.end.byte_offset == content.range().end
            })
        {
            push(
                path,
                &content,
                &content,
                EvidenceKind::Source,
                Capability::UploadedFileContent,
                "csharp-webforms-posted-file-content",
                "content",
                &["CWE-434"],
                &["webforms", "upload", "attacker-controlled", "content"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        push(
            path,
            &invocation,
            &content,
            EvidenceKind::Sink,
            Capability::FileUpload,
            if save_as {
                "csharp-webforms-posted-file-save"
            } else {
                "csharp-webforms-upload-file-write"
            },
            "content",
            &["CWE-434"],
            &["webforms", "upload", "file-storage"],
            comments,
            conditional,
            literals,
            evidence,
        );
        if let Some(sink) = evidence.last_mut() {
            sink.captures.insert(
                "destination".to_string(),
                Capture {
                    text: destination.text().into_owned(),
                    location: location(path, destination),
                },
            );
        }
    }
}

fn has_webforms_page(root: &Node<'_, StrDoc<SupportLang>>) -> bool {
    root.dfs().any(|node| {
        node.kind().as_ref() == "class_declaration"
            && node
                .children()
                .find(|child| child.kind().as_ref() == "base_list")
                .is_some_and(|bases| {
                    let text = compact(bases.text().as_ref());
                    text == ":Page" || text.contains("System.Web.UI.Page")
                })
    })
}

#[allow(clippy::too_many_arguments)]
fn add_unverified_sso_cookie_identity<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let method_text = compact(method.text().as_ref());
        if has_cookie_integrity_protection(&method_text) {
            continue;
        }
        let declarations = method
            .dfs()
            .filter(|node| node.kind().as_ref() == "variable_declarator")
            .collect::<Vec<_>>();
        let Some((cookie_name, _cookie_access)) = declarations.iter().find_map(|declaration| {
            let name = declaration.field("name")?;
            let value = initializer(declaration)?;
            let text = compact(value.text().as_ref());
            (text.starts_with("HttpContext.Request.Cookies[")
                || text.starts_with("Request.Cookies[")
                || text.starts_with("HttpContext.Current.Request.Cookies["))
            .then_some((name.text().trim().to_string(), value))
        }) else {
            continue;
        };
        let Some((decoded_name, _)) = declarations.iter().find_map(|declaration| {
            let name = declaration.field("name")?;
            let value = initializer(declaration)?;
            (compact(value.text().as_ref()) == format!("Convert.FromBase64String({cookie_name})"))
                .then_some((name.text().trim().to_string(), value))
        }) else {
            continue;
        };
        let Some((json_name, _)) = declarations.iter().find_map(|declaration| {
            let name = declaration.field("name")?;
            let value = initializer(declaration)?;
            let text = compact(value.text().as_ref());
            (text.starts_with("JObject.Parse(") && text.contains(&decoded_name))
                .then_some((name.text().trim().to_string(), value))
        }) else {
            continue;
        };
        let Some((identity, identity_name)) = declarations.iter().find_map(|declaration| {
            let name = declaration.field("name")?;
            let value = initializer(declaration)?;
            let text = compact(value.text().as_ref());
            let identity_name = name.text().trim().to_string();
            (text == format!("{json_name}[\"auth_user\"]")
                || text == format!("{json_name}[\"user_id\"]")
                || text == format!("{json_name}[\"sub\"]"))
            .then_some((name, identity_name))
        }) else {
            continue;
        };
        let Some(token_issuer) = invocations(&method).into_iter().find(|invocation| {
            invocation.range().start > identity.range().end
                && invocation.field("function").is_some_and(|function| {
                    compact(function.text().as_ref()).ends_with(".createAccessToken")
                        || compact(function.text().as_ref()).ends_with(".CreateAccessToken")
                        || compact(function.text().as_ref()).ends_with(".GenerateToken")
                })
        }) else {
            continue;
        };
        if !method_text.contains(&identity_name) {
            continue;
        }
        push(
            path,
            &identity,
            &identity,
            EvidenceKind::Source,
            Capability::HttpRequestData,
            "csharp-sso-cookie-identity-source",
            "value",
            &["CWE-20", "CWE-345"],
            &[
                "cookie",
                "sso",
                "identity",
                "unsigned",
                "attacker-controlled",
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
        let source_id = evidence_id(
            path,
            "csharp-sso-cookie-identity-source",
            identity.range().start,
            identity.range().end,
        );
        push(
            path,
            &token_issuer,
            &identity,
            EvidenceKind::Sink,
            Capability::Authentication,
            "csharp-unverified-sso-cookie-token-issuance",
            "unverified_token",
            &["CWE-345"],
            &[
                "cookie",
                "sso",
                "identity",
                "token-issuance",
                "no-integrity-proof",
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
        if let Some(sink) = evidence.last_mut() {
            sink.related_evidence = vec![source_id];
            sink.provenance.engine =
                "mehscan csharp cookie identity bounded-node-identity-boundary".to_string();
        }
    }
}

fn has_cookie_integrity_protection(method: &str) -> bool {
    [
        ".Unprotect(",
        ".UnprotectAsync(",
        "MachineKey.Unprotect(",
        "ValidateToken(",
        "JwtSecurityTokenHandler",
        "HMACSHA",
        "VerifyData(",
    ]
    .iter()
    .any(|marker| method.contains(marker))
}

fn typed_receiver(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    function: &str,
    expected: &str,
) -> bool {
    let Some(receiver) = function.strip_suffix(".RegisterClientScriptInclude") else {
        return false;
    };
    variable_has_type(root, use_site, receiver, &[expected])
}

fn variable_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
    expected: &[&str],
) -> bool {
    root.dfs().any(|node| {
        if node.range().start >= use_site.range().start
            || node
                .field("name")
                .is_none_or(|field| field.text().trim() != name)
        {
            return false;
        }
        let declared_type = match node.kind().as_ref() {
            "variable_declarator" => node.parent().and_then(|parent| parent.field("type")),
            "parameter" => node.field("type"),
            _ => None,
        };
        declared_type.is_some_and(|kind| {
            let compact_type = compact(kind.text().as_ref());
            let observed = terminal_type(&compact_type);
            expected.contains(&observed)
        })
    })
}

fn initializer<'tree>(
    declaration: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    declaration.field("value").or_else(|| {
        declaration
            .children()
            .filter(|child| child.is_named())
            .last()
    })
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
        .collect()
}

fn arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .collect()
        })
        .unwrap_or_default()
}

fn has_exact_using(root: &Node<'_, StrDoc<SupportLang>>, namespace: &str) -> bool {
    let expected = format!("using{namespace};");
    root.dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .any(|node| compact(node.text().as_ref()) == expected)
}

fn declares_type(root: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == expected)
    })
}

fn terminal_type(observed: &str) -> &str {
    observed.rsplit('.').next().unwrap_or(observed)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::from([(
            role.to_string(),
            Capture {
                text: value.text().into_owned(),
                location: location(path, value),
            },
        )]),
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: BTreeMap::from([(role.to_string(), literals.evaluate(value))]),
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
