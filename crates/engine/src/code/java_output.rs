use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, SymbolConfidence, SymbolResolution, SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, enclosing_type_start, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan java-html-template-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_output_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }

    // Replace the name-only declarative Java seeds with framework-identified
    // observations. JSON and other writer uses remain ordinary output unless an
    // HTML media type is syntactically established.
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "java-html-output" | "java-html-encoding"
        )
    });

    let imports = imports(root);
    let declarations = declared_types(root);
    add_servlet_output(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_spring_html_responses(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_encoders(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_template_boundaries(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_servlet_output<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let servlet_response = imported_any_exact(
        imports,
        declarations,
        &[
            "jakarta.servlet.http.HttpServletResponse",
            "javax.servlet.http.HttpServletResponse",
        ],
    );
    let print_writer = imported_exact(imports, declarations, "java.io.PrintWriter", "PrintWriter");
    let jsp_writer = imported_any_exact(
        imports,
        declarations,
        &[
            "jakarta.servlet.jsp.JspWriter",
            "javax.servlet.jsp.JspWriter",
        ],
    );

    for invocation in invocations(root) {
        let Some(operation) = invocation
            .field("name")
            .map(|node| node.text().into_owned())
        else {
            continue;
        };
        if !matches!(operation.as_str(), "write" | "print" | "println" | "append") {
            continue;
        }
        let args = arguments(&invocation);
        let Some(content) = args.first() else {
            continue;
        };
        let Some(object) = invocation.field("object") else {
            continue;
        };

        if jsp_writer && receiver_is_at(&invocation, &object, "JspWriter") {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                "java-jsp-writer-html-output",
                &["CWE-79"],
                &["html", "xss", "jsp", "response-writer", operation.as_str()],
                &[("content", content)],
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }

        if !servlet_response {
            continue;
        }
        let Some(response_name) =
            servlet_response_for_writer(root, &invocation, &object, print_writer)
        else {
            continue;
        };
        if !html_response_context(root, &invocation, &response_name, imports) {
            continue;
        }
        push(
            path,
            &invocation,
            EvidenceKind::Sink,
            Capability::HtmlOutput,
            "java-servlet-html-response-output",
            &["CWE-79"],
            &[
                "html",
                "xss",
                "servlet",
                "response-writer",
                operation.as_str(),
            ],
            &[("content", content)],
            Some(SymbolResolution {
                canonical: format!(
                    "jakarta.servlet.http.HttpServletResponse.getWriter().{operation}"
                ),
                observed: invocation.text().into_owned(),
                method: SymbolResolutionMethod::ImportedNamespace,
                confidence: SymbolConfidence::High,
            }),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn servlet_response_for_writer<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    writer: &Node<'tree, StrDoc<SupportLang>>,
    print_writer: bool,
) -> Option<String> {
    if writer.kind().as_ref() == "method_invocation"
        && writer
            .field("name")
            .is_some_and(|name| name.text().trim() == "getWriter")
        && let Some(response) = writer.field("object")
        && receiver_is_at(use_site, &response, "HttpServletResponse")
    {
        return Some(response.text().trim().to_string());
    }
    if !print_writer || !receiver_is_at(use_site, writer, "PrintWriter") {
        return None;
    }
    let name = writer.text();
    let initializer = initializer_before(root, use_site, name.trim())?;
    if initializer.kind().as_ref() != "method_invocation"
        || initializer
            .field("name")
            .is_none_or(|method| method.text().trim() != "getWriter")
    {
        return None;
    }
    let response = initializer.field("object")?;
    receiver_is_at(use_site, &response, "HttpServletResponse")
        .then(|| response.text().trim().to_string())
}

fn html_response_context(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    response: &str,
    imports: &BTreeSet<String>,
) -> bool {
    if enclosing_method(use_site).is_some_and(|method| method_declares_html(&method, imports)) {
        return true;
    }
    let Some(method) = enclosing_method(use_site) else {
        return false;
    };
    root.dfs().any(|candidate| {
        candidate.kind().as_ref() == "method_invocation"
            && candidate.range().start >= method.range().start
            && candidate.range().start < use_site.range().start
            && candidate
                .field("name")
                .is_some_and(|name| name.text().trim() == "setContentType")
            && candidate
                .field("object")
                .is_some_and(|object| object.text().trim() == response)
            && arguments(&candidate)
                .first()
                .is_some_and(|content_type| html_media_type(content_type.text().as_ref(), imports))
    })
}

#[allow(clippy::too_many_arguments)]
fn add_spring_html_responses<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !imported_exact(
        imports,
        declarations,
        "org.springframework.http.ResponseEntity",
        "ResponseEntity",
    ) {
        return;
    }
    for invocation in invocations(root) {
        if invocation
            .field("name")
            .is_none_or(|name| name.text().trim() != "body")
        {
            continue;
        }
        let args = arguments(&invocation);
        let Some(content) = args.first() else {
            continue;
        };
        let Some(object) = invocation.field("object") else {
            continue;
        };
        let chain = compact(object.text().as_ref());
        if !chain.starts_with("ResponseEntity.")
            && !chain.starts_with("org.springframework.http.ResponseEntity.")
        {
            continue;
        }
        let explicit_html = chain.contains(".contentType(MediaType.TEXT_HTML)")
            || chain.contains(".contentType(org.springframework.http.MediaType.TEXT_HTML)")
            || chain.contains(".contentType(MediaType.TEXT_HTML_VALUE)")
            || chain.contains("\"text/html\"");
        let method_html = enclosing_method(&invocation)
            .is_some_and(|method| method_declares_html(&method, imports));
        if !explicit_html && !method_html {
            continue;
        }
        push(
            path,
            &invocation,
            EvidenceKind::Sink,
            Capability::HtmlOutput,
            "java-spring-responseentity-html-output",
            &["CWE-79"],
            &[
                "html",
                "xss",
                "spring-mvc",
                "response-entity",
                "explicit-media-type",
            ],
            &[("content", content)],
            Some(SymbolResolution {
                canonical: "org.springframework.http.ResponseEntity.BodyBuilder.body".to_string(),
                observed: invocation.text().into_owned(),
                method: SymbolResolutionMethod::ImportedNamespace,
                confidence: SymbolConfidence::High,
            }),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_encoders<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let owasp = imported_exact(imports, declarations, "org.owasp.encoder.Encode", "Encode");
    let spring = imported_exact(
        imports,
        declarations,
        "org.springframework.web.util.HtmlUtils",
        "HtmlUtils",
    );
    let jsoup = imported_exact(imports, declarations, "org.jsoup.Jsoup", "Jsoup")
        && imported_exact(
            imports,
            declarations,
            "org.jsoup.safety.Safelist",
            "Safelist",
        );
    let commons = imported_exact(
        imports,
        declarations,
        "org.apache.commons.text.StringEscapeUtils",
        "StringEscapeUtils",
    );
    for invocation in invocations(root) {
        let Some(operation) = invocation
            .field("name")
            .map(|name| name.text().into_owned())
        else {
            continue;
        };
        let args = arguments(&invocation);
        let Some(value) = args.first() else {
            continue;
        };
        let object = invocation
            .field("object")
            .map(|node| node.text().trim().to_string());
        let (rule, context, canonical) = if owasp
            && object.as_deref() == Some("Encode")
            && matches!(
                operation.as_str(),
                "forHtml"
                    | "forHtmlContent"
                    | "forHtmlAttribute"
                    | "forJavaScript"
                    | "forJavaScriptAttribute"
                    | "forUriComponent"
                    | "forCssString"
                    | "forCssUrl"
            ) {
            (
                "java-owasp-contextual-encoding",
                owasp_context(&operation),
                format!("org.owasp.encoder.Encode.{operation}"),
            )
        } else if spring
            && object.as_deref() == Some("HtmlUtils")
            && matches!(
                operation.as_str(),
                "htmlEscape" | "htmlEscapeDecimal" | "htmlEscapeHex"
            )
        {
            (
                "java-spring-html-text-encoding",
                "html_text",
                format!("org.springframework.web.util.HtmlUtils.{operation}"),
            )
        } else if commons
            && object.as_deref() == Some("StringEscapeUtils")
            && operation == "escapeHtml4"
        {
            (
                "java-commons-html4-encoding",
                "html_text",
                "org.apache.commons.text.StringEscapeUtils.escapeHtml4".to_string(),
            )
        } else if jsoup
            && object.as_deref() == Some("Jsoup")
            && operation == "clean"
            && args.len() >= 2
            && args.iter().skip(1).any(|arg| {
                let text = compact(arg.text().as_ref());
                text.starts_with("Safelist.") || text.starts_with("org.jsoup.safety.Safelist.")
            })
        {
            (
                "java-jsoup-safelist-html-sanitization",
                "html_fragment",
                "org.jsoup.Jsoup.clean".to_string(),
            )
        } else {
            continue;
        };
        push(
            path,
            &invocation,
            EvidenceKind::Sanitizer,
            Capability::HtmlEncoding,
            rule,
            &["CWE-79"],
            &["html", "xss", "output-protection", context],
            &[("value", value)],
            Some(SymbolResolution {
                canonical,
                observed: invocation.text().into_owned(),
                method: SymbolResolutionMethod::ImportedNamespace,
                confidence: SymbolConfidence::High,
            }),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn owasp_context(operation: &str) -> &'static str {
    match operation {
        "forHtml" | "forHtmlContent" => "html_text",
        "forHtmlAttribute" => "html_attribute",
        "forJavaScript" | "forJavaScriptAttribute" => "javascript",
        "forUriComponent" => "url_component",
        "forCssString" | "forCssUrl" => "css",
        _ => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
fn add_template_boundaries<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let thymeleaf = imported_exact(
        imports,
        declarations,
        "org.thymeleaf.TemplateEngine",
        "TemplateEngine",
    );
    let freemarker = imported_exact(
        imports,
        declarations,
        "freemarker.template.Template",
        "Template",
    );
    let velocity = imported_exact(
        imports,
        declarations,
        "org.apache.velocity.app.VelocityEngine",
        "VelocityEngine",
    );
    for invocation in invocations(root) {
        let Some(operation) = invocation
            .field("name")
            .map(|name| name.text().into_owned())
        else {
            continue;
        };
        let Some(object) = invocation.field("object") else {
            continue;
        };
        let args = arguments(&invocation);
        let (rule, tags, captures) = if thymeleaf
            && operation == "process"
            && receiver_is_at(&invocation, &object, "TemplateEngine")
            && !args.is_empty()
        {
            (
                "java-thymeleaf-render-boundary",
                &["html", "template", "thymeleaf", "autoescape-review"][..],
                args.iter()
                    .take(2)
                    .enumerate()
                    .map(|(index, node)| (if index == 0 { "template" } else { "model" }, node))
                    .collect::<Vec<_>>(),
            )
        } else if freemarker
            && operation == "process"
            && receiver_is_at(&invocation, &object, "Template")
            && !args.is_empty()
        {
            (
                "java-freemarker-render-boundary",
                &["html", "template", "freemarker", "autoescape-review"][..],
                args.iter()
                    .take(2)
                    .enumerate()
                    .map(|(index, node)| (if index == 0 { "model" } else { "writer" }, node))
                    .collect::<Vec<_>>(),
            )
        } else if velocity
            && matches!(operation.as_str(), "evaluate" | "mergeTemplate")
            && receiver_is_at(&invocation, &object, "VelocityEngine")
        {
            (
                "java-velocity-render-boundary",
                &["html", "template", "velocity", "autoescape-review"][..],
                args.iter()
                    .take(4)
                    .enumerate()
                    .map(|(index, node)| {
                        (
                            match index {
                                0 => "context",
                                1 => "writer",
                                2 => "template",
                                _ => "encoding",
                            },
                            node,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        } else {
            continue;
        };
        push(
            path,
            &invocation,
            EvidenceKind::SensitiveOperation,
            Capability::HtmlOutput,
            rule,
            &["CWE-79"],
            tags,
            &captures,
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn method_declares_html(
    method: &Node<'_, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
) -> bool {
    let Some(modifiers) = method
        .children()
        .find(|child| child.kind().as_ref() == "modifiers")
    else {
        return false;
    };
    let text = compact(modifiers.text().as_ref());
    let spring_mapping = imports.contains("org.springframework.web.bind.annotation.*")
        || imports.iter().any(|import| {
            import.starts_with("org.springframework.web.bind.annotation.")
                && import.ends_with("Mapping")
        });
    let jaxrs_produces = imports.contains("jakarta.ws.rs.Produces")
        || imports.contains("javax.ws.rs.Produces")
        || imports.contains("jakarta.ws.rs.*")
        || imports.contains("javax.ws.rs.*");
    (spring_mapping
        && text.contains("Mapping")
        && text.contains("produces=")
        && html_media_type(&text, imports))
        || (jaxrs_produces && text.contains("@Produces(") && html_media_type(&text, imports))
}

fn html_media_type(text: &str, imports: &BTreeSet<String>) -> bool {
    let text = compact(text);
    text.contains("\"text/html")
        || text.contains("org.springframework.http.MediaType.TEXT_HTML")
        || text.contains("jakarta.ws.rs.core.MediaType.TEXT_HTML")
        || text.contains("javax.ws.rs.core.MediaType.TEXT_HTML")
        || ((imports.contains("org.springframework.http.MediaType")
            || imports.contains("jakarta.ws.rs.core.MediaType")
            || imports.contains("javax.ws.rs.core.MediaType"))
            && text.contains("MediaType.TEXT_HTML"))
}

fn enclosing_method<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
}

fn initializer_before<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let method = enclosing_method(use_site)?;
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && node.range().start >= method.range().start
                && node.range().start < use_site.range().start
                && node
                    .field("name")
                    .is_some_and(|candidate| candidate.text().trim() == name)
        })
        .filter_map(|node| node.field("value"))
        .last()
}

fn receiver_is_at(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    expected: &str,
) -> bool {
    let name_text = receiver.text();
    let name = name_text.trim();
    let Some(scope) = enclosing_method(use_site) else {
        return false;
    };
    let mut found = None;
    for node in scope
        .dfs()
        .filter(|node| node.range().start <= use_site.range().start)
    {
        if matches!(node.kind().as_ref(), "parameter" | "formal_parameter")
            && node
                .field("name")
                .is_some_and(|candidate| candidate.text().trim() == name)
            && let Some(kind) = node.field("type")
        {
            found = Some(kind.text().into_owned());
        }
        if node.kind().as_ref() == "local_variable_declaration"
            && lexical_declaration_visible_at(&node, use_site)
            && node.children().any(|child| {
                child.kind().as_ref() == "variable_declarator"
                    && child
                        .field("name")
                        .is_some_and(|candidate| candidate.text().trim() == name)
            })
            && let Some(kind) = node.field("type")
        {
            found = Some(kind.text().into_owned());
        }
    }
    if found.is_some_and(|kind| short_type(&kind) == expected) {
        return true;
    }
    let use_owner = enclosing_type_start(use_site);
    use_site.ancestors().last().is_some_and(|root| {
        root.dfs().any(|node| {
            node.kind().as_ref() == "field_declaration"
                && enclosing_type_start(&node) == use_owner
                && node
                    .field("type")
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
                && node.children().any(|child| {
                    child.kind().as_ref() == "variable_declarator"
                        && child
                            .field("name")
                            .is_some_and(|candidate| candidate.text().trim() == name)
                })
        })
    })
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> impl Iterator<Item = Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
}

fn arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .map(|import| {
            import
                .text()
                .trim()
                .trim_start_matches("import ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .to_string()
        })
        .collect()
}

fn declared_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
                    | "annotation_type_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .collect()
}

fn imported_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonical: &str,
    short: &str,
) -> bool {
    let namespace = canonical
        .rsplit_once('.')
        .map(|(namespace, _)| namespace)
        .unwrap_or_default();
    !declarations.contains(short)
        && (imports.contains(canonical) || imports.contains(&format!("{namespace}.*")))
}

fn imported_any_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonicals: &[&str],
) -> bool {
    canonicals
        .iter()
        .any(|canonical| imported_exact(imports, declarations, canonical, short_type(canonical)))
}

fn short_type(kind: &str) -> &str {
    kind.trim()
        .rsplit('.')
        .next()
        .unwrap_or(kind.trim())
        .split('<')
        .next()
        .unwrap_or(kind.trim())
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
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    captures: &[(&str, &Node<'tree, StrDoc<SupportLang>>)],
    symbol_resolution: Option<SymbolResolution>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    );
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
    let mut literal_values = BTreeMap::new();
    let captures = captures
        .iter()
        .map(|(role, capture)| {
            literal_values.insert((*role).to_string(), literals.evaluate(capture));
            (
                (*role).to_string(),
                Capture {
                    text: capture.text().into_owned(),
                    location: location(path, capture),
                },
            )
        })
        .collect();
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: literal_values,
            ..EvidenceContext::default()
        },
        symbol_resolution,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let range = node.range();
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: range.start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: range.end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}
