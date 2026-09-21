use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language,
    LiteralState, Location, Position, Provenance, Resolution, SymbolConfidence, SymbolResolution,
    SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const BROWSER_ENGINE: &str = "ast-grep 0.45.1 + bounded-browser-boundary";

pub(crate) fn accepts_angular_trust_bypass(
    root: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let sanitizer_types =
        imported_named_bindings(root, &["@angular/platform-browser"], "DomSanitizer");
    if sanitizer_types.is_empty() {
        return false;
    }
    let receiver = normalized(&receiver.text());
    let name = receiver.rsplit('.').next().unwrap_or(&receiver);
    let source = normalized(&root.text());
    sanitizer_types.iter().any(|sanitizer_type| {
        source.contains(&format!("{name}:{sanitizer_type}"))
            || source.contains(&format!("{name}=inject({sanitizer_type})"))
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_browser_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        return;
    }

    let shadowed_globals = shadowed_browser_globals(root);
    let message_data = message_data_ranges(root, &shadowed_globals);
    let socket_data = socket_data_ranges(root);
    let response_data = fetch_response_data_ranges(root);
    let dom_bindings = dom_bindings(root, &shadowed_globals);
    let react_refs = react_ref_targets(root);
    let react_factories = react_factories(root);
    let lit_unsafe_html = imported_named_bindings(
        root,
        &[
            "lit/directives/unsafe-html.js",
            "lit-html/directives/unsafe-html.js",
        ],
        "unsafeHTML",
    );
    let vue_factories = imported_named_bindings(root, &["vue"], "h");
    let jquery_factories = imported_default_or_required_bindings(root, &["jquery"]);
    let solid_runtime = imports_module(root, "solid-js");
    let react_state = untrusted_react_state_fields(root, &response_data);

    for node in root.dfs() {
        let kind = node.kind();
        let kind = kind.as_ref();
        if matches!(kind, "member_expression" | "subscript_expression")
            && !is_assignment_target(&node)
        {
            let observed = normalized(&node.text());
            if let Some(source_kind) = browser_member_source(&observed, &shadowed_globals) {
                push_observation(
                    path,
                    language,
                    &node,
                    &node,
                    EvidenceKind::Source,
                    Capability::BrowserInput,
                    &format!("{}-browser-{source_kind}-source", language_prefix(language)),
                    "value",
                    &observed,
                    &["browser", "trust-boundary", source_kind],
                    Confidence::Medium,
                    "browser input expression",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if message_data.contains(&node.range().start) {
                push_observation(
                    path,
                    language,
                    &node,
                    &node,
                    EvidenceKind::Source,
                    Capability::BrowserInput,
                    &format!("{}-browser-message-source", language_prefix(language)),
                    "value",
                    &observed,
                    &["browser", "postmessage", "cross-origin-input"],
                    Confidence::Medium,
                    "MessageEvent.data",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if socket_data.contains(&node.range().start) {
                push_observation(
                    path,
                    language,
                    &node,
                    &node,
                    EvidenceKind::Source,
                    Capability::BrowserInput,
                    &format!(
                        "{}-browser-socket-message-source",
                        language_prefix(language)
                    ),
                    "value",
                    &observed,
                    &["browser", "websocket", "socket-event", "remote-message"],
                    Confidence::Medium,
                    "Socket event payload",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if response_data.contains(&node.range().start) {
                push_observation(
                    path,
                    language,
                    &node,
                    &node,
                    EvidenceKind::Source,
                    Capability::BrowserInput,
                    &format!("{}-browser-http-response-source", language_prefix(language)),
                    "value",
                    &observed,
                    &["browser", "http-response", "remote-data"],
                    Confidence::Medium,
                    "fetch response data",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if react_state.contains(&observed) {
                push_observation(
                    path,
                    language,
                    &node,
                    &node,
                    EvidenceKind::Source,
                    Capability::BrowserInput,
                    &format!("{}-react-response-state-source", language_prefix(language)),
                    "value",
                    &observed,
                    &["browser", "react", "state", "http-response"],
                    Confidence::Medium,
                    "React state derived from fetch response",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if kind == "string" && node.text().contains("MEHSCAN_TOKEN") {
            let before = evidence.len();
            push_observation(
                path,
                language,
                &node,
                &node,
                EvidenceKind::Source,
                Capability::CredentialMaterial,
                &format!(
                    "{}-ejs-credential-material-source",
                    language_prefix(language)
                ),
                "value",
                "EJS apiToken",
                &["browser", "ejs", "credential", "template-value"],
                Confidence::High,
                "EJS credential template value",
                comments,
                conditional,
                literals,
                evidence,
            );
            if evidence.len() > before
                && let Some(value) = evidence
                    .last_mut()
                    .and_then(|item| item.captures.get_mut("value"))
            {
                value.text = "<%-apiToken%>".to_string();
            }
        }

        if kind == "call_expression" {
            if let Some((source_kind, value)) = storage_source(&node, &shadowed_globals) {
                push_observation(
                    path,
                    language,
                    &node,
                    &value,
                    EvidenceKind::Source,
                    Capability::BrowserInput,
                    &format!("{}-browser-storage-source", language_prefix(language)),
                    "value",
                    source_kind,
                    &["browser", "storage", "persisted-client-data"],
                    Confidence::Medium,
                    source_kind,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some((content, canonical)) =
                html_call_sink(&node, &dom_bindings, &react_refs, &shadowed_globals)
            {
                push_observation(
                    path,
                    language,
                    &node,
                    &content,
                    EvidenceKind::Sink,
                    Capability::HtmlOutput,
                    &format!("{}-browser-dom-html-output", language_prefix(language)),
                    "content",
                    canonical,
                    &["browser", "dom", "html", "xss"],
                    Confidence::High,
                    canonical,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some(content) = jquery_html_sink(root, &node, &jquery_factories) {
                push_observation(
                    path,
                    language,
                    &node,
                    &content,
                    EvidenceKind::Sink,
                    Capability::HtmlOutput,
                    &format!("{}-jquery-html-output", language_prefix(language)),
                    "content",
                    "jQuery HTML insertion",
                    &[
                        "browser",
                        "jquery",
                        "trusted-markup",
                        "explicit-raw-html",
                        "xss",
                    ],
                    Confidence::High,
                    "import-owned jQuery HTML insertion API",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some(content) = imported_unary_call_content(&node, &lit_unsafe_html) {
                push_observation(
                    path,
                    language,
                    &node,
                    &content,
                    EvidenceKind::Sink,
                    Capability::HtmlOutput,
                    &format!("{}-lit-unsafe-html-output", language_prefix(language)),
                    "content",
                    "Lit unsafeHTML",
                    &[
                        "browser",
                        "lit",
                        "trusted-markup",
                        "explicit-raw-html",
                        "xss",
                    ],
                    Confidence::High,
                    "Lit unsafeHTML directive",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some(content) = vue_render_inner_html_content(&node, &vue_factories) {
                push_observation(
                    path,
                    language,
                    &node,
                    &content,
                    EvidenceKind::Sink,
                    Capability::HtmlOutput,
                    &format!("{}-vue-inner-html-output", language_prefix(language)),
                    "content",
                    "Vue h innerHTML",
                    &[
                        "browser",
                        "vue",
                        "trusted-markup",
                        "explicit-raw-html",
                        "xss",
                    ],
                    Confidence::High,
                    "Vue render-function innerHTML property",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some((content, canonical)) =
                url_attribute_call_sink(&node, &dom_bindings, &react_refs, &shadowed_globals)
            {
                push_observation(
                    path,
                    language,
                    &node,
                    &content,
                    EvidenceKind::Sink,
                    Capability::HtmlOutput,
                    &format!("{}-browser-url-attribute-output", language_prefix(language)),
                    "content",
                    canonical,
                    &["browser", "dom", "url-attribute", "xss"],
                    Confidence::High,
                    canonical,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some(request_data) = credentialed_xhr_sink(&node, root) {
                push_observation(
                    path,
                    language,
                    &node,
                    &request_data,
                    EvidenceKind::Sink,
                    Capability::BrowserCredentialedRequest,
                    &format!("{}-browser-credentialed-request", language_prefix(language)),
                    "request_data",
                    "XMLHttpRequest.send",
                    &["browser", "csrf", "credentialed-request", "state-change"],
                    Confidence::High,
                    "credentialed XMLHttpRequest",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some(message) = wildcard_postmessage_sink(&node) {
                push_observation(
                    path,
                    language,
                    &node,
                    &message,
                    EvidenceKind::Sink,
                    Capability::BrowserMessageSend,
                    &format!(
                        "{}-browser-wildcard-message-send",
                        language_prefix(language)
                    ),
                    "message",
                    "Window.postMessage(* targetOrigin)",
                    &[
                        "browser",
                        "postmessage",
                        "wildcard-origin",
                        "information-disclosure",
                    ],
                    Confidence::High,
                    "Window.postMessage wildcard targetOrigin",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some(content) = react_create_element_content(&node, &react_factories) {
                push_observation(
                    path,
                    language,
                    &node,
                    &content,
                    EvidenceKind::Sink,
                    Capability::HtmlOutput,
                    &format!("{}-react-dangerous-html-output", language_prefix(language)),
                    "content",
                    "React.createElement dangerouslySetInnerHTML",
                    &["browser", "react", "dangerously-set-inner-html", "xss"],
                    Confidence::High,
                    "React.createElement",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }

            if let Some((destination, canonical)) = navigation_call_sink(&node, &shadowed_globals) {
                push_observation(
                    path,
                    language,
                    &node,
                    &destination,
                    EvidenceKind::Sink,
                    Capability::BrowserNavigation,
                    &format!("{}-browser-navigation", language_prefix(language)),
                    "destination",
                    canonical,
                    &["browser", "navigation", "open-redirect"],
                    Confidence::High,
                    canonical,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if kind == "assignment_expression"
            && let (Some(left), Some(right)) = (node.field("left"), node.field("right"))
        {
            let target = normalized(&left.text());
            if dom_html_property(&target, &dom_bindings, &react_refs, &shadowed_globals) {
                push_observation(
                    path,
                    language,
                    &node,
                    &right,
                    EvidenceKind::Sink,
                    Capability::HtmlOutput,
                    &format!("{}-browser-dom-html-output", language_prefix(language)),
                    "content",
                    &target,
                    &["browser", "dom", "html", "xss"],
                    Confidence::High,
                    "Element.innerHTML",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if navigation_assignment(&target, &shadowed_globals) {
                push_observation(
                    path,
                    language,
                    &node,
                    &right,
                    EvidenceKind::Sink,
                    Capability::BrowserNavigation,
                    &format!("{}-browser-navigation", language_prefix(language)),
                    "destination",
                    &target,
                    &["browser", "navigation", "open-redirect"],
                    Confidence::High,
                    "Window.location",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if kind == "jsx_attribute"
            && let Some(content) = jsx_url_attribute_content(&node)
        {
            let content_text = normalized(&content.text());
            if react_state.contains(&content_text) {
                push_observation(
                    path,
                    language,
                    &content,
                    &content,
                    EvidenceKind::Source,
                    Capability::BrowserInput,
                    &format!("{}-react-response-state-source", language_prefix(language)),
                    "value",
                    &content_text,
                    &["browser", "react", "state", "http-response"],
                    Confidence::Medium,
                    "React state derived from fetch response",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            push_observation(
                path,
                language,
                &node,
                &content,
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                &format!("{}-react-url-attribute-output", language_prefix(language)),
                "content",
                "React href attribute",
                &["browser", "react", "url-attribute", "xss"],
                Confidence::High,
                "React href attribute",
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if solid_runtime
            && kind == "jsx_attribute"
            && jsx_attribute_is_on_intrinsic_element(&node)
            && let Some(content) = jsx_attribute_content(&node, "innerHTML")
        {
            push_observation(
                path,
                language,
                &node,
                &content,
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                &format!("{}-solid-inner-html-output", language_prefix(language)),
                "content",
                "Solid innerHTML",
                &[
                    "browser",
                    "solidjs",
                    "trusted-markup",
                    "explicit-raw-html",
                    "xss",
                ],
                Confidence::High,
                "Solid innerHTML JSX property",
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if kind == "pair"
            && let Some(content) = dangerous_html_pair(&node)
            && node.ancestors().any(|ancestor| {
                ancestor.kind().as_ref() == "jsx_attribute"
                    && normalized(&ancestor.text()).starts_with("dangerouslySetInnerHTML=")
            })
        {
            push_observation(
                path,
                language,
                &node,
                &content,
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                &format!("{}-react-dangerous-html-output", language_prefix(language)),
                "content",
                "dangerouslySetInnerHTML",
                &["browser", "react", "dangerously-set-inner-html", "xss"],
                Confidence::High,
                "React dangerouslySetInnerHTML",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
    add_decoded_storage_sources(
        path,
        root,
        language,
        &shadowed_globals,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_message_origin_validations(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    compact_orphan_browser_reads(evidence);
}

#[allow(clippy::too_many_arguments)]
fn add_decoded_storage_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    shadowed_globals: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let decoders = jwt_decode_factories(root);
    if decoders.is_empty() {
        return;
    }
    for function in root.dfs().filter(is_function) {
        let storage_bindings = function
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "variable_declarator"
                    && nearest_function_range(node) == Some(function.range())
            })
            .filter_map(|declaration| {
                let name = declaration.field("name")?;
                let value = declaration.field("value")?;
                (value.kind().as_ref() == "call_expression"
                    && storage_source(&value, shadowed_globals).is_some())
                .then(|| normalized(&name.text()))
            })
            .collect::<BTreeSet<_>>();
        if storage_bindings.is_empty() {
            continue;
        }
        let decoded_bindings = function
            .dfs()
            .filter(|node| {
                matches!(
                    node.kind().as_ref(),
                    "variable_declarator" | "assignment_expression"
                ) && nearest_function_range(node) == Some(function.range())
            })
            .filter_map(|assignment| {
                let target = assignment
                    .field("name")
                    .or_else(|| assignment.field("left"))?;
                let value = assignment
                    .field("value")
                    .or_else(|| assignment.field("right"))?;
                if value.kind().as_ref() != "call_expression"
                    || !decoders.contains(&normalized(&value.field("function")?.text()))
                {
                    return None;
                }
                let argument = value
                    .field("arguments")?
                    .children()
                    .find(|child| child.is_named())?;
                storage_bindings
                    .contains(&normalized(&argument.text()))
                    .then(|| normalized(&target.text()))
            })
            .collect::<BTreeSet<_>>();
        for node in function.dfs().filter(|node| {
            matches!(
                node.kind().as_ref(),
                "member_expression" | "subscript_expression"
            ) && nearest_function_range(node) == Some(function.range())
        }) {
            let observed = normalized(&node.text());
            let Some(decoded) = decoded_bindings
                .iter()
                .find(|binding| observed.starts_with(&format!("{binding}.")))
            else {
                continue;
            };
            if node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind().as_ref(),
                    "member_expression" | "subscript_expression"
                ) && normalized(&parent.text()).starts_with(&format!("{decoded}."))
            }) {
                continue;
            }
            push_observation(
                path,
                language,
                &node,
                &node,
                EvidenceKind::Source,
                Capability::BrowserInput,
                &format!(
                    "{}-browser-decoded-storage-source",
                    language_prefix(language)
                ),
                "value",
                &observed,
                &["browser", "storage", "jwt-decode", "derived-client-data"],
                Confidence::Medium,
                "jwt-decode decoded browser storage",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn jwt_decode_factories(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let mut decoders = BTreeSet::new();
    for import in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = import.text();
        let Some((clause, module)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        if exact_quoted(module.trim().trim_end_matches(';')) != Some("jwt-decode") {
            continue;
        }
        let clause = clause.trim();
        if clause.starts_with('{') {
            for entry in clause.trim_matches(['{', '}']).split(',') {
                let words = entry.split_whitespace().collect::<Vec<_>>();
                if words.first() == Some(&"jwtDecode") {
                    decoders.insert(
                        if words.get(1) == Some(&"as") {
                            words.get(2).copied().unwrap_or("jwtDecode")
                        } else {
                            "jwtDecode"
                        }
                        .to_string(),
                    );
                }
            }
        } else {
            let default = clause.split(',').next().unwrap_or_default().trim();
            if is_identifier(default) {
                decoders.insert(default.to_string());
            }
        }
    }
    decoders
}

fn compact_orphan_browser_reads(evidence: &mut Vec<Evidence>) {
    let sink_symbols = evidence
        .iter()
        .filter(|item| {
            matches!(
                item.capability,
                Capability::HtmlOutput | Capability::BrowserNavigation
            ) && (item.rule_id.contains("browser-dom-html-output")
                || item.rule_id.contains("react-dangerous-html-output")
                || item.rule_id.contains("url-attribute-output")
                || item.rule_id.contains("angular-html-trust-bypass")
                || item.capability == Capability::BrowserNavigation)
        })
        .map(|item| item.enclosing_symbol.clone())
        .collect::<BTreeSet<_>>();
    evidence.retain(|item| {
        item.provenance.engine != BROWSER_ENGINE
            || item.capability != Capability::BrowserInput
            || item.rule_id.contains("message-source")
            || item.rule_id.contains("response-state-source")
            || sink_symbols.contains(&item.enclosing_symbol)
    });
}

fn browser_member_source(
    observed: &str,
    shadowed_globals: &BTreeSet<String>,
) -> Option<&'static str> {
    if starts_with_shadowed_global(observed, shadowed_globals) {
        return None;
    }
    match observed {
        "location.search"
        | "window.location.search"
        | "document.location.search"
        | "globalThis.location.search"
        | "location.hash"
        | "window.location.hash"
        | "document.location.hash"
        | "globalThis.location.hash"
        | "location.href"
        | "window.location.href"
        | "document.location.href"
        | "globalThis.location.href"
        | "document.URL"
        | "document.documentURI"
        | "document.referrer"
        | "window.name" => Some("url"),
        _ => None,
    }
}

fn storage_source<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    shadowed_globals: &BTreeSet<String>,
) -> Option<(&'static str, Node<'tree, StrDoc<SupportLang>>)> {
    let callee = call.field("function")?;
    let observed = normalized(&callee.text());
    if starts_with_shadowed_global(&observed, shadowed_globals) {
        return None;
    }
    let canonical = match observed.as_str() {
        "localStorage.getItem" | "window.localStorage.getItem" => "localStorage.getItem",
        "sessionStorage.getItem" | "window.sessionStorage.getItem" => "sessionStorage.getItem",
        _ => return None,
    };
    Some((canonical, call.clone()))
}

fn shadowed_browser_globals(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    const GLOBALS: [&str; 10] = [
        "window",
        "document",
        "location",
        "globalThis",
        "self",
        "localStorage",
        "sessionStorage",
        "onmessage",
        "addEventListener",
        "Document",
    ];
    root.dfs()
        .filter_map(|node| match node.kind().as_ref() {
            "variable_declarator" | "function_declaration" | "class_declaration" => {
                node.field("name")
            }
            _ => None,
        })
        .filter_map(|name| {
            let name = normalized(&name.text());
            GLOBALS.contains(&name.as_str()).then_some(name)
        })
        .collect()
}

fn starts_with_shadowed_global(observed: &str, shadowed: &BTreeSet<String>) -> bool {
    observed
        .split(['.', '[', '('])
        .next()
        .is_some_and(|root| shadowed.contains(root))
}

fn message_data_ranges(
    root: &Node<'_, StrDoc<SupportLang>>,
    shadowed_globals: &BTreeSet<String>,
) -> BTreeSet<usize> {
    let mut ranges = BTreeSet::new();
    for node in root.dfs() {
        if node.kind().as_ref() == "call_expression" {
            let Some(callee) = node.field("function") else {
                continue;
            };
            if starts_with_shadowed_global(&normalized(&callee.text()), shadowed_globals) {
                continue;
            }
            if !matches!(
                normalized(&callee.text()).as_str(),
                "addEventListener"
                    | "window.addEventListener"
                    | "self.addEventListener"
                    | "globalThis.addEventListener"
            ) {
                continue;
            }
            let Some(arguments) = node.field("arguments") else {
                continue;
            };
            let arguments = arguments
                .children()
                .filter(|child| child.is_named())
                .collect::<Vec<_>>();
            if arguments.len() < 2 || exact_quoted(&arguments[0].text()) != Some("message") {
                continue;
            }
            collect_message_callback_data(&arguments[1], &mut ranges);
        } else if node.kind().as_ref() == "assignment_expression" {
            let (Some(left), Some(right)) = (node.field("left"), node.field("right")) else {
                continue;
            };
            if starts_with_shadowed_global(&normalized(&left.text()), shadowed_globals) {
                continue;
            }
            if matches!(
                normalized(&left.text()).as_str(),
                "onmessage" | "window.onmessage" | "self.onmessage" | "globalThis.onmessage"
            ) {
                collect_message_callback_data(&right, &mut ranges);
            }
        }
    }
    ranges
}

fn collect_message_callback_data(
    callback: &Node<'_, StrDoc<SupportLang>>,
    ranges: &mut BTreeSet<usize>,
) {
    if !is_function(callback) {
        return;
    }
    let Some(parameter) = callback_parameter(callback) else {
        return;
    };
    for node in callback.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "member_expression" | "subscript_expression"
        ) && nearest_function_range(node) == Some(callback.range())
    }) {
        if normalized(&node.text()) == format!("{parameter}.data") {
            ranges.insert(node.range().start);
        }
    }
}

fn socket_data_ranges(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<usize> {
    let sockets = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = normalized(&declaration.field("value")?.text());
            (value.starts_with("io.connect(")
                || value.starts_with("io(")
                || value.contains("socket.io-client"))
            .then(|| normalized(&name.text()))
        })
        .collect::<BTreeSet<_>>();
    let mut ranges = BTreeSet::new();
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
    {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let callee = normalized(&callee.text());
        let Some((receiver, method)) = callee.rsplit_once('.') else {
            continue;
        };
        if method != "on" || !sockets.contains(receiver) {
            continue;
        }
        let Some(arguments) = call.field("arguments") else {
            continue;
        };
        let arguments = arguments
            .children()
            .filter(|child| child.is_named())
            .collect::<Vec<_>>();
        if arguments.len() < 2 || exact_quoted(&arguments[0].text()).is_none() {
            continue;
        }
        collect_callback_parameter_members(&arguments[1], &mut ranges);
    }
    ranges
}

fn collect_callback_parameter_members(
    callback: &Node<'_, StrDoc<SupportLang>>,
    ranges: &mut BTreeSet<usize>,
) {
    if !is_function(callback) {
        return;
    }
    let Some(parameter) = callback_parameter(callback) else {
        return;
    };
    for member in callback.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "member_expression" | "subscript_expression"
        ) && nearest_function_range(node) == Some(callback.range())
    }) {
        let observed = normalized(&member.text());
        if observed.starts_with(&format!("{parameter}."))
            && !observed.ends_with(".toFixed")
            && !member.parent().is_some_and(|parent| {
                matches!(
                    parent.kind().as_ref(),
                    "member_expression" | "subscript_expression"
                ) && normalized(&parent.text()).starts_with(&format!("{parameter}."))
            })
        {
            ranges.insert(member.range().start);
        }
    }
}

fn fetch_response_data_ranges(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<usize> {
    let responses = fetch_response_bindings(root);
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "member_expression" | "subscript_expression"
            )
        })
        .filter_map(|member| {
            let scope = nearest_function_range(&member).map(|range| (range.start, range.end));
            let observed = normalized(&member.text());
            responses
                .iter()
                .any(|(response_scope, response)| {
                    *response_scope == scope && observed.starts_with(&format!("{response}."))
                })
                .then_some(member.range().start)
        })
        .collect()
}

fn fetch_response_bindings(
    root: &Node<'_, StrDoc<SupportLang>>,
) -> BTreeSet<(Option<(usize, usize)>, String)> {
    let declarations = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            Some((
                nearest_function_range(&declaration).map(|range| (range.start, range.end)),
                normalized(&declaration.field("name")?.text()),
                normalized(&declaration.field("value")?.text()),
            ))
        })
        .collect::<Vec<_>>();
    let fetches = declarations
        .iter()
        .filter(|(_, _, value)| value.trim_start_matches("await").starts_with("fetch("))
        .map(|(scope, name, _)| (*scope, name.clone()))
        .collect::<BTreeSet<_>>();
    declarations
        .iter()
        .filter_map(|(scope, name, value)| {
            let value = value.trim_start_matches("await");
            fetches
                .iter()
                .any(|(fetch_scope, fetch)| {
                    fetch_scope == scope && value == format!("{fetch}.json()")
                })
                .then_some((*scope, name.clone()))
        })
        .collect()
}

fn untrusted_react_state_fields(
    root: &Node<'_, StrDoc<SupportLang>>,
    response_data: &BTreeSet<usize>,
) -> BTreeSet<String> {
    let response_bindings = fetch_response_bindings(root);
    let mut fields = BTreeSet::new();
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
    {
        let Some(callee) = call.field("function") else {
            continue;
        };
        if !normalized(&callee.text()).ends_with(".setState") {
            continue;
        }
        let Some(object) = call
            .field("arguments")
            .and_then(|arguments| arguments.children().find(|child| child.is_named()))
        else {
            continue;
        };
        let scope = nearest_function_range(&call).map(|range| (range.start, range.end));
        for pair in object
            .children()
            .filter(|child| child.kind().as_ref() == "pair")
        {
            let (Some(key), Some(value)) = (pair.field("key"), pair.field("value")) else {
                continue;
            };
            let value_text = normalized(&value.text());
            if value
                .dfs()
                .any(|node| response_data.contains(&node.range().start))
                || response_bindings.iter().any(|(response_scope, response)| {
                    *response_scope == scope && value_text.starts_with(&format!("{response}."))
                })
            {
                fields.insert(format!(
                    "this.state.{}",
                    normalized(&key.text()).trim_matches(['\'', '"'])
                ));
            }
        }
    }
    fields
}

fn callback_parameter(callback: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    callback
        .field("parameter")
        .or_else(|| {
            callback
                .field("parameters")?
                .children()
                .find(|child| child.is_named())
        })
        .and_then(identifier_within)
}

fn identifier_within(node: Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if node.kind().as_ref() == "identifier" {
        return Some(node.text().into_owned());
    }
    node.dfs()
        .find(|child| child.kind().as_ref() == "identifier")
        .map(|child| child.text().into_owned())
}

fn dom_bindings(
    root: &Node<'_, StrDoc<SupportLang>>,
    shadowed_globals: &BTreeSet<String>,
) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|node| {
            let name = node.field("name")?;
            let value = node.field("value")?;
            let value = normalized(&value.text());
            (proved_dom_expression(&value)
                && !starts_with_shadowed_global(&value, shadowed_globals))
            .then(|| normalized(&name.text()))
        })
        .collect()
}

fn react_ref_targets(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "variable_declarator" | "assignment_expression"
            )
        })
        .filter_map(|assignment| {
            let target = assignment
                .field("name")
                .or_else(|| assignment.field("left"))?;
            let value = assignment
                .field("value")
                .or_else(|| assignment.field("right"))?;
            normalized(&value.text())
                .ends_with(".createRef()")
                .then(|| format!("{}.current", normalized(&target.text())))
        })
        .collect()
}

fn proved_dom_expression(value: &str) -> bool {
    [
        "document.querySelector(",
        "document.getElementById(",
        "document.getElementsByClassName(",
        "document.createElement(",
        "window.document.querySelector(",
        "window.document.getElementById(",
        "window.document.createElement(",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn dom_html_property(
    target: &str,
    bindings: &BTreeSet<String>,
    react_refs: &BTreeSet<String>,
    shadowed_globals: &BTreeSet<String>,
) -> bool {
    let Some((receiver, property)) = target.rsplit_once('.') else {
        return false;
    };
    if !matches!(property, "innerHTML" | "outerHTML") {
        return false;
    }
    let receiver = receiver.trim_end_matches('!');
    !starts_with_shadowed_global(receiver, shadowed_globals)
        && (receiver.starts_with("document.")
            || receiver.starts_with("window.document.")
            || proved_dom_expression(receiver)
            || bindings.contains(receiver)
            || react_refs.contains(receiver))
}

fn html_call_sink<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    bindings: &BTreeSet<String>,
    react_refs: &BTreeSet<String>,
    shadowed_globals: &BTreeSet<String>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, &'static str)> {
    let callee = normalized(&call.field("function")?.text());
    if starts_with_shadowed_global(&callee, shadowed_globals) {
        return None;
    }
    let arguments = call
        .field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .collect::<Vec<_>>();
    if matches!(
        callee.as_str(),
        "document.write" | "window.document.write" | "document.writeln" | "window.document.writeln"
    ) {
        return Some((arguments.first()?.clone(), "Document.write"));
    }
    if callee == "Document.parseHTMLUnsafe" {
        return Some((arguments.first()?.clone(), "Document.parseHTMLUnsafe"));
    }
    let (receiver, method) = callee.rsplit_once('.')?;
    let receiver = receiver.trim_end_matches('!');
    if method == "insertAdjacentHTML"
        && (receiver.starts_with("document.")
            || receiver.starts_with("window.document.")
            || proved_dom_expression(receiver)
            || bindings.contains(receiver)
            || react_refs.contains(receiver))
    {
        return Some((arguments.get(1)?.clone(), "Element.insertAdjacentHTML"));
    }
    if method == "setHTMLUnsafe"
        && (receiver.starts_with("document.")
            || receiver.starts_with("window.document.")
            || proved_dom_expression(receiver)
            || bindings.contains(receiver)
            || react_refs.contains(receiver)
            || receiver.strip_suffix(".shadowRoot").is_some_and(|host| {
                proved_dom_expression(host) || bindings.contains(host) || react_refs.contains(host)
            }))
    {
        return Some((arguments.first()?.clone(), "Element.setHTMLUnsafe"));
    }
    None
}

fn jquery_html_sink<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    call: &Node<'tree, StrDoc<SupportLang>>,
    factories: &BTreeSet<String>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let callee = normalized(&call.field("function")?.text());
    let (receiver, method) = callee.rsplit_once('.')?;
    if !matches!(
        method,
        "html"
            | "append"
            | "prepend"
            | "before"
            | "after"
            | "replaceWith"
            | "wrap"
            | "wrapAll"
            | "wrapInner"
    ) || !(factories
        .iter()
        .any(|factory| receiver.starts_with(&format!("{factory}(")))
        || latest_jquery_binding_is_owned(root, call, receiver, factories))
    {
        return None;
    }
    call.field("arguments")?
        .children()
        .find(|child| child.is_named())
}

fn latest_jquery_binding_is_owned(
    root: &Node<'_, StrDoc<SupportLang>>,
    call: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    factories: &BTreeSet<String>,
) -> bool {
    let call_scope = nearest_function_range(call);
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "variable_declarator" | "assignment_expression"
            ) && node.range().start < call.range().start
                && nearest_function_range(node) == call_scope
        })
        .filter_map(|node| {
            let target = node.field("name").or_else(|| node.field("left"))?;
            (normalized(&target.text()) == receiver).then(|| {
                (
                    node.range().start,
                    node.field("value")
                        .or_else(|| node.field("right"))
                        .map(|value| normalized(&value.text())),
                )
            })
        })
        .max_by_key(|(offset, _)| *offset)
        .and_then(|(_, value)| value)
        .is_some_and(|value| {
            factories
                .iter()
                .any(|factory| value.starts_with(&format!("{factory}(")))
        })
}

fn url_attribute_call_sink<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    bindings: &BTreeSet<String>,
    react_refs: &BTreeSet<String>,
    shadowed_globals: &BTreeSet<String>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, &'static str)> {
    let callee = normalized(&call.field("function")?.text());
    if starts_with_shadowed_global(&callee, shadowed_globals) {
        return None;
    }
    let (receiver, method) = callee.rsplit_once('.')?;
    if method != "setAttribute"
        || !(proved_dom_expression(receiver)
            || bindings.contains(receiver)
            || react_refs.contains(receiver))
    {
        return None;
    }
    let arguments = call
        .field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .collect::<Vec<_>>();
    if !matches!(
        exact_quoted(&arguments.first()?.text()),
        Some("href" | "src" | "xlink:href")
    ) {
        return None;
    }
    Some((arguments.get(1)?.clone(), "Element URL attribute"))
}

fn credentialed_xhr_sink<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let callee = normalized(&call.field("function")?.text());
    let (receiver, method) = callee.rsplit_once('.')?;
    if method != "send" || !is_identifier(receiver) {
        return None;
    }
    let scope = nearest_function_range(call)?;
    let xhr = root.dfs().any(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node.range().start >= scope.start
            && node.range().end <= scope.end
            && node.range().end <= call.range().start
            && node
                .field("name")
                .is_some_and(|name| normalized(&name.text()) == receiver)
            && node
                .field("value")
                .is_some_and(|value| normalized(&value.text()).starts_with("newXMLHttpRequest("))
    });
    if !xhr {
        return None;
    }
    let credentialed = root.dfs().any(|node| {
        node.range().start >= scope.start
            && node.range().end <= scope.end
            && node.range().end <= call.range().start
            && ((node.kind().as_ref() == "assignment_expression"
                && node.field("left").is_some_and(|left| {
                    normalized(&left.text()) == format!("{receiver}.withCredentials")
                })
                && node
                    .field("right")
                    .is_some_and(|right| normalized(&right.text()) == "true"))
                || (node.kind().as_ref() == "call_expression"
                    && node.field("function").is_some_and(|function| {
                        normalized(&function.text()) == format!("{receiver}.setRequestHeader")
                    })
                    && node.field("arguments").is_some_and(|arguments| {
                        arguments
                            .children()
                            .find(|child| child.is_named())
                            .is_some_and(|header| {
                                exact_quoted(&header.text()).is_some_and(|header| {
                                    header.eq_ignore_ascii_case("authorization")
                                })
                            })
                    })))
    });
    credentialed.then(|| {
        call.field("arguments")?
            .children()
            .find(|child| child.is_named())
    })?
}

fn wildcard_postmessage_sink<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let callee = normalized(&call.field("function")?.text());
    if !callee.ends_with(".postMessage") {
        return None;
    }
    let arguments = call
        .field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .collect::<Vec<_>>();
    (arguments.len() >= 2 && exact_quoted(&arguments[1].text()) == Some("*"))
        .then(|| arguments[0].clone())
}

fn imports_module(root: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
        .any(|node| {
            node.text()
                .trim()
                .strip_prefix("import ")
                .and_then(|rest| rest.rsplit_once(" from "))
                .and_then(|(_, module)| exact_quoted(module.trim().trim_end_matches(';')))
                == Some(expected)
        })
}

fn imported_named_bindings(
    root: &Node<'_, StrDoc<SupportLang>>,
    modules: &[&str],
    exported: &str,
) -> BTreeSet<String> {
    let mut bindings = BTreeSet::new();
    for import in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = import.text();
        let Some((clause, module)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        let Some(module) = exact_quoted(module.trim().trim_end_matches(';')) else {
            continue;
        };
        if !modules.contains(&module) {
            continue;
        }
        for entry in clause.trim().trim_matches(['{', '}']).split(',') {
            let words = entry.split_whitespace().collect::<Vec<_>>();
            if words.first() == Some(&exported) {
                bindings.insert(
                    if words.get(1) == Some(&"as") {
                        words.get(2).copied().unwrap_or(exported)
                    } else {
                        exported
                    }
                    .to_string(),
                );
            }
        }
    }
    bindings
}

fn imported_default_or_required_bindings(
    root: &Node<'_, StrDoc<SupportLang>>,
    modules: &[&str],
) -> BTreeSet<String> {
    let mut bindings = BTreeSet::new();
    for node in root.dfs() {
        if node.kind().as_ref() == "import_statement" {
            let text = node.text();
            let Some((clause, module)) = text
                .trim()
                .strip_prefix("import ")
                .and_then(|rest| rest.rsplit_once(" from "))
            else {
                continue;
            };
            let Some(module) = exact_quoted(module.trim().trim_end_matches(';')) else {
                continue;
            };
            if modules.contains(&module)
                && let Some(binding) = clause.split(',').next().map(str::trim).filter(|binding| {
                    !binding.is_empty() && !binding.starts_with('{') && !binding.starts_with('*')
                })
            {
                bindings.insert(binding.to_string());
            }
        } else if node.kind().as_ref() == "variable_declarator"
            && let (Some(name), Some(value)) = (node.field("name"), node.field("value"))
        {
            let value = normalized(&value.text());
            if modules.iter().any(|module| {
                value == format!("require('{module}')") || value == format!("require(\"{module}\")")
            }) {
                bindings.insert(normalized(&name.text()));
            }
        }
    }
    bindings
}

fn imported_unary_call_content<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    bindings: &BTreeSet<String>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let callee = normalized(&call.field("function")?.text());
    bindings.contains(&callee).then(|| {
        call.field("arguments")?
            .children()
            .find(|child| child.is_named())
    })?
}

fn vue_render_inner_html_content<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    factories: &BTreeSet<String>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let callee = normalized(&call.field("function")?.text());
    if !factories.contains(&callee) {
        return None;
    }
    let arguments = call
        .field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .collect::<Vec<_>>();
    let tag_text = arguments.first()?.text();
    let tag = exact_quoted(&tag_text)?;
    if !tag
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_lowercase())
    {
        return None;
    }
    let properties = arguments.get(1)?;
    properties
        .dfs()
        .find(|node| {
            node.kind().as_ref() == "pair"
                && node
                    .field("key")
                    .is_some_and(|key| normalized(&key.text()) == "innerHTML")
        })?
        .field("value")
}

fn jsx_attribute_is_on_intrinsic_element(attribute: &Node<'_, StrDoc<SupportLang>>) -> bool {
    attribute
        .ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "jsx_opening_element" | "jsx_self_closing_element"
            )
        })
        .and_then(|element| {
            normalized(&element.text())
                .trim_start_matches('<')
                .split(|character: char| {
                    character.is_whitespace() || matches!(character, '>' | '/')
                })
                .next()
                .and_then(|name| name.chars().next())
        })
        .is_some_and(|character| character.is_ascii_lowercase())
}

#[allow(clippy::too_many_arguments)]
fn add_message_origin_validations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let message_data = message_data_ranges(root, &shadowed_browser_globals(root));
    for comparison in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "binary_expression")
    {
        let Some(callback) = comparison.ancestors().find(is_function) else {
            continue;
        };
        let Some(parameter) = callback_parameter(&callback) else {
            continue;
        };
        let compact = normalized(&comparison.text());
        let rejects_untrusted_origin = comparison.ancestors().any(|ancestor| {
            ancestor.kind().as_ref() == "if_statement"
                && ancestor.field("condition").is_some_and(|condition| {
                    condition.range().start <= comparison.range().start
                        && condition.range().end >= comparison.range().end
                })
                && ancestor.field("consequence").is_some_and(|consequence| {
                    consequence.dfs().any(|node| {
                        matches!(node.kind().as_ref(), "return_statement" | "throw_statement")
                    })
                })
        });
        if !compact.contains(&format!("{parameter}.origin"))
            || !["!==", "!="]
                .iter()
                .any(|operator| compact.contains(operator))
            || !rejects_untrusted_origin
            || !comparison.dfs().any(|node| {
                matches!(node.kind().as_ref(), "string" | "string_fragment")
                    && exact_quoted(&node.text()).is_some_and(|origin| origin != "*")
            })
        {
            continue;
        }
        let Some(data) = callback.dfs().find(|node| {
            message_data.contains(&node.range().start)
                && normalized(&node.text()) == format!("{parameter}.data")
        }) else {
            continue;
        };
        push_observation(
            path,
            language,
            &comparison,
            &data,
            EvidenceKind::Validation,
            Capability::Authorization,
            &format!(
                "{}-browser-message-origin-validation",
                language_prefix(language)
            ),
            "value",
            &compact,
            &["browser", "postmessage", "origin-validation", "control"],
            Confidence::High,
            "MessageEvent.origin comparison",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn jsx_url_attribute_content<'tree>(
    attribute: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    jsx_attribute_content(attribute, "href")
}

fn jsx_attribute_content<'tree>(
    attribute: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let text = normalized(&attribute.text());
    if !text.starts_with(&format!("{name}=")) {
        return None;
    }
    let value = attribute.field("value").or_else(|| {
        attribute.children().find(|child| {
            child.is_named()
                && child.kind().as_ref() != "property_identifier"
                && child.kind().as_ref() != "jsx_identifier"
        })
    })?;
    if value.kind().as_ref() == "jsx_expression" {
        value.children().find(|child| child.is_named())
    } else {
        Some(value)
    }
}

fn react_factories(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let mut factories = BTreeSet::new();
    for import in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = import.text();
        let Some((clause, module)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        if exact_quoted(module.trim().trim_end_matches(';')) != Some("react") {
            continue;
        }
        let clause = clause.trim().strip_prefix("type ").unwrap_or(clause.trim());
        if let Some(namespace) = clause.strip_prefix("* as ") {
            factories.insert(format!("{}.createElement", namespace.trim()));
        } else if clause.starts_with('{') {
            for entry in clause.trim_matches(['{', '}']).split(',') {
                let words = entry.split_whitespace().collect::<Vec<_>>();
                if words.first() == Some(&"createElement") {
                    factories.insert(
                        if words.get(1) == Some(&"as") {
                            words.get(2).copied().unwrap_or("createElement")
                        } else {
                            "createElement"
                        }
                        .to_string(),
                    );
                }
            }
        } else {
            let default = clause.split(',').next().unwrap_or_default().trim();
            if is_identifier(default) {
                factories.insert(format!("{default}.createElement"));
            }
        }
    }
    factories
}

fn react_create_element_content<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    factories: &BTreeSet<String>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let callee = normalized(&call.field("function")?.text());
    if !factories.contains(&callee) {
        return None;
    }
    let properties = call
        .field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .nth(1)?;
    properties
        .dfs()
        .find(|node| {
            node.kind().as_ref() == "pair"
                && node
                    .field("key")
                    .is_some_and(|key| normalized(&key.text()) == "dangerouslySetInnerHTML")
        })?
        .field("value")?
        .dfs()
        .find_map(|node| dangerous_html_pair(&node))
}

fn dangerous_html_pair<'tree>(
    pair: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    (pair.kind().as_ref() == "pair"
        && pair
            .field("key")
            .is_some_and(|key| normalized(&key.text()) == "__html"))
    .then(|| pair.field("value"))
    .flatten()
}

fn navigation_call_sink<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    shadowed_globals: &BTreeSet<String>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, &'static str)> {
    let callee = normalized(&call.field("function")?.text());
    if starts_with_shadowed_global(&callee, shadowed_globals) {
        return None;
    }
    let canonical = match callee.as_str() {
        "location.assign" | "window.location.assign" | "globalThis.location.assign" => {
            "Window.location.assign"
        }
        "location.replace" | "window.location.replace" | "globalThis.location.replace" => {
            "Window.location.replace"
        }
        "window.open" | "globalThis.open" => "Window.open",
        _ => return None,
    };
    let destination = call
        .field("arguments")?
        .children()
        .find(|child| child.is_named())?;
    Some((destination, canonical))
}

fn navigation_assignment(target: &str, shadowed_globals: &BTreeSet<String>) -> bool {
    if starts_with_shadowed_global(target, shadowed_globals) {
        return false;
    }
    matches!(
        target,
        "location"
            | "window.location"
            | "globalThis.location"
            | "location.href"
            | "window.location.href"
            | "globalThis.location.href"
    )
}

fn is_assignment_target(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind().as_ref() == "assignment_expression"
            && parent
                .field("left")
                .is_some_and(|left| left.range() == node.range())
    })
}

#[allow(clippy::too_many_arguments)]
fn push_observation<'tree>(
    path: &str,
    _language: Language,
    anchor: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    role: &str,
    observed: &str,
    tags: &[&str],
    confidence: Confidence,
    canonical: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(anchor.range())
        || (kind == EvidenceKind::Sink
            && matches!(
                capability,
                Capability::HtmlOutput | Capability::BrowserNavigation
            )
            && matches!(literals.evaluate(value).state, LiteralState::Known))
        || evidence.iter().any(|item| {
            item.capability == capability
                && item.location.start.byte_offset == anchor.range().start
                && item.location.end.byte_offset == anchor.range().end
        })
    {
        return;
    }
    let mut captures = BTreeMap::from([(role.to_string(), capture(path, value))]);
    if kind == EvidenceKind::Validation && capability == Capability::Authorization {
        captures.insert("request_data".to_string(), capture(path, value));
    }
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, anchor.range().start, anchor.range().end),
        kind,
        capability,
        location: location(path, anchor),
        enclosing_symbol: enclosing_symbol(anchor),
        captures,
        cwe_candidates: vec![
            match capability {
                Capability::HtmlOutput => "CWE-79",
                Capability::BrowserNavigation => "CWE-601",
                Capability::BrowserCredentialedRequest => "CWE-352",
                Capability::BrowserMessageSend => "CWE-200",
                Capability::Authorization => "CWE-346",
                _ => "CWE-20",
            }
            .to_string(),
        ],
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: BROWSER_ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(anchor, literals)),
            availability: Some(conditional.availability_for(anchor.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: Some(SymbolResolution {
            canonical: canonical.to_string(),
            observed: observed.to_string(),
            method: SymbolResolutionMethod::FullyQualified,
            confidence: SymbolConfidence::Exact,
        }),
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn is_function(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
    )
}

fn nearest_function_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(is_function)
        .map(|function| function.range())
}

fn language_prefix(language: Language) -> &'static str {
    match language {
        Language::Javascript => "javascript",
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => unreachable!(),
    }
}

fn exact_quoted(text: &str) -> Option<&str> {
    let text = text.trim();
    let quote = text.chars().next()?;
    matches!(quote, '\'' | '"')
        .then(|| text.strip_prefix(quote)?.strip_suffix(quote))
        .flatten()
}

fn normalized(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .replace("?.", ".")
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(|first| {
        (first == '_' || first == '$' || first.is_alphabetic())
            && characters.all(|character| {
                character == '_' || character == '$' || character.is_alphanumeric()
            })
    })
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
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
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use ast_grep_core::AstGrep;
    use ast_grep_core::tree_sitter::StrDoc;
    use ast_grep_language::SupportLang;

    use super::*;

    #[test]
    fn summarizes_fetch_response_fields_stored_in_react_state() {
        let source = r#"
          async saveData() {
            const request = await fetch('/profile');
            const response = await request.json();
            this.setState({ name: response.name, website: response.website });
          }
          render() { return <a href={this.state.website}>site</a>; }
        "#;
        let doc = StrDoc::try_new(source, SupportLang::JavaScript).expect("javascript");
        let ast = AstGrep::doc(doc);
        let root = ast.root();
        let response = fetch_response_data_ranges(&root);
        let state = untrusted_react_state_fields(&root, &response);
        assert_eq!(
            state,
            [
                "this.state.name".to_string(),
                "this.state.website".to_string()
            ]
            .into_iter()
            .collect()
        );
    }
}
