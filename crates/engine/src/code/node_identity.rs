//! Lexical identity for two browser/platform names. No value propagation or CFG.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Evidence, Language, SymbolConfidence, SymbolResolution, SymbolResolutionMethod,
};
use std::{collections::BTreeMap, ops::Range};
type N<'a> = Node<'a, StrDoc<SupportLang>>;

struct Binding<'a> {
    name: String,
    scope: Range<usize>,
    declaration: N<'a>,
    parameter: bool,
}

fn function(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "generator_function"
            | "generator_function_declaration"
    )
}

fn scope(node: &N<'_>, function_only: bool) -> Range<usize> {
    node.ancestors()
        .find(|n| {
            n.kind().as_ref() == "program"
                || function(n.kind().as_ref())
                || !function_only
                    && matches!(
                        n.kind().as_ref(),
                        "statement_block" | "for_statement" | "for_in_statement" | "catch_clause"
                    )
        })
        .map(|n| n.range())
        .unwrap_or(0..usize::MAX)
}

pub(super) fn module_declaration(node: &N<'_>) -> bool {
    node.ancestors()
        .all(|n| !function(n.kind().as_ref()) && n.kind().as_ref() != "statement_block")
}

pub(super) fn bound_names(pattern: &N<'_>, out: &mut Vec<String>) {
    match pattern.kind().as_ref() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            out.push(pattern.text().into_owned())
        }
        "pair_pattern" => {
            if let Some(value) = pattern.field("value") {
                bound_names(&value, out);
            }
        }
        "assignment_pattern" | "object_assignment_pattern" => {
            if let Some(left) = pattern.field("left") {
                bound_names(&left, out);
            }
        }
        "required_parameter" | "optional_parameter" => {
            if let Some(p) = pattern.field("pattern").or_else(|| pattern.field("name")) {
                bound_names(&p, out);
            }
        }
        "object_pattern" | "array_pattern" | "rest_pattern" => {
            for c in pattern.children().filter(|n| n.is_named()) {
                bound_names(&c, out);
            }
        }
        _ => {}
    }
}

fn bindings<'a>(root: &N<'a>) -> Vec<Binding<'a>> {
    let mut result = Vec::new();
    for n in root.dfs() {
        let kind = n.kind();
        let (patterns, range, parameter) = if function(kind.as_ref()) {
            let mut params = n
                .field("parameters")
                .map(|p| p.children().filter(|c| c.is_named()).collect::<Vec<_>>())
                .unwrap_or_default();
            if let Some(p) = n.field("parameter") {
                params.push(p);
            }
            if let Some(name) = n.field("name") {
                let text = name.text().into_owned();
                if matches!(
                    text.as_str(),
                    "fetch"
                        | "location"
                        | "window"
                        | "globalThis"
                        | "document"
                        | "navigator"
                        | "localStorage"
                        | "sessionStorage"
                ) {
                    let declaration_scope = if matches!(
                        kind.as_ref(),
                        "function_declaration" | "generator_function_declaration"
                    ) {
                        scope(&n, false)
                    } else {
                        n.range()
                    };
                    result.push(Binding {
                        name: text,
                        scope: declaration_scope,
                        declaration: n.clone(),
                        parameter: false,
                    });
                }
            }
            (params, n.range(), true)
        } else if kind.as_ref() == "variable_declarator" {
            let is_var = n
                .parent()
                .is_some_and(|p| p.kind().as_ref() == "variable_declaration");
            (
                n.field("name").into_iter().collect(),
                scope(&n, is_var),
                false,
            )
        } else if kind.as_ref() == "catch_clause" {
            (n.field("parameter").into_iter().collect(), n.range(), true)
        } else if kind.as_ref() == "import_statement" {
            // Import specifiers distinguish imported keys from visible bindings.
            let mut names = Vec::new();
            for c in n.dfs() {
                match c.kind().as_ref() {
                    "import_specifier" => {
                        if let Some(p) = c.field("alias").or_else(|| c.field("name")) {
                            names.push(p);
                        }
                    }
                    "identifier"
                        if c.parent().is_some_and(|p| {
                            matches!(p.kind().as_ref(), "import_clause" | "namespace_import")
                        }) =>
                    {
                        names.push(c)
                    }
                    _ => {}
                }
            }
            (names, scope(&n, false), false)
        } else {
            continue;
        };
        for pattern in patterns {
            let mut names = Vec::new();
            bound_names(&pattern, &mut names);
            for name in names {
                if matches!(
                    name.as_str(),
                    "fetch"
                        | "location"
                        | "window"
                        | "globalThis"
                        | "document"
                        | "navigator"
                        | "localStorage"
                        | "sessionStorage"
                ) {
                    result.push(Binding {
                        name,
                        scope: range.clone(),
                        declaration: if parameter {
                            pattern.clone()
                        } else {
                            n.clone()
                        },
                        parameter,
                    });
                }
            }
        }
    }
    result
}

fn binding<'b, 'a>(bindings: &'b [Binding<'a>], name: &str, at: usize) -> Option<&'b Binding<'a>> {
    bindings
        .iter()
        .filter(|b| b.name == name && b.scope.contains(&at))
        .min_by_key(|b| b.scope.end - b.scope.start)
}

fn http_signature(text: &str, aliases: &BTreeMap<String, String>) -> bool {
    let text = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let text = text.trim_start_matches(':');
    let text = aliases.get(text).map_or(text, String::as_str);
    text == "typeofglobalThis.fetch"
        || text == "typeofwindow.fetch"
        || text
            .strip_suffix("=>Promise<Response>")
            .is_some_and(|args| args.starts_with('(') && args.ends_with(')'))
}

fn http_parameter<'a>(
    node: &N<'a>,
    aliases: &BTreeMap<String, String>,
    alias_nodes: &BTreeMap<String, N<'a>>,
) -> bool {
    let Some(annotation) = node.field("type") else {
        return false;
    };
    if http_signature(annotation.text().as_ref(), aliases) {
        return true;
    }
    let name = annotation.text();
    let resolved = alias_nodes
        .get(name.trim().trim_start_matches(':').trim())
        .unwrap_or(&annotation);
    node.field("pattern")
        .is_some_and(|p| p.kind().as_ref() == "object_pattern")
        && resolved
            .dfs()
            .filter(|n| n.kind().as_ref() == "property_signature")
            .any(|p| {
                p.field("name").is_some_and(|n| n.text().trim() == "fetch")
                    && p.field("type")
                        .is_some_and(|t| http_signature(t.text().as_ref(), aliases))
            })
}

pub(super) fn correct(
    language: Language,
    root: &N<'_>,
    symbols: &super::symbols::FileSymbolEnvironment,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        return;
    }
    let bindings = bindings(root);
    if bindings.is_empty() {
        return;
    }
    let nodes = root
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "call_expression"
                    | "assignment_expression"
                    | "member_expression"
                    | "subscript_expression"
            )
        })
        .map(|n| ((n.range().start, n.range().end), n))
        .collect::<BTreeMap<_, _>>();
    let aliases = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "type_alias_declaration")
        .filter_map(|n| {
            Some((
                n.field("name")?.text().into_owned(),
                n.field("value")?
                    .text()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let alias_nodes = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "type_alias_declaration")
        .filter_map(|n| Some((n.field("name")?.text().into_owned(), n.field("value")?)))
        .collect::<BTreeMap<_, _>>();
    evidence.retain_mut(|e| {
        if !matches!(
            e.rule_id.as_str(),
            "javascript-outbound-http"
                | "typescript-outbound-http"
                | "tsx-outbound-http"
                | "javascript-browser-navigation"
                | "typescript-browser-navigation"
                | "tsx-browser-navigation"
                | "javascript-browser-url-source"
                | "typescript-browser-url-source"
                | "tsx-browser-url-source"
                | "javascript-browser-cookie-source"
                | "typescript-browser-cookie-source"
                | "tsx-browser-cookie-source"
        ) {
            return true;
        }
        let Some(n) = nodes.get(&(e.location.start.byte_offset, e.location.end.byte_offset)) else {
            return true;
        };
        let at = n.range().start;
        if e.capability == Capability::BrowserInput {
            let observed = n.text();
            let head = observed.split(['.', '[', '?']).next().unwrap_or("").trim();
            return binding(&bindings, head, at).is_none();
        }
        if e.capability == Capability::BrowserNavigation {
            let Some(target) = n.field("left").or_else(|| n.field("function")) else {
                return true;
            };
            let text = target.text();
            let head = text.split(['.', '[']).next().unwrap_or("").trim();
            return binding(&bindings, head, at).is_none();
        }
        if n.field("function")
            .is_none_or(|c| c.text().trim() != "fetch")
        {
            return true;
        }
        let Some(b) = binding(&bindings, "fetch", at) else {
            return true;
        };
        if b.parameter && http_parameter(&b.declaration, &aliases, &alias_nodes) {
            e.tags
                .push("http-interface:declared-fetch-signature".into());
            e.captures.insert(
                "http_callback_definition".into(),
                super::node_operands::capture_at("", e, &b.declaration),
            );
            e.symbol_resolution = Some(SymbolResolution {
                canonical: "delegated-http-fetch".into(),
                observed: "fetch".into(),
                method: SymbolResolutionMethod::Alias,
                confidence: SymbolConfidence::High,
            });
            return true;
        }
        if b.declaration.kind().as_ref() == "import_statement"
            && ["node-fetch", "undici.fetch"]
                .iter()
                .any(|api| symbols.resolve_imported("fetch", api).is_some())
        {
            return true;
        }
        if let Some(value) = b.declaration.field("value") {
            if value.kind().as_ref() == "call_expression"
                && value
                    .field("function")
                    .is_some_and(|n| n.text().trim() == "require")
                && value.field("arguments").is_some_and(|args| {
                    let values = args.children().filter(|n| n.is_named()).collect::<Vec<_>>();
                    values.len() == 1
                        && values[0].kind().as_ref() == "string"
                        && matches!(
                            values[0].text().trim_matches(['\'', '"']),
                            "node-fetch" | "undici"
                        )
                })
                && ["node-fetch", "undici.fetch"]
                    .iter()
                    .any(|api| symbols.resolve_imported("fetch", api).is_some())
            {
                return true;
            }
            let text = value
                .text()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>();
            if matches!(text.as_str(), "globalThis.fetch" | "window.fetch")
                && binding(&bindings, text.split('.').next().unwrap(), at).is_none()
            {
                return true;
            }
        }
        false
    });
}
