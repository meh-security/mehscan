//! Exact template-source and framework file-delivery boundaries. Discovery is
//! local and bounded; this does not infer arbitrary same-named receiver APIs.
use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Provenance,
    Resolution, SymbolConfidence, SymbolResolution, SymbolResolutionMethod,
};

use super::{
    comments::CommentRanges,
    conditional::ConditionalRegions,
    context::enclosing_symbol,
    literals::LiteralEnvironment,
    matcher::{evidence_id, location},
    reachability,
    symbols::FileSymbolEnvironment,
};

type Ast<'a> = Node<'a, StrDoc<SupportLang>>;

#[allow(clippy::too_many_arguments)]
pub(super) fn add_boundaries<'a>(
    path: &str,
    root: &Ast<'a>,
    language: Language,
    symbols: &FileSymbolEnvironment,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let prefix = match language {
        Language::Javascript => "javascript",
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => return,
    };
    let source = root.text();
    if !source.contains("nunjucks") && !source.contains("express") {
        return;
    }
    if !["renderString", "compile", "sendFile", "download"]
        .iter()
        .any(|api| source.contains(api))
    {
        return;
    }
    let functions = root.dfs().filter(|n| is_function(n)).collect::<Vec<_>>();
    let mut responses = super::node_express::typed_response_bindings(root);
    let routers = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "variable_declarator")
        .filter_map(|n| {
            let name = n.field("name")?;
            let value = n.field("value")?;
            let callee = value.field("function")?;
            (name.kind().as_ref() == "identifier"
                && value.kind().as_ref() == "call_expression"
                && ["express", "express.Router"]
                    .iter()
                    .any(|api| exact_imported_api(root, symbols, &callee, api, language)))
            .then(|| name.text().into_owned())
        })
        .collect::<BTreeSet<_>>();

    // Resolve only inline or uniquely named local handlers on identified routers.
    for call in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let Some((receiver, method)) = member(&callee) else {
            continue;
        };
        if !matches!(
            method.as_str(),
            "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "all" | "use"
        ) || !router_receiver(root, &receiver, &routers, 0)
        {
            continue;
        }
        for argument in arguments(&call) {
            let handler = if is_function(&argument) {
                Some(argument)
            } else if argument.kind().as_ref() == "identifier" {
                let matches = functions
                    .iter()
                    .filter(|f| function_name(f).as_deref() == Some(argument.text().as_ref()))
                    .collect::<Vec<_>>();
                (matches.len() == 1 && stable_binding(root, &argument)).then(|| matches[0].clone())
            } else {
                None
            };
            let Some(handler) = handler else { continue };
            let Some(parameters) = handler.field("parameters") else {
                continue;
            };
            let parameters = parameters
                .children()
                .filter(|n| n.is_named())
                .collect::<Vec<_>>();
            // Error middleware has (err, req, res, next).
            let index = if parameters.len() == 4 { 2 } else { 1 };
            let Some(parameter) = parameters.get(index) else {
                continue;
            };
            let pattern = parameter
                .field("pattern")
                .or_else(|| parameter.field("name"))
                .unwrap_or_else(|| parameter.clone());
            if pattern.kind().as_ref() == "identifier" {
                responses
                    .entry(handler.range().start)
                    .or_default()
                    .push(pattern.text().into_owned());
            }
        }
    }

    for call in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        if comments.is_in_comment(call.range()) {
            continue;
        }
        let Some(callee) = call.field("function") else {
            continue;
        };
        let args = arguments(&call);
        let Some(operand) = args.first() else {
            continue;
        };
        let template_api = ["nunjucks.renderString", "nunjucks.compile"]
            .into_iter()
            .find(|api| exact_imported_api(root, symbols, &callee, api, language))
            .map(str::to_string)
            .or_else(|| {
                let (receiver, method) = member(&callee)?;
                if method != "renderString" || receiver.kind().as_ref() != "identifier" {
                    return None;
                }
                let declaration = unique_declaration(root, &receiver)?;
                let value = declaration.field("value")?;
                let target = if value.kind().as_ref() == "new_expression" {
                    value.field("constructor")?
                } else if value.kind().as_ref() == "call_expression" {
                    value.field("function")?
                } else {
                    return None;
                };
                let api = if value.kind().as_ref() == "new_expression" {
                    "nunjucks.Environment"
                } else {
                    "nunjucks.configure"
                };
                exact_imported_api(root, symbols, &target, api, language)
                    .then(|| "nunjucks.Environment.renderString".to_string())
            });
        let (capability, suffix, canonical, role) = if let Some(api) = template_api {
            (
                Capability::TemplateEvaluation,
                "nunjucks-template-source",
                api,
                "template",
            )
        } else {
            let Some((receiver, method)) = member(&callee) else {
                continue;
            };
            if !matches!(method.as_str(), "sendFile" | "download") {
                continue;
            }
            let Some(function) = owner(&call) else {
                continue;
            };
            let Some(names) = responses.get(&function.range().start) else {
                continue;
            };
            if !response_receiver(root, &receiver, names, 0) {
                continue;
            }
            (
                Capability::FilesystemRead,
                "express-file-delivery",
                format!("express.Response.{method}"),
                "path",
            )
        };
        let rule = format!("{prefix}-{suffix}");
        let mut captures = BTreeMap::from([(role.to_string(), capture(path, operand))]);
        let mut literal_facts = BTreeMap::from([(role.to_string(), literals.evaluate(operand))]);
        let mut unresolved_file_options = false;
        if capability == Capability::FilesystemRead {
            // download(path, [filename], [options], [callback]); filename is a
            // display name, never the filesystem operand. Keep options as context.
            let options = if canonical.ends_with(".sendFile") {
                args.get(1)
            } else {
                args.get(1)
                    .filter(|n| n.kind().as_ref() == "object")
                    .or_else(|| args.get(2))
            };
            if let Some(options) = options.filter(|n| !is_function(n)) {
                captures.insert("file_options".into(), capture(path, options));
                unresolved_file_options = options.kind().as_ref() != "object"
                    || options.children().any(|n| {
                        matches!(n.kind().as_ref(), "spread_element" | "method_definition")
                            || n.field("key")
                                .is_some_and(|key| key.kind().as_ref() == "computed_property_name")
                    });
                if options.kind().as_ref() == "object" {
                    for pair in options.children().filter(|n| n.kind().as_ref() == "pair") {
                        if pair
                            .field("key")
                            .is_some_and(|n| n.text().trim_matches(['\'', '"']) == "root")
                            && let Some(value) = pair.field("value")
                        {
                            captures.insert("root".into(), capture(path, &value));
                            literal_facts.insert("root".into(), literals.evaluate(&value));
                        }
                    }
                }
            }
        }
        let mut tags = vec![
            "exact-api-boundary".into(),
            "review-admission:source-sink-required".into(),
            if capability == Capability::TemplateEvaluation {
                "template-source"
            } else {
                "file-delivery"
            }
            .into(),
        ];
        if unresolved_file_options {
            tags.push("file-root:unresolved-options".into());
        }
        evidence.push(Evidence {
            id: evidence_id(path, &rule, call.range().start, call.range().end),
            kind: EvidenceKind::Sink,
            capability,
            location: location(path, &call),
            enclosing_symbol: enclosing_symbol(&call),
            captures,
            cwe_candidates: vec![
                if capability == Capability::TemplateEvaluation {
                    "CWE-1336"
                } else {
                    "CWE-22"
                }
                .into(),
            ],
            tags,
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "ast-grep 0.45.1 + bounded-node-api".into(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&call, literals)),
                availability: Some(conditional.availability_for(call.range())),
                literals: literal_facts,
                ..EvidenceContext::default()
            },
            symbol_resolution: Some(SymbolResolution {
                canonical,
                observed: callee.text().into_owned(),
                method: SymbolResolutionMethod::Alias,
                confidence: SymbolConfidence::High,
            }),
            rule_id: rule,
            related_evidence: Vec::new(),
        });
    }
}

fn member<'a>(node: &Ast<'a>) -> Option<(Ast<'a>, String)> {
    (node.kind().as_ref() == "member_expression").then_some(())?;
    Some((
        node.field("object")?,
        node.field("property")?.text().into_owned(),
    ))
}
fn arguments<'a>(call: &Ast<'a>) -> Vec<Ast<'a>> {
    call.field("arguments")
        .map(|n| {
            n.children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .collect()
        })
        .unwrap_or_default()
}
fn is_function(node: &Ast<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
    )
}
fn owner<'a>(node: &Ast<'a>) -> Option<Ast<'a>> {
    node.ancestors().find(is_function)
}
fn function_name(function: &Ast<'_>) -> Option<String> {
    function
        .field("name")
        .or_else(|| {
            function
                .parent()
                .filter(|n| n.kind().as_ref() == "variable_declarator")
                .and_then(|n| n.field("name"))
        })
        .map(|n| n.text().into_owned())
}
fn capture(path: &str, node: &Ast<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

// Conservative local identity check. A competing declaration or assignment is
// unresolved; this pass does not guess which dynamic receiver wins.
fn stable_binding(root: &Ast<'_>, identifier: &Ast<'_>) -> bool {
    let name = identifier.text();
    let declarations = root
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "variable_declarator"
                && n.field("name").is_some_and(|left| left.text() == name)
                && owner(n).is_none_or(|f| f.range().contains(&identifier.range().start))
        })
        .collect::<Vec<_>>();
    if declarations.len() > 1 {
        return false;
    }
    if let Some(declaration) = declarations.first() {
        if declaration.range().end > identifier.range().start {
            return false;
        }
        if owner(declaration).is_some_and(|f| !f.range().contains(&identifier.range().start)) {
            return false;
        }
        if root
            .dfs()
            .filter(|n| n.kind().as_ref() == "import_statement")
            .any(|n| {
                n.dfs()
                    .any(|child| child.kind().as_ref() == "identifier" && child.text() == name)
            })
        {
            return false;
        }
        // A declaration competing with an enclosing parameter shadows it.
        if identifier
            .ancestors()
            .filter(is_function)
            .filter_map(|f| f.field("parameters"))
            .any(|p| {
                p.dfs()
                    .any(|n| n.kind().as_ref() == "identifier" && n.text() == name)
            })
        {
            return false;
        }
    }
    !root.dfs().any(|n| {
        if n.range().start >= identifier.range().start
            || owner(&n).is_some_and(|f| !f.range().contains(&identifier.range().start))
        {
            return false;
        }
        match n.kind().as_ref() {
            "assignment_expression" | "augmented_assignment_expression" => {
                n.field("left").is_some_and(|left| {
                    left.text() == name
                        || member(&left).is_some_and(|(object, method)| {
                            object.text() == name
                                && matches!(
                                    method.as_str(),
                                    "renderString"
                                        | "compile"
                                        | "configure"
                                        | "Environment"
                                        | "sendFile"
                                        | "download"
                                        | "status"
                                        | "set"
                                        | "header"
                                        | "type"
                                        | "append"
                                        | "attachment"
                                )
                        })
                })
            }
            _ => false,
        }
    })
}
pub(crate) fn exact_imported_api(
    root: &Ast<'_>,
    symbols: &FileSymbolEnvironment,
    callee: &Ast<'_>,
    api: &str,
    language: Language,
) -> bool {
    let observed = callee
        .text()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .replace("?.", ".");
    let head = root_identifier(callee);
    !symbols.has_shadowing_parameter(callee, &observed, language)
        && !callee
            .ancestors()
            .filter(is_function)
            .filter_map(|f| f.field("parameters"))
            .any(|p| {
                p.dfs()
                    .any(|n| n.kind().as_ref() == "identifier" && n.text() == head.text())
            })
        && symbols.resolve_imported(&observed, api).is_some()
        && stable_binding(root, &head)
}
fn root_identifier<'a>(node: &Ast<'a>) -> Ast<'a> {
    node.field("object")
        .map(|n| root_identifier(&n))
        .unwrap_or_else(|| node.clone())
}
fn unique_declaration<'a>(root: &Ast<'a>, receiver: &Ast<'a>) -> Option<Ast<'a>> {
    if !stable_binding(root, receiver) {
        return None;
    }
    let declarations = root
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "variable_declarator"
                && n.field("name")
                    .is_some_and(|name| name.text() == receiver.text())
                && owner(n).is_none_or(|f| f.range().contains(&receiver.range().start))
        })
        .collect::<Vec<_>>();
    if declarations.len() != 1 || declarations[0].range().end > receiver.range().start {
        return None;
    }
    let declaration = &declarations[0];
    let scope = owner(declaration);
    if scope.is_some_and(|f| !f.range().contains(&receiver.range().start)) {
        return None;
    }
    Some(declaration.clone())
}
fn router_receiver<'a>(
    root: &Ast<'a>,
    node: &Ast<'a>,
    routers: &BTreeSet<String>,
    depth: usize,
) -> bool {
    if depth > 3 {
        return false;
    }
    if node.kind().as_ref() == "identifier" {
        return routers.contains(node.text().as_ref())
            && unique_declaration(root, node).is_some()
            && !owner(node)
                .and_then(|n| n.field("parameters"))
                .is_some_and(|p| p.dfs().any(|n| n.text() == node.text()));
    }
    node.field("function")
        .and_then(|n| member(&n))
        .is_some_and(|(receiver, method)| {
            method == "route" && router_receiver(root, &receiver, routers, depth + 1)
        })
}
fn response_receiver(root: &Ast<'_>, node: &Ast<'_>, names: &[String], depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    if node.kind().as_ref() == "identifier" {
        return names.iter().any(|n| n == node.text().as_ref()) && stable_binding(root, node);
    }
    node.field("function")
        .and_then(|n| member(&n))
        .is_some_and(|(receiver, method)| {
            matches!(
                method.as_str(),
                "status" | "set" | "header" | "type" | "attachment" | "append"
            ) && response_receiver(root, &receiver, names, depth + 1)
        })
}
