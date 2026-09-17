use super::identity::{self, Imports, KNode};
use crate::code::matcher::{evidence_id, location};
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Provenance,
    Resolution, SecurityPath, SecurityPathProvenance, SecurityPathState, SecurityPathStep,
    SecurityPathStepKind,
};
use std::collections::BTreeMap;

const SOURCE: &str = "kotlin-spring-mvc-parameter-source";

/// Bounded scalar MVC sources. Model attributes, helpers and cross-file
/// dispatch are intentionally not inferred by this adapter.
pub(in crate::code) fn sources<'a>(
    path: &str,
    root: &KNode<'a>,
    imports: &Imports,
    comments: &crate::code::comments::CommentRanges,
    conditional: &crate::code::conditional::ConditionalRegions,
    literals: &crate::code::literals::LiteralEnvironment<
        'a,
        ast_grep_core::tree_sitter::StrDoc<ast_grep_language::SupportLang>,
    >,
    evidence: &mut Vec<Evidence>,
) {
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return;
    }
    for function in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "function_declaration")
    {
        let Some(owner) = identity::owner(&function) else {
            continue;
        };
        if !function.parent().is_some_and(|body| {
            body.kind().as_ref() == "class_body"
                && body
                    .parent()
                    .is_some_and(|class| class.range() == owner.range())
        }) {
            continue;
        }
        if ![
            "org.springframework.web.bind.annotation.RestController",
            "org.springframework.stereotype.Controller",
        ]
        .iter()
        .any(|a| identity::annotation(root, imports, &owner, a))
        {
            continue;
        }
        if ![
            "GetMapping",
            "PostMapping",
            "PutMapping",
            "PatchMapping",
            "DeleteMapping",
            "RequestMapping",
        ]
        .iter()
        .any(|a| {
            identity::annotation(
                root,
                imports,
                &function,
                &format!("org.springframework.web.bind.annotation.{a}"),
            )
        }) {
            continue;
        }
        let Some(parameters) = identity::named_child(&function, "function_value_parameters") else {
            continue;
        };
        let mut modifiers = None;
        for child in parameters.children() {
            match child.kind().as_ref() {
                "parameter_modifiers" => modifiers = Some(child),
                "parameter" => {
                    let annotations = modifiers.take();
                    let bound = annotations.is_some_and(|a| {
                        [
                            "RequestParam",
                            "PathVariable",
                            "RequestHeader",
                            "CookieValue",
                            "RequestBody",
                        ]
                        .iter()
                        .any(|name| {
                            identity::annotation(
                                root,
                                imports,
                                &a,
                                &format!("org.springframework.web.bind.annotation.{name}"),
                            )
                        })
                    });
                    let Some(name) = identity::name(&child) else {
                        continue;
                    };
                    let Some(ty) = identity::binding_type(root, &child, &name) else {
                        continue;
                    };
                    if !bound || !imports.exact(root, &child, &ty, "kotlin.String") {
                        continue;
                    }
                    let Some(parameter) = identity::named_child(&child, "simple_identifier") else {
                        continue;
                    };
                    evidence.push(Evidence {
                        id: evidence_id(path, SOURCE, child.range().start, child.range().end),
                        kind: EvidenceKind::Source,
                        capability: Capability::HttpRequestData,
                        location: location(path, &child),
                        enclosing_symbol: identity::name(&function),
                        captures: BTreeMap::from([(
                            "parameter".into(),
                            Capture {
                                text: name,
                                location: location(path, &parameter),
                            },
                        )]),
                        cwe_candidates: vec!["CWE-20".into()],
                        tags: vec![
                            "kotlin".into(),
                            "spring-mvc".into(),
                            "request".into(),
                            "attacker-controlled".into(),
                        ],
                        confidence: Confidence::High,
                        provenance: Provenance {
                            resolution: Resolution::Ast,
                            engine: "mehscan Kotlin MVC scalar summary 1".into(),
                            rule_version: 1,
                        },
                        context: EvidenceContext {
                            comment: comments.is_in_comment(child.range()),
                            reachability: Some(crate::code::reachability::classify(
                                &child, literals,
                            )),
                            availability: Some(conditional.availability_for(child.range())),
                            ..EvidenceContext::default()
                        },
                        symbol_resolution: None,
                        rule_id: SOURCE.into(),
                        related_evidence: vec![],
                    });
                }
                _ => {}
            }
        }
    }
}

fn depends<'a>(root: &KNode<'a>, expression: &KNode<'a>, source: &KNode<'a>, depth: usize) -> bool {
    if depth == 0
        || identity::callable(expression).map(|n| n.range())
            != identity::callable(source).map(|n| n.range())
    {
        return false;
    }
    match expression.kind().as_ref() {
        "simple_identifier" | "interpolated_identifier" => {
            let symbol = expression.text();
            if !identity::receiver_unchanged(root, expression, &symbol) {
                return false;
            }
            let Some(binding) = identity::binding(root, expression, &symbol) else {
                return false;
            };
            if binding.range() == source.range() {
                return true;
            }
            if binding.kind().as_ref() != "variable_declaration" {
                return false;
            }
            let Some(property) = binding
                .parent()
                .filter(|n| n.kind().as_ref() == "property_declaration")
            else {
                return false;
            };
            if !property
                .children()
                .any(|n| n.kind().as_ref() == "binding_pattern_kind" && n.text().as_ref() == "val")
            {
                return false;
            }
            property
                .children()
                .filter(|n| n.is_named())
                .last()
                .is_some_and(|value| {
                    value.range() != binding.range() && depends(root, &value, source, depth - 1)
                })
        }
        "string_literal" => expression.children().filter(|n| n.is_named()).any(|n| {
            matches!(
                n.kind().as_ref(),
                "interpolated_identifier" | "interpolated_expression"
            ) && depends(root, &n, source, depth - 1)
        }),
        "additive_expression" => {
            expression
                .children()
                .filter(|n| !n.is_named())
                .all(|n| n.text().as_ref() == "+")
                && expression
                    .children()
                    .filter(|n| n.is_named())
                    .any(|n| depends(root, &n, source, depth - 1))
        }
        "parenthesized_expression" | "interpolated_expression" => expression
            .children()
            .filter(|n| n.is_named())
            .any(|n| depends(root, &n, source, depth - 1)),
        "postfix_expression" if expression.text().trim_end().ends_with("!!") => expression
            .children()
            .find(|n| n.is_named())
            .is_some_and(|n| depends(root, &n, source, depth - 1)),
        "call_expression" => super::path::operands(root, expression, 8).is_some_and(|operands| {
            operands
                .iter()
                .any(|operand| depends(root, operand, source, depth - 1))
        }),
        _ => false,
    }
}

pub(in crate::code) fn paths(
    root: &KNode<'_>,
    evidence: &[Evidence],
    relations: &[mehscan_core::RelationContract],
) -> Vec<SecurityPath> {
    let mut result = vec![];
    for source in evidence.iter().filter(|e| e.rule_id == SOURCE) {
        let Some(parameter) = root.dfs().find(|n| {
            n.range().start == source.location.start.byte_offset
                && n.range().end == source.location.end.byte_offset
                && n.kind().as_ref() == "parameter"
        }) else {
            continue;
        };
        for sink in evidence
            .iter()
            .filter(|e| e.rule_id.starts_with("kotlin-") && e.kind == EvidenceKind::Sink)
        {
            let role = match sink.capability {
                Capability::DatabaseQuery => "query",
                Capability::ProcessExecution => "command",
                Capability::FilesystemRead | Capability::FilesystemWrite => "path",
                _ => continue,
            };
            let Some(relation) = relations.iter().find(|r| {
                r.source.accepts(source.capability)
                    && r.sink.capability == sink.capability
                    && r.sink.input_roles.iter().any(|r| r == role)
                    && r.strategy == mehscan_core::RelationStrategy::BoundedLocalValue
            }) else {
                continue;
            };
            let Some(capture) = sink.captures.get(role) else {
                continue;
            };
            let Some(operand) = root.dfs().find(|n| {
                n.range().start == capture.location.start.byte_offset
                    && n.range().end == capture.location.end.byte_offset
                    && n.kind().as_ref() != "value_argument"
            }) else {
                continue;
            };
            let filesystem = matches!(
                sink.capability,
                Capability::FilesystemRead | Capability::FilesystemWrite
            );
            let path_value = super::path::known_path(root, &operand, 8);
            if filesystem != path_value {
                // Files accepts Path values; SQL and Runtime.exec accept text,
                // not a Path object. Do not turn a known type mismatch into a path.
                continue;
            }
            if !depends(root, &operand, &parameter, 8) {
                continue;
            }
            result.push(SecurityPath {
                id: format!("kotlin-path-{}-{}", source.id, sink.id),
                source_evidence_id: source.id.clone(),
                sink_evidence_id: sink.id.clone(),
                capability: sink.capability,
                cwe_candidates: relation.cwe_candidates.clone(),
                state: SecurityPathState::Propagated,
                steps: vec![
                    SecurityPathStep {
                        kind: SecurityPathStepKind::Source,
                        location: source.location.clone(),
                        evidence_id: Some(source.id.clone()),
                        symbol: source.captures.get("parameter").map(|c| c.text.clone()),
                    },
                    SecurityPathStep {
                        kind: SecurityPathStepKind::Sink,
                        location: sink.location.clone(),
                        evidence_id: Some(sink.id.clone()),
                        symbol: Some(capture.text.clone()),
                    },
                ],
                protection_evidence_ids: vec![],
                uncertainty_reasons: vec![],
                provenance: SecurityPathProvenance {
                    engine: "mehscan bounded Kotlin MVC scalar flow 1".into(),
                    maximum_propagation_depth: 8,
                },
            });
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    fn source_count(body: &str) -> usize {
        let text = format!(
            "import org.springframework.web.bind.annotation.RestController\nimport org.springframework.web.bind.annotation.GetMapping\nimport org.springframework.web.bind.annotation.RequestParam\n{body}"
        );
        let ast = SupportLang::Kotlin.ast_grep(&text);
        let root = ast.root();
        let imports = Imports::build(&root);
        let comments = crate::code::comments::CommentRanges::from_root(&root);
        let conditional = crate::code::conditional::ConditionalRegions::from_source(
            mehscan_core::Language::Kotlin,
            &text,
            &BTreeMap::new(),
        );
        let literals =
            crate::code::literals::LiteralEnvironment::build(&root, mehscan_core::Language::Kotlin);
        let mut evidence = Vec::new();
        sources(
            "app.kt",
            &root,
            &imports,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
        evidence.len()
    }

    #[test]
    fn mvc_sources_require_direct_mapped_controller_string_parameters() {
        assert_eq!(
            source_count(
                "@RestController class C { @GetMapping fun f(@RequestParam value: String) {} }"
            ),
            1
        );
        for body in [
            "class C { @GetMapping fun f(@RequestParam value: String) {} }",
            "@RestController class C { fun f(@RequestParam value: String) {} }",
            "@RestController class C { @GetMapping fun f(@RequestParam value: Long) {} }",
            "@RestController class C { fun outer() { @GetMapping fun f(@RequestParam value: String) {} } }",
        ] {
            assert_eq!(source_count(body), 0, "{body}");
        }
    }

    fn scalar_flow(body: &str) -> bool {
        let text = format!("fun f(input: String) {{ {body} }}");
        let ast = SupportLang::Kotlin.ast_grep(&text);
        let root = ast.root();
        let source = root
            .dfs()
            .find(|n| n.kind().as_ref() == "parameter")
            .unwrap();
        let sink = root
            .dfs()
            .find_map(|n| identity::call(&n).filter(|c| c.callee.text().as_ref() == "consume"))
            .unwrap();
        depends(&root, &sink.arguments[0].value, &source, 8)
    }

    #[test]
    fn flow_preserves_templates_aliases_and_stops_at_kills_or_helpers() {
        for body in [
            "consume(input)",
            "val value = input; consume(value)",
            "consume(\"query '$input'\")",
            "consume(\"query '${input}'\")",
            "consume(\"\"\"query '$input'\"\"\")",
            "consume(\"query \" + input)",
            "consume(java.nio.file.Path.of(input))",
            "consume(java.nio.file.Paths.get(input).normalize())",
            "val root = java.nio.file.Path.of(\"/fixed\"); consume(root.resolve(input))",
        ] {
            assert!(scalar_flow(body), "{body}");
        }
        for body in [
            "consume(\"fixed\")",
            "val input = \"fixed\"; consume(input)",
            "input = \"fixed\"; consume(input)",
            "val value = helper(input); consume(value)",
            "var value = input; value = \"fixed\"; consume(value)",
            "consume(fake.Path.of(input))",
            "consume(java.nio.file.Path.of(\"/fixed\"))",
            "val path = helper(input); consume(path.normalize())",
        ] {
            assert!(!scalar_flow(body), "{body}");
        }
    }
}
