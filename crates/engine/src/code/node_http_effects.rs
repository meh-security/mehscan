//! Direct HTTP effects for review, distinct from unconditional taint summaries.
//! Reuses the project module index and its single parse of exported functions.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HttpEffect {
    definition: Capture,
    primitive: Capture,
    parameter: usize,
}

pub(super) fn known_fetch_api(
    observed: &str,
    imports: &BTreeMap<String, ImportTarget>,
) -> Option<String> {
    external_sink_api(observed, imports)
        .filter(|api| matches!(api.as_str(), "node-fetch" | "undici.fetch"))
}

pub(super) fn collect(
    path: &str,
    module: &str,
    name: &str,
    function: &Node<'_, StrDoc<SupportLang>>,
    call: &CallSite<'_>,
    parameter: usize,
    effects: &mut BTreeMap<NodeSummaryKey, Vec<HttpEffect>>,
) {
    let parameters = function
        .field("parameters")
        .map(|p| {
            p.children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| function.field("parameter").into_iter().collect());
    let Some(p) = parameters.get(parameter) else {
        return;
    };
    let pattern = p
        .field("pattern")
        .or_else(|| p.field("name"))
        .unwrap_or_else(|| p.clone());
    if pattern.kind().as_ref() != "identifier" {
        return; // No flattened destructuring or guessed positional adaptation.
    }
    let effect = HttpEffect {
        definition: Capture {
            text: name.into(),
            location: location(path, function),
        },
        primitive: capture(path, &call.node),
        parameter,
    };
    let list = effects
        .entry((path.into(), format!("{module}.{name}")))
        .or_default();
    if !list.contains(&effect) {
        list.push(effect);
    }
}

impl NodeProjectContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_http_effect_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) {
            return;
        }
        let Some(imports) = self.imports_by_path.get(path) else {
            return;
        };
        let owns_effect = self
            .http_effects
            .range((path.to_string(), String::new())..)
            .next()
            .is_some_and(|((owner, _), _)| owner == path);
        let imports_effect = imports.iter().any(|(name, t)| {
            (!t.source && matches!(t.module.as_str(), "node-fetch" | "undici"))
                || (t.source
                    && resolve_handler(name, "", imports)
                        .and_then(|canonical| resolved_summary_key(path, name, &canonical, imports))
                        .is_some_and(|key| self.http_effects.contains_key(&key)))
        });
        if !owns_effect && !imports_effect {
            return;
        }
        let bindings = SummaryBindingIndex::new(root);
        let current_module = module_path(path).unwrap_or_default();
        for call in root.dfs().filter_map(call_site) {
            if comments.is_in_comment(call.node.range()) {
                continue;
            }
            let observed = compact(&call.callee);
            let head = observed.split('.').next().unwrap_or(&observed);
            if !continuation_binding_is_stable(&bindings, &call.node, head, true) {
                continue;
            }
            let package = known_fetch_api(&observed, imports);
            let effects = resolve_handler(&observed, &current_module, imports)
                .and_then(|canonical| resolved_summary_key(path, &observed, &canonical, imports))
                .and_then(|key| self.http_effects.get(&key));
            let effects = effects.filter(|items| {
                items.first().is_some_and(|first| {
                    items.iter().all(|e| {
                        e.definition.location == first.definition.location
                            && e.parameter == first.parameter
                    })
                })
            });
            if package.is_none() && effects.is_none() {
                continue;
            }
            let parameter = effects.map_or(0, |items| items[0].parameter);
            let Some(endpoint) = call.arguments.get(parameter) else {
                continue;
            };
            let prefix = match language {
                Language::Javascript => "javascript",
                Language::Typescript => "typescript",
                Language::Tsx => "tsx",
                _ => continue,
            };
            let rule_id = format!("{prefix}-outbound-http");
            let id = evidence_id(
                path,
                &rule_id,
                call.node.range().start,
                call.node.range().end,
            );
            let mut captures = BTreeMap::from([("endpoint".into(), capture(path, endpoint))]);
            if let Some(options) = call.arguments.get(parameter + 1) {
                captures.insert("http_options".into(), capture(path, options));
            }
            let mut tags = vec!["http".into(), "network".into(), "ssrf".into()];
            let canonical = if let Some(api) = package {
                api
            } else {
                let effects = effects.unwrap();
                captures.insert(
                    "http_helper_definition".into(),
                    effects[0].definition.clone(),
                );
                for (i, effect) in effects.iter().take(2).enumerate() {
                    captures.insert(
                        format!("http_primitive_{i}_definition"),
                        effect.primitive.clone(),
                    );
                }
                tags.push("http-effect:observed-direct-parameter".into());
                tags.push("http-effect:reachability-and-controls-unproved".into());
                "delegated-http-fetch".into()
            };
            // Existing unconditional summaries own real paths. Enrich that
            // anchor rather than replacing it or manufacturing a second job.
            if let Some(existing) = evidence.iter_mut().find(|e| {
                e.rule_id.ends_with("-parameter-sink-summary")
                    && e.capability == Capability::OutboundNetworkRequest
                    && e.location == location(path, &call.node)
                    && e.captures
                        .get("endpoint")
                        .is_some_and(|c| c.location == capture(path, endpoint).location)
            }) {
                existing.captures.extend(captures);
                for tag in tags {
                    if !existing.tags.contains(&tag) {
                        existing.tags.push(tag);
                    }
                }
                continue;
            }
            if let Some(existing) = evidence.iter_mut().find(|e| e.id == id) {
                existing.captures.extend(captures);
                for tag in tags {
                    if !existing.tags.contains(&tag) {
                        existing.tags.push(tag);
                    }
                }
                continue;
            }
            let mut item = Evidence {
                id,
                rule_id,
                kind: EvidenceKind::Sink,
                capability: Capability::OutboundNetworkRequest,
                location: location(path, &call.node),
                enclosing_symbol: enclosing_symbol(&call.node),
                captures,
                cwe_candidates: vec!["CWE-918".into()],
                tags,
                confidence: Confidence::High,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "ast-grep + direct resolved HTTP effect observation".into(),
                    rule_version: 1,
                },
                context: EvidenceContext {
                    comment: false,
                    reachability: Some(reachability::classify(&call.node, literals)),
                    availability: Some(conditional.availability_for(call.node.range())),
                    literals: BTreeMap::from([("endpoint".into(), literals.evaluate(endpoint))]),
                    ..EvidenceContext::default()
                },
                symbol_resolution: Some(SymbolResolution {
                    canonical,
                    observed: call.callee.clone(),
                    method: SymbolResolutionMethod::Alias,
                    confidence: SymbolConfidence::High,
                }),
                related_evidence: vec![],
            };
            self.annotate(path, root, language, std::slice::from_mut(&mut item));
            evidence.push(item);
        }
    }
}
