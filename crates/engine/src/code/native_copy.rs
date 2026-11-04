//! Source-defined copy effects and the subtraction invariant at their callers.
use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Availability, AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceContext,
    EvidenceKind, Language, Location, Position, Provenance, Resolution, SecurityPath,
    SecurityPathProvenance, SecurityPathState, SecurityPathStep, SecurityPathStepKind,
};

use super::{
    comments::CommentRanges, conditional::ConditionalRegions, context::enclosing_symbol,
    literals::LiteralEnvironment, native_api::NativeApiContext, native_signedness, reachability,
};

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const ENGINE: &str = "tree-sitter c-family defined-copy subtraction relationship";
const PATH_ENGINE: &str = "mehscan c-family defined-copy subtraction relationship 1";
const SOURCE_RULE: &str = "c-family-subtracted-copy-input";
const CONTRACT_RULE: &str = "c-family-defined-copy-contract";
const SINK_RULE: &str = "c-family-subtracted-copy-extent";
const GUARD_RULE: &str = "c-family-copy-subtraction-lower-bound";

#[derive(Clone)]
struct CopyEffect {
    source: usize,
    count: usize,
    parameter_types: Vec<String>,
    count_types: Vec<String>,
    definition: Capture,
    operation: Capture,
    constructor: bool,
    initializer: Option<Capture>,
}

#[derive(Clone)]
enum Rejection {
    Direct,
    Forward(String),
}

#[derive(Clone)]
struct RejectEffect {
    predicate: usize,
    effect: Rejection,
    definition: Capture,
}

#[derive(Default)]
pub(crate) struct NativeCopyProjectContext {
    copies: BTreeMap<(String, usize), CopyEffect>,
    rejects: BTreeMap<String, Vec<Capture>>,
    declarations: BTreeSet<(String, usize)>,
    namespaces: BTreeSet<String>,
    non_integer_types: BTreeSet<String>,
    non_integer_type_names: BTreeSet<String>,
}

impl NativeCopyProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str, &'a BTreeMap<String, bool>)>,
    ) -> Self {
        let mut copies = BTreeMap::<(String, usize), Vec<Option<CopyEffect>>>::new();
        let mut rejects = BTreeMap::<String, Vec<Option<RejectEffect>>>::new();
        let mut signatures = BTreeMap::<(String, usize), BTreeSet<Vec<String>>>::new();
        let mut definitions = BTreeMap::<String, BTreeSet<Vec<String>>>::new();
        let mut declared_signatures = BTreeMap::<String, BTreeSet<Vec<String>>>::new();
        let mut namespaces = BTreeSet::new();
        let mut non_integer_types = BTreeSet::new();
        let trace = std::env::var_os("MEHSCAN_TRACE_NATIVE_COPY").is_some();
        for (path, language, source, symbols) in sources {
            let parser = match language {
                Language::C => SupportLang::C,
                Language::Cpp => SupportLang::Cpp,
                _ => continue,
            };
            let Ok(doc) = StrDoc::try_new(source, parser) else {
                continue;
            };
            let ast = AstGrep::doc(doc);
            let root = ast.root();
            let conditional = ConditionalRegions::from_source(language, source, symbols);
            let api = NativeApiContext::new(&root, language);
            for owner in root.dfs().filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
                )
            }) {
                if conditional.availability_for(owner.range()).state == AvailabilityState::Excluded
                {
                    continue;
                }
                if let Some(name) = owner.field("name") {
                    let prefix = scope_prefix(path, &owner);
                    non_integer_types.insert(if prefix.is_empty() {
                        name.text().into_owned()
                    } else {
                        format!("{prefix}::{}", name.text())
                    });
                }
            }
            for namespace in root
                .dfs()
                .filter(|n| n.kind().as_ref() == "namespace_definition")
            {
                let prefix = scope_prefix(path, &namespace);
                let name = namespace
                    .field("name")
                    .map(|n| compact(n.text().as_ref()))
                    .unwrap_or_else(|| format!("@{path}:{}", namespace.range().start));
                namespaces.insert(if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}::{name}")
                });
            }
            for declarator in root
                .dfs()
                .filter(|n| n.kind().as_ref() == "function_declarator")
            {
                if conditional.availability_for(declarator.range()).state
                    == AvailabilityState::Excluded
                {
                    continue;
                }
                let Some(name) = declarator_name(path, &declarator) else {
                    continue;
                };
                let params = declarator
                    .field("parameters")
                    .into_iter()
                    .flat_map(|n| n.children().collect::<Vec<_>>())
                    .filter(|n| n.is_named())
                    .collect::<Vec<_>>();
                let signature = params.iter().map(parameter_signature).collect::<Vec<_>>();
                declared_signatures
                    .entry(name.clone())
                    .or_default()
                    .insert(signature.clone());
                let key = constructor_key(&name).unwrap_or(name);
                signatures
                    .entry((key, params.len()))
                    .or_default()
                    .insert(signature);
            }
            for function in root
                .dfs()
                .filter(|n| n.kind().as_ref() == "function_definition")
            {
                if conditional.availability_for(function.range()).state
                    == AvailabilityState::Excluded
                {
                    continue;
                }
                let Some(name) = function_name(path, &function) else {
                    continue;
                };
                let params = parameters(&function);
                definitions
                    .entry(name.clone())
                    .or_default()
                    .insert(params.iter().map(parameter_signature).collect());
                let copy_key = constructor_owner(&name, &function).unwrap_or_else(|| name.clone());
                let effect = copy_effect(path, &function, &params, &api, &conditional);
                if trace && (effect.is_some() || function.text().contains("copy_n")) {
                    eprintln!(
                        "mehscan_native_copy {}",
                        serde_json::json!({"phase":"definition", "path":path, "name":name,
                        "arity":params.len(), "signature":params.iter().map(parameter_signature).collect::<Vec<_>>(),
                        "copy":effect.is_some(), "parameters":params.iter().map(parameter_name).collect::<Vec<_>>() })
                    );
                }
                copies
                    .entry((copy_key, params.len()))
                    .or_default()
                    .push(effect);
                rejects.entry(name).or_default().push(reject_effect(
                    path,
                    &function,
                    &params,
                    &conditional,
                ));
            }
        }
        for (name, signatures) in &declared_signatures {
            if signatures.iter().any(|signature| {
                definitions
                    .get(name)
                    .is_none_or(|defined| !defined.contains(signature))
            }) {
                rejects.entry(name.clone()).or_default().push(None);
            }
        }
        // A noncopy or ambiguous same-arity overload blocks propagation. The
        // source call remains available to ordinary investigation.
        let copies = copies
            .into_iter()
            .filter_map(|(key, values)| {
                if trace && values.iter().any(Option::is_some) {
                    eprintln!("mehscan_native_copy {}", serde_json::json!({"phase":"overloads", "key":key,
                        "bodies":values.len(), "signatures":signatures.get(&key),
                        "body_signatures":values.iter().flatten().map(|v| &v.parameter_types).collect::<Vec<_>>() }));
                }
                (values.len() == 1)
                    .then(|| values.into_iter().next().flatten())
                    .flatten()
                    .filter(|effect| {
                        // Nonconstructor member calls need receiver/dispatch
                        // binding beyond this free-helper effect index.
                        let bound_target = effect.constructor
                            || key.0.rsplit_once("::").is_none_or(|(owner, _)| !non_integer_types.contains(owner));
                        let integer_count = !effect.count_types.iter().any(|name| non_integer_types.contains(name));
                        let matching_declarations = signatures.get(&key).is_some_and(|declared| {
                            declared
                                .iter()
                                .all(|signature| signature == &effect.parameter_types)
                        });
                        bound_target && integer_count && matching_declarations
                    })
                    .map(|effect| (key, effect))
            })
            .collect();
        let mut proved = BTreeMap::<String, Vec<Capture>>::new();
        for _ in 0..4 {
            let mut additions = Vec::new();
            for (name, variants) in &rejects {
                if proved.contains_key(name) || variants.iter().any(Option::is_none) {
                    continue;
                }
                let variants = variants.iter().flatten().collect::<Vec<_>>();
                if variants.is_empty() || variants.iter().any(|v| v.predicate != 0) {
                    continue;
                }
                let direct = variants
                    .iter()
                    .any(|v| matches!(v.effect, Rejection::Direct));
                let mut support = Vec::new();
                let valid = variants.iter().all(|variant| {
                    support.push(variant.definition.clone());
                    match &variant.effect {
                        Rejection::Direct => true,
                        // This establishes return-implies-predicate, not a
                        // termination claim for recursive overload dispatch.
                        Rejection::Forward(target) if target == name && direct => true,
                        Rejection::Forward(target) => {
                            proved.get(target).is_some_and(|definitions| {
                                support.extend(definitions.iter().cloned());
                                true
                            })
                        }
                    }
                });
                if valid {
                    additions.push((name.clone(), support));
                }
            }
            if additions.is_empty() {
                break;
            }
            proved.extend(additions);
        }
        let non_integer_type_names = non_integer_types
            .iter()
            .filter_map(|name| name.rsplit("::").next().map(str::to_string))
            .collect();
        Self {
            copies,
            rejects: proved,
            declarations: signatures.into_keys().collect(),
            namespaces,
            non_integer_types,
            non_integer_type_names,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        root: &N<'tree>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        api: &NativeApiContext,
        evidence: &mut Vec<Evidence>,
    ) -> Vec<SecurityPath> {
        if !matches!(language, Language::C | Language::Cpp) {
            return Vec::new();
        }
        let mut paths = Vec::new();
        for node in root
            .dfs()
            .filter(|n| matches!(n.kind().as_ref(), "call_expression" | "return_statement"))
        {
            let Some((source, count, effect, bindings)) =
                self.consumer(path, &node, api, conditional)
            else {
                continue;
            };
            let Some((value, offset)) = subtraction(&count) else {
                continue;
            };
            let Some(integer) = native_signedness::integer_declaration(&node, &value) else {
                continue;
            };
            if integer.nominal
                || comments.is_in_comment(node.range())
                || conditional.availability_for(node.range()).state == AvailabilityState::Excluded
                || node.dfs().any(|n| n.kind().as_ref() == "ERROR")
                || integer
                    .declaration
                    .dfs()
                    .any(|n| n.kind().as_ref() == "ERROR")
                || !compatible(
                    &conditional.availability_for(integer.declaration.range()),
                    &conditional.availability_for(node.range()),
                )
            {
                continue;
            }
            if self.non_integer_type_names.contains(
                integer
                    .resolved_type
                    .rsplit("::")
                    .next()
                    .unwrap_or(&integer.resolved_type),
            ) && self
                .lookup_groups(path, &count, &integer.resolved_type, conditional, 0)
                .iter()
                .flatten()
                .any(|(name, _)| self.non_integer_types.contains(name))
            {
                continue;
            }
            let Some(scope) = node.ancestors().find(|n| {
                matches!(
                    n.kind().as_ref(),
                    "function_definition" | "lambda_expression"
                )
            }) else {
                continue;
            };
            let stable_operands = !integer.volatile && operand_evaluation_is_pure(&node, &source);
            let guard = stable_operands
                .then(|| {
                    self.lower_bound(
                        path,
                        &scope,
                        &node,
                        &value,
                        offset,
                        integer.signed,
                        &integer.declaration,
                        conditional,
                        api,
                    )
                })
                .flatten();
            let fact = |anchor: &N<'tree>, rule, kind, capability, captures, related| {
                make_evidence(
                    path,
                    anchor,
                    rule,
                    kind,
                    capability,
                    captures,
                    related,
                    comments,
                    conditional,
                    literals,
                )
            };
            let mut input_captures = BTreeMap::from([
                (
                    "value".into(),
                    capture(path, &count.field("left").expect("subtraction")),
                ),
                ("declaration".into(), capture(path, &integer.declaration)),
            ]);
            if let Some(alias) = &integer.alias {
                input_captures.insert("type_definition".into(), capture(path, alias));
            }
            let input = fact(
                &count,
                SOURCE_RULE,
                EvidenceKind::Source,
                Capability::IntegerExtentInput,
                input_captures,
                vec![],
            );
            let mut contracts = BTreeMap::from([("source_operand".into(), capture(path, &source))]);
            for (index, binding) in bindings.into_iter().enumerate() {
                contracts.insert(format!("binding_{index}"), binding);
            }
            if let Some(effect) = effect {
                contracts.insert("definition".into(), effect.definition.clone());
                contracts.insert("defined_copy".into(), effect.operation.clone());
                if let Some(initializer) = &effect.initializer {
                    contracts.insert("member_initializers".into(), initializer.clone());
                }
            } else {
                contracts.insert("standard_copy".into(), capture(path, &node));
            }
            let mut contract = fact(
                &node,
                CONTRACT_RULE,
                EvidenceKind::Resource,
                Capability::MemoryCopyContract,
                contracts,
                vec![],
            );
            if effect.is_some_and(|e| e.initializer.is_some()) {
                contract
                    .tags
                    .push("copy-effect:member-initializer-effects-unresolved".into());
            }
            let protection = guard.as_ref().map(|(check, support)| {
                let mut captures =
                    BTreeMap::from([("lower_bound_check".into(), capture(path, check))]);
                for (index, definition) in support.iter().enumerate() {
                    captures.insert(format!("rejecting_definition_{index}"), definition.clone());
                }
                fact(
                    check,
                    GUARD_RULE,
                    EvidenceKind::Validation,
                    Capability::MemoryExtentLowerBoundValidation,
                    captures,
                    vec![input.id.clone()],
                )
            });
            let mut related = vec![input.id.clone(), contract.id.clone()];
            if let Some(protection) = &protection {
                related.push(protection.id.clone());
            }
            let mut sink = fact(
                &node,
                SINK_RULE,
                EvidenceKind::Sink,
                Capability::SubtractedMemoryExtent,
                BTreeMap::from([
                    ("extent".into(), capture(path, &count)),
                    ("source".into(), capture(path, &source)),
                ]),
                related,
            );
            if !stable_operands {
                sink.tags
                    .push("copy-effect:operand-evaluation-unresolved".into());
            }
            let state = if protection.is_some() {
                SecurityPathState::Protected
            } else {
                SecurityPathState::Unknown
            };
            let mut steps = vec![
                step(SecurityPathStepKind::Source, &input),
                step(SecurityPathStepKind::Assignment, &contract),
            ];
            if let Some(protection) = &protection {
                steps.push(step(SecurityPathStepKind::Protection, protection));
            }
            steps.push(step(SecurityPathStepKind::Sink, &sink));
            paths.push(SecurityPath {
                id: stable_id("path", &format!("{}\0{}\0{state:?}", input.id, sink.id)),
                source_evidence_id: input.id.clone(),
                sink_evidence_id: sink.id.clone(),
                capability: Capability::SubtractedMemoryExtent,
                cwe_candidates: cwes(),
                state,
                steps,
                protection_evidence_ids: protection
                    .as_ref()
                    .map(|p| vec![p.id.clone()])
                    .unwrap_or_default(),
                uncertainty_reasons: if state == SecurityPathState::Protected {
                    vec![]
                } else {
                    vec![
                        "subtracted_copy_count_lower_bound_unproven".into(),
                        "copy_execution_and_effective_conversion_require_confirmation".into(),
                    ]
                },
                provenance: SecurityPathProvenance {
                    engine: PATH_ENGINE.into(),
                    maximum_propagation_depth: usize::from(effect.is_some()),
                },
            });
            evidence.extend([input, contract]);
            if let Some(protection) = protection {
                evidence.push(protection);
            }
            evidence.push(sink);
        }
        paths
    }

    fn consumer<'a>(
        &self,
        path: &str,
        node: &N<'a>,
        api: &NativeApiContext,
        conditional: &ConditionalRegions,
    ) -> Option<(N<'a>, N<'a>, Option<&CopyEffect>, Vec<Capture>)> {
        if node.kind().as_ref() == "return_statement" {
            let list = node
                .children()
                .find(|n| n.kind().as_ref() == "initializer_list")?;
            let args = list.children().filter(|n| n.is_named()).collect::<Vec<_>>();
            if !args.iter().any(|n| subtraction(n).is_some()) {
                return None;
            }
            let function = node.ancestors().find(|n| {
                matches!(
                    n.kind().as_ref(),
                    "function_definition" | "lambda_expression"
                )
            })?;
            if function.kind().as_ref() != "function_definition" {
                return None;
            }
            let owner = callable_name(function.field("type")?.text().as_ref())?;
            let ty = function.field("type")?;
            let (effect, mut bindings) =
                self.resolve_copy(path, &ty, &owner, args.len(), conditional)?;
            bindings.push(capture(path, &ty));
            if !effect.constructor {
                return None;
            }
            return Some((
                args.get(effect.source)?.clone(),
                args.get(effect.count)?.clone(),
                Some(effect),
                bindings,
            ));
        }
        let args = arguments(node);
        if !args.iter().any(|n| subtraction(n).is_some()) {
            return None;
        }
        if let Some(operation) = api.call_name(node) {
            if !node.field("function")?.text().contains("::") && self.class_context(path, node) {
                // A separately declared member can shadow a free standard API.
                // This pass does not bind an implicit receiver across headers.
                return None;
            }
            // copy_n's signed count has different semantics from a C size_t
            // parameter. Its typed helper/constructor mapping is handled above.
            if operation == "copy_n" {
                return None;
            }
            let (source, count) = copy_roles(operation)?;
            return Some((
                args.get(source)?.clone(),
                args.get(count)?.clone(),
                None,
                vec![],
            ));
        }
        let observed = callable_name(node.field("function")?.text().as_ref())?;
        if !observed.contains("::") && self.class_context(path, node) {
            return None;
        }
        if api.local_shadow(node, observed.split("::").next()?) {
            return None;
        }
        let (effect, bindings) =
            self.resolve_copy(path, node, &observed, args.len(), conditional)?;
        if effect.constructor {
            return None;
        }
        Some((
            args.get(effect.source)?.clone(),
            args.get(effect.count)?.clone(),
            Some(effect),
            bindings,
        ))
    }

    fn resolve_copy(
        &self,
        path: &str,
        node: &N<'_>,
        observed: &str,
        arity: usize,
        conditional: &ConditionalRegions,
    ) -> Option<(&CopyEffect, Vec<Capture>)> {
        for group in self.lookup_groups(path, node, observed, conditional, 0) {
            let matches = group
                .into_iter()
                .filter(|(name, _)| self.declarations.contains(&(name.clone(), arity)))
                .collect::<Vec<_>>();
            if !matches.is_empty() {
                if matches.len() != 1 {
                    return None;
                }
                let (name, bindings) = matches.into_iter().next()?;
                return self
                    .copies
                    .get(&(name, arity))
                    .map(|effect| (effect, bindings));
            }
        }
        None
    }

    fn class_context(&self, path: &str, node: &N<'_>) -> bool {
        node.ancestors()
            .any(|n| matches!(n.kind().as_ref(), "class_specifier" | "struct_specifier"))
            || node
                .ancestors()
                .find(|n| n.kind().as_ref() == "function_definition")
                .and_then(|n| function_name(path, &n))
                .and_then(|name| name.rsplit_once("::").map(|(owner, _)| owner.to_string()))
                .is_some_and(|owner| self.non_integer_types.contains(&owner))
    }

    fn lookup_groups(
        &self,
        path: &str,
        node: &N<'_>,
        observed: &str,
        conditional: &ConditionalRegions,
        depth: usize,
    ) -> Vec<Vec<(String, Vec<Capture>)>> {
        if depth > 4 {
            return vec![];
        }
        if observed.starts_with("::") {
            return vec![vec![(
                observed.trim_start_matches("::").to_string(),
                vec![],
            )]];
        }
        let Some(root) = node.ancestors().last() else {
            return vec![];
        };
        let imports = root
            .dfs()
            .filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "using_declaration" | "alias_declaration" | "namespace_alias_definition"
                )
            })
            .filter(|n| {
                n.range().end <= node.range().start
                    && import_scope(n).is_some_and(|scope| contains(&scope, node))
            })
            .collect::<Vec<_>>();
        let first = observed.split("::").next().unwrap_or(observed);
        let mut aliases = Vec::new();
        for import in &imports {
            let text = compact(import.text().as_ref());
            let alias = match import.kind().as_ref() {
                "namespace_alias_definition" => text
                    .strip_prefix("namespace")
                    .and_then(|s| s.strip_suffix(';'))
                    .and_then(|s| s.split_once('='))
                    .map(|(name, target)| (name.to_string(), target.to_string(), true)),
                "alias_declaration" => {
                    import
                        .field("name")
                        .zip(import.field("type"))
                        .map(|(name, target)| {
                            (
                                name.text().into_owned(),
                                compact(target.text().as_ref()),
                                false,
                            )
                        })
                }
                "using_declaration" if !text.starts_with("usingnamespace") => text
                    .strip_prefix("using")
                    .and_then(|s| s.strip_suffix(';'))
                    .and_then(|target| {
                        target
                            .rsplit_once("::")
                            .map(|(_, name)| (name.to_string(), target.to_string(), false))
                    }),
                _ => None,
            };
            if let Some((name, target, namespace)) = alias.filter(|(name, _, _)| name == first) {
                let _ = name;
                aliases.push((
                    import_scope(import)
                        .map(|n| n.range().len())
                        .unwrap_or(usize::MAX),
                    usize::MAX - import.range().start,
                    import.clone(),
                    target,
                    namespace,
                ));
            }
        }
        aliases.sort_by_key(|(size, start, _, _, _)| (*size, *start));
        if let Some((_, _, import, target, namespace)) = aliases.first() {
            if !compatible(
                &conditional.availability_for(import.range()),
                &conditional.availability_for(node.range()),
            ) || callable_name(target).is_none()
            {
                return vec![];
            }
            for group in self.lookup_groups(path, import, target, conditional, depth + 1) {
                let targets = group
                    .into_iter()
                    .filter(|(name, _)| {
                        if *namespace {
                            self.namespaces.contains(name)
                        } else {
                            self.non_integer_types.contains(name)
                                || self
                                    .declarations
                                    .iter()
                                    .any(|(declared, _)| declared == name)
                        }
                    })
                    .collect::<Vec<_>>();
                if !targets.is_empty() {
                    if targets.len() != 1 {
                        return vec![];
                    }
                    let (target, mut support) = targets.into_iter().next().expect("one target");
                    support.push(capture(path, import));
                    return vec![vec![(
                        format!("{target}{}", &observed[first.len()..]),
                        support,
                    )]];
                }
            }
            return vec![];
        }
        let mut additions = BTreeMap::<String, Vec<(String, Vec<Capture>)>>::new();
        for import in imports {
            let text = compact(import.text().as_ref());
            let Some(target) = text
                .strip_prefix("usingnamespace")
                .and_then(|s| s.strip_suffix(';'))
            else {
                continue;
            };
            if !compatible(
                &conditional.availability_for(import.range()),
                &conditional.availability_for(node.range()),
            ) {
                return vec![];
            }
            let mut resolved = None;
            for group in self.lookup_groups(path, &import, target, conditional, depth + 1) {
                let targets = group
                    .into_iter()
                    .filter(|(name, _)| self.namespaces.contains(name))
                    .collect::<Vec<_>>();
                if !targets.is_empty() {
                    if targets.len() != 1 {
                        return vec![];
                    }
                    resolved = targets.into_iter().next();
                    break;
                }
            }
            let Some((target, mut support)) = resolved else {
                continue;
            };
            let local = scope_prefix(path, &import);
            let left = local
                .split("::")
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            let right = target.split("::").collect::<Vec<_>>();
            let shared = left
                .iter()
                .zip(&right)
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| *a)
                .collect::<Vec<_>>()
                .join("::");
            support.push(capture(path, &import));
            additions
                .entry(shared)
                .or_default()
                .push((format!("{target}::{observed}"), support));
        }
        let mut groups = Vec::new();
        for name in qualified_names(path, node, observed) {
            let prefix = name
                .strip_suffix(observed)
                .unwrap_or("")
                .trim_end_matches("::");
            let mut candidates = vec![(name.clone(), vec![])];
            if let Some(imported) = additions.remove(prefix) {
                candidates.extend(imported);
            }
            let mut distinct = BTreeMap::new();
            for (name, bindings) in candidates {
                distinct.entry(name).or_insert(bindings);
            }
            groups.push(distinct.into_iter().collect());
        }
        groups
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_bound<'a>(
        &self,
        path: &str,
        scope: &N<'a>,
        consumer: &N<'a>,
        value: &str,
        offset: u128,
        signed: bool,
        declaration: &N<'_>,
        conditional: &ConditionalRegions,
        api: &NativeApiContext,
    ) -> Option<(N<'a>, Vec<Capture>)> {
        let valid = |check: &N<'_>| {
            !check.dfs().any(|n| n.kind().as_ref() == "ERROR")
                && native_signedness::declarator_at(check, value)
                    .is_some_and(|(binding, _)| binding.range() == declaration.range())
                && compatible(
                    &conditional.availability_for(check.range()),
                    &conditional.availability_for(consumer.range()),
                )
                && !native_signedness::changed_between(
                    scope,
                    value,
                    check.range().start,
                    consumer.range().start,
                )
                && !native_signedness::guard_bypassed(scope, check, consumer)
                && !native_signedness::loop_changes_after_use(consumer, check, value)
        };
        for ancestor in consumer
            .ancestors()
            .filter(|n| n.kind().as_ref() == "if_statement")
        {
            let condition = ancestor.field("condition")?;
            if ancestor
                .field("consequence")
                .is_some_and(|body| contains(&body, consumer))
                && bound(&condition, value, offset, true, signed)
                && valid(&condition)
            {
                return Some((condition, vec![]));
            }
        }
        for statement in scope.dfs().filter(|n| {
            n.kind().as_ref() == "if_statement" && n.range().end < consumer.range().start
        }) {
            let Some(condition) = statement.field("condition") else {
                continue;
            };
            if statement
                .field("consequence")
                .is_some_and(|body| native_signedness::rejecting_branch(&body))
                && super::context::precedes_in_block(&statement, consumer)
                && native_signedness::dominates_use(&statement, consumer)
                && bound(&condition, value, offset, false, signed)
                && valid(&condition)
            {
                return Some((condition, vec![]));
            }
        }
        for call in scope.dfs().filter(|n| {
            n.kind().as_ref() == "call_expression" && n.range().end < consumer.range().start
        }) {
            if !super::context::precedes_in_block(&call, consumer)
                || !native_signedness::dominates_use(&call, consumer)
            {
                continue;
            }
            let Some(function) = call
                .field("function")
                .and_then(|n| callable_name(n.text().as_ref()))
            else {
                continue;
            };
            if !function.contains("::") && self.class_context(path, &call) {
                continue;
            }
            if api.local_shadow(&call, function.split("::").next()?) {
                continue;
            }
            let Some(predicate) = arguments(&call).first().cloned() else {
                continue;
            };
            if !bound(&predicate, value, offset, true, signed) || !valid(&call) {
                continue;
            }
            for group in self.lookup_groups(path, &call, &function, conditional, 0) {
                let matches = group
                    .into_iter()
                    .filter(|(name, _)| {
                        self.declarations
                            .iter()
                            .any(|(declared, _)| declared == name)
                    })
                    .collect::<Vec<_>>();
                if !matches.is_empty() {
                    if matches.len() == 1 {
                        let (name, mut bindings) = matches.into_iter().next()?;
                        if let Some(support) = self.rejects.get(&name) {
                            bindings.extend(support.iter().cloned());
                            return Some((call, bindings));
                        }
                    }
                    break;
                }
            }
        }
        None
    }
}

fn qualified_names(path: &str, node: &N<'_>, observed: &str) -> Vec<String> {
    if observed.starts_with("::") {
        return vec![observed.trim_start_matches("::").to_string()];
    }
    let namespace = scope_prefix(path, node);
    let mut result = Vec::new();
    let mut prefix = namespace.as_str();
    while !prefix.is_empty() {
        result.push(format!("{prefix}::{observed}"));
        prefix = prefix.rsplit_once("::").map(|(head, _)| head).unwrap_or("");
    }
    result.push(observed.to_string());
    result
}

fn import_scope<'a>(node: &N<'a>) -> Option<N<'a>> {
    node.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "compound_statement"
                | "namespace_definition"
                | "translation_unit"
                | "field_declaration_list"
        )
    })
}

fn operand_evaluation_is_pure(consumer: &N<'_>, source: &N<'_>) -> bool {
    if !pointer_expression(source) {
        return false;
    }
    let args = if consumer.kind().as_ref() == "return_statement" {
        consumer
            .children()
            .find(|n| n.kind().as_ref() == "initializer_list")
            .into_iter()
            .flat_map(|n| n.children().collect::<Vec<_>>())
            .filter(|n| n.is_named())
            .collect()
    } else {
        arguments(consumer)
    };
    if !args
        .iter()
        .all(|arg| pointer_expression(arg) || integer_expression(arg))
    {
        return false;
    }
    // Arguments may run before the count expression. A body-defined copy does
    // not establish that arbitrary caller-side conversions or callbacks are pure.
    consumer.dfs().all(|node| match node.kind().as_ref() {
        "assignment_expression" | "update_expression" => false,
        "call_expression" => node.range() == consumer.range(),
        _ => true,
    })
}

fn pointer_expression(node: &N<'_>) -> bool {
    match node.kind().as_ref() {
        "identifier" => native_signedness::declarator_at(node, node.text().trim()).is_some_and(
            |(_, declarator)| {
                declarator
                    .dfs()
                    .any(|n| matches!(n.kind().as_ref(), "pointer_declarator" | "array_declarator"))
                    && !declarator
                        .dfs()
                        .any(|n| n.kind().as_ref() == "function_declarator")
            },
        ),
        "parenthesized_expression" => node
            .children()
            .find(|n| n.is_named())
            .is_some_and(|n| pointer_expression(&n)),
        "binary_expression" => {
            let (Some(left), Some(right), Some(op)) =
                (node.field("left"), node.field("right"), operator(node))
            else {
                return false;
            };
            matches!(op.as_str(), "+" | "-")
                && pointer_expression(&left)
                && integer_expression(&right)
                || op == "+" && integer_expression(&left) && pointer_expression(&right)
        }
        _ => false,
    }
}

fn integer_expression(node: &N<'_>) -> bool {
    match node.kind().as_ref() {
        "number_literal" => number(node.text().as_ref()).is_some(),
        "identifier" => native_signedness::integer_declaration(node, node.text().trim())
            .is_some_and(|ty| !ty.nominal),
        "parenthesized_expression" => node
            .children()
            .find(|n| n.is_named())
            .is_some_and(|n| integer_expression(&n)),
        "binary_expression" => {
            matches!(operator(node).as_deref(), Some("+" | "-" | "*"))
                && node.field("left").is_some_and(|n| integer_expression(&n))
                && node.field("right").is_some_and(|n| integer_expression(&n))
        }
        _ => false,
    }
}

fn subtraction(node: &N<'_>) -> Option<(String, u128)> {
    if node.kind().as_ref() != "binary_expression" || operator(node)? != "-" {
        return None;
    }
    let left = node.field("left")?;
    let right = node.field("right")?;
    let value = left.text();
    if !identifier(value.trim()) {
        return None;
    }
    let offset = number(right.text().as_ref())?;
    (offset > 0).then(|| (value.trim().to_string(), offset))
}

fn operator(node: &N<'_>) -> Option<String> {
    let left = node.field("left")?;
    let right = node.field("right")?;
    node.text()
        .get(left.range().end - node.range().start..right.range().start - node.range().start)
        .map(|s| s.trim().to_string())
}

fn bound(node: &N<'_>, value: &str, offset: u128, positive: bool, signed: bool) -> bool {
    if node.kind().as_ref() == "condition_clause"
        && node.dfs().any(|n| n.kind().as_ref() == "declaration")
    {
        return false;
    }
    if matches!(
        node.kind().as_ref(),
        "parenthesized_expression" | "condition_clause"
    ) {
        return node
            .field("value")
            .or_else(|| node.children().find(|n| n.is_named()))
            .is_some_and(|n| bound(&n, value, offset, positive, signed));
    }
    if !signed
        && offset == 1
        && (positive && node.text().trim() == value
            || !positive && compact(node.text().as_ref()) == format!("!{value}"))
    {
        return true;
    }
    let Some(op) = operator(node) else {
        return false;
    };
    if op == "&&" && positive || op == "||" && !positive {
        return ["left", "right"]
            .iter()
            .filter_map(|field| node.field(field))
            .any(|n| bound(&n, value, offset, positive, signed));
    }
    let (Some(left), Some(right)) = (node.field("left"), node.field("right")) else {
        return false;
    };
    let (op, literal) = if left.text().trim() == value {
        (op, right.text().into_owned())
    } else if right.text().trim() == value {
        (
            match op.as_str() {
                ">=" => "<=",
                ">" => "<",
                "<=" => ">=",
                "<" => ">",
                _ => return false,
            }
            .to_string(),
            left.text().into_owned(),
        )
    } else {
        return false;
    };
    if signed && !signed_literal(&literal) {
        return false;
    }
    number(&literal).is_some_and(|limit| match (positive, op.as_str()) {
        (true, ">=") | (false, "<") => limit >= offset,
        (true, ">") | (false, "<=") => limit.checked_add(1).is_some_and(|limit| limit >= offset),
        (true, "!=") | (false, "==") if !signed && limit == 0 => offset == 1,
        _ => false,
    })
}

fn number(text: &str) -> Option<u128> {
    let text = text
        .trim()
        .trim_end_matches(['u', 'U', 'l', 'L'])
        .replace('\'', "");
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        u128::from_str_radix(binary, 2).ok()
    } else if text.len() > 1 && text.starts_with('0') {
        u128::from_str_radix(&text[1..], 8).ok()
    } else {
        text.parse().ok()
    }
}

fn signed_literal(text: &str) -> bool {
    if text.contains(['u', 'U']) {
        return false;
    }
    let Some(value) = number(text) else {
        return false;
    };
    let text = text.trim().trim_end_matches(['l', 'L']);
    if text.starts_with('0') && text.len() > 1 {
        value <= 32767
    } else {
        value <= i64::MAX as u128
    }
}

fn compatible(proof: &Availability, consumer: &Availability) -> bool {
    proof.state == AvailabilityState::Always
        || proof.state != AvailabilityState::Excluded && proof == consumer
}

fn contains(parent: &N<'_>, child: &N<'_>) -> bool {
    parent.range().start <= child.range().start && child.range().end <= parent.range().end
}

#[allow(clippy::too_many_arguments)]
fn make_evidence<'a>(
    path: &str,
    node: &N<'a>,
    rule: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    related_evidence: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: stable_id(
            "ev",
            &format!(
                "{path}\0{rule}\0{}:{}",
                node.range().start,
                node.range().end
            ),
        ),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes(),
        tags: vec![
            "native".into(),
            "defined-copy-extent".into(),
            "parse-recovery:locally-complete".into(),
            "invariant:subtraction-lower-bound-only".into(),
        ],
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.into(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule.into(),
        related_evidence,
    }
}

fn step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: evidence.location.clone(),
        evidence_id: Some(evidence.id.clone()),
        symbol: None,
    }
}
fn cwes() -> Vec<String> {
    vec!["CWE-191".into(), "CWE-195".into(), "CWE-125".into()]
}
fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

fn copy_effect(
    path: &str,
    function: &N<'_>,
    params: &[N<'_>],
    api: &NativeApiContext,
    conditional: &ConditionalRegions,
) -> Option<CopyEffect> {
    let body = function.field("body")?;
    if function.dfs().any(|n| n.kind().as_ref() == "ERROR") {
        return None;
    }
    let names = params
        .iter()
        .map(parameter_name)
        .collect::<Option<Vec<_>>>()?;
    let calls = body
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
        .filter(|n| {
            n.ancestors()
                .find(|a| a.kind().as_ref() == "function_definition")
                .is_some_and(|a| a.range() == function.range())
        })
        .filter(|n| {
            !n.ancestors()
                .take_while(|a| a.range() != function.range())
                .any(|a| {
                    matches!(
                        a.kind().as_ref(),
                        "if_statement"
                            | "for_statement"
                            | "while_statement"
                            | "do_statement"
                            | "switch_statement"
                            | "lambda_expression"
                            | "conditional_expression"
                    )
                })
        })
        .filter_map(|call| {
            let operation = api.call_name(&call)?;
            let (source, count) = copy_roles(operation)?;
            let args = arguments(&call);
            let source_name = args.get(source)?.text();
            let count_name = args.get(count)?.text();
            let source_param = names.iter().position(|name| name == source_name.trim())?;
            let count_param = names.iter().position(|name| name == count_name.trim())?;
            let integer = native_signedness::integer_declaration(&call, &names[count_param])?;
            if integer.nominal || operation == "copy_n" && integer.signed {
                return None;
            }
            if !params[source_param]
                .field("declarator")?
                .dfs()
                .any(|n| matches!(n.kind().as_ref(), "pointer_declarator" | "array_declarator"))
            {
                return None;
            }
            if conditional.availability_for(call.range()).state != AvailabilityState::Always {
                return None;
            }
            if body.dfs().any(|n| {
                n.range().start < call.range().start
                    && matches!(
                        n.kind().as_ref(),
                        "return_statement" | "throw_statement" | "goto_statement"
                    )
            }) {
                return None;
            }
            if names.iter().any(|name| {
                native_signedness::changed_between(
                    function,
                    name,
                    function.range().start,
                    call.range().start,
                )
            }) {
                return None;
            }
            let initializer = function
                .children()
                .find(|n| n.kind().as_ref() == "field_initializer_list");
            // A visible mutation in an initializer stops the mapping. An
            // ordinary member initializer is retained as an explicit boundary.
            if initializer.as_ref().is_some_and(|init| {
                init.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "assignment_expression" | "update_expression"
                    )
                })
            }) {
                return None;
            }
            Some(CopyEffect {
                source: source_param,
                count: count_param,
                parameter_types: params.iter().map(parameter_signature).collect(),
                count_types: qualified_names(path, &call, &integer.resolved_type),
                definition: capture(path, function),
                operation: capture(path, &call),
                constructor: function_name(path, function)
                    .and_then(|name| constructor_owner(&name, function))
                    .is_some(),
                initializer: initializer.map(|n| capture(path, &n)),
            })
        })
        .collect::<Vec<_>>();
    (calls.len() == 1)
        .then(|| calls.into_iter().next())
        .flatten()
}

fn reject_effect(
    path: &str,
    function: &N<'_>,
    params: &[N<'_>],
    conditional: &ConditionalRegions,
) -> Option<RejectEffect> {
    let predicate = params.first()?;
    if parameter_type(predicate) != "bool"
        || predicate.field("declarator")?.kind().as_ref() != "identifier"
    {
        return None;
    }
    let name = parameter_name(predicate)?;
    let body = function.field("body")?;
    let statements = body
        .children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
        .collect::<Vec<_>>();
    if statements.len() != 1
        || conditional.availability_for(statements[0].range()).state != AvailabilityState::Always
    {
        return None;
    }
    let statement = &statements[0];
    let effect = if statement.kind().as_ref() == "if_statement"
        && compact(statement.field("condition")?.text().as_ref()).trim_matches(['(', ')'])
            == format!("!{name}")
        && statement.field("alternative").is_none()
        && always_throws(&statement.field("consequence")?)
    {
        Rejection::Direct
    } else {
        if !matches!(
            statement.kind().as_ref(),
            "expression_statement" | "return_statement"
        ) {
            return None;
        }
        let named = statement
            .children()
            .filter(|n| n.is_named() && !n.kind().contains("comment"))
            .collect::<Vec<_>>();
        if named.len() != 1 || named[0].kind().as_ref() != "call_expression" {
            return None;
        }
        let call = named[0].clone();
        let args = arguments(&call);
        if args.first()?.text().trim() != name {
            return None;
        }
        if args.iter().skip(1).any(|arg| {
            arg.dfs()
                .any(|n| n.kind().as_ref() == "identifier" && n.text().trim() == name)
        }) {
            return None;
        }
        let observed = callable_name(call.field("function")?.text().as_ref())?;
        let namespace = scope_prefix(path, function);
        let target = if observed.starts_with("::") {
            observed.trim_start_matches("::").to_string()
        } else if namespace.is_empty() {
            observed
        } else {
            format!("{namespace}::{observed}")
        };
        Rejection::Forward(target)
    };
    Some(RejectEffect {
        predicate: 0,
        effect,
        definition: capture(path, function),
    })
}

fn parameters<'a>(function: &N<'a>) -> Vec<N<'a>> {
    function
        .field("declarator")
        .and_then(|d| d.field("parameters"))
        .into_iter()
        .flat_map(|n| n.children().collect::<Vec<_>>())
        .filter(|n| n.is_named())
        .collect()
}

fn parameter_name(parameter: &N<'_>) -> Option<String> {
    parameter
        .field("declarator")?
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "identifier" | "field_identifier"))
        .last()
        .map(|n| n.text().into_owned())
}

fn parameter_type(parameter: &N<'_>) -> String {
    parameter
        .field("type")
        .map(|n| {
            compact(n.text().as_ref())
                .trim_start_matches("std::")
                .to_string()
        })
        .unwrap_or_default()
}

fn parameter_signature(parameter: &N<'_>) -> String {
    let mut ty = parameter
        .children()
        .filter(|n| n.kind().as_ref() == "type_qualifier")
        .map(|n| compact(n.text().as_ref()))
        .collect::<Vec<_>>()
        .join(" ");
    ty.push_str(&parameter_type(parameter));
    if let Some(declarator) = parameter.field("declarator") {
        let shape = compact(declarator.text().as_ref());
        let name = parameter_name(parameter).unwrap_or_default();
        ty.push_str(if name.is_empty() {
            &shape
        } else {
            shape.strip_suffix(&name).unwrap_or(&shape)
        });
    }
    if !ty.contains(['*', '&']) {
        ty = ty.replace("const", "");
    }
    ty
}

fn always_throws(branch: &N<'_>) -> bool {
    if branch.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "return_statement" | "goto_statement" | "try_statement" | "lambda_expression"
        )
    }) {
        return false;
    }
    match branch.kind().as_ref() {
        "throw_statement" => true,
        "compound_statement" => branch
            .children()
            .filter(|n| n.is_named() && !n.kind().contains("comment"))
            .last()
            .is_some_and(|n| always_throws(&n)),
        "if_statement" => {
            branch
                .field("consequence")
                .is_some_and(|n| always_throws(&n))
                && branch
                    .field("alternative")
                    .is_some_and(|n| always_throws(&n))
        }
        _ => false,
    }
}

fn function_name(path: &str, function: &N<'_>) -> Option<String> {
    declarator_name(path, &function.field("declarator")?)
}

fn declarator_name(path: &str, declarator: &N<'_>) -> Option<String> {
    let decl = declarator.field("declarator")?;
    let name = callable_name(decl.text().as_ref())?;
    let mut prefix = scope_prefix(path, declarator);
    if !name.contains("::")
        && let Some(owner) = declarator
            .ancestors()
            .find(|n| matches!(n.kind().as_ref(), "class_specifier" | "struct_specifier"))
            .and_then(|n| n.field("name"))
    {
        if !prefix.is_empty() {
            prefix.push_str("::");
        }
        prefix.push_str(owner.text().as_ref());
    }
    Some(if name.starts_with("::") {
        name.trim_start_matches("::").to_string()
    } else if prefix.is_empty() {
        name
    } else {
        format!("{prefix}::{name}")
    })
}

fn constructor_owner(name: &str, function: &N<'_>) -> Option<String> {
    if function.field("type").is_some() {
        return None;
    }
    constructor_key(name)
}

fn constructor_key(name: &str) -> Option<String> {
    let (owner, member) = name.rsplit_once("::")?;
    (owner.rsplit("::").next()? == member).then(|| owner.to_string())
}

fn scope_prefix(path: &str, node: &N<'_>) -> String {
    let mut namespaces = node
        .ancestors()
        .filter(|n| n.kind().as_ref() == "namespace_definition")
        .map(|n| {
            n.field("name")
                .map(|n| compact(n.text().as_ref()))
                .unwrap_or_else(|| format!("@{path}:{}", n.range().start))
        })
        .collect::<Vec<_>>();
    namespaces.reverse();
    namespaces.join("::")
}

fn callable_name(text: &str) -> Option<String> {
    let text = compact(text);
    let name = text.split('<').next()?;
    (!name.is_empty() && name.trim_start_matches("::").split("::").all(identifier))
        .then(|| name.to_string())
}

fn copy_roles(name: &str) -> Option<(usize, usize)> {
    match name {
        "memcpy" | "memmove" => Some((1, 2)),
        "bcopy" => Some((0, 2)),
        "copy_n" => Some((0, 1)),
        _ => None,
    }
}

fn arguments<'a>(call: &N<'a>) -> Vec<N<'a>> {
    call.field("arguments")
        .into_iter()
        .flat_map(|n| n.children().collect::<Vec<_>>())
        .filter(|n| n.is_named())
        .collect()
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || i > 0 && b.is_ascii_digit())
}
fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}
fn capture(path: &str, node: &N<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}
fn location(path: &str, node: &N<'_>) -> Location {
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
