use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Evidence, EvidenceKind, Language, Location, Position, QueryProvenance, Resolution,
    ReviewNeighborhood, ReviewNeighborhoodFact, ReviewNeighborhoodVerification,
    ReviewTriageContract,
};

const ENGINE: &str = "mehscan csharp-review-neighborhood 1";

#[derive(Clone)]
struct PropertyRecord {
    owner: String,
    name: String,
    property_type: String,
    location: Location,
    excerpt: String,
}

#[derive(Clone)]
struct ParameterRecord {
    name: String,
    parameter_type: String,
}

struct MethodRecord {
    name: String,
    parameters: Vec<ParameterRecord>,
    persisted_parameters: BTreeMap<String, PersistenceRecord>,
}

#[derive(Clone)]
struct PersistenceRecord {
    location: Location,
    excerpt: String,
}

struct AssignmentRecord {
    owner: String,
    property: String,
    value: String,
    carrier: Option<String>,
    method: String,
    parameters: Vec<ParameterRecord>,
    local_persistence: Option<PersistenceRecord>,
    location: Location,
    excerpt: String,
}

struct CallRecord {
    name: String,
    arguments: Vec<String>,
    method: String,
    location: Location,
    excerpt: String,
}

#[derive(Default)]
struct ProjectCatalog {
    properties: Vec<PropertyRecord>,
    methods: Vec<MethodRecord>,
    assignments: Vec<AssignmentRecord>,
    calls: Vec<CallRecord>,
}

pub(crate) fn build<'a>(
    evidence: &[Evidence],
    sources: impl Iterator<Item = (&'a str, Option<Language>, &'a str)>,
    max_neighborhoods: usize,
) -> (Vec<ReviewNeighborhood>, bool) {
    let source_map = sources
        .map(|(path, language, source)| (path.to_string(), (language, source.to_string())))
        .collect::<BTreeMap<_, _>>();
    let mut catalog = ProjectCatalog::default();
    for (path, (language, source)) in &source_map {
        if *language == Some(Language::Csharp) {
            catalog_file(path, source, &mut catalog);
        }
    }

    let source_evidence = evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Source
                && item.rule_id != "csharp-controller-service-parameter-source"
                && matches!(
                    item.capability,
                    mehscan_core::Capability::HttpRequestData
                        | mehscan_core::Capability::RpcRequestData
                )
        })
        .collect::<Vec<_>>();
    let mut neighborhoods = Vec::new();
    for anchor in evidence.iter().filter(|item| {
        item.kind == EvidenceKind::Sink
            && item.rule_id == "csharp-razor-html-raw-output"
            && item.captures.contains_key("html")
    }) {
        let Some((_, view_source)) = source_map.get(&anchor.location.path) else {
            continue;
        };
        let expression = anchor.captures["html"].text.trim();
        let Some(property) = terminal_identifier(expression) else {
            continue;
        };
        for owner in resolve_view_owners(expression, view_source, &property, &catalog) {
            let assignments = catalog
                .assignments
                .iter()
                .filter(|item| item.owner == owner && item.property == property)
                .collect::<Vec<_>>();
            if assignments.is_empty() {
                continue;
            }
            let mut facts = vec![evidence_fact(
                "raw_output_sink",
                &format!("{owner}.{property}"),
                anchor,
            )];
            facts.extend(
                catalog
                    .properties
                    .iter()
                    .filter(|item| item.owner == owner && item.name == property)
                    .map(|item| ReviewNeighborhoodFact {
                        role: "model_property".to_string(),
                        symbol: format!("{}.{}: {}", item.owner, item.name, item.property_type),
                        location: item.location.clone(),
                        excerpt: item.excerpt.clone(),
                        evidence_id: None,
                        provenance: ast_provenance(),
                    }),
            );

            let mut anchor_ids = BTreeSet::from([anchor.id.clone()]);
            for assignment in assignments {
                facts.push(ReviewNeighborhoodFact {
                    role: "property_assignment".to_string(),
                    symbol: format!("{}.{} <- {}", owner, property, assignment.value),
                    location: assignment.location.clone(),
                    excerpt: assignment.excerpt.clone(),
                    evidence_id: None,
                    provenance: ast_provenance(),
                });

                if let Some(source) = exact_source_in_method(
                    &source_evidence,
                    &assignment.location.path,
                    &assignment.method,
                    &assignment.value,
                ) {
                    anchor_ids.insert(source.id.clone());
                    facts.push(evidence_fact(
                        "bound_remote_input",
                        &assignment.value,
                        source,
                    ));
                } else if let Some(index) = assignment
                    .parameters
                    .iter()
                    .position(|parameter| parameter.name == assignment.value)
                {
                    add_unique_callsite_source(
                        &catalog,
                        &source_evidence,
                        &assignment.method,
                        assignment.parameters.len(),
                        index,
                        &mut anchor_ids,
                        &mut facts,
                    );
                }

                if let Some(persistence) = &assignment.local_persistence {
                    facts.push(ReviewNeighborhoodFact {
                        role: "persistence_call_observed".to_string(),
                        symbol: format!("{} persisted in {}", owner, assignment.method),
                        location: persistence.location.clone(),
                        excerpt: persistence.excerpt.clone(),
                        evidence_id: None,
                        provenance: ast_provenance(),
                    });
                } else if let Some(carrier) = assignment.carrier.as_deref() {
                    add_repository_handoff(
                        &catalog,
                        &assignment.location.path,
                        &assignment.method,
                        carrier,
                        &owner,
                        &mut facts,
                    );
                }
            }
            sort_and_deduplicate_facts(&mut facts);
            if !facts.iter().any(|fact| fact.role == "bound_remote_input")
                || !facts
                    .iter()
                    .any(|fact| fact.role == "persistence_call_observed")
            {
                continue;
            }
            let key = format!("{owner}.{property}");
            neighborhoods.push(ReviewNeighborhood {
                id: neighborhood_id(&key, &anchor.location),
                language: Language::Csharp,
                candidate: "Potential stored XSS through raw Razor output".to_string(),
                cwe: "CWE-79".to_string(),
                key,
                anchor_evidence_ids: anchor_ids.into_iter().collect(),
                facts,
                verification: ReviewNeighborhoodVerification {
                    persistence_call_observed: true,
                    runtime_persistence_verified: false,
                    retrieval_verified: false,
                    raw_output_observed: true,
                    encoding_verified: false,
                    authorization_verified: false,
                    runtime_dispatch_verified: false,
                },
                open_questions: vec![
                    "Does this persisted model property reach the raw Razor output at runtime?"
                        .to_string(),
                    "Is the value sanitized or encoded between input, persistence, retrieval, and raw output?"
                        .to_string(),
                    "Is the value restricted to trusted authors by an invariant that holds for every write path?"
                        .to_string(),
                ],
                uncertainties: vec![
                    "persistence_unproven".to_string(),
                    "runtime_flow_unproven".to_string(),
                    "symbol_binding_syntactic".to_string(),
                ],
                ai_guidance: vec![
                    "Review whether the exact remote input is stored in this model property and later rendered through the raw Razor escape hatch.".to_string(),
                    "Treat this neighborhood as cross-file review context, not a SecurityPath or vulnerability verdict.".to_string(),
                    "Verify runtime dispatch, persistence mapping, retrieval, encoding expectations, and application authorization.".to_string(),
                ],
            });
        }
    }
    neighborhoods.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.id.cmp(&right.id))
    });
    neighborhoods.dedup_by(|left, right| left.id == right.id);
    let truncated = neighborhoods.len() > max_neighborhoods;
    neighborhoods.truncate(max_neighborhoods);
    (neighborhoods, truncated)
}

pub(crate) fn triage_contract() -> ReviewTriageContract {
    ReviewTriageContract {
        response_fields: vec![
            "neighborhood_id".to_string(),
            "decision".to_string(),
            "confidence".to_string(),
            "summary".to_string(),
            "checks".to_string(),
        ],
        decisions: vec![
            "issue".to_string(),
            "not_issue".to_string(),
            "needs_review".to_string(),
        ],
        confidence_levels: vec!["high".to_string(), "medium".to_string(), "low".to_string()],
        instructions: vec![
            "Make a final decision from the supplied facts; the scanner has not made one."
                .to_string(),
            "Use needs_review only when a named missing fact could change the decision."
                .to_string(),
            "Keep summary to two sentences. Use checks only for needs_review and keep them to the smallest decisive set."
                .to_string(),
        ],
    }
}

pub(crate) fn fingerprint(
    neighborhoods: &[ReviewNeighborhood],
    contract: &ReviewTriageContract,
) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for value in contract
        .response_fields
        .iter()
        .chain(&contract.decisions)
        .chain(&contract.confidence_levels)
        .chain(&contract.instructions)
    {
        hash_text(&mut hash, value);
    }
    for neighborhood in neighborhoods {
        hash_text(&mut hash, &neighborhood.id);
        hash_text(&mut hash, &neighborhood.key);
        hash_text(&mut hash, &neighborhood.candidate);
        hash_text(&mut hash, &neighborhood.cwe);
        for evidence_id in &neighborhood.anchor_evidence_ids {
            hash_text(&mut hash, evidence_id);
        }
        for fact in &neighborhood.facts {
            hash_text(&mut hash, &fact.role);
            hash_text(&mut hash, &fact.symbol);
            hash_text(&mut hash, &fact.location.path);
            hash_text(&mut hash, &fact.location.start.byte_offset.to_string());
            hash_text(&mut hash, &fact.location.end.byte_offset.to_string());
            hash_text(&mut hash, &fact.excerpt);
            hash_text(&mut hash, fact.evidence_id.as_deref().unwrap_or("<null>"));
            hash_text(&mut hash, &format!("{:?}", fact.provenance.resolution));
            hash_text(&mut hash, &fact.provenance.engine);
        }
        for question in &neighborhood.open_questions {
            hash_text(&mut hash, question);
        }
    }
    format!("csharp-reviewpack-{hash:016x}")
}

fn hash_text(hash: &mut u64, text: &str) {
    for byte in text.bytes().chain(std::iter::once(0xff)) {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
}

fn catalog_file(path: &str, source: &str, catalog: &mut ProjectCatalog) {
    let Ok(document) = StrDoc::try_new(source, SupportLang::CSharp) else {
        return;
    };
    let ast = AstGrep::doc(document);
    let root = ast.root();
    if root.dfs().any(|node| node.is_error() || node.is_missing()) {
        return;
    }
    for property in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "property_declaration")
    {
        let Some(owner) = enclosing_class_name(&property) else {
            continue;
        };
        let Some(name) = property
            .field("name")
            .and_then(|node| simple_identifier(node.text().as_ref()))
        else {
            continue;
        };
        let property_type = property
            .field("type")
            .map(|node| compact(node.text().as_ref()))
            .unwrap_or_default();
        catalog.properties.push(PropertyRecord {
            owner,
            name,
            property_type,
            location: node_location(path, source, &property),
            excerpt: excerpt(property.text().as_ref()),
        });
    }

    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let Some(name) = method
            .field("name")
            .and_then(|node| simple_identifier(node.text().as_ref()))
        else {
            continue;
        };
        let parameters = method_parameters(&method);
        let persisted_parameters = parameters
            .iter()
            .filter_map(|parameter| {
                let call = persistence_call(&method, &parameter.name)?;
                Some((
                    parameter.name.clone(),
                    PersistenceRecord {
                        location: node_location(path, source, &call),
                        excerpt: excerpt(call.text().as_ref()),
                    },
                ))
            })
            .collect::<BTreeMap<_, _>>();
        catalog.methods.push(MethodRecord {
            name: name.clone(),
            parameters: parameters.clone(),
            persisted_parameters,
        });

        for assignment in method
            .dfs()
            .filter(|node| node.kind().as_ref() == "assignment_expression")
        {
            let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
            else {
                continue;
            };
            let (Some(property), Some(value)) = (
                terminal_identifier(left.text().as_ref()),
                simple_identifier(right.text().as_ref()),
            ) else {
                continue;
            };
            let Some((owner, carrier)) = assignment_owner_and_carrier(&assignment, &method, &left)
            else {
                continue;
            };
            let local_persistence = carrier
                .as_deref()
                .and_then(|carrier| persistence_call(&method, carrier))
                .map(|call| PersistenceRecord {
                    location: node_location(path, source, &call),
                    excerpt: excerpt(call.text().as_ref()),
                });
            catalog.assignments.push(AssignmentRecord {
                owner,
                property,
                value,
                carrier,
                method: name.clone(),
                parameters: parameters.clone(),
                local_persistence,
                location: node_location(path, source, &assignment),
                excerpt: excerpt(assignment.text().as_ref()),
            });
        }
    }

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let (Some(name), Some(method)) = (
            terminal_identifier(function.text().as_ref()),
            enclosing_method_name(&invocation),
        ) else {
            continue;
        };
        catalog.calls.push(CallRecord {
            name,
            arguments: invocation_arguments(&invocation),
            method,
            location: node_location(path, source, &invocation),
            excerpt: excerpt(invocation.text().as_ref()),
        });
    }
}

fn resolve_view_owners(
    expression: &str,
    source: &str,
    property: &str,
    catalog: &ProjectCatalog,
) -> Vec<String> {
    let receiver = expression
        .rsplit_once('.')
        .map(|(receiver, _)| receiver.trim())
        .unwrap_or_default();
    let model = razor_model_type(source);
    let mut owners = BTreeSet::new();
    if receiver == "Model" {
        if let Some(model) = model.as_deref().and_then(element_type) {
            owners.insert(model);
        }
    } else if let (Some(model), Some(collection)) = (
        model.as_deref().and_then(element_type),
        foreach_collection(source, receiver),
    ) && let Some(relation) = terminal_identifier(&collection)
    {
        for item in catalog
            .properties
            .iter()
            .filter(|item| item.owner == model && item.name == relation)
        {
            if let Some(owner) = element_type(&item.property_type) {
                owners.insert(owner);
            }
        }
    }
    owners.retain(|owner| {
        catalog
            .properties
            .iter()
            .any(|item| item.owner == *owner && item.name == property)
    });
    if owners.is_empty() {
        let candidates = catalog
            .properties
            .iter()
            .filter(|item| item.name == property)
            .map(|item| item.owner.clone())
            .collect::<BTreeSet<_>>();
        if candidates.len() == 1 {
            owners.extend(candidates);
        }
    }
    owners.into_iter().collect()
}

#[allow(clippy::too_many_arguments)]
fn add_unique_callsite_source(
    catalog: &ProjectCatalog,
    sources: &[&Evidence],
    method: &str,
    argument_count: usize,
    parameter_index: usize,
    anchor_ids: &mut BTreeSet<String>,
    facts: &mut Vec<ReviewNeighborhoodFact>,
) {
    if catalog
        .methods
        .iter()
        .filter(|candidate| {
            candidate.name == method && candidate.parameters.len() == argument_count
        })
        .count()
        != 1
    {
        return;
    }
    let matches = catalog
        .calls
        .iter()
        .filter(|call| call.name == method && call.arguments.len() == argument_count)
        .filter_map(|call| {
            let argument = call.arguments.get(parameter_index)?;
            let source =
                exact_source_in_method(sources, &call.location.path, &call.method, argument)?;
            Some((call, source, argument))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return;
    }
    let (call, source, argument) = matches[0];
    anchor_ids.insert(source.id.clone());
    facts.push(evidence_fact("bound_remote_input", argument, source));
    facts.push(ReviewNeighborhoodFact {
        role: "controller_repository_call".to_string(),
        symbol: format!("{} argument {}", call.name, parameter_index + 1),
        location: call.location.clone(),
        excerpt: call.excerpt.clone(),
        evidence_id: None,
        provenance: ast_provenance(),
    });
}

fn add_repository_handoff(
    catalog: &ProjectCatalog,
    path: &str,
    method: &str,
    carrier: &str,
    owner: &str,
    facts: &mut Vec<ReviewNeighborhoodFact>,
) {
    let matches = catalog
        .calls
        .iter()
        .filter(|call| call.location.path == path && call.method == method)
        .flat_map(|call| {
            call.arguments
                .iter()
                .enumerate()
                .filter(move |(_, argument)| *argument == carrier)
                .map(move |(index, _)| (call, index))
        })
        .filter_map(|(call, index)| {
            let methods = catalog
                .methods
                .iter()
                .filter(|candidate| {
                    candidate.name == call.name
                        && candidate.parameters.len() == call.arguments.len()
                        && candidate.parameters.get(index).is_some_and(|parameter| {
                            element_type(&parameter.parameter_type).as_deref() == Some(owner)
                                && candidate.persisted_parameters.contains_key(&parameter.name)
                        })
                })
                .collect::<Vec<_>>();
            (methods.len() == 1).then_some((call, methods[0], index))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return;
    }
    let (call, target, index) = matches[0];
    let persistence = &target.persisted_parameters[&target.parameters[index].name];
    facts.push(ReviewNeighborhoodFact {
        role: "controller_repository_call".to_string(),
        symbol: format!("{} argument {}", call.name, index + 1),
        location: call.location.clone(),
        excerpt: call.excerpt.clone(),
        evidence_id: None,
        provenance: ast_provenance(),
    });
    facts.push(ReviewNeighborhoodFact {
        role: "persistence_call_observed".to_string(),
        symbol: format!("{} persists {}", target.name, target.parameters[index].name),
        location: persistence.location.clone(),
        excerpt: persistence.excerpt.clone(),
        evidence_id: None,
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: format!("{ENGINE}; unique method signature and exact parameter identity"),
        },
    });
}

fn exact_source_in_method<'a>(
    sources: &'a [&Evidence],
    path: &str,
    method: &str,
    symbol: &str,
) -> Option<&'a Evidence> {
    let mut matches = sources.iter().copied().filter(|item| {
        item.location.path == path
            && item.enclosing_symbol.as_deref() == Some(method)
            && item
                .captures
                .get("parameter")
                .is_some_and(|capture| capture.text.trim() == symbol)
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn assignment_owner_and_carrier(
    assignment: &Node<'_, StrDoc<SupportLang>>,
    method: &Node<'_, StrDoc<SupportLang>>,
    left: &Node<'_, StrDoc<SupportLang>>,
) -> Option<(String, Option<String>)> {
    if let Some(creation) = assignment.ancestors().find(|ancestor| {
        ancestor.kind().as_ref() == "object_creation_expression"
            && ancestor.range().start >= method.range().start
            && ancestor.range().end <= method.range().end
    }) {
        let owner = creation
            .field("type")
            .and_then(|node| element_type(node.text().as_ref()))?;
        let carrier = creation
            .ancestors()
            .find(|ancestor| ancestor.kind().as_ref() == "variable_declarator")
            .and_then(|node| node.field("name"))
            .and_then(|node| simple_identifier(node.text().as_ref()));
        return Some((owner, carrier));
    }
    let left_text = left.text();
    let (receiver, _) = left_text.rsplit_once('.')?;
    let receiver = simple_identifier(receiver.trim())?;
    let parameter = method_parameters(method)
        .into_iter()
        .find(|parameter| parameter.name == receiver)?;
    Some((element_type(&parameter.parameter_type)?, Some(receiver)))
}

fn persistence_call<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
    value: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    method.dfs().find(|node| {
        if node.kind().as_ref() != "invocation_expression" {
            return false;
        }
        let Some(function) = node.field("function") else {
            return false;
        };
        matches!(
            terminal_identifier(function.text().as_ref()).as_deref(),
            Some("Add" | "AddAsync" | "Update" | "UpdateRange")
        ) && invocation_arguments(node)
            .iter()
            .any(|argument| argument == value)
    })
}

fn method_parameters(method: &Node<'_, StrDoc<SupportLang>>) -> Vec<ParameterRecord> {
    let Some(parameters) = method.field("parameters") else {
        return Vec::new();
    };
    parameters
        .dfs()
        .filter(|node| node.kind().as_ref() == "parameter")
        .filter_map(|parameter| {
            Some(ParameterRecord {
                name: parameter
                    .field("name")
                    .and_then(|node| simple_identifier(node.text().as_ref()))?,
                parameter_type: parameter
                    .field("type")
                    .map(|node| compact(node.text().as_ref()))?,
            })
        })
        .collect()
}

fn invocation_arguments(invocation: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    let Some(arguments) = invocation.field("arguments") else {
        return Vec::new();
    };
    arguments
        .children()
        .filter(|node| node.is_named())
        .map(|node| compact(node.text().as_ref()))
        .collect()
}

fn enclosing_class_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "class_declaration")?
        .field("name")
        .and_then(|name| simple_identifier(name.text().as_ref()))
}

fn enclosing_method_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")?
        .field("name")
        .and_then(|name| simple_identifier(name.text().as_ref()))
}

fn razor_model_type(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        line.trim()
            .trim_start_matches('\u{feff}')
            .strip_prefix("@model ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn foreach_collection(source: &str, variable: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let line = line.trim();
        let body = line.strip_prefix("@foreach (")?.strip_suffix(')')?;
        let tokens = body.split_whitespace().collect::<Vec<_>>();
        (tokens.len() == 4 && tokens[0] == "var" && tokens[1] == variable && tokens[2] == "in")
            .then(|| tokens[3..].join(" "))
    })
}

fn element_type(text: &str) -> Option<String> {
    let compact = compact(text).trim_end_matches('?').to_string();
    let candidate = compact
        .rsplit_once('<')
        .map(|(_, inner)| {
            inner
                .trim_end_matches('>')
                .split(',')
                .next()
                .unwrap_or(inner)
        })
        .unwrap_or(&compact)
        .rsplit('.')
        .next()?
        .trim()
        .trim_end_matches("[]");
    simple_identifier(candidate)
}

fn terminal_identifier(text: &str) -> Option<String> {
    simple_identifier(text.trim().rsplit('.').next()?.trim())
}

fn simple_identifier(text: &str) -> Option<String> {
    let text = text.trim().trim_start_matches('@');
    (!text.is_empty()
        && text.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_alphabetic()
                || (index > 0 && character.is_ascii_digit())
        }))
    .then(|| text.to_string())
}

fn evidence_fact(role: &str, symbol: &str, evidence: &Evidence) -> ReviewNeighborhoodFact {
    ReviewNeighborhoodFact {
        role: role.to_string(),
        symbol: symbol.to_string(),
        location: evidence.location.clone(),
        excerpt: evidence
            .captures
            .values()
            .next()
            .map(|capture| excerpt(&capture.text))
            .unwrap_or_default(),
        evidence_id: Some(evidence.id.clone()),
        provenance: QueryProvenance {
            resolution: evidence.provenance.resolution,
            engine: evidence.provenance.engine.clone(),
        },
    }
}

fn sort_and_deduplicate_facts(facts: &mut Vec<ReviewNeighborhoodFact>) {
    facts.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then_with(|| {
                left.location
                    .start
                    .byte_offset
                    .cmp(&right.location.start.byte_offset)
            })
            .then_with(|| left.role.cmp(&right.role))
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    facts.dedup_by(|left, right| {
        left.role == right.role && left.symbol == right.symbol && left.location == right.location
    });
}

fn ast_provenance() -> QueryProvenance {
    QueryProvenance {
        resolution: Resolution::Ast,
        engine: ENGINE.to_string(),
    }
}

fn node_location(path: &str, source: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    location(path, source, node.range().start, node.range().end)
}

fn location(path: &str, source: &str, start: usize, end: usize) -> Location {
    Location {
        path: path.to_string(),
        start: position(source, start),
        end: position(source, end),
    }
}

fn position(source: &str, offset: usize) -> Position {
    let bounded = offset.min(source.len());
    let prefix = &source[..bounded];
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    Position {
        line: prefix.bytes().filter(|byte| *byte == b'\n').count() + 1,
        column: source[line_start..bounded].chars().count() + 1,
        byte_offset: bounded,
    }
}

fn excerpt(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect()
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn neighborhood_id(key: &str, location: &Location) -> String {
    let material = format!(
        "csharp:{key}:{}:{}:{}",
        location.path, location.start.byte_offset, location.end.byte_offset
    );
    let hash = material.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    format!("rn-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_generic_element_types() {
        assert_eq!(
            element_type("IList<BlogResponse>"),
            Some("BlogResponse".to_string())
        );
        assert_eq!(element_type("BlogEntry?"), Some("BlogEntry".to_string()));
    }

    #[test]
    fn rejects_expression_as_identifier() {
        assert_eq!(simple_identifier("response.Contents"), None);
        assert_eq!(simple_identifier("contents"), Some("contents".to_string()));
    }

    #[test]
    fn catalogs_property_assignment_and_persistence() {
        let source = r#"
class BlogEntry { public string Contents { get; set; } }
class Repo {
  public BlogEntry Create(string contents) {
    var entry = new BlogEntry { Contents = contents };
    db.BlogEntries.Add(entry);
    return entry;
  }
}"#;
        let mut catalog = ProjectCatalog::default();
        catalog_file("Sample.cs", source, &mut catalog);
        assert_eq!(catalog.properties.len(), 1);
        assert_eq!(catalog.assignments.len(), 1);
        assert_eq!(catalog.assignments[0].owner, "BlogEntry");
        assert!(catalog.assignments[0].local_persistence.is_some());
    }

    #[test]
    fn catalogs_webgoat_blog_shapes_when_corpus_exists() {
        let Some(root) =
            std::env::var_os("MEHSCAN_WEBGOAT_DOTNET_ROOT").map(std::path::PathBuf::from)
        else {
            return;
        };
        let root = root.join("WebGoat.NET");
        let mut catalog = ProjectCatalog::default();
        for relative in [
            "Models/BlogEntry.cs",
            "Models/BlogResponse.cs",
            "Data/BlogEntryRepository.cs",
            "Data/BlogResponseRepository.cs",
            "Controllers/BlogController.cs",
        ] {
            let source = std::fs::read_to_string(root.join(relative)).expect("WebGoat source");
            catalog_file(relative, &source, &mut catalog);
        }
        assert!(
            catalog
                .assignments
                .iter()
                .any(|item| item.owner == "BlogEntry" && item.property == "Contents"),
            "assignments: {:?}",
            catalog
                .assignments
                .iter()
                .map(|item| (&item.owner, &item.property, &item.value))
                .collect::<Vec<_>>()
        );
        assert!(
            catalog
                .properties
                .iter()
                .any(|item| item.owner == "BlogEntry" && item.name == "Contents"),
            "properties: {:?}",
            catalog
                .properties
                .iter()
                .map(|item| (&item.owner, &item.name, &item.property_type))
                .collect::<Vec<_>>()
        );
        assert!(catalog.methods.iter().any(|item| {
            item.name == "CreateBlogResponse" && item.persisted_parameters.contains_key("response")
        }));
        let partial = std::fs::read_to_string(root.join("Views/Blog/_BlogEntryPartial.cshtml"))
            .expect("Razor partial");
        assert_eq!(razor_model_type(&partial), Some("BlogEntry".to_string()));
        assert_eq!(
            razor_model_type(&partial).as_deref().and_then(element_type),
            Some("BlogEntry".to_string())
        );
        assert_eq!(
            resolve_view_owners("Model.Contents", &partial, "Contents", &catalog),
            vec!["BlogEntry".to_string()]
        );
        let index =
            std::fs::read_to_string(root.join("Views/Blog/Index.cshtml")).expect("Razor index");
        assert_eq!(
            resolve_view_owners("response.Contents", &index, "Contents", &catalog),
            vec!["BlogResponse".to_string()]
        );
    }
}
