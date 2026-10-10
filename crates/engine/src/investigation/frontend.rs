//! Bounded JSX caller navigation for existing raw-HTML reviews, not taint or safety.
use super::*;

const MAX_CALLERS: usize = 2;
const MAX_FACT_BYTES: usize = 2048;

#[derive(Default)]
pub(super) struct FrontendContext {
    packets: BTreeMap<String, (Vec<ReviewNeighborhoodFact>, bool)>,
    imports: BTreeMap<String, Vec<(Vec<String>, ReviewNeighborhoodFact)>>,
}

struct PropContract {
    evidence_id: String,
    path: String,
    component: String,
    prop: String,
    exports: BTreeSet<String>,
    default_export: bool,
    parameter: ReviewNeighborhoodFact,
    producers: Vec<ReviewNeighborhoodFact>,
}

impl FrontendContext {
    pub(super) fn build(sources: &RepositorySources, groups: &[ObservationGroup]) -> Self {
        let mut context = Self::default();
        let mut contracts = Vec::new();
        let mut documents = BTreeMap::new();
        for group in groups {
            let Ok(file) = sources.file(&group.path) else {
                continue;
            };
            let sinks: Vec<_> = group
                .evidence
                .iter()
                .filter(|e| {
                    e.capability == Capability::HtmlOutput
                        && (e.rule_id.ends_with("react-dangerous-html-output")
                            || e.rule_id.ends_with("solid-inner-html-output"))
                })
                .collect();
            if sinks.is_empty() {
                continue;
            }
            let Some(ast) = documents
                .entry(file.path.clone())
                .or_insert_with(|| parse(file))
                .as_ref()
            else {
                continue;
            };
            for sink in sinks {
                if let Some(contract) = prop_contract(file, &ast.root(), sink) {
                    contracts.push(contract);
                }
            }
        }
        if contracts.is_empty() {
            return context;
        }

        // Only JSX-containing frontend files can supply these callers. Parse a
        // file once for all selected contracts, never once per review ID.
        for file in sources.files.values().filter(|f| f.source.contains('<')) {
            if !contracts.iter().any(|c| {
                c.path == file.path
                    || ((!c.exports.is_empty() || c.default_export)
                        && mentions_module(file, &c.path))
            }) {
                continue;
            }
            let Some(ast) = documents
                .entry(file.path.clone())
                .or_insert_with(|| parse(file))
                .as_ref()
            else {
                continue;
            };
            let root = ast.root();
            let partial_parse = root.dfs().any(|n| n.is_error() || n.is_missing());
            context.imports.insert(
                file.path.clone(),
                root.children()
                    .filter(|n| {
                        n.kind().as_ref() == "import_statement"
                            && valid(n)
                            && n.range().len() <= MAX_FACT_BYTES
                    })
                    .map(|n| {
                        let names = n
                            .dfs()
                            .filter(|n| n.kind().as_ref() == "identifier")
                            .map(|n| n.text().to_string())
                            .collect();
                        (
                            names,
                            fact(
                                file,
                                &n,
                                "frontend_import_binding_context",
                                "caller/helper imports",
                                "",
                            ),
                        )
                    })
                    .collect(),
            );
            for contract in &contracts {
                let aliases = component_aliases(file, &root, contract, sources);
                if aliases.is_empty() {
                    continue;
                }
                for element in root.dfs().filter(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "jsx_opening_element" | "jsx_self_closing_element"
                    )
                }) {
                    let Some(name) = element.field("name") else {
                        continue;
                    };
                    if !valid(&element)
                        || element.ancestors().any(|n| n.is_error() || n.is_missing())
                        || !aliases.contains(name.text().trim())
                        || shadowed(&element, name.text().trim())
                    {
                        continue;
                    }
                    let attributes: Vec<_> = element
                        .children()
                        .filter(|n| {
                            n.kind().as_ref() == "jsx_attribute"
                                && n.children()
                                    .find(|c| c.is_named())
                                    .is_some_and(|n| n.text().trim() == contract.prop)
                        })
                        .collect();
                    let spread = element
                        .children()
                        .any(|n| n.kind().as_ref() == "jsx_expression");
                    if attributes.is_empty() && !spread {
                        continue;
                    }
                    let (facts, truncated) = context
                        .packets
                        .entry(contract.evidence_id.clone())
                        .or_default();
                    *truncated |= partial_parse;
                    if facts.is_empty() {
                        facts.push(contract.parameter.clone());
                        facts.extend(contract.producers.clone());
                    }
                    if facts
                        .iter()
                        .filter(|f| f.role == "frontend_prop_caller_context")
                        .count()
                        >= MAX_CALLERS
                    {
                        *truncated = true;
                        continue;
                    }
                    if element.range().len() > MAX_FACT_BYTES {
                        *truncated = true;
                        continue;
                    }
                    if attributes.len() != 1 || spread {
                        // A spread can replace a prop. Show the actual caller, but
                        // leave its reaching value explicit rather than guessing.
                        *truncated |= spread || attributes.len() > 1;
                        if !spread && attributes.is_empty() {
                            continue;
                        }
                    }
                    facts.push(fact(
                        file,
                        &element,
                        "frontend_prop_caller_context",
                        &format!("{}.{}", contract.component, contract.prop),
                        &contract.evidence_id,
                    ));
                    if !spread && attributes.len() == 1 {
                        let value = attributes[0].children().filter(|n| n.is_named()).nth(1);
                        if let Some(value) = value {
                            let expression = if value.kind().as_ref() == "jsx_expression" {
                                value.children().find(|n| n.is_named())
                            } else {
                                Some(value)
                            };
                            if let Some(expression) = expression {
                                append_producer(
                                    file,
                                    &element,
                                    expression,
                                    facts,
                                    &contract.evidence_id,
                                );
                            }
                        }
                    }
                }
            }
        }
        context
    }

    pub(super) fn all_facts(&self) -> impl Iterator<Item = &ReviewNeighborhoodFact> {
        self.packets.values().flat_map(|(facts, _)| facts)
    }

    pub(super) fn import_facts(
        &self,
        facts: &[ReviewNeighborhoodFact],
    ) -> Vec<ReviewNeighborhoodFact> {
        let mut imports = Vec::new();
        for source in facts {
            let Some(bindings) = self.imports.get(&source.location.path) else {
                continue;
            };
            for (names, fact) in bindings {
                if names
                    .iter()
                    .any(|name| contains_identifier(&source.excerpt, name))
                    && !imports
                        .iter()
                        .any(|f: &ReviewNeighborhoodFact| f.location == fact.location)
                {
                    let mut fact = fact.clone();
                    fact.evidence_id = source.evidence_id.clone();
                    imports.push(fact);
                    if imports.len() == 4 {
                        return imports;
                    }
                }
            }
        }
        imports
    }

    pub(super) fn facts(&self, evidence: &[Evidence]) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let mut facts = Vec::new();
        let mut truncated = false;
        for item in evidence {
            if let Some((packet, cut)) = self.packets.get(&item.id) {
                truncated |= cut;
                for fact in packet {
                    if !facts.iter().any(|f: &ReviewNeighborhoodFact| {
                        f.role == fact.role && f.location == fact.location
                    }) {
                        facts.push(fact.clone());
                    }
                }
            }
        }
        (facts, truncated)
    }
}

fn parse(file: &SourceFile) -> Option<AstGrep<StrDoc<SupportLang>>> {
    let language = file.language?;
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) || file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
    {
        return None;
    }
    let ast = AstGrep::doc(StrDoc::try_new(&file.source, parser_language(language)).ok()?);
    Some(ast)
}

fn valid(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    !node.dfs().any(|n| n.is_error() || n.is_missing())
}

fn prop_contract(
    file: &SourceFile,
    root: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
) -> Option<PropContract> {
    let capture = sink.captures.get("content")?;
    let node = root.dfs().find(|n| {
        n.range().start == capture.location.start.byte_offset
            && n.range().end == capture.location.end.byte_offset
    })?;
    let owner = node.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_declaration" | "arrow_function" | "function_expression"
        )
    })?;
    if !valid(&owner) || owner.ancestors().any(|n| n.is_error() || n.is_missing()) {
        return None;
    }
    let (name, binding) = if owner.kind().as_ref() == "function_declaration" {
        (owner.field("name")?, owner.clone())
    } else {
        let binding = owner.parent()?;
        if binding.kind().as_ref() != "variable_declarator"
            || binding.field("value")?.range() != owner.range()
            || !binding.parent()?.text().trim_start().starts_with("const ")
        {
            return None;
        }
        (binding.field("name")?, binding)
    };
    let component = name.text().to_string();
    if !component.chars().next()?.is_ascii_uppercase()
        || name.kind().as_ref() != "identifier"
        || owner.ancestors().any(|n| {
            matches!(
                n.kind().as_ref(),
                "function_declaration"
                    | "arrow_function"
                    | "function_expression"
                    | "class_declaration"
            )
        })
    {
        return None;
    }
    let parameters = owner.field("parameters");
    let parameter = parameters
        .as_ref()
        .and_then(|n| n.children().find(|n| n.is_named()))
        .or_else(|| owner.field("parameter"))?;
    if parameter.field("value").is_some() {
        return None;
    }
    let pattern = parameter
        .field("pattern")
        .or_else(|| parameter.field("name"))
        .unwrap_or(parameter.clone());
    let mut producers = Vec::new();
    let mut expression = node.clone();
    for _ in 0..2 {
        if expression.kind().as_ref() != "identifier" {
            break;
        }
        let bindings: Vec<_> = owner
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "variable_declarator"
                    && n.range().start < node.range().start
                    && n.field("name")
                        .is_some_and(|n| n.text() == expression.text())
                    && n.parent()
                        .is_some_and(|n| n.text().trim_start().starts_with("const "))
                    && n.ancestors()
                        .find(|n| callable(n))
                        .is_some_and(|n| n.range() == owner.range())
                    && n.ancestors()
                        .find(|n| n.kind().as_ref() == "statement_block")
                        .is_some_and(|n| {
                            n.range().start <= node.range().start
                                && node.range().end <= n.range().end
                        })
            })
            .collect();
        if bindings.len() != 1 {
            break;
        }
        let binding = &bindings[0];
        if binding.range().len() > MAX_FACT_BYTES {
            return None;
        }
        producers.push(fact(
            file,
            binding,
            "frontend_output_producer_context",
            expression.text().trim(),
            &sink.id,
        ));
        expression = binding.field("value")?;
    }
    let mut reads = BTreeSet::new();
    if pattern.kind().as_ref() == "identifier" {
        let object = pattern.text().to_string();
        for read in expression
            .dfs()
            .filter(|n| n.kind().as_ref() == "member_expression")
        {
            if read
                .field("object")
                .is_some_and(|n| n.text().trim() == object)
                && !parameter_shadow(&read, &owner, &object)
                && let Some(property) = read.field("property")
                && property.kind().as_ref() == "property_identifier"
            {
                reads.insert((property.text().to_string(), object.clone()));
            }
        }
    } else if pattern.kind().as_ref() == "object_pattern" {
        for field in pattern.children() {
            let pair = if field.kind().as_ref() == "shorthand_property_identifier_pattern" {
                Some((field.text().to_string(), field.text().to_string()))
            } else if field.kind().as_ref() == "pair_pattern" {
                field
                    .field("key")
                    .zip(field.field("value"))
                    .filter(|(k, v)| {
                        k.kind().as_ref() == "property_identifier"
                            && v.kind().as_ref() == "identifier"
                    })
                    .map(|(k, v)| (k.text().to_string(), v.text().to_string()))
            } else {
                None
            };
            if let Some((prop, local)) = pair
                && expression.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "identifier" | "shorthand_property_identifier"
                    ) && n.text().trim() == local
                        && !parameter_shadow(&n, &owner, &local)
                })
            {
                reads.insert((prop, local));
            }
        }
    }
    if reads.len() != 1 {
        return None;
    }
    let (prop, local) = reads.into_iter().next()?;
    let content = capture.text.trim();
    if owner.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "assignment_expression" | "augmented_assignment_expression" | "update_expression"
        ) && n
            .field("left")
            .or_else(|| n.field("argument"))
            .is_some_and(|left| {
                left.text().trim() == local
                    || left.text().trim() == content
                    || left.text().trim() == format!("{local}.{prop}")
            })
    }) {
        return None;
    }
    let export = binding
        .ancestors()
        .find(|n| n.kind().as_ref() == "export_statement");
    let mut default_export = export
        .as_ref()
        .is_some_and(|n| n.children().any(|c| c.kind().as_ref() == "default"));
    let mut exports = BTreeSet::new();
    if export.is_some() && !default_export {
        exports.insert(component.clone());
    }
    for declaration in root
        .children()
        .filter(|n| n.kind().as_ref() == "export_statement" && n.field("source").is_none())
    {
        for spec in declaration
            .dfs()
            .filter(|n| n.kind().as_ref() == "export_specifier")
        {
            if spec
                .field("name")
                .is_some_and(|n| n.text().trim() == component)
            {
                if let Some(name) = spec.field("alias").or_else(|| spec.field("name")) {
                    exports.insert(name.text().to_string());
                }
            }
        }
        if declaration
            .children()
            .any(|n| n.kind().as_ref() == "default")
            && declaration
                .field("value")
                .is_some_and(|n| n.text().trim() == component)
        {
            default_export = true;
        }
    }
    let parameter_fact = fact(
        file,
        &parameter,
        "frontend_component_prop_context",
        &format!("{component}.{prop}"),
        &sink.id,
    );
    Some(PropContract {
        evidence_id: sink.id.clone(),
        path: file.path.clone(),
        component,
        prop,
        exports,
        default_export,
        parameter: parameter_fact,
        producers,
    })
}

fn callable(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration" | "arrow_function" | "function_expression"
    )
}

fn parameter_shadow(
    node: &Node<'_, StrDoc<SupportLang>>,
    owner: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
) -> bool {
    node.ancestors()
        .take_while(|n| n.range() != owner.range())
        .any(|n| {
            callable(&n)
                && n.field("parameters")
                    .or_else(|| n.field("parameter"))
                    .is_some_and(|p| {
                        p.dfs().any(|n| {
                            matches!(
                                n.kind().as_ref(),
                                "identifier" | "shorthand_property_identifier_pattern"
                            ) && n.text().trim() == name
                        })
                    })
        })
}

fn mentions_module(file: &SourceFile, target: &str) -> bool {
    let stem = Path::new(target)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    // index imports name their directory. This is a cheap prefilter only;
    // actual ownership is checked from AST imports and resolved paths below.
    let token = if stem == "index" {
        Path::new(target)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or(stem)
    } else {
        stem
    };
    file.source.contains(token)
}

fn component_aliases(
    file: &SourceFile,
    root: &Node<'_, StrDoc<SupportLang>>,
    contract: &PropContract,
    sources: &RepositorySources,
) -> BTreeSet<String> {
    if file.path == contract.path {
        if root.dfs().any(|n| {
            matches!(
                n.kind().as_ref(),
                "assignment_expression" | "augmented_assignment_expression"
            ) && n
                .field("left")
                .is_some_and(|n| n.text().trim() == contract.component)
        }) {
            return BTreeSet::new();
        }
        return BTreeSet::from([contract.component.clone()]);
    }
    if contract.exports.is_empty() && !contract.default_export {
        return BTreeSet::new();
    }
    let mut aliases = BTreeSet::new();
    for import in root
        .children()
        .filter(|n| n.kind().as_ref() == "import_statement" && valid(n))
    {
        let Some(module) = import.field("source") else {
            continue;
        };
        let module = module.text();
        let module = module.trim_matches(['\'', '"']);
        if !module.starts_with('.') {
            continue;
        }
        let resolved = resolve_relative_typescript_module(&file.path, module, sources);
        if resolved.as_deref() != Some(&contract.path) {
            continue;
        }
        for spec in import
            .dfs()
            .filter(|n| n.kind().as_ref() == "import_specifier")
        {
            if spec
                .field("name")
                .is_some_and(|n| contract.exports.contains(n.text().trim()))
            {
                if let Some(name) = spec.field("alias").or_else(|| spec.field("name")) {
                    aliases.insert(name.text().to_string());
                }
            }
        }
        if contract.default_export {
            for clause in import
                .children()
                .filter(|n| n.kind().as_ref() == "import_clause")
            {
                if let Some(name) = clause
                    .children()
                    .find(|n| n.kind().as_ref() == "identifier")
                {
                    aliases.insert(name.text().to_string());
                }
            }
        }
    }
    aliases
}

fn shadowed(element: &Node<'_, StrDoc<SupportLang>>, name: &str) -> bool {
    element.ancestors().any(|owner| {
        matches!(
            owner.kind().as_ref(),
            "function_declaration" | "arrow_function" | "function_expression"
        ) && (owner
            .field("parameters")
            .or_else(|| owner.field("parameter"))
            .is_some_and(|p| {
                p.dfs()
                    .any(|n| n.kind().as_ref() == "identifier" && n.text().trim() == name)
            })
            || owner.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "variable_declarator" | "function_declaration"
                ) && n.field("name").is_some_and(|n| n.text().trim() == name)
            }))
    })
}

fn append_producer<'a>(
    file: &SourceFile,
    element: &Node<'a, StrDoc<SupportLang>>,
    expression: Node<'a, StrDoc<SupportLang>>,
    facts: &mut Vec<ReviewNeighborhoodFact>,
    evidence_id: &str,
) {
    let mut expression = expression;
    for _ in 0..2 {
        if expression.kind().as_ref() != "identifier" {
            break;
        }
        let Some(scope) = element.ancestors().find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_declaration" | "arrow_function" | "function_expression"
            )
        }) else {
            break;
        };
        let bindings: Vec<_> = scope
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "variable_declarator"
                    && n.range().start < element.range().start
                    && n.ancestors()
                        .find(|a| {
                            matches!(
                                a.kind().as_ref(),
                                "function_declaration" | "arrow_function" | "function_expression"
                            )
                        })
                        .is_some_and(|a| a.range() == scope.range())
                    && n.ancestors()
                        .find(|a| a.kind().as_ref() == "statement_block")
                        .is_some_and(|a| {
                            a.range().start <= element.range().start
                                && element.range().end <= a.range().end
                        })
                    && n.field("name")
                        .is_some_and(|name| name.text() == expression.text())
                    && n.parent()
                        .is_some_and(|p| p.text().trim_start().starts_with("const "))
            })
            .collect();
        if bindings.len() != 1 {
            break;
        }
        let binding = &bindings[0];
        if binding.range().len() > MAX_FACT_BYTES {
            break;
        }
        facts.push(fact(
            file,
            binding,
            "frontend_prop_producer_context",
            expression.text().trim(),
            evidence_id,
        ));
        let Some(value) = binding.field("value") else {
            break;
        };
        expression = value;
    }
}

fn fact(
    file: &SourceFile,
    node: &Node<'_, StrDoc<SupportLang>>,
    role: &str,
    symbol: &str,
    evidence_id: &str,
) -> ReviewNeighborhoodFact {
    ReviewNeighborhoodFact {
        role: role.into(), symbol: symbol.into(),
        location: location_from_offsets(&file.path, &file.source, node.range().start, node.range().end),
        excerpt: redact_helper_definition(symbol, node.text().as_ref()),
        evidence_id: Some(evidence_id.into()),
        provenance: QueryProvenance { resolution: Resolution::Ast, engine: "bounded JSX component prop/caller navigation; caller trust, reaching values and controls require review 1".into() },
    }
}
