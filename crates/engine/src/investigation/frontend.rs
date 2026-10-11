//! Bounded frontend navigation for existing raw-HTML reviews, not taint or safety.
use super::*;
mod helpers;
mod vue;

const MAX_CALLERS: usize = 2;
const MAX_PROPS: usize = 3;
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
    props: BTreeSet<String>,
    partial: bool,
    exports: BTreeSet<String>,
    default_export: bool,
    parameter: ReviewNeighborhoodFact,
    wrappers: Vec<ReviewNeighborhoodFact>,
}

impl FrontendContext {
    pub(super) fn build(sources: &RepositorySources, groups: &[ObservationGroup]) -> Self {
        let mut context = Self::default();
        let mut contracts = Vec::new();
        let mut vue_contracts = Vec::new();
        let mut documents = BTreeMap::new();
        for group in groups {
            let Ok(file) = sources.file(&group.path) else {
                continue;
            };
            if group
                .evidence
                .iter()
                .any(|e| e.tags.iter().any(|t| t == "vue-dom-ref"))
            {
                if let Some(ast) = documents
                    .entry(file.path.clone())
                    .or_insert_with(|| parse(file))
                    .as_ref()
                {
                    let root = ast.root();
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
                                        "Vue/helper import",
                                        "",
                                    ),
                                )
                            })
                            .collect(),
                    );
                    for item in group
                        .evidence
                        .iter()
                        .filter(|e| e.tags.iter().any(|t| t == "vue-dom-ref"))
                    {
                        let mut facts = Vec::new();
                        let mut partial = false;
                        for (key, role) in [
                            ("vue_dom_ref_template", "frontend_dom_ref_template_context"),
                            (
                                "vue_dom_ref_declaration",
                                "frontend_dom_ref_declaration_context",
                            ),
                        ] {
                            if let Some(capture) = item
                                .captures
                                .get(key)
                                .filter(|c| c.text.len() <= MAX_FACT_BYTES)
                            {
                                facts.push(ReviewNeighborhoodFact {role:role.into(),symbol:"Vue native DOM ref".into(),location:capture.location.clone(),excerpt:capture.text.clone(),evidence_id:Some(item.id.clone()),provenance:QueryProvenance {resolution:Resolution::Ast,engine:"bounded Vue native template ref navigation; input trust and controls require review 1".into()}});
                            }
                        }
                        if let Some(capture) = item.captures.get("content") {
                            if let Some(operand) = root.dfs().find(|n| {
                                n.range().start == capture.location.start.byte_offset
                                    && n.range().end == capture.location.end.byte_offset
                                    && valid(n)
                            }) {
                                if operand.range().len() <= MAX_FACT_BYTES {
                                    facts.push(fact(
                                        file,
                                        &operand,
                                        "frontend_output_producer_context",
                                        "HTML operand",
                                        &item.id,
                                    ));
                                }
                                if operand.kind().as_ref() == "identifier" {
                                    let owner = operand.ancestors().find(|n| {
                                        matches!(
                                            n.kind().as_ref(),
                                            "function_declaration"
                                                | "arrow_function"
                                                | "function_expression"
                                        )
                                    });
                                    if let Some(owner) = owner {
                                        let name = operand.text();
                                        for writer in owner
                                            .dfs()
                                            .filter(|n| {
                                                valid(n)
                                                    && n.range().start < operand.range().start
                                                    && n.range().len() <= MAX_FACT_BYTES
                                                    && n.ancestors()
                                                        .find(|a| {
                                                            matches!(
                                                                a.kind().as_ref(),
                                                                "function_declaration"
                                                                    | "arrow_function"
                                                                    | "function_expression"
                                                            )
                                                        })
                                                        .is_some_and(|a| a.range() == owner.range())
                                                    && match n.kind().as_ref() {
                                                        "variable_declarator" => n
                                                            .field("name")
                                                            .is_some_and(|n| n.text() == name),
                                                        "assignment_expression"
                                                        | "augmented_assignment_expression" => n
                                                            .field("left")
                                                            .is_some_and(|n| n.text() == name),
                                                        _ => false,
                                                    }
                                            })
                                            .take(4)
                                        {
                                            if facts
                                                .iter()
                                                .filter(|f| {
                                                    f.role == "frontend_output_writer_context"
                                                })
                                                .count()
                                                == 3
                                            {
                                                partial = true;
                                                break;
                                            }
                                            facts.push(fact(file,&writer,"frontend_output_writer_context","candidate operand writer; branches and later changes require review",&item.id));
                                        }
                                    }
                                }
                            }
                        }
                        context.packets.insert(item.id.clone(), (facts, partial));
                    }
                }
            }
            if file.path.ends_with(".vue") {
                if let Some(ast) = documents
                    .entry(file.path.clone())
                    .or_insert_with(|| parse(file))
                    .as_ref()
                {
                    vue_contracts.extend(vue::prepare(
                        file,
                        &ast.root(),
                        &group.evidence,
                        &mut context,
                    ));
                }
            }
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
            context
                .imports
                .entry(file.path.clone())
                .or_insert_with(|| import_bindings(file, &ast.root()));
            for sink in sinks {
                let root = ast.root();
                let Some(operand) = sink.captures.get("content").and_then(|capture| {
                    root.dfs().find(|n| {
                        n.range().start == capture.location.start.byte_offset
                            && n.range().end == capture.location.end.byte_offset
                            && valid(n)
                    })
                }) else {
                    continue;
                };
                let (facts, partial) = context.packets.entry(sink.id.clone()).or_default();
                let expressions = dependencies(
                    file,
                    &root,
                    vec![operand],
                    facts,
                    partial,
                    &sink.id,
                    "frontend_output_producer_context",
                );
                if let Some(contract) = prop_contract(file, &root, sink, &expressions) {
                    *partial |= contract.partial;
                    facts.push(contract.parameter.clone());
                    facts.extend(contract.wrappers.clone());
                    append_prop_types(file, &root, &contract.parameter, &sink.id, facts, partial);
                    contracts.push(contract);
                }
            }
        }
        vue::callers(sources, &vue_contracts, &mut documents, &mut context);

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
            context
                .imports
                .entry(file.path.clone())
                .or_insert_with(|| import_bindings(file, &root));
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
                    let attributes: Vec<_> = contract
                        .props
                        .iter()
                        .map(|prop| {
                            (
                                prop,
                                element
                                    .children()
                                    .filter(|n| {
                                        n.kind().as_ref() == "jsx_attribute"
                                            && n.children()
                                                .find(|c| c.is_named())
                                                .is_some_and(|n| n.text().trim() == prop)
                                    })
                                    .collect::<Vec<_>>(),
                            )
                        })
                        .collect();
                    let spread = element
                        .children()
                        .any(|n| n.kind().as_ref() == "jsx_expression");
                    if attributes.iter().all(|(_, values)| values.is_empty()) && !spread {
                        continue;
                    }
                    let (facts, truncated) = context
                        .packets
                        .entry(contract.evidence_id.clone())
                        .or_default();
                    *truncated |= partial_parse;
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
                    // Omitted/duplicate props and spreads have unresolved reaching
                    // values. Preserve the caller once, then bind only exact args.
                    *truncated |= spread || attributes.iter().any(|(_, values)| values.len() != 1);
                    facts.push(fact(
                        file,
                        &element,
                        "frontend_prop_caller_context",
                        &contract
                            .props
                            .iter()
                            .map(|prop| format!("{}.{}", contract.component, prop))
                            .collect::<Vec<_>>()
                            .join(", "),
                        &contract.evidence_id,
                    ));
                    for (prop, values) in attributes
                        .iter()
                        .filter(|(_, values)| !spread && values.len() == 1)
                    {
                        let value = values[0].children().filter(|n| n.is_named()).nth(1);
                        if value.is_none() && contract.props.len() > 1 {
                            // Bare JSX attributes are explicit boolean arguments.
                            facts.push(fact(
                                file,
                                &values[0],
                                "frontend_prop_value_context",
                                &format!("{}.{}", contract.component, prop),
                                &contract.evidence_id,
                            ));
                        }
                        if let Some(value) = value {
                            let expression = if value.kind().as_ref() == "jsx_expression" {
                                value.children().find(|n| n.is_named())
                            } else {
                                Some(value)
                            };
                            if let Some(expression) = expression {
                                if contract.props.len() > 1 {
                                    facts.push(fact(
                                        file,
                                        &expression,
                                        "frontend_prop_value_context",
                                        &format!("{}.{}", contract.component, prop),
                                        &contract.evidence_id,
                                    ));
                                }
                                append_producer(
                                    file,
                                    &root,
                                    expression,
                                    facts,
                                    truncated,
                                    &contract.evidence_id,
                                );
                            } else {
                                *truncated = true;
                            }
                        }
                    }
                }
            }
        }
        helpers::append(sources, &mut documents, &mut context);
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
        // Output helper ownership is decisive before upstream caller sampling.
        // Preserve the existing four-import cap instead of enlarging packets.
        let mut ordered: Vec<_> = facts.iter().collect();
        ordered.sort_by_key(|f| {
            !(f.role == "frontend_imported_helper_context"
                || f.role.starts_with("frontend_helper_"))
        });
        for source in ordered {
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
    if file.path.ends_with(".vue") && file.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
        let sfc = crate::code::vue::parse(&file.path, &file.source);
        return Some(AstGrep::doc(
            StrDoc::try_new(&sfc.script, parser_language(sfc.language)).ok()?,
        ));
    }
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

fn import_bindings(
    file: &SourceFile,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> Vec<(Vec<String>, ReviewNeighborhoodFact)> {
    root.children()
        .filter(|n| {
            n.kind().as_ref() == "import_statement" && valid(n) && n.range().len() <= MAX_FACT_BYTES
        })
        .map(|n| {
            (
                n.dfs()
                    .filter(|n| n.kind().as_ref() == "identifier")
                    .map(|n| n.text().to_string())
                    .collect(),
                fact(
                    file,
                    &n,
                    "frontend_import_binding_context",
                    "frontend helper/component imports",
                    "",
                ),
            )
        })
        .collect()
}

fn prop_contract(
    file: &SourceFile,
    root: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    expressions: &[Node<'_, StrDoc<SupportLang>>],
) -> Option<PropContract> {
    let capture = sink.captures.get("content")?;
    let node = root.dfs().find(|n| {
        n.range().start == capture.location.start.byte_offset
            && n.range().end == capture.location.end.byte_offset
    })?;
    // A nested render callback can capture its component's props. Bind the
    // enclosing component, not the callback; parameter_shadow still rejects
    // intervening parameter/block bindings. Do not cross a class boundary.
    let owner = node
        .ancestors()
        .take_while(|n| !matches!(n.kind().as_ref(), "class_declaration" | "class"))
        .filter(callable)
        .last()?;
    if !valid(&owner) || owner.ancestors().any(|n| n.is_error() || n.is_missing()) {
        return None;
    }
    let mut wrappers = Vec::new();
    let (name, binding) = if owner.kind().as_ref() == "function_declaration" {
        (owner.field("name")?, owner.clone())
    } else {
        let mut value = owner.clone();
        for _ in 0..2 {
            let Some(arguments) = value.parent().filter(|n| n.kind().as_ref() == "arguments")
            else {
                break;
            };
            if arguments.children().find(|n| n.is_named())?.range() != value.range() {
                return None;
            }
            let call = arguments.parent()?;
            let callee = call.field("function")?;
            if !react_wrapper(root, &callee) {
                return None;
            }
            wrappers.push(fact(
                file,
                &callee,
                "frontend_component_wrapper_context",
                "React component wrapper; not an HTML control",
                &sink.id,
            ));
            value = call;
        }
        let binding = value.parent()?;
        if binding.kind().as_ref() != "variable_declarator"
            || binding.field("value")?.range() != value.range()
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
    let mut reads = BTreeSet::new();
    if pattern.kind().as_ref() == "identifier" {
        let object = pattern.text().to_string();
        for read in expressions
            .iter()
            .flat_map(|expression| expression.dfs())
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
                && expressions
                    .iter()
                    .flat_map(|expression| expression.dfs())
                    .any(|n| {
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
    if reads.is_empty() {
        return None;
    }
    let content = capture.text.trim();
    if reads.iter().any(|(prop, local)| {
        owner.dfs().any(|n| {
            matches!(
                n.kind().as_ref(),
                "assignment_expression" | "augmented_assignment_expression" | "update_expression"
            ) && n
                .field("left")
                .or_else(|| n.field("argument"))
                .is_some_and(|left| {
                    left.text().trim() == local.as_str()
                        || left.text().trim() == content
                        || left.text().trim() == format!("{local}.{prop}")
                })
        })
    }) {
        return None;
    }
    let partial = reads.len() > MAX_PROPS;
    let props: BTreeSet<_> = reads
        .into_iter()
        .take(MAX_PROPS)
        .map(|(prop, _)| prop)
        .collect();
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
        &props
            .iter()
            .map(|prop| format!("{component}.{prop}"))
            .collect::<Vec<_>>()
            .join(", "),
        &sink.id,
    );
    Some(PropContract {
        evidence_id: sink.id.clone(),
        path: file.path.clone(),
        component,
        props,
        partial,
        exports,
        default_export,
        parameter: parameter_fact,
        wrappers,
    })
}

fn react_wrapper(
    root: &Node<'_, StrDoc<SupportLang>>,
    callee: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let (binding, method) = if callee.kind().as_ref() == "member_expression" {
        let Some(object) = callee
            .field("object")
            .filter(|n| n.kind().as_ref() == "identifier")
        else {
            return false;
        };
        let Some(property) = callee.field("property") else {
            return false;
        };
        (object.text().to_string(), Some(property.text().to_string()))
    } else if callee.kind().as_ref() == "identifier" {
        (callee.text().to_string(), None)
    } else {
        return false;
    };
    if method
        .as_ref()
        .is_some_and(|m| !matches!(m.as_str(), "memo" | "forwardRef"))
        || shadowed(callee, &binding)
        || root.dfs().any(|n| {
            matches!(
                n.kind().as_ref(),
                "assignment_expression" | "augmented_assignment_expression"
            ) && n
                .field("left")
                .is_some_and(|n| n.text() == binding || n.text() == callee.text())
        })
    {
        return false;
    }
    root.children()
        .filter(|n| {
            n.kind().as_ref() == "import_statement"
                && valid(n)
                && !n.text().trim_start().starts_with("import type ")
                && n.field("source")
                    .is_some_and(|n| n.text().trim_matches(['\'', '"']) == "react")
        })
        .any(|import| {
            if method.is_some() {
                import
                    .children()
                    .filter(|n| n.kind().as_ref() == "import_clause")
                    .flat_map(|n| n.children().collect::<Vec<_>>())
                    .any(|n| {
                        n.kind().as_ref() == "identifier" && n.text() == binding
                            || n.kind().as_ref() == "namespace_import"
                                && n.dfs().any(|n| {
                                    n.kind().as_ref() == "identifier" && n.text() == binding
                                })
                    })
            } else {
                import
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "import_specifier")
                    .any(|n| {
                        n.field("name")
                            .is_some_and(|n| matches!(n.text().as_ref(), "memo" | "forwardRef"))
                            && n.field("alias")
                                .or_else(|| n.field("name"))
                                .is_some_and(|n| n.text() == binding)
                    })
            }
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
            (callable(&n)
                && n.field("parameters")
                    .or_else(|| n.field("parameter"))
                    .is_some_and(|p| {
                        p.dfs().any(|n| {
                            matches!(
                                n.kind().as_ref(),
                                "identifier" | "shorthand_property_identifier_pattern"
                            ) && n.text().trim() == name
                        })
                    }))
                || n.kind().as_ref() == "statement_block"
                    && n.dfs().any(|binding| {
                        binding.kind().as_ref() == "variable_declarator"
                            && binding
                                .ancestors()
                                .find(|a| a.kind().as_ref() == "statement_block")
                                .is_some_and(|a| a.range() == n.range())
                            && binding.field("name").is_some_and(|p| {
                                p.dfs().any(|part| {
                                    matches!(
                                        part.kind().as_ref(),
                                        "identifier" | "shorthand_property_identifier_pattern"
                                    ) && part.text() == name
                                })
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
                p.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "identifier" | "shorthand_property_identifier_pattern"
                    ) && n.text().trim() == name
                })
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
    root: &Node<'a, StrDoc<SupportLang>>,
    expression: Node<'a, StrDoc<SupportLang>>,
    facts: &mut Vec<ReviewNeighborhoodFact>,
    partial: &mut bool,
    evidence_id: &str,
) {
    dependencies(
        file,
        root,
        vec![expression],
        facts,
        partial,
        evidence_id,
        "frontend_prop_producer_context",
    );
}

// Candidate lexical inputs, not reaching-value/taint proof. Shared by Vue/JSX.
fn dependencies<'a>(
    file: &SourceFile,
    root: &Node<'a, StrDoc<SupportLang>>,
    mut seeds: Vec<Node<'a, StrDoc<SupportLang>>>,
    facts: &mut Vec<ReviewNeighborhoodFact>,
    partial: &mut bool,
    id: &str,
    role: &str,
) -> Vec<Node<'a, StrDoc<SupportLang>>> {
    let mut inspected = seeds.clone();
    let mut visited = BTreeSet::new();
    let mut count = facts.iter().filter(|f| f.role == role).count();
    for seed in seeds
        .iter()
        .filter(|_| role == "frontend_output_producer_context")
    {
        if seed.kind().as_ref() == "identifier"
            || facts.iter().any(|f| {
                f.location.path == file.path
                    && f.location.start.byte_offset <= seed.range().start
                    && f.location.end.byte_offset >= seed.range().end
            })
        {
            continue;
        }
        if seed.range().len() > MAX_FACT_BYTES || count == 4 {
            *partial = true;
            continue;
        }
        facts.push(fact(
            file,
            seed,
            role,
            "HTML input expression; transformations require review",
            id,
        ));
        count += 1;
    }
    for _ in 0..2 {
        let mut next = Vec::new();
        for expression in seeds {
            for name in expression.dfs().filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "identifier" | "shorthand_property_identifier"
                )
            }) {
                let Some(binding) = lexical_binding(root, &name) else {
                    continue;
                };
                if !binding
                    .parent()
                    .is_some_and(|n| n.text().trim_start().starts_with("const "))
                    || !visited.insert(binding.range().start)
                {
                    continue;
                }
                if file.path.ends_with(".vue") && vue::props_macro(&binding).is_some() {
                    continue; // Pack the actual props contract only when read.
                }
                let covered = facts.iter().any(|f| {
                    f.location.path == file.path
                        && f.location.start.byte_offset <= binding.range().start
                        && f.location.end.byte_offset >= binding.range().end
                });
                if !covered {
                    if count == 4 || binding.range().len() > MAX_FACT_BYTES {
                        *partial = true;
                        continue;
                    }
                    facts.push(fact(
                        file,
                        &binding,
                        role,
                        "candidate local input; reaching value and transformations require review",
                        id,
                    ));
                    count += 1;
                }
                // Covered nested declarations still contribute their inputs.
                if let Some(value) = binding.field("value") {
                    inspected.push(value.clone());
                    next.push(value);
                }
            }
        }
        seeds = next;
    }
    inspected
}

fn lexical_binding<'a>(
    root: &Node<'a, StrDoc<SupportLang>>,
    name: &Node<'a, StrDoc<SupportLang>>,
) -> Option<Node<'a, StrDoc<SupportLang>>> {
    for scope in name
        .ancestors()
        .filter(|n| matches!(n.kind().as_ref(), "statement_block" | "program") || callable(n))
    {
        if callable(&scope)
            && scope
                .field("parameters")
                .or_else(|| scope.field("parameter"))
                .is_some_and(|p| {
                    p.dfs().any(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "identifier" | "shorthand_property_identifier_pattern"
                        ) && n.text() == name.text()
                    })
                })
        {
            return None;
        }
        let bindings: Vec<_> = root
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "variable_declarator"
                    && n.field("name").is_some_and(|pattern| {
                        pattern.dfs().any(|n| {
                            matches!(
                                n.kind().as_ref(),
                                "identifier" | "shorthand_property_identifier_pattern"
                            ) && n.text() == name.text()
                        })
                    })
                    && n.ancestors()
                        .find(|a| {
                            matches!(a.kind().as_ref(), "statement_block" | "program")
                                || callable(a)
                        })
                        .is_some_and(|a| a.range() == scope.range())
            })
            .collect();
        if !bindings.is_empty() {
            return (bindings.len() == 1
                && bindings[0]
                    .field("name")
                    .is_some_and(|n| n.kind().as_ref() == "identifier")
                && bindings[0].range().start < name.range().start
                && valid(&bindings[0]))
            .then(|| bindings[0].clone());
        }
    }
    None
}

fn append_prop_types(
    file: &SourceFile,
    root: &Node<'_, StrDoc<SupportLang>>,
    parameter: &ReviewNeighborhoodFact,
    id: &str,
    facts: &mut Vec<ReviewNeighborhoodFact>,
    partial: &mut bool,
) {
    let Some(parameter) = root.dfs().find(|n| {
        n.range().start == parameter.location.start.byte_offset
            && n.range().end == parameter.location.end.byte_offset
    }) else {
        return;
    };
    let names: BTreeSet<_> = parameter
        .dfs()
        .filter(|n| n.kind().as_ref() == "type_identifier")
        .map(|n| n.text().to_string())
        .collect();
    for declaration in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "interface_declaration" | "type_alias_declaration"
        ) && n
            .ancestors()
            .all(|a| matches!(a.kind().as_ref(), "program" | "export_statement"))
            && n.field("name")
                .is_some_and(|n| names.contains(n.text().as_ref()))
    }) {
        if facts
            .iter()
            .filter(|f| f.role == "frontend_component_prop_type_context")
            .count()
            == 2
            || declaration.range().len() > MAX_FACT_BYTES
        {
            *partial = true;
            continue;
        }
        facts.push(fact(
            file,
            &declaration,
            "frontend_component_prop_type_context",
            "local props type; input trust requires review",
            id,
        ));
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
        provenance: QueryProvenance { resolution: Resolution::Ast, engine: if file.path.ends_with(".vue") {"bounded Vue operand/writer navigation; reaching values and controls require review 1"} else {"bounded JSX component prop/caller navigation; caller trust, reaching values and controls require review 1"}.into() },
    }
}
