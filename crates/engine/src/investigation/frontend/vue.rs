//! Located Vue setup producers and directly imported callers; no reactive/value proof.
use super::*;

const MAX_PRODUCERS: usize = 4;
const MAX_DEPTH: usize = 2;

pub(super) struct Contract {
    evidence_id: String,
    path: String,
    props: BTreeSet<String>,
}

pub(super) fn prepare(
    file: &SourceFile,
    root: &Node<'_, StrDoc<SupportLang>>,
    evidence: &[Evidence],
    context: &mut FrontendContext,
) -> Vec<Contract> {
    if !crate::code::vue::parse(&file.path, &file.source).setup {
        return Vec::new();
    }
    let shadowed_macro = root.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "variable_declarator" | "function_declaration"
        ) && n
            .field("name")
            .is_some_and(|n| matches!(n.text().as_ref(), "defineProps" | "withDefaults"))
    }) || root
        .children()
        .filter(|n| n.kind().as_ref() == "import_statement")
        .any(|n| {
            n.dfs().any(|n| {
                n.kind().as_ref() == "identifier"
                    && matches!(n.text().as_ref(), "defineProps" | "withDefaults")
            })
        });
    let props = (!shadowed_macro)
        .then(|| {
            root.dfs()
                .find(|n| {
                    n.kind().as_ref() == "variable_declarator"
                        && top_level(n)
                        && valid(n)
                        && n.field("name")
                            .is_some_and(|n| n.kind().as_ref() == "identifier")
                        && props_macro(n).is_some()
                })
                .or_else(|| {
                    root.children().find(|n| {
                        n.kind().as_ref() == "expression_statement"
                            && valid(n)
                            && props_macro(n).is_some()
                    })
                })
        })
        .flatten();
    let mut contracts = Vec::new();
    let html = StrDoc::try_new(&file.source, SupportLang::Html)
        .ok()
        .map(AstGrep::doc);
    for item in evidence
        .iter()
        .filter(|e| e.capability == Capability::HtmlOutput && e.kind == EvidenceKind::Sink)
    {
        let Some(content) = item.captures.get("content") else {
            continue;
        };
        let (facts, partial) = context.packets.entry(item.id.clone()).or_default();
        if item.rule_id == "vue-sfc-v-html-output" {
            if let Some(attribute) = html.as_ref().and_then(|ast| {
                ast.root().dfs().find(|n| {
                    n.kind().as_ref() == "attribute"
                        && n.range().start == item.location.start.byte_offset
                })
            }) {
                let scopes = template_scopes(&attribute);
                if !scopes.is_empty() {
                    *partial = true;
                    add(
                        file,
                        &scopes[0],
                        "frontend_template_scope_context",
                        "Vue template-local binding; producer requires review",
                        &item.id,
                        facts,
                        partial,
                    );
                    continue;
                }
            }
        }
        let mut seeds = Vec::new();
        if item.rule_id == "vue-sfc-v-html-output" {
            // The template expression has no JS node at its original byte offset.
            // Only an exact setup identifier or props.member is connected here.
            if let Some(binding) = root.dfs().find(|n| {
                n.kind().as_ref() == "variable_declarator"
                    && top_level(n)
                    && valid(n)
                    && n.field("name")
                        .is_some_and(|n| n.text() == content.text.trim())
            }) {
                add(
                    file,
                    &binding,
                    "frontend_output_producer_context",
                    "Vue setup binding; updates require review",
                    &item.id,
                    facts,
                    partial,
                );
                if let Some(value) = binding.field("value") {
                    seeds.push(value)
                }
            }
        } else if let Some(operand) = root.dfs().find(|n| {
            n.range().start == content.location.start.byte_offset
                && n.range().end == content.location.end.byte_offset
                && valid(n)
        }) {
            seeds.push(operand);
            for writer in facts
                .iter()
                .filter(|f| f.role == "frontend_output_writer_context")
            {
                if let Some(node) = root.dfs().find(|n| {
                    n.range().start == writer.location.start.byte_offset
                        && n.range().end == writer.location.end.byte_offset
                }) {
                    if let Some(value) = node.field("value").or_else(|| node.field("right")) {
                        seeds.push(value)
                    }
                }
            }
        }
        let mut inspected = seeds.clone();
        let mut visited = BTreeSet::new();
        let mut producers = 0;
        for _ in 0..MAX_DEPTH {
            let mut next = Vec::new();
            for expression in seeds {
                for name in expression
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "identifier")
                {
                    let Some(binding) = lexical_binding(root, &name) else {
                        continue;
                    };
                    if !binding
                        .parent()
                        .is_some_and(|n| n.text().trim_start().starts_with("const "))
                    {
                        continue;
                    }
                    if !visited.insert(binding.range().start) {
                        continue;
                    }
                    if facts.iter().any(|f| {
                        f.location.start.byte_offset == binding.range().start
                            && f.location.end.byte_offset == binding.range().end
                    }) {
                        continue;
                    }
                    if props.as_ref().is_some_and(|p| p.range() == binding.range()) {
                        continue;
                    }
                    if producers == MAX_PRODUCERS {
                        *partial = true;
                        continue;
                    }
                    if add(
                        file,
                        &binding,
                        "frontend_output_dependency_context",
                        "candidate local input; reaching value and transformations require review",
                        &item.id,
                        facts,
                        partial,
                    ) {
                        producers += 1;
                        if let Some(value) = binding.field("value") {
                            inspected.push(value.clone());
                            next.push(value)
                        }
                    }
                }
            }
            seeds = next;
        }
        let Some(props) = props.as_ref() else {
            continue;
        };
        let prop_name = props.field("name").map(|n| n.text().to_string());
        let mut reads = BTreeSet::new();
        for expression in inspected {
            for read in expression
                .dfs()
                .filter(|n| n.kind().as_ref() == "member_expression")
            {
                if prop_name.as_ref().is_some_and(|prop_name| {
                    read.field("object").is_some_and(|n| {
                        n.kind().as_ref() == "identifier" && n.text() == prop_name.as_str()
                    }) && !crate::code::vue::ref_shadowed(&read, prop_name)
                }) {
                    if let Some(property) = read
                        .field("property")
                        .filter(|n| n.kind().as_ref() == "property_identifier")
                    {
                        reads.insert(property.text().to_string());
                    }
                }
            }
        }
        if item.rule_id == "vue-sfc-v-html-output" {
            if let Some(prop_name) = prop_name {
                if let Some(property) = content
                    .text
                    .trim()
                    .strip_prefix(&format!("{prop_name}."))
                    .filter(|p| is_plain_identifier(p))
                {
                    reads.insert(property.into());
                }
            }
            if let Some(head) = content
                .text
                .trim()
                .split('.')
                .next()
                .filter(|p| is_plain_identifier(p))
            {
                let setup_binding = root.dfs().any(|n| {
                    n.kind().as_ref() == "variable_declarator"
                        && top_level(&n)
                        && n.field("name").is_some_and(|n| n.text() == head)
                });
                if !setup_binding && declared_props(root, props).contains(head) {
                    reads.insert(head.into());
                }
            }
        }
        if reads.is_empty() {
            continue;
        }
        add(
            file,
            props,
            "frontend_component_prop_context",
            "Vue defineProps binding; caller authority requires review",
            &item.id,
            facts,
            partial,
        );
        // Locate an actual named type, rather than assuming a macro's generic
        // name tells the reviewer what the props contain.
        let mut types = 0;
        for declaration in root.children().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "interface_declaration" | "type_alias_declaration"
            )
        }) {
            if declaration.field("name").is_some_and(|name| {
                props
                    .dfs()
                    .any(|n| n.kind().as_ref() == "type_identifier" && n.text() == name.text())
            }) {
                if types == 2 {
                    *partial = true;
                    break;
                }
                types += 1;
                add(
                    file,
                    &declaration,
                    "frontend_component_prop_type_context",
                    "Vue props type",
                    &item.id,
                    facts,
                    partial,
                );
            }
        }
        contracts.push(Contract {
            evidence_id: item.id.clone(),
            path: file.path.clone(),
            props: reads,
        });
    }
    if !context.packets.is_empty() {
        context
            .imports
            .entry(file.path.clone())
            .or_insert_with(|| import_facts(file, root));
    }
    contracts
}

fn top_level(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.parent()
        .and_then(|n| n.parent())
        .is_some_and(|n| n.kind().as_ref() == "program")
}

fn props_macro<'a>(node: &Node<'a, StrDoc<SupportLang>>) -> Option<Node<'a, StrDoc<SupportLang>>> {
    let value = node
        .field("value")
        .or_else(|| {
            node.children()
                .find(|n| n.kind().as_ref() == "call_expression")
        })
        .unwrap_or_else(|| node.clone());
    let call = if value
        .field("function")
        .is_some_and(|n| n.text() == "withDefaults")
    {
        value
            .field("arguments")?
            .children()
            .find(|n| n.is_named())?
    } else {
        value
    };
    (call.kind().as_ref() == "call_expression"
        && call
            .field("function")
            .is_some_and(|n| n.text() == "defineProps"))
    .then_some(call)
}

fn declared_props<'a>(
    root: &Node<'a, StrDoc<SupportLang>>,
    declaration: &Node<'a, StrDoc<SupportLang>>,
) -> BTreeSet<String> {
    let Some(call) = props_macro(declaration) else {
        return BTreeSet::new();
    };
    let mut names = BTreeSet::new();
    let mut containers = Vec::new();
    if let Some(types) = call
        .children()
        .find(|n| n.kind().as_ref() == "type_arguments")
    {
        containers.push(types.clone());
        for declaration in root.children().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "interface_declaration" | "type_alias_declaration"
            )
        }) {
            if declaration.field("name").is_some_and(|name| {
                types
                    .dfs()
                    .any(|n| n.kind().as_ref() == "type_identifier" && n.text() == name.text())
            }) {
                containers.push(declaration);
            }
        }
    } else if let Some(argument) = call
        .field("arguments")
        .and_then(|n| n.children().find(|n| n.is_named()))
    {
        if argument.kind().as_ref() == "array" {
            for name in argument
                .children()
                .filter(|n| n.kind().as_ref() == "string")
            {
                let text = name.text();
                if !text.contains('\\') {
                    names.insert(text[1..text.len() - 1].to_string());
                }
            }
        } else if argument.kind().as_ref() == "object" {
            containers.push(argument)
        }
    }
    for container in containers {
        for property in container
            .dfs()
            .filter(|n| matches!(n.kind().as_ref(), "property_signature" | "pair"))
        {
            if property
                .ancestors()
                .take_while(|n| n.range() != container.range())
                .filter(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "object_type" | "object" | "interface_body"
                    )
                })
                .count()
                > 1
            {
                continue;
            }
            if let Some(name) = property.field("name").or_else(|| property.field("key")) {
                let text = name.text();
                let text = text.trim_matches(['\'', '"']);
                if is_plain_identifier(text) {
                    names.insert(text.into());
                }
            }
        }
    }
    names
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
                    && n.field("name").is_some_and(|n| {
                        n.kind().as_ref() == "identifier" && n.text() == name.text()
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
                && bindings[0].range().start < name.range().start
                && valid(&bindings[0]))
            .then(|| bindings[0].clone());
        }
    }
    None
}

fn add(
    file: &SourceFile,
    node: &Node<'_, StrDoc<SupportLang>>,
    role: &str,
    symbol: &str,
    id: &str,
    facts: &mut Vec<ReviewNeighborhoodFact>,
    partial: &mut bool,
) -> bool {
    if node.range().len() > MAX_FACT_BYTES || !valid(node) {
        *partial = true;
        return false;
    }
    if !facts.iter().any(|f| {
        f.role == role
            && f.location.start.byte_offset == node.range().start
            && f.location.path == file.path
    }) {
        facts.push(fact(file, node, role, symbol, id));
    }
    true
}

fn import_facts(
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
                    "Vue caller/helper import",
                    "",
                ),
            )
        })
        .collect()
}

pub(super) fn callers(
    sources: &RepositorySources,
    contracts: &[Contract],
    documents: &mut BTreeMap<String, Option<AstGrep<StrDoc<SupportLang>>>>,
    context: &mut FrontendContext,
) {
    if contracts.is_empty() {
        return;
    }
    for file in sources.files.values().filter(|f| {
        f.path.ends_with(".vue") && contracts.iter().any(|c| mentions_module(f, &c.path))
    }) {
        let Some(ast) = documents
            .entry(file.path.clone())
            .or_insert_with(|| parse(file))
            .as_ref()
        else {
            continue;
        };
        let root = ast.root();
        if !crate::code::vue::parse(&file.path, &file.source).setup {
            continue;
        }
        let Ok(doc) = StrDoc::try_new(&file.source, SupportLang::Html) else {
            continue;
        };
        let html = AstGrep::doc(doc);
        let templates: Vec<_> = html
            .root()
            .children()
            .filter(|n| {
                n.children().any(|t| {
                    t.kind().as_ref() == "start_tag"
                        && t.children().any(|name| {
                            name.kind().as_ref() == "tag_name" && name.text() == "template"
                        })
                })
            })
            .collect();
        if templates.len() != 1 {
            continue;
        }
        let template = &templates[0];
        let Some(open) = template
            .children()
            .find(|n| n.kind().as_ref() == "start_tag")
        else {
            continue;
        };
        if open.children().any(|n| {
            n.kind().as_ref() == "attribute"
                && n.children().any(|a| {
                    a.kind().as_ref() == "attribute_name"
                        && matches!(a.text().as_ref(), "src" | "lang")
                })
        }) {
            continue;
        }
        for import in root.children().filter(|n| {
            n.kind().as_ref() == "import_statement"
                && valid(n)
                && !n.text().trim_start().starts_with("import type ")
        }) {
            let Some(module) = import.field("source") else {
                continue;
            };
            let module = module.text();
            let module = module.trim_matches(['\'', '"']);
            if !module.starts_with('.') || !module.ends_with(".vue") || module.contains('\\') {
                continue;
            }
            let path = relative_vue_path(&file.path, module);
            let Some(alias) = import
                .children()
                .find(|n| n.kind().as_ref() == "import_clause")
                .and_then(|n| n.children().find(|n| n.kind().as_ref() == "identifier"))
            else {
                continue;
            };
            let alias = alias.text();
            let kebab: String = alias
                .chars()
                .enumerate()
                .flat_map(|(i, c)| {
                    let mut out = String::new();
                    if i > 0 && c.is_ascii_uppercase() {
                        out.push('-')
                    }
                    out.push(c.to_ascii_lowercase());
                    out.chars().collect::<Vec<_>>()
                })
                .collect();
            for contract in contracts
                .iter()
                .filter(|c| path.as_deref() == Some(&c.path))
            {
                for tag in template.dfs().filter(|n| {
                    matches!(n.kind().as_ref(), "start_tag" | "self_closing_tag") && valid(n)
                }) {
                    if !tag.children().any(|n| {
                        n.kind().as_ref() == "tag_name"
                            && (n.text() == alias || n.text().as_ref() == kebab)
                    }) {
                        continue;
                    }
                    if tag
                        .ancestors()
                        .take_while(|n| n.range() != template.range())
                        .any(|n| matches!(n.kind().as_ref(), "script_element" | "style_element"))
                    {
                        continue;
                    }
                    let attrs: Vec<_> = tag
                        .children()
                        .filter(|n| n.kind().as_ref() == "attribute")
                        .collect();
                    let spread = attrs.iter().any(|a| {
                        a.children().any(|n| {
                            n.kind().as_ref() == "attribute_name"
                                && (n.text() == "v-bind" || n.text().starts_with("v-bind:["))
                        })
                    });
                    let relevant: Vec<_> = attrs
                        .iter()
                        .filter(|a| {
                            a.children().any(|n| {
                                n.kind().as_ref() == "attribute_name"
                                    && contract
                                        .props
                                        .iter()
                                        .any(|p| prop_attribute(n.text().as_ref(), p))
                            })
                        })
                        .collect();
                    if relevant.is_empty() && !spread {
                        continue;
                    }
                    let (facts, partial) = context.packets.get_mut(&contract.evidence_id).unwrap();
                    if facts
                        .iter()
                        .filter(|f| f.role == "frontend_prop_caller_context")
                        .count()
                        >= MAX_CALLERS
                    {
                        *partial = true;
                        continue;
                    }
                    *partial |= spread || html.root().dfs().any(|n| n.is_error() || n.is_missing());
                    let scopes = template_scopes(&tag);
                    let template_local = !scopes.is_empty();
                    *partial |= template_local;
                    if add(
                        file,
                        &tag,
                        "frontend_prop_caller_context",
                        "directly imported Vue child; prop authority and updates require review",
                        &contract.evidence_id,
                        facts,
                        partial,
                    ) {
                        if let Some(scope) = scopes.first() {
                            add(
                                file,
                                scope,
                                "frontend_template_scope_context",
                                "caller template-local binding; collection/slot authority requires review",
                                &contract.evidence_id,
                                facts,
                                partial,
                            );
                        }
                        for attr in relevant {
                            if spread
                                || template_local
                                || !attr.children().any(|n| {
                                    n.kind().as_ref() == "attribute_name"
                                        && (n.text().starts_with(':')
                                            || n.text().starts_with("v-bind:")
                                            || n.text().starts_with("v-model"))
                                })
                            {
                                continue;
                            }
                            if let Some(value) =
                                attr.dfs().find(|n| n.kind().as_ref() == "attribute_value")
                            {
                                if let Some(binding) = root.dfs().find(|n| {
                                    n.kind().as_ref() == "variable_declarator"
                                        && top_level(n)
                                        && n.field("name").is_some_and(|n| n.text() == value.text())
                                }) {
                                    if facts
                                        .iter()
                                        .filter(|f| f.role == "frontend_prop_producer_context")
                                        .count()
                                        >= MAX_PRODUCERS
                                    {
                                        *partial = true;
                                        continue;
                                    }
                                    add(
                                        file,
                                        &binding,
                                        "frontend_prop_producer_context",
                                        "caller setup binding; updates require review",
                                        &contract.evidence_id,
                                        facts,
                                        partial,
                                    );
                                }
                            }
                        }
                        context
                            .imports
                            .entry(file.path.clone())
                            .or_insert_with(|| import_facts(file, &root));
                    }
                }
            }
        }
    }
}

fn relative_vue_path(importer: &str, module: &str) -> Option<String> {
    let mut parts: Vec<_> = importer.split('/').collect();
    parts.pop()?;
    for part in module.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value),
        }
    }
    Some(parts.join("/"))
}

fn prop_attribute(attribute: &str, prop: &str) -> bool {
    let kebab: String = prop
        .chars()
        .flat_map(|c| {
            if c.is_ascii_uppercase() {
                vec!['-', c.to_ascii_lowercase()]
            } else {
                vec![c]
            }
        })
        .collect();
    let attribute = attribute
        .strip_prefix(':')
        .or_else(|| attribute.strip_prefix("v-bind:"))
        .or_else(|| attribute.strip_prefix("v-model:"))
        .unwrap_or(attribute);
    attribute == prop || attribute == kebab || attribute == "v-model" && prop == "modelValue"
}

fn template_scopes<'a>(node: &Node<'a, StrDoc<SupportLang>>) -> Vec<Node<'a, StrDoc<SupportLang>>> {
    node.ancestors()
        .flat_map(|n| {
            n.children()
                .filter(|n| matches!(n.kind().as_ref(), "start_tag" | "self_closing_tag"))
                .collect::<Vec<_>>()
        })
        .filter(|tag| {
            tag.children()
                .filter(|n| n.kind().as_ref() == "attribute")
                .any(|n| {
                    n.children().any(|n| {
                        n.kind().as_ref() == "attribute_name"
                            && (n.text() == "v-for"
                                || n.text().starts_with("v-slot")
                                || n.text().starts_with('#'))
                    })
                })
        })
        .collect()
}
