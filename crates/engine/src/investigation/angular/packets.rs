use super::*;
use registry::{Declaration, Kind, Registry, bounded_fact, core_imports};
use templates::{Binding, Template, pipe_names};

pub(crate) struct AngularContext {
    registry: Registry,
}

struct Packet {
    facts: Vec<ReviewNeighborhoodFact>,
    partial: bool,
    limit: usize,
    bytes: usize,
}
impl Packet {
    fn push(&mut self, fact: ReviewNeighborhoodFact) -> bool {
        if self
            .facts
            .iter()
            .any(|f| f.role == fact.role && f.location == fact.location)
        {
            return true;
        }
        if self.facts.len() == self.limit || self.bytes + fact.excerpt.len() > 6144 {
            self.partial = true;
            return false;
        }
        self.bytes += fact.excerpt.len();
        self.facts.push(fact);
        true
    }
    fn template(&mut self, template: &Template, binding: &Binding, role: &str, name: &str) -> bool {
        if let Some(fact) = template.fact(binding.start, binding.end, role, name) {
            self.push(fact)
        } else {
            self.partial = true;
            false
        }
    }
}

struct Input {
    name: String,
    alias: String,
    fact: ReviewNeighborhoodFact,
}

impl AngularContext {
    pub(crate) fn build(sources: &RepositorySources) -> Self {
        Self {
            registry: Registry::build(sources),
        }
    }

    pub(crate) fn facts(
        &self,
        sources: &RepositorySources,
        paths: &BTreeSet<&str>,
        existing: &[ReviewNeighborhoodFact],
        precise: Option<&BTreeSet<String>>,
        limit: usize,
        anchor: Option<&Location>,
    ) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let mut packet = Packet {
            facts: Vec::new(),
            partial: false,
            limit,
            bytes: 0,
        };
        if limit == 0 {
            return (packet.facts, false);
        }
        for path in paths {
            let relevant: Vec<_> = existing
                .iter()
                .filter(|f| f.location.path == *path && f.excerpt.contains("bypassSecurityTrust"))
                .collect();
            if relevant.is_empty() {
                continue;
            }
            if !self.registry.documents.contains_key(*path) {
                packet.partial = true;
                continue;
            }
            let file = sources.file(path).unwrap();
            let mut matched = false;
            for (id, decl) in self
                .registry
                .declarations
                .iter()
                .enumerate()
                .filter(|(_, d)| d.path == *path && d.kind != Kind::Module)
            {
                let owner = self.registry.owner(decl);
                let calls: Vec<_> = owner
                    .dfs()
                    .filter(|call| {
                        call.kind().as_ref() == "call_expression"
                            && call.field("function").is_some_and(|f| {
                                f.field("property")
                                    .is_some_and(|p| p.text().starts_with("bypassSecurityTrust"))
                            })
                            && relevant.iter().any(|f| {
                                f.location.start.byte_offset <= call.range().start
                                    && call.range().end <= f.location.end.byte_offset
                            })
                            && anchor.is_none_or(|a| {
                                a.path == *path
                                    && a.start.byte_offset < call.range().end
                                    && call.range().start < a.end.byte_offset
                            })
                            && call
                                .ancestors()
                                .find(|n| n.kind().as_ref() == "class_declaration")
                                .is_some_and(|n| n.range() == owner.range())
                    })
                    .collect();
                if calls.is_empty() {
                    continue;
                }
                matched = true;
                packet.partial |= decl.partial;
                if !packet.push(decl.metadata.clone()) {
                    break;
                }
                if decl.kind == Kind::Pipe {
                    self.pipe_consumers(sources, id, &mut packet);
                    continue;
                }
                let mut names = BTreeSet::new();
                let mut methods = BTreeSet::new();
                let mut scopes = Vec::new();
                for call in calls {
                    if let Some(scope) = call.ancestors().find(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "method_definition" | "arrow_function" | "function_expression"
                        )
                    }) {
                        scopes.push(scope.range());
                    }
                    for parent in call.ancestors().take_while(|n| n.range() != owner.range()) {
                        match parent.kind().as_ref() {
                            "assignment_expression" => {
                                if let Some(left) = parent.field("left") {
                                    if let Some(name) = left.field("property").or_else(|| {
                                        (left.kind().as_ref() == "identifier").then(|| left.clone())
                                    }) {
                                        names.insert(name.text().to_string());
                                    }
                                }
                                break;
                            }
                            "pair" => {
                                if let Some(key) = parent.field("key") {
                                    if is_plain_identifier(key.text().as_ref()) {
                                        names.insert(key.text().to_string());
                                    }
                                }
                                break;
                            }
                            "variable_declarator" | "public_field_definition" => {
                                if let Some(name) = parent.field("name") {
                                    if is_plain_identifier(name.text().as_ref()) {
                                        names.insert(name.text().to_string());
                                    }
                                }
                                break;
                            }
                            "return_statement" => {
                                if let Some(method) = parent.ancestors().find(|n| {
                                    matches!(
                                        n.kind().as_ref(),
                                        "method_definition"
                                            | "arrow_function"
                                            | "function_expression"
                                    )
                                }) && method.kind().as_ref() == "method_definition"
                                    && let Some(name) = method.field("name")
                                {
                                    methods.insert(name.text().to_string());
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                if let Some(precise) = precise {
                    names.retain(|n| precise.contains(n))
                }
                names.extend(methods);
                // One local rename/object-key handoff. It is an observed expression,
                // not a claim that same-named objects have the same reaching value.
                let originals = names.clone();
                let mut renames = Vec::new();
                for node in owner.dfs().filter(|n| {
                    matches!(n.kind().as_ref(), "pair" | "assignment_expression")
                        && scopes
                            .iter()
                            .any(|s| s.start <= n.range().start && n.range().end <= s.end)
                }) {
                    let (left, right) = if node.kind().as_ref() == "pair" {
                        (node.field("key"), node.field("value"))
                    } else {
                        (
                            node.field("left").and_then(|n| {
                                n.field("property")
                                    .or_else(|| (n.kind().as_ref() == "identifier").then_some(n))
                            }),
                            node.field("right"),
                        )
                    };
                    if let (Some(left), Some(right)) = (left, right)
                        && is_plain_identifier(left.text().as_ref())
                        && !originals.contains(left.text().as_ref())
                        && originals
                            .iter()
                            .any(|n| mentions_binding(right.text().as_ref(), n))
                    {
                        names.insert(left.text().to_string());
                        renames.push(
                            bounded_fact(
                                file,
                                &node,
                                "frontend_value_handoff_context",
                                left.text().as_ref(),
                            )
                            .0,
                        );
                    }
                }
                for rename in renames.into_iter().take(2) {
                    packet.push(rename);
                }
                if names.is_empty() {
                    packet.partial = true;
                    continue;
                }
                self.render(sources, id, &names, None, 0, &mut packet);
            }
            if !matched {
                packet.partial = true
            }
        }
        (packet.facts, packet.partial)
    }

    fn pipe_consumers(&self, sources: &RepositorySources, pipe: usize, packet: &mut Packet) {
        let decl = &self.registry.declarations[pipe];
        let Some(name) = decl.pipe_name.as_deref() else {
            packet.partial = true;
            return;
        };
        if let Some(method) = self.registry.owner(decl).dfs().find(|n| {
            n.kind().as_ref() == "method_definition"
                && n.field("name").is_some_and(|n| n.text() == "transform")
        }) {
            let (fact, cut) = bounded_fact(
                sources.file(&decl.path).unwrap(),
                &method,
                "frontend_pipe_implementation_context",
                name,
            );
            packet.partial |= cut;
            packet.push(fact);
        } else {
            packet.partial = true
        }
        let mut found = 0;
        for (component, consumer) in self
            .registry
            .declarations
            .iter()
            .enumerate()
            .filter(|(_, d)| d.kind == Kind::Component)
        {
            let visible = self.registry.visible(component);
            let matches: Vec<_> = visible
                .iter()
                .filter(|(id, _)| {
                    self.registry.declarations[*id].kind == Kind::Pipe
                        && self.registry.declarations[*id].pipe_name.as_deref() == Some(name)
                })
                .collect();
            if matches.len() != 1 || matches[0].0 != pipe {
                if matches.iter().any(|(id, _)| *id == pipe) {
                    packet.partial = true
                }
                continue;
            }
            let Some(template) = Template::load(&self.registry, sources, consumer) else {
                packet.partial = true;
                continue;
            };
            for binding in template
                .bindings()
                .into_iter()
                .filter(|b| b.output() && pipe_names(&b.expression).contains(name))
            {
                if found == 2 {
                    packet.partial = true;
                    return;
                }
                found += 1;
                for proof in &matches[0].1 {
                    packet.push(proof.clone());
                }
                packet.partial |= consumer.partial;
                packet.push(consumer.metadata.clone());
                if let Some(producer) = &template.producer {
                    packet.push(producer.clone());
                }
                packet.template(&template, &binding, "frontend_pipe_consumer_context", name);
                self.pipe_controls(sources, component, &binding, Some(pipe), packet);
            }
        }
        if found == 0 {
            packet.partial = true
        }
    }

    fn pipe_controls(
        &self,
        sources: &RepositorySources,
        component: usize,
        binding: &Binding,
        skip: Option<usize>,
        packet: &mut Packet,
    ) {
        let visible = self.registry.visible(component);
        for name in pipe_names(&binding.expression).into_iter().take(2) {
            let matches: Vec<_> = visible
                .iter()
                .filter(|(id, _)| {
                    self.registry.declarations[*id].kind == Kind::Pipe
                        && self.registry.declarations[*id].pipe_name.as_deref()
                            == Some(name.as_str())
                })
                .collect();
            if matches.len() != 1 {
                packet.partial |= matches.len() > 1;
                continue;
            }
            let (id, proof) = matches[0];
            if Some(*id) == skip {
                continue;
            }
            let decl = &self.registry.declarations[*id];
            for fact in proof {
                packet.push(fact.clone());
            }
            packet.push(decl.metadata.clone());
            if let Some(method) = self.registry.owner(decl).dfs().find(|n| {
                n.kind().as_ref() == "method_definition"
                    && n.field("name").is_some_and(|n| n.text() == "transform")
            }) {
                let (fact, cut) = bounded_fact(
                    sources.file(&decl.path).unwrap(),
                    &method,
                    "frontend_pipe_implementation_context",
                    &name,
                );
                packet.partial |= cut;
                packet.push(fact);
            } else {
                packet.partial = true
            }
        }
    }

    fn render(
        &self,
        sources: &RepositorySources,
        component: usize,
        names: &BTreeSet<String>,
        input: Option<&BTreeSet<String>>,
        depth: usize,
        packet: &mut Packet,
    ) {
        let decl = &self.registry.declarations[component];
        let mut found = self.host_consumers(sources, component, names, packet);
        let Some(template) = Template::load(&self.registry, sources, decl) else {
            packet.partial |= !found;
            return;
        };
        if let Some(producer) = &template.producer {
            packet.push(producer.clone());
        }
        let mut names = names.clone();
        let mut inputs = input.cloned();
        let scalar_input = input.is_none_or(|roots| names.iter().any(|name| roots.contains(name)));
        let aliases = template.aliases(inputs.as_ref().unwrap_or(&names));
        for (name, fact) in &aliases {
            if scalar_input {
                names.insert(name.clone());
            }
            if let Some(inputs) = &mut inputs {
                inputs.insert(name.clone());
            }
            packet.push(fact.clone());
        }
        let visible = self.registry.visible(component);
        let bindings = template.bindings();
        for binding in &bindings {
            if !binding.output()
                || !names
                    .iter()
                    .any(|n| mentions_binding(&binding.expression, n))
                || inputs.as_ref().is_some_and(|roots| {
                    !roots
                        .iter()
                        .any(|n| mentions_binding(&binding.expression, n))
                })
            {
                continue;
            }
            // A declared component input may shadow a native-looking property.
            if visible.iter().any(|(id, _)| {
                self.registry.declarations[*id].kind == Kind::Component
                    && self.registry.declarations[*id].selector.as_deref()
                        == Some(binding.tag.as_str())
            }) {
                continue;
            }
            found = true;
            packet.template(
                &template,
                binding,
                "frontend_template_binding_context",
                names
                    .iter()
                    .find(|n| mentions_binding(&binding.expression, n))
                    .unwrap(),
            );
            self.pipe_controls(sources, component, binding, None, packet);
        }
        if !found && depth < 2 {
            let mut registration = Vec::new();
            for (child, proof) in visible
                .iter()
                .filter(|(id, _)| self.registry.declarations[*id].kind == Kind::Component)
            {
                let target = &self.registry.declarations[*child];
                let Some(selector) = target.selector.as_deref() else {
                    continue;
                };
                for binding in bindings.iter().filter(|b| b.tag == selector) {
                    for input in self
                        .inputs(sources, target)
                        .into_iter()
                        .filter(|i| i.alias == binding.property.trim_matches(['(', ')']))
                    {
                        let Some(child_template) = Template::load(&self.registry, sources, target)
                        else {
                            continue;
                        };
                        let mut roots = BTreeSet::from([input.name.clone()]);
                        for (alias, _) in child_template.aliases(&roots) {
                            roots.insert(alias);
                        }
                        let direct = names
                            .iter()
                            .any(|n| mentions_binding(&binding.expression, n));
                        let child_names = if direct {
                            BTreeSet::from([input.name.clone()])
                        } else {
                            names.clone()
                        };
                        // Object handoffs are candidates only when the child actually
                        // mentions the selected member and the bound input (or alias).
                        if !direct
                            && !child_template.bindings().iter().any(|b| {
                                names.iter().any(|n| mentions_binding(&b.expression, n))
                                    && roots.iter().any(|n| mentions_binding(&b.expression, n))
                            })
                            && !self.dialog_candidate(target, &names, &roots)
                        {
                            continue;
                        }
                        packet.template(
                            &template,
                            binding,
                            "frontend_component_handoff_context",
                            &input.alias,
                        );
                        packet.push(input.fact);
                        packet.partial |= target.partial;
                        self.render(
                            sources,
                            *child,
                            &child_names,
                            Some(&BTreeSet::from([input.name])),
                            depth + 1,
                            packet,
                        );
                        for fact in proof {
                            registration.push(fact.clone());
                        }
                        registration.push(target.metadata.clone());
                        found = true;
                    }
                }
            }
            self.dialog_consumers(sources, component, &names, inputs.as_ref(), packet);
            for fact in registration {
                packet.push(fact);
            }
        }
        if !found {
            packet.partial = true
        }
    }

    fn inputs(&self, sources: &RepositorySources, decl: &Declaration) -> Vec<Input> {
        let file = sources.file(&decl.path).unwrap();
        let root = self.registry.documents[&decl.path].root();
        let decorators = core_imports(&root, "Input");
        let mut signals = core_imports(&root, "input");
        signals.extend(core_imports(&root, "model"));
        let mut result = Vec::new();
        for field in self.registry.owner(decl).dfs().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "public_field_definition" | "method_definition"
            ) && n
                .ancestors()
                .find(|a| a.kind().as_ref() == "class_declaration")
                .is_some_and(|a| a.range() == decl.range)
        }) {
            let Some(name) = field.field("name") else {
                continue;
            };
            let mut alias = None;
            for decorator in field
                .children()
                .filter(|n| n.kind().as_ref() == "decorator")
            {
                for call in decorator.children() {
                    let Some(function) = call.field("function") else {
                        continue;
                    };
                    if !decorators.contains(function.text().as_ref()) {
                        continue;
                    }
                    alias = Some(name.text().to_string());
                    if let Some(args) = call.field("arguments")
                        && let Some(arg) = args.children().find(|n| n.is_named())
                    {
                        if let Some(value) = static_literal(&arg) {
                            alias = Some(value)
                        } else if arg.kind().as_ref() == "object" {
                            alias = object_alias(&arg, name.text().as_ref())
                        } else {
                            alias = None
                        }
                    }
                }
            }
            if let Some(value) = field.field("value")
                && value.kind().as_ref() == "call_expression"
                && value.field("function").is_some_and(|f| {
                    signals
                        .iter()
                        .any(|s| f.text() == *s || f.text() == format!("{s}.required"))
                })
            {
                alias = Some(name.text().to_string());
                if let Some(args) = value.field("arguments") {
                    let values: Vec<_> = args.children().filter(|n| n.is_named()).collect();
                    let required = value
                        .field("function")
                        .is_some_and(|f| f.text().ends_with(".required"));
                    if let Some(options) = values.get(if required { 0 } else { 1 }) {
                        alias = object_alias(options, name.text().as_ref());
                    }
                }
            }
            if let Some(alias) = alias {
                result.push(Input {
                    name: name.text().to_string(),
                    alias,
                    fact: bounded_fact(
                        file,
                        &field,
                        "frontend_component_input_context",
                        name.text().as_ref(),
                    )
                    .0,
                });
            }
        }
        if let Some(metadata) = self.registry.property(decl, "inputs") {
            for value in metadata.children().filter(|n| n.is_named()) {
                if let Some(spec) = static_literal(&value) {
                    let (name, alias) = spec.split_once(':').unwrap_or((&spec, &spec));
                    let (name, alias) = (name.trim(), alias.trim());
                    if is_plain_identifier(name) && is_plain_identifier(alias) {
                        result.push(Input {
                            name: name.into(),
                            alias: alias.into(),
                            fact: bounded_fact(
                                file,
                                &value,
                                "frontend_component_input_context",
                                name,
                            )
                            .0,
                        });
                    }
                }
            }
        }
        result
    }

    fn host_consumers(
        &self,
        sources: &RepositorySources,
        component: usize,
        names: &BTreeSet<String>,
        packet: &mut Packet,
    ) -> bool {
        let decl = &self.registry.declarations[component];
        let file = sources.file(&decl.path).unwrap();
        let mut found = false;
        if let Some(host) = self.registry.property(decl, "host") {
            for pair in host.children() {
                let (Some(key), Some(value)) = (pair.field("key"), pair.field("value")) else {
                    continue;
                };
                let Some(property) = static_literal(&key) else {
                    continue;
                };
                let Some(expression) = static_literal(&value) else {
                    continue;
                };
                let binding = Binding {
                    start: 0,
                    end: 0,
                    tag: String::new(),
                    property: property.trim_matches(['[', ']']).into(),
                    expression,
                };
                if binding.output()
                    && names
                        .iter()
                        .any(|n| mentions_binding(&binding.expression, n))
                {
                    packet.push(
                        bounded_fact(
                            file,
                            &pair,
                            "frontend_host_binding_context",
                            &binding.property,
                        )
                        .0,
                    );
                    found = true;
                }
            }
        }
        let root = self.registry.documents[&decl.path].root();
        let decorators = core_imports(&root, "HostBinding");
        for field in self.registry.owner(decl).dfs().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "public_field_definition" | "method_definition"
            ) && n
                .ancestors()
                .find(|n| n.kind().as_ref() == "class_declaration")
                .is_some_and(|n| n.range() == decl.range)
        }) {
            let Some(name) = field.field("name") else {
                continue;
            };
            if !names.contains(name.text().as_ref()) {
                continue;
            }
            for decorator in field
                .children()
                .filter(|n| n.kind().as_ref() == "decorator")
            {
                for call in decorator.children().filter(|n| {
                    n.field("function")
                        .is_some_and(|f| decorators.contains(f.text().as_ref()))
                }) {
                    let Some(property) = call
                        .field("arguments")
                        .and_then(|n| n.children().find(|n| n.is_named()))
                        .and_then(|n| static_literal(&n))
                    else {
                        continue;
                    };
                    let binding = Binding {
                        start: 0,
                        end: 0,
                        tag: String::new(),
                        property: property.clone(),
                        expression: String::new(),
                    };
                    if binding.output() {
                        packet.push(
                            bounded_fact(file, &field, "frontend_host_binding_context", &property)
                                .0,
                        );
                        found = true;
                    }
                }
            }
        }
        found
    }

    fn dialog_candidate(
        &self,
        decl: &Declaration,
        names: &BTreeSet<String>,
        roots: &BTreeSet<String>,
    ) -> bool {
        self.registry.owner(decl).dfs().any(|n| {
            n.kind().as_ref() == "call_expression"
                && dialog::receiver(&self.registry, decl, &n)
                && n.field("function")
                    .is_some_and(|f| f.field("property").is_some_and(|p| p.text() == "open"))
                && n.text().contains("data:")
                && names
                    .union(roots)
                    .any(|name| mentions_binding(n.text().as_ref(), name))
        })
    }

    fn dialog_consumers(
        &self,
        sources: &RepositorySources,
        component: usize,
        names: &BTreeSet<String>,
        roots: Option<&BTreeSet<String>>,
        packet: &mut Packet,
    ) {
        let decl = &self.registry.declarations[component];
        let file = sources.file(&decl.path).unwrap();
        for call in self.registry.owner(decl).dfs().filter(|n| {
            n.kind().as_ref() == "call_expression"
                && dialog::receiver(&self.registry, decl, n)
                && n.field("function")
                    .is_some_and(|f| f.field("property").is_some_and(|p| p.text() == "open"))
        }) {
            if !names
                .iter()
                .chain(roots.into_iter().flatten())
                .any(|n| mentions_binding(call.text().as_ref(), n))
            {
                continue;
            }
            let Some(args) = call.field("arguments") else {
                continue;
            };
            let values: Vec<_> = args.children().filter(|n| n.is_named()).collect();
            if values.len() != 2
                || values[0].kind().as_ref() != "identifier"
                || values[1].kind().as_ref() != "object"
            {
                continue;
            }
            let Some((target, proof)) =
                self.registry.resolve(&decl.path, values[0].text().as_ref())
            else {
                continue;
            };
            let target = &self.registry.declarations[target];
            if target.kind != Kind::Component {
                continue;
            }
            let Some(data) = values[1]
                .children()
                .find(|p| p.field("key").is_some_and(|k| k.text() == "data"))
                .and_then(|p| p.field("value"))
            else {
                continue;
            };
            let Some(template) = Template::load(&self.registry, sources, target) else {
                continue;
            };
            let inputs = dialog::data(&self.registry, sources, target);
            let scalar = data.kind().as_ref() != "object"
                && names
                    .iter()
                    .any(|n| mentions_binding(data.text().as_ref(), n));
            let consumers: Vec<_> = template
                .bindings()
                .into_iter()
                .filter(|b| {
                    b.output()
                        && inputs
                            .iter()
                            .any(|(name, _)| mentions_binding(&b.expression, name))
                        && (scalar || names.iter().any(|n| mentions_binding(&b.expression, n)))
                })
                .collect();
            if consumers.is_empty() {
                continue;
            }
            // Imported receiver and token locate the source handoff, not runtime identity.
            packet
                .push(bounded_fact(file, &call, "frontend_dialog_handoff_context", &target.name).0);
            for (_, fact) in inputs {
                packet.push(fact);
            }
            for binding in consumers.into_iter().take(2) {
                packet.template(
                    &template,
                    &binding,
                    "frontend_template_binding_context",
                    &target.name,
                );
            }
            for fact in proof {
                packet.push(fact);
            }
            packet.push(target.metadata.clone());
        }
    }
}

fn object_alias(node: &Node<'_, StrDoc<SupportLang>>, fallback: &str) -> Option<String> {
    if node.kind().as_ref() != "object"
        || node.children().filter(|n| n.is_named()).any(|n| {
            n.kind().as_ref() != "pair"
                || n.field("key")
                    .is_some_and(|k| k.kind().as_ref() == "computed_property_name")
        })
    {
        return None;
    }
    let aliases: Vec<_> = node
        .children()
        .filter(|n| {
            n.field("key")
                .is_some_and(|k| k.text().trim_matches(['\'', '"']) == "alias")
        })
        .filter_map(|n| n.field("value"))
        .collect();
    if aliases.is_empty() {
        Some(fallback.into())
    } else if aliases.len() == 1 {
        static_literal(&aliases[0])
    } else {
        None
    }
}
