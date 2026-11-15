//! Declared manager/queryset and argument navigation. Syntactic chain membership
//! never establishes effective scoping, actor identity or a safe result.
use super::*;

fn arguments<'a>(node: &Py<'a>) -> Vec<Py<'a>> {
    node.field("arguments")
        .map(|a| {
            a.children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .collect()
        })
        .unwrap_or_default()
}

fn enclosing_function<'a>(node: &Py<'a>) -> Option<Py<'a>> {
    node.ancestors()
        .find(|n| n.kind().as_ref() == "function_definition")
}

fn shadowed(node: &Py<'_>, symbol: &str) -> bool {
    node.ancestors()
        .filter(|n| n.kind().as_ref() == "function_definition")
        .any(|owner| {
            owner.dfs().any(|n| {
                if enclosing_function(&n).is_some_and(|f| f.range() != owner.range()) {
                    return false;
                }
                let binding = match n.kind().as_ref() {
                    "assignment"
                    | "augmented_assignment"
                    | "named_expression"
                    | "for_statement"
                    | "for_in_clause" => n.field("left").or_else(|| n.field("name")),
                    "identifier"
                        if n.parent()
                            .is_some_and(|p| p.kind().as_ref() == "parameters") =>
                    {
                        Some(n.clone())
                    }
                    "typed_parameter" | "default_parameter" => n
                        .field("name")
                        .or_else(|| n.children().find(|n| n.kind().as_ref() == "identifier")),
                    "function_definition" | "class_definition" => n.field("name"),
                    "list_splat_pattern" | "dictionary_splat_pattern" => Some(n.clone()),
                    "as_pattern" => n.field("alias"),
                    _ => None,
                };
                binding.is_some_and(|b| {
                    b.dfs()
                        .any(|n| n.kind().as_ref() == "identifier" && n.text() == symbol)
                }) || matches!(
                    n.kind().as_ref(),
                    "import_statement" | "import_from_statement"
                ) && n
                    .field_children("name")
                    .any(|name| name.field("alias").unwrap_or(name).text() == symbol)
            })
        })
}

fn type_path(text: &str) -> Option<&str> {
    let base = text.split_once('[').map_or(text, |(base, _)| base);
    simple_path(base).then_some(base)
}

// Explicit spelling bound to Django's API. No repository-wide name guessing.
fn django_type(index: &Index, path: &str, name: &str, expected: &str) -> bool {
    let Some(file) = index.files.get(path) else {
        return false;
    };
    let Some(name) = type_path(name) else {
        return false;
    };
    let prefix = name.split('.').next().unwrap_or("");
    if file.wildcard
        || file.blocked.contains(prefix)
        || file.classes.contains_key(prefix)
        || file.functions.contains_key(prefix)
    {
        return false;
    }
    let bindings = file
        .bindings
        .iter()
        .filter(|b| {
            name == b.local
                || name
                    .strip_prefix(&b.local)
                    .is_some_and(|r| r.starts_with('.'))
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return false;
    };
    let rest = name
        .strip_prefix(&binding.local)
        .unwrap_or("")
        .trim_start_matches('.');
    let (module, symbol) = match &binding.symbol {
        Some(symbol) if rest.is_empty() => (binding.module.clone(), symbol.as_str()),
        Some(symbol) => (format!("{}.{}", binding.module, symbol), rest),
        None => (binding.module.clone(), rest),
    };
    module == "django.db.models" && symbol == expected
}

fn queryset_class(index: &Index, key: &Key, visited: &mut BTreeSet<Key>) -> bool {
    if visited.len() >= 8 || !visited.insert(key.clone()) {
        return false;
    }
    let Some(class) = index.class(key) else {
        return false;
    };
    class.bases.iter().any(|base| {
        django_type(index, &class.path, base, "QuerySet")
            || type_path(base)
                .and_then(|base| index.resolve(&class.path, base, 8, &mut Vec::new()))
                .is_some_and(|base| queryset_class(index, &base, visited))
    })
}

fn assignments<'a>(root: &Py<'a>, class: Option<&Class>, name: &str) -> Vec<Py<'a>> {
    root.dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "assignment" | "augmented_assignment" | "named_expression"
            ) && n
                .field("left")
                .or_else(|| n.field("name"))
                .is_some_and(|n| n.text() == name)
        })
        .filter(|n| {
            if enclosing_function(n).is_some() {
                return false;
            }
            let owner = n
                .ancestors()
                .find(|n| n.kind().as_ref() == "class_definition");
            match class {
                Some(class) => owner.is_some_and(|n| n.range() == class.span),
                None => owner.is_none(),
            }
        })
        .collect()
}

fn direct_assignment(node: &Py<'_>) -> bool {
    if node.kind().as_ref() != "assignment" {
        return false;
    }
    node.parent().and_then(|p| p.parent()).is_some_and(|p| {
        p.kind().as_ref() == "module"
            || p.kind().as_ref() == "block"
                && p.parent()
                    .is_some_and(|p| p.kind().as_ref() == "class_definition")
    })
}

// Resolve an alias location without pretending a generated manager is a class
// declaration. The unique assignment and factory are checked separately.
fn reference(
    index: &Index,
    path: &str,
    name: &str,
    depth: usize,
    refs: &mut Vec<(String, Range<usize>)>,
) -> Option<Key> {
    if depth == 0 || !simple_path(name) {
        return None;
    }
    let file = index.files.get(path)?;
    if file.wildcard {
        return None;
    }
    let bindings = file
        .bindings
        .iter()
        .filter(|b| {
            name == b.local
                || name
                    .strip_prefix(&b.local)
                    .is_some_and(|r| r.starts_with('.'))
        })
        .collect::<Vec<_>>();
    if bindings.is_empty() && !name.contains('.') {
        return Some((path.into(), name.into()));
    }
    let [binding] = bindings.as_slice() else {
        return None;
    };
    if file.blocked.contains(name.split('.').next()?) {
        return None;
    }
    let rest = name.strip_prefix(&binding.local)?.trim_start_matches('.');
    let (module, symbol) = match &binding.symbol {
        Some(symbol) if rest.is_empty() => (binding.module.clone(), symbol.clone()),
        Some(symbol) => (format!("{}.{}", binding.module, symbol), rest.into()),
        None => (binding.module.clone(), rest.into()),
    };
    let [target] = index.modules.get(&module)?.as_slice() else {
        return None;
    };
    refs.push((path.into(), binding.span.clone()));
    reference(index, target, &symbol, depth - 1, refs)
}

fn manager(
    index: &Index,
    sources: &RepositorySources,
    path: &str,
    value: &Py<'_>,
    instance: bool,
    depth: usize,
    refs: &mut Vec<(String, Range<usize>)>,
) -> Option<Key> {
    if depth == 0 {
        return None;
    }
    if value.kind().as_ref() == "call" {
        let function = value.field("function")?;
        let args = arguments(value);
        let callee = function.text();
        if let Some(receiver) = callee.strip_suffix(".from_queryset") {
            if instance || args.len() != 1 || !django_type(index, path, receiver, "Manager") {
                return None;
            }
            let key = index.resolve(path, args[0].text().as_ref(), 8, refs)?;
            return queryset_class(index, &key, &mut BTreeSet::new()).then_some(key);
        }
        if let Some(receiver) = callee.strip_suffix(".as_manager") {
            if !instance || !args.is_empty() {
                return None;
            }
            let key = index.resolve(path, receiver, 8, refs)?;
            let mut graph = Vec::new();
            index.graph(
                &key,
                6,
                &mut BTreeSet::new(),
                &mut graph,
                &mut Vec::new(),
                &mut false,
            );
            if graph
                .iter()
                .filter_map(|k| index.class(k))
                .any(|c| c.methods.contains_key("as_manager"))
            {
                return None;
            }
            for key in &graph {
                let class = index.class(key)?;
                let ast = python_review::parse(sources.files.get(&class.path)?)?;
                if !assignments(&ast.root(), Some(class), "as_manager").is_empty() {
                    return None;
                }
            }
            return queryset_class(index, &key, &mut BTreeSet::new()).then_some(key);
        }
        if instance && args.is_empty() {
            return manager(index, sources, path, &function, false, depth - 1, refs);
        }
        return None;
    }
    if !instance && simple_path(value.text().as_ref()) {
        let key = reference(index, path, value.text().as_ref(), depth, refs)?;
        let file = index.files.get(&key.0)?;
        if file.classes.contains_key(&key.1) || file.functions.contains_key(&key.1) {
            return None;
        }
        let source = sources.files.get(&key.0)?;
        let ast = python_review::parse(source)?;
        let assigned = assignments(&ast.root(), None, &key.1);
        let [assignment] = assigned.as_slice() else {
            return None;
        };
        if !direct_assignment(assignment) {
            return None;
        }
        refs.push((key.0.clone(), assignment.range()));
        return manager(
            index,
            sources,
            &key.0,
            &assignment.field("right")?,
            false,
            depth - 1,
            refs,
        );
    }
    None
}

fn model_manager(
    index: &Index,
    sources: &RepositorySources,
    model: &Key,
    attr: &str,
    refs: &mut Vec<(String, Range<usize>)>,
) -> Option<Key> {
    let mut graph = Vec::new();
    index.graph(
        model,
        6,
        &mut BTreeSet::new(),
        &mut graph,
        &mut Vec::new(),
        &mut false,
    );
    let mut bindings = Vec::new();
    for key in graph {
        let class = index.class(&key)?;
        if class.methods.contains_key(attr) {
            return None;
        }
        let file = sources.files.get(&class.path)?;
        let ast = python_review::parse(file)?;
        let assigned = assignments(&ast.root(), Some(class), attr);
        if !assigned.is_empty() {
            if assigned.len() != 1 || !direct_assignment(&assigned[0]) {
                return None;
            }
            let mut origin = vec![(class.path.clone(), assigned[0].range())];
            let query = manager(
                index,
                sources,
                &class.path,
                &assigned[0].field("right")?,
                true,
                8,
                &mut origin,
            )?;
            bindings.push((query, origin));
            if &key == model {
                break;
            }
        }
    }
    let [(query, origin)] = bindings.as_slice() else {
        return None;
    };
    refs.extend(origin.iter().cloned());
    Some(query.clone())
}

fn chain<'a>(call: &Py<'a>, steps: &mut Vec<(String, Py<'a>)>, depth: usize) -> Option<Py<'a>> {
    if depth == 0 {
        return None;
    }
    let function = call.field("function")?;
    if function.kind().as_ref() != "attribute" {
        return None;
    }
    let object = function.field("object")?;
    let method = function.field("attribute")?.text().into_owned();
    let base = if object.kind().as_ref() == "call" {
        chain(&object, steps, depth - 1)?
    } else {
        object
    };
    steps.push((method, call.clone()));
    Some(base)
}

fn definitions(
    index: &Index,
    sources: &RepositorySources,
    query: &Key,
    method: &str,
) -> Vec<(Key, Range<usize>)> {
    let mut graph = Vec::new();
    index.graph(
        query,
        6,
        &mut BTreeSet::new(),
        &mut graph,
        &mut Vec::new(),
        &mut false,
    );
    let mut result = Vec::new();
    for key in graph {
        let Some(class) = index.class(&key) else {
            continue;
        };
        let Some(file) = sources.files.get(&class.path) else {
            continue;
        };
        let Some(ast) = python_review::parse(file) else {
            continue;
        };
        if !assignments(&ast.root(), Some(class), method).is_empty() {
            return Vec::new();
        }
        if let Some(spans) = class.methods.get(method) {
            if spans.len() != 1 {
                return Vec::new();
            }
            result.push((key, spans[0].clone()));
        }
    }
    result
}

fn argument_context<'a>(
    index: &Index,
    packet: &mut Packet<'_>,
    path: &str,
    root: &Py<'a>,
    call: &Py<'a>,
    argument: &Py<'a>,
) {
    let value = argument
        .field("value")
        .filter(|_| argument.kind().as_ref() == "keyword_argument")
        .unwrap_or_else(|| argument.clone());
    let name = value.text();
    let mut origin = value.clone();
    if value.kind().as_ref() == "identifier" {
        let Some(owner) = enclosing_function(call) else {
            return;
        };
        let assigned = root
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "assignment"
                    && n.field("left").is_some_and(|n| n.text() == name)
                    && enclosing_function(n).is_some_and(|n| n.range() == owner.range())
            })
            .collect::<Vec<_>>();
        if let [assignment] = assigned.as_slice() {
            if assignment.range().end > call.range().start {
                return;
            }
            packet.add(path, assignment.range(), "python_queryset_argument_context", &name, "unique lexical supplied-argument binding candidate; no actor authentication, dominance or runtime value proof");
            if let Some(right) = assignment.field("right") {
                origin = right;
            }
        } else {
            if let Some(parameters) = owner.field("parameters") {
                packet.add(
                    path,
                    parameters.range(),
                    "python_queryset_argument_context",
                    &name,
                    "callable parameters; actual argument identity and authority remain open",
                );
            }
            return;
        }
    } else {
        packet.add(path, value.range(), "python_queryset_argument_context", &name, "supplied expression only; inspect which parameter is the actor and whether its authority is valid");
    }
    if origin.kind().as_ref() == "call" {
        if let Some(function) = origin.field("function") {
            let name = function.text();
            if shadowed(&origin, name.split('.').next().unwrap_or("")) {
                return;
            }
            if let Some(target) = index.resolve(path, &name, 8, &mut Vec::new()) {
                if let Some(spans) = index
                    .files
                    .get(&target.0)
                    .and_then(|f| f.functions.get(&target.1))
                {
                    if let [span] = spans.as_slice() {
                        packet.add(&target.0, span.clone(), "python_queryset_argument_helper_context", &target.1, "import-bound argument producer source; returned actor type, authentication and use are not established");
                    }
                }
            }
        }
    }
}

pub(super) fn contexts(
    index: &Index,
    sources: &RepositorySources,
    anchors: &[&Evidence],
) -> BTreeMap<String, (Vec<ReviewNeighborhoodFact>, bool)> {
    let mut result = BTreeMap::new();
    let mut files: BTreeMap<&str, Vec<&Evidence>> = BTreeMap::new();
    for e in anchors {
        files.entry(&e.location.path).or_default().push(e);
    }
    for (path, anchors) in files {
        let Some(file) = sources.files.get(path) else {
            continue;
        };
        let Some(ast) = python_review::parse(file) else {
            continue;
        };
        let root = ast.root();
        for e in anchors {
            let Some(call) = root
                .dfs()
                .filter(|n| {
                    n.kind().as_ref() == "call"
                        && n.range().start <= e.location.start.byte_offset
                        && e.location.end.byte_offset <= n.range().end
                })
                .min_by_key(|n| n.range().len())
            else {
                continue;
            };
            let mut steps = Vec::new();
            let Some(base) = chain(&call, &mut steps, 32) else {
                continue;
            };
            let Some((model_name, attr)) = base
                .text()
                .rsplit_once('.')
                .map(|(a, b)| (a.to_string(), b.to_string()))
            else {
                continue;
            };
            if shadowed(&call, model_name.split('.').next().unwrap_or("")) {
                continue;
            }
            let mut refs = Vec::new();
            let Some(model) = index
                .resolve(path, &model_name, 8, &mut refs)
                .filter(|k| index.class(k).is_some())
            else {
                continue;
            };
            let Some(query) = model_manager(index, sources, &model, &attr, &mut refs) else {
                continue;
            };
            let mut methods = Vec::new();
            for (name, step) in steps.iter().take(steps.len().saturating_sub(1)) {
                for (owner, span) in definitions(index, sources, &query, name) {
                    methods.push((name.clone(), step.clone(), owner, span));
                }
            }
            if methods.is_empty() {
                continue;
            }
            let mut packet = Packet {
                sources,
                facts: Vec::new(),
                truncated: false,
            };
            if let Some(class) = index.class(&model) {
                packet.add(
                    &class.path,
                    class.header.clone(),
                    "python_queryset_model_context",
                    &class.name,
                    "model declaration only; actual manager and runtime dispatch remain to inspect",
                );
            }
            for (path, span) in refs {
                packet.add(&path,span,"python_queryset_manager_context",&model_name,"unique declared manager/factory/import source; not proof that the returned query preserves a restriction");
            }
            let mut delegates = Vec::new();
            packet.truncated |= methods.len() > 2;
            for (name, step, owner, span) in methods.into_iter().take(2) {
                let Some(class) = index.class(&owner) else {
                    continue;
                };
                packet.add(&class.path,class.header.clone(),"python_queryset_class_context",&class.name,"import-bound queryset declaration; multiple bases and overrides can change runtime dispatch");
                packet.add(&class.path,span.clone(),"python_queryset_method_context",&name,"declared method candidate on this syntactic receiver chain; it may preserve, replace or clear filtering");
                packet.add(path,step.range(),"python_queryset_call_context",&name,"method and supplied inputs on the selector's receiver chain; not effective scoping or guard proof");
                let args = arguments(&step);
                packet.truncated |= args.len() > 2;
                for arg in args.iter().take(2) {
                    argument_context(index, &mut packet, path, &root, &step, arg);
                }
                if let Some(source) = sources
                    .files
                    .get(&class.path)
                    .and_then(python_review::parse)
                {
                    for call in source.root().dfs().filter(|n| {
                        n.kind().as_ref() == "call"
                            && span.start <= n.range().start
                            && n.range().end <= span.end
                    }) {
                        let Some(function) = call.field("function") else {
                            continue;
                        };
                        if function.kind().as_ref() == "attribute"
                            && function.field("object").is_some_and(|n| n.text() == "self")
                        {
                            if let Some(method) = function.field("attribute") {
                                for definition in
                                    definitions(index, sources, &query, method.text().as_ref())
                                {
                                    delegates.push((method.text().into_owned(), definition));
                                }
                            }
                        }
                    }
                }
            }
            delegates.sort_by(|a, b| {
                (&a.0, &a.1.0, a.1.1.start, a.1.1.end).cmp(&(&b.0, &b.1.0, b.1.1.start, b.1.1.end))
            });
            delegates.dedup();
            packet.truncated |= delegates.len() > 2;
            for (name, (owner, span)) in delegates.into_iter().take(2) {
                packet.add(&owner.0,span,"python_queryset_delegate_context",&name,"declared self-method delegate candidate; no runtime receiver identity or effective policy is credited");
            }
            result.insert(e.id.clone(), (packet.facts, packet.truncated));
        }
    }
    result
}
