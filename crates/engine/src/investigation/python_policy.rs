//! Import-bound Python mutation policy context, never an effective-control or
//! runtime-MRO proof. Unknown bases, dynamic dispatch and missing policy remain
//! review work. No application-specific names or admission changes.
use super::*;
use std::ops::Range;
mod querysets;

type Py<'a> = Node<'a, StrDoc<SupportLang>>;
type Key = (String, String);

#[derive(Clone)]
struct Binding {
    local: String,
    module: String,
    symbol: Option<String>,
    span: Range<usize>,
}

#[derive(Default)]
struct FileIndex {
    bindings: Vec<Binding>,
    blocked: BTreeSet<String>,
    classes: BTreeMap<String, Vec<Class>>,
    functions: BTreeMap<String, Vec<Range<usize>>>,
    fields: Vec<(String, Range<usize>)>,
    direct_calls: Vec<(String, Range<usize>)>,
    wildcard: bool,
}

#[derive(Clone)]
struct Class {
    path: String,
    name: String,
    span: Range<usize>,
    header: Range<usize>,
    bases: Vec<String>,
    metadata: Vec<Range<usize>>,
    methods: BTreeMap<String, Vec<Range<usize>>>,
}

struct Index {
    files: BTreeMap<String, FileIndex>,
    modules: BTreeMap<String, Vec<String>>,
}

#[derive(Default)]
pub(super) struct PolicyContext {
    facts: BTreeMap<String, Vec<ReviewNeighborhoodFact>>,
    truncated: BTreeSet<String>,
}

fn direct(node: Py<'_>) -> Py<'_> {
    if node.kind().as_ref() == "decorated_definition" {
        let definition = node.children().find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_definition" | "class_definition"
            )
        });
        definition.unwrap_or(node)
    } else {
        node
    }
}

fn simple_path(name: &str) -> bool {
    !name.is_empty() && name.split('.').all(is_plain_identifier)
}

impl FileIndex {
    fn build(file: &SourceFile) -> Option<Self> {
        let ast = python_review::parse(file)?;
        let root = ast.root();
        if root
            .dfs()
            .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
        {
            return None;
        }
        let mut result = Self::default();
        for node in root.children().filter(|n| n.is_named()).map(direct) {
            match node.kind().as_ref() {
                "import_statement" | "import_from_statement" => {
                    result.wildcard |= node
                        .children()
                        .any(|n| n.kind().as_ref() == "wildcard_import");
                    let from = node.field("module_name").and_then(|n| {
                        python_review::imported_module(&file.path, n.text().as_ref())
                    });
                    for name in node.field_children("name") {
                        let original = name
                            .field("name")
                            .unwrap_or_else(|| name.clone())
                            .text()
                            .into_owned();
                        let alias = name.field("alias").map(|n| n.text().into_owned());
                        result.bindings.push(Binding {
                            local: alias.unwrap_or_else(|| original.clone()),
                            module: from.clone().unwrap_or_else(|| original.clone()),
                            symbol: from.as_ref().map(|_| original),
                            span: node.range(),
                        });
                    }
                }
                "class_definition" => {
                    let name = node.field("name")?.text().into_owned();
                    let body = node.field("body")?;
                    let mut class = Class {
                        path: file.path.clone(),
                        name: name.clone(),
                        span: node.range(),
                        header: node
                            .parent()
                            .filter(|n| n.kind().as_ref() == "decorated_definition")
                            .map_or(node.range().start, |n| n.range().start)
                            ..body.range().start,
                        bases: Vec::new(),
                        metadata: Vec::new(),
                        methods: BTreeMap::new(),
                    };
                    if let Some(bases) = node.field("superclasses") {
                        class.bases = bases
                            .children()
                            .filter(|n| n.is_named())
                            .map(|n| n.text().into_owned())
                            .collect();
                    }
                    for member in body.children().filter(|n| n.is_named()).map(direct) {
                        if let Some(member_name) = member.field("name") {
                            if member.kind().as_ref() == "function_definition" {
                                class
                                    .methods
                                    .entry(member_name.text().into_owned())
                                    .or_default()
                                    .push(
                                        member
                                            .parent()
                                            .filter(|n| n.kind().as_ref() == "decorated_definition")
                                            .unwrap_or_else(|| member.clone())
                                            .range(),
                                    );
                            } else if member.kind().as_ref() == "class_definition"
                                && member_name.text() == "Meta"
                            {
                                class.metadata.push(member.range());
                            }
                        }
                    }
                    result.classes.entry(name).or_default().push(class);
                }
                "function_definition" => {
                    let name = node.field("name")?.text().into_owned();
                    result.functions.entry(name).or_default().push(
                        node.parent()
                            .filter(|n| n.kind().as_ref() == "decorated_definition")
                            .unwrap_or_else(|| node.clone())
                            .range(),
                    );
                }
                _ => {
                    for import in node.dfs().filter(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "import_statement" | "import_from_statement"
                        )
                    }) {
                        for name in import.field_children("name") {
                            let binding = name.field("alias").unwrap_or(name);
                            result
                                .blocked
                                .insert(binding.text().split('.').next().unwrap_or("").into());
                        }
                    }
                    for assignment in node.dfs().filter(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "assignment" | "augmented_assignment" | "named_expression"
                        )
                    }) {
                        if let Some(left) = assignment
                            .field("left")
                            .or_else(|| assignment.field("name"))
                        {
                            result
                                .blocked
                                .insert(left.text().split('.').next().unwrap_or("").into());
                        }
                    }
                }
            }
        }
        // Only syntax-level Field construction outside functions. It is not
        // proof that this schema is installed or this entrypoint executes.
        for call in root.dfs().filter(|n| n.kind().as_ref() == "call") {
            let Some(function) = call.field("function") else {
                continue;
            };
            let text = function.text();
            if let Some(target) = text
                .strip_suffix(".perform_mutation")
                .or_else(|| text.strip_suffix(".mutate"))
                .filter(|s| simple_path(s))
            {
                let prefix = target.split('.').next().unwrap_or("");
                let shadowed = call
                    .ancestors()
                    .find(|n| n.kind().as_ref() == "function_definition")
                    .is_some_and(|owner| {
                        owner.dfs().any(|n| {
                            let binding = match n.kind().as_ref() {
                                "assignment" | "augmented_assignment" => n.field("left"),
                                "identifier"
                                    if n.parent()
                                        .is_some_and(|p| p.kind().as_ref() == "parameters") =>
                                {
                                    Some(n.clone())
                                }
                                "typed_parameter" | "default_parameter" => {
                                    n.field("name").or_else(|| {
                                        n.children().find(|n| n.kind().as_ref() == "identifier")
                                    })
                                }
                                _ => None,
                            };
                            binding.is_some_and(|n| n.text() == prefix)
                        })
                    });
                if !shadowed {
                    result.direct_calls.push((target.into(), call.range()));
                }
            }
            if call
                .ancestors()
                .any(|n| n.kind().as_ref() == "function_definition")
            {
                continue;
            }
            let Some(target) = text.strip_suffix(".Field").filter(|s| simple_path(s)) else {
                continue;
            };
            let prefix = target.split('.').next().unwrap_or("");
            let class_shadow = call
                .ancestors()
                .find(|n| n.kind().as_ref() == "class_definition")
                .and_then(|n| n.field("body"))
                .is_some_and(|body| {
                    body.children().map(direct).any(|n| {
                        n.field("name").is_some_and(|n| n.text() == prefix)
                            || n.dfs().any(|a| {
                                a.kind().as_ref() == "assignment"
                                    && a.field("left").is_some_and(|n| n.text() == prefix)
                            })
                    })
                });
            if !class_shadow {
                result.fields.push((
                    target.into(),
                    call.parent()
                        .filter(|n| n.kind().as_ref() == "assignment")
                        .unwrap_or(call)
                        .range(),
                ));
            }
        }
        Some(result)
    }
}

impl Index {
    fn build(sources: &RepositorySources) -> Self {
        let mut result = Self {
            files: BTreeMap::new(),
            modules: BTreeMap::new(),
        };
        for file in sources
            .files
            .values()
            .filter(|f| f.language == Some(Language::Python))
        {
            if let Some(index) = FileIndex::build(file) {
                result
                    .modules
                    .entry(python_review::module(&file.path))
                    .or_default()
                    .push(file.path.clone());
                result.files.insert(file.path.clone(), index);
            }
        }
        result
    }

    // Unique direct imports/reexports only. No same-name repository fallback.
    fn resolve(
        &self,
        path: &str,
        name: &str,
        depth: usize,
        imports: &mut Vec<(String, Range<usize>)>,
    ) -> Option<Key> {
        if depth == 0 || !simple_path(name) {
            return None;
        }
        let file = self.files.get(path)?;
        let prefix = name.split('.').next()?;
        if file.wildcard
            || file.blocked.contains(prefix)
            || name.contains('.')
                && (file.functions.contains_key(prefix) || file.classes.contains_key(prefix))
        {
            return None;
        }
        if !name.contains('.') {
            if file.classes.get(name).is_some_and(|v| v.len() == 1) {
                if file.bindings.iter().any(|b| b.local == name) {
                    return None;
                }
                return Some((path.into(), name.into()));
            }
            if file.functions.get(name).is_some_and(|v| v.len() == 1)
                && !file.bindings.iter().any(|b| b.local == name)
            {
                return Some((path.into(), name.into()));
            }
            if file.functions.contains_key(name) {
                return None;
            }
        }
        let bindings = file
            .bindings
            .iter()
            .filter(|b| {
                name == b.local
                    || name
                        .strip_prefix(&b.local)
                        .is_some_and(|rest| rest.starts_with('.'))
            })
            .collect::<Vec<_>>();
        let [binding] = bindings.as_slice() else {
            return None;
        };
        let remainder = name.strip_prefix(&binding.local)?.trim_start_matches('.');
        let (module, symbol) = if let Some(symbol) = &binding.symbol {
            if remainder.is_empty() {
                (binding.module.clone(), symbol.clone())
            } else {
                (format!("{}.{}", binding.module, symbol), remainder.into())
            }
        } else {
            (binding.module.clone(), remainder.into())
        };
        if symbol.is_empty() {
            return None;
        }
        let paths = self.modules.get(&module)?;
        let [target] = paths.as_slice() else {
            return None;
        };
        imports.push((path.into(), binding.span.clone()));
        self.resolve(target, &symbol, depth - 1, imports)
    }

    fn class(&self, key: &Key) -> Option<&Class> {
        let definitions = self.files.get(&key.0)?.classes.get(&key.1)?;
        let [class] = definitions.as_slice() else {
            return None;
        };
        Some(class)
    }

    fn graph(
        &self,
        key: &Key,
        depth: usize,
        visited: &mut BTreeSet<Key>,
        classes: &mut Vec<Key>,
        imports: &mut Vec<(String, Range<usize>)>,
        unresolved: &mut bool,
    ) {
        if depth == 0 || !visited.insert(key.clone()) {
            *unresolved = true;
            return;
        }
        let Some(class) = self.class(key) else {
            *unresolved = true;
            return;
        };
        classes.push(key.clone());
        for base in &class.bases {
            if let Some(base) = self
                .resolve(&class.path, base, 8, imports)
                .filter(|k| self.class(k).is_some())
            {
                self.graph(&base, depth - 1, visited, classes, imports, unresolved);
            } else {
                *unresolved = true;
            }
        }
    }
}

struct Packet<'a> {
    sources: &'a RepositorySources,
    facts: Vec<ReviewNeighborhoodFact>,
    truncated: bool,
}

impl Packet<'_> {
    fn add(&mut self, path: &str, span: Range<usize>, role: &str, symbol: &str, detail: &str) {
        if self.facts.len() >= 12 {
            self.truncated = true;
            return;
        }
        let Some(file) = self.sources.files.get(path) else {
            return;
        };
        if self.facts.iter().any(|f| {
            f.location.path == path
                && f.location.start.byte_offset == span.start
                && f.location.end.byte_offset == span.end
        }) {
            return;
        }
        let Some(text) = file.source.get(span.clone()) else {
            return;
        };
        let bytes = text
            .split_inclusive('\n')
            .take(40)
            .map(str::len)
            .sum::<usize>()
            .min(4 * 1024);
        let end = floor_char_boundary(&file.source, span.start + bytes);
        self.truncated |= end < span.end;
        self.facts.push(ReviewNeighborhoodFact {
            role: role.into(), symbol: symbol.into(),
            location: location_from_offsets(path, &file.source, span.start, end),
            excerpt: file.source[span.start..end].into(), evidence_id: None,
            provenance: QueryProvenance { resolution: Resolution::Ast, engine: format!("Python import-bound class policy context 1; {detail}; source graph only, not runtime MRO, guard dominance, actor trust or reachability proof") },
        });
    }
}

impl PolicyContext {
    pub(super) fn build(sources: &RepositorySources, groups: &[ObservationGroup]) -> Self {
        let mut result = Self::default();
        let anchors = groups
            .iter()
            .flat_map(|g| {
                g.evidence.iter().filter(|e| {
                    g.anchor_evidence_ids.contains(&e.id)
                        && e.rule_id == "python-django-orm-resource-access"
                })
            })
            .collect::<Vec<_>>();
        if anchors.is_empty() {
            return result;
        }
        let index = Index::build(sources);
        for (id, (facts, cut)) in querysets::contexts(&index, sources, &anchors) {
            result.facts.insert(id.clone(), facts);
            if cut {
                result.truncated.insert(id);
            }
        }
        let mut packets: BTreeMap<Key, (Vec<ReviewNeighborhoodFact>, bool)> = BTreeMap::new();
        for e in anchors {
            let Some(file) = index.files.get(&e.location.path) else {
                continue;
            };
            let Some(class) = file
                .classes
                .values()
                .flatten()
                .filter(|c| {
                    c.span.start <= e.location.start.byte_offset
                        && e.location.end.byte_offset <= c.span.end
                })
                .min_by_key(|c| c.span.len())
            else {
                continue;
            };
            let key = (class.path.clone(), class.name.clone());
            let packet = packets.entry(key.clone()).or_insert_with(|| {
                let mut classes = Vec::new(); let mut imports = Vec::new(); let mut unresolved = false;
                index.graph(&key, 6, &mut BTreeSet::new(), &mut classes, &mut imports, &mut unresolved);
                if !classes.iter().filter_map(|k| index.class(k)).any(|c| c.methods.contains_key("mutate") || c.methods.contains_key("perform_mutation") || c.methods.contains_key("check_permissions")) { return (Vec::new(), false); }
                let mut packet = Packet { sources, facts: Vec::new(), truncated: false };
                packet.add(&class.path, class.header.clone(), "python_mutation_class_context", &class.name, if unresolved { "unresolved or repeated base boundary; no complete policy binding" } else { "direct declaration and declared base graph, not MRO; overrides remain distinct" });
                for metadata in &class.metadata { packet.add(&class.path, metadata.clone(), "python_mutation_metadata_context", &class.name, "literal Meta declaration; missing permissions, inheritance and runtime metadata transformation are not closed"); }
                // Child overrides precede base candidates, but no C3/MRO proof is claimed.
                let mut helpers = Vec::new();
                for class_key in &classes {
                    let Some(owner) = index.class(class_key) else { continue; };
                    if class_key != &key {
                        packet.add(&owner.path, owner.header.clone(), "python_mutation_base_context", &owner.name, "import-bound intermediate/base declaration; traversal order is not runtime MRO");
                        for metadata in &owner.metadata {
                            if sources.files.get(&owner.path).and_then(|f| f.source.get(metadata.clone())).is_some_and(|s| contains_identifier(s, "permissions")) {
                                packet.add(&owner.path, metadata.clone(), "python_mutation_inherited_metadata_context", &owner.name, "base Meta declaration candidate; runtime metadata inheritance and overrides remain to review");
                            }
                        }
                    }
                    for method in ["mutate", "check_permissions"] {
                        if let Some(spans) = owner.methods.get(method) {
                            if spans.len() != 1 { packet.truncated = true; continue; }
                            if class_key != &key { packet.add(&owner.path, owner.header.clone(), "python_mutation_base_context", &owner.name, "import-bound base declaration; other bases and overrides may change dispatch"); }
                            packet.add(&owner.path, spans[0].clone(), if method == "mutate" { "python_mutation_entrypoint_context" } else { "python_mutation_check_context" }, &format!("{}.{}", owner.name, method), if class_key == &key { "direct method/override; inspect actual order and delegation" } else { "base method candidate; do not credit it through an overriding method" });
                            if method == "check_permissions" { helpers.push((owner.path.clone(), spans[0].clone())); }
                        }
                    }
                }
                // Field construction sites carry identity, never exposure or invocation.
                let mut sites = 0;
                for (path, file) in &index.files {
                    for (name, span) in &file.direct_calls {
                        if index.resolve(path, name, 8, &mut Vec::new()).as_ref() == Some(&key) {
                            if sites == 2 { packet.truncated = true; break; }
                            packet.add(path, span.clone(), "python_mutation_direct_call_context", name, "direct method call site; an alternate caller may bypass mutate guards, so inspect its policy independently");
                            sites += 1;
                        }
                    }
                }
                sites = 0;
                for (path, file) in &index.files {
                    for (name, span) in &file.fields {
                        if index.resolve(path, name, 8, &mut Vec::new()).as_ref() == Some(&key) {
                            if sites == 2 { packet.truncated = true; break; }
                            packet.add(path, span.clone(), "python_mutation_field_context", name, "import-bound Field construction; root schema registration and installed routing remain to inspect");
                            sites += 1;
                        }
                    }
                }
                for (path, span) in imports.into_iter().take(3) { packet.add(&path, span, "python_mutation_import_context", &class.name, "class-base import binding, not a permission contract"); }
                let mut count = 0;
                for (path, span) in helpers {
                    let Some(source) = sources.files.get(&path) else { continue; };
                    let Some(ast) = python_review::parse(source) else { continue; };
                    for call in ast.root().dfs().filter(|n| n.kind().as_ref() == "call" && span.start <= n.range().start && n.range().end <= span.end) {
                        let Some(callee) = call.field("function") else { continue; };
                        let Some(target) = index.resolve(&path, callee.text().as_ref(), 8, &mut Vec::new()) else { continue; };
                        let Some(definitions) = index.files.get(&target.0).and_then(|f| f.functions.get(&target.1)) else { continue; };
                        let [definition] = definitions.as_slice() else { continue; };
                        if count == 2 { packet.truncated = true; break; }
                        packet.add(&target.0, definition.clone(), "python_permission_helper_context", &target.1, "one-hop imported/local helper called by check_permissions; actual user/app and any/all semantics remain to review");
                        count += 1;
                    }
                }
                (packet.facts, packet.truncated)
            });
            result
                .facts
                .entry(e.id.clone())
                .or_default()
                .extend(packet.0.iter().cloned());
            if packet.1 {
                result.truncated.insert(e.id.clone());
            }
        }
        result
    }

    pub(super) fn facts(&self, group: &ObservationGroup) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let mut facts = Vec::new();
        let mut cut = false;
        for id in &group.anchor_evidence_ids {
            cut |= self.truncated.contains(id);
            for fact in self.facts.get(id).into_iter().flatten() {
                if !facts
                    .iter()
                    .any(|f: &ReviewNeighborhoodFact| f.location == fact.location)
                {
                    facts.push(fact.clone());
                }
            }
        }
        (facts, cut)
    }
}
