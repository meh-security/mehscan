//! Shared source preparation and bounded contextual dependencies, never dispatch proof.
use super::*;
use ast_grep_language::SupportLang;

pub(super) struct RustSources {
    trees: BTreeMap<String, AstGrep<StrDoc<SupportLang>>>,
}
impl RustSources {
    pub(super) fn build(
        sources: &RepositorySources,
        selection: &rust_configuration::Selection,
    ) -> Self {
        Self {
            trees: sources
                .files
                .values()
                .filter(|f| {
                    f.language == Some(Language::Rust)
                        && f.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
                        && !selection.excluded_file(&f.path)
                })
                .filter_map(|f| {
                    StrDoc::try_new(&f.source, SupportLang::Rust)
                        .ok()
                        .map(|doc| (f.path.clone(), AstGrep::doc(doc)))
                })
                .collect(),
        }
    }
    pub(super) fn root(&self, path: &str) -> Option<Node<'_, StrDoc<SupportLang>>> {
        Some(self.trees.get(path)?.root())
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Reference {
    name: String,
    macro_call: bool,
}
struct Definition {
    key: String,
    module: String,
    capture: Capture,
    references: Vec<Reference>,
    macro_definition: bool,
    bindings: Vec<Capture>,
}

struct ImportBinding {
    aliases: Vec<(String, String)>,
    declaration: Capture,
}
#[derive(Default)]
struct ScopeImports {
    scopes: BTreeMap<usize, Vec<ImportBinding>>,
}
impl ScopeImports {
    fn build(
        file: &SourceFile,
        selection: &rust_configuration::Selection,
        root: &Node<'_, StrDoc<SupportLang>>,
    ) -> Self {
        let mut result = Self::default();
        for declaration in root.dfs().filter(|n| {
            n.kind().as_ref() == "use_declaration" && !selection.excluded(&file.path, n.range())
        }) {
            let Some(scope) = declaration.parent() else {
                continue;
            };
            let mut imports = Vec::new();
            rust_shared_state::imports(&declaration, "", false, &mut imports);
            result
                .scopes
                .entry(scope.range().start)
                .or_default()
                .push(ImportBinding {
                    aliases: imports.into_iter().map(|(a, t, _)| (a, t)).collect(),
                    declaration: capture(file, &declaration),
                });
        }
        result
    }
}

pub(super) struct Dependencies {
    definitions: Vec<Definition>,
    names: BTreeMap<String, Vec<usize>>,
    operations: BTreeMap<String, Vec<usize>>,
    implementations: BTreeMap<String, Vec<usize>>,
    macros: BTreeMap<(String, String), Vec<usize>>,
    imports: BTreeMap<String, ScopeImports>,
    cache: RefCell<BTreeMap<usize, (Vec<usize>, bool)>>,
}

fn compact(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}
fn local_module(file: &str, node: &Node<'_, StrDoc<SupportLang>>) -> String {
    let mut module = rust_shared_state::module(file);
    let mut names = node
        .ancestors()
        .filter(|n| n.kind().as_ref() == "mod_item")
        .filter_map(|n| n.field("name").map(|n| n.text().into_owned()))
        .collect::<Vec<_>>();
    names.reverse();
    for name in names {
        module.push_str("::");
        module.push_str(&name);
    }
    module
}
fn root_namespace(module: &str) -> &str {
    module.split("::").next().unwrap_or(module)
}
fn canonical(
    selection: &rust_configuration::Selection,
    file: &str,
    module: &str,
    node: &Node<'_, StrDoc<SupportLang>>,
    value: &str,
    prepared: Option<&ScopeImports>,
) -> String {
    let head = value.split("::").next().unwrap_or(value);
    if node
        .ancestors()
        .filter_map(|n| n.field("type_parameters"))
        .any(|p| {
            p.children()
                .filter_map(|n| n.field("name"))
                .any(|n| n.text() == head)
        })
    {
        return format!("generic::{value}");
    }
    let mut choices = BTreeSet::new();
    for scope in node.ancestors().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "block" | "declaration_list" | "source_file"
        )
    }) {
        let module_boundary = scope
            .parent()
            .is_some_and(|p| p.kind().as_ref() == "mod_item");
        if let Some(prepared) = prepared {
            for binding in prepared
                .scopes
                .get(&scope.range().start)
                .into_iter()
                .flatten()
            {
                for (alias, target) in &binding.aliases {
                    if alias == head {
                        choices.insert(format!("{target}{}", &value[head.len()..]));
                    }
                }
            }
            if !choices.is_empty() || module_boundary {
                break;
            }
            continue;
        }
        for item in scope.children().filter(|n| {
            n.kind().as_ref() == "use_declaration" && !selection.excluded(file, n.range())
        }) {
            let mut imports = Vec::new();
            rust_shared_state::imports(&item, "", false, &mut imports);
            for (alias, target, _) in imports {
                if alias == head {
                    choices.insert(format!("{target}{}", &value[head.len()..]));
                }
            }
        }
        if !choices.is_empty() || module_boundary {
            break;
        }
    }
    if choices.len() == 1 {
        return rust_shared_state::qualified(module, choices.first().unwrap());
    }
    if choices.len() > 1 {
        return format!("ambiguous::{value}");
    }
    rust_shared_state::qualified(module, value)
}

pub(super) fn type_key(
    file: &str,
    selection: &rust_configuration::Selection,
    node: &Node<'_, StrDoc<SupportLang>>,
) -> String {
    canonical(
        selection,
        file,
        &local_module(file, node),
        node,
        compact(&node.text()).split('<').next().unwrap_or_default(),
        None,
    )
}

impl Dependencies {
    pub(super) fn build(
        sources: &RepositorySources,
        selection: &rust_configuration::Selection,
        parsed: &RustSources,
    ) -> Self {
        let mut index = Self {
            definitions: Vec::new(),
            names: BTreeMap::new(),
            operations: BTreeMap::new(),
            implementations: BTreeMap::new(),
            macros: BTreeMap::new(),
            imports: BTreeMap::new(),
            cache: RefCell::new(BTreeMap::new()),
        };
        for file in sources
            .files
            .values()
            .filter(|f| f.language == Some(Language::Rust))
        {
            let Some(root) = parsed.root(&file.path) else {
                continue;
            };
            let imports = ScopeImports::build(file, selection, &root);
            for node in root.dfs().filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "function_item"
                        | "struct_item"
                        | "enum_item"
                        | "type_item"
                        | "trait_item"
                        | "impl_item"
                        | "macro_definition"
                )
            }) {
                if selection.excluded(&file.path, node.range())
                    || node.range().len() > 16384
                    || node.dfs().any(|n| n.is_error() || n.is_missing())
                {
                    continue;
                }
                // Function-local declarations and closures have distinct bindings;
                // this project context does not promote them to module symbols.
                if node.ancestors().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "function_item" | "closure_expression" | "trait_item"
                    )
                }) {
                    continue;
                }
                let module = local_module(&file.path, &node);
                let parent_impl = node.ancestors().find(|n| n.kind().as_ref() == "impl_item");
                let owner_node = if node.kind().as_ref() == "impl_item" {
                    Some(node.clone())
                } else {
                    parent_impl
                };
                let owner = owner_node
                    .as_ref()
                    .and_then(|n| n.field("type"))
                    .filter(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "type_identifier" | "scoped_type_identifier" | "generic_type"
                        )
                    })
                    .map(|n| {
                        canonical(
                            selection,
                            &file.path,
                            &module,
                            &n,
                            compact(&n.text()).split('<').next().unwrap_or_default(),
                            Some(&imports),
                        )
                    });
                let function = node.kind().as_ref() == "function_item";
                let macro_definition = node.kind().as_ref() == "macro_definition";
                let name = node
                    .field("name")
                    .map(|n| n.text().into_owned())
                    .unwrap_or_default();
                let key = if node.kind().as_ref() == "impl_item" {
                    format!(
                        "{}::#implementation:{}",
                        owner.as_deref().unwrap_or(&module),
                        node.range().start
                    )
                } else if function && owner.is_some() {
                    if owner_node
                        .as_ref()
                        .is_some_and(|n| n.field("trait").is_some())
                    {
                        format!(
                            "{}::#trait:{}::{name}",
                            owner.as_deref().unwrap(),
                            node.range().start
                        )
                    } else {
                        format!("{}::{name}", owner.as_deref().unwrap())
                    }
                } else {
                    format!("{module}::{name}")
                };
                let mut references = BTreeSet::new();
                if function {
                    if let Some(owner) = &owner {
                        references.insert(Reference {
                            name: owner.clone(),
                            macro_call: false,
                        });
                    }
                }
                let mut variables = BTreeMap::new();
                for parameter in node
                    .field("parameters")
                    .into_iter()
                    .flat_map(|n| n.children().collect::<Vec<_>>())
                    .filter(|n| n.kind().as_ref() == "parameter")
                {
                    if let (Some(p), Some(ty)) =
                        (parameter.field("pattern"), parameter.field("type"))
                    {
                        if let Some(t) = ty.dfs().find(|n| {
                            matches!(
                                n.kind().as_ref(),
                                "type_identifier" | "scoped_type_identifier"
                            )
                        }) {
                            variables.insert(
                                p.text().into_owned(),
                                canonical(
                                    selection,
                                    &file.path,
                                    &module,
                                    &t,
                                    &compact(&t.text()),
                                    Some(&imports),
                                ),
                            );
                        }
                    }
                }
                if let Some(owner) = &owner {
                    variables.insert("self".into(), owner.clone());
                }
                for child in node
                    .dfs()
                    .filter(|n| !selection.excluded(&file.path, n.range()))
                {
                    if matches!(
                        child.kind().as_ref(),
                        "type_identifier" | "scoped_type_identifier"
                    ) {
                        references.insert(Reference {
                            name: canonical(
                                selection,
                                &file.path,
                                &module,
                                &child,
                                &compact(&child.text()),
                                Some(&imports),
                            ),
                            macro_call: false,
                        });
                    }
                    if child.kind().as_ref() == "macro_invocation" {
                        if let Some(m) = child.field("macro") {
                            references.insert(Reference {
                                name: canonical(
                                    selection,
                                    &file.path,
                                    &module,
                                    &m,
                                    &compact(&m.text()),
                                    Some(&imports),
                                ),
                                macro_call: true,
                            });
                        }
                    }
                    if child.kind().as_ref() == "call_expression" {
                        let Some(mut callee) = child.field("function") else {
                            continue;
                        };
                        if callee.kind().as_ref() == "generic_function" {
                            let Some(f) = callee.field("function") else {
                                continue;
                            };
                            callee = f;
                        }
                        let target = if callee.kind().as_ref() == "field_expression" {
                            let (Some(value), Some(method)) =
                                (callee.field("value"), callee.field("field"))
                            else {
                                continue;
                            };
                            variables
                                .get(value.text().as_ref())
                                .map(|ty| format!("{ty}::{}", method.text()))
                        } else {
                            let text = compact(&callee.text());
                            if let Some(rest) = text.strip_prefix("Self::") {
                                owner.as_ref().map(|o| format!("{o}::{rest}"))
                            } else {
                                Some(canonical(
                                    selection,
                                    &file.path,
                                    &module,
                                    &callee,
                                    &text,
                                    Some(&imports),
                                ))
                            }
                        };
                        if let Some(name) = target {
                            references.insert(Reference {
                                name,
                                macro_call: false,
                            });
                        }
                    }
                }
                let slot = index.definitions.len();
                let identifiers = node
                    .dfs()
                    .filter(|n| {
                        matches!(n.kind().as_ref(), "identifier" | "type_identifier" | "self")
                    })
                    .map(|n| n.text().into_owned())
                    .collect::<BTreeSet<_>>();
                let mut bindings = Vec::new();
                for scope in node.ancestors().filter(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "source_file" | "declaration_list" | "block"
                    )
                }) {
                    for binding in imports
                        .scopes
                        .get(&scope.range().start)
                        .into_iter()
                        .flatten()
                    {
                        if binding
                            .aliases
                            .iter()
                            .any(|(alias, _)| identifiers.contains(alias))
                        {
                            bindings.push(binding.declaration.clone());
                        }
                    }
                }
                index.names.entry(key.clone()).or_default().push(slot);
                if function {
                    index
                        .operations
                        .entry(file.path.clone())
                        .or_default()
                        .push(slot);
                }
                if node.kind().as_ref() == "impl_item" {
                    if let Some(owner) = &owner {
                        index
                            .implementations
                            .entry(owner.clone())
                            .or_default()
                            .push(slot);
                    }
                }
                if macro_definition {
                    index
                        .macros
                        .entry((root_namespace(&module).into(), name))
                        .or_default()
                        .push(slot);
                }
                index.definitions.push(Definition {
                    key,
                    module,
                    capture: capture(file, &node),
                    references: references.into_iter().collect(),
                    macro_definition,
                    bindings,
                });
            }
            for declaration in root.dfs().filter(|n| {
                n.kind().as_ref() == "use_declaration"
                    && !selection.excluded(&file.path, n.range())
                    && !n.ancestors().any(|n| {
                        matches!(n.kind().as_ref(), "function_item" | "closure_expression")
                    })
            }) {
                let module = local_module(&file.path, &declaration);
                let mut imports = Vec::new();
                rust_shared_state::imports(&declaration, "", false, &mut imports);
                for (alias, target, _) in imports.into_iter().filter(|(a, _, _)| a != "*") {
                    let key = format!("{module}::{alias}");
                    let target = rust_shared_state::qualified(&module, &target);
                    if key == target {
                        continue;
                    }
                    let slot = index.definitions.len();
                    index.names.entry(key.clone()).or_default().push(slot);
                    index.definitions.push(Definition {
                        key,
                        module: module.clone(),
                        capture: capture(file, &declaration),
                        references: vec![Reference {
                            name: target,
                            macro_call: false,
                        }],
                        macro_definition: false,
                        bindings: Vec::new(),
                    });
                }
            }
            index.imports.insert(file.path.clone(), imports);
        }
        for slots in index.operations.values_mut() {
            slots.sort_by_key(|slot| index.definitions[*slot].capture.location.start.byte_offset);
        }
        index
    }

    fn resolve(&self, reference: &Reference, module: &str) -> Option<usize> {
        if let Some(slots) = self.names.get(&reference.name) {
            return (slots.len() == 1).then_some(slots[0]);
        }
        if reference.macro_call {
            let leaf = reference.name.rsplit("::").next()?;
            let slots = self
                .macros
                .get(&(root_namespace(module).into(), leaf.into()))?;
            // A unique macro body is navigation context, not expansion or binding proof.
            return (slots.len() == 1).then_some(slots[0]);
        }
        None
    }
    pub(super) fn call_definition(
        &self,
        file: &str,
        selection: &rust_configuration::Selection,
        call: &Node<'_, StrDoc<SupportLang>>,
    ) -> Option<&Capture> {
        let mut function = call.field("function")?;
        if function.kind().as_ref() == "generic_function" {
            function = function.field("function")?;
        }
        if !matches!(function.kind().as_ref(), "identifier" | "scoped_identifier") {
            return None;
        }
        if function.kind().as_ref() == "identifier" {
            let name = function.text();
            let shadowed = call.ancestors().any(|scope| {
                scope.field("parameters").is_some_and(|p| {
                    p.children()
                        .any(|n| n.field("pattern").is_some_and(|p| p.text() == name))
                }) || (matches!(scope.kind().as_ref(), "block" | "declaration_list")
                    && scope.children().any(|n| {
                        (n.kind().as_ref() == "let_declaration"
                            && n.range().end < call.range().start
                            && n.field("pattern").is_some_and(|p| {
                                p.text().trim().trim_start_matches("mut ") == name
                            }))
                            || (n.kind().as_ref() == "function_item"
                                && n.field("name").is_some_and(|p| p.text() == name))
                    }))
            });
            if shadowed {
                return None;
            }
        }
        let module = local_module(file, call);
        let key = canonical(
            selection,
            file,
            &module,
            &function,
            &compact(&function.text()),
            self.imports.get(file),
        );
        let slots = self.names.get(&key)?;
        (slots.len() == 1).then(|| &self.definitions[slots[0]].capture)
    }
    fn closure(&self, start: usize) -> (Vec<usize>, bool) {
        if let Some(value) = self.cache.borrow().get(&start) {
            return value.clone();
        }
        let mut selected = BTreeSet::new();
        let mut pending = VecDeque::from([(start, 0)]);
        let mut bytes = 0;
        let mut limited = false;
        while let Some((slot, depth)) = pending.pop_front() {
            let definition = &self.definitions[slot];
            let mut targets = definition
                .references
                .iter()
                .filter_map(|r| self.resolve(r, &definition.module))
                .collect::<Vec<_>>();
            if let Some(impls) = self.implementations.get(&definition.key) {
                targets.extend(impls.iter().copied());
            }
            for target in targets {
                if target == start || selected.contains(&target) {
                    continue;
                }
                let next = &self.definitions[target];
                if selected.len() >= 12 || bytes + next.capture.text.len() > 49152 {
                    limited = true;
                    continue;
                }
                selected.insert(target);
                bytes += next.capture.text.len();
                if depth < 3 {
                    pending.push_back((target, depth + 1));
                } else if !next.references.is_empty() {
                    limited = true;
                }
            }
        }
        let value = (selected.into_iter().collect(), limited);
        self.cache.borrow_mut().insert(start, value.clone());
        value
    }
    pub(super) fn enrich(&self, groups: &mut [ObservationGroup]) {
        for group in groups {
            let Some(slots) = self.operations.get(&group.path) else {
                continue;
            };
            for fact in &mut group.evidence {
                let offset = fact.location.start.byte_offset;
                let stop = slots.partition_point(|slot| {
                    self.definitions[*slot].capture.location.start.byte_offset <= offset
                });
                let Some(slot) = slots[..stop].last().copied().filter(|slot| {
                    self.definitions[*slot].capture.location.end.byte_offset
                        >= fact.location.end.byte_offset
                }) else {
                    continue;
                };
                let mut seeds = fact
                    .captures
                    .values()
                    .filter_map(|c| {
                        self.operations.get(&c.location.path).and_then(|items| {
                            items
                                .binary_search_by_key(&c.location.start.byte_offset, |i| {
                                    self.definitions[*i].capture.location.start.byte_offset
                                })
                                .ok()
                                .map(|p| items[p])
                                .filter(|i| {
                                    self.definitions[*i].capture.location.end.byte_offset
                                        == c.location.end.byte_offset
                                })
                        })
                    })
                    .collect::<Vec<_>>();
                seeds.push(slot);
                let mut dependencies = Vec::new();
                let mut limited = false;
                let mut bytes = 0;
                for seed in seeds {
                    let (items, clipped) = self.closure(seed);
                    limited |= clipped;
                    for item in items {
                        if dependencies.contains(&item) || item == slot {
                            continue;
                        }
                        let size = self.definitions[item].capture.text.len();
                        if dependencies.len() >= 12 || bytes + size > 65536 {
                            limited = true;
                            continue;
                        }
                        bytes += size;
                        dependencies.push(item);
                    }
                }
                if dependencies.is_empty() {
                    continue;
                }
                let operation = &self.definitions[slot];
                fact.captures.insert(
                    "rust_context_operation_definition".into(),
                    operation.capture.clone(),
                );
                let mut bindings = Vec::<Capture>::new();
                for slot in std::iter::once(slot).chain(dependencies.iter().copied()) {
                    for binding in &self.definitions[slot].bindings {
                        if bindings.len() < 8
                            && !bindings.iter().any(|c| c.location == binding.location)
                        {
                            bindings.push(binding.clone());
                        }
                    }
                }
                for (index, binding) in bindings.into_iter().enumerate() {
                    fact.captures.insert(
                        format!("rust_context_binding_{index:02}_definition"),
                        binding,
                    );
                }
                for (index, target) in dependencies.iter().enumerate() {
                    fact.captures.insert(
                        format!("rust_context_{index:02}_definition"),
                        self.definitions[*target].capture.clone(),
                    );
                }
                fact.tags
                    .push("rust-source-context:not-dispatch-proof".into());
                if limited {
                    fact.tags
                        .push("rust-source-context:bounded-dependencies".into());
                }
                if dependencies
                    .iter()
                    .any(|d| self.definitions[*d].macro_definition)
                {
                    fact.tags
                        .push("rust-source-context:macro-expansion-unresolved".into());
                }
                // Multiple trait implementations, external SDKs and dynamic calls
                // stay unresolved even when useful implementation source is supplied.
                fact.tags
                    .push("rust-source-context:trait-and-external-dispatch-unresolved".into());
            }
        }
    }
}

pub(super) fn capture(file: &SourceFile, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    let a = node.start_pos();
    let b = node.end_pos();
    Capture {
        text: node.text().into_owned(),
        location: Location {
            path: file.path.clone(),
            start: Position {
                line: a.line() + 1,
                column: a.column(node) + 1,
                byte_offset: node.range().start,
            },
            end: Position {
                line: b.line() + 1,
                column: b.column(node) + 1,
                byte_offset: node.range().end,
            },
        },
    }
}
