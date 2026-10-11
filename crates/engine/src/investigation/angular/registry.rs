//! Lazy, source-bound Angular registration navigation. No runtime resolution.
use super::*;
use std::ops::Range;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Component,
    Pipe,
    Module,
    Directive,
}

pub(super) struct Declaration {
    pub path: String,
    pub name: String,
    pub range: Range<usize>,
    pub kind: Kind,
    pub metadata: ReviewNeighborhoodFact,
    pub properties: BTreeMap<String, Range<usize>>,
    pub selector: Option<String>,
    pub pipe_name: Option<String>,
    pub partial: bool,
    exports: BTreeSet<String>,
    arrays: BTreeMap<String, Vec<String>>,
}

pub(super) struct Registry {
    pub documents: BTreeMap<String, AstGrep<StrDoc<SupportLang>>>,
    pub declarations: Vec<Declaration>,
    imports: BTreeMap<String, BTreeMap<String, (String, String, ReviewNeighborhoodFact)>>,
    names: BTreeMap<(String, String), Vec<usize>>,
    exports: BTreeMap<(String, String), Vec<usize>>,
    visibility: RefCell<BTreeMap<usize, Vec<(usize, Vec<ReviewNeighborhoodFact>)>>>,
}

impl Registry {
    pub fn build(sources: &RepositorySources) -> Self {
        let mut this = Self {
            documents: BTreeMap::new(),
            declarations: Vec::new(),
            imports: BTreeMap::new(),
            names: BTreeMap::new(),
            exports: BTreeMap::new(),
            visibility: RefCell::new(BTreeMap::new()),
        };
        for file in sources.files.values() {
            let Some(language) = file.language else {
                continue;
            };
            if !matches!(
                language,
                Language::Javascript | Language::Typescript | Language::Tsx
            ) || file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
                || !file.source.contains("@angular/core")
            {
                continue;
            }
            let Ok(doc) = StrDoc::try_new(&file.source, parser_language(language)) else {
                continue;
            };
            let ast = AstGrep::doc(doc);
            let root = ast.root();
            let mut imports = BTreeMap::new();
            for statement in root
                .children()
                .filter(|n| n.kind().as_ref() == "import_statement" && valid(n))
            {
                let Some(module) = statement.field("source").and_then(|n| static_literal(&n))
                else {
                    continue;
                };
                for spec in statement
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "import_specifier")
                {
                    let Some(name) = spec.field("name") else {
                        continue;
                    };
                    let local = spec.field("alias").unwrap_or_else(|| name.clone());
                    imports.insert(
                        local.text().to_string(),
                        (
                            module.clone(),
                            name.text().to_string(),
                            bounded_fact(
                                file,
                                &statement,
                                "frontend_import_binding_context",
                                local.text().as_ref(),
                            )
                            .0,
                        ),
                    );
                }
                for clause in statement
                    .children()
                    .filter(|n| n.kind().as_ref() == "import_clause")
                {
                    for local in clause
                        .children()
                        .filter(|n| n.kind().as_ref() == "identifier")
                    {
                        imports.insert(
                            local.text().to_string(),
                            (
                                module.clone(),
                                "default".into(),
                                bounded_fact(
                                    file,
                                    &statement,
                                    "frontend_import_binding_context",
                                    local.text().as_ref(),
                                )
                                .0,
                            ),
                        );
                    }
                }
            }
            this.imports.insert(file.path.clone(), imports);
            for owner in root
                .dfs()
                .filter(|n| n.kind().as_ref() == "class_declaration")
            {
                let Some(name) = owner.field("name") else {
                    continue;
                };
                let decorators: Vec<_> = owner
                    .children()
                    .chain(
                        owner
                            .parent()
                            .into_iter()
                            .filter(|p| p.kind().as_ref() == "export_statement")
                            .flat_map(|p| p.children().collect::<Vec<_>>()),
                    )
                    .filter(|n| n.kind().as_ref() == "decorator")
                    .flat_map(|n| n.children().collect::<Vec<_>>())
                    .collect();
                let metadata: Vec<_> = decorators
                    .iter()
                    .filter_map(|n| {
                        let function = n.field("function")?;
                        [
                            (Kind::Component, "Component"),
                            (Kind::Pipe, "Pipe"),
                            (Kind::Module, "NgModule"),
                            (Kind::Directive, "Directive"),
                        ]
                        .into_iter()
                        .find(|(_, export)| {
                            core_imports(&root, export).contains(function.text().as_ref())
                        })
                        .map(|(kind, _)| (kind, n))
                    })
                    .collect();
                if metadata.len() != 1 {
                    continue;
                }
                let (kind, call) = metadata[0];
                let Some(args) = call.field("arguments") else {
                    continue;
                };
                let objects: Vec<_> = args.children().filter(|n| n.is_named()).collect();
                if objects.len() != 1
                    || objects[0].kind().as_ref() != "object"
                    || !valid(&objects[0])
                {
                    continue;
                }
                let object = &objects[0];
                let mut partial = false;
                let mut properties = BTreeMap::new();
                for pair in object.children().filter(|n| n.is_named()) {
                    let (Some(key), Some(value)) = (pair.field("key"), pair.field("value")) else {
                        partial = true;
                        continue;
                    };
                    if key.kind().as_ref() == "computed_property_name" {
                        partial = true;
                        continue;
                    }
                    let key = key.text().trim_matches(['\'', '"']).to_string();
                    if properties.insert(key, value.range()).is_some() {
                        partial = true
                    }
                }
                // Spreads/duplicate/computed metadata can replace registration or a
                // template. Retain its source, but never invent an effective value.
                if partial {
                    properties.clear()
                }
                let property = |key: &str| {
                    object
                        .children()
                        .find(|n| {
                            n.field("key")
                                .is_some_and(|k| k.text().trim_matches(['\'', '"']) == key)
                        })
                        .and_then(|n| n.field("value"))
                };
                let selector = (!partial)
                    .then(|| property("selector").and_then(|n| static_literal(&n)))
                    .flatten();
                let pipe_name = (!partial)
                    .then(|| property("name").and_then(|n| static_literal(&n)))
                    .flatten();
                let mut arrays = BTreeMap::new();
                if !partial {
                    for key in ["imports", "declarations", "exports"] {
                        if let Some(value) = property(key) {
                            if value.kind().as_ref() != "array" {
                                partial = true;
                                continue;
                            }
                            let mut values = Vec::new();
                            for item in value.children().filter(|n| n.is_named()).take(129) {
                                if values.len() == 128 {
                                    partial = true;
                                    break;
                                }
                                if item.kind().as_ref() == "identifier" {
                                    values.push(item.text().to_string())
                                } else if item.kind().as_ref() == "call_expression"
                                    && item.field("function").is_some_and(|f| {
                                        core_imports(&root, "forwardRef")
                                            .contains(f.text().as_ref())
                                    })
                                    && let Some(args) = item.field("arguments")
                                    && args.children().filter(|n| n.is_named()).count() == 1
                                    && let Some(callback) = args.children().find(|n| n.is_named())
                                    && callback.kind().as_ref() == "arrow_function"
                                    && let Some(body) = callback.field("body")
                                    && body.kind().as_ref() == "identifier"
                                {
                                    values.push(body.text().to_string())
                                } else {
                                    partial = true
                                }
                            }
                            arrays.insert(key.into(), values);
                        }
                    }
                }
                let mut exports = BTreeSet::new();
                if owner
                    .parent()
                    .is_some_and(|p| p.kind().as_ref() == "export_statement")
                {
                    exports.insert(
                        if owner
                            .parent()
                            .unwrap()
                            .text()
                            .trim_start()
                            .starts_with("export default")
                        {
                            "default".into()
                        } else {
                            name.text().to_string()
                        },
                    );
                }
                for spec in root
                    .children()
                    .filter(|n| {
                        n.kind().as_ref() == "export_statement" && n.field("source").is_none()
                    })
                    .flat_map(|n| {
                        n.dfs()
                            .filter(|n| n.kind().as_ref() == "export_specifier")
                            .collect::<Vec<_>>()
                    })
                {
                    if spec.field("name").is_some_and(|n| n.text() == name.text()) {
                        if let Some(alias) = spec.field("alias").or_else(|| spec.field("name")) {
                            exports.insert(alias.text().to_string());
                        }
                    }
                }
                let (metadata, cut) = bounded_fact(
                    file,
                    call,
                    if kind == Kind::Pipe {
                        "frontend_pipe_metadata_context"
                    } else if kind == Kind::Module {
                        "frontend_module_registration_context"
                    } else if kind == Kind::Directive {
                        "frontend_directive_metadata_context"
                    } else {
                        "frontend_component_template_context"
                    },
                    name.text().as_ref(),
                );
                this.declarations.push(Declaration {
                    path: file.path.clone(),
                    name: name.text().into(),
                    range: owner.range(),
                    kind,
                    metadata,
                    properties,
                    selector,
                    pipe_name,
                    partial: partial || cut,
                    exports,
                    arrays,
                });
            }
            this.documents.insert(file.path.clone(), ast);
        }
        for (id, decl) in this.declarations.iter().enumerate() {
            this.names
                .entry((decl.path.clone(), decl.name.clone()))
                .or_default()
                .push(id);
            for name in &decl.exports {
                this.exports
                    .entry((decl.path.clone(), name.clone()))
                    .or_default()
                    .push(id);
            }
        }
        this
    }

    pub fn owner(&self, decl: &Declaration) -> Node<'_, StrDoc<SupportLang>> {
        self.documents[&decl.path]
            .root()
            .dfs()
            .find(|n| n.range() == decl.range && n.kind().as_ref() == "class_declaration")
            .unwrap()
    }

    pub fn property(&self, decl: &Declaration, key: &str) -> Option<Node<'_, StrDoc<SupportLang>>> {
        let range = decl.properties.get(key)?;
        self.documents[&decl.path]
            .root()
            .dfs()
            .find(|n| n.range() == *range)
    }

    pub fn resolve(&self, path: &str, local: &str) -> Option<(usize, Vec<ReviewNeighborhoodFact>)> {
        if let Some((module, export, proof)) = self.imports.get(path).and_then(|m| m.get(local)) {
            if !module.starts_with('.') {
                return None;
            }
            // Resolve only actual indexed repository files, including explicit extensions.
            let mut parts: Vec<_> = path.split('/').collect();
            parts.pop()?;
            for part in module.split('/') {
                match part {
                    "" | "." => {}
                    ".." => {
                        parts.pop()?;
                    }
                    s => parts.push(s),
                }
            }
            let base = parts.join("/");
            let candidates = [
                base.clone(),
                format!("{base}.ts"),
                format!("{base}.tsx"),
                format!("{base}.js"),
                format!("{base}/index.ts"),
            ];
            let matches: Vec<_> = candidates
                .iter()
                .flat_map(|path| {
                    self.exports
                        .get(&(path.clone(), export.clone()))
                        .into_iter()
                        .flatten()
                })
                .copied()
                .collect();
            return (matches.len() == 1).then(|| (matches[0], vec![proof.clone()]));
        }
        let matches = self.names.get(&(path.into(), local.into()))?;
        (matches.len() == 1).then(|| (matches[0], Vec::new()))
    }

    // Entities made available by explicit imports or a declaring NgModule.
    // Imported modules expose only exports, not their private declarations.
    pub fn visible(&self, component: usize) -> Vec<(usize, Vec<ReviewNeighborhoodFact>)> {
        if let Some(visible) = self.visibility.borrow().get(&component) {
            return visible.clone();
        }
        let decl = &self.declarations[component];
        let mut result = BTreeMap::new();
        for local in decl.arrays.get("imports").into_iter().flatten() {
            if let Some((target, proof)) = self.resolve(&decl.path, local) {
                self.expose(target, proof, 0, &mut result);
            }
        }
        for module in self.declarations.iter().filter(|d| d.kind == Kind::Module) {
            if module
                .arrays
                .get("declarations")
                .into_iter()
                .flatten()
                .any(|name| {
                    self.resolve(&module.path, name)
                        .is_some_and(|(i, _)| i == component)
                })
            {
                for name in module.arrays.get("declarations").into_iter().flatten() {
                    if let Some((target, mut proof)) = self.resolve(&module.path, name) {
                        proof.push(module.metadata.clone());
                        result.entry(target).or_insert(proof);
                    }
                }
                for name in module.arrays.get("imports").into_iter().flatten() {
                    if let Some((target, mut proof)) = self.resolve(&module.path, name) {
                        proof.push(module.metadata.clone());
                        self.expose(target, proof, 0, &mut result);
                    }
                }
            }
        }
        result.remove(&component);
        let result: Vec<_> = result.into_iter().collect();
        self.visibility
            .borrow_mut()
            .insert(component, result.clone());
        result
    }

    pub fn imported(&self, path: &str, local: &str, module: &str, name: &str) -> bool {
        self.imports
            .get(path)
            .and_then(|imports| imports.get(local))
            .is_some_and(|(m, n, _)| m == module && n == name)
    }

    fn expose(
        &self,
        target: usize,
        mut proof: Vec<ReviewNeighborhoodFact>,
        depth: usize,
        result: &mut BTreeMap<usize, Vec<ReviewNeighborhoodFact>>,
    ) {
        let decl = &self.declarations[target];
        if decl.kind != Kind::Module {
            if self
                .property(decl, "standalone")
                .is_some_and(|n| n.text() == "false")
            {
                return;
            }
            result.entry(target).or_insert(proof);
            return;
        }
        if depth == 2 {
            return;
        }
        proof.push(decl.metadata.clone());
        for name in decl.arrays.get("exports").into_iter().flatten() {
            let Some((entity, links)) = self.resolve(&decl.path, name) else {
                continue;
            };
            let available = ["declarations", "imports"].iter().any(|key| {
                decl.arrays.get(*key).into_iter().flatten().any(|local| {
                    self.resolve(&decl.path, local)
                        .is_some_and(|(i, _)| i == entity)
                })
            });
            if !available {
                continue;
            }
            let mut chain = proof.clone();
            chain.extend(links);
            self.expose(entity, chain, depth + 1, result);
        }
    }
}

pub(super) fn bounded_fact(
    file: &SourceFile,
    node: &Node<'_, StrDoc<SupportLang>>,
    role: &str,
    name: &str,
) -> (ReviewNeighborhoodFact, bool) {
    let range = node.range();
    let mut end = range.end.min(range.start + MAX_FACT_BYTES);
    while !file.source.is_char_boundary(end) {
        end -= 1
    }
    (fact(file, range.start, end, role, name), end < range.end)
}

pub(super) fn core_imports(root: &Node<'_, StrDoc<SupportLang>>, export: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for statement in root.children().filter(|n| {
        n.kind().as_ref() == "import_statement"
            && n.field("source")
                .is_some_and(|s| s.text().trim_matches(['\'', '"']) == "@angular/core")
    }) {
        for spec in statement.dfs().filter(|n| {
            n.kind().as_ref() == "import_specifier"
                && n.field("name").is_some_and(|n| n.text() == export)
        }) {
            if let Some(local) = spec.field("alias").or_else(|| spec.field("name")) {
                names.insert(local.text().to_string());
            }
        }
        for spec in statement
            .dfs()
            .filter(|n| n.kind().as_ref() == "namespace_import")
        {
            if let Some(local) = spec.children().find(|n| n.kind().as_ref() == "identifier") {
                names.insert(format!("{}.{export}", local.text()));
            }
        }
    }
    names
}
