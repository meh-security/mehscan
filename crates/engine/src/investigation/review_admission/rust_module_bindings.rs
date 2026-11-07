//! Bounded source-owned module bindings. Configuration remains a separate input.
use super::*;
use rust_shared_state::AstNode as N;

#[derive(Clone)]
pub(super) struct Located<'a> {
    pub(super) file: &'a SourceFile,
    pub(super) node: N<'a>,
    pub(super) module: Option<usize>,
}

impl<'a> Located<'a> {
    pub(super) fn with_node(&self, node: N<'a>) -> Self {
        Self {
            file: self.file,
            node,
            module: self.module,
        }
    }
    pub(super) fn capture(&self) -> Capture {
        rust_dependencies::capture(self.file, &self.node)
    }
}

struct Module<'a> {
    scope: Located<'a>,
    parent: Option<usize>,
    children: BTreeMap<usize, usize>,
    directory: String,
    support: Vec<Capture>,
}

pub(super) struct Project<'a> {
    sources: &'a RepositorySources,
    parsed: &'a rust_dependencies::RustSources,
    selection: &'a rust_configuration::Selection,
    modules: Vec<Module<'a>>,
    owners: BTreeMap<(String, usize, usize), Vec<usize>>,
    has_manifests: bool,
    limited: bool,
}

fn directory_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

// Normalize in-root logical paths only; never access the filesystem here.
fn join(base: &str, relative: &str) -> Option<String> {
    if relative.starts_with(['/', '\\']) || relative.contains(':') {
        return None;
    }
    let mut parts = base
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for part in relative.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part.into()),
        }
    }
    Some(parts.join("/"))
}

fn module_scope<'a>(node: &N<'a>) -> Option<N<'a>> {
    std::iter::once(node.clone())
        .chain(node.ancestors())
        .find(|n| {
            n.kind().as_ref() == "source_file"
                || n.kind().as_ref() == "declaration_list"
                    && n.parent().is_some_and(|p| p.kind().as_ref() == "mod_item")
        })
}

impl<'a> Project<'a> {
    pub(super) fn build(
        sources: &'a RepositorySources,
        parsed: &'a rust_dependencies::RustSources,
        selection: &'a rust_configuration::Selection,
    ) -> Self {
        let manifests = sources
            .files
            .values()
            .filter(|f| f.path.rsplit('/').next() == Some("Cargo.toml"))
            .map(|f| (f.path.clone(), f.source.clone()))
            .collect::<Vec<_>>();
        let paths = sources
            .files
            .values()
            .filter(|f| f.language == Some(Language::Rust))
            .map(|f| f.path.clone())
            .collect();
        let roots = crate::code::rust_modules::RustModules::target_roots(paths, &manifests, true);
        let mut result = Self {
            sources,
            parsed,
            selection,
            modules: Vec::new(),
            owners: BTreeMap::new(),
            has_manifests: !manifests.is_empty(),
            limited: false,
        };
        for (path, support) in roots {
            let (Some(file), Some(node)) = (sources.files.get(&path), parsed.root(&path)) else {
                continue;
            };
            if selection.excluded_file(&path) {
                continue;
            }
            result.add_module(
                Located {
                    file,
                    node,
                    module: None,
                },
                None,
                directory_of(&path).into(),
                support,
                0,
            );
        }
        result
    }

    fn add_module(
        &mut self,
        mut scope: Located<'a>,
        parent: Option<usize>,
        directory: String,
        support: Vec<Capture>,
        depth: usize,
    ) -> Option<usize> {
        if depth > 16 || self.modules.len() >= 4096 {
            self.limited = true;
            return None;
        }
        let mut ancestor = parent;
        while let Some(id) = ancestor {
            let previous = &self.modules[id];
            if previous.scope.file.path == scope.file.path
                && previous.scope.node.range() == scope.node.range()
            {
                return None;
            }
            ancestor = previous.parent;
        }
        let id = self.modules.len();
        scope.module = Some(id);
        self.owners
            .entry((
                scope.file.path.clone(),
                scope.node.range().start,
                scope.node.range().end,
            ))
            .or_default()
            .push(id);
        self.modules.push(Module {
            scope: scope.clone(),
            parent,
            children: BTreeMap::new(),
            directory,
            support,
        });
        let mut attributes = Vec::new();
        for node in scope.node.children() {
            if node.kind().contains("comment") {
                continue;
            }
            if node.kind().as_ref() == "attribute_item" {
                attributes.push(node);
                continue;
            }
            let attrs = std::mem::take(&mut attributes);
            if node.kind().as_ref() != "mod_item" || !self.selected(&scope.with_node(node.clone()))
            {
                continue;
            }
            let mut path = None;
            let mut opaque = false;
            for attribute in &attrs {
                let text = rust_shared_state::compact(&attribute.text());
                let head = text
                    .trim_start_matches("#[")
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("");
                if head == "path" {
                    let literal = attribute
                        .children()
                        .find(|n| n.kind().as_ref() == "attribute")
                        .and_then(|n| n.field("value"))
                        .filter(|n| {
                            matches!(n.kind().as_ref(), "string_literal" | "raw_string_literal")
                        })
                        .and_then(|n| crate::code::rust_modules::literal(&n.text()));
                    if path.is_some() || literal.is_none() {
                        opaque = true;
                    }
                    path = literal;
                } else if !matches!(
                    head,
                    "cfg"
                        | "doc"
                        | "allow"
                        | "deny"
                        | "warn"
                        | "forbid"
                        | "deprecated"
                        | "macro_use"
                ) {
                    opaque = true;
                }
            }
            if opaque {
                continue;
            }
            let Some(name) = node.field("name") else {
                continue;
            };
            let name = name.text().trim_start_matches("r#").to_string();
            let mut route = self.modules[id].support.clone();
            // A module's body may be large. Capture its actual declaration header.
            let end = node
                .field("body")
                .map_or(node.range().end, |b| b.range().start);
            route.push(Capture {
                text: scope.file.source[node.range().start..end].into(),
                location: location_from_offsets(
                    &scope.file.path,
                    &scope.file.source,
                    node.range().start,
                    end,
                ),
            });
            route.extend(
                attrs
                    .iter()
                    .map(|n| rust_dependencies::capture(scope.file, n)),
            );
            if route.len() > 16 || route.iter().map(|c| c.text.len()).sum::<usize>() > 16384 {
                self.limited = true;
                continue;
            }
            let child = if let Some(body) = node.field("body") {
                // Inline path attributes and conditional paths need a fuller model.
                if path.is_some() {
                    continue;
                }
                let Some(directory) = join(&self.modules[id].directory, &name) else {
                    continue;
                };
                self.add_module(scope.with_node(body), Some(id), directory, route, depth + 1)
            } else {
                let explicit = path.is_some();
                let candidates = if let Some(path) = path {
                    // Outside inline modules literal paths use the physical parent;
                    // inside them the owned module directory includes inline names.
                    let base = if scope.node.kind().as_ref() == "source_file" {
                        directory_of(&scope.file.path)
                    } else {
                        &self.modules[id].directory
                    };
                    join(base, &path).into_iter().collect::<Vec<_>>()
                } else {
                    [format!("{name}.rs"), format!("{name}/mod.rs")]
                        .iter()
                        .filter_map(|p| join(&self.modules[id].directory, p))
                        .collect()
                };
                let candidates = candidates
                    .into_iter()
                    .filter(|p| self.sources.files.contains_key(p))
                    .collect::<Vec<_>>();
                if candidates.len() != 1 {
                    continue;
                }
                let path = &candidates[0];
                let (Some(file), Some(body)) =
                    (self.sources.files.get(path), self.parsed.root(path))
                else {
                    continue;
                };
                if self.selection.excluded_file(path) {
                    continue;
                }
                let directory = if explicit || path.ends_with("/mod.rs") {
                    directory_of(path).into()
                } else {
                    path.trim_end_matches(".rs").into()
                };
                self.add_module(
                    Located {
                        file,
                        node: body,
                        module: None,
                    },
                    Some(id),
                    directory,
                    route,
                    depth + 1,
                )
            };
            if let Some(child) = child {
                self.modules[id].children.insert(node.node_id(), child);
            }
        }
        Some(id)
    }

    pub(super) fn locate(&self, file: &'a SourceFile, node: N<'a>) -> Located<'a> {
        let module = (!self.limited)
            .then(|| module_scope(&node))
            .flatten()
            .and_then(|s| {
                self.owners
                    .get(&(file.path.clone(), s.range().start, s.range().end))
            })
            .filter(|ids| ids.len() == 1)
            .map(|ids| ids[0]);
        Located { file, node, module }
    }
    pub(super) fn selected(&self, place: &Located<'a>) -> bool {
        !self
            .selection
            .excluded(&place.file.path, place.node.range())
    }
    pub(super) fn root(&self, place: &Located<'a>) -> Option<N<'a>> {
        self.parsed.root(&place.file.path)
    }
    pub(super) fn support(&self, place: &Located<'a>) -> Vec<Capture> {
        place
            .module
            .map(|id| self.modules[id].support.clone())
            .unwrap_or_default()
    }
    pub(super) fn crate_scope(&self, place: &Located<'a>) -> Option<Located<'a>> {
        if let Some(mut id) = place.module {
            while let Some(parent) = self.modules[id].parent {
                id = parent;
            }
            return Some(self.modules[id].scope.clone());
        }
        if !self.has_manifests
            && matches!(
                place.file.path.as_str(),
                "src/lib.rs" | "src/main.rs" | "lib.rs" | "main.rs"
            )
        {
            return Some(place.with_node(self.root(place)?));
        }
        None
    }
    pub(super) fn parent_scope(&self, place: &Located<'a>) -> Option<Located<'a>> {
        if let Some(id) = place.module {
            return Some(self.modules[self.modules[id].parent?].scope.clone());
        }
        let scope = module_scope(&place.node)?;
        let parent = scope.ancestors().find(|n| {
            n.kind().as_ref() == "source_file"
                || n.kind().as_ref() == "declaration_list"
                    && n.parent().is_some_and(|p| p.kind().as_ref() == "mod_item")
        })?;
        Some(place.with_node(parent))
    }
    pub(super) fn current_scope(&self, place: &Located<'a>) -> Option<Located<'a>> {
        if let Some(id) = place.module {
            return Some(self.modules[id].scope.clone());
        }
        Some(place.with_node(module_scope(&place.node)?))
    }
    pub(super) fn child_scope(&self, scope: &Located<'a>, item: &N<'a>) -> Option<Located<'a>> {
        if let Some(id) = scope.module {
            let id = *self.modules[id].children.get(&item.node_id())?;
            return Some(self.modules[id].scope.clone());
        }
        Some(scope.with_node(item.field("body")?))
    }
}
