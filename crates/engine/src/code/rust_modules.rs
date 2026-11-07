//! Source-owned Rust module availability. No Cargo, macro or target-code execution.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;

use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Availability, AvailabilityState, Capture, ConfigurationDependency, Evidence, Language,
    Location, Position, SourceConfiguration,
};
use sha2::{Digest, Sha256};

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const MAX_TERMS: usize = 32;
const MAX_DEPENDENCIES: usize = 64;
const MAX_CLAUSES_PER_TERM: usize = 64;

#[derive(Default)]
pub(crate) struct RustModules {
    files: BTreeMap<String, FileConfiguration>,
}

type FileConfiguration = SourceConfiguration;

/// Item selection used by derived review markers as well as helper binding.
/// Parse each source once here; callers retain the original bytes for lookup.
pub(crate) fn review_regions(
    path: &str,
    source: &str,
    include_tests: bool,
) -> Vec<(Range<usize>, SourceConfiguration)> {
    if !source.contains("cfg") && (include_tests || !source.contains("test")) {
        return Vec::new();
    }
    let Ok(document) = StrDoc::try_new(source, SupportLang::Rust) else {
        return Vec::new();
    };
    let ast = AstGrep::doc(document);
    let root = ast.root();
    let records = super::rust_cfg::review_condition_records(
        &root,
        if include_tests { None } else { Some(false) },
    );
    let origin = Origin::new(path, source);
    let mut regions: Vec<_> = records
        .into_iter()
        .filter(|(_, _, _, truth)| *truth != Some(true))
        .map(|(range, attribute, condition, truth)| {
            let dependency = origin.dependency(attribute, path);
            let oversized = condition.len() > 8192;
            (
                range,
                SourceConfiguration {
                    availability: Availability {
                        state: if truth == Some(false) {
                            AvailabilityState::Excluded
                        } else if oversized {
                            AvailabilityState::Unknown
                        } else {
                            AvailabilityState::Conditional
                        },
                        condition: Some(if oversized {
                            "configuration detail limit reached; inspect source declaration".into()
                        } else {
                            condition
                        }),
                    },
                    dependencies: vec![dependency],
                },
            )
        })
        .collect();
    if !include_tests {
        regions.extend(
            super::rust_tests::ranges_in_root(&root)
                .into_iter()
                .map(|range| {
                    (
                        range,
                        SourceConfiguration {
                            availability: Availability {
                                state: AvailabilityState::Excluded,
                                condition: Some("Rust test-only source item".into()),
                            },
                            dependencies: Vec::new(),
                        },
                    )
                }),
        );
    }
    regions
}

struct Clause {
    truth: Option<bool>,
    text: String,
    dependency: usize,
}

struct Edge {
    target: String,
    // Roots/#[path] own their physical parent; ordinary x.rs defers x/.
    from_owned: bool,
    target_owned: bool,
    clauses: BTreeSet<usize>,
    dependency: usize,
    unresolved: bool,
    binding_dependencies: Vec<usize>,
}

#[derive(Default)]
struct File {
    inner: BTreeSet<usize>,
    edges: Vec<Edge>,
    opaque: bool,
    opaque_dependency: Option<usize>,
    unresolved_modes: BTreeMap<bool, usize>,
}

#[derive(Clone, Default)]
struct State {
    seen: bool,
    unresolved: bool,
    limited: bool,
    terms: BTreeSet<BTreeSet<usize>>,
    dependencies: BTreeSet<usize>,
}

impl State {
    fn root(dependency: usize) -> Self {
        Self {
            seen: true,
            terms: [BTreeSet::new()].into(),
            dependencies: [dependency].into(),
            ..Self::default()
        }
    }

    fn constrain(mut self, ids: &BTreeSet<usize>, clauses: &[Clause]) -> Self {
        if !self.seen {
            return self;
        }
        if let Some(id) = ids.iter().find(|id| clauses[**id].truth == Some(false)) {
            self.terms.clear();
            // A false local predicate excludes even an unresolved incoming route.
            self.unresolved = false;
            self.limited = false;
            // This predicate decides the route independently of earlier detail.
            self.dependencies = [clauses[*id].dependency].into();
            return self;
        }
        if self.terms.is_empty() && !self.unresolved {
            return self;
        }
        self.dependencies
            .extend(ids.iter().map(|id| clauses[*id].dependency));
        if !self.terms.is_empty() {
            let unknown: BTreeSet<_> = ids
                .iter()
                .copied()
                .filter(|id| clauses[*id].truth.is_none())
                .collect();
            self.terms = self
                .terms
                .into_iter()
                .map(|mut term| {
                    term.extend(&unknown);
                    term
                })
                .collect();
        }
        self.bound();
        self
    }

    fn merge(&mut self, other: Self) {
        self.seen |= other.seen;
        self.unresolved |= other.unresolved;
        self.limited |= other.limited;
        self.terms.extend(other.terms);
        self.dependencies.extend(other.dependencies);
        if self.terms.contains(&BTreeSet::new()) {
            self.terms = [BTreeSet::new()].into();
        }
        self.bound();
    }

    fn bound(&mut self) {
        if self.terms.len() > MAX_TERMS
            || self
                .terms
                .iter()
                .any(|term| term.len() > MAX_CLAUSES_PER_TERM)
            || self.dependencies.len() > MAX_DEPENDENCIES
        {
            self.limited = true;
            if !self.terms.contains(&BTreeSet::new()) && (!self.terms.is_empty() || self.unresolved)
            {
                // Discarding constraints cannot create a weaker known route.
                // Unknown keeps the observation; a later false predicate or
                // separately established unconditional root can still decide.
                self.unresolved = true;
                self.terms.clear();
            }
            while self.dependencies.len() > MAX_DEPENDENCIES {
                self.dependencies.pop_last();
            }
        }
    }

    fn availability(&self, clauses: &[Clause]) -> Availability {
        if self.terms.contains(&BTreeSet::new()) {
            return Availability {
                state: AvailabilityState::Always,
                condition: None,
            };
        }
        if self
            .terms
            .iter()
            .map(|term| {
                term.iter()
                    .map(|id| clauses[*id].text.len() + 4)
                    .sum::<usize>()
            })
            .sum::<usize>()
            > 8192
        {
            return Availability { state: AvailabilityState::Unknown, condition: Some("source-module condition expansion exceeds display bound; inspect configuration dependencies".into()) };
        }
        let state = if self.unresolved || !self.seen {
            AvailabilityState::Unknown
        } else if self.terms.is_empty() {
            AvailabilityState::Excluded
        } else {
            AvailabilityState::Conditional
        };
        let mut terms = self
            .terms
            .iter()
            .map(|term| {
                format!(
                    "({})",
                    term.iter()
                        .map(|id| clauses[*id].text.as_str())
                        .collect::<Vec<_>>()
                        .join(" && ")
                )
            })
            .collect::<Vec<_>>();
        if self.unresolved || !self.seen {
            terms.push(if self.limited {
                "source-module detail limit reached; inspect configuration dependencies".into()
            } else {
                "unresolved source-module alternatives".into()
            });
        }
        if terms.is_empty() {
            terms.push("all established source-module inclusions are excluded".into());
        }
        Availability {
            state,
            condition: Some(terms.join(" || ")),
        }
    }
}

struct Origin<'a> {
    path: &'a str,
    source: &'a str,
    hash: String,
    lines: Vec<usize>,
    continuations: Vec<usize>,
}

impl<'a> Origin<'a> {
    fn new(path: &'a str, source: &'a str) -> Self {
        let mut lines = vec![0];
        let mut continuations = Vec::new();
        for (at, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                lines.push(at + 1);
            }
            if byte & 0xc0 == 0x80 {
                continuations.push(at);
            }
        }
        Self {
            path,
            source,
            hash: format!("{:x}", Sha256::digest(source.as_bytes())),
            lines,
            continuations,
        }
    }

    fn position(&self, at: usize) -> Position {
        let line = self.lines.partition_point(|start| *start <= at) - 1;
        let start = self.lines[line];
        let extra = self.continuations.partition_point(|p| *p < at)
            - self.continuations.partition_point(|p| *p < start);
        Position {
            line: line + 1,
            column: at - start - extra + 1,
            byte_offset: at,
        }
    }

    fn dependency(&self, range: Range<usize>, target: &str) -> ConfigurationDependency {
        let truncated = range.len() > 2048;
        let mut end = range.end.min(range.start.saturating_add(2048));
        while !self.source.is_char_boundary(end) {
            end -= 1;
        }
        let range = range.start..end;
        ConfigurationDependency {
            declaration: Capture {
                text: self.source[range.clone()].into(),
                location: Location {
                    path: self.path.into(),
                    start: self.position(range.start),
                    end: self.position(range.end),
                },
            },
            source_sha256: self.hash.clone(),
            target_path: target.into(),
            truncated,
        }
    }
}

#[derive(Default)]
struct Builder {
    files: BTreeMap<String, File>,
    clauses: Vec<Clause>,
    dependencies: Vec<ConfigurationDependency>,
    roots: BTreeMap<String, State>,
    packages: BTreeSet<String>,
    owners: BTreeMap<String, String>,
    // One concrete witness establishes unknown expansion alternatives. Listing
    // every opaque macro in the package adds no stronger applicability fact.
    open_packages: BTreeMap<String, usize>,
}

impl RustModules {
    pub(crate) fn build<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
        manifests: &[(String, String)],
        include_tests: bool,
    ) -> Self {
        let sources: BTreeMap<_, _> = sources
            .filter(|(_, language, _)| *language == Language::Rust)
            .map(|(path, _, source)| (path.replace('\\', "/"), source))
            .collect();
        if sources.is_empty() {
            return Self::default();
        }
        let mut builder =
            Builder::targets(sources.keys().cloned().collect(), manifests, include_tests);
        for (path, source) in &sources {
            builder.source(path, source, include_tests);
        }
        builder.finish()
    }

    /// The same source-owned target roots used by configuration analysis.
    pub(crate) fn target_roots(
        paths: BTreeSet<String>,
        manifests: &[(String, String)],
        include_tests: bool,
    ) -> BTreeMap<String, Vec<mehscan_core::Capture>> {
        let builder = Builder::targets(paths, manifests, include_tests);
        builder
            .roots
            .iter()
            .map(|(path, state)| {
                (
                    path.clone(),
                    state
                        .dependencies
                        .iter()
                        .map(|i| builder.dependencies[*i].declaration.clone())
                        .collect(),
                )
            })
            .collect()
    }

    pub(crate) fn excluded(&self, path: &str) -> bool {
        self.files
            .get(path)
            .is_some_and(|file| file.availability.state == AvailabilityState::Excluded)
    }

    pub(crate) fn annotate(&self, path: &str, evidence: &mut [Evidence]) {
        if let Some(file) = self.files.get(path) {
            for fact in evidence {
                file.apply_to(&mut fact.context);
            }
        }
    }

    pub(crate) fn configurations(&self) -> BTreeMap<String, SourceConfiguration> {
        self.files.clone()
    }
}

impl Builder {
    fn targets(
        paths: BTreeSet<String>,
        manifests: &[(String, String)],
        include_tests: bool,
    ) -> Self {
        let mut builder = Self::default();
        builder.files = paths
            .iter()
            .map(|path| (path.clone(), File::default()))
            .collect();
        let manifests: Vec<_> = manifests
            .iter()
            .filter_map(|(path, source)| {
                let doc = toml_edit::Document::parse(source.as_str()).ok()?;
                doc.as_table().get("package")?.as_table()?;
                Some((path.as_str(), source.as_str(), doc))
            })
            .collect();
        builder.packages = manifests
            .iter()
            .map(|(path, _, _)| parent(path).to_string())
            .collect();
        let mut owned = BTreeMap::<String, Vec<String>>::new();
        for path in &paths {
            if let Some(owner) = nearest_package(path, &builder.packages) {
                builder.owners.insert(path.clone(), owner);
            }
        }
        for (path, owner) in &builder.owners {
            owned.entry(owner.clone()).or_default().push(path.clone());
        }
        for (path, source, doc) in &manifests {
            builder.manifest(
                path,
                source,
                doc,
                owned
                    .get(parent(path))
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                include_tests,
            );
        }
        builder
    }

    fn dependency(&mut self, value: ConfigurationDependency) -> usize {
        let id = self.dependencies.len();
        self.dependencies.push(value);
        id
    }

    fn clause(&mut self, truth: Option<bool>, text: String, dependency: usize) -> usize {
        let id = self.clauses.len();
        self.clauses.push(Clause {
            truth,
            text,
            dependency,
        });
        id
    }

    fn source(&mut self, path: &str, source: &str, include_tests: bool) {
        if !self.owners.contains_key(path) && !source.contains("mod") && !source.contains("#!") {
            return;
        }
        if !source.contains("mod")
            && !source.contains("#!")
            && !source.contains('!')
            && !source.contains("#[")
        {
            return;
        }
        let Ok(doc) = StrDoc::try_new(source, SupportLang::Rust) else {
            return;
        };
        let ast = AstGrep::doc(doc);
        let root = ast.root();
        let origin = Origin::new(path, source);
        let mut conditions = BTreeMap::<(usize, usize), BTreeSet<usize>>::new();
        for (scope, attribute, text, truth) in
            super::rust_cfg::condition_records(&root, (!include_tests).then_some(false))
        {
            let dep = self.dependency(origin.dependency(attribute, path));
            let id = self.clause(truth, format!("{path}: {text}"), dep);
            conditions
                .entry((scope.start, scope.end))
                .or_default()
                .insert(id);
        }
        let false_scopes: BTreeSet<_> = conditions
            .iter()
            .filter(|(_, ids)| ids.iter().any(|id| self.clauses[*id].truth == Some(false)))
            .map(|(range, _)| *range)
            .collect();
        let mut attributes = BTreeMap::<usize, Vec<N<'_>>>::new();
        let mut index = super::rust_cfg::AttributeIndex::default();
        let mut file = File::default();
        file.inner = conditions
            .get(&(root.range().start, root.range().end))
            .cloned()
            .unwrap_or_default();
        for attribute in root.dfs().filter(|n| n.kind().as_ref() == "attribute_item") {
            if let Some(item) = index.following(&attribute) {
                attributes
                    .entry(item.node_id())
                    .or_default()
                    .push(attribute);
            }
        }
        for node in root.dfs() {
            let kind = node.kind();
            let relevant = matches!(
                kind.as_ref(),
                "macro_definition"
                    | "macro_invocation"
                    | "attribute_item"
                    | "inner_attribute_item"
                    | "use_declaration"
                    | "ERROR"
            );
            let affected = if kind.as_ref() == "attribute_item" {
                index.following(&node).unwrap_or_else(|| node.clone())
            } else {
                node.clone()
            };
            let inactive = relevant
                && std::iter::once(affected.clone())
                    .chain(affected.ancestors())
                    .any(|scope| false_scopes.contains(&(scope.range().start, scope.range().end)));
            if !inactive {
                if kind.as_ref() == "macro_definition" {
                    file.opaque = true;
                }
                if kind.as_ref() == "macro_invocation" {
                    let name = node
                        .field("macro")
                        .map(|n| n.text().into_owned())
                        .unwrap_or_default();
                    if !builtin_macro(&name) {
                        file.opaque = true;
                    }
                }
                if kind.as_ref() == "attribute_item" {
                    let text = node.text();
                    let head = text
                        .trim_start_matches('#')
                        .trim_start_matches('[')
                        .trim_start()
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or("");
                    if !matches!(
                        head,
                        "cfg"
                            | "cfg_attr"
                            | "path"
                            | "doc"
                            | "allow"
                            | "deny"
                            | "forbid"
                            | "warn"
                            | "repr"
                            | "inline"
                            | "cold"
                            | "must_use"
                            | "deprecated"
                            | "non_exhaustive"
                            | "macro_export"
                            | "macro_use"
                            | "test"
                            | "ignore"
                            | "should_panic"
                            | "no_mangle"
                            | "export_name"
                            | "link"
                            | "link_name"
                            | "automatically_derived"
                    ) {
                        file.opaque = true;
                    }
                    if head == "macro_use" {
                        file.opaque = true;
                    }
                }
                if kind.as_ref() == "use_declaration"
                    && node.dfs().any(|n| {
                        n.text().as_ref() == "*"
                            || n.kind().as_ref() == "identifier" && builtin_macro(&n.text())
                    })
                {
                    file.opaque = true;
                }
                if kind.as_ref() == "ERROR" {
                    file.opaque = true;
                }
                if kind.as_ref() == "inner_attribute_item" && node.text().contains("cfg_attr") {
                    file.opaque = true;
                }
                if kind.as_ref() == "attribute_item" && node.text().contains("cfg_attr") {
                    file.opaque = true;
                }
            }
            if file.opaque && file.opaque_dependency.is_none() {
                let anchor = node
                    .field("macro")
                    .or_else(|| node.field("name"))
                    .or_else(|| node.dfs().find(|n| n.kind().as_ref() == "identifier"))
                    .unwrap_or_else(|| node.clone());
                file.opaque_dependency =
                    Some(self.dependency(origin.dependency(anchor.range(), path)));
            }
            if kind.as_ref() != "mod_item" || node.field("body").is_some() {
                continue;
            }
            let Some(name) = node
                .field("name")
                .map(|n| n.text().trim_start_matches("r#").to_string())
            else {
                file.opaque = true;
                continue;
            };
            let mut clauses = BTreeSet::<usize>::new();
            for ancestor in std::iter::once(node.clone()).chain(node.ancestors()) {
                // File predicates were applied once on entry to this file.
                // Repeating them on every outgoing edge multiplies retained
                // state without adding another applicability relationship.
                if ancestor.node_id() == root.node_id() {
                    continue;
                }
                if let Some(ids) = conditions.get(&(ancestor.range().start, ancestor.range().end)) {
                    clauses.extend(ids);
                }
            }
            let mut attrs = attributes.get(&node.node_id()).cloned().unwrap_or_default();
            attrs.sort_by_key(|a| a.range().start);
            let mut explicit = Vec::new();
            let mut unresolved = false;
            for attribute in &attrs {
                let text = attribute.text();
                if !transparent_module_attribute(&text) {
                    unresolved = true;
                }
                let compact = text.split_whitespace().collect::<String>();
                if compact.starts_with("#[path=") {
                    if let Some(value) = attribute
                        .dfs()
                        .find(|n| {
                            matches!(n.kind().as_ref(), "string_literal" | "raw_string_literal")
                        })
                        .and_then(|n| literal(&n.text()))
                    {
                        explicit.push(value);
                    } else {
                        unresolved = true;
                    }
                } else if compact.starts_with("#[cfg_attr(") && compact.contains("path") {
                    unresolved = true;
                    explicit.extend(
                        attribute
                            .dfs()
                            .filter(|n| {
                                matches!(n.kind().as_ref(), "string_literal" | "raw_string_literal")
                            })
                            .filter_map(|n| literal(&n.text()))
                            .filter(|value| value.ends_with(".rs")),
                    );
                }
            }
            if explicit.len() > 1 {
                unresolved = true;
            }
            let inline: Vec<_> = node
                .ancestors()
                .filter(|n| n.kind().as_ref() == "mod_item")
                .collect();
            let physical_parent = parent(path);
            let stem = path
                .rsplit('/')
                .next()
                .unwrap_or(path)
                .trim_end_matches(".rs");
            let start = attrs
                .first()
                .map_or(node.range().start, |a| a.range().start);
            let range = if node.range().end - start <= 8192 {
                start..node.range().end
            } else {
                unresolved = true;
                node.range()
            };
            for from_owned in [false, true] {
                let mut ambiguous = unresolved;
                let mut base = physical_parent.to_string();
                let mut deferred = !from_owned && stem != "mod";
                if deferred {
                    base = join(&base, stem).unwrap_or_default();
                }
                for ancestor in inline.iter().rev() {
                    if attributes.get(&ancestor.node_id()).is_some_and(|attrs| {
                        attrs
                            .iter()
                            .any(|a| !transparent_module_attribute(&a.text()))
                    }) {
                        ambiguous = true;
                    }
                    let attr = attributes
                        .get(&ancestor.node_id())
                        .into_iter()
                        .flatten()
                        .find(|a| {
                            a.text()
                                .split_whitespace()
                                .collect::<String>()
                                .starts_with("#[path=")
                        });
                    if let Some(attr) = attr {
                        let value = attr
                            .dfs()
                            .find(|n| {
                                matches!(n.kind().as_ref(), "string_literal" | "raw_string_literal")
                            })
                            .and_then(|n| literal(&n.text()));
                        if let Some(value) = value {
                            let relative = if deferred {
                                physical_parent
                            } else {
                                base.as_str()
                            };
                            if let Some(next) = join(relative, &value) {
                                base = next;
                            } else {
                                ambiguous = true;
                            }
                        } else {
                            ambiguous = true;
                        }
                    } else if let Some(name) = ancestor.field("name") {
                        base =
                            join(&base, name.text().trim_start_matches("r#")).unwrap_or_default();
                    }
                    if attributes.get(&ancestor.node_id()).is_some_and(|attrs| {
                        attrs.iter().any(|a| {
                            let text = a.text();
                            text.contains("cfg_attr") && text.contains("path")
                        })
                    }) {
                        ambiguous = true;
                    }
                    deferred = false;
                }
                let mut candidates = Vec::new();
                if explicit.is_empty() || ambiguous {
                    for suffix in [format!("{name}.rs"), format!("{name}/mod.rs")] {
                        if let Some(target) =
                            join(&base, &suffix).filter(|p| self.files.contains_key(p))
                        {
                            candidates.push((target, false));
                        }
                    }
                    if candidates.len() > 1 {
                        ambiguous = true;
                    }
                }
                let explicit_base = if inline.is_empty() {
                    physical_parent
                } else {
                    base.as_str()
                };
                let mut missing = false;
                for value in &explicit {
                    if let Some(target) =
                        join(explicit_base, value).filter(|p| self.files.contains_key(p))
                    {
                        candidates.push((target, true));
                    } else {
                        missing = true;
                    }
                }
                candidates.sort();
                candidates.dedup();
                if (candidates.is_empty() || missing || ambiguous)
                    && !clauses
                        .iter()
                        .any(|id| self.clauses[*id].truth == Some(false))
                {
                    file.unresolved_modes
                        .entry(from_owned)
                        .or_insert_with(|| self.dependency(origin.dependency(range.clone(), path)));
                }
                for (target, target_owned) in candidates {
                    let dep = self.dependency(origin.dependency(range.clone(), &target));
                    let binding_dependencies = inline
                        .iter()
                        .flat_map(|ancestor| {
                            attributes.get(&ancestor.node_id()).into_iter().flatten()
                        })
                        .filter(|attr| {
                            attr.text().contains("path")
                                || !transparent_module_attribute(&attr.text())
                        })
                        .map(|attr| self.dependency(origin.dependency(attr.range(), &target)))
                        .collect();
                    file.edges.push(Edge {
                        target,
                        from_owned,
                        target_owned,
                        clauses: clauses.clone(),
                        dependency: dep,
                        unresolved: ambiguous,
                        binding_dependencies,
                    });
                }
            }
        }
        if file.opaque && file.opaque_dependency.is_none() {
            file.opaque_dependency = Some(self.dependency(origin.dependency(0..0, path)));
        }
        self.files.insert(path.into(), file);
    }

    fn manifest(
        &mut self,
        path: &str,
        source: &str,
        doc: &toml_edit::Document<&str>,
        paths: &[String],
        include_tests: bool,
    ) {
        let table = doc.as_table();
        let Some(package) = table.get("package").and_then(|item| item.as_table()) else {
            return;
        };
        let directory = parent(path);
        self.packages.insert(directory.into());
        let origin = Origin::new(path, source);
        let Some(package_name) = package.get("name") else {
            return;
        };
        let fallback = package_name.span().unwrap_or(0..0);
        let mut explicit_names = BTreeSet::new();
        for kind in ["lib", "bin", "test", "bench", "example"] {
            let targets: Vec<_> = if kind == "lib" {
                table
                    .get(kind)
                    .and_then(|i| i.as_table())
                    .into_iter()
                    .collect()
            } else {
                table
                    .get(kind)
                    .and_then(|i| i.as_array_of_tables())
                    .into_iter()
                    .flat_map(|a| a.iter())
                    .collect()
            };
            for target in targets {
                let name = target
                    .get("name")
                    .and_then(|i| i.as_str())
                    .or_else(|| package_name.as_str())
                    .unwrap_or("");
                if kind == "bin" {
                    explicit_names.insert(name.to_string());
                }
                let target_path = target
                    .get("path")
                    .and_then(|i| i.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        if kind == "lib" {
                            "src/lib.rs".into()
                        } else if kind == "bin" && Some(name) == package_name.as_str() {
                            "src/main.rs".into()
                        } else if kind == "bin" {
                            format!("src/bin/{name}.rs")
                        } else {
                            format!("{kind}s/{name}.rs")
                        }
                    });
                let Some(resolved) =
                    join(directory, &target_path).filter(|p| self.files.contains_key(p))
                else {
                    continue;
                };
                let range = target
                    .get("path")
                    .and_then(|i| i.span())
                    .unwrap_or_else(|| fallback.clone());
                let dep = self.dependency(origin.dependency(range, &resolved));
                let mut state = State::root(dep);
                let mut ids = BTreeSet::new();
                if !include_tests && matches!(kind, "test" | "bench" | "example") {
                    ids.insert(self.clause(
                        Some(false),
                        format!("{path}: non-production Cargo {kind} target"),
                        dep,
                    ));
                }
                if let Some(required) = target.get("required-features") {
                    let req_dep = self.dependency(origin.dependency(
                        required.span().unwrap_or_else(|| fallback.clone()),
                        &resolved,
                    ));
                    ids.insert(self.clause(
                        None,
                        format!("{path}: Cargo target required-features"),
                        req_dep,
                    ));
                }
                state = state.constrain(&ids, &self.clauses);
                self.roots.entry(resolved).or_default().merge(state);
            }
        }
        for file in paths {
            let relative = file
                .strip_prefix(directory)
                .unwrap_or(&file)
                .trim_start_matches('/');
            let automatic = relative == "src/lib.rs"
                && !table.contains_key("lib")
                && package.get("autolib").and_then(|i| i.as_bool()) != Some(false)
                || relative == "src/main.rs"
                    && package.get("autobins").and_then(|i| i.as_bool()) != Some(false)
                    && !explicit_names.contains(package_name.as_str().unwrap_or(""))
                || relative.strip_prefix("src/bin/").is_some_and(|rest| {
                    let name = rest
                        .strip_suffix("/main.rs")
                        .or_else(|| rest.strip_suffix(".rs"));
                    package.get("autobins").and_then(|i| i.as_bool()) != Some(false)
                        && name.is_some_and(|name| {
                            !name.contains('/') && !explicit_names.contains(name)
                        })
                })
                || relative
                    == package
                        .get("build")
                        .and_then(|i| i.as_str())
                        .unwrap_or("build.rs")
                    && package.get("build").and_then(|i| i.as_bool()) != Some(false);
            if automatic {
                let dep = self.dependency(origin.dependency(fallback.clone(), &file));
                self.roots
                    .entry(file.clone())
                    .or_default()
                    .merge(State::root(dep));
            }
        }
    }

    fn finish(mut self) -> RustModules {
        type Key = (String, bool);
        let root_paths: BTreeSet<_> = self.roots.keys().cloned().collect();
        let mut states: BTreeMap<Key, State> = std::mem::take(&mut self.roots)
            .into_iter()
            .map(|(path, state)| ((path, true), state))
            .collect();
        let mut reachable: BTreeSet<Key> = states.keys().cloned().collect();
        let mut walk: VecDeque<Key> = reachable.iter().cloned().collect();
        while let Some((path, owned)) = walk.pop_front() {
            for edge in self.files[&path]
                .edges
                .iter()
                .filter(|e| e.from_owned == owned)
            {
                let key = (edge.target.clone(), edge.target_owned);
                if reachable.insert(key.clone()) {
                    walk.push_back(key);
                }
            }
        }
        let mut incoming: BTreeMap<Key, usize> =
            reachable.iter().map(|key| (key.clone(), 0)).collect();
        let mut incoming_dependencies = BTreeMap::<String, BTreeSet<usize>>::new();
        let mut connected = BTreeSet::new();
        for (path, file) in &self.files {
            for edge in &file.edges {
                connected.insert(path.clone());
                connected.insert(edge.target.clone());
                incoming_dependencies
                    .entry(edge.target.clone())
                    .or_default()
                    .insert(edge.dependency);
                if reachable.contains(&(path.clone(), edge.from_owned)) {
                    *incoming
                        .get_mut(&(edge.target.clone(), edge.target_owned))
                        .unwrap() += 1;
                }
            }
        }
        let mut queue: VecDeque<Key> = incoming
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(key, _)| key.clone())
            .collect();
        let mut done = BTreeMap::<Key, State>::new();
        while let Some((path, owned)) = queue.pop_front() {
            let key = (path.clone(), owned);
            let file = &self.files[&path];
            let state = states
                .remove(&key)
                .unwrap_or_default()
                .constrain(&file.inner, &self.clauses);
            if (file.opaque || file.unresolved_modes.contains_key(&owned))
                && (!state.terms.is_empty() || state.unresolved)
            {
                if let Some(package) = self.owners.get(&path) {
                    if let Some(dependency) = file
                        .opaque_dependency
                        .filter(|_| file.opaque)
                        .or_else(|| file.unresolved_modes.get(&owned).copied())
                    {
                        self.open_packages
                            .entry(package.clone())
                            .or_insert(dependency);
                    }
                }
            }
            for edge in file.edges.iter().filter(|e| e.from_owned == owned) {
                let mut next = state.clone().constrain(&edge.clauses, &self.clauses);
                next.dependencies.insert(edge.dependency);
                next.dependencies.extend(&edge.binding_dependencies);
                if edge.unresolved && (!next.terms.is_empty() || next.unresolved) {
                    next.unresolved = true;
                    next.terms.clear();
                }
                let target = (edge.target.clone(), edge.target_owned);
                states.entry(target.clone()).or_default().merge(next);
                let degree = incoming.get_mut(&target).unwrap();
                *degree -= 1;
                if *degree == 0 {
                    queue.push_back(target);
                }
            }
            done.insert(key, state);
        }
        let mut result = RustModules::default();
        for (path, file) in &self.files {
            let open = self
                .owners
                .get(path)
                .and_then(|owner| self.open_packages.get(owner));
            if !connected.contains(path)
                && !root_paths.contains(path)
                && open.is_none()
                && !file
                    .inner
                    .iter()
                    .any(|id| self.clauses[*id].truth == Some(false))
            {
                continue;
            }
            let mut state = State::default();
            let mut cycle = false;
            for owned in [false, true] {
                let key = (path.clone(), owned);
                if let Some(value) = done.remove(&key) {
                    state.merge(value);
                } else if reachable.contains(&key) {
                    cycle = true;
                }
            }
            if cycle || !state.seen {
                state.seen = true;
                state.unresolved = true;
                if cycle {
                    state.terms.clear();
                }
                if let Some(deps) = incoming_dependencies.get(path) {
                    state.dependencies.extend(deps);
                }
                if !cycle {
                    state = state.constrain(&file.inner, &self.clauses);
                }
            }
            if let Some(dependency) = open {
                state.unresolved = true;
                state.dependencies.insert(*dependency);
            }
            state.bound();
            let availability = state.availability(&self.clauses);
            if availability.state == AvailabilityState::Always {
                continue;
            }
            let mut dependencies: Vec<_> = state
                .dependencies
                .iter()
                .map(|id| self.dependencies[*id].clone())
                .collect();
            dependencies.sort_by(|a, b| {
                (
                    &a.declaration.location.path,
                    a.declaration.location.start.byte_offset,
                    &a.target_path,
                )
                    .cmp(&(
                        &b.declaration.location.path,
                        b.declaration.location.start.byte_offset,
                        &b.target_path,
                    ))
            });
            dependencies.dedup();
            result.files.insert(
                path.clone(),
                FileConfiguration {
                    availability,
                    dependencies,
                },
            );
        }
        result
    }
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn transparent_module_attribute(text: &str) -> bool {
    let head = text
        .trim_start_matches('#')
        .trim_start_matches('[')
        .trim_start()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or("");
    matches!(
        head,
        "cfg"
            | "path"
            | "doc"
            | "allow"
            | "deny"
            | "forbid"
            | "warn"
            | "deprecated"
            | "macro_use"
            | "no_implicit_prelude"
    )
}

fn nearest_package(path: &str, packages: &BTreeSet<String>) -> Option<String> {
    let mut directory = parent(path);
    loop {
        if packages.contains(directory) {
            return Some(directory.into());
        }
        if directory.is_empty() {
            return None;
        }
        directory = parent(directory);
    }
}

fn join(base: &str, relative: &str) -> Option<String> {
    if relative.starts_with(['/', '\\']) || relative.contains(':') {
        return None;
    }
    let combined = format!("{base}/{relative}").replace('\\', "/");
    let mut parts = Vec::new();
    for part in combined.split('/') {
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

pub(crate) fn literal(value: &str) -> Option<String> {
    if let Some(inner) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return (!inner.contains('\\')).then(|| inner.into());
    }
    let raw = value.strip_prefix('r')?;
    let quote = raw.find('"')?;
    let hashes = &raw[..quote];
    hashes.chars().all(|c| c == '#').then_some(())?;
    raw.get(quote + 1..)?
        .strip_suffix(&format!("\"{hashes}"))
        .map(str::to_string)
}

fn builtin_macro(name: &str) -> bool {
    matches!(
        name,
        "assert"
            | "assert_eq"
            | "assert_ne"
            | "debug_assert"
            | "debug_assert_eq"
            | "debug_assert_ne"
            | "println"
            | "print"
            | "eprintln"
            | "eprint"
            | "format"
            | "format_args"
            | "panic"
            | "todo"
            | "unimplemented"
            | "unreachable"
            | "vec"
            | "matches"
            | "cfg"
            | "stringify"
            | "concat"
            | "env"
            | "option_env"
            | "include_str"
            | "include_bytes"
            | "line"
            | "file"
            | "column"
            | "module_path"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_route_conjunctions_remain_bounded_without_claiming_unconditional_availability() {
        let clauses: Vec<_> = (0..4096)
            .map(|i| Clause {
                truth: None,
                text: format!("feature=\"f{i}\""),
                dependency: i,
            })
            .collect();
        let mut state = State::root(4096);
        for id in 0..clauses.len() {
            state = state.constrain(&[id].into(), &clauses);
            assert!(state.terms.iter().all(|term| term.len() <= 64));
            assert!(state.dependencies.len() <= 64);
        }
        let availability = state.availability(&clauses);
        assert_eq!(availability.state, AvailabilityState::Unknown);
        assert!(
            availability
                .condition
                .unwrap()
                .contains("detail limit reached")
        );
        state.merge(State::root(4097));
        assert_eq!(
            state.availability(&clauses).state,
            AvailabilityState::Always
        );
    }
}
