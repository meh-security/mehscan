use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::{AstGrep, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capture, Language};

use super::{RubyNode, capture};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FrameworkClass {
    Controller,
    Record,
}

#[derive(Default)]
pub(in crate::code) struct RubyProject {
    // A repeated declaration or assignment makes the constant ambiguous.
    classes: BTreeMap<String, Option<Class>>,
    names: BTreeSet<String>,
}

struct Class {
    base: Capture,
    overrides: BTreeSet<String>,
}

impl RubyProject {
    pub(in crate::code) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let mut project = Self::default();
        for (path, language, source) in sources {
            if language != Language::Ruby {
                continue;
            }
            let Ok(document) = StrDoc::try_new(source, SupportLang::Ruby) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            if crate::code::has_unsupported_syntax_errors(&root, language) {
                continue;
            }
            for node in root.dfs() {
                let kind = node.kind();
                let field = match kind.as_ref() {
                    "module" | "class" => "name",
                    "assignment" | "operator_assignment" => "left",
                    _ => continue,
                };
                let Some(name) = node
                    .field(field)
                    .and_then(|name| declared_name(&node, &name))
                else {
                    continue;
                };
                project.names.insert(name.clone());
                if kind == "module" {
                    project.classes.insert(name, None);
                    continue;
                }
                let class = (kind == "class")
                    .then(|| {
                        let parent = node.field("superclass")?;
                        let base = parent
                            .children()
                            .find_map(|part| constant(&part).map(|_| part))?;
                        let mut overrides = BTreeSet::new();
                        if let Some(body) = node.field("body") {
                            for method in body.dfs().filter(|part| {
                                matches!(
                                    part.kind().as_ref(),
                                    "method" | "singleton_method" | "alias"
                                )
                            }) {
                                if enclosing_namespace(&method).as_deref() == Some(name.as_str())
                                    && let Some(method_name) = method.field("name")
                                {
                                    overrides.insert(method_name.text().into_owned());
                                }
                            }
                        }
                        Some(Class {
                            base: capture(path, &base),
                            overrides,
                        })
                    })
                    .flatten();
                project
                    .classes
                    .entry(name)
                    .and_modify(|entry| *entry = None)
                    .or_insert(class);
            }
        }
        project
    }

    pub(super) fn witness(
        &self,
        name: &str,
        family: FrameworkClass,
        method: &str,
    ) -> Option<&Capture> {
        let mut current = name.to_string();
        for _ in 0..32 {
            let class = self.classes.get(&current)?.as_ref()?;
            if class.overrides.contains(method) {
                return None;
            }
            let scope = current.rsplit_once("::").map(|(owner, _)| owner);
            let base = self.resolve(&normalize(&class.base.text), scope);
            let root = base.split("::").next()?;
            let canonical = match family {
                FrameworkClass::Controller => {
                    matches!(
                        base.as_str(),
                        "ActionController::Base" | "ActionController::API"
                    )
                }
                FrameworkClass::Record => base == "ActiveRecord::Base",
            };
            if canonical && !self.names.contains(root) && !self.names.contains(&base) {
                return Some(&class.base);
            }
            current = base;
        }
        None
    }

    pub(super) fn resolve(&self, name: &str, mut scope: Option<&str>) -> String {
        if let Some(absolute) = name.strip_prefix("::") {
            return absolute.to_string();
        }
        let first = name.split("::").next().unwrap_or(name);
        while let Some(owner) = scope {
            if self.names.contains(&format!("{owner}::{first}")) {
                return format!("{owner}::{name}");
            }
            scope = owner.rsplit_once("::").map(|(parent, _)| parent);
        }
        name.to_string()
    }

    pub(super) fn active_record_base(&self) -> Option<&Capture> {
        if self.defines("ActiveRecord") || self.defines("ActiveRecord::Base") {
            return None;
        }
        self.classes.iter().find_map(|(name, class)| {
            let base = &class.as_ref()?.base;
            let scope = name.rsplit_once("::").map(|(owner, _)| owner);
            (self.resolve(&normalize(&base.text), scope) == "ActiveRecord::Base").then_some(base)
        })
    }

    pub(super) fn defines(&self, name: &str) -> bool {
        self.names.contains(name)
    }
}

pub(super) fn enclosing_namespace(node: &RubyNode<'_>) -> Option<String> {
    let owner = node
        .ancestors()
        .find(|part| matches!(part.kind().as_ref(), "class" | "module"))?;
    declared_name(&owner, &owner.field("name")?)
}

pub(super) fn constant(node: &RubyNode<'_>) -> Option<String> {
    match node.kind().as_ref() {
        "constant" => Some(node.text().into_owned()),
        "scope_resolution"
            if node
                .field("name")
                .is_some_and(|name| name.kind() == "constant")
                && node
                    .field("scope")
                    .is_none_or(|scope| constant(&scope).is_some()) =>
        {
            Some(normalize(node.text().as_ref()))
        }
        _ => None,
    }
}

fn declared_name(node: &RubyNode<'_>, name: &RubyNode<'_>) -> Option<String> {
    let name = constant(name)?;
    if let Some(absolute) = name.strip_prefix("::") {
        return Some(absolute.to_string());
    }
    Some(match enclosing_namespace(node) {
        Some(owner) => format!("{owner}::{name}"),
        None => name,
    })
}

fn normalize(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
