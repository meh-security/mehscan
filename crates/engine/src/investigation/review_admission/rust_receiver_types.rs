//! Bounded source-owned declaration witnesses, not trait dispatch or value flow.
use super::*;
use rust_module_bindings::{Located, Project};
use rust_shared_state::AstNode as N;

enum Type<'a> {
    Vector,
    Usize,
    NonNull,
    RawPointer(Located<'a>),
    Record(Located<'a>),
}

struct Witness<'a> {
    ty: Type<'a>,
    support: Vec<Capture>,
}

fn named<'a>(node: &N<'a>) -> Vec<N<'a>> {
    node.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
        .collect()
}

fn pattern_shadows(scope: &N<'_>, value: &N<'_>, name: &str) -> bool {
    let binds = |node: &N<'_>| {
        node.field("pattern")
            .is_some_and(|p| p.dfs().any(|n| n.text() == name))
    };
    let contains = |node: &N<'_>| {
        node.range().start <= value.range().start && value.range().end <= node.range().end
    };
    match scope.kind().as_ref() {
        "for_expression" => scope.field("body").is_some_and(|b| contains(&b)) && binds(scope),
        "match_arm" => binds(scope),
        "if_expression" | "while_expression" => {
            // Let-condition bindings can shadow in the consequence/body and
            // condition operands, never in the else branch.
            let branch = scope.field("consequence").or_else(|| scope.field("body"));
            scope.field("condition").is_some_and(|c| {
                (contains(&c) || branch.is_some_and(|b| contains(&b)))
                    && c.dfs()
                        .any(|n| n.kind().as_ref() == "let_condition" && binds(&n))
            })
        }
        _ => false,
    }
}

pub(super) fn local_binding<'a>(value: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    if value.kind().as_ref() != "identifier" {
        return None;
    }
    let name = value.text();
    for scope in value
        .ancestors()
        .take_while(|n| n.range() != function.range())
    {
        if pattern_shadows(&scope, value, &name) {
            return None;
        }
        if scope.kind().as_ref() != "block" {
            continue;
        }
        let binding = scope
            .children()
            .filter(|n| {
                n.kind().as_ref() == "let_declaration"
                    && n.range().end <= value.range().start
                    && n.field("pattern").is_some_and(|p| {
                        p.dfs()
                            .any(|n| n.kind().as_ref() == "identifier" && n.text() == name)
                    })
            })
            .last();
        if let Some(binding) = binding {
            if binding.field("pattern")?.kind().as_ref() != "identifier"
                || function.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "assignment_expression" | "compound_assignment_expr"
                    ) && n.range().start >= binding.range().end
                        && n.range().start < value.range().start
                        && n.field("left").is_some_and(|n| n.text() == name)
                })
            {
                return None;
            }
            return Some(binding);
        }
    }
    function.field("parameters")?.children().find(|n| {
        n.kind().as_ref() == "parameter" && n.field("pattern").is_some_and(|n| n.text() == name)
    })
}

struct Resolver<'a, 's> {
    project: &'s Project<'a>,
    site: Located<'a>,
}

impl<'a> Resolver<'a, '_> {
    fn at(&self, site: Located<'a>) -> Self {
        Self {
            project: self.project,
            site,
        }
    }

    fn capture(&self, node: &N<'a>) -> Capture {
        rust_dependencies::capture(self.site.file, node)
    }

    fn configured(&self, node: &N<'a>) -> bool {
        self.project.selected(&self.site.with_node(node.clone()))
    }

    fn selected(&self, node: &N<'a>) -> bool {
        self.configured(node)
            && node.range().len() <= 8192
            && !node.dfs().any(|n| n.is_error() || n.is_missing())
    }

    fn route(&self, target: &Located<'a>, support: &mut Vec<Capture>) {
        if self.site.file.path != target.file.path {
            support.extend(self.project.support(&self.site));
            support.extend(self.project.support(target));
        }
    }

    // No fallback to same-spelled items in other files or targets. Scope changes
    // must use a source-owned module edge, an explicit alias, or a logical parent.
    fn item(&self, site: &N<'a>, text: &str, depth: usize) -> Option<(Located<'a>, Vec<Capture>)> {
        if depth > 24 {
            return None;
        }
        let text = rust_shared_state::compact(text);
        let (head, rest) = text.split_once("::").unwrap_or((&text, ""));
        if site
            .ancestors()
            .filter_map(|n| n.field("type_parameters"))
            .any(|p| {
                p.children()
                    .any(|n| n.field("name").is_some_and(|n| n.text() == head))
            })
        {
            return None;
        }
        if matches!(head, "crate" | "self" | "super") {
            let place = self.site.with_node(site.clone());
            let mut scope = match head {
                "crate" => self.project.crate_scope(&place)?,
                "self" => self.project.current_scope(&place)?,
                _ => self.project.parent_scope(&place)?,
            };
            let mut rest = rest;
            if head == "super" {
                while let Some(tail) = rest.strip_prefix("super::") {
                    scope = self.project.parent_scope(&scope)?;
                    rest = tail;
                }
            }
            let (item, mut support) =
                self.at(scope.clone())
                    .in_scope(&scope.node, rest, depth + 1)?;
            self.route(&scope, &mut support);
            return Some((item, support));
        }
        for scope in site.ancestors().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "block" | "declaration_list" | "source_file"
            )
        }) {
            if let Some(result) = self.in_scope(&scope, &text, depth + 1) {
                return Some(result);
            }
            // A nearer unresolved declaration still shadows outer declarations.
            if self.binds(&scope, head)
                || scope.kind().as_ref() == "declaration_list"
                    && scope
                        .parent()
                        .is_some_and(|p| p.kind().as_ref() == "mod_item")
            {
                break;
            }
        }
        None
    }

    fn binds(&self, scope: &N<'a>, name: &str) -> bool {
        scope.children().any(|n| {
            self.configured(&n)
                && (n.field("name").is_some_and(|n| n.text() == name)
                    || n.kind().as_ref() == "use_declaration" && {
                        if n.range().len() > 8192 {
                            return true;
                        }
                        let mut imports = Vec::new();
                        rust_shared_state::imports(&n, "", false, &mut imports);
                        imports
                            .iter()
                            .any(|(alias, _, _)| alias == name || alias == "*")
                    })
        })
    }

    fn in_scope(
        &self,
        scope: &N<'a>,
        text: &str,
        depth: usize,
    ) -> Option<(Located<'a>, Vec<Capture>)> {
        if depth > 24 || text.is_empty() {
            return None;
        }
        let (head, rest) = text.split_once("::").unwrap_or((text, ""));
        let mut choices = Vec::new();
        for node in scope.children() {
            if node.field("name").is_some_and(|n| n.text() == head) && self.configured(&node) {
                choices.push((node, None));
            } else if node.kind().as_ref() == "use_declaration" && self.configured(&node) {
                if !self.selected(&node) {
                    return None;
                }
                let mut imports = Vec::new();
                rust_shared_state::imports(&node, "", false, &mut imports);
                for (alias, target, _) in imports {
                    if alias == head {
                        choices.push((node.clone(), Some(target)));
                    }
                }
            }
        }
        if choices.len() != 1 {
            return None;
        }
        let (node, target) = choices.pop()?;
        if let Some(target) = target {
            let target = if rest.is_empty() {
                target
            } else {
                format!("{target}::{rest}")
            };
            if rust_raw_memory::canonical(&self.project.root(&self.site)?, &node, &target)
                .is_some_and(|s| matches!(s.as_str(), "std::vec::Vec" | "alloc::vec::Vec"))
            {
                return Some((self.site.with_node(node.clone()), vec![self.capture(&node)]));
            }
            let (item, mut support) = self.item(&node, &target, depth + 1)?;
            support.push(self.capture(&node));
            return Some((item, support));
        }
        if rest.is_empty() {
            return self
                .selected(&node)
                .then(|| (self.site.with_node(node), Vec::new()));
        }
        if node.kind().as_ref() != "mod_item" {
            return None;
        }
        let child = self
            .project
            .child_scope(&self.site.with_node(scope.clone()), &node)?;
        let (item, mut support) = self
            .at(child.clone())
            .in_scope(&child.node, rest, depth + 1)?;
        self.route(&child, &mut support);
        if self.site.file.path == child.file.path {
            support.push(self.capture(&node.field("name")?));
        }
        Some((item, support))
    }

    fn declared(&self, node: &N<'a>, depth: usize) -> Option<Witness<'a>> {
        if depth > 12 || !self.selected(node) {
            return None;
        }
        if matches!(node.kind().as_ref(), "reference_type" | "generic_type") {
            let mut result = self.declared(&node.field("type")?, depth + 1)?;
            result.support.push(self.capture(node));
            return Some(result);
        }
        if node.kind().as_ref() == "pointer_type" {
            return Some(Witness {
                ty: Type::RawPointer(self.site.with_node(node.field("type")?)),
                support: vec![self.capture(node)],
            });
        }
        if node.kind().as_ref() == "primitive_type" && node.text() == "usize" {
            return Some(Witness {
                ty: Type::Usize,
                support: vec![self.capture(node)],
            });
        }
        if node.text() == "Self" {
            let implementation = node
                .ancestors()
                .find(|n| n.kind().as_ref() == "impl_item")?;
            if implementation.field("trait").is_some() {
                return None;
            }
            return self.declared(&implementation.field("type")?, depth + 1);
        }
        let library_type =
            match rust_raw_memory::canonical(&self.project.root(&self.site)?, node, &node.text())
                .as_deref()
            {
                Some("std::vec::Vec" | "alloc::vec::Vec") => Some(Type::Vector),
                Some("std::ptr::NonNull" | "core::ptr::NonNull") => Some(Type::NonNull),
                _ => None,
            };
        if let Some(ty) = library_type {
            let mut support = vec![self.capture(node)];
            if let Some((_, Some(import))) = crate::code::rust_http::canonical(
                &self.project.root(&self.site)?,
                node,
                &node.text(),
            ) {
                if !self.selected(&import) {
                    return None;
                }
                support.push(self.capture(&import));
            }
            return Some(Witness { ty, support });
        }
        let (item, mut support) = self.item(node, &node.text(), depth + 1)?;
        support.push(item.capture());
        let mut result = match item.node.kind().as_ref() {
            "struct_item" => Witness {
                ty: Type::Record(item),
                support: Vec::new(),
            },
            "use_declaration" => Witness {
                ty: Type::Vector,
                support: Vec::new(),
            },
            "type_item" => self
                .at(item.clone())
                .declared(&item.node.field("type")?, depth + 1)?,
            _ => return None,
        };
        result.support.extend(support);
        Some(result)
    }

    fn expression(&self, value: &N<'a>, function: &N<'a>, depth: usize) -> Option<Witness<'a>> {
        if depth > 12 || !self.selected(value) {
            return None;
        }
        if matches!(
            value.kind().as_ref(),
            "reference_expression" | "parenthesized_expression"
        ) {
            return self.expression(
                &value
                    .field("value")
                    .or_else(|| named(value).into_iter().next())?,
                function,
                depth + 1,
            );
        }
        if value.kind().as_ref() == "unary_expression"
            && value.children().next().is_some_and(|op| op.text() == "*")
        {
            let pointer =
                self.expression(&named(value).into_iter().next()?, function, depth + 1)?;
            let Type::RawPointer(pointee) = pointer.ty else {
                return None;
            };
            let mut result = self
                .at(pointee.clone())
                .declared(&pointee.node, depth + 1)?;
            result.support.extend(pointer.support);
            return Some(result);
        }
        if value.kind().as_ref() == "field_expression" {
            let mut owner = self.expression(&value.field("value")?, function, depth + 1)?;
            let Type::Record(record) = owner.ty else {
                return None;
            };
            let field = value.field("field")?;
            let owner_resolver = self.at(record.clone());
            let fields = record
                .node
                .field("body")?
                .children()
                .filter(|n| {
                    owner_resolver.configured(n)
                        && n.field("name").is_some_and(|n| n.text() == field.text())
                })
                .collect::<Vec<_>>();
            if fields.len() != 1 || !owner_resolver.selected(&fields[0]) {
                return None;
            }
            let mut result = owner_resolver.declared(&fields[0].field("type")?, depth + 1)?;
            owner.support.push(owner_resolver.capture(&fields[0]));
            result.support.extend(owner.support);
            return Some(result);
        }
        if value.kind().as_ref() == "call_expression" {
            if rust_raw_memory::api(&self.project.root(&self.site)?, value).is_some_and(|s| {
                matches!(
                    s.as_str(),
                    "std::vec::Vec::new"
                        | "alloc::vec::Vec::new"
                        | "std::vec::Vec::with_capacity"
                        | "alloc::vec::Vec::with_capacity"
                )
            }) {
                let mut support = vec![self.capture(value)];
                if let Some((_, Some(import))) = crate::code::rust_raw_slice::function_identity(
                    &self.project.root(&self.site)?,
                    value,
                ) {
                    if !self.selected(&import) {
                        return None;
                    }
                    support.push(self.capture(&import));
                }
                return Some(Witness {
                    ty: Type::Vector,
                    support,
                });
            }
            let mut callee = value.field("function")?;
            if callee.kind().as_ref() == "generic_function" {
                callee = callee.field("function")?;
            }
            if !matches!(callee.kind().as_ref(), "identifier" | "scoped_identifier") {
                return None;
            }
            if callee.kind().as_ref() == "identifier" && self.value_shadow(&callee, function) {
                return None;
            }
            let (item, support) = self.item(&callee, &callee.text(), depth + 1)?;
            if item.node.kind().as_ref() != "function_item"
                || item.node.children().any(|n| {
                    n.kind().as_ref() == "function_modifiers" && n.text().contains("async")
                })
            {
                return None;
            }
            let mut result = self
                .at(item.clone())
                .declared(&item.node.field("return_type")?, depth + 1)?;
            result.support.extend(support);
            result.support.push(item.capture());
            return Some(result);
        }
        if value.kind().as_ref() == "self" {
            let implementation = function
                .ancestors()
                .find(|n| n.kind().as_ref() == "impl_item")?;
            if implementation.field("trait").is_some() {
                return None;
            }
            return self.declared(&implementation.field("type")?, depth + 1);
        }
        let binding = local_binding(value, function)?;
        let mut result = if let Some(ty) = binding.field("type") {
            self.declared(&ty, depth + 1)?
        } else {
            self.expression(&binding.field("value")?, function, depth + 1)?
        };
        result.support.push(self.capture(&binding));
        Some(result)
    }

    fn value_shadow(&self, value: &N<'a>, function: &N<'a>) -> bool {
        let name = value.text();
        value
            .ancestors()
            .take_while(|n| n.range() != function.range())
            .any(|scope| {
                pattern_shadows(&scope, value, &name)
                    || scope.kind().as_ref() == "block"
                        && scope.children().any(|n| {
                            n.kind().as_ref() == "let_declaration"
                                && n.range().end <= value.range().start
                                && n.field("pattern")
                                    .is_some_and(|p| p.dfs().any(|n| n.text() == name))
                        })
            })
            || function.field("parameters").is_some_and(|p| {
                p.children().any(|n| {
                    n.field("pattern")
                        .is_some_and(|p| p.dfs().any(|n| n.text() == name))
                })
            })
    }
}

pub(super) fn vector_support<'a>(
    project: &Project<'a>,
    value: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
) -> Option<Vec<Capture>> {
    type_support(project, value, function, file, |ty| {
        matches!(ty, Type::Vector)
    })
}

pub(super) fn extent_field_support<'a>(
    project: &Project<'a>,
    value: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
) -> Option<Vec<Capture>> {
    type_support(project, value, function, file, |ty| {
        matches!(ty, Type::Usize)
    })
}

pub(super) fn pointer_field_support<'a>(
    project: &Project<'a>,
    value: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    nonnull: bool,
) -> Option<Vec<Capture>> {
    type_support(project, value, function, file, |ty| match ty {
        Type::NonNull => nonnull,
        Type::RawPointer(_) => !nonnull,
        _ => false,
    })
}

fn type_support<'a>(
    project: &Project<'a>,
    value: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    accepts: impl FnOnce(&Type<'a>) -> bool,
) -> Option<Vec<Capture>> {
    let resolver = Resolver {
        project,
        site: project.locate(file, value.clone()),
    };
    let result = resolver.expression(value, function, 0)?;
    if !accepts(&result.ty) {
        return None;
    }
    let mut support = result.support;
    support.sort_by(|a, b| {
        (
            &a.location.path,
            a.location.start.byte_offset,
            a.location.end.byte_offset,
        )
            .cmp(&(
                &b.location.path,
                b.location.start.byte_offset,
                b.location.end.byte_offset,
            ))
    });
    support.dedup_by(|a, b| a.location == b.location);
    if support.len() > 24 || support.iter().map(|c| c.text.len()).sum::<usize>() > 32768 {
        return None;
    }
    Some(support)
}
