//! Bounded typed ownership for HTTP clients; method spelling is not a type.
use std::collections::BTreeMap;

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::Capture;

use super::rust_context::{expand_use, is_identifier};

type N<'a> = Node<'a, StrDoc<SupportLang>>;
type Support = BTreeMap<String, Capture>;

#[derive(Default)]
pub(super) struct RustHttpProjectContext {
    owners: BTreeMap<String, usize>,
    methods: BTreeMap<(String, String), usize>,
    fields: BTreeMap<(String, String), Vec<Support>>,
    accessors: BTreeMap<(String, String), Vec<(String, Support)>>,
}

impl RustHttpProjectContext {
    pub(super) fn collect(&mut self, path: &str, root: &N<'_>) {
        for owner in root.dfs().filter(|n| n.kind().as_ref() == "struct_item") {
            let Some(name) = owner.field("name") else {
                continue;
            };
            let key = local_key(path, &owner, name.text().as_ref());
            *self.owners.entry(key.clone()).or_default() += 1;
            if owner.field("type_parameters").is_some() {
                continue;
            }
            for field in owner
                .field("body")
                .into_iter()
                .flat_map(|b| b.children().collect::<Vec<_>>())
            {
                let (Some(name), Some(ty)) = (field.field("name"), field.field("type")) else {
                    continue;
                };
                if let Some(mut support) = client_support(path, root, &ty) {
                    support.insert("http_client_field_type".into(), capture(path, &ty));
                    self.fields
                        .entry((key.clone(), name.text().into_owned()))
                        .or_default()
                        .push(support);
                }
            }
        }
        for owner in root.dfs().filter(|n| n.kind().as_ref() == "impl_item") {
            if owner.field("trait").is_some() || owner.field("type_parameters").is_some() {
                continue;
            }
            let Some(ty) = owner.field("type") else {
                continue;
            };
            let Some((canonical, _)) = canonical(root, &ty, ty.text().as_ref()) else {
                continue;
            };
            let key = local_key(path, &owner, &canonical);
            for function in owner
                .field("body")
                .into_iter()
                .flat_map(|b| b.children().collect::<Vec<_>>())
            {
                if function.kind().as_ref() != "function_item" {
                    continue;
                }
                if let Some(name) = function.field("name") {
                    *self
                        .methods
                        .entry((key.clone(), name.text().into_owned()))
                        .or_default() += 1;
                }
                if function.range().len() > 4096 {
                    continue;
                }
                let (Some(name), Some(ret), Some(body), Some(parameters)) = (
                    function.field("name"),
                    function.field("return_type"),
                    function.field("body"),
                    function.field("parameters"),
                ) else {
                    continue;
                };
                if compact(parameters.text().as_ref()) != "(&self)" {
                    continue;
                }
                let Some(mut support) = client_support(path, root, &ret) else {
                    continue;
                };
                let mut expressions = body.children().filter(|n| {
                    n.is_named() && !matches!(n.kind().as_ref(), "line_comment" | "block_comment")
                });
                let Some(expression) = expressions
                    .next()
                    .filter(|n| n.kind().as_ref() == "reference_expression")
                else {
                    continue;
                };
                if expressions.next().is_some() {
                    continue;
                }
                let Some(value) = expression
                    .field("value")
                    .filter(|n| n.kind().as_ref() == "field_expression")
                else {
                    continue;
                };
                if value
                    .field("value")
                    .is_none_or(|n| n.text().as_ref() != "self")
                {
                    continue;
                }
                let Some(field) = value.field("field") else {
                    continue;
                };
                support.insert("http_client_accessor".into(), capture(path, &function));
                self.accessors
                    .entry((key.clone(), name.text().into_owned()))
                    .or_default()
                    .push((field.text().into_owned(), support));
            }
        }
    }

    pub(super) fn request_support<'a>(
        &self,
        path: &str,
        root: &N<'a>,
        matched: &N<'a>,
    ) -> Option<Support> {
        let call = std::iter::once(matched.clone())
            .chain(matched.ancestors())
            .find(|n| n.kind().as_ref() == "call_expression")?;
        let function = call.field("function")?;
        let method = function.field("field")?;
        if !matches!(
            method.text().as_ref(),
            "get" | "post" | "put" | "patch" | "delete" | "head" | "request"
        ) {
            return None;
        }
        let receiver = function.field("value")?;
        self.receiver(path, root, &call, &receiver)
    }

    // At most one field/accessor edge is followed, with exact crate/module keys.
    fn receiver<'a>(
        &self,
        path: &str,
        root: &N<'a>,
        site: &N<'a>,
        receiver: &N<'a>,
    ) -> Option<Support> {
        if receiver.kind().as_ref() == "field_expression" {
            let base = receiver.field("value")?;
            let field = receiver.field("field")?;
            let (owner, mut support) = owner_binding(path, root, site, &base)?;
            if self.owners.get(&owner) != Some(&1) {
                return None;
            }
            let [field_support] = self
                .fields
                .get(&(owner, field.text().into_owned()))?
                .as_slice()
            else {
                return None;
            };
            support.extend(field_support.clone());
            return Some(support);
        }
        if receiver.kind().as_ref() == "call_expression" {
            if receiver
                .field("arguments")?
                .children()
                .any(|n| n.is_named())
            {
                return None;
            }
            let function = receiver.field("function")?;
            let base = function.field("value")?;
            let method = function.field("field")?;
            let (owner, mut support) = owner_binding(path, root, site, &base)?;
            if self.owners.get(&owner) != Some(&1)
                || self
                    .methods
                    .get(&(owner.clone(), method.text().into_owned()))
                    != Some(&1)
            {
                return None;
            }
            let [(field, accessor)] = self
                .accessors
                .get(&(owner.clone(), method.text().into_owned()))?
                .as_slice()
            else {
                return None;
            };
            let [field_support] = self.fields.get(&(owner, field.clone()))?.as_slice() else {
                return None;
            };
            support.extend(field_support.clone());
            support.extend(accessor.clone());
            return Some(support);
        }
        let (_, ty) = parameter(path, root, site, receiver)?;
        client_support(path, root, &ty)
    }
}

fn owner_binding<'a>(
    path: &str,
    root: &N<'a>,
    site: &N<'a>,
    receiver: &N<'a>,
) -> Option<(String, Support)> {
    let (owner, ty) = if receiver.text().as_ref() == "self" {
        let function = site
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_item")?;
        if !function
            .field("parameters")?
            .children()
            .any(|n| n.kind().as_ref() == "self_parameter")
        {
            return None;
        }
        let owner = function
            .ancestors()
            .find(|n| n.kind().as_ref() == "impl_item")?;
        if owner.field("trait").is_some() {
            return None;
        }
        let ty = owner.field("type")?;
        (owner, ty)
    } else {
        parameter(path, root, site, receiver)?
    };
    let base = unwrap_type(root, &ty)?;
    let (canonical, import) = canonical(root, &base, base.text().as_ref())?;
    let mut support = BTreeMap::from([("http_client_owner_type".into(), capture(path, &ty))]);
    if let Some(import) = import {
        support.insert("http_client_owner_import".into(), capture(path, &import));
    }
    Some((local_key(path, &owner, &canonical), support))
}

fn parameter<'a>(_: &str, _: &N<'a>, site: &N<'a>, receiver: &N<'a>) -> Option<(N<'a>, N<'a>)> {
    let name = receiver.text();
    if !is_identifier(name.as_ref()) {
        return None;
    }
    let function = site
        .ancestors()
        .find(|n| n.kind().as_ref() == "function_item")?;
    // Do not borrow another function's declaration or a captured name that a
    // closure/let binding has replaced. Unknown local inference stays unknown.
    for ancestor in site
        .ancestors()
        .take_while(|n| n.range() != function.range())
    {
        if matches!(ancestor.kind().as_ref(), "for_expression" | "match_arm")
            && ancestor
                .field("pattern")
                .is_some_and(|p| p.dfs().any(|n| n.text() == name))
        {
            return None;
        }
        if matches!(
            ancestor.kind().as_ref(),
            "if_expression" | "while_expression"
        ) && ancestor.field("condition").is_some_and(|c| {
            c.dfs().any(|n| {
                n.kind().as_ref() == "let_condition"
                    && n.field("pattern")
                        .is_some_and(|p| p.dfs().any(|n| n.text() == name))
            })
        }) {
            return None;
        }
        if ancestor.kind().as_ref() == "closure_expression"
            && ancestor.field("parameters").is_some_and(|p| {
                p.dfs()
                    .any(|n| n.kind().as_ref() == "identifier" && n.text() == name)
            })
        {
            return None;
        }
        if ancestor.kind().as_ref() == "block"
            && ancestor.children().any(|n| {
                n.kind().as_ref() == "let_declaration"
                    && n.range().start < site.range().start
                    && n.field("pattern")
                        .is_some_and(|p| p.dfs().any(|n| n.text() == name))
            })
        {
            return None;
        }
    }
    let parameter = function
        .field("parameters")?
        .children()
        .find(|n| n.field("pattern").is_some_and(|p| p.text() == name))?;
    let ty = parameter.field("type")?;
    Some((function, ty))
}

fn client_support<'a>(path: &str, root: &N<'a>, ty: &N<'a>) -> Option<Support> {
    let base = unwrap_type(root, ty)?;
    let (name, import) = canonical(root, &base, base.text().as_ref())?;
    if !matches!(
        name.as_str(),
        "reqwest::Client"
            | "reqwest::blocking::Client"
            | "reqwest_middleware::ClientWithMiddleware"
    ) {
        return None;
    }
    let mut support = BTreeMap::from([("http_client_type".into(), capture(path, ty))]);
    if let Some(import) = import {
        support.insert("http_client_import".into(), capture(path, &import));
    }
    Some(support)
}

fn unwrap_type<'a>(root: &N<'a>, ty: &N<'a>) -> Option<N<'a>> {
    let mut ty = ty.clone();
    for _ in 0..4 {
        if ty.kind().as_ref() == "reference_type" {
            ty = ty.field("type")?;
            continue;
        }
        if ty.kind().as_ref() != "generic_type" {
            return Some(ty);
        }
        let outer = ty.field("type")?;
        let (name, _) = canonical(root, &outer, outer.text().as_ref())?;
        if !matches!(name.as_str(), "std::sync::Arc" | "std::boxed::Box") {
            return None;
        }
        let arguments = ty.field("type_arguments")?;
        let mut children = arguments.children().filter(|n| n.is_named());
        let inner = children.next()?;
        if children.next().is_some() {
            return None;
        }
        ty = inner;
    }
    None
}

// Resolve only visible explicit imports. Inline modules do not inherit a
// parent's uses, and local/generic type shadows cannot certify a library type.
fn canonical<'a>(_root: &N<'a>, site: &N<'a>, text: &str) -> Option<(String, Option<N<'a>>)> {
    let text = compact(text);
    let first = text.split("::").next()?;
    for ancestor in site.ancestors() {
        if ancestor.field("type_parameters").is_some_and(|p| {
            p.children().any(|n| {
                n.field("name")
                    .is_some_and(|name| name.text().as_ref() == first)
            })
        }) {
            return None;
        }
    }
    let mut choices = Vec::new();
    for item in lexical_scopes(site)
        .into_iter()
        .flat_map(|n| n.children().collect::<Vec<_>>())
    {
        let Some(scope) = item.parent() else { continue };
        if matches!(
            item.kind().as_ref(),
            "struct_item" | "enum_item" | "type_item" | "trait_item" | "mod_item"
        ) && item
            .field("name")
            .is_some_and(|name| name.text().as_ref() == first)
        {
            // A local type remains a local owner, even when its short name
            // collides with an outer import. Never canonicalize it as Reqwest.
            return Some((format!("self::{text}"), None));
        }
        if item.kind().as_ref() != "use_declaration" {
            continue;
        }
        let source = item.text();
        let Some(spec) = source
            .trim()
            .strip_prefix("use ")
            .and_then(|s| s.strip_suffix(';'))
        else {
            continue;
        };
        let mut aliases = BTreeMap::new();
        expand_use("", spec, &mut aliases);
        if let Some(value) = aliases.get(first) {
            choices.push((scope.range().len(), value.clone(), item));
        }
    }
    choices.sort_by_key(|c| c.0);
    if let Some((scope, value, item)) = choices.first() {
        if choices.iter().any(|c| c.0 == *scope && c.1 != *value) {
            return None;
        }
        let import_root = value.split("::").next()?;
        if lexical_scopes(item)
            .into_iter()
            .flat_map(|s| s.children().collect::<Vec<_>>())
            .any(|n| {
                n.kind().as_ref() == "mod_item"
                    && n.field("name")
                        .is_some_and(|name| name.text().as_ref() == import_root)
                    && n.parent().is_some_and(|s| {
                        s.range().start <= item.range().start && s.range().end >= item.range().end
                    })
            })
        {
            return Some((
                format!("self::{value}{}", &text[first.len()..]),
                Some(item.clone()),
            ));
        }
        return Some((
            format!("{value}{}", &text[first.len()..]),
            Some(item.clone()),
        ));
    }
    Some((text, None))
}

fn lexical_scopes<'a>(site: &N<'a>) -> Vec<N<'a>> {
    let mut scopes = Vec::new();
    for node in site.ancestors() {
        if matches!(
            node.kind().as_ref(),
            "block" | "declaration_list" | "source_file"
        ) {
            let module_body = node
                .parent()
                .is_some_and(|p| p.kind().as_ref() == "mod_item");
            scopes.push(node);
            if module_body {
                break;
            }
        }
    }
    scopes
}

fn local_key(path: &str, site: &N<'_>, ty: &str) -> String {
    let path = path.replace('\\', "/");
    let (crate_root, relative) = path
        .rsplit_once("/src/")
        .map(|(a, b)| (format!("{a}/src"), b))
        .or_else(|| path.strip_prefix("src/").map(|p| ("src".to_string(), p)))
        .unwrap_or_else(|| (String::new(), path.as_str()));
    let mut module = relative
        .trim_end_matches(".rs")
        .split('/')
        .map(str::to_string)
        .collect::<Vec<_>>();
    if module
        .last()
        .is_some_and(|p| matches!(p.as_str(), "lib" | "main" | "mod"))
    {
        module.pop();
    }
    let mut inline = site
        .ancestors()
        .filter(|n| n.kind().as_ref() == "mod_item")
        .filter_map(|n| n.field("name").map(|n| n.text().into_owned()))
        .collect::<Vec<_>>();
    inline.reverse();
    module.extend(inline);
    let mut ty = ty;
    if let Some(rest) = ty.strip_prefix("crate::") {
        module.clear();
        ty = rest;
    } else if let Some(rest) = ty.strip_prefix("self::") {
        ty = rest;
    }
    while let Some(rest) = ty.strip_prefix("super::") {
        if module.pop().is_none() {
            return format!("{crate_root}\0<unresolved>");
        }
        ty = rest;
    }
    module.push(ty.to_string());
    format!("{crate_root}\0{}", module.join("::"))
}

fn capture(path: &str, node: &N<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: super::matcher::location(path, node),
    }
}
fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::AstGrep;

    #[test]
    fn imported_accessor_retains_the_declared_field_and_return_type() {
        let source = "use reqwest_middleware::ClientWithMiddleware as Http; use std::sync::Arc; pub struct State { http: Arc<Http> } impl State { pub fn outbound(&self) -> &Http { &self.http } }";
        let ast = AstGrep::doc(StrDoc::try_new(source, SupportLang::Rust).unwrap());
        let mut index = RustHttpProjectContext::default();
        index.collect("src/context.rs", &ast.root());
        assert_eq!(index.fields.len(), 1, "fields: {:?}", index.fields.keys());
        assert_eq!(
            index.accessors.len(),
            1,
            "accessors: {:?}",
            index.accessors.keys()
        );
        let request = "use crate::context::State as Shared; async fn fetch(state: &Shared, url: &str) { state.outbound().get(url).send().await; }";
        let ast = AstGrep::doc(StrDoc::try_new(request, SupportLang::Rust).unwrap());
        let root = ast.root();
        let get = root
            .dfs()
            .find(|n| {
                n.kind().as_ref() == "call_expression"
                    && n.text().as_ref() == "state.outbound().get(url)"
            })
            .unwrap();
        assert!(
            index
                .request_support("src/request.rs", &root, &get)
                .is_some()
        );
    }
}
