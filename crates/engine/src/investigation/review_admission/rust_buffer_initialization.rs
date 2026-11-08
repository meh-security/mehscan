//! Source-defined capacity/position/length-publication relationships.
//! A concrete Vec implementation is a witness, never proof about every trait implementation.
use super::*;
use rust_shared_state::{AstNode as N, compact, imports, owns};

const RULE: &str = "rust-buffer-initialized-prefix-review-marker";

fn named<'a>(node: &N<'a>) -> Vec<N<'a>> {
    node.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
        .collect()
}

fn text(node: &N<'_>) -> String {
    compact(&node.text())
}

fn base(value: &str) -> &str {
    value.split('<').next().unwrap_or(value)
}

fn field<'a>(node: &N<'a>) -> Option<(N<'a>, String)> {
    (node.kind().as_ref() == "field_expression").then_some(())?;
    Some((
        node.field("value")?,
        node.field("field")?.text().into_owned(),
    ))
}

fn args<'a>(call: &N<'a>) -> Vec<N<'a>> {
    call.field("arguments")
        .map(|n| named(&n))
        .unwrap_or_default()
}

fn method<'a>(call: &N<'a>) -> Option<(N<'a>, String, Vec<N<'a>>)> {
    if call.kind().as_ref() != "call_expression" {
        return None;
    }
    let (receiver, name) = field(&call.field("function")?)?;
    Some((receiver, name, args(call)))
}

fn parameters(function: &N<'_>) -> Vec<(String, String)> {
    function
        .field("parameters")
        .into_iter()
        .flat_map(|p| named(&p))
        .filter(|p| p.kind().as_ref() == "parameter")
        .filter_map(|p| Some((text(&p.field("pattern")?), text(&p.field("type")?))))
        .collect()
}

fn tail<'a>(mut node: N<'a>) -> Option<N<'a>> {
    for _ in 0..8 {
        if !matches!(
            node.kind().as_ref(),
            "block" | "unsafe_block" | "expression_statement" | "return_expression"
        ) {
            return Some(node);
        }
        let children = named(&node);
        if children.len() != 1 {
            return None;
        }
        node = children[0].clone();
    }
    None
}

fn fields<'a>(expression: &N<'a>) -> Vec<(String, N<'a>)> {
    expression
        .field("body")
        .into_iter()
        .flat_map(|body| named(&body))
        .filter_map(|field| {
            if field.kind().as_ref() == "field_initializer" {
                Some((
                    field.field("field")?.text().into_owned(),
                    field.field("value")?,
                ))
            } else if field.kind().as_ref() == "shorthand_field_initializer" {
                let name = named(&field).into_iter().next()?;
                Some((name.text().into_owned(), name))
            } else {
                None
            }
        })
        .collect()
}

struct Coordinates {
    lines: Vec<usize>,
}

impl Coordinates {
    fn new(source: &str) -> Self {
        Self {
            lines: std::iter::once(0)
                .chain(
                    source
                        .bytes()
                        .enumerate()
                        .filter_map(|(offset, byte)| (byte == b'\n').then_some(offset + 1)),
                )
                .collect(),
        }
    }

    fn location(&self, file: &SourceFile, start: usize, end: usize) -> Location {
        let position = |offset| {
            let line = self.lines.partition_point(|start| *start <= offset) - 1;
            Position {
                line: line + 1,
                column: file.source[self.lines[line]..offset].chars().count() + 1,
                byte_offset: offset,
            }
        };
        Location {
            path: file.path.clone(),
            start: position(start),
            end: position(end),
        }
    }
}

fn capture(file: &SourceFile, coordinates: &Coordinates, node: &N<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: coordinates.location(file, node.range().start, node.range().end),
    }
}

fn public_safe(function: &N<'_>) -> bool {
    function
        .children()
        .any(|n| n.kind().as_ref() == "visibility_modifier")
        && !function
            .children()
            .any(|n| n.kind().as_ref() == "function_modifiers" && n.text().contains("unsafe"))
}

fn methods<'a>(
    file: &SourceFile,
    item: &N<'a>,
    selection: &rust_configuration::Selection,
) -> Vec<N<'a>> {
    item.field("body")
        .into_iter()
        .flat_map(|body| named(&body))
        .filter(|n| {
            n.kind().as_ref() == "function_item"
                && n.range().len() <= 16384
                && n.end_pos().line() <= n.start_pos().line() + 119
                && !selection.excluded(&file.path, n.range())
                && !n
                    .dfs()
                    .any(|c| matches!(c.kind().as_ref(), "ERROR" | "MISSING"))
        })
        .collect()
}

// Prune only direct source-proved exclusions; unknown conditions remain leads.
pub(super) fn runtime_path(node: &N<'_>, function: &N<'_>) -> bool {
    let mut current = node.clone();
    while let Some(parent) = current.parent() {
        if parent.range() == function.range() {
            break;
        }
        if parent.kind().as_ref() == "if_expression" {
            if let Some(condition) = parent.field("condition") {
                for (branch, excluded) in [("consequence", "false"), ("alternative", "true")] {
                    if text(&condition) == excluded
                        && parent.field(branch).is_some_and(|body| {
                            body.range().start <= node.range().start
                                && node.range().end <= body.range().end
                        })
                    {
                        return false;
                    }
                }
            }
        }
        if parent.kind().as_ref() == "block"
            && named(&parent).iter().any(|sibling| {
                sibling.range().end <= current.range().start
                    && (sibling.kind().as_ref() == "return_expression"
                        || (sibling.kind().as_ref() == "expression_statement"
                            && named(sibling)
                                .first()
                                .is_some_and(|n| n.kind().as_ref() == "return_expression")))
            })
        {
            return false;
        }
        current = parent;
    }
    true
}

struct Bindings {
    local: BTreeMap<String, usize>,
    traits: BTreeSet<String>,
    aliases: BTreeMap<String, Vec<String>>,
    no_prelude: bool,
    explicit_sdk: BTreeSet<String>,
}

impl Bindings {
    fn new(file: &SourceFile, root: &N<'_>, selection: &rust_configuration::Selection) -> Self {
        let mut result = Self {
            local: BTreeMap::new(),
            traits: BTreeSet::new(),
            aliases: BTreeMap::new(),
            no_prelude: root.children().any(|n| {
                n.kind().as_ref() == "inner_attribute_item"
                    && n.text().contains("no_implicit_prelude")
            }),
            explicit_sdk: BTreeSet::new(),
        };
        for node in named(root)
            .into_iter()
            .filter(|n| !selection.excluded(&file.path, n.range()))
        {
            if matches!(
                node.kind().as_ref(),
                "struct_item" | "enum_item" | "type_item" | "trait_item" | "mod_item"
            ) {
                if let Some(name) = node.field("name") {
                    *result.local.entry(text(&name)).or_default() += 1;
                    if node.kind().as_ref() == "trait_item" {
                        result.traits.insert(text(&name));
                    }
                }
            } else if node.kind().as_ref() == "use_declaration" {
                let mut values = Vec::new();
                imports(&node, "", false, &mut values);
                for (alias, target, _) in values {
                    result.aliases.entry(alias).or_default().push(target);
                }
            } else if node.kind().as_ref() == "extern_crate_declaration" {
                let declaration = text(&node);
                for name in ["std", "alloc", "core"] {
                    if declaration == format!("externcrate{name};") {
                        result.explicit_sdk.insert(name.into());
                    }
                }
                for name in ["std", "alloc", "Vec", "Drop"] {
                    if declaration.ends_with(&format!("{name};"))
                        && declaration != format!("externcrate{name};")
                    {
                        result.local.insert(name.into(), 2);
                    }
                }
            }
        }
        result
    }

    fn canonical(&self, value: &str) -> Option<String> {
        let value = value.trim_start_matches("::");
        let first = value.split("::").next()?;
        if self.local.contains_key(first) {
            return None;
        }
        if self.aliases.contains_key("*") && !self.explicit_sdk.contains(first) {
            return None;
        }
        if let Some(aliases) = self.aliases.get(first) {
            if aliases.len() != 1 {
                return None;
            }
            let root = aliases[0].split("::").next()?;
            if self.local.contains_key(root) {
                return None;
            }
            return Some(format!("{}{}", aliases[0], &value[first.len()..]));
        }
        if first == "Vec" && !self.no_prelude {
            return Some(format!("std::vec::{value}"));
        }
        if first == "Drop" && !self.no_prelude {
            return Some(format!("core::ops::{value}"));
        }
        Some(value.into())
    }

    fn vec(&self, ty: &str) -> bool {
        // Primitive type names are shadowable. A locally aliased u8 may be a
        // zero-sized or unrelated element, so it cannot supply a byte witness.
        let byte_element = match self.aliases.get("u8") {
            Some(targets) if targets.len() == 1 => {
                self.canonical(&targets[0]).is_some_and(|name| {
                    matches!(name.as_str(), "std::primitive::u8" | "core::primitive::u8")
                })
            }
            Some(_) => false,
            None => !self.aliases.contains_key("*"),
        };
        if self.local.contains_key("u8") || !byte_element {
            return false;
        }
        let Some(ty) = ty.strip_suffix("<u8>") else {
            return false;
        };
        self.canonical(ty)
            .is_some_and(|name| matches!(name.as_str(), "std::vec::Vec" | "alloc::vec::Vec"))
    }
}

struct Protocol<'a> {
    implementation: N<'a>,
    capacity: N<'a>,
    initialized: N<'a>,
    pointer: N<'a>,
    publication: N<'a>,
}

fn primitive_call(node: &N<'_>, name: &str, arguments: &[&str], bindings: &Bindings) -> bool {
    if let Some((receiver, method, actual)) = method(node) {
        return text(&receiver) == "self"
            && method == name
            && actual.iter().map(text).collect::<Vec<_>>() == arguments;
    }
    let Some(function) = node.field("function") else {
        return false;
    };
    let path = text(&function);
    let Some(owner) = path.strip_suffix(&format!("::{name}")) else {
        return false;
    };
    let Some(canonical) = bindings.canonical(owner) else {
        return false;
    };
    if !matches!(canonical.as_str(), "std::vec::Vec" | "alloc::vec::Vec") {
        return false;
    }
    let actual = args(node).iter().map(text).collect::<Vec<_>>();
    actual.first().is_some_and(|a| a == "self") && actual[1..] == *arguments
}

fn protocols<'a>(
    file: &SourceFile,
    root: &N<'a>,
    bindings: &Bindings,
    selection: &rust_configuration::Selection,
) -> BTreeMap<String, Vec<Protocol<'a>>> {
    let mut result = BTreeMap::<_, Vec<_>>::new();
    for item in named(root)
        .into_iter()
        .filter(|n| n.kind().as_ref() == "impl_item" && !selection.excluded(&file.path, n.range()))
    {
        let (Some(ty), Some(trait_node)) = (item.field("type"), item.field("trait")) else {
            continue;
        };
        let trait_name = text(&trait_node);
        if trait_node.kind().as_ref() != "type_identifier"
            || bindings.local.get(&trait_name) != Some(&1)
            || !bindings.traits.contains(&trait_name)
            || !bindings.vec(&text(&ty))
        {
            continue;
        }
        if item.field("type_parameters").is_some() {
            continue;
        }
        let functions = methods(file, &item, selection);
        let mut capacity = Vec::new();
        let mut initialized = Vec::new();
        let mut pointer = Vec::new();
        let mut publication = Vec::new();
        for function in functions {
            let Some(body) = function.field("body").and_then(tail) else {
                continue;
            };
            let result_type = function
                .field("return_type")
                .map(|n| text(&n))
                .unwrap_or_default();
            let params = parameters(&function);
            if params.is_empty() {
                if result_type == "usize" && primitive_call(&body, "capacity", &[], bindings) {
                    capacity.push(function.clone());
                }
                if result_type == "&[u8]"
                    && (text(&body) == "&self[..]"
                        || primitive_call(&body, "as_slice", &[], bindings))
                {
                    initialized.push(function.clone());
                }
                if result_type == "*mutu8" && primitive_call(&body, "as_mut_ptr", &[], bindings) {
                    pointer.push(function.clone());
                }
            } else if params.len() == 1
                && params[0].1 == "usize"
                && function
                    .field("parameters")
                    .is_some_and(|n| text(&n).contains("&mutself"))
                && primitive_call(&body, "set_len", &[&params[0].0], bindings)
            {
                publication.push(function);
            }
        }
        if capacity.len() == 1
            && initialized.len() == 1
            && pointer.len() == 1
            && publication.len() == 1
        {
            result
                .entry(trait_name.clone())
                .or_default()
                .push(Protocol {
                    implementation: item.clone(),
                    capacity: capacity.remove(0),
                    initialized: initialized.remove(0),
                    pointer: pointer.remove(0),
                    publication: publication.remove(0),
                });
        }
    }
    result
}

fn function_name(node: &N<'_>) -> String {
    node.field("name").map(|n| text(&n)).unwrap_or_default()
}

fn bound_parameters(item: &N<'_>) -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::<String, Vec<String>>::new();
    for parameter in item
        .field("type_parameters")
        .into_iter()
        .flat_map(|p| named(&p))
    {
        let (Some(bounds), Some(name)) = (parameter.field("bounds"), parameter.field("name"))
        else {
            continue;
        };
        for bound in text(&bounds).trim_start_matches(':').split('+') {
            result.entry(bound.into()).or_default().push(text(&name));
        }
    }
    result
}

fn declared_parameter(
    owner: &N<'_>,
    implementation_type: &N<'_>,
    variable: &str,
) -> Option<String> {
    let declaration = owner.field("type_parameters")?;
    let arguments = implementation_type.field("type_arguments")?;
    let parameters = named(&declaration);
    let values = named(&arguments);
    if parameters.len() != values.len() {
        return None;
    }
    values
        .iter()
        .position(|value| text(value) == variable)
        .and_then(|index| parameters[index].field("name"))
        .map(|name| text(&name))
}

fn buffer_fields(owner: &N<'_>, parameter: &str) -> Vec<String> {
    owner
        .field("body")
        .into_iter()
        .flat_map(|body| named(&body))
        .filter_map(|field| {
            let ty = field.field("type")?;
            (ty.kind().as_ref() == "reference_type"
                && text(&ty).contains("mut")
                && ty.field("type").is_some_and(|n| text(&n) == parameter))
            .then(|| field.field("name").map(|n| text(&n)))
            .flatten()
        })
        .collect()
}

struct Publication<'a> {
    function: N<'a>,
    call: N<'a>,
    name: String,
}

fn publications<'a>(
    functions: &[N<'a>],
    buffer: &str,
    protocol: &Protocol<'a>,
) -> Vec<Publication<'a>> {
    let mut result = Vec::new();
    let receiver = format!("self.{buffer}");
    let target = function_name(&protocol.publication);
    for function in functions {
        let params = parameters(function);
        for call in function.dfs().filter(|n| {
            n.kind().as_ref() == "call_expression" && owns(n, function) && runtime_path(n, function)
        }) {
            let Some((value, name, args)) = method(&call) else {
                continue;
            };
            if text(&value) == receiver
                && name == target
                && args.len() == 1
                && params
                    .iter()
                    .any(|(name, ty)| ty == "usize" && *name == text(&args[0]))
            {
                result.push(Publication {
                    function: function.clone(),
                    call,
                    name: function_name(function),
                });
            }
        }
    }
    result
}

#[derive(Clone)]
struct Carrier<'a> {
    wrap: N<'a>,
    drop: N<'a>,
    caller: N<'a>,
}

fn referenced_type<'a>(ty: &N<'a>) -> Option<N<'a>> {
    if ty.kind().as_ref() != "reference_type" || !text(ty).contains("mut") {
        return None;
    }
    ty.field("type")
}

fn borrowed_parameters(function: &N<'_>) -> Vec<(String, String)> {
    function
        .field("parameters")
        .into_iter()
        .flat_map(|n| named(&n))
        .filter_map(|parameter| {
            Some((
                text(&parameter.field("pattern")?),
                text(&referenced_type(&parameter.field("type")?)?),
            ))
        })
        .collect()
}

struct Links<'a> {
    owners: BTreeMap<String, N<'a>>,
    drops: BTreeMap<String, Vec<N<'a>>>,
    callers: BTreeMap<(String, String), Vec<N<'a>>>,
}

fn is_forget(call: &N<'_>, bindings: &Bindings) -> bool {
    call.field("function")
        .and_then(|n| bindings.canonical(&text(&n)))
        .is_some_and(|name| matches!(name.as_str(), "std::mem::forget" | "core::mem::forget"))
}

fn forgotten_calls(function: &N<'_>, bindings: &Bindings) -> BTreeSet<(usize, usize)> {
    let mut result = BTreeSet::new();
    for block in function
        .dfs()
        .filter(|n| n.kind().as_ref() == "block" && owns(n, function))
    {
        let statements = named(&block);
        for pair in statements.windows(2) {
            let declaration = &pair[0];
            let (Some(pattern), Some(value)) =
                (declaration.field("pattern"), declaration.field("value"))
            else {
                continue;
            };
            if declaration.kind().as_ref() != "let_declaration"
                || pattern.kind().as_ref() != "identifier"
                || value.kind().as_ref() != "call_expression"
            {
                continue;
            }
            let Some(call) = tail(pair[1].clone()) else {
                continue;
            };
            let arguments = args(&call);
            // Adjacent unconditional forget only: an intervening operation may
            // unwind and run Drop, so it cannot certify suppressed publication.
            if is_forget(&call, bindings)
                && arguments.len() == 1
                && text(&arguments[0]) == text(&pattern)
            {
                result.insert((value.range().start, value.range().end));
            }
        }
    }
    result
}

impl<'a> Links<'a> {
    fn new(
        root: &N<'a>,
        file: &SourceFile,
        bindings: &Bindings,
        selection: &rust_configuration::Selection,
    ) -> Self {
        let owners: BTreeMap<_, _> = named(root)
            .into_iter()
            .filter(|n| {
                n.kind().as_ref() == "struct_item"
                    && !selection.excluded(&file.path, n.range())
                    && bindings.local.get(&function_name(n)) == Some(&1)
            })
            .map(|n| (function_name(&n), n))
            .collect();
        let mut result = Self {
            owners,
            drops: BTreeMap::new(),
            callers: BTreeMap::new(),
        };
        let mut functions = Vec::new();
        for item in named(root)
            .into_iter()
            .filter(|n| !selection.excluded(&file.path, n.range()))
        {
            if item.kind().as_ref() == "function_item" {
                functions.push(item);
                continue;
            }
            if item.kind().as_ref() != "impl_item" {
                continue;
            }
            let list = methods(file, &item, selection);
            let drop = item
                .field("trait")
                .and_then(|t| bindings.canonical(&text(&t)))
                .is_some_and(|name| matches!(name.as_str(), "std::ops::Drop" | "core::ops::Drop"));
            if drop {
                if let Some(ty) = item.field("type") {
                    result
                        .drops
                        .entry(base(&text(&ty)).to_string())
                        .or_default()
                        .extend(list.clone());
                }
            }
            functions.extend(list);
        }
        for function in functions
            .into_iter()
            .filter(|n| public_safe(n) && n.range().len() <= 16384)
        {
            let parameters = borrowed_parameters(&function);
            let forgotten = forgotten_calls(&function, bindings);
            let mut shadows = BTreeMap::<String, Vec<(usize, std::ops::Range<usize>)>>::new();
            for declaration in function
                .dfs()
                .filter(|n| n.kind().as_ref() == "let_declaration" && owns(n, &function))
            {
                let Some(pattern) = declaration.field("pattern") else {
                    continue;
                };
                if pattern.kind().as_ref() != "identifier" {
                    continue;
                }
                if let Some(scope) = declaration
                    .ancestors()
                    .find(|n| n.kind().as_ref() == "block")
                {
                    shadows
                        .entry(text(&pattern))
                        .or_default()
                        .push((declaration.range().end, scope.range()));
                }
            }
            for call in function.dfs().filter(|n| {
                n.kind().as_ref() == "call_expression"
                    && owns(n, &function)
                    && runtime_path(n, &function)
                    && !forgotten.contains(&(n.range().start, n.range().end))
            }) {
                let Some((receiver, name, args)) = method(&call) else {
                    continue;
                };
                if !args.is_empty() {
                    continue;
                }
                for (parameter, ty) in &parameters {
                    let owner = base(ty);
                    if text(&receiver) != *parameter || !result.owners.contains_key(owner) {
                        continue;
                    }
                    let generic_shadow = function.field("type_parameters").is_some_and(|p| {
                        named(&p)
                            .iter()
                            .any(|n| n.field("name").is_some_and(|n| text(&n) == owner))
                    });
                    let local_shadow = shadows.get(parameter).is_some_and(|bindings| {
                        bindings.iter().any(|(end, scope)| {
                            *end <= call.range().start
                                && scope.start <= call.range().start
                                && call.range().end <= scope.end
                        })
                    });
                    if !generic_shadow && !local_shadow {
                        result
                            .callers
                            .entry((owner.into(), name.clone()))
                            .or_default()
                            .push(function.clone());
                    }
                }
            }
        }
        result
    }
}

fn carrier<'a>(
    links: &Links<'a>,
    owner: &str,
    buffer: &str,
    position: &str,
    functions: &[N<'a>],
    publication: &Publication<'a>,
    capacity: &str,
) -> Option<Carrier<'a>> {
    for wrap in functions {
        let callers = links.callers.get(&(owner.into(), function_name(wrap)));
        let Some(caller) = callers.and_then(|callers| callers.first()) else {
            continue;
        };
        for literal in wrap.dfs().filter(|n| {
            n.kind().as_ref() == "struct_expression" && owns(n, wrap) && runtime_path(n, wrap)
        }) {
            let Some(name) = literal.field("name") else {
                continue;
            };
            let wrapper = base(&text(&name)).to_string();
            let Some(wrapper_type) = links.owners.get(&wrapper) else {
                continue;
            };
            let Some(drops) = links.drops.get(&wrapper) else {
                continue;
            };
            let values = fields(&literal);
            for (parent, _) in values.iter().filter(|(_, value)| text(value) == "self") {
                let owns_parent = wrapper_type
                    .field("body")
                    .into_iter()
                    .flat_map(|n| named(&n))
                    .any(|f| {
                        f.field("name").is_some_and(|n| text(&n) == *parent)
                            && f.field("type")
                                .and_then(|n| referenced_type(&n))
                                .is_some_and(|ty| base(&text(&ty)) == owner)
                    });
                if !owns_parent {
                    continue;
                }
                for (member, nested) in values
                    .iter()
                    .filter(|(_, value)| value.kind().as_ref() == "struct_expression")
                {
                    let nested_fields = fields(nested);
                    if !nested_fields.iter().any(|(_, value)| {
                        method(value).is_some_and(|(receiver, name, args)| {
                            text(&receiver) == format!("self.{buffer}")
                                && name == capacity
                                && args.is_empty()
                        })
                    }) {
                        continue;
                    }
                    for (offset, _) in nested_fields
                        .iter()
                        .filter(|(_, value)| text(value) == format!("self.{position}"))
                    {
                        for drop in drops {
                            let linked = drop
                                .dfs()
                                .filter(|n| {
                                    n.kind().as_ref() == "call_expression"
                                        && owns(n, drop)
                                        && runtime_path(n, drop)
                                })
                                .any(|n| {
                                    method(&n).is_some_and(|(receiver, name, args)| {
                                        text(&receiver) == format!("self.{parent}")
                                            && name == publication.name
                                            && args.len() == 1
                                            && text(&args[0]) == format!("self.{member}.{offset}")
                                    })
                                });
                            if linked {
                                return Some(Carrier {
                                    wrap: wrap.clone(),
                                    drop: drop.clone(),
                                    caller: caller.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub(super) fn groups(
    sources: &RepositorySources,
    existing: &[Evidence],
    scope: Option<&mehscan_core::ImpactScanScope>,
    include_material: bool,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    for file in sources.files.values().filter(|file| {
        file.language == Some(Language::Rust)
            && file.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
            && file.source.contains("set_len")
            && !selection.excluded_file(&file.path)
            && (include_material || !is_review_material_path(&file.path))
    }) {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        let bindings = Bindings::new(file, &root, selection);
        let protocols = protocols(file, &root, &bindings, selection);
        if protocols.is_empty() {
            continue;
        }
        let coordinates = Coordinates::new(&file.source);
        let links = Links::new(&root, file, &bindings, selection);
        let owners: BTreeMap<_, _> = named(&root)
            .into_iter()
            .filter(|n| {
                n.kind().as_ref() == "struct_item" && !selection.excluded(&file.path, n.range())
            })
            .filter_map(|n| Some((function_name(&n), n)))
            .collect();
        for implementation in named(&root).into_iter().filter(|n| {
            n.kind().as_ref() == "impl_item"
                && n.field("trait").is_none()
                && !selection.excluded(&file.path, n.range())
        }) {
            let Some(ty) = implementation.field("type") else {
                continue;
            };
            let owner_name = base(&text(&ty)).to_string();
            let Some(owner) = owners.get(&owner_name) else {
                continue;
            };
            if bindings.local.get(&owner_name) != Some(&1) {
                continue;
            }
            let functions = methods(file, &implementation, selection);
            for (trait_name, bound_arguments) in bound_parameters(&implementation) {
                if bound_arguments.len() != 1 {
                    continue;
                }
                let Some(alternatives) = protocols.get(&trait_name) else {
                    continue;
                };
                for protocol in alternatives {
                    let parameter = bound_arguments[0].clone();
                    let field_parameter = declared_parameter(owner, &ty, &parameter)
                        .unwrap_or_else(|| parameter.clone());
                    for buffer in buffer_fields(owner, &field_parameter) {
                        for publication in publications(&functions, &buffer, protocol) {
                            let chains: BTreeMap<_, _> = owner
                                .field("body")
                                .into_iter()
                                .flat_map(|n| named(&n))
                                .filter(|n| n.field("type").is_some_and(|t| text(&t) == "usize"))
                                .filter_map(|n| {
                                    let position = text(&n.field("name")?);
                                    let chain = carrier(
                                        &links,
                                        &owner_name,
                                        &buffer,
                                        &position,
                                        &functions,
                                        &publication,
                                        &function_name(&protocol.capacity),
                                    )?;
                                    Some((position, chain))
                                })
                                .collect();
                            if chains.is_empty() {
                                continue;
                            }
                            for constructor in functions.iter().filter(|n| public_safe(n)) {
                                let params = parameters(constructor);
                                for literal in constructor.dfs().filter(|n| {
                                    n.kind().as_ref() == "struct_expression"
                                        && owns(n, constructor)
                                        && runtime_path(n, constructor)
                                        && n.field("name").is_some_and(|name| {
                                            matches!(text(&name).as_str(), "Self")
                                                || text(&name) == owner_name
                                        })
                                }) {
                                    let values = fields(&literal);
                                    let Some((_, input)) =
                                        values.iter().find(|(name, _)| name == &buffer)
                                    else {
                                        continue;
                                    };
                                    if !borrowed_parameters(constructor)
                                        .iter()
                                        .any(|(name, ty)| *name == text(input) && *ty == parameter)
                                    {
                                        continue;
                                    }
                                    let input = text(input);
                                    for (position, initial) in values.iter().filter(|(_, value)| {
                                        params
                                            .iter()
                                            .any(|(name, ty)| ty == "usize" && *name == text(value))
                                    }) {
                                        let limit = constructor
                                            .dfs()
                                            .filter(|n| {
                                                n.kind().as_ref() == "call_expression"
                                                    && owns(n, constructor)
                                            })
                                            .find(|n| {
                                                method(n).is_some_and(|(receiver, name, args)| {
                                                    text(&receiver) == input
                                                        && name == function_name(&protocol.capacity)
                                                        && args.is_empty()
                                                }) && n
                                                    .ancestors()
                                                    .any(|a| a.kind().as_ref() == "if_expression")
                                            });
                                        let Some(limit) = limit else {
                                            continue;
                                        };
                                        let Some(chain) = chains.get(position) else {
                                            continue;
                                        };
                                        let location = coordinates.location(
                                            file,
                                            constructor.range().start,
                                            constructor.range().end,
                                        );
                                        if scope.is_some_and(|s| match s.result_policy.as_str() {
                                            "changed_locations" => {
                                                !crate::impact::location_is_changed(
                                                    &location,
                                                    &s.changed_files,
                                                )
                                            }
                                            "changed_files" | "impact_scope" => !s
                                                .included_files
                                                .iter()
                                                .any(|f| f.path == file.path),
                                            _ => false,
                                        }) {
                                            continue;
                                        }
                                        let descriptor = ReviewAdmissionDescriptor {
                                            rule_id: RULE,
                                            capability: Capability::BufferLengthPublication,
                                            cwe_candidates: vec!["CWE-908".into()],
                                            tags: Vec::new(),
                                        };
                                        if marker_covered_by_existing_evidence(
                                            existing,
                                            &file.path,
                                            constructor.range().start,
                                            constructor.range().end,
                                            &descriptor,
                                        ) {
                                            continue;
                                        }
                                        let id = review_admission_marker_id(
                                            &file.path,
                                            RULE,
                                            constructor.range().start,
                                            constructor.range().end,
                                        );
                                        if groups.iter().any(|g: &ObservationGroup| {
                                            g.anchor_evidence_ids.contains(&id)
                                        }) {
                                            continue;
                                        }
                                        let captures = BTreeMap::from([
                                            (
                                                "helper_definition".into(),
                                                capture(file, &coordinates, constructor),
                                            ),
                                            (
                                                "buffer_owner_definition".into(),
                                                capture(file, &coordinates, owner),
                                            ),
                                            (
                                                "capacity_check".into(),
                                                capture(file, &coordinates, &limit),
                                            ),
                                            (
                                                "initial_position".into(),
                                                capture(file, &coordinates, initial),
                                            ),
                                            (
                                                "capacity_effect".into(),
                                                capture(file, &coordinates, &protocol.capacity),
                                            ),
                                            (
                                                "initialized_extent".into(),
                                                capture(file, &coordinates, &protocol.initialized),
                                            ),
                                            (
                                                "buffer_pointer".into(),
                                                capture(file, &coordinates, &protocol.pointer),
                                            ),
                                            (
                                                "length_effect".into(),
                                                capture(file, &coordinates, &protocol.publication),
                                            ),
                                            (
                                                "length_publication_definition".into(),
                                                capture(file, &coordinates, &publication.function),
                                            ),
                                            (
                                                "length_publication".into(),
                                                capture(file, &coordinates, &publication.call),
                                            ),
                                            (
                                                "position_transfer_definition".into(),
                                                capture(file, &coordinates, &chain.wrap),
                                            ),
                                            (
                                                "publication_caller_definition".into(),
                                                capture(file, &coordinates, &chain.drop),
                                            ),
                                            (
                                                "safe_operation_definition".into(),
                                                capture(file, &coordinates, &chain.caller),
                                            ),
                                            (
                                                "vector_implementation_definition".into(),
                                                capture(
                                                    file,
                                                    &coordinates,
                                                    &protocol.implementation,
                                                ),
                                            ),
                                        ]);
                                        let mut captures = captures;
                                        if let Some(body) = implementation.field("body") {
                                            let start = implementation.range().start;
                                            let end = body.range().start;
                                            captures.insert(
                                                "owner_implementation_definition".into(),
                                                Capture {
                                                    text: file.source[start..end].into(),
                                                    location: coordinates
                                                        .location(file, start, end),
                                                },
                                            );
                                        }
                                        let evidence=Evidence {id:id.clone(),kind:EvidenceKind::SensitiveOperation,capability:Capability::BufferLengthPublication,location,
                                        enclosing_symbol:Some(function_name(constructor)),captures,cwe_candidates:vec!["CWE-908".into()],
                                        tags:["review-admission-marker","buffer-initialized-prefix","capacity-is-not-initialization","trait-implementation:witness-not-universal","initialization-and-ffi-effects-require-review"].into_iter().map(str::to_string).collect(),
                                        confidence:Confidence::Medium,provenance:Provenance{resolution:Resolution::Ast,engine:"bounded Rust initialized-prefix publication relationship".into(),rule_version:1},
                                        context:EvidenceContext::default(),symbol_resolution:None,rule_id:RULE.into(),related_evidence:Vec::new()};
                                        groups.push(ObservationGroup {
                                            review_material: is_review_material_path(&file.path),
                                            path: file.path.clone(),
                                            symbol: function_name(constructor),
                                            evidence: vec![evidence],
                                            anchor_evidence_ids: vec![id],
                                            priority: 1,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    groups
}
