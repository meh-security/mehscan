//! Length guarantees on the same iterator element that reaches a byte parser.
use super::*;
use rust_parser_provenance::{
    arguments, declared_type, definition, enclosing_function, literal, named, peel, private, scope,
    slice_type, vector,
};
use rust_shared_state::AstNode as N;

struct ChunkCall<'a> {
    name: N<'a>,
    call: N<'a>,
    chunks: N<'a>,
    buffer_declaration: N<'a>,
    type_support: Vec<Capture>,
    guard: Option<N<'a>>,
    minimum: usize,
}

#[derive(Default)]
pub(super) struct Callers<'a> {
    by_argument: BTreeMap<(usize, usize), Vec<ChunkCall<'a>>>,
    references: BTreeMap<String, BTreeSet<usize>>,
    closed_scopes: BTreeMap<(usize, usize), bool>,
}

fn closed_scope(module: &N<'_>) -> bool {
    !module.dfs().any(|n| {
        n.is_error()
            || n.is_missing()
            || (n.kind().as_ref() == "mod_item" && n.field("body").is_none())
            || (n.kind().as_ref() == "macro_invocation"
                && n.field("macro")
                    .is_some_and(|m| m.text().rsplit("::").next() == Some("include")))
    })
}

fn closure_parameter<'a>(closure: &N<'a>) -> Option<N<'a>> {
    (closure.kind().as_ref() == "closure_expression").then_some(())?;
    let params = closure.field("parameters")?;
    let parameter = rust_parser_provenance::unique(named(&params))?;
    (parameter.kind().as_ref() == "identifier").then_some(parameter)
}

fn minimum_length<'a>(closure: &N<'a>) -> Option<usize> {
    let parameter = closure_parameter(closure)?;
    let test = peel(closure.field("body")?)?;
    let left = test.field("left")?;
    let right = test.field("right")?;
    let operator = test.field("operator")?;
    let (length, count, direction) = if let Some(n) = literal(&right) {
        (left, n, operator.text())
    } else {
        let reversed = match operator.text().as_ref() {
            "<=" => ">=",
            "<" => ">",
            "==" => "==",
            _ => return None,
        };
        (right, literal(&left)?, std::borrow::Cow::Borrowed(reversed))
    };
    let (receiver, method) = rust_allocation::method(&length)?;
    if method != "len"
        || !arguments(&length)?.is_empty()
        || receiver.kind().as_ref() != "identifier"
        || receiver.text() != parameter.text()
    {
        return None;
    }
    match direction.as_ref() {
        "==" | ">=" => Some(count),
        ">" => count.checked_add(1),
        _ => None,
    }
}

impl<'a> Callers<'a> {
    pub(super) fn build(
        root: &N<'a>,
        enabled: &impl Fn(&N<'a>) -> bool,
        local_globs: &impl Fn(&N<'a>) -> Option<Vec<Capture>>,
    ) -> Self {
        let mut callers = Self::default();
        let mut names = BTreeSet::new();
        for map in root
            .dfs()
            .filter(|n| n.kind().as_ref() == "call_expression" && enabled(n))
        {
            let Some((iterator, name)) = rust_allocation::method(&map) else {
                continue;
            };
            if name != "map" {
                continue;
            }
            let Some([closure]) = arguments(&map).and_then(|args| <[_; 1]>::try_from(args).ok())
            else {
                continue;
            };
            let Some(parameter) = closure_parameter(&closure) else {
                continue;
            };
            let Some(call) = closure.field("body").and_then(peel) else {
                continue;
            };
            let Some(callee) = call.field("function") else {
                continue;
            };
            let Some(function) = enclosing_function(&map) else {
                continue;
            };
            let Some(reference) = callee
                .field("name")
                .or_else(|| (callee.kind().as_ref() == "identifier").then_some(callee.clone()))
            else {
                continue;
            };
            let Some((receiver, method)) = rust_allocation::method(&iterator) else {
                continue;
            };
            let (chunks, guard, lower) = if method == "filter" {
                let Some([guard]) =
                    arguments(&iterator).and_then(|args| <[_; 1]>::try_from(args).ok())
                else {
                    continue;
                };
                let Some(lower) = minimum_length(&guard) else {
                    continue;
                };
                (receiver, Some(guard), lower)
            } else {
                (iterator, None, 1)
            };
            let Some((buffer, method)) = rust_allocation::method(&chunks) else {
                continue;
            };
            if !matches!(method.as_str(), "chunks" | "chunks_exact") {
                continue;
            }
            let Some([width]) = arguments(&chunks).and_then(|args| <[_; 1]>::try_from(args).ok())
            else {
                continue;
            };
            let Some(width) = literal(&width).filter(|w| *w > 0) else {
                continue;
            };
            let Some(target) = definition(&call, &function, enabled, 0) else {
                continue;
            };
            let Some(target_name) = target.field("name") else {
                continue;
            };
            let Some((ty, buffer_declaration)) = declared_type(buffer, &function, enabled, 0)
            else {
                continue;
            };
            let Some((element, type_support)) = vector(root, &ty, local_globs).or_else(|| {
                let slice = slice_type(&ty)?;
                Some((
                    slice.field("element").or_else(|| slice.field("type"))?,
                    Vec::new(),
                ))
            }) else {
                continue;
            };
            if element.text() != "u8"
                || !enabled(&chunks)
                || guard.as_ref().is_some_and(|g| !enabled(g))
                || !rust_buffer_initialization::runtime_path(&map, &function)
            {
                continue;
            }
            let Some(args) = arguments(&call) else {
                continue;
            };
            for (index, arg) in args
                .iter()
                .enumerate()
                .filter(|(_, n)| n.kind().as_ref() == "identifier" && n.text() == parameter.text())
            {
                if !enabled(arg) {
                    continue;
                }
                let minimum = if method == "chunks_exact" {
                    width.max(lower)
                } else {
                    lower.max(1)
                };
                names.insert(target_name.text().into_owned());
                if let Some(module) = scope(&target) {
                    let range = module.range();
                    callers
                        .closed_scopes
                        .entry((range.start, range.end))
                        .or_insert_with(|| closed_scope(&module));
                }
                callers
                    .by_argument
                    .entry((target.range().start, index))
                    .or_default()
                    .push(ChunkCall {
                        name: reference.clone(),
                        call: call.clone(),
                        chunks: chunks.clone(),
                        buffer_declaration: buffer_declaration.clone(),
                        type_support: type_support.clone(),
                        guard: guard.clone(),
                        minimum,
                    });
            }
        }
        if !names.is_empty() {
            for reference in root.dfs().filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "identifier" | "field_identifier" | "type_identifier"
                ) && enabled(n)
            }) {
                if names.contains(reference.text().as_ref()) {
                    callers
                        .references
                        .entry(reference.text().into_owned())
                        .or_default()
                        .insert(reference.range().start);
                }
            }
        }
        callers
    }

    // Removing an intrinsic question requires a private, closed local caller
    // set. An unmodeled reference or a possible out-of-line caller keeps it.
    pub(super) fn assess(
        &self,
        function: &N<'a>,
        parameter: &N<'a>,
        required: usize,
        file: &SourceFile,
    ) -> Option<(bool, BTreeMap<String, Capture>)> {
        let params = function.field("parameters")?;
        let index = named(&params).position(|p| p.range() == parameter.range())?;
        let calls = self.by_argument.get(&(function.range().start, index))?;
        let name = function.field("name")?;
        let references = self.references.get(name.text().as_ref())?;
        let bounded = private(function)
            && calls.iter().all(|c| c.minimum >= required)
            && references.len() == calls.len() + 1
            && scope(function).is_some_and(|module| {
                let range = module.range();
                self.closed_scopes.get(&(range.start, range.end)) == Some(&true)
            });
        let mut captures = BTreeMap::new();
        for (index, site) in calls
            .iter()
            .filter(|c| c.minimum < required)
            .take(4)
            .enumerate()
        {
            for (role, node) in [
                ("chunk_caller", &site.call),
                ("chunk_iterator", &site.chunks),
                ("chunk_buffer_type", &site.buffer_declaration),
                ("chunk_callee_name", &site.name),
            ] {
                captures.insert(
                    format!("{role}_{index:02}"),
                    rust_dependencies::capture(file, node),
                );
            }
            if let Some(guard) = &site.guard {
                captures.insert(
                    format!("chunk_length_guard_{index:02}"),
                    rust_dependencies::capture(file, guard),
                );
            }
            for (part, capture) in site.type_support.iter().enumerate() {
                captures.insert(
                    format!("chunk_type_support_{index:02}_{part:02}"),
                    capture.clone(),
                );
            }
        }
        Some((bounded, captures))
    }
}

pub(super) fn required_length(operation: &N<'_>) -> Option<usize> {
    let index = if operation.kind().as_ref() == "index_expression" {
        named(operation).nth(1)?
    } else {
        let (get, _) = rust_allocation::method(operation)?;
        let [index]: [_; 1] = arguments(&get)?.try_into().ok()?;
        index
    };
    if let Some(index) = literal(&index) {
        return index.checked_add(1);
    }
    if index.kind().as_ref() != "range_expression" {
        return None;
    }
    let operator = index
        .children()
        .find(|n| matches!(n.text().as_ref(), ".." | "..="))?;
    let mut endpoints = named(&index);
    let first = endpoints.next()?;
    let end = if first.range().start < operator.range().start {
        let end = endpoints.next()?;
        if literal(&first)? > literal(&end)? {
            return None;
        }
        end
    } else {
        first
    };
    literal(&end)?.checked_add(usize::from(operator.text() == "..="))
}
