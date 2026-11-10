//! Import-bound query expression navigation. SQL correlation is never inferred.
use super::selection::{binds, rebinds, receiver_expression, same_scope, target, value};
use super::*;

struct Binding {
    local: String,
    api: String,
    span: std::ops::Range<usize>,
}

#[derive(Default)]
pub(super) struct Bindings {
    imports: Vec<Binding>,
    counts: BTreeMap<String, usize>,
    blocked: BTreeSet<String>,
    wildcard: bool,
}

fn scope<'a>(node: &PyNode<'a>) -> Option<PyNode<'a>> {
    node.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_definition" | "class_definition" | "lambda"
        )
    })
}

fn import_names(node: &PyNode<'_>) -> Vec<String> {
    node.field_children("name")
        .map(|n| {
            n.field("alias")
                .unwrap_or(n)
                .text()
                .split('.')
                .next()
                .unwrap_or("")
                .into()
        })
        .collect()
}

impl Bindings {
    pub(super) fn build(root: &PyNode<'_>) -> Self {
        let mut result = Self::default();
        for node in root.dfs().filter(|n| scope(n).is_none()) {
            if matches!(
                node.kind().as_ref(),
                "import_statement" | "import_from_statement"
            ) {
                result.wildcard |= node
                    .children()
                    .any(|n| n.kind().as_ref() == "wildcard_import");
                for name in import_names(&node) {
                    *result.counts.entry(name).or_default() += 1;
                }
                if !node.parent().is_some_and(|n| n.kind().as_ref() == "module") {
                    continue;
                }
                let module = node.field("module_name").map(|n| n.text().into_owned());
                for name in node.field_children("name") {
                    let original = name
                        .field("name")
                        .unwrap_or_else(|| name.clone())
                        .text()
                        .into_owned();
                    let local = name
                        .field("alias")
                        .map_or_else(|| original.clone(), |n| n.text().into_owned());
                    let api = module
                        .as_ref()
                        .map_or_else(|| original.clone(), |m| format!("{m}.{original}"));
                    result.imports.push(Binding {
                        local,
                        api,
                        span: node.range(),
                    });
                }
            }
            if let Some(binding) = target(&node) {
                for name in binding.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                    result.blocked.insert(name.text().into_owned());
                }
            }
            if node.kind().as_ref() == "delete_statement" {
                for name in node.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                    result.blocked.insert(name.text().into_owned());
                }
            }
        }
        result
    }

    fn constructor<'a>(&self, call: &PyNode<'a>) -> Option<(&str, std::ops::Range<usize>)> {
        if self.wildcard {
            return None;
        }
        let name = call.field("function")?.text().into_owned();
        if !name.split('.').all(is_plain_identifier) {
            return None;
        }
        let prefix = name.split('.').next()?;
        if self.blocked.contains(prefix) || self.counts.get(prefix) != Some(&1) {
            return None;
        }
        let imports = self
            .imports
            .iter()
            .filter(|b| {
                name == b.local
                    || name
                        .strip_prefix(&b.local)
                        .is_some_and(|r| r.starts_with('.'))
            })
            .collect::<Vec<_>>();
        let [binding] = imports.as_slice() else {
            return None;
        };
        let full = format!("{}{}", binding.api, name.strip_prefix(&binding.local)?);
        let canonical = match full.as_str() {
            "django.db.models.Exists" | "django.db.models.expressions.Exists" => "Exists",
            "django.db.models.Subquery" | "django.db.models.expressions.Subquery" => "Subquery",
            "django.db.models.OuterRef" | "django.db.models.expressions.OuterRef" => "OuterRef",
            _ => return None,
        };
        for parent in call.ancestors() {
            if matches!(
                parent.kind().as_ref(),
                "lambda"
                    | "list_comprehension"
                    | "dictionary_comprehension"
                    | "set_comprehension"
                    | "generator_expression"
            ) {
                return None;
            }
            if parent.kind().as_ref() != "function_definition" {
                continue;
            }
            if parent.dfs().filter(|n| same_scope(n, &parent)).any(|n| {
                rebinds(&n, prefix)
                    || target(&n).is_some_and(|t| t.text().starts_with(&format!("{prefix}.")))
                    || n.kind().as_ref() == "identifier"
                        && n.text() == prefix
                        && n.parent()
                            .is_some_and(|p| p.kind().as_ref() == "parameters")
                    || matches!(
                        n.kind().as_ref(),
                        "typed_parameter"
                            | "default_parameter"
                            | "typed_default_parameter"
                            | "list_splat_pattern"
                            | "dictionary_splat_pattern"
                    ) && n
                        .field("name")
                        .or_else(|| n.children().find(|n| n.kind().as_ref() == "identifier"))
                        .is_some_and(|n| n.text() == prefix)
            }) {
                return None;
            }
        }
        Some((canonical, binding.span.clone()))
    }
}

struct Packet<'a> {
    file: &'a SourceFile,
    anchor: &'a Evidence,
    facts: Vec<ReviewNeighborhoodFact>,
    truncated: bool,
}

impl Packet<'_> {
    fn add(&mut self, span: std::ops::Range<usize>, role: &str, symbol: &str, detail: &str) {
        if self.facts.iter().any(|f| {
            f.role == role
                && f.location.start.byte_offset == span.start
                && f.location.end.byte_offset == span.end
        }) {
            return;
        }
        if self.facts.len() >= 16 {
            self.truncated = true;
            return;
        }
        let text = &self.file.source[span.clone()];
        let bytes = text
            .split_inclusive('\n')
            .take(40)
            .map(str::len)
            .sum::<usize>()
            .min(4096);
        let end = floor_char_boundary(&self.file.source, span.start + bytes);
        self.truncated |= end < span.end;
        self.facts.push(ReviewNeighborhoodFact {
            role: role.into(), symbol: symbol.into(),
            location: location_from_offsets(&self.file.path, &self.file.source, span.start, end),
            excerpt: self.file.source[span.start..end].into(), evidence_id: Some(self.anchor.id.clone()),
            provenance: QueryProvenance { resolution: Resolution::Ast, engine: format!("Python import-bound query expression navigation 1; {detail}; source syntax only, not SQL scope, reaching-definition, row identity, shared-witness correlation, authorization or execution proof") },
        });
    }
}

fn reference(node: &PyNode<'_>, expression: &PyNode<'_>) -> bool {
    if node.kind().as_ref() != "identifier" {
        return false;
    }
    if node.parent().is_some_and(|p| {
        p.kind().as_ref() == "attribute"
            && p.field("attribute")
                .is_some_and(|n| n.range() == node.range())
            || p.kind().as_ref() == "keyword_argument"
                && p.field("name").is_some_and(|n| n.range() == node.range())
            || p.kind().as_ref() == "call"
                && p.field("function")
                    .is_some_and(|n| n.range() == node.range())
    }) {
        return false;
    }
    node.range() == expression.range()
        || !node
            .ancestors()
            .take_while(|n| n.range() != expression.range())
            .any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "lambda"
                        | "function_definition"
                        | "class_definition"
                        | "list_comprehension"
                        | "dictionary_comprehension"
                        | "set_comprehension"
                        | "generator_expression"
                )
            })
}

pub(super) fn facts<'a>(
    file: &SourceFile,
    bindings: &Bindings,
    call: &PyNode<'a>,
    anchor: &Evidence,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let Some(function) = owner(call) else {
        return (Vec::new(), false);
    };
    if function
        .dfs()
        .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
    {
        return (Vec::new(), false);
    }
    // An ORM anchor can be the whole positional Exists expression. Retain the
    // surrounding selector and sibling predicates, rather than isolating that
    // one argument and losing the query it constrains.
    let enclosing = std::iter::once(call.clone())
        .chain(call.ancestors())
        .filter(|n| {
            n.kind().as_ref() == "call"
                && same_scope(n, &function)
                && n.field("function")
                    .and_then(|f| f.field("attribute"))
                    .is_some_and(|m| {
                        matches!(
                            m.text().as_ref(),
                            "filter" | "exclude" | "annotate" | "get" | "update" | "delete"
                        )
                    })
        })
        .last()
        .unwrap_or_else(|| call.clone());
    let expression = receiver_expression(&enclosing);
    let mut pending = vec![(expression.clone(), 0)];
    let mut seen = BTreeSet::new();
    let mut definitions = Vec::new();
    let mut constructors = BTreeMap::new();
    let mut cut = false;
    while let Some((expression, depth)) = pending.pop() {
        for node in expression.dfs().filter(|n| n.kind().as_ref() == "call") {
            if let Some((name, import)) = bindings.constructor(&node) {
                constructors.insert((node.range().start, node.range().end), (node, name, import));
            }
        }
        for use_node in expression.dfs().filter(|n| reference(n, &expression)) {
            let name = use_node.text();
            let mut origins = function
                .dfs()
                .filter(|n| {
                    same_scope(n, &function)
                        && n.range().end <= use_node.range().start
                        && value(n).is_some()
                        && target(n).is_some_and(|t| binds(&t, &name))
                })
                .collect::<Vec<_>>();
            origins.sort_by_key(|n| n.range().start);
            cut |= origins.len() > 2;
            for origin in origins.into_iter().rev().take(2) {
                if !seen.insert((origin.range().start, origin.range().end)) {
                    continue;
                }
                if depth >= 4 || definitions.len() >= 8 {
                    cut = true;
                    continue;
                }
                if let Some(rhs) = value(&origin) {
                    pending.push((rhs, depth + 1));
                }
                definitions.push((origin, name.clone().into_owned(), use_node.range()));
            }
        }
    }
    if !constructors
        .values()
        .any(|(_, name, _)| matches!(*name, "Exists" | "Subquery"))
    {
        return (Vec::new(), false);
    }
    let mut packet = Packet {
        file,
        anchor,
        facts: Vec::new(),
        truncated: cut,
    };
    packet.add(expression.range(), "python_orm_query_context", "receiver expression", "enclosing receiver expression, including separate predicates and surrounding operators; separate Exists inputs do not establish one shared related row");
    let mut imports = BTreeSet::new();
    let mut predicates = Vec::new();
    let mut outer_refs = Vec::new();
    for (_, (node, name, import)) in constructors {
        imports.insert((import.start, import.end));
        if name == "OuterRef" {
            outer_refs.push(node);
        } else {
            predicates.push((node, name));
        }
    }
    packet.truncated |= imports.len() > 2 || predicates.len() > 4 || outer_refs.len() > 6;
    for (start, end) in imports.into_iter().take(2) {
        packet.add(start..end, "python_orm_query_import_context", "Django expressions", "unique direct import spelling; observed rebinding/shadowing is rejected, runtime monkeypatching remains open");
    }
    for (node, name) in predicates.into_iter().take(4) {
        let span = node
            .parent()
            .filter(|n| n.kind().as_ref() == "unary_operator")
            .unwrap_or(node)
            .range();
        packet.add(span, "python_orm_query_predicate_context", name, "independent import-bound query expression occurrence; inspect its own input and outer-reference nesting, not neighboring predicate names");
    }
    for node in outer_refs.into_iter().take(6) {
        packet.add(node.range(), "python_orm_outer_reference_context", "OuterRef", "import-bound outer-reference spelling; enclosing query level, nested OuterRef and field/model meaning are unresolved");
    }
    definitions.sort_by_key(|(n, _, _)| n.range().start);
    for (node, name, use_span) in definitions {
        packet.add(node.range(), "python_orm_query_binding_context", &name, &format!("prior lexical input binding candidate referenced at bytes {}..{}; branches, rebinding and helper/collection semantics can change the actual query", use_span.start, use_span.end));
    }
    (packet.facts, packet.truncated)
}
