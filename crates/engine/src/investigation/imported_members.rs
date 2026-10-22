//! Bounded source navigation through explicit JS/TS imports, not a call graph.
use super::*;
use std::ops::Range;

#[derive(Default)]
pub(super) struct Cache {
    files: BTreeMap<String, Option<FileIndex>>,
}

struct FileIndex {
    imports: BTreeMap<String, (String, Option<String>)>,
    uses: Vec<(String, String, Range<usize>)>,
    blocked: BTreeSet<String>,
    mutated: BTreeSet<String>,
    locals: BTreeMap<String, Declaration>,
    exports: BTreeMap<String, Export>,
}

#[derive(Clone)]
enum Declaration {
    Callable(Range<usize>),
    Members(BTreeMap<String, Member>),
}

#[derive(Clone)]
enum Member {
    Body(Range<usize>),
    Local(String),
}

enum Export {
    Local(String),
    Inline(Declaration),
}

fn callable(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "function"
            | "generator_function"
            | "arrow_function"
    )
}

fn declaration(node: &Node<'_, StrDoc<SupportLang>>) -> Option<Declaration> {
    if callable(node) {
        return Some(Declaration::Callable(node.range()));
    }
    let class = matches!(node.kind().as_ref(), "class" | "class_declaration");
    let body = if class {
        node.field("body")?
    } else {
        node.clone()
    };
    if !class && body.kind().as_ref() != "object" {
        return None;
    }
    let mut members = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for child in body.children().filter(|n| n.is_named()) {
        // Spreads and computed keys make the object's member identity ambiguous.
        if matches!(child.kind().as_ref(), "spread_element") {
            return None;
        }
        if class && !child.text().trim_start().starts_with("static ") {
            continue;
        }
        if child.kind().as_ref() == "method_definition"
            && child
                .children()
                .any(|part| matches!(part.kind().as_ref(), "get" | "set"))
        {
            return None;
        }
        if let Some(key) = child
            .field("key")
            .or_else(|| child.field("name"))
            .or_else(|| {
                (child.kind().as_ref() == "shorthand_property_identifier").then(|| child.clone())
            })
        {
            if !matches!(key.kind().as_ref(), "identifier" | "property_identifier")
                && key.kind().as_ref() != "shorthand_property_identifier"
                || !keys.insert(key.text().into_owned())
            {
                return None;
            }
        }
        let (name, value) = match child.kind().as_ref() {
            "method_definition" => (child.field("name")?, Member::Body(child.range())),
            "pair" | "public_field_definition" => {
                let name = child.field("key").or_else(|| child.field("name"))?;
                let value = child.field("value")?;
                let value = if value.kind().as_ref() == "identifier" {
                    Member::Local(value.text().into_owned())
                } else if callable(&value) || value.kind().as_ref() == "array" {
                    Member::Body(child.range())
                } else {
                    continue;
                };
                (name, value)
            }
            "shorthand_property_identifier" => {
                (child.clone(), Member::Local(child.text().into_owned()))
            }
            _ => continue,
        };
        if !matches!(
            name.kind().as_ref(),
            "property_identifier" | "identifier" | "shorthand_property_identifier"
        ) {
            return None;
        }
        if members.insert(name.text().into_owned(), value).is_some() {
            return None;
        }
    }
    Some(Declaration::Members(members))
}

fn record_locals(
    node: &Node<'_, StrDoc<SupportLang>>,
    locals: &mut BTreeMap<String, Declaration>,
) -> Vec<String> {
    let mut names = Vec::new();
    let nodes = if matches!(
        node.kind().as_ref(),
        "lexical_declaration" | "variable_declaration"
    ) {
        node.children()
            .filter(|n| n.kind().as_ref() == "variable_declarator")
            .collect::<Vec<_>>()
    } else {
        vec![node.clone()]
    };
    for node in nodes {
        let Some(name) = node
            .field("name")
            .filter(|n| matches!(n.kind().as_ref(), "identifier" | "type_identifier"))
        else {
            continue;
        };
        let value = node.field("value").unwrap_or_else(|| node.clone());
        if let Some(definition) = declaration(&value) {
            let name = name.text().into_owned();
            names.push(name.clone());
            locals.insert(name, definition);
        }
    }
    names
}

fn identifiers(node: &Node<'_, StrDoc<SupportLang>>, names: &mut BTreeSet<String>) {
    for id in node.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "identifier" | "shorthand_property_identifier_pattern"
        )
    }) {
        names.insert(id.text().into_owned());
    }
}

impl FileIndex {
    fn build(file: &SourceFile) -> Option<Self> {
        let language = file.language?;
        if !matches!(
            language,
            Language::Javascript | Language::Typescript | Language::Tsx
        ) || file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        {
            return None;
        }
        let ast = AstGrep::doc(StrDoc::try_new(&file.source, parser_language(language)).ok()?);
        let root = ast.root();
        let mut index = Self {
            imports: BTreeMap::new(),
            uses: Vec::new(),
            blocked: BTreeSet::new(),
            mutated: BTreeSet::new(),
            locals: BTreeMap::new(),
            exports: BTreeMap::new(),
        };
        for node in root.children().filter(|n| n.is_named()) {
            match node.kind().as_ref() {
                "import_statement" => {
                    if node.text().trim_start().starts_with("import type ") {
                        continue;
                    }
                    let Some(source) = node.field("source") else {
                        continue;
                    };
                    let source_text = source.text();
                    let Some(module) = first_quoted_value(source_text.as_ref()) else {
                        continue;
                    };
                    for clause in node
                        .children()
                        .filter(|n| n.kind().as_ref() == "import_clause")
                    {
                        for part in clause.children().filter(|n| n.is_named()) {
                            if part.kind().as_ref() == "identifier" {
                                index.imports.insert(
                                    part.text().into_owned(),
                                    (module.to_string(), Some("default".into())),
                                );
                            } else if part.kind().as_ref() == "namespace_import" {
                                if let Some(binding) =
                                    part.children().find(|n| n.kind().as_ref() == "identifier")
                                {
                                    index.imports.insert(
                                        binding.text().into_owned(),
                                        (module.to_string(), None),
                                    );
                                }
                            } else if part.kind().as_ref() == "named_imports" {
                                for specifier in part
                                    .children()
                                    .filter(|n| n.kind().as_ref() == "import_specifier")
                                {
                                    if specifier.text().trim_start().starts_with("type ") {
                                        continue;
                                    }
                                    if let Some(name) = specifier.field("name") {
                                        let binding = specifier
                                            .field("alias")
                                            .unwrap_or_else(|| name.clone());
                                        index.imports.insert(
                                            binding.text().into_owned(),
                                            (module.to_string(), Some(name.text().into_owned())),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                "export_statement" => {
                    // Re-exports/barrels need another binding edge; leave them to lookup.
                    if node.field("source").is_some() {
                        continue;
                    }
                    let default = node.text().trim_start().starts_with("export default ");
                    if let Some(value) = node.field("declaration").or_else(|| node.field("value")) {
                        let names = record_locals(&value, &mut index.locals);
                        if default {
                            if value.kind().as_ref() == "identifier" {
                                index.exports.insert(
                                    "default".into(),
                                    Export::Local(value.text().into_owned()),
                                );
                            } else if let Some(decl) = declaration(&value) {
                                index.exports.insert("default".into(), Export::Inline(decl));
                            }
                        } else {
                            for name in names {
                                index.exports.insert(name.clone(), Export::Local(name));
                            }
                        }
                    }
                    for clause in node
                        .children()
                        .filter(|n| n.kind().as_ref() == "export_clause")
                    {
                        for specifier in clause
                            .children()
                            .filter(|n| n.kind().as_ref() == "export_specifier")
                        {
                            if let Some(name) = specifier.field("name") {
                                let alias =
                                    specifier.field("alias").unwrap_or_else(|| name.clone());
                                index.exports.insert(
                                    alias.text().into_owned(),
                                    Export::Local(name.text().into_owned()),
                                );
                            }
                        }
                    }
                }
                _ => {
                    record_locals(&node, &mut index.locals);
                }
            }
        }
        for node in root.dfs() {
            match node.kind().as_ref() {
                "ERROR" | "with_statement" => return None,
                "member_expression" => {
                    if let Some(object) = node
                        .field("object")
                        .filter(|n| n.kind().as_ref() == "identifier")
                        && let Some(property) = node
                            .field("property")
                            .filter(|n| n.kind().as_ref() == "property_identifier")
                    {
                        index.uses.push((
                            object.text().into_owned(),
                            property.text().into_owned(),
                            node.range(),
                        ));
                    }
                }
                "variable_declarator" => {
                    if let Some(name) = node.field("name") {
                        identifiers(&name, &mut index.blocked);
                    }
                }
                "function_declaration" | "function_expression" | "class_declaration" | "class" => {
                    if let Some(name) = node.field("name") {
                        identifiers(&name, &mut index.blocked);
                    }
                }
                "assignment_expression"
                | "augmented_assignment_expression"
                | "update_expression" => {
                    if let Some(left) = node.field("left").or_else(|| node.field("argument")) {
                        identifiers(&left, &mut index.blocked);
                        identifiers(&left, &mut index.mutated);
                    }
                }
                "call_expression" => {
                    if node
                        .field("function")
                        .is_some_and(|n| n.text().as_ref() == "eval")
                    {
                        return None;
                    }
                }
                _ => {}
            }
            if node.is_missing() {
                return None;
            }
            if let Some(parameters) = node.field("parameters").or_else(|| node.field("parameter")) {
                identifiers(&parameters, &mut index.blocked);
            }
        }
        Some(index)
    }

    fn member(&self, export: Option<&str>, member: &str) -> Option<Range<usize>> {
        let exported = self.exports.get(export.unwrap_or(member))?;
        let declaration = match exported {
            Export::Local(name) if !self.mutated.contains(name) => self.locals.get(name)?,
            Export::Local(_) => return None,
            Export::Inline(value) => value,
        };
        match declaration {
            Declaration::Callable(range) if export.is_none() => Some(range.clone()),
            Declaration::Members(members) if export.is_some() => match members.get(member)? {
                Member::Body(range) => Some(range.clone()),
                Member::Local(name) if !self.mutated.contains(name) => {
                    match self.locals.get(name)? {
                        Declaration::Callable(range) => Some(range.clone()),
                        _ => None,
                    }
                }
                Member::Local(_) => None,
            },
            _ => None,
        }
    }
}

impl Cache {
    fn file(&mut self, file: &SourceFile) -> Option<&FileIndex> {
        self.files
            .entry(file.path.clone())
            .or_insert_with(|| FileIndex::build(file))
            .as_ref()
    }

    pub(super) fn definitions(
        &mut self,
        sources: &RepositorySources,
        paths: &BTreeSet<&str>,
        references: &BTreeSet<String>,
        scopes: &[&Location],
        limit: usize,
    ) -> (Vec<OutlineSymbol>, bool) {
        if scopes.is_empty() || limit == 0 {
            return (Vec::new(), false);
        }
        let mut targets = BTreeSet::new();
        for path in paths {
            let Ok(file) = sources.file(path) else {
                continue;
            };
            let Some(index) = self.file(file) else {
                continue;
            };
            for (binding, member, range) in &index.uses {
                if !references.contains(member)
                    || index.blocked.contains(binding)
                    || !scopes.iter().any(|location| {
                        location.path == *path
                            && location.start.byte_offset <= range.start
                            && location.end.byte_offset >= range.end
                    })
                {
                    continue;
                }
                if let Some((module, export)) = index.imports.get(binding) {
                    targets.insert((
                        member.clone(),
                        file.path.clone(),
                        module.clone(),
                        export.clone(),
                    ));
                }
            }
        }
        let mut result = Vec::new();
        let mut targets = targets.into_iter().collect::<Vec<_>>();
        targets.sort_by(|a, b| {
            reference_priority(&b.0)
                .cmp(&reference_priority(&a.0))
                .then_with(|| a.cmp(b))
        });
        let mut truncated = targets.len() > limit.saturating_mul(2);
        // Bound target resolution as well as packet size. No recursive library walk.
        for (member, caller, module, export) in targets.into_iter().take(limit.saturating_mul(2)) {
            let Some(path) = resolve_relative_typescript_module(&caller, &module, sources) else {
                continue;
            };
            let Ok(file) = sources.file(&path) else {
                continue;
            };
            let Some(index) = self.file(file) else {
                continue;
            };
            let Some(range) = index.member(export.as_deref(), &member) else {
                continue;
            };
            let location = location_from_offsets(&path, &file.source, range.start, range.end);
            if result
                .iter()
                .any(|s: &OutlineSymbol| s.location == location)
            {
                continue;
            }
            result.push(OutlineSymbol {
                name: member,
                symbol_type: "imported_member".into(),
                signature: bounded_line_text(&file.source[range.clone()]),
                ast_kind: "declared_imported_member".into(),
                location,
                parent: export,
                is_import: false,
                is_exported: true,
                is_public: None,
            });
        }
        result.sort_by(|a, b| {
            let clipped = |s: &OutlineSymbol| {
                s.location.end.line.saturating_sub(s.location.start.line)
                    >= MAX_REVIEW_HELPER_LINES - 1
            };
            clipped(a)
                .cmp(&clipped(b))
                .then_with(|| reference_priority(&b.name).cmp(&reference_priority(&a.name)))
        });
        truncated |= result.len() > limit;
        result.truncate(limit);
        (result, truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_members_follow_exports_not_same_named_neighbors() {
        let caller = "import Local from './policy';\nimport * as NS from './policy';\nimport { output as Renderer, Api } from './policy';\nfunction handle(req) {\n Local.permit(req); Local.short(req); Local.clean(req); NS.direct(req); Renderer.encode(req); Api.write(req);\n}\n";
        let provider = "function run(req) { return rejectUnlessOwner(req); }\nconst unrelated = { permit(req) { return allowAnyone(req); } };\nconst policy = { permit(req) { return rejectUnlessOwner(req); }, short: run, clean: (req) => sanitize(req) };\nexport default policy;\nexport const output = { encode(req) { return escapeHtml(req); } };\nexport function direct(req) { return check(req); }\nexport class Api { static write(req) { return save(req); } instance(req) { return save(req); } }\n";
        let file = |path: &str, source: &str| SourceFile {
            path: path.into(),
            language: Some(Language::Typescript),
            source: source.into(),
        };
        let sources = RepositorySources {
            node_modules: Default::default(),
            root: "fixture".into(),
            files: BTreeMap::from([
                ("route.ts".into(), file("route.ts", caller)),
                ("policy.ts".into(), file("policy.ts", provider)),
                (
                    "unrelated.ts".into(),
                    file("unrelated.ts", "export const permit = () => allowAnyone()"),
                ),
            ]),
        };
        let paths = BTreeSet::from(["route.ts"]);
        let references = [
            "permit", "short", "clean", "direct", "encode", "write", "instance",
        ]
        .map(str::to_string)
        .into_iter()
        .collect();
        let existing = vec![ReviewNeighborhoodFact {
            role: "sink_context".into(),
            symbol: "handle".into(),
            location: location_from_offsets("route.ts", caller, 0, caller.len()),
            excerpt: caller.into(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        }];
        let context = ReviewContextIndex::build(&sources, &references).unwrap();
        let (facts, _) = observation_helper_definition_facts(
            &sources,
            &context,
            &paths,
            &references,
            &existing,
            Some(&existing[0].location),
            8,
        );
        for name in ["permit", "short", "clean", "direct", "encode", "write"] {
            let fact = facts
                .iter()
                .find(|fact| fact.symbol == name)
                .unwrap_or_else(|| panic!("missing {name}: {facts:?}"));
            assert_eq!(fact.location.path, "policy.ts");
            assert!(!fact.excerpt.contains("allowAnyone"));
        }
        assert!(!facts.iter().any(|fact| fact.symbol == "instance"));
        assert_eq!(context.imported_members.borrow().files.len(), 2);
        let again = observation_helper_definition_facts(
            &sources,
            &context,
            &paths,
            &references,
            &existing,
            Some(&existing[0].location),
            8,
        );
        assert_eq!(facts, again.0);
        assert_eq!(context.imported_members.borrow().files.len(), 2);
        // A surrounding source window may include other routes/calls. Only
        // members inside the exact selected operation supply its context.
        let start = caller.find("Local.permit").unwrap();
        let scope = location_from_offsets("route.ts", caller, start, start + "Local.permit".len());
        let (narrow, _) = context.imported_members.borrow_mut().definitions(
            &sources,
            &paths,
            &references,
            &[&scope],
            8,
        );
        assert_eq!(
            narrow.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            vec!["permit"]
        );

        let mut shadowed = sources;
        shadowed
            .files
            .get_mut("route.ts")
            .unwrap()
            .source
            .push_str("function other(Local) { Local.permit({}); }\n");
        let context = ReviewContextIndex::build(&shadowed, &references).unwrap();
        let (facts, _) = observation_helper_definition_facts(
            &shadowed,
            &context,
            &paths,
            &references,
            &existing,
            Some(&existing[0].location),
            8,
        );
        assert!(
            !facts
                .iter()
                .any(|fact| ["permit", "short", "clean"].contains(&fact.symbol.as_str()))
        );
        assert!(facts.iter().any(|fact| fact.symbol == "encode"));
        for ambiguous in [
            "const policy = { permit(req) { return check(req); }, permit: 0 }; export default policy;",
            "const policy = { permit(req) { return check(req); }, [key]: other }; export default policy;",
            "const policy = { permit(req) { return check(req); }, ...other }; export default policy;",
            "const policy = { permit(req) { return check(req); } }; policy.permit = other; export default policy;",
            "const policy = { get permit() { return other; } }; export default policy;",
        ] {
            let index = FileIndex::build(&file("policy.ts", ambiguous)).unwrap();
            assert!(
                index.member(Some("default"), "permit").is_none(),
                "{ambiguous}"
            );
        }
    }
}
