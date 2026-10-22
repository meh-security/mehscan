//! Exact immutable application constants, not a configuration trust model.
//! Parse only files with selected operands and their resolved export targets,
//! once each. Unknown expressions, shadows and writes never close a question.
use super::*;

#[derive(Clone)]
enum TextPart {
    Literal(String),
    Import(String),
}

#[derive(Default)]
struct FileFacts {
    imports: BTreeMap<String, (String, String)>,
    exports: BTreeMap<String, (Option<String>, String)>,
    strings: BTreeMap<String, String>,
    operands: BTreeMap<(usize, usize), Vec<TextPart>>,
    fetch_operands: BTreeSet<(usize, usize)>,
    data_yaml: BTreeSet<(usize, usize)>,
}

type Ast<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn exclusions(evidence: &[Evidence], sources: &RepositorySources) -> BTreeSet<String> {
    let mut cache = BTreeMap::<String, FileFacts>::new();
    let mut excluded = BTreeSet::new();
    for item in evidence.iter().filter(|e| e.kind == EvidenceKind::Sink) {
        let role = if item.capability == Capability::OutboundNetworkRequest
            && item.cwe_candidates == ["CWE-918"]
            && !has_known_string_literal(item, "endpoint")
            && !has_fixed_http_authority(item)
            && item
                .symbol_resolution
                .as_ref()
                .is_some_and(|s| s.canonical == "fetch")
            && !item.tags.iter().any(|tag| {
                matches!(
                    tag.as_str(),
                    "outbound-request:unresolved-client-options"
                        | "request-authority-after-hook-unresolved"
                )
            }) {
            "endpoint"
        } else if matches!(
            item.rule_id.as_str(),
            "javascript-yaml-deserialization"
                | "typescript-yaml-deserialization"
                | "tsx-yaml-deserialization"
        ) && item
            .symbol_resolution
            .as_ref()
            .is_some_and(|s| s.canonical == "js-yaml.load")
        {
            "payload"
        } else {
            continue;
        };
        let Some(capture) = item.captures.get(role) else {
            continue;
        };
        let Some(file) = sources.files.get(&item.location.path) else {
            continue;
        };
        let facts = cache
            .entry(file.path.clone())
            .or_insert_with(|| inspect(file));
        if role == "payload" {
            if facts.data_yaml.contains(&(
                item.location.start.byte_offset,
                item.location.end.byte_offset,
            )) {
                excluded.insert(item.id.clone());
            }
            continue;
        }
        if !facts.fetch_operands.contains(&(
            capture.location.start.byte_offset,
            capture.location.end.byte_offset,
        )) {
            continue;
        }
        let Some(parts) = facts
            .operands
            .get(&(
                capture.location.start.byte_offset,
                capture.location.end.byte_offset,
            ))
            .cloned()
        else {
            continue;
        };
        let imports = facts.imports.clone();
        let mut value = String::new();
        let mut complete = true;
        for part in parts {
            match part {
                TextPart::Literal(text) => value.push_str(&text),
                TextPart::Import(name) => {
                    let resolved = imports.get(&name).and_then(|(module, export)| {
                        let path = resolve_relative_typescript_module(&file.path, module, sources)?;
                        exported_string(&path, export, sources, &mut cache, 0)
                    });
                    if let Some(text) = resolved {
                        value.push_str(&text);
                    } else {
                        complete = false;
                        break;
                    }
                }
            }
        }
        // Full URL only: no prefix inference across unknown suffixes or
        // environment values. Matches the existing exact-literal admission.
        if complete && (value.starts_with("https://") || value.starts_with("http://")) {
            excluded.insert(item.id.clone());
        }
    }
    excluded
}

fn exported_string(
    path: &str,
    name: &str,
    sources: &RepositorySources,
    cache: &mut BTreeMap<String, FileFacts>,
    depth: usize,
) -> Option<String> {
    if depth >= 8 {
        return None;
    }
    let file = sources.files.get(path)?;
    let facts = cache
        .entry(path.to_string())
        .or_insert_with(|| inspect(file));
    let (module, local) = facts.exports.get(name)?.clone();
    if let Some(module) = module {
        let target = resolve_relative_typescript_module(path, &module, sources)?;
        return exported_string(&target, &local, sources, cache, depth + 1);
    }
    if let Some(value) = facts.strings.get(&local) {
        return Some(value.clone());
    }
    let (module, imported) = facts.imports.get(&local)?.clone();
    let target = resolve_relative_typescript_module(path, &module, sources)?;
    exported_string(&target, &imported, sources, cache, depth + 1)
}

fn inspect(file: &SourceFile) -> FileFacts {
    let mut facts = FileFacts::default();
    let Some(language @ (Language::Javascript | Language::Typescript | Language::Tsx)) =
        file.language
    else {
        return facts;
    };
    if file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
        return facts;
    }
    let Ok(document) = StrDoc::try_new(&file.source, parser_language(language)) else {
        return facts;
    };
    let ast = AstGrep::doc(document);
    let root = ast.root();
    if root
        .dfs()
        .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
    {
        return facts;
    }
    let mut counts = BTreeMap::<String, usize>::new();
    let mut blocked = BTreeSet::new();
    for node in root.dfs() {
        match node.kind().as_ref() {
            "import_statement" => {
                if node.children().any(|n| n.kind().as_ref() == "type") {
                    continue;
                }
                let Some(module) = node.field("source").and_then(|n| plain_string(&n)) else {
                    continue;
                };
                for specifier in node
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "import_specifier")
                {
                    if specifier.children().any(|n| n.kind().as_ref() == "type") {
                        continue;
                    }
                    let Some(name) = specifier.field("name") else {
                        continue;
                    };
                    let alias = specifier.field("alias").unwrap_or_else(|| name.clone());
                    *counts.entry(alias.text().into_owned()).or_default() += 1;
                    facts.imports.insert(
                        alias.text().into_owned(),
                        (module.clone(), name.text().into_owned()),
                    );
                }
                if let Some(clause) = node
                    .children()
                    .find(|n| n.kind().as_ref() == "import_clause")
                {
                    for binding in clause
                        .children()
                        .filter(|n| matches!(n.kind().as_ref(), "identifier" | "namespace_import"))
                    {
                        let name = if binding.kind().as_ref() == "identifier" {
                            Some(binding)
                        } else {
                            binding
                                .children()
                                .find(|n| n.kind().as_ref() == "identifier")
                        };
                        if let Some(name) = name {
                            *counts.entry(name.text().into_owned()).or_default() += 1;
                            facts
                                .imports
                                .insert(name.text().into_owned(), (module.clone(), "*".into()));
                        }
                    }
                }
            }
            "variable_declarator" => {
                if let Some(name) = node.field("name") {
                    for identifier in name.dfs().filter(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "identifier" | "shorthand_property_identifier_pattern"
                        )
                    }) {
                        *counts.entry(identifier.text().into_owned()).or_default() += 1;
                    }
                    if name.kind().as_ref() == "identifier"
                        && node.parent().is_some_and(|n| {
                            n.kind().as_ref() == "lexical_declaration"
                                && n.children().any(|n| n.kind().as_ref() == "const")
                        })
                        && !node
                            .ancestors()
                            .any(|n| matches!(n.kind().as_ref(), "statement_block" | "class_body"))
                        && let Some(value) = node.field("value").and_then(|n| plain_string(&n))
                    {
                        facts.strings.insert(name.text().into_owned(), value);
                    }
                }
            }
            "formal_parameters" | "required_parameter" | "optional_parameter" => {
                for name in node.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                    blocked.insert(name.text().into_owned());
                }
            }
            "arrow_function" => {
                if let Some(name) = node.field("parameter") {
                    blocked.insert(name.text().into_owned());
                }
            }
            "function_declaration" | "class_declaration" | "catch_clause" => {
                if let Some(name) = node.field("name").or_else(|| node.field("parameter")) {
                    blocked.insert(name.text().into_owned());
                }
            }
            "assignment_expression" | "augmented_assignment_expression" | "update_expression" => {
                if let Some(left) = node.field("left").or_else(|| node.field("argument")) {
                    for name in left.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                        blocked.insert(name.text().into_owned());
                    }
                }
            }
            _ => {}
        }
    }
    let allowed = |name: &str| !blocked.contains(name) && counts.get(name) == Some(&1);
    facts.imports.retain(|name, _| allowed(name));
    facts.strings.retain(|name, _| allowed(name));
    // Explicit ESM exports only. Star ambiguity, CommonJS objects and dynamic
    // module behavior remain unresolved instead of expanding the analysis.
    for statement in root
        .children()
        .filter(|n| n.kind().as_ref() == "export_statement")
    {
        if statement.children().any(|n| n.kind().as_ref() == "type") {
            continue;
        }
        let module = statement.field("source").and_then(|n| plain_string(&n));
        if let Some(clause) = statement
            .children()
            .find(|n| n.kind().as_ref() == "export_clause")
        {
            for specifier in clause
                .children()
                .filter(|n| n.kind().as_ref() == "export_specifier")
            {
                if specifier.children().any(|n| n.kind().as_ref() == "type") {
                    continue;
                }
                let Some(name) = specifier.field("name") else {
                    continue;
                };
                let alias = specifier.field("alias").unwrap_or_else(|| name.clone());
                facts.exports.insert(
                    alias.text().into_owned(),
                    (module.clone(), name.text().into_owned()),
                );
            }
        } else if let Some(declaration) = statement.field("declaration") {
            for variable in declaration
                .children()
                .filter(|n| n.kind().as_ref() == "variable_declarator")
            {
                if let Some(name) = variable
                    .field("name")
                    .filter(|n| n.kind().as_ref() == "identifier")
                {
                    facts
                        .exports
                        .insert(name.text().into_owned(), (None, name.text().into_owned()));
                }
            }
        }
    }
    // Only call operands are indexed; no recursive per-sink repository walks.
    for call in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        let Some(arguments) = call.field("arguments") else {
            continue;
        };
        let args = arguments
            .children()
            .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
            .collect::<Vec<_>>();
        if let Some(endpoint) = args.first()
            && let Some(parts) = text_parts(endpoint, &facts, &mut 64)
        {
            facts
                .operands
                .insert((endpoint.range().start, endpoint.range().end), parts);
            if call.field("function").is_some_and(|n| n.text() == "fetch")
                && !counts.contains_key("fetch")
                && !blocked.contains("fetch")
                && args.len() <= 2
                && args.get(1).is_none_or(fetch_data_options)
            {
                facts
                    .fetch_operands
                    .insert((endpoint.range().start, endpoint.range().end));
            }
        }
        if args.len() == 2
            && call
                .field("function")
                .is_some_and(|callee| yaml_loader(&callee, &facts))
            && data_schema(&args[1], &facts)
        {
            facts
                .data_yaml
                .insert((call.range().start, call.range().end));
        }
    }
    facts
}

fn yaml_loader(callee: &Ast<'_>, facts: &FileFacts) -> bool {
    if callee.kind().as_ref() == "identifier" {
        return facts
            .imports
            .get(callee.text().as_ref())
            .is_some_and(|(module, name)| module == "js-yaml" && name == "load");
    }
    callee.kind().as_ref() == "member_expression"
        && callee.field("property").is_some_and(|n| n.text() == "load")
        && callee.field("object").is_some_and(|object| {
            facts
                .imports
                .get(object.text().as_ref())
                .is_some_and(|(module, name)| module == "js-yaml" && name == "*")
        })
}

fn fetch_data_options(options: &Ast<'_>) -> bool {
    options.kind().as_ref() == "object"
        && options
            .children()
            .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
            .all(|entry| {
                entry.kind().as_ref() == "pair"
                    && entry.field("key").is_some_and(|key| {
                        matches!(
                            key.text().as_ref(),
                            "method"
                                | "headers"
                                | "body"
                                | "signal"
                                | "credentials"
                                | "mode"
                                | "cache"
                                | "redirect"
                                | "integrity"
                                | "referrer"
                                | "referrerPolicy"
                                | "keepalive"
                        )
                    })
            })
}

fn plain_string(node: &Ast<'_>) -> Option<String> {
    let text = node.text();
    if node.kind().as_ref() != "string" || text.contains('\\') {
        return None;
    }
    complete_quoted_literal_contents(&text).map(str::to_string)
}

fn text_parts(node: &Ast<'_>, facts: &FileFacts, work: &mut usize) -> Option<Vec<TextPart>> {
    if *work == 0 {
        return None;
    }
    *work -= 1;
    if let Some(text) = plain_string(node) {
        return Some(vec![TextPart::Literal(text)]);
    }
    match node.kind().as_ref() {
        "identifier" => {
            let name = node.text();
            if let Some(value) = facts.strings.get(name.as_ref()) {
                Some(vec![TextPart::Literal(value.clone())])
            } else if facts.imports.contains_key(name.as_ref()) {
                Some(vec![TextPart::Import(name.into_owned())])
            } else {
                None
            }
        }
        "binary_expression" if node.field("operator").is_some_and(|n| n.text() == "+") => {
            let mut left = text_parts(&node.field("left")?, facts, work)?;
            left.extend(text_parts(&node.field("right")?, facts, work)?);
            Some(left)
        }
        "template_string" | "template_substitution" => {
            let mut parts = Vec::new();
            for child in node.children().filter(|n| n.is_named()) {
                if child.kind().as_ref() == "string_fragment" && !child.text().contains('\\') {
                    parts.push(TextPart::Literal(child.text().into_owned()));
                } else {
                    parts.extend(text_parts(&child, facts, work)?);
                }
            }
            Some(parts)
        }
        _ => None,
    }
}

fn data_schema(options: &Ast<'_>, facts: &FileFacts) -> bool {
    if options.kind().as_ref() != "object" {
        return false;
    }
    let entries = options
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
        .collect::<Vec<_>>();
    let [entry] = entries.as_slice() else {
        return false;
    };
    if entry.kind().as_ref() != "pair" || entry.field("key").is_none_or(|n| n.text() != "schema") {
        return false;
    }
    let Some(value) = entry.field("value") else {
        return false;
    };
    let (binding, schema) = if value.kind().as_ref() == "identifier" {
        let Some((module, name)) = facts.imports.get(value.text().as_ref()) else {
            return false;
        };
        return module == "js-yaml"
            && matches!(
                name.as_str(),
                "JSON_SCHEMA" | "FAILSAFE_SCHEMA" | "CORE_SCHEMA"
            );
    } else if value.kind().as_ref() == "member_expression" {
        let (Some(object), Some(property)) = (value.field("object"), value.field("property"))
        else {
            return false;
        };
        (object.text().into_owned(), property.text().into_owned())
    } else {
        return false;
    };
    facts
        .imports
        .get(&binding)
        .is_some_and(|(module, name)| module == "js-yaml" && name == "*")
        && matches!(
            schema.as_str(),
            "JSON_SCHEMA" | "FAILSAFE_SCHEMA" | "CORE_SCHEMA"
        )
}
