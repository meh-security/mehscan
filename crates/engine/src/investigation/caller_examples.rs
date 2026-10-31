//! Selected caller examples, not a project call graph or a taint proof.
//! Only three same-file positional forwarding edges and one imported consumer.
use super::*;
use crate::code::node_modules::{ImportMode, ModuleTarget};
use std::ops::Range;
type N<'a> = ast_grep_core::Node<'a, StrDoc<SupportLang>>;

#[derive(Default)]
pub(super) struct Examples {
    cache: BTreeMap<(String, usize, String), (Vec<ReviewNeighborhoodFact>, bool)>,
}

impl Examples {
    pub(super) fn facts(
        &mut self,
        sources: &RepositorySources,
        e: &Evidence,
        existing: &[ReviewNeighborhoodFact],
    ) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let role = match e.capability {
            Capability::OutboundNetworkRequest => "endpoint",
            Capability::DatabaseQuery => "query",
            Capability::FilesystemRead | Capability::FilesystemWrite => "path",
            Capability::ProcessExecution => "command",
            _ => return (Vec::new(), false),
        };
        let Some(operand) = e.captures.get(role) else {
            return (Vec::new(), false);
        };
        if !is_plain_identifier(operand.text.trim()) {
            return (Vec::new(), false);
        }
        let key = (
            e.location.path.clone(),
            e.location.start.byte_offset,
            role.to_string(),
        );
        let (facts, cut) = self
            .cache
            .entry(key)
            .or_insert_with(|| build(sources, e, operand.text.trim()));
        (
            facts
                .iter()
                .filter(|f| !facts_cover_location(existing, &f.location))
                .cloned()
                .collect(),
            *cut,
        )
    }
}

fn callable(n: &N<'_>) -> bool {
    matches!(
        n.kind().as_ref(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function_declaration"
    )
}
fn arguments<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.field("arguments")
        .map(|a| {
            a.children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .collect()
        })
        .unwrap_or_default()
}
fn identifier_parameter(n: &N<'_>) -> Option<String> {
    let n = if n.kind().as_ref() == "required_parameter" {
        n.field("pattern")?
    } else {
        n.clone()
    };
    (n.kind().as_ref() == "identifier").then(|| n.text().into_owned())
}
struct Function<'a> {
    name: String,
    node: N<'a>,
    params: Vec<Option<String>>,
}
#[derive(Clone)]
struct Reach {
    name: String,
    param: usize,
    bridges: Vec<Range<usize>>,
}
fn function_index<'a>(root: &N<'a>) -> Vec<Function<'a>> {
    root.dfs()
        .filter(callable)
        .filter(|n| {
            !n.ancestors()
                .any(|a| callable(&a) || a.kind().as_ref() == "method_definition")
        })
        .filter_map(|n| {
            let name = n.field("name").or_else(|| {
                n.parent()
                    .filter(|p| p.kind().as_ref() == "variable_declarator")
                    .and_then(|p| p.field("name"))
            })?;
            if name.kind().as_ref() != "identifier" {
                return None;
            }
            let params = n
                .field("parameters")
                .map(|p| {
                    p.children()
                        .filter(|c| c.is_named())
                        .map(|p| identifier_parameter(&p))
                        .collect()
                })
                .unwrap_or_default();
            Some(Function {
                name: name.text().into_owned(),
                node: n,
                params,
            })
        })
        .collect()
}
fn unique<'a, 'b>(functions: &'b [Function<'a>], name: &str) -> Option<&'b Function<'a>> {
    let mut found = functions.iter().filter(|f| f.name == name);
    let first = found.next()?;
    found.next().is_none().then_some(first)
}
fn rewritten(function: &Function<'_>, name: &str) -> bool {
    function.node.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "assignment_expression" | "augmented_assignment_expression" | "update_expression"
        ) && n
            .field("left")
            .or_else(|| n.field("argument"))
            .is_some_and(|p| p.text().trim() == name)
    })
}
fn target_exports(root: &N<'_>, states: &[Reach]) -> BTreeMap<String, Reach> {
    let mut out = BTreeMap::new();
    for statement in root
        .children()
        .filter(|n| n.kind().as_ref() == "export_statement")
    {
        if statement.field("source").is_some()
            || statement.children().any(|n| n.kind().as_ref() == "type")
        {
            continue;
        }
        if let Some(clause) = statement
            .children()
            .find(|n| n.kind().as_ref() == "export_clause")
        {
            for spec in clause
                .children()
                .filter(|n| n.kind().as_ref() == "export_specifier")
                .filter(|n| !n.children().any(|c| c.kind().as_ref() == "type"))
            {
                if let Some(name) = spec.field("name") {
                    if let Some(state) = states.iter().find(|s| s.name == name.text().as_ref()) {
                        let alias = spec.field("alias").unwrap_or(name);
                        out.insert(alias.text().into_owned(), state.clone());
                    }
                }
            }
        } else if let Some(decl) = statement
            .field("declaration")
            .or_else(|| statement.field("value"))
        {
            let default = statement.children().any(|n| n.kind().as_ref() == "default");
            let names = if let Some(name) = decl.field("name") {
                vec![name]
            } else if decl.kind().as_ref() == "identifier" {
                vec![decl]
            } else {
                decl.children()
                    .filter(|n| n.kind().as_ref() == "variable_declarator")
                    .filter_map(|n| n.field("name"))
                    .collect()
            };
            for name in names {
                if let Some(state) = states.iter().find(|s| s.name == name.text().as_ref()) {
                    out.insert(
                        if default {
                            "default".into()
                        } else {
                            name.text().into_owned()
                        },
                        state.clone(),
                    );
                }
            }
        }
    }
    // Explicit CommonJS function exports, not arbitrary object interpretation.
    for n in root.dfs().filter(|n| {
        n.kind().as_ref() == "assignment_expression" && !n.ancestors().any(|p| callable(&p))
    }) {
        let (Some(left), Some(right)) = (n.field("left"), n.field("right")) else {
            continue;
        };
        if right.kind().as_ref() != "identifier" {
            continue;
        }
        let text = left.text();
        let exported = if text.as_ref() == "module.exports" {
            Some("default")
        } else {
            text.strip_prefix("exports.")
                .or_else(|| text.strip_prefix("module.exports."))
        };
        if let (Some(exported), Some(state)) = (
            exported,
            states.iter().find(|s| s.name == right.text().as_ref()),
        ) {
            out.insert(exported.into(), state.clone());
        }
    }
    out
}

fn owned_exports(
    sources: &RepositorySources,
    module: &str,
    target: &str,
    exports: &BTreeMap<String, Reach>,
    depth: usize,
) -> BTreeMap<String, Reach> {
    if module == target {
        return exports.clone();
    }
    if depth > 1 {
        return BTreeMap::new();
    }
    let Ok(file) = sources.file(module) else {
        return BTreeMap::new();
    };
    let Some(language) = file.language else {
        return BTreeMap::new();
    };
    if file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES || !file.source.contains("export ") {
        return BTreeMap::new();
    }
    let Ok(doc) = StrDoc::try_new(&file.source, parser_language(language)) else {
        return BTreeMap::new();
    };
    let ast = AstGrep::doc(doc);
    let root = ast.root();
    let mut out = BTreeMap::new();
    let mut duplicate = BTreeSet::new();
    for statement in root
        .children()
        .filter(|n| n.kind().as_ref() == "export_statement")
    {
        if statement.children().any(|n| n.kind().as_ref() == "type") {
            continue;
        }
        let Some(source) = statement.field("source") else {
            continue;
        };
        let specifier = source.text();
        let ModuleTarget::Source(path) = sources.node_modules.resolve(
            module,
            specifier.trim_matches(['\'', '"']),
            ImportMode::Import,
        ) else {
            continue;
        };
        let child = owned_exports(sources, &path, target, exports, depth + 1);
        let mut insert = |name: String, state: Reach| {
            if out.insert(name.clone(), state).is_some() {
                duplicate.insert(name);
            }
        };
        if let Some(clause) = statement
            .children()
            .find(|n| n.kind().as_ref() == "export_clause")
        {
            for spec in clause
                .children()
                .filter(|n| n.kind().as_ref() == "export_specifier")
                .filter(|n| !n.children().any(|c| c.kind().as_ref() == "type"))
            {
                let Some(name) = spec.field("name") else {
                    continue;
                };
                if let Some(state) = child.get(name.text().as_ref()) {
                    insert(
                        spec.field("alias").unwrap_or(name).text().into_owned(),
                        state.clone(),
                    );
                }
            }
        } else if statement.children().any(|n| n.kind().as_ref() == "*") {
            for (name, state) in child {
                if name != "default" {
                    insert(name, state)
                }
            }
        }
    }
    for name in duplicate {
        out.remove(&name);
    }
    out
}

fn module_exports(
    sources: &RepositorySources,
    file: &SourceFile,
    specifier: &str,
    mode: ImportMode,
    target: &str,
    exports: &BTreeMap<String, Reach>,
    cache: &mut BTreeMap<String, BTreeMap<String, Reach>>,
) -> BTreeMap<String, Reach> {
    let ModuleTarget::Source(path) = sources.node_modules.resolve(&file.path, specifier, mode)
    else {
        return BTreeMap::new();
    };
    cache
        .entry(path.clone())
        .or_insert_with(|| owned_exports(sources, &path, target, exports, 0))
        .clone()
}
fn imports(
    root: &N<'_>,
    sources: &RepositorySources,
    file: &SourceFile,
    target: &str,
    exports: &BTreeMap<String, Reach>,
    cache: &mut BTreeMap<String, BTreeMap<String, Reach>>,
) -> BTreeMap<String, Reach> {
    let mut out = BTreeMap::new();
    for n in root
        .children()
        .filter(|n| n.kind().as_ref() == "import_statement")
    {
        if n.children().any(|n| n.kind().as_ref() == "type") {
            continue;
        }
        let Some(source) = n.field("source") else {
            continue;
        };
        let owned = module_exports(
            sources,
            file,
            source.text().trim_matches(['\'', '"']),
            ImportMode::Import,
            target,
            exports,
            cache,
        );
        if owned.is_empty() {
            continue;
        }
        for c in n.dfs() {
            match c.kind().as_ref() {
                "import_specifier" if !c.children().any(|n| n.kind().as_ref() == "type") => {
                    if let Some(name) = c.field("name") {
                        if let Some(state) = owned.get(name.text().as_ref()) {
                            out.insert(
                                c.field("alias").unwrap_or(name).text().into_owned(),
                                state.clone(),
                            );
                        }
                    }
                }
                "namespace_import" => {
                    if let Some(name) = c.children().find(|n| n.kind().as_ref() == "identifier") {
                        for (export, state) in &owned {
                            out.insert(format!("{}.{export}", name.text()), state.clone());
                        }
                    }
                }
                "identifier"
                    if c.parent()
                        .is_some_and(|p| p.kind().as_ref() == "import_clause") =>
                {
                    if let Some(state) = owned.get("default") {
                        out.insert(c.text().into_owned(), state.clone());
                    }
                }
                _ => {}
            }
        }
    }
    for n in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "variable_declarator")
    {
        let (Some(name), Some(value)) = (n.field("name"), n.field("value")) else {
            continue;
        };
        if value.kind().as_ref() != "call_expression"
            || value
                .field("function")
                .is_none_or(|n| n.text().trim() != "require")
        {
            continue;
        }
        let arguments = arguments(&value);
        let [source] = arguments.as_slice() else {
            continue;
        };
        if source.kind().as_ref() != "string" {
            continue;
        }
        let owned = module_exports(
            sources,
            file,
            source.text().trim_matches(['\'', '"']),
            ImportMode::Require,
            target,
            exports,
            cache,
        );
        match name.kind().as_ref() {
            "identifier" => {
                if let Some(state) = owned.get("default") {
                    out.insert(name.text().into_owned(), state.clone());
                }
                for (export, state) in &owned {
                    if export != "default" {
                        out.insert(format!("{}.{export}", name.text()), state.clone());
                    }
                }
            }
            "object_pattern" => {
                for property in name.children().filter(|p| p.is_named()) {
                    let (key, visible) = if property.kind().as_ref() == "pair_pattern" {
                        (property.field("key"), property.field("value"))
                    } else {
                        (Some(property.clone()), Some(property))
                    };
                    if let (Some(key), Some(visible)) = (key, visible) {
                        if let Some(state) = owned.get(key.text().as_ref()) {
                            out.insert(visible.text().into_owned(), state.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn caller_binding(root: &N<'_>, call: &N<'_>, name: &str) -> bool {
    let head = name.split('.').next().unwrap_or(name);
    let Some(callee) = call.field("function") else {
        return false;
    };
    let mut id = callee;
    while let Some(object) = id.field("object") {
        id = object;
    }
    if !crate::code::stable_js_import_binding(root, &id) {
        return false;
    }
    if call
        .ancestors()
        .filter(|n| callable(n) || n.kind().as_ref() == "catch_clause")
        .filter_map(|n| n.field("parameters").or_else(|| n.field("parameter")))
        .any(|p| {
            p.dfs()
                .any(|n| n.kind().as_ref() == "identifier" && n.text().as_ref() == head)
        })
    {
        return false;
    }
    !root.dfs().any(|n| {
        n.kind().as_ref() == "function_declaration"
            && n.field("name").is_some_and(|p| p.text().as_ref() == head)
            && n.ancestors()
                .find(|p| p.kind().as_ref() == "statement_block" || p.kind().as_ref() == "program")
                .is_some_and(|s| s.range().contains(&call.range().start))
    })
}
fn fact(
    file: &SourceFile,
    range: Range<usize>,
    role: &str,
    symbol: String,
) -> ReviewNeighborhoodFact {
    ReviewNeighborhoodFact {
        role: role.into(),
        symbol,
        location: location_from_offsets(&file.path, &file.source, range.start, range.end),
        excerpt: file.source[range].into(),
        evidence_id: None,
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "bounded resolved incoming caller and observed parameter position; example only, not taint, execution, complete caller coverage or authorization proof 1".into(),
        },
    }
}

fn build(
    sources: &RepositorySources,
    e: &Evidence,
    operand: &str,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let Ok(file) = sources.file(&e.location.path) else {
        return (Vec::new(), false);
    };
    let Some(language) = file.language.filter(|l| {
        matches!(
            l,
            Language::Javascript | Language::Typescript | Language::Tsx
        )
    }) else {
        return (Vec::new(), false);
    };
    if file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
        return (Vec::new(), true);
    }
    let Ok(doc) = StrDoc::try_new(&file.source, parser_language(language)) else {
        return (Vec::new(), true);
    };
    let ast = AstGrep::doc(doc);
    let root = ast.root();
    let Some(local) = resource_helpers::LocalHelpers::build(file) else {
        return (Vec::new(), true);
    };
    let functions = function_index(&root);
    let Some(owner) = functions
        .iter()
        .filter(|f| f.node.range().contains(&e.location.start.byte_offset))
        .min_by_key(|f| f.node.range().len())
    else {
        return (Vec::new(), false);
    };
    let Some(param) = owner
        .params
        .iter()
        .position(|p| p.as_deref() == Some(operand))
    else {
        return (Vec::new(), false);
    };
    if rewritten(owner, operand) {
        return (Vec::new(), false);
    }
    let calls = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
        .map(|n| ((n.range().start, n.range().end), n))
        .collect::<BTreeMap<_, _>>();
    let mut states = vec![Reach {
        name: owner.name.clone(),
        param,
        bridges: vec![],
    }];
    let mut seen = BTreeSet::from([(owner.name.clone(), param)]);
    let mut at = 0;
    let mut cut = false;
    while at < states.len() && states.len() < 24 {
        let state = states[at].clone();
        at += 1;
        if state.bridges.len() >= 3 {
            continue;
        }
        let Some(target) = unique(&functions, &state.name) else {
            continue;
        };
        for (range, _) in local
            .calls()
            .filter(|(_, definition)| **definition == target.node.range())
        {
            let Some(call) = calls.get(&(range.start, range.end)) else {
                continue;
            };
            let Some(parent) = functions.iter().find(|f| {
                call.ancestors()
                    .find(callable)
                    .is_some_and(|n| n.range() == f.node.range())
            }) else {
                continue;
            };
            let args = arguments(call);
            let Some(arg) = args
                .get(state.param)
                .filter(|n| n.kind().as_ref() == "identifier")
            else {
                continue;
            };
            let Some(param) = parent
                .params
                .iter()
                .position(|p| p.as_deref() == Some(arg.text().as_ref()))
            else {
                continue;
            };
            if rewritten(parent, arg.text().as_ref()) || !seen.insert((parent.name.clone(), param))
            {
                continue;
            }
            let mut bridges = vec![range.clone()];
            bridges.extend(state.bridges.clone());
            states.push(Reach {
                name: parent.name.clone(),
                param,
                bridges,
            });
            if states.len() >= 24 {
                cut = true;
                break;
            }
        }
    }
    let exports = target_exports(&root, &states);
    if exports.is_empty() {
        return (Vec::new(), cut);
    }
    let mut needles = exports
        .keys()
        .filter(|n| n.as_str() != "default")
        .cloned()
        .collect::<Vec<_>>();
    if let Some(stem) = std::path::Path::new(&file.path)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !matches!(*s, "index" | "main"))
    {
        needles.push(stem.into());
    }
    let mut dir = std::path::Path::new(&file.path).parent();
    while let Some(parent) = dir {
        let manifest = parent
            .join("package.json")
            .to_string_lossy()
            .replace('\\', "/");
        if let Ok(package) = sources.file(&manifest) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&package.source) {
                if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
                    needles.push(name.into());
                    break;
                }
            }
        }
        dir = parent.parent();
    }
    let mut facts = Vec::new();
    let mut bridges = BTreeSet::new();
    let mut module_cache = BTreeMap::new();
    let mut inspected = 0;
    for caller in sources.files.values().filter(|f| {
        f.path != file.path
            && matches!(
                f.language,
                Some(Language::Javascript | Language::Typescript | Language::Tsx)
            )
            && !is_nonproduction_review_context_path(&f.path)
    }) {
        if !needles.iter().any(|name| caller.source.contains(name))
            || !caller.source.contains("import") && !caller.source.contains("require")
        {
            continue;
        }
        if inspected >= 64 {
            cut = true;
            break;
        }
        inspected += 1;
        if caller.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
            cut = true;
            continue;
        }
        let Ok(doc) = StrDoc::try_new(&caller.source, parser_language(caller.language.unwrap()))
        else {
            cut = true;
            continue;
        };
        let caller_ast = AstGrep::doc(doc);
        let caller_root = caller_ast.root();
        if caller_root
            .dfs()
            .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
        {
            cut = true;
            continue;
        }
        let imports = imports(
            &caller_root,
            sources,
            caller,
            &file.path,
            &exports,
            &mut module_cache,
        );
        if imports.is_empty() {
            continue;
        }
        for call in caller_root
            .dfs()
            .filter(|n| n.kind().as_ref() == "call_expression")
        {
            let Some(callee) = call.field("function") else {
                continue;
            };
            let observed = callee
                .text()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>();
            let Some(state) = imports.get(&observed) else {
                continue;
            };
            if !caller_binding(&caller_root, &call, &observed)
                || arguments(&call).get(state.param).is_none()
            {
                continue;
            }
            let location = location_from_offsets(
                &caller.path,
                &caller.source,
                call.range().start,
                call.range().end,
            );
            let start = location.start.line.saturating_sub(3).max(1);
            let end = location.end.line + 1;
            let range = source_slice(caller, start, end)
                .ok()
                .filter(|(s, _)| s.text.len() <= 512)
                .map(|(s, _)| s.location.start.byte_offset..s.location.end.byte_offset)
                .unwrap_or_else(|| call.range());
            let mut example = fact(
                caller,
                range,
                "caller_context",
                format!("{observed} argument {} -> {}", state.param + 1, owner.name),
            );
            if example.excerpt.len() > 512 {
                example.excerpt.clear();
                cut = true;
            }
            facts.push(example);
            for range in &state.bridges {
                bridges.insert((range.start, range.end));
            }
            break; // source diversity: at most one example per consumer file
        }
        if facts.len() == 3 {
            cut = true;
            break;
        }
    }
    if !facts.is_empty() {
        cut |= bridges.len() > 3;
        for (start, end) in bridges.into_iter().take(3) {
            facts.push(fact(
                file,
                start..end,
                "caller_bridge_context",
                "observed local forwarding call; inspect producer and transformations".into(),
            ));
        }
    }
    (facts, cut)
}
