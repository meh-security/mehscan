//! Python review scope and deciding context. These facts never certify safety.
use super::*;
mod correlation;
mod selection;
mod value;

#[derive(Default)]
pub(super) struct OrmContext {
    by_anchor: BTreeMap<String, Vec<ReviewNeighborhoodFact>>,
    selection_by_anchor: BTreeMap<String, Vec<ReviewNeighborhoodFact>>,
    truncated: BTreeSet<String>,
}

struct Target {
    path: String,
    name: String,
    anchors: Vec<String>,
}

fn owner<'a>(node: &PyNode<'a>) -> Option<PyNode<'a>> {
    node.ancestors()
        .find(|n| n.kind().as_ref() == "function_definition")
}

fn context_fact(file: &SourceFile, node: &PyNode<'_>, role: &str) -> ReviewNeighborhoodFact {
    let function = owner(node);
    let scope = function.as_ref().map_or(node.range(), |n| n.range());
    let spans = line_spans(&file.source);
    let row = spans.partition_point(|(_, end)| *end <= node.range().start);
    let start = row.saturating_sub(6);
    let end = (row + 14).min(spans.len());
    let first = spans[start].0.max(scope.start);
    let last = spans[end.saturating_sub(1)].1.min(scope.end);
    ReviewNeighborhoodFact {
        role: role.into(), symbol: function.and_then(|n| n.field("name")).map_or_else(|| "module".into(), |n| n.text().into_owned()),
        location: location_from_offsets(&file.path, &file.source, first, last),
        excerpt: file.source[first..last].into(), evidence_id: None,
        provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Python ORM operation or uniquely bound direct caller; bounded syntax context, not execution, actor authenticity or authorization proof 1".into() },
    }
}

pub(super) fn module(path: &str) -> String {
    path.trim_end_matches(".py")
        .trim_end_matches("/__init__")
        .replace('/', ".")
}

pub(super) fn imported_module(path: &str, imported: &str) -> Option<String> {
    let dots = imported.bytes().take_while(|b| *b == b'.').count();
    if dots == 0 {
        return Some(imported.into());
    }
    let mut parts = path.trim_end_matches(".py").split('/').collect::<Vec<_>>();
    parts.pop();
    for _ in 1..dots {
        parts.pop()?;
    }
    let suffix = imported[dots..].trim();
    if !suffix.is_empty() {
        parts.extend(suffix.split('.'));
    }
    Some(parts.join("."))
}

fn unshadowed(root: &PyNode<'_>, call: &PyNode<'_>, name: &str) -> bool {
    !root.dfs().any(|n| {
        if owner(&n).is_some_and(|scope| {
            !(scope.range().start <= call.range().start && call.range().end <= scope.range().end)
        }) {
            return false;
        }
        let binding = match n.kind().as_ref() {
            "assignment" | "augmented_assignment" | "named_expression" => {
                n.field("left").or_else(|| n.field("name"))
            }
            "identifier"
                if n.parent()
                    .is_some_and(|p| p.kind().as_ref() == "parameters") =>
            {
                Some(n.clone())
            }
            "typed_parameter" | "default_parameter" => n
                .field("name")
                .or_else(|| n.children().find(|n| n.kind().as_ref() == "identifier")),
            "class_definition" => n.field("name"),
            _ => None,
        };
        binding.is_some_and(|b| b.text() == name)
    })
}

impl OrmContext {
    pub(super) fn build(
        sources: &RepositorySources,
        groups: &[ObservationGroup],
        evidence: &[Evidence],
    ) -> Self {
        let mut result = Self::default();
        let mut targets: BTreeMap<(String, String), Target> = BTreeMap::new();
        let mut per_file: BTreeMap<&str, Vec<&Evidence>> = BTreeMap::new();
        for group in groups {
            for e in group.evidence.iter().filter(|e| {
                e.rule_id == "python-django-orm-resource-access"
                    && group.anchor_evidence_ids.contains(&e.id)
            }) {
                per_file.entry(&e.location.path).or_default().push(e);
            }
        }
        for (path, anchors) in per_file {
            let Some(file) = sources.files.get(path) else {
                continue;
            };
            let Some(ast) = parse(file) else {
                continue;
            };
            let root = ast.root();
            let query_bindings = correlation::Bindings::build(&root);
            // Selected bundles may omit the deferred siblings. Use the raw
            // file evidence to retain the complete representative obligation.
            let all_anchors = evidence
                .iter()
                .filter(|e| {
                    e.location.path == path && e.rule_id == "python-django-orm-resource-access"
                })
                .collect::<Vec<_>>();
            let shared_chains = value::chains(&root, &all_anchors);
            for e in anchors {
                let Some(call) = root
                    .dfs()
                    .filter(|n| {
                        n.kind().as_ref() == "call"
                            && n.range().start <= e.location.start.byte_offset
                            && e.location.end.byte_offset <= n.range().end
                    })
                    .min_by_key(|n| n.range().len())
                else {
                    continue;
                };
                result
                    .by_anchor
                    .entry(e.id.clone())
                    .or_default()
                    .push(context_fact(file, &call, "python_orm_effect_context"));
                if let Some(chain) = shared_chains
                    .iter()
                    .find(|c| c.anchors.iter().any(|a| a.id == e.id))
                {
                    result.by_anchor.entry(e.id.clone()).or_default().push(ReviewNeighborhoodFact {
                        role: "python_orm_shared_chain_context".into(), symbol: "all selectors and terminal effect".into(),
                        location: location_from_offsets(&file.path, &file.source, chain.span.start, chain.span.end),
                        excerpt: file.source[chain.span.clone()].into(), evidence_id: Some(e.id.clone()),
                        provenance: QueryProvenance { resolution: Resolution::Ast, engine: format!("Python shared receiver-chain review 1; review all predicates and the terminal effect together; {} native selector questions share this complete expression; nested queries, caller authority and correlation remain unverified; no safe verdict transfer", chain.anchors.len()) },
                    });
                }
                let (mut facts, cut) = selection::facts(file, &call, e);
                let (query_facts, query_cut) = correlation::facts(file, &query_bindings, &call, e);
                facts.extend(query_facts);
                result.selection_by_anchor.insert(e.id.clone(), facts);
                if cut || query_cut {
                    result.truncated.insert(e.id.clone());
                }
                let Some(function) = owner(&call) else {
                    continue;
                };
                if function.ancestors().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "function_definition" | "class_definition"
                    )
                }) {
                    continue;
                }
                let Some(name) = function.field("name").map(|n| n.text().into_owned()) else {
                    continue;
                };
                if root
                    .dfs()
                    .filter(|n| {
                        n.kind().as_ref() == "function_definition"
                            && n.field("name").is_some_and(|n| n.text() == name)
                    })
                    .count()
                    != 1
                {
                    continue;
                }
                targets
                    .entry((module(path), name.clone()))
                    .or_insert_with(|| Target {
                        path: path.into(),
                        name,
                        anchors: Vec::new(),
                    })
                    .anchors
                    .push(e.id.clone());
            }
        }
        if targets.is_empty() {
            return result;
        }
        for file in sources
            .files
            .values()
            .filter(|f| f.language == Some(Language::Python))
        {
            // One parse per relevant caller file, not one repository walk per ORM site.
            if !targets.values().any(|t| file.source.contains(&t.name)) {
                continue;
            }
            let Some(ast) = parse(file) else {
                continue;
            };
            let root = ast.root();
            if root
                .dfs()
                .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
            {
                continue;
            }
            for call in root.dfs().filter(|n| n.kind().as_ref() == "call") {
                let Some(function) = call.field("function") else {
                    continue;
                };
                let called = function.text();
                let name = called
                    .strip_suffix(".delay")
                    .or_else(|| called.strip_suffix(".apply_async"))
                    .unwrap_or(&called);
                if !is_plain_identifier(name) || !unshadowed(&root, &call, name) {
                    continue;
                }
                let mut bindings = Vec::new();
                let mut import_count = 0;
                for import in root.dfs().filter(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "import_statement" | "import_from_statement"
                    )
                }) {
                    if owner(&import).is_some_and(|scope| {
                        !(scope.range().start <= call.range().start
                            && call.range().end <= scope.range().end)
                            || import.range().end > call.range().start
                    }) {
                        continue;
                    }
                    for imported in import.field_children("name") {
                        let original = imported.field("name").unwrap_or_else(|| imported.clone());
                        let alias = imported.field("alias").unwrap_or(imported);
                        if alias.text() != name {
                            continue;
                        }
                        import_count += 1;
                        if let Some(module_name) = import
                            .field("module_name")
                            .and_then(|n| imported_module(&file.path, n.text().as_ref()))
                        {
                            bindings.push((module_name, original.text().into_owned()));
                        }
                    }
                }
                if import_count == 0 {
                    bindings.push((module(&file.path), name.into()));
                }
                if bindings.len() != 1 || import_count > 1 {
                    continue;
                }
                let Some(target) = targets.get(&bindings[0]) else {
                    continue;
                };
                // An independently declared local callable replaces an imported binding.
                if file.path != target.path
                    && root.dfs().any(|n| {
                        n.kind().as_ref() == "function_definition"
                            && n.field("name").is_some_and(|n| n.text() == name)
                    })
                {
                    continue;
                }
                for anchor in &target.anchors {
                    let facts = result.by_anchor.get_mut(anchor).expect("target anchor");
                    if facts.len() >= 3 {
                        result.truncated.insert(anchor.clone());
                        continue;
                    }
                    let fact = context_fact(file, &call, "python_orm_caller_context");
                    if !facts.iter().any(|f| f.location == fact.location) {
                        facts.push(fact);
                    }
                }
            }
        }
        result
    }

    pub(super) fn facts(&self, group: &ObservationGroup) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let mut facts = Vec::new();
        let mut truncated = false;
        for id in &group.anchor_evidence_ids {
            truncated |= self.truncated.contains(id);
            for fact in self.by_anchor.get(id).into_iter().flatten() {
                if !facts
                    .iter()
                    .any(|f: &ReviewNeighborhoodFact| f.location == fact.location)
                {
                    facts.push(fact.clone());
                }
            }
            for fact in self.selection_by_anchor.get(id).into_iter().flatten() {
                if !facts.iter().any(|f| {
                    f.role == fact.role
                        && f.location == fact.location
                        && f.evidence_id == fact.evidence_id
                }) {
                    facts.push(fact.clone());
                }
            }
        }
        (facts, truncated)
    }
}

type PyNode<'a> = Node<'a, StrDoc<SupportLang>>;

fn quoted(text: &str) -> Option<&str> {
    let text = text.trim();
    if text.len() < 2 {
        return None;
    }
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || text.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let value = &text[1..text.len().checked_sub(1)?];
    (!value.contains(['\\', '\'', '"', '{', '}'])).then_some(value)
}

fn fixed_sql_string(text: &str) -> bool {
    let text = text.trim();
    if text.len() > 16 * 1024 {
        return false;
    }
    let Ok(doc) = StrDoc::try_new(text, SupportLang::Python) else {
        return false;
    };
    let ast = AstGrep::doc(doc);
    let root = ast.root();
    if root
        .dfs()
        .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
    {
        return false;
    }
    let statements = root.children().filter(|n| n.is_named()).collect::<Vec<_>>();
    let [statement] = statements.as_slice() else {
        return false;
    };
    if statement.kind().as_ref() != "expression_statement" {
        return false;
    }
    let Some(value) = statement.children().find(|n| n.is_named()) else {
        return false;
    };
    value.kind().as_ref() == "string"
        && !value.dfs().any(|n| {
            n.kind().as_ref() == "interpolation"
                || n.kind().as_ref() == "string_start"
                    && n.text()
                        .to_ascii_lowercase()
                        .split(['\'', '"'])
                        .next()
                        .is_some_and(|prefix| prefix.contains('b'))
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixed_sql_requires_one_text_literal_without_runtime_interpolation() {
        for value in [
            "'''CREATE TABLE t(x TEXT)'''",
            "\"SELECT 'quoted'\"",
            "r'SELECT 1'",
            "'SELECT \\n 1'",
        ] {
            assert!(super::fixed_sql_string(value), "{value}");
        }
        for value in [
            "query",
            "f'SELECT {name}'",
            "'SELECT ' + name",
            "b'SELECT 1'",
            "'unterminated",
            "'SELECT 1'; execute(other)",
        ] {
            assert!(!super::fixed_sql_string(value), "{value}");
        }
    }
}

pub(super) fn parse(file: &SourceFile) -> Option<AstGrep<StrDoc<SupportLang>>> {
    (file.language == Some(Language::Python)
        && file.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES)
        .then(|| StrDoc::try_new(&file.source, SupportLang::Python).ok())
        .flatten()
        .map(AstGrep::doc)
}

fn renderer(root: &PyNode<'_>, call: &PyNode<'_>) -> bool {
    let Some(function) = call.field("function") else {
        return false;
    };
    let symbol = function.text();
    if function.kind().as_ref() != "identifier" {
        return false;
    }
    let mut imports = 0;
    for node in root.dfs() {
        if node.kind().as_ref() == "import_from_statement"
            && node
                .field("module_name")
                .is_some_and(|m| m.text() == "flask")
        {
            if node
                .ancestors()
                .find(|n| n.kind().as_ref() == "function_definition")
                .is_some_and(|owner| {
                    !(owner.range().start <= call.range().start
                        && call.range().end <= owner.range().end)
                        || node.range().end > call.range().start
                })
            {
                continue;
            }
            for name in node.field_children("name") {
                let original = name.field("name").unwrap_or_else(|| name.clone());
                let binding = name.field("alias").unwrap_or(name);
                if original.text() == "render_template" && binding.text() == symbol {
                    imports += 1;
                }
            }
        }
        let binding = match node.kind().as_ref() {
            "assignment" | "augmented_assignment" | "named_expression" => {
                node.field("left").or_else(|| node.field("name"))
            }
            "function_definition" | "class_definition" => node.field("name"),
            "identifier"
                if node
                    .parent()
                    .is_some_and(|p| p.kind().as_ref() == "parameters") =>
            {
                Some(node.clone())
            }
            "typed_parameter" | "default_parameter" => node
                .field("name")
                .or_else(|| node.children().find(|n| n.kind().as_ref() == "identifier")),
            _ => None,
        };
        if binding.is_some_and(|n| n.text() == symbol) {
            return false;
        }
        // A second import with the same binding can replace the Flask callable.
        if matches!(
            node.kind().as_ref(),
            "import_statement" | "import_from_statement"
        ) {
            for name in node.field_children("name") {
                let binding = name.field("alias").unwrap_or_else(|| name.clone());
                if binding.text() == symbol
                    && !(node.kind().as_ref() == "import_from_statement"
                        && node
                            .field("module_name")
                            .is_some_and(|m| m.text() == "flask")
                        && name.field("name").unwrap_or_else(|| name.clone()).text()
                            == "render_template")
                {
                    return false;
                }
            }
        }
    }
    imports == 1
}

fn template_path(sources: &RepositorySources, view: &str, name: &str) -> Option<String> {
    if !valid_django_template_name(name) {
        return None;
    }
    let mut directory = Path::new(view).parent();
    while let Some(parent) = directory {
        let candidate = parent
            .join("templates")
            .join(name)
            .to_string_lossy()
            .replace('\\', "/");
        if sources.files.contains_key(&candidate) {
            return Some(candidate);
        }
        directory = parent.parent();
    }
    let suffix = format!("/templates/{name}");
    let matches = sources
        .files
        .keys()
        .filter(|p| p.ends_with(&suffix) || *p == &format!("templates/{name}"))
        .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches[0].clone())
}

// Deliberately small: dynamic attributes, filters, custom tags and template
// programs stay in Value. No HTML/JS/CSS equivalence is inferred from escaping.
fn escaped_text_template(
    sources: &RepositorySources,
    path: &str,
    visited: &mut BTreeSet<String>,
    bindings: &BTreeSet<String>,
) -> bool {
    if visited.len() >= 8 || !visited.insert(path.into()) {
        return false;
    }
    let Some(file) = sources.files.get(path) else {
        return false;
    };
    if file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
        return false;
    }
    let text = file.source.as_str();
    let lower = text.to_ascii_lowercase();
    let mut bindings = bindings.clone();
    // Preserve the relationship of supplied collections to simple loop aliases.
    // More elaborate template programs remain unresolved below.
    for _ in 0..8 {
        let old = bindings.len();
        for part in text
            .split("{%")
            .skip(1)
            .filter_map(|s| s.split_once("%}").map(|(s, _)| s.trim()))
        {
            if let Some(rest) = part.strip_prefix("for ") {
                let Some((alias, iterable)) = rest.split_once(" in ") else {
                    return false;
                };
                if bindings
                    .iter()
                    .any(|key| contains_identifier(iterable, key))
                {
                    if !is_plain_identifier(alias.trim())
                        || !iterable
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
                    {
                        return false;
                    }
                    bindings.insert(alias.trim().into());
                }
            }
        }
        if bindings.len() == old {
            break;
        }
    }
    let mut offset = 0;
    while let Some(at) = text[offset..].find("{{") {
        let at = offset + at;
        let Some(end) = text[at + 2..].find("}}") else {
            return false;
        };
        let end = at + 2 + end;
        let expression = text[at + 2..end].trim();
        if !bindings
            .iter()
            .any(|key| contains_identifier(expression, key))
        {
            offset = end + 2;
            continue;
        }
        if expression.is_empty()
            || !expression
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ' '))
        {
            return false;
        }
        let prefix = &lower[..at];
        if prefix.rfind('<') > prefix.rfind('>')
            || prefix.rfind("<script") > prefix.rfind("</script")
            || prefix.rfind("<style") > prefix.rfind("</style")
            || prefix.rfind("<!--") > prefix.rfind("-->")
        {
            return false;
        }
        offset = end + 2;
    }
    offset = 0;
    while let Some(at) = text[offset..].find("{%") {
        let at = offset + at;
        let Some(end) = text[at + 2..].find("%}") else {
            return false;
        };
        let end = at + 2 + end;
        let directive = text[at + 2..end].trim();
        let prefix = &lower[..at];
        if prefix.rfind('<') > prefix.rfind('>')
            || prefix.rfind("<script") > prefix.rfind("</script")
            || prefix.rfind("<style") > prefix.rfind("</style")
        {
            return false;
        }
        let (tag, value) = directive
            .split_once(char::is_whitespace)
            .unwrap_or((directive, ""));
        match tag {
            "extends" | "include" => {
                let Some(name) = quoted(value) else {
                    return false;
                };
                let Some(dependency) = template_path(sources, path, name) else {
                    return false;
                };
                if !escaped_text_template(sources, &dependency, visited, &bindings) {
                    return false;
                }
            }
            "if" | "elif" | "else" | "endif" | "for" | "endfor" | "block" | "endblock" => (),
            _ => return false,
        }
        offset = end + 2;
    }
    true
}

pub(super) fn apply_hints(
    entries: &mut [ReviewInventoryEntry],
    evidence: &[Evidence],
    sources: &RepositorySources,
) {
    value::apply(entries, evidence, sources);
    let by_id = evidence
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    for entry in entries.iter_mut().filter(|e| {
        matches!(
            e.rule_id.as_str(),
            "python-database-query" | "python-proved-dbapi-cursor-query"
        ) && e.value_hint.is_none()
    }) {
        let Some(anchor) = entry
            .identity
            .as_ref()
            .and_then(|i| by_id.get(i.anchor_id.as_str()))
        else {
            continue;
        };
        if anchor
            .captures
            .get("query")
            .is_some_and(|c| fixed_sql_string(&c.text))
        {
            entry.value_hint = Some(ValueReviewHint {
                reason: "python_fixed_sql_structure_research".into(), target: entry.path.clone(),
                assumption: "The selected query operand is a fixed Python string, independently of neighboring dynamic queries. Value defers this SQL grammar question; Comprehensive retains the operation and raw evidence. Driver binding, stored data, authorization and query effects are not certified safe.".into(), depends_on: None,
            });
        }
    }
    // Unknown custom environment/filter/loader policy is not a default renderer.
    if sources
        .files
        .values()
        .filter(|f| f.language == Some(Language::Python))
        .any(|f| {
            [
                "jinja_env",
                "jinja_options",
                "template_filter",
                "jinja_loader",
                "context_processor",
                "template_folder",
                "template_global",
                "add_template_global",
                "template_test",
                "pass_context",
                "pass_environment",
                "contextfunction",
                "environmentfunction",
            ]
            .iter()
            .any(|s| contains_identifier(&f.source, s))
                || ((f.source.contains("flask") || f.source.contains("jinja"))
                    && f.source.contains("autoescape"))
        })
    {
        return;
    }
    let by_id = evidence
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    let paths = entries
        .iter()
        .filter(|e| e.rule_id == "python-html-output" && e.value_hint.is_none())
        .map(|e| e.path.clone())
        .collect::<BTreeSet<_>>();
    for path in paths {
        let Some(file) = sources.files.get(&path) else {
            continue;
        };
        if ["Markup", "mark_safe", "__html__"]
            .iter()
            .any(|s| file.source.contains(s))
        {
            continue;
        }
        let Some(ast) = parse(file) else {
            continue;
        };
        let root = ast.root();
        if root
            .dfs()
            .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
        {
            continue;
        }
        for entry in entries.iter_mut().filter(|e| {
            e.path == path && e.rule_id == "python-html-output" && e.value_hint.is_none()
        }) {
            let Some(anchor) = entry
                .identity
                .as_ref()
                .and_then(|i| by_id.get(i.anchor_id.as_str()))
            else {
                continue;
            };
            let Some(template) = anchor
                .captures
                .get("template")
                .and_then(|c| quoted(&c.text))
            else {
                continue;
            };
            let Some(call) = root
                .dfs()
                .filter(|n| n.kind().as_ref() == "call")
                .find(|n| {
                    n.range().start <= anchor.location.start.byte_offset
                        && anchor.location.end.byte_offset <= n.range().end
                })
            else {
                continue;
            };
            if !renderer(&root, &call) {
                continue;
            }
            let owner = call
                .ancestors()
                .find(|n| n.kind().as_ref() == "function_definition")
                .unwrap_or_else(|| root.clone());
            if [
                "Markup",
                "mark_safe",
                "__html__",
                "setattr",
                "globals(",
                "locals(",
            ]
            .iter()
            .any(|s| owner.text().contains(s))
            {
                continue;
            }
            let Some(target) = template_path(sources, &path, template) else {
                continue;
            };
            let arguments = call
                .field("arguments")
                .map(|args| args.children().filter(|n| n.is_named()).collect::<Vec<_>>())
                .unwrap_or_default();
            if arguments.len() < 2
                || arguments
                    .iter()
                    .skip(1)
                    .any(|n| n.kind().as_ref() != "keyword_argument")
            {
                continue;
            }
            let bindings = arguments
                .iter()
                .skip(1)
                .filter_map(|n| n.field("name"))
                .map(|n| n.text().into_owned())
                .collect::<BTreeSet<_>>();
            if !escaped_text_template(sources, &target, &mut BTreeSet::new(), &bindings) {
                continue;
            }
            entry.value_hint = Some(ValueReviewHint {
                reason: "python_autoescaped_text_template_research".into(), target,
                assumption: "The uniquely imported Flask renderer selects a fixed .html template. In the discovered dependency graph, the explicitly supplied bindings and simple loop aliases occur only in ordinary escaped text expressions, or are unused. Value defers custom value/renderer provenance research; Comprehensive retains this exact operation and raw evidence. This is not a safe verdict or proof against custom __html__, external extensions or deployment overrides. Raw markup, active binding contexts and unresolved template programs stay in Value.".into(),
                depends_on: None,
            });
        }
    }
}
