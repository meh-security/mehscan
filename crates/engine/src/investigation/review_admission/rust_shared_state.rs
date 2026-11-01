//! Local read/check/increment/write questions; no route or atomicity verdict.
//! Macro token trees are source leads, never reparsed as resolved database AST.
use super::*;
use ast_grep_core::Node;
use ast_grep_language::SupportLang;

type AstNode<'a> = Node<'a, StrDoc<SupportLang>>;
const RULE: &str = "rust-shared-state-limit-review-marker";

#[derive(Default)]
struct FileIndex {
    module: String,
    imports: Vec<(String, String, bool)>,
    types: BTreeSet<String>,
}

struct Method {
    definition: Capture,
    name: String,
    returns_self: bool,
    writes_self: bool,
    reads: bool,
    delegates: Vec<String>,
    macro_backed: bool,
}

#[derive(Default)]
struct Index {
    files: BTreeMap<String, FileIndex>,
    modules: BTreeMap<String, Vec<String>>,
    methods: BTreeMap<(String, String), Vec<Method>>,
    rejecting_macros: BTreeMap<String, Vec<Capture>>,
}

fn compact(text: &str) -> String {
    text.split_whitespace().collect()
}

fn module(path: &str) -> String {
    let (prefix, tail) = path.strip_prefix("src/").map_or_else(
        || path.split_once("/src/").unwrap_or(("", path)),
        |tail| ("", tail),
    );
    let tail = tail.trim_end_matches(".rs");
    let mut parts = tail.split('/').collect::<Vec<_>>();
    if parts.last() == Some(&"mod") || (parts.len() == 1 && matches!(parts[0], "lib" | "main")) {
        parts.pop();
    }
    format!(
        "{prefix}@crate{}",
        if parts.is_empty() {
            String::new()
        } else {
            format!("::{}", parts.join("::"))
        }
    )
}

fn qualified(current: &str, name: &str) -> String {
    let crate_root = current.split("::").next().unwrap_or(current);
    if let Some(rest) = name.strip_prefix("crate::") {
        return format!("{crate_root}::{rest}");
    }
    if let Some(rest) = name.strip_prefix("self::") {
        return format!("{current}::{rest}");
    }
    if let Some(rest) = name.strip_prefix("super::") {
        return qualified(current.rsplit_once("::").map_or(current, |(p, _)| p), rest);
    }
    format!("{current}::{name}")
}

fn capture(file: &SourceFile, node: &AstNode<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location_from_offsets(
            &file.path,
            &file.source,
            node.range().start,
            node.range().end,
        ),
    }
}

fn owns(node: &AstNode<'_>, function: &AstNode<'_>) -> bool {
    node.ancestors()
        .find(|n| matches!(n.kind().as_ref(), "function_item" | "closure_expression"))
        .is_some_and(|n| n.range() == function.range())
}

fn block_contains(node: &AstNode<'_>, target: &AstNode<'_>) -> bool {
    node.ancestors()
        .find(|n| n.kind().as_ref() == "block")
        .is_some_and(|b| {
            b.range().start <= target.range().start && target.range().end <= b.range().end
        })
}

// Ignore strings and comments even inside macro token trees. This preserves
// token spelling; it does not expand macros or establish backend semantics.
fn tokens(node: &AstNode<'_>) -> String {
    if node.kind().as_ref().contains("comment")
        || matches!(
            node.kind().as_ref(),
            "string_literal" | "raw_string_literal" | "char_literal"
        )
    {
        return String::new();
    }
    let children = node.children().collect::<Vec<_>>();
    if children.is_empty() {
        return node.text().into_owned();
    }
    children.iter().map(tokens).collect()
}

fn has_self_argument(text: &str) -> bool {
    [".values(", ".set("].iter().any(|start| {
        let mut rest = text;
        while let Some(offset) = rest.find(start) {
            let arguments = &rest[offset + start.len()..];
            let mut depth = 1usize;
            for (end, c) in arguments.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    if arguments[..end]
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|s| s == "self")
                    {
                        return true;
                    }
                    break;
                }
            }
            rest = arguments;
        }
        false
    })
}

fn imports(
    node: &AstNode<'_>,
    prefix: &str,
    public: bool,
    output: &mut Vec<(String, String, bool)>,
) {
    match node.kind().as_ref() {
        "scoped_use_list" => {
            let path = node
                .field("path")
                .map(|n| compact(&n.text()))
                .unwrap_or_default();
            let next = if prefix.is_empty() {
                path
            } else {
                format!("{prefix}::{path}")
            };
            if let Some(list) = node.field("list") {
                imports(&list, &next, public, output);
            }
        }
        "use_list" | "use_declaration" => {
            for child in node
                .children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "visibility_modifier")
            {
                imports(&child, prefix, public, output);
            }
        }
        "use_as_clause" => {
            if let (Some(path), Some(alias)) = (node.field("path"), node.field("alias")) {
                let path = compact(&path.text());
                output.push((
                    alias.text().into_owned(),
                    if prefix.is_empty() {
                        path
                    } else {
                        format!("{prefix}::{path}")
                    },
                    public,
                ));
            }
        }
        "use_wildcard" => {
            let path = compact(&node.text());
            let path = path.trim_end_matches("::*").trim_end_matches('*');
            output.push((
                "*".into(),
                if prefix.is_empty() {
                    path.into()
                } else if path.is_empty() {
                    prefix.into()
                } else {
                    format!("{prefix}::{path}")
                },
                public,
            ));
        }
        "identifier" | "scoped_identifier" | "self" | "crate" | "super" => {
            let path = compact(&node.text());
            let name = path.rsplit("::").next().unwrap_or(&path).to_string();
            let target = if path == "self" {
                prefix.to_string()
            } else if prefix.is_empty() {
                path
            } else {
                format!("{prefix}::{path}")
            };
            output.push((name, target, public));
        }
        _ => {}
    }
}

impl Index {
    fn build(sources: &RepositorySources) -> Self {
        let mut index = Self::default();
        for file in sources.files.values().filter(|f| {
            f.language == Some(Language::Rust)
                && f.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        }) {
            let Ok(document) = StrDoc::try_new(&file.source, SupportLang::Rust) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            let mut facts = FileIndex {
                module: module(&file.path),
                ..Default::default()
            };
            for declaration in root
                .children()
                .filter(|n| n.kind().as_ref() == "use_declaration")
            {
                let public = declaration
                    .children()
                    .any(|n| n.kind().as_ref() == "visibility_modifier");
                imports(&declaration, "", public, &mut facts.imports);
            }
            for child in root.children() {
                match child.kind().as_ref() {
                    "struct_item" | "enum_item" | "type_item" => {
                        if let Some(name) = child.field("name") {
                            facts.types.insert(name.text().into_owned());
                        }
                    }
                    "macro_definition" => {
                        if tokens(&child).contains("returnErr(") {
                            if let Some(name) = child.field("name") {
                                index
                                    .rejecting_macros
                                    .entry(name.text().into_owned())
                                    .or_default()
                                    .push(capture(file, &child));
                            }
                        }
                    }
                    "impl_item" if child.field("trait").is_none() => {
                        let (Some(owner), Some(body)) = (child.field("type"), child.field("body"))
                        else {
                            continue;
                        };
                        if owner.kind().as_ref() != "type_identifier" {
                            continue;
                        }
                        let owner = owner.text().into_owned();
                        facts.types.insert(owner.clone());
                        for function in body
                            .children()
                            .filter(|n| n.kind().as_ref() == "function_item")
                        {
                            let (Some(name), Some(body)) =
                                (function.field("name"), function.field("body"))
                            else {
                                continue;
                            };
                            if function.end_pos().line() > function.start_pos().line() + 119
                                || function.range().len() > 32768
                            {
                                continue;
                            }
                            let text = tokens(&body);
                            let shadowed = root.dfs().any(|n| {
                                matches!(
                                    n.kind().as_ref(),
                                    "mod_item" | "struct_item" | "enum_item" | "type_item"
                                ) && n.field("name").is_some_and(|n| n.text() == "diesel")
                            }) || facts
                                .imports
                                .iter()
                                .any(|(alias, target, _)| alias == "diesel" && target != "diesel");
                            let writes_self = !shadowed
                                && [
                                    "diesel::update(",
                                    "diesel::insert_into(",
                                    "diesel::replace_into(",
                                ]
                                .iter()
                                .any(|s| text.contains(s))
                                && text.contains(".execute(")
                                && has_self_argument(&text);
                            let delegates = function
                                .dfs()
                                .filter(|n| {
                                    n.kind().as_ref() == "call_expression" && owns(n, &function)
                                })
                                .filter_map(|n| n.field("function"))
                                .filter_map(|n| {
                                    compact(&n.text())
                                        .strip_prefix("Self::")
                                        .map(str::to_string)
                                })
                                .collect();
                            let method = Method {
                                definition: capture(file, &function),
                                name: name.text().into_owned(),
                                returns_self: function
                                    .field("return_type")
                                    .is_some_and(|n| compact(&n.text()) == "Option<Self>"),
                                writes_self,
                                reads: text.contains(".first::<")
                                    || text.contains(".get_result::<"),
                                delegates,
                                macro_backed: body
                                    .dfs()
                                    .any(|n| n.kind().as_ref() == "macro_invocation"),
                            };
                            index
                                .methods
                                .entry((format!("{}::{owner}", facts.module), method.name.clone()))
                                .or_default()
                                .push(method);
                        }
                    }
                    _ => {}
                }
            }
            index
                .modules
                .entry(facts.module.clone())
                .or_default()
                .push(file.path.clone());
            index.files.insert(file.path.clone(), facts);
        }
        index
    }

    fn resolve(
        &self,
        module: &str,
        name: &str,
        depth: usize,
        exports_only: bool,
    ) -> Option<String> {
        if depth > 8 {
            return None;
        }
        let paths = self.modules.get(module)?;
        if paths.len() != 1 {
            return None;
        }
        let file = self.files.get(&paths[0])?;
        if !name.contains("::") && file.types.contains(name) {
            return Some(format!("{module}::{name}"));
        }
        let (head, tail) = name.split_once("::").map_or((name, ""), |(h, t)| (h, t));
        let mut candidates = BTreeSet::new();
        for (alias, target, public) in &file.imports {
            if exports_only && !public {
                continue;
            }
            if alias == head || alias == "*" {
                let target = if alias == "*" {
                    format!("{target}::{name}")
                } else if tail.is_empty() {
                    target.clone()
                } else {
                    format!("{target}::{tail}")
                };
                let target = qualified(module, &target);
                if let Some((parent, leaf)) = target.rsplit_once("::") {
                    if let Some(resolved) = self.resolve(parent, leaf, depth + 1, true) {
                        candidates.insert(resolved);
                    }
                }
            }
        }
        if name.contains("::") {
            let target = qualified(module, name);
            if let Some((parent, leaf)) = target.rsplit_once("::") {
                if parent != module {
                    if let Some(resolved) = self.resolve(parent, leaf, depth + 1, true) {
                        candidates.insert(resolved);
                    }
                }
            }
        }
        (candidates.len() == 1).then(|| candidates.into_iter().next().unwrap())
    }

    fn method(&self, owner: &str, name: &str) -> Option<&Method> {
        let methods = self.methods.get(&(owner.to_string(), name.to_string()))?;
        (methods.len() == 1).then(|| &methods[0])
    }

    fn load(&self, owner: &str, name: &str, depth: usize) -> Option<Vec<&Method>> {
        if depth > 2 {
            return None;
        }
        let method = self.method(owner, name)?;
        if !method.returns_self {
            return None;
        }
        if method.reads {
            return Some(vec![method]);
        }
        method
            .delegates
            .iter()
            .find_map(|name| self.load(owner, name, depth + 1))
            .map(|mut chain| {
                chain.insert(0, method);
                chain
            })
    }
}

fn field(node: &AstNode<'_>) -> Option<(String, String)> {
    if node.kind().as_ref() != "field_expression" {
        return None;
    }
    let (Some(value), Some(field)) = (node.field("value"), node.field("field")) else {
        return None;
    };
    (value.kind().as_ref() == "identifier")
        .then(|| (value.text().into_owned(), field.text().into_owned()))
}

fn comparison(
    condition: &AstNode<'_>,
    object: &str,
    state_field: &str,
    limit: Option<&str>,
) -> bool {
    condition.dfs().any(|b| {
        b.kind().as_ref() == "binary_expression"
            && b.field("operator")
                .is_some_and(|o| matches!(o.text().as_ref(), ">=" | ">"))
            && b.field("left")
                .and_then(|l| field(&l))
                .is_some_and(|(o, f)| o == object && f == state_field)
            && limit.is_none_or(|limit| b.field("right").is_some_and(|r| r.text().trim() == limit))
    })
}

fn rejects(block: &AstNode<'_>, function: &AstNode<'_>, index: &Index) -> bool {
    block.dfs().any(|r| {
        owns(&r, function)
            && (r.kind().as_ref() == "return_expression"
                || (r.kind().as_ref() == "macro_invocation"
                    && r.field("macro").is_some_and(|m| {
                        index
                            .rejecting_macros
                            .get(m.text().as_ref())
                            .is_some_and(|v| v.len() == 1)
                    })))
    })
}

fn limit_guard(
    check: &AstNode<'_>,
    function: &AstNode<'_>,
    index: &Index,
    object: &str,
    state_field: &str,
) -> bool {
    let (Some(condition), Some(body)) = (check.field("condition"), check.field("consequence"))
    else {
        return false;
    };
    if comparison(&condition, object, state_field, None) && rejects(&body, function, index) {
        return true;
    }
    // An optional limit is conditional context, not an arbitrary enclosing
    // branch: bind a field on this object, then compare against that binding.
    if condition.kind().as_ref() != "let_condition" {
        return false;
    }
    let (Some(pattern), Some(value)) = (condition.field("pattern"), condition.field("value"))
    else {
        return false;
    };
    if field(&value).is_none_or(|(receiver, _)| receiver != object)
        || pattern.kind().as_ref() != "tuple_struct_pattern"
        || pattern.field("type").is_none_or(|t| t.text() != "Some")
    {
        return false;
    }
    let pattern_type = pattern.field("type").unwrap().range();
    let bindings = pattern
        .dfs()
        .filter(|n| n.kind().as_ref() == "identifier" && n.range() != pattern_type)
        .collect::<Vec<_>>();
    if bindings.len() != 1 {
        return false;
    }
    let binding = bindings[0].text();
    body.dfs()
        .filter(|n| {
            n.kind().as_ref() == "if_expression"
                && owns(n, function)
                && n.ancestors()
                    .find(|a| a.kind().as_ref() == "block")
                    .is_some_and(|a| a.range() == body.range())
        })
        .any(|inner| {
            inner
                .field("condition")
                .is_some_and(|c| comparison(&c, object, state_field, Some(&binding)))
                && inner
                    .field("consequence")
                    .is_some_and(|c| rejects(&c, function, index))
        })
}

fn eligible(
    file: &SourceFile,
    scope: Option<&mehscan_core::ImpactScanScope>,
    include_material: bool,
) -> bool {
    file.language == Some(Language::Rust)
        && file.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        && (include_material || !is_review_material_path(&file.path))
        && !scope.is_some_and(|s| match s.result_policy.as_str() {
            "changed_files" | "impact_scope" => {
                !s.included_files.iter().any(|f| f.path == file.path)
            }
            "changed_locations" => !s.changed_files.iter().any(|f| f.path == file.path),
            _ => false,
        })
}

pub(super) fn groups(
    sources: &RepositorySources,
    existing: &[Evidence],
    scope: Option<&mehscan_core::ImpactScanScope>,
    include_material: bool,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    if !sources
        .files
        .values()
        .any(|f| eligible(f, scope, include_material) && f.source.contains("+="))
    {
        return groups;
    }
    let index = Index::build(sources);
    for file in sources
        .files
        .values()
        .filter(|f| eligible(f, scope, include_material) && f.source.contains("+="))
    {
        let Ok(document) = StrDoc::try_new(&file.source, SupportLang::Rust) else {
            continue;
        };
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let Some(file_index) = index.files.get(&file.path) else {
            continue;
        };
        for function in root
            .children()
            .filter(|n| n.kind().as_ref() == "function_item")
        {
            let Some(name) = function.field("name") else {
                continue;
            };
            if function.field("type_parameters").is_some()
                || function.dfs().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "use_declaration"
                            | "struct_item"
                            | "enum_item"
                            | "type_item"
                            | "macro_definition"
                    ) && owns(&n, &function)
                })
            {
                continue;
            }
            for mutation in function
                .dfs()
                .filter(|n| n.kind().as_ref() == "compound_assignment_expr" && owns(n, &function))
            {
                if mutation.field("operator").is_none_or(|n| n.text() != "+=") {
                    continue;
                }
                let Some(left) = mutation.field("left") else {
                    continue;
                };
                let Some((object, state_field)) = field(&left) else {
                    continue;
                };
                if mutation.field("right").is_none_or(|n| {
                    n.kind().as_ref() != "integer_literal" || !n.text().starts_with('1')
                }) {
                    continue;
                }
                let Some(declaration) = function
                    .dfs()
                    .filter(|n| {
                        n.kind().as_ref() == "let_declaration"
                            && owns(n, &function)
                            && n.range().end < mutation.range().start
                            && block_contains(n, &mutation)
                            && n.field("pattern")
                                .is_some_and(|p| p.text().trim() == object)
                    })
                    .max_by_key(|n| n.range().start)
                else {
                    continue;
                };
                let Some(value) = declaration.field("value") else {
                    continue;
                };
                let mut load_candidates = Vec::new();
                for call in value
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "call_expression")
                {
                    let Some(callee) = call.field("function") else {
                        continue;
                    };
                    let callee = compact(&callee.text());
                    let Some((owner, method)) = callee.rsplit_once("::") else {
                        continue;
                    };
                    let Some(owner) = index.resolve(&file_index.module, owner, 0, false) else {
                        continue;
                    };
                    if let Some(load) = index.load(&owner, method, 0) {
                        load_candidates.push((owner, load));
                    }
                }
                if load_candidates.len() != 1 {
                    continue;
                }
                let (owner, load) = &load_candidates[0];
                let Some(check) = function
                    .dfs()
                    .filter(|n| {
                        n.kind().as_ref() == "if_expression"
                            && owns(n, &function)
                            && n.range().start > declaration.range().end
                            && n.range().end < mutation.range().start
                            && block_contains(n, &mutation)
                    })
                    .find(|n| limit_guard(n, &function, &index, &object, &state_field))
                else {
                    continue;
                };
                for call in function.dfs().filter(|n| {
                    n.kind().as_ref() == "call_expression"
                        && owns(n, &function)
                        && n.range().start > mutation.range().end
                }) {
                    if !block_contains(&call, &mutation) {
                        continue;
                    }
                    let Some(callee) = call.field("function") else {
                        continue;
                    };
                    if field(&callee).is_none_or(|(receiver, _)| receiver != object) {
                        continue;
                    }
                    let Some(method_name) = callee.field("field") else {
                        continue;
                    };
                    let Some(persist) = index.method(owner, &method_name.text()) else {
                        continue;
                    };
                    if !persist.writes_self {
                        continue;
                    }
                    // Rebinding, nested scopes or local type declarations make
                    // this bounded receiver relationship unavailable.
                    if function.dfs().any(|n| {
                        n.range().start > declaration.range().end
                            && n.range().start < call.range().start
                            && owns(&n, &function)
                            && ((n.kind().as_ref() == "let_declaration"
                                && n.field("pattern")
                                    .is_some_and(|p| p.text().trim() == object))
                                || (n.kind().as_ref() == "assignment_expression"
                                    && n.field("left").is_some_and(|p| p.text().trim() == object)))
                    }) {
                        continue;
                    }
                    let location = location_from_offsets(
                        &file.path,
                        &file.source,
                        call.range().start,
                        call.range().end,
                    );
                    if scope.is_some_and(|s| {
                        s.result_policy == "changed_locations"
                            && !crate::impact::location_is_changed(&location, &s.changed_files)
                    }) {
                        continue;
                    }
                    let descriptor = ReviewAdmissionDescriptor {
                        rule_id: RULE,
                        capability: Capability::ResourceAccess,
                        cwe_candidates: vec!["CWE-362".into()],
                        tags: Vec::new(),
                    };
                    if marker_covered_by_existing_evidence(
                        existing,
                        &file.path,
                        call.range().start,
                        call.range().end,
                        &descriptor,
                    ) {
                        continue;
                    }
                    let mut captures = BTreeMap::from([
                        ("operation".into(), capture(file, &name)),
                        ("shared_state_effect".into(), capture(file, &call)),
                        ("current_value".into(), capture(file, &declaration)),
                        ("limit_check".into(), capture(file, &check)),
                        ("derived_value".into(), capture(file, &mutation)),
                        ("state_field".into(), capture(file, &left)),
                        ("persistence_helper".into(), capture(file, &method_name)),
                        ("persistence_definition".into(), persist.definition.clone()),
                        ("state_load_definition".into(), load[0].definition.clone()),
                    ]);
                    for (index, helper) in load.iter().enumerate().skip(1) {
                        captures.insert(
                            format!("state_load_helper_definition_{index}"),
                            helper.definition.clone(),
                        );
                    }
                    if let Some(rejection) = check
                        .dfs()
                        .filter(|n| n.kind().as_ref() == "macro_invocation")
                        .filter_map(|n| n.field("macro"))
                        .find_map(|n| {
                            index
                                .rejecting_macros
                                .get(n.text().as_ref())
                                .and_then(|v| (v.len() == 1).then(|| v[0].clone()))
                        })
                    {
                        captures.insert("rejection_macro_definition".into(), rejection);
                    }
                    let id = review_admission_marker_id(
                        &file.path,
                        RULE,
                        call.range().start,
                        call.range().end,
                    );
                    if groups
                        .iter()
                        .any(|g: &ObservationGroup| g.anchor_evidence_ids.contains(&id))
                    {
                        continue;
                    }
                    let mut tags = vec![
                        "review-admission-marker",
                        "review-invariant:shared-state-limit-enforcement",
                        "shared-state-limit",
                        "read-check-increment-write",
                        "database-atomicity-unresolved",
                        "caller-applicability-unresolved",
                    ];
                    if persist.macro_backed {
                        tags.push("macro-persistence-semantics-unresolved");
                    }
                    let evidence = Evidence { id: id.clone(), kind: EvidenceKind::SensitiveOperation, capability: Capability::ResourceAccess,
                        location, enclosing_symbol: Some(name.text().into_owned()), captures, cwe_candidates: vec!["CWE-362".into()],
                        tags: tags.into_iter().map(str::to_string).collect(), confidence: Confidence::Medium,
                        provenance: Provenance { resolution: Resolution::Textual, engine: "bounded Rust shared-state relationship; database helper semantics require review".into(), rule_version: 1 },
                        context: EvidenceContext::default(), symbol_resolution: None, rule_id: RULE.into(), related_evidence: Vec::new() };
                    groups.push(ObservationGroup {
                        review_material: is_review_material_path(&file.path),
                        path: file.path.clone(),
                        symbol: name.text().into_owned(),
                        evidence: vec![evidence],
                        anchor_evidence_ids: vec![id],
                        priority: 1,
                    });
                }
            }
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL: &str = r#"
pub struct Meter { used: i32, ceiling: i32 }
impl Meter {
    pub fn load(conn: &mut Connection) -> Option<Self> {
        storage! { meters::table.filter(id.eq(7)).first::<MeterRow>(conn).ok() }
    }
    pub fn lookup(conn: &mut Connection) -> Option<Self> { Self::load(conn) }
    pub fn commit(&mut self, conn: &mut Connection) {
        storage! { diesel::update(meters::table).set(self).execute(conn) }
    }
}
"#;
    const CALLER: &str = r#"
use crate::models::Meter;
fn consume(conn: &mut Connection) -> Result<(), Error> {
    let mut row = Meter::lookup(conn).unwrap();
    if row.used >= row.ceiling { return Err(Error::Limit); }
    row.used += 1;
    row.commit(conn);
    Ok(())
}
"#;

    fn source(files: &[(&str, &str)]) -> RepositorySources {
        RepositorySources {
            root: ".".into(),
            node_modules: Default::default(),
            files: files
                .iter()
                .map(|(p, s)| {
                    (
                        p.to_string(),
                        SourceFile {
                            path: p.to_string(),
                            source: s.to_string(),
                            language: Some(Language::Rust),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn local_limit_question_keeps_exact_model_and_macro_evidence_without_a_route_requirement() {
        let sources = source(&[("src/models.rs", MODEL), ("src/api.rs", CALLER)]);
        let groups = super::groups(&sources, &[], None, true);
        assert_eq!(groups.len(), 1);
        let evidence = &groups[0].evidence[0];
        assert_eq!(evidence.capability, Capability::ResourceAccess);
        assert_eq!(evidence.enclosing_symbol.as_deref(), Some("consume"));
        assert!(
            evidence
                .tags
                .iter()
                .any(|t| t == "macro-persistence-semantics-unresolved")
        );
        assert_eq!(
            review_contract(&groups[0].evidence).unwrap().relationship,
            "bounded_shared_state_limit_enforcement_review"
        );
        for name in [
            "limit_check",
            "current_value",
            "derived_value",
            "persistence_definition",
            "state_load_definition",
        ] {
            let c = &evidence.captures[name];
            let s = &sources.files[&c.location.path].source;
            assert_eq!(
                &s[c.location.start.byte_offset..c.location.end.byte_offset],
                c.text
            );
        }
    }

    #[test]
    fn explicit_alias_and_wildcard_reexport_bind_the_same_model() {
        for caller in [
            CALLER.replace("use crate::models::Meter;", "use crate::exports::*;"),
            CALLER.replace(
                "use crate::models::Meter;",
                "use crate::exports::Counter as Meter;",
            ),
        ] {
            let sources = source(&[
                ("src/models.rs", MODEL),
                (
                    "src/exports.rs",
                    "pub use crate::models::Meter; pub use crate::models::Meter as Counter;",
                ),
                ("src/api.rs", &caller),
            ]);
            assert_eq!(super::groups(&sources, &[], None, true).len(), 1);
        }
    }

    #[test]
    fn optional_limits_keep_the_binding_and_macro_rejection_source() {
        let optional = CALLER.replace(
            "if row.used >= row.ceiling { return Err(Error::Limit); }",
            "if let Some(ceiling) = row.ceiling { if row.used >= ceiling { deny!(); } }",
        );
        let model =
            format!("{MODEL}\nmacro_rules! deny {{ () => {{ return Err(Error::Limit); }} }}");
        let sources = source(&[("src/models.rs", &model), ("src/api.rs", &optional)]);
        let groups = super::groups(&sources, &[], None, true);
        assert_eq!(groups.len(), 1);
        assert!(
            groups[0].evidence[0].captures["limit_check"]
                .text
                .starts_with("if let Some")
        );
        assert!(
            groups[0].evidence[0]
                .captures
                .contains_key("rejection_macro_definition")
        );
        for control in [
            optional.replace("= row.ceiling", "= other.ceiling"),
            optional.replace("row.used >= ceiling", "row.used >= different_limit"),
            optional.replace("deny!();", "println!(\"limit\");"),
        ] {
            let sources = source(&[("src/models.rs", &model), ("src/api.rs", &control)]);
            assert!(
                super::groups(&sources, &[], None, true).is_empty(),
                "{control}"
            );
        }
    }

    #[test]
    fn module_roots_and_nested_globs_keep_their_real_namespace() {
        assert_eq!(module("src/src/model.rs"), "@crate::src::model");
        assert_eq!(module("src/worker/main.rs"), "@crate::worker::main");
        assert_eq!(module("one/src/lib.rs"), "one@crate");
        assert_eq!(module("two/src/models/mod.rs"), "two@crate::models");
        let caller = CALLER.replace("use crate::models::Meter;", "use crate::{exports::{*}};");
        let sources = source(&[
            ("src/models.rs", MODEL),
            ("src/exports.rs", "pub use crate::models::Meter;"),
            ("src/api.rs", &caller),
        ]);
        assert_eq!(super::groups(&sources, &[], None, true).len(), 1);
    }

    #[test]
    fn receiver_scope_and_actual_storage_lead_are_required() {
        for caller in [
            CALLER.replace("row.commit(conn)", "other.commit(conn)"),
            CALLER.replace("row.used += 1", "other.used += 1"),
            CALLER.replace("row.used >=", "other.used >="),
            CALLER.replace(
                "let mut row = Meter::lookup(conn).unwrap();",
                "let mut row = Meter::new();",
            ),
            CALLER.replace("row.commit(conn);", ""),
            CALLER.replace("return Err(Error::Limit);", "println!(\"limit reached\");"),
            CALLER.replace("row.used += 1;", "(|| { row.used += 1; })();"),
            CALLER.replace(
                "if row.used >= row.ceiling { return Err(Error::Limit); }",
                "if enabled { if row.used >= row.ceiling { return Err(Error::Limit); } }",
            ),
            CALLER.replace(
                "row.used += 1;",
                "row.used += 1; let mut row = Meter::lookup(conn).unwrap();",
            ),
            CALLER.replace("fn consume(", "fn consume<Meter>("),
        ] {
            let sources = source(&[("src/models.rs", MODEL), ("src/api.rs", &caller)]);
            assert!(
                super::groups(&sources, &[], None, true).is_empty(),
                "{caller}"
            );
        }
        for model in [
            MODEL.replace(
                "diesel::update(meters::table).set(self).execute(conn)",
                "println!(\"diesel::update(meters::table).set(self).execute(conn)\")",
            ),
            MODEL.replace(".set(self)", ".set(other)"),
            format!("mod diesel {{}}\n{MODEL}"),
            format!("{MODEL}\nuse crate::fake as diesel;"),
        ] {
            let sources = source(&[("src/models.rs", &model), ("src/api.rs", CALLER)]);
            assert!(
                super::groups(&sources, &[], None, true).is_empty(),
                "{model}"
            );
        }
    }

    #[test]
    fn ambiguous_exports_do_not_select_a_model_and_atomic_helpers_remain_review_controls() {
        let caller = CALLER.replace(
            "use crate::models::Meter;",
            "use crate::models::*; use crate::other::*;",
        );
        let sources = source(&[
            ("src/models.rs", MODEL),
            ("src/other.rs", MODEL),
            ("src/api.rs", &caller),
        ]);
        assert!(super::groups(&sources, &[], None, true).is_empty());
        let atomic = MODEL.replace(
            "diesel::update(meters::table)",
            "diesel::update(meters::table.filter(used.lt(ceiling)))",
        );
        let sources = source(&[("src/models.rs", &atomic), ("src/api.rs", CALLER)]);
        assert_eq!(super::groups(&sources, &[], None, true).len(), 1); // Question, never a deterministic race verdict.
    }
}
