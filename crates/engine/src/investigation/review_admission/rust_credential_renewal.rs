//! Bounded OAuth renewal -> stored credential -> JWT issuer/consumer evidence.
//! This selects a lifecycle question, never a revocation or vulnerability verdict.
use super::rust_shared_state::{
    AstNode, ModelBindings, block_contains, compact, imports, module, owns, qualified, tokens,
};
use super::*;

const RULE: &str = "rust-credential-renewal-review-marker";

#[derive(Clone)]
struct Function {
    key: String,
    module: String,
    definition: Capture,
    root_imports: Vec<(String, String, bool)>,
    blocked: BTreeSet<String>,
    parameters: Vec<(String, String)>,
    result: String,
    request_guard: bool,
}

struct Functions<'a> {
    sources: &'a RepositorySources,
    models: ModelBindings,
    functions: BTreeMap<String, Vec<Function>>,
}

fn named<'a>(node: &AstNode<'a>) -> Vec<AstNode<'a>> {
    node.children()
        .filter(|n| n.is_named() && !n.kind().as_ref().contains("comment"))
        .collect()
}

fn field(node: &AstNode<'_>) -> Option<(String, String)> {
    if node.kind().as_ref() != "field_expression" {
        return None;
    }
    let (value, field) = (node.field("value")?, node.field("field")?);
    (value.kind().as_ref() == "identifier" || value.kind().as_ref() == "self")
        .then(|| (value.text().into_owned(), field.text().into_owned()))
}

fn callee(call: &AstNode<'_>) -> Option<String> {
    let mut function = call.field("function")?;
    if function.kind().as_ref() == "generic_function" {
        function = function.field("function")?;
    }
    Some(compact(&function.text()))
}

fn arguments<'a>(call: &AstNode<'a>) -> Vec<AstNode<'a>> {
    call.field("arguments")
        .map(|a| named(&a))
        .unwrap_or_default()
}

fn tail<'a>(function: &AstNode<'a>) -> Option<AstNode<'a>> {
    let body = function.field("body")?;
    let last = named(&body).pop()?;
    if last.kind().as_ref() == "expression_statement" {
        let value = named(&last).into_iter().next()?;
        return (value.kind().as_ref() == "return_expression"
            || !last.text().trim_end().ends_with(';'))
        .then_some(value);
    }
    Some(last)
}

fn unwrap_expression<'a>(node: &AstNode<'a>) -> AstNode<'a> {
    let mut node = node.clone();
    while matches!(
        node.kind().as_ref(),
        "reference_expression"
            | "parenthesized_expression"
            | "try_expression"
            | "return_expression"
    ) {
        let Some(child) = named(&node).pop() else {
            break;
        };
        node = child;
    }
    node
}

fn declaration<'a>(function: &AstNode<'a>, name: &str, before: usize) -> Option<AstNode<'a>> {
    function
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "let_declaration"
                && owns(n, function)
                && n.range().end <= before
                && n.field("pattern").is_some_and(|p| p.text().trim() == name)
        })
        .max_by_key(|n| n.range().start)
}

// Follow only identity-like local aliases. An unrelated reassignment or opaque
// helper call does not inherit the credential's origin.
fn origin(node: &AstNode<'_>, function: &AstNode<'_>, before: usize, depth: usize) -> String {
    if depth > 6 {
        return String::new();
    }
    let node = unwrap_expression(node);
    if node.kind().as_ref() == "identifier" {
        if let Some(binding) = declaration(function, node.text().trim(), before) {
            if let Some(value) = binding.field("value") {
                return origin(&value, function, binding.range().start, depth + 1);
            }
        }
    }
    if node.kind().as_ref() == "call_expression" {
        if let Some(f) = node.field("function") {
            if let Some((receiver, method)) = field(&f) {
                if [
                    "unwrap",
                    "expect",
                    "as_ref",
                    "as_str",
                    "clone",
                    "to_owned",
                    "to_string",
                    "into",
                    "into_inner",
                    "replace",
                ]
                .contains(&method.as_str())
                {
                    if let Some(value) = f.field("value") {
                        return origin(&value, function, before, depth + 1);
                    }
                    return receiver;
                }
            } else if matches!(callee(&node).as_deref(), Some("Ok" | "Some" | "Json")) {
                if let Some(value) = arguments(&node).first() {
                    return origin(value, function, before, depth + 1);
                }
            }
            // Method chains can have a field expression as their receiver.
            if f.kind().as_ref() == "field_expression"
                && f.field("field").is_some_and(|m| {
                    [
                        "unwrap",
                        "expect",
                        "as_ref",
                        "as_str",
                        "clone",
                        "to_owned",
                        "to_string",
                        "into",
                    ]
                    .contains(&m.text().as_ref())
                })
            {
                if let Some(value) = f.field("value") {
                    return origin(&value, function, before, depth + 1);
                }
            }
        }
    }
    compact(&node.text())
}

fn variant(pattern: &AstNode<'_>, expected: &str) -> Option<String> {
    let tuple = pattern.dfs().find(|n| {
        n.kind().as_ref() == "tuple_struct_pattern"
            && n.field("type").is_some_and(|t| t.text() == expected)
    })?;
    let ty = tuple.field("type")?.range();
    let names = tuple
        .dfs()
        .filter(|n| n.kind().as_ref() == "identifier" && n.range() != ty)
        .collect::<Vec<_>>();
    (names.len() == 1).then(|| names[0].text().into_owned())
}

fn identity(node: &AstNode<'_>, name: &str) -> bool {
    let node = unwrap_expression(node);
    if node.kind().as_ref() == "block" {
        return named(&node).last().is_some_and(|n| identity(n, name));
    }
    if compact(&node.text()) == name {
        return true;
    }
    if node.kind().as_ref() == "call_expression" {
        if matches!(callee(&node).as_deref(), Some("Ok" | "Some")) {
            return arguments(&node).first().is_some_and(|n| identity(n, name));
        }
    }
    false
}

fn forwarded_call<'a>(value: &AstNode<'a>) -> Option<AstNode<'a>> {
    let mut value = unwrap_expression(value);
    if value.kind().as_ref() == "match_expression" {
        let mut success = false;
        for arm in value
            .field("body")?
            .children()
            .filter(|n| n.kind().as_ref() == "match_arm")
        {
            let Some(binding) = arm.field("pattern").and_then(|p| variant(&p, "Ok")) else {
                continue;
            };
            if !identity(&arm.field("value")?, &binding) {
                return None;
            }
            success = true;
        }
        if !success {
            return None;
        }
        value = value.field("value")?;
    }
    if value.kind().as_ref() == "call_expression" {
        if let Some(function) = value.field("function") {
            if function.kind().as_ref() == "field_expression"
                && function
                    .field("field")
                    .is_some_and(|m| matches!(m.text().as_ref(), "unwrap" | "expect"))
            {
                value = function.field("value")?;
            }
        }
    }
    (value.kind().as_ref() == "call_expression").then_some(value)
}

fn returned_principal(function: &AstNode<'_>, lookup: &AstNode<'_>) -> Option<String> {
    let Some(binding) = function.dfs().find(|n| {
        n.kind().as_ref() == "let_declaration"
            && owns(n, function)
            && n.field("value").is_some_and(|v| {
                v.range().start <= lookup.range().start && lookup.range().end <= v.range().end
            })
    }) else {
        return None;
    };
    let Some(name) = binding
        .field("pattern")
        .filter(|p| p.kind().as_ref() == "identifier")
    else {
        return None;
    };
    tail(function)
        .is_some_and(|t| {
            t.dfs().any(|n| {
                (n.kind().as_ref() == "shorthand_field_initializer" && n.text() == name.text())
                    || (n.kind().as_ref() == "field_initializer"
                        && n.field("value").is_some_and(|v| v.text() == name.text()))
                    || (n.kind().as_ref() == "call_expression"
                        && callee(&n).is_some_and(|s| s.ends_with("::Success"))
                        && arguments(&n).iter().any(|a| a.text() == name.text()))
            })
        })
        .then(|| name.text().into_owned())
}

fn with_function<T>(
    function: &Function,
    action: impl FnOnce(&AstNode<'_>) -> Option<T>,
) -> Option<T> {
    let ast = AstGrep::doc(
        StrDoc::try_new(
            &function.definition.text,
            ast_grep_language::SupportLang::Rust,
        )
        .ok()?,
    );
    let root = ast.root();
    let node = root
        .children()
        .find(|n| n.kind().as_ref() == "function_item")?;
    action(&node)
}

impl Function {
    fn capture(&self, sources: &RepositorySources, node: &AstNode<'_>) -> Capture {
        let file = &sources.files[&self.definition.location.path];
        let start = self.definition.location.start.byte_offset + node.range().start;
        Capture {
            text: node.text().into_owned(),
            location: location_from_offsets(
                &file.path,
                &file.source,
                start,
                self.definition.location.start.byte_offset + node.range().end,
            ),
        }
    }

    fn visible(&self, function: &AstNode<'_>, at: &AstNode<'_>, name: &str) -> Option<String> {
        let head = name.split("::").next()?;
        if self.blocked.contains(head)
            || function.dfs().any(|n| {
                owns(&n, function)
                    && matches!(
                        n.kind().as_ref(),
                        "function_item" | "mod_item" | "struct_item" | "type_item"
                    )
                    && n.field("name").is_some_and(|n| n.text() == head)
            })
        {
            return None;
        }
        let mut local = Vec::new();
        for declaration in function.dfs().filter(|n| {
            n.kind().as_ref() == "use_declaration"
                && owns(n, function)
                && n.range().end < at.range().start
                && block_contains(n, at)
        }) {
            imports(&declaration, "", false, &mut local);
        }
        for bindings in [&local, &self.root_imports] {
            let matches = bindings
                .iter()
                .filter(|(alias, _, _)| alias == head)
                .map(|(_, target, _)| target)
                .collect::<BTreeSet<_>>();
            if matches.len() > 1 {
                return None;
            }
            if let Some(target) = matches.into_iter().next() {
                return Some(format!("{target}{}", &name[head.len()..]));
            }
        }
        Some(name.into())
    }
}

impl<'a> Functions<'a> {
    fn build(sources: &'a RepositorySources) -> Self {
        let mut result = Self {
            sources,
            models: ModelBindings::build(sources),
            functions: BTreeMap::new(),
        };
        for file in sources.files.values().filter(|f| {
            f.language == Some(Language::Rust)
                && f.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        }) {
            let Ok(doc) = StrDoc::try_new(&file.source, ast_grep_language::SupportLang::Rust)
            else {
                continue;
            };
            let ast = AstGrep::doc(doc);
            let root = ast.root();
            let namespace = module(&file.path);
            let mut root_imports = Vec::new();
            for n in root
                .children()
                .filter(|n| n.kind().as_ref() == "use_declaration")
            {
                imports(&n, "", false, &mut root_imports);
            }
            let blocked = root
                .children()
                .filter(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "mod_item" | "struct_item" | "enum_item" | "type_item"
                    )
                })
                .filter_map(|n| n.field("name"))
                .map(|n| n.text().into_owned())
                .collect::<BTreeSet<_>>();
            for node in root.children() {
                let (owner, guard, functions) = if node.kind().as_ref() == "function_item" {
                    (None, false, vec![node.clone()])
                } else if node.kind().as_ref() == "impl_item" {
                    let Some(owner) = node.field("type") else {
                        continue;
                    };
                    if owner.kind().as_ref() != "type_identifier" {
                        continue;
                    }
                    let guard = node.field("trait").is_some_and(|t| {
                        let name = compact(&t.text())
                            .split('<')
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        let path = root_imports
                            .iter()
                            .find(|(alias, _, _)| alias == &name)
                            .map(|(_, p, _)| p.as_str())
                            .unwrap_or(&name);
                        matches!(
                            path,
                            "rocket::request::FromRequest"
                                | "actix_web::FromRequest"
                                | "axum::extract::FromRequestParts"
                        )
                    });
                    (
                        Some(owner.text().into_owned()),
                        guard,
                        node.field("body")
                            .map(|b| {
                                named(&b)
                                    .into_iter()
                                    .filter(|n| n.kind().as_ref() == "function_item")
                                    .collect()
                            })
                            .unwrap_or_default(),
                    )
                } else {
                    continue;
                };
                for function in functions {
                    let Some(name) = function.field("name") else {
                        continue;
                    };
                    if function.range().len() > 32768
                        || function.end_pos().line() > function.start_pos().line() + 119
                    {
                        continue;
                    }
                    let key = format!(
                        "{namespace}::{}{}",
                        owner.as_ref().map(|s| format!("{s}::")).unwrap_or_default(),
                        name.text()
                    );
                    let parameters = function
                        .field("parameters")
                        .map(|p| {
                            p.children()
                                .filter(|p| p.kind().as_ref() == "parameter")
                                .filter_map(|p| {
                                    Some((
                                        p.field("pattern")?.text().into_owned(),
                                        compact(&p.field("type")?.text()),
                                    ))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let definition = Capture {
                        text: function.text().into_owned(),
                        location: location_from_offsets(
                            &file.path,
                            &file.source,
                            function.range().start,
                            function.range().end,
                        ),
                    };
                    result
                        .functions
                        .entry(key.clone())
                        .or_default()
                        .push(Function {
                            key,
                            module: namespace.clone(),
                            definition,
                            root_imports: root_imports.clone(),
                            blocked: blocked.clone(),
                            parameters,
                            result: function
                                .field("return_type")
                                .map(|t| compact(&t.text()))
                                .unwrap_or_default(),
                            request_guard: guard,
                        });
                }
            }
        }
        result
    }

    fn one(&self, key: &str) -> Option<&Function> {
        let matches = self.functions.get(key)?;
        (matches.len() == 1).then_some(&matches[0])
    }

    fn resolve(
        &self,
        caller: &Function,
        function: &AstNode<'_>,
        call: &AstNode<'_>,
    ) -> Option<&Function> {
        let name = caller.visible(function, call, &callee(call)?)?;
        self.one(&qualified(&caller.module, &name))
    }

    fn sdk(
        &self,
        caller: &Function,
        function: &AstNode<'_>,
        call: &AstNode<'_>,
        method: &str,
    ) -> bool {
        callee(call)
            .and_then(|name| caller.visible(function, call, &name))
            .is_some_and(|name| name == format!("jsonwebtoken::{method}"))
    }

    // Prove a returned SDK result, not merely an encode/decode somewhere in a
    // body. A successful match arm must forward the token or decoded claims.
    fn crypto_path(
        &self,
        caller: &Function,
        method: &str,
        depth: usize,
    ) -> Option<(usize, Vec<Capture>)> {
        if depth > 2 {
            return None;
        }
        with_function(caller, |function| {
            let mut expression = unwrap_expression(&tail(function)?);
            if expression.kind().as_ref() == "tuple_expression" {
                expression = named(&expression).into_iter().next()?;
            }
            if expression.kind().as_ref() == "match_expression" {
                let body = expression.field("body")?;
                let arms = body
                    .children()
                    .filter(|n| n.kind().as_ref() == "match_arm")
                    .collect::<Vec<_>>();
                let mut success = false;
                for arm in arms {
                    let Some(binding) = arm.field("pattern").and_then(|p| variant(&p, "Ok")) else {
                        continue;
                    };
                    let expected = if method == "decode" {
                        format!("{binding}.claims")
                    } else {
                        binding
                    };
                    if !identity(&arm.field("value")?, &expected) {
                        return None;
                    }
                    success = true;
                }
                if !success {
                    return None;
                }
                expression = expression.field("value")?;
            }
            let mut expression = unwrap_expression(&expression);
            if expression.kind().as_ref() == "call_expression"
                && expression.field("function").is_some_and(|f| {
                    f.kind().as_ref() == "field_expression"
                        && f.field("field")
                            .is_some_and(|m| matches!(m.text().as_ref(), "unwrap" | "expect"))
                })
            {
                expression = expression.field("function")?.field("value")?;
            }
            if expression.kind().as_ref() != "call_expression" {
                return None;
            }
            let (argument, mut evidence) = if self.sdk(caller, function, &expression, method) {
                (
                    usize::from(method == "encode"),
                    vec![caller.capture(self.sources, &expression)],
                )
            } else {
                let child = self.resolve(caller, function, &expression)?;
                let (index, path) = self.crypto_path(child, method, depth + 1)?;
                (index, path)
            };
            let args = arguments(&expression);
            let arg = args.get(argument)?;
            let origin = origin(arg, function, expression.range().start, 0);
            let parameter = caller
                .parameters
                .iter()
                .position(|(name, _)| name == &origin)?;
            evidence.push(caller.definition.clone());
            Some((parameter, evidence))
        })
    }

    fn claim_type(
        &self,
        caller: &Function,
        function: &AstNode<'_>,
        node: &AstNode<'_>,
    ) -> Option<String> {
        let name = node.field("name")?.text().into_owned();
        if let Some(local) = self
            .models
            .resolve_type(&caller.definition.location.path, &name)
        {
            return Some(local);
        }
        let name = caller.visible(function, node, &name)?;
        self.models
            .resolve_type(&caller.definition.location.path, &name)
    }
}

fn request_parameter(
    caller: &Function,
    function: &AstNode<'_>,
    receiver: &str,
    at: &AstNode<'_>,
) -> bool {
    let Some((_, ty)) = caller.parameters.iter().find(|(name, _)| name == receiver) else {
        return false;
    };
    let outer = ty.split('<').next().unwrap_or(ty);
    let Some(path) = caller.visible(function, at, outer) else {
        return false;
    };
    if !matches!(
        path.as_str(),
        "rocket::form::Form"
            | "rocket::serde::json::Json"
            | "actix_web::web::Form"
            | "actix_web::web::Json"
            | "axum::Form"
            | "axum::Json"
    ) {
        return false;
    }
    // Only an extraction of the same request parameter may shadow it.
    function
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "let_declaration"
                && owns(n, function)
                && n.range().end < at.range().start
                && n.field("pattern")
                    .is_some_and(|p| p.text().trim() == receiver)
        })
        .all(|n| {
            n.field("value")
                .is_some_and(|v| compact(&v.text()) == format!("{receiver}.into_inner()"))
        })
}

fn refresh_receiver(selector: &AstNode<'_>) -> Option<String> {
    selector
        .dfs()
        .filter_map(|n| field(&n))
        .find_map(|(receiver, field)| (field == "grant_type").then_some(receiver))
}

fn tuple_first(pattern: &AstNode<'_>) -> Option<String> {
    if pattern.kind().as_ref() == "identifier" {
        return Some(pattern.text().into_owned());
    }
    if pattern.kind().as_ref() == "tuple_pattern" {
        return named(pattern)
            .first()
            .filter(|p| p.kind().as_ref() == "identifier")
            .map(|p| p.text().into_owned());
    }
    None
}

fn response_uses(function: &AstNode<'_>, variable: &str) -> bool {
    let Some(tail) = tail(function) else {
        return false;
    };
    let mut candidates = vec![tail.clone()];
    for node in tail.dfs().filter(|n| n.kind().as_ref() == "identifier") {
        if let Some(d) = declaration(function, &node.text(), tail.range().start) {
            if let Some(v) = d.field("value") {
                candidates.push(v);
            }
        }
    }
    candidates.into_iter().any(|n| {
        n.dfs().any(|m| {
            m.kind().as_ref() == "macro_invocation"
                && m.field("macro")
                    .is_some_and(|m| matches!(m.text().as_ref(), "json" | "serde_json::json"))
                && m.children()
                    .filter(|n| n.kind().as_ref() == "token_tree")
                    .any(|tree| {
                        let object = if tree.text().starts_with('{') {
                            Some(tree.clone())
                        } else {
                            tree.children().find(|n| {
                                n.kind().as_ref() == "token_tree" && n.text().starts_with('{')
                            })
                        };
                        object.is_some_and(|object| {
                            let entries = object
                                .children()
                                .filter(|n| !n.kind().as_ref().contains("comment"))
                                .collect::<Vec<_>>();
                            entries.windows(3).any(|w| {
                                w[0].kind().as_ref() == "string_literal"
                                    && w[0].text() == "\"access_token\""
                                    && w[1].text() == ":"
                                    && w[2].kind().as_ref() == "identifier"
                                    && w[2].text() == variable
                            })
                        })
                    })
        })
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
        .any(|f| eligible(f, scope, include_material) && f.source.contains("refresh_token"))
        || !sources
            .files
            .values()
            .any(|f| f.language == Some(Language::Rust) && f.source.contains("jsonwebtoken"))
    {
        return groups;
    }
    let index = Functions::build(sources);
    for caller in index
        .functions
        .values()
        .filter(|v| v.len() == 1)
        .map(|v| &v[0])
        .filter(|f| {
            eligible(
                &sources.files[&f.definition.location.path],
                scope,
                include_material,
            )
        })
    {
        with_function(caller, |function| {
            for choice in function
                .dfs()
                .filter(|n| n.kind().as_ref() == "match_expression" && owns(n, function))
            {
                let Some(receiver) = choice.field("value").and_then(|n| refresh_receiver(&n))
                else {
                    continue;
                };
                if !request_parameter(caller, function, &receiver, &choice) {
                    continue;
                }
                let Some(body) = choice.field("body") else {
                    continue;
                };
                for arm in body.children().filter(|n| {
                    n.kind().as_ref() == "match_arm"
                        && n.field("pattern")
                            .is_some_and(|p| compact(&p.text()) == "\"refresh_token\"")
                }) {
                    for call in arm.dfs().filter(|n| n.kind().as_ref() == "call_expression") {
                        let args = arguments(&call);
                        let Some(position) = args.iter().position(|a| {
                            a.kind().as_ref() == "identifier" && a.text() == receiver
                        }) else {
                            continue;
                        };
                        let Some(helper) = index.resolve(caller, function, &call) else {
                            continue;
                        };
                        let Some((input, _)) = helper.parameters.get(position) else {
                            continue;
                        };
                        inspect_renewal(
                            &index,
                            caller,
                            &arm,
                            helper,
                            input,
                            existing,
                            scope,
                            &mut groups,
                        );
                    }
                }
            }
            Some(())
        });
    }
    groups
}

fn inspect_renewal(
    index: &Functions<'_>,
    caller: &Function,
    arm: &AstNode<'_>,
    helper: &Function,
    input: &str,
    existing: &[Evidence],
    scope: Option<&mehscan_core::ImpactScanScope>,
    groups: &mut Vec<ObservationGroup>,
) {
    with_function(helper, |function| {
        for loaded in function
            .dfs()
            .filter(|n| n.kind().as_ref() == "let_declaration" && owns(n, function))
        {
            let (Some(record), Some(value)) = (loaded.field("pattern"), loaded.field("value"))
            else {
                continue;
            };
            if record.kind().as_ref() != "identifier" {
                continue;
            }
            for lookup in value
                .dfs()
                .filter(|n| n.kind().as_ref() == "call_expression")
            {
                let Some(name) = callee(&lookup) else {
                    continue;
                };
                let Some((owner, method)) = name.rsplit_once("::") else {
                    continue;
                };
                let Some(owner) = index
                    .models
                    .resolve_type(&helper.definition.location.path, owner)
                else {
                    continue;
                };
                let Some(lookup_source) = index.models.lookup(&owner, method) else {
                    continue;
                };
                let args = arguments(&lookup);
                let Some(position) = args.iter().position(|a| {
                    origin(a, function, lookup.range().start, 0) == format!("{input}.refresh_token")
                }) else {
                    continue;
                };
                let Some(lookup_fn) = index.one(&format!("{owner}::{method}")) else {
                    continue;
                };
                let Some((parameter, _)) = lookup_fn.parameters.get(position) else {
                    continue;
                };
                let stored_match = with_function(lookup_fn, |n| {
                    Some(tokens(n).contains(&format!(".eq({parameter})")))
                })
                .unwrap_or(false);
                if !stored_match {
                    continue;
                }
                for issued in function.dfs().filter(|n| {
                    n.kind().as_ref() == "let_declaration"
                        && owns(n, function)
                        && n.range().start > loaded.range().end
                }) {
                    let (Some(pattern), Some(value)) =
                        (issued.field("pattern"), issued.field("value"))
                    else {
                        continue;
                    };
                    let Some(token_name) = tuple_first(&pattern) else {
                        continue;
                    };
                    if !response_uses(function, &token_name) {
                        continue;
                    }
                    for issue_call in value
                        .dfs()
                        .filter(|n| n.kind().as_ref() == "call_expression")
                    {
                        let Some(callee) = issue_call.field("function") else {
                            continue;
                        };
                        let Some((object, method)) = field(&callee) else {
                            continue;
                        };
                        if object != record.text() {
                            continue;
                        }
                        let Some(issuer) = index.one(&format!("{owner}::{method}")) else {
                            continue;
                        };
                        if index
                            .models
                            .method(&owner, &method)
                            .is_none_or(|d| d.location != issuer.definition.location)
                        {
                            continue;
                        }
                        if !(issuer.result == "String" || issuer.result.starts_with("(String,")) {
                            continue;
                        }
                        let Some((claim_type, crypto, subject_source)) =
                            issuer_claims(index, issuer)
                        else {
                            continue;
                        };
                        let Some(consumer) = consumer(index, &claim_type) else {
                            continue;
                        };
                        let effect = helper.capture(index.sources, &issue_call);
                        if scope.is_some_and(|s| {
                            s.result_policy == "changed_locations"
                                && !crate::impact::location_is_changed(
                                    &effect.location,
                                    &s.changed_files,
                                )
                        }) {
                            continue;
                        }
                        let descriptor = ReviewAdmissionDescriptor {
                            rule_id: RULE,
                            capability: Capability::Authentication,
                            cwe_candidates: vec!["CWE-613".into()],
                            tags: Vec::new(),
                        };
                        if marker_covered_by_existing_evidence(
                            existing,
                            &effect.location.path,
                            effect.location.start.byte_offset,
                            effect.location.end.byte_offset,
                            &descriptor,
                        ) {
                            continue;
                        }
                        let id = review_admission_marker_id(
                            &effect.location.path,
                            RULE,
                            effect.location.start.byte_offset,
                            effect.location.end.byte_offset,
                        );
                        if groups.iter().any(|g| g.anchor_evidence_ids.contains(&id)) {
                            continue;
                        }
                        let mut captures = BTreeMap::from([
                            ("effect".into(), effect.clone()),
                            (
                                "credential_exchange_definition".into(),
                                helper.definition.clone(),
                            ),
                            (
                                "credential_renewal_grant".into(),
                                caller.capture(index.sources, arm),
                            ),
                            (
                                "credential_consumer".into(),
                                helper.capture(index.sources, &lookup),
                            ),
                            (
                                "credential_consumer_definition".into(),
                                lookup_source.clone(),
                            ),
                            ("authority_issuance".into(), effect.clone()),
                            (
                                "authority_issuer_definition".into(),
                                issuer.definition.clone(),
                            ),
                            ("issued_claims".into(), subject_source),
                            (
                                "token_validator_definition".into(),
                                consumer.validator.definition.clone(),
                            ),
                            (
                                "authority_consumer_definition".into(),
                                consumer.guard.definition.clone(),
                            ),
                        ]);
                        for (i, lookup) in consumer.lookups.into_iter().enumerate() {
                            captures.insert(format!("authority_subject_lookup_{i}"), lookup);
                        }
                        for (i, evidence) in crypto.into_iter().chain(consumer.decoder).enumerate()
                        {
                            captures.insert(format!("crypto_source_{i}"), evidence);
                        }
                        for (i, (check, principal_owner, state_field)) in
                            consumer.state_checks.into_iter().enumerate()
                        {
                            let suffix = if i == 0 {
                                String::new()
                            } else {
                                format!("_{i}")
                            };
                            captures.insert(format!("current_security_state_check{suffix}"), check);
                            add_state_writers(
                                index,
                                &principal_owner,
                                &state_field,
                                &suffix,
                                &mut captures,
                            );
                        }
                        let evidence = Evidence { id: id.clone(), kind: EvidenceKind::SensitiveOperation, capability: Capability::Authentication,
                            location: effect.location.clone(), enclosing_symbol: helper.key.rsplit("::").next().map(str::to_string), captures,
                            cwe_candidates: vec!["CWE-613".into()], tags: ["review-admission-marker", "review-invariant:credential-lifecycle", "credential-renewal", "credential-consumer-to-issuer", "credential-revocation-unresolved", "route-registration-unresolved"].into_iter().map(str::to_string).collect(),
                            confidence: Confidence::Medium, provenance: Provenance { resolution: Resolution::Textual, engine: "bounded Rust credential renewal source relationship; lifecycle requires review".into(), rule_version: 1 },
                            context: EvidenceContext::default(), symbol_resolution: None, rule_id: RULE.into(), related_evidence: Vec::new() };
                        groups.push(ObservationGroup {
                            path: effect.location.path.clone(),
                            symbol: evidence.enclosing_symbol.clone().unwrap_or_default(),
                            review_material: is_review_material_path(&effect.location.path),
                            evidence: vec![evidence],
                            anchor_evidence_ids: vec![id],
                            priority: 1,
                        });
                    }
                }
            }
        }
        Some(())
    });
}

fn issuer_claims(
    index: &Functions<'_>,
    issuer: &Function,
) -> Option<(String, Vec<Capture>, Capture)> {
    with_function(issuer, |function| {
        let mut expression = unwrap_expression(&tail(function)?);
        if expression.kind().as_ref() == "tuple_expression" {
            expression = named(&expression).into_iter().next()?;
        }
        let signer = index.resolve(issuer, function, &expression)?;
        if signer.result != "String" {
            return None;
        }
        let (parameter, crypto) = index.crypto_path(signer, "encode", 0)?;
        let args = arguments(&expression);
        let argument = args.get(parameter)?;
        let origin = origin(argument, function, expression.range().start, 0);
        let declaration = declaration(
            function,
            &compact(&unwrap_expression(argument).text()),
            expression.range().start,
        )?;
        let claims = declaration.field("value")?;
        if claims.kind().as_ref() != "struct_expression"
            || !tokens(&claims).contains("sub:")
            || origin.is_empty()
        {
            return None;
        }
        Some((
            index.claim_type(issuer, function, &claims)?,
            crypto,
            issuer.capture(index.sources, &claims),
        ))
    })
}

struct Consumer<'a> {
    validator: &'a Function,
    decoder: Vec<Capture>,
    guard: &'a Function,
    lookups: Vec<Capture>,
    state_checks: Vec<(Capture, String, String)>,
}

fn consumer<'a>(index: &'a Functions<'_>, claim_type: &str) -> Option<Consumer<'a>> {
    let mut candidates: BTreeMap<(&str, &str), Consumer<'a>> = BTreeMap::new();
    for validator in index
        .functions
        .values()
        .filter(|v| v.len() == 1)
        .map(|v| &v[0])
        .filter(|f| f.result.starts_with("Result<"))
    {
        let target = validator
            .result
            .trim_start_matches("Result<")
            .split(',')
            .next()
            .unwrap_or_default();
        if index
            .models
            .resolve_type(&validator.definition.location.path, target)
            .as_deref()
            != Some(claim_type)
        {
            continue;
        }
        let Some((parameter, decoder)) = index.crypto_path(validator, "decode", 0) else {
            continue;
        };
        for guard in index
            .functions
            .values()
            .filter(|v| v.len() == 1)
            .map(|v| &v[0])
            .filter(|f| f.request_guard)
        {
            with_function(guard, |function| {
                for declaration_node in function
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "let_declaration" && owns(n, function))
                {
                    let (Some(name), Some(value)) = (
                        declaration_node.field("pattern"),
                        declaration_node.field("value"),
                    ) else {
                        continue;
                    };
                    if name.kind().as_ref() != "identifier" {
                        continue;
                    }
                    let Some(decoded) = forwarded_call(&value) else {
                        continue;
                    };
                    if !index
                        .resolve(guard, function, &decoded)
                        .is_some_and(|f| f.key == validator.key)
                        || arguments(&decoded).get(parameter).is_none()
                    {
                        continue;
                    }
                    for subject in function.dfs().filter(|n| {
                        n.kind().as_ref() == "call_expression"
                            && owns(n, function)
                            && n.range().start > declaration_node.range().end
                    }) {
                        if !arguments(&subject).iter().any(|a| {
                            origin(a, function, subject.range().start, 0)
                                == format!("{}.sub", name.text())
                        }) {
                            continue;
                        }
                        let Some(callee) = callee(&subject) else {
                            continue;
                        };
                        let Some((owner, method)) = callee.rsplit_once("::") else {
                            continue;
                        };
                        let Some(owner) = index
                            .models
                            .resolve_type(&guard.definition.location.path, owner)
                        else {
                            continue;
                        };
                        if index.models.lookup(&owner, method).is_none() {
                            continue;
                        }
                        let Some(principal) = returned_principal(function, &subject) else {
                            continue;
                        };
                        let state = function.dfs().find_map(|n| {
                            if n.kind().as_ref() != "binary_expression"
                                || !owns(&n, function)
                                || n.field("operator").is_none_or(|o| o.text() != "!=")
                            {
                                return None;
                            }
                            let (left, right) =
                                (field(&n.field("left")?)?, field(&n.field("right")?)?);
                            let state = if left.0 == principal && right.0 == name.text() {
                                left.1
                            } else if right.0 == principal && left.0 == name.text() {
                                right.1
                            } else {
                                return None;
                            };
                            Some((guard.capture(index.sources, &n), owner.clone(), state))
                        });
                        let candidate = candidates
                            .entry((&validator.key, &guard.key))
                            .or_insert_with(|| Consumer {
                                validator,
                                decoder: decoder.clone(),
                                guard,
                                lookups: Vec::new(),
                                state_checks: Vec::new(),
                            });
                        let lookup = guard.capture(index.sources, &subject);
                        if !candidate
                            .lookups
                            .iter()
                            .any(|c| c.location == lookup.location)
                        {
                            candidate.lookups.push(lookup);
                        }
                        if let Some(state) = state {
                            if !candidate
                                .state_checks
                                .iter()
                                .any(|c| c.0.location == state.0.location)
                            {
                                candidate.state_checks.push(state);
                            }
                        }
                    }
                }
                Some(())
            });
        }
    }
    (candidates.len() == 1).then(|| candidates.into_values().next().unwrap())
}

fn add_state_writers(
    index: &Functions<'_>,
    owner: &str,
    state_field: &str,
    suffix: &str,
    captures: &mut BTreeMap<String, Capture>,
) {
    let mut writers = Vec::new();
    for definition in index.models.methods(owner) {
        let ast = AstGrep::doc(
            StrDoc::try_new(&definition.text, ast_grep_language::SupportLang::Rust).unwrap(),
        );
        let root = ast.root();
        let Some(function) = root
            .children()
            .find(|n| n.kind().as_ref() == "function_item")
        else {
            continue;
        };
        if function.dfs().any(|n| {
            n.kind().as_ref() == "assignment_expression"
                && owns(&n, &function)
                && n.field("left")
                    .and_then(|n| field(&n))
                    .is_some_and(|(receiver, field)| receiver == "self" && field == state_field)
        }) {
            if writers.len() == 2 {
                break;
            }
            captures.insert(
                format!("security_state_writer{suffix}_{}", writers.len()),
                definition.clone(),
            );
            if let Some(name) = function.field("name") {
                writers.push(name.text().into_owned());
            }
        }
    }
    let mut callers = 0;
    for definition in index.models.methods(owner) {
        if callers == 2 {
            break;
        }
        let ast = AstGrep::doc(
            StrDoc::try_new(&definition.text, ast_grep_language::SupportLang::Rust).unwrap(),
        );
        let root = ast.root();
        let Some(function) = root
            .children()
            .find(|n| n.kind().as_ref() == "function_item")
        else {
            continue;
        };
        if function.dfs().any(|n| {
            n.kind().as_ref() == "call_expression"
                && owns(&n, &function)
                && n.field("function")
                    .and_then(|n| field(&n))
                    .is_some_and(|(receiver, method)| {
                        receiver == "self" && writers.contains(&method)
                    })
        }) {
            captures.insert(
                format!("security_state_caller{suffix}_{callers}"),
                definition.clone(),
            );
            callers += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRYPTO: &str = r#"
pub struct AccessClaims { pub sub: String, pub epoch: i64 }
pub fn sign(claims: &AccessClaims) -> String {
    match jsonwebtoken::encode(&HEADER, claims, &KEY) { Ok(token) => token, Err(e) => panic!("signing failed") }
}
fn decode<T>(token: &str) -> Result<T, Error> {
    match jsonwebtoken::decode(token, &KEY, &VALIDATION) { Ok(data) => Ok(data.claims), Err(e) => Err(e) }
}
pub fn verify(token: &str) -> Result<AccessClaims, Error> { decode(token) }
"#;
    const MODEL: &str = r#"
pub struct Session { user_id: String }
pub struct Account { id: String, epoch: i64 }
impl Session {
    pub fn by_secret(value: &str, db: &mut Connection) -> Option<Self> {
        db! { sessions::table.filter(sessions::secret.eq(value)).first::<SessionRow>(db).ok() }
    }
    pub fn issue(&mut self, account: &Account) -> (String, i64) {
        use crate::crypto::{AccessClaims, sign};
        let claims = AccessClaims { sub: account.id.clone(), epoch: account.epoch };
        (sign(&claims), 600)
    }
}
impl Account {
    pub fn fetch(id: &str, db: &mut Connection) -> Option<Self> {
        db! { accounts::table.filter(accounts::id.eq(id)).first::<AccountRow>(db).ok() }
    }
    pub fn revoke(&mut self) { self.epoch = next_epoch(); }
}
"#;
    const API: &str = r#"
use rocket::form::Form;
use crate::model::{Session, Account};
fn token(data: Form<Grant>, db: &mut Connection) -> JsonResult {
    let data = data.into_inner();
    match data.grant_type.as_ref() {
        "refresh_token" => renew(data, db),
        "password" => password(data, db),
        _ => return Err(Error::Grant),
    }
}
fn renew(data: Grant, db: &mut Connection) -> JsonResult {
    let token = data.refresh_token.unwrap();
    let mut session = Session::by_secret(&token, db).unwrap();
    let account = Account::fetch(&session.user_id, db).unwrap();
    let (access_token, expires_in) = session.issue(&account);
    let result = json!({"access_token": access_token, "expires_in": expires_in});
    Ok(Json(result))
}
"#;
    const GUARD: &str = r#"
use rocket::request::FromRequest;
use crate::{crypto::verify, model::Account};
pub struct Principal { user: Account }
impl FromRequest for Principal {
    fn from_request(request: &Request) -> Outcome<Self, Error> {
        let claims = match verify(request.token()) { Ok(c) => c, Err(e) => return Outcome::Error(e) };
        let id = claims.sub;
        let user = Account::fetch(&id, request.db()).unwrap();
        if user.epoch != claims.epoch { return Outcome::Error(Error::Revoked); }
        Outcome::Success(Principal { user })
    }
}
"#;

    fn sources(api: &str, model: &str, crypto: &str, guard: &str) -> RepositorySources {
        RepositorySources {
            root: ".".into(),
            node_modules: Default::default(),
            files: [
                ("src/api.rs", api),
                ("src/model.rs", model),
                ("src/crypto.rs", crypto),
                ("src/guard.rs", guard),
            ]
            .into_iter()
            .map(|(p, text)| {
                (
                    p.into(),
                    SourceFile {
                        path: p.into(),
                        language: Some(Language::Rust),
                        source: text.into(),
                    },
                )
            })
            .collect(),
        }
    }

    #[test]
    fn renewal_has_a_stored_proof_real_signer_and_bound_authority_consumer() {
        let source = sources(API, MODEL, CRYPTO, GUARD);
        let groups = super::groups(&source, &[], None, true);
        assert_eq!(groups.len(), 1);
        let evidence = &groups[0].evidence[0];
        assert_eq!(evidence.enclosing_symbol.as_deref(), Some("renew"));
        assert_eq!(evidence.cwe_candidates, ["CWE-613"]);
        assert!(evidence.tags.iter().any(|t| t == "credential-renewal"));
        assert_eq!(
            review_contract(&groups[0].evidence).unwrap().relationship,
            "bounded_credential_renewal_review"
        );
        assert!(
            evidence
                .captures
                .contains_key("current_security_state_check")
        );
        assert!(evidence.captures.contains_key("security_state_writer_0"));
        for c in evidence.captures.values() {
            let text = &source.files[&c.location.path].source;
            assert_eq!(
                &text[c.location.start.byte_offset..c.location.end.byte_offset],
                c.text
            );
        }
    }

    #[test]
    fn one_guard_can_resolve_multiple_subject_records_but_distinct_guards_are_ambiguous() {
        let model = MODEL.replace("impl Account {", "impl Session { pub fn for_subject(id: &str, db: &mut Connection) -> Option<Self> { db! { sessions::table.filter(sessions::user_id.eq(id)).first::<SessionRow>(db).ok() } } }\nimpl Account {");
        let guard = GUARD.replace("model::Account", "model::{Account, Session}")
            .replace("user: Account }", "user: Account, session: Session }")
            .replace("let user = Account::fetch", "let session = Session::for_subject(&id, request.db()).unwrap();\nlet user = Account::fetch")
            .replace("Principal { user }", "Principal { user, session }");
        let source = sources(API, &model, CRYPTO, &guard);
        let groups = super::groups(&source, &[], None, true);
        assert_eq!(groups.len(), 1);
        let captures = &groups[0].evidence[0].captures;
        assert_eq!(
            captures
                .keys()
                .filter(|k| k.starts_with("authority_subject_lookup_"))
                .count(),
            2
        );
        assert!(
            captures["current_security_state_check"]
                .text
                .contains("user.epoch")
        );
        assert!(captures.contains_key("security_state_writer_0"));
        let second = GUARD
            .replace("Principal", "OtherPrincipal")
            .replace("use rocket::request::FromRequest;", "")
            .replace("use crate::{crypto::verify, model::Account};", "");
        let source = sources(API, MODEL, CRYPTO, &format!("{GUARD}\n{second}"));
        assert!(super::groups(&source, &[], None, true).is_empty());
    }

    #[test]
    fn source_bindings_accept_aliases_without_globally_admitting_login_handlers() {
        let api = API
            .replace("rocket::form::Form;", "rocket::form::Form as RequestBody;")
            .replace("Form<Grant>", "RequestBody<Grant>")
            .replace("Session, Account", "Session as Lease, Account")
            .replace("Session::by_secret", "Lease::by_secret");
        let crypto = CRYPTO
            .replace(
                "pub struct AccessClaims",
                "use jsonwebtoken as jwt;\npub struct AccessClaims",
            )
            .replace("jsonwebtoken::encode", "jwt::encode")
            .replace("jsonwebtoken::decode", "jwt::decode");
        let source = sources(&api, MODEL, &crypto, GUARD);
        assert_eq!(super::groups(&source, &[], None, true).len(), 1);
        let source = sources(
            &API.replace("\"refresh_token\" =>", "\"client_credentials\" =>"),
            MODEL,
            CRYPTO,
            GUARD,
        );
        assert!(super::groups(&source, &[], None, true).is_empty());
    }

    #[test]
    fn token_names_and_response_keys_do_not_establish_credential_or_issuance_flow() {
        for api in [
            API.replace("data.refresh_token.unwrap()", "data.unrelated.unwrap()"),
            API.replace("by_secret(&token,", "by_secret(\"constant\","),
            API.replace("session.issue(&account)", "other.issue(&account)"),
            API.replace(
                "\"access_token\": access_token",
                "\"access_token\": unrelated",
            ),
            API.replace(
                "let data = data.into_inner();",
                "let data = make_local_data();",
            ),
            API.replace(
                "match data.grant_type.as_ref()",
                "match fixed.grant_type.as_ref()",
            ),
        ] {
            let source = sources(&api, MODEL, CRYPTO, GUARD);
            assert!(super::groups(&source, &[], None, true).is_empty(), "{api}");
        }
        for model in [
            MODEL.replace("secret.eq(value)", "secret.eq(other)"),
            MODEL.replace(
                "(sign(&claims), 600)",
                "{ let ignored = sign(&claims); (String::new(), 600) }",
            ),
        ] {
            let source = sources(API, &model, CRYPTO, GUARD);
            assert!(
                super::groups(&source, &[], None, true).is_empty(),
                "{model}"
            );
        }
        for crypto in [
            CRYPTO.replace("Ok(token) => token", "Ok(token) => String::new()"),
            CRYPTO.replace("&HEADER, claims,", "&HEADER, unrelated,"),
            format!("mod jsonwebtoken {{}}\n{CRYPTO}"),
        ] {
            let source = sources(API, MODEL, &crypto, GUARD);
            assert!(
                super::groups(&source, &[], None, true).is_empty(),
                "{crypto}"
            );
        }
    }

    #[test]
    fn parsing_or_discarding_a_decoder_is_not_a_validating_authority_consumer() {
        for crypto in [
            CRYPTO.replace(
                "jsonwebtoken::decode(token, &KEY, &VALIDATION)",
                "parse_json(token)",
            ),
            CRYPTO.replace(
                "Result<AccessClaims, Error>",
                "Result<DifferentClaims, Error>",
            ),
        ] {
            let source = sources(API, MODEL, &crypto, GUARD);
            assert!(super::groups(&source, &[], None, true).is_empty());
        }
        for guard in [GUARD.replace("let claims = match verify(request.token()) { Ok(c) => c, Err(e) => return Outcome::Error(e) };", "let claims = { verify(request.token()); default_claims() };"),
                      GUARD.replace("Principal { user }", "Principal { user: fixed_user }"),
                      GUARD.replace("impl FromRequest", "impl UnrelatedTrait")] {
            let source = sources(API, MODEL, CRYPTO, &guard);
            assert!(super::groups(&source, &[], None, true).is_empty(), "{guard}");
        }
    }

    #[test]
    fn enforcing_revocation_stays_a_review_control_not_an_automatic_finding() {
        let model = MODEL.replace(
            ".filter(sessions::secret.eq(value))",
            ".filter(sessions::secret.eq(value)).filter(sessions::revoked.eq(false))",
        );
        let source = sources(API, &model, CRYPTO, GUARD);
        let groups = super::groups(&source, &[], None, true);
        assert_eq!(groups.len(), 1);
        assert!(
            groups[0].evidence[0].captures["credential_consumer_definition"]
                .text
                .contains("revoked.eq(false)")
        );
    }
}
